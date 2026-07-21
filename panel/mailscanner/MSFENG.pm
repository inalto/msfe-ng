package MailScanner::CustomConfig;

# MSFE-NG MailScanner logging plugin (clean-room reimplementation).
#
# Purpose: log one row per scanned message into the `maillog` MySQL table that
# backs MSFE-NG's reporting and quarantine views. Written from scratch; the
# behavior (forked persistent-connection logger, the maillog column set) follows
# the MailScanner logging contract and is compatible with MailWatch's schema.
# No original ConfigServer or MailWatch code is copied.
#
# Activation (do NOT run automatically — see `msfe-ng mailscanner enable-logging`):
#   1. install this file into MailScanner's custom-functions directory, and
#   2. set in MailScanner.conf:  Always Looked Up Last = &MSFENGLogging
# MailScanner then calls InitMSFENGLogging at startup, MSFENGLogging per message,
# and EndMSFENGLogging at shutdown.

use strict;
use warnings;

use IO::Socket::INET ();
use Storable qw(freeze thaw);
use POSIX ();
use Sys::Hostname qw(hostname);

# DBI/DBD::mysql are only needed inside the forked logger, and only in the live
# MailScanner environment. require (not use) so `perl -c` passes on CI hosts
# without the driver installed.

my $CONF_FILE = $ENV{MSFE_NG_CONFIG} || '/etc/msfe-ng/config.toml';
my $LISTEN_IP = '127.0.0.1';
my $LISTEN_PORT = 47_712;         # MSFE-NG's own port (localhost only)
my $IDLE_TIMEOUT = 3600;          # self-terminate a wedged logger after 1h

my %DB;                           # db_host/db_port/db_name/db_user/db_pass
my $DBH;
my $INSERT;

# ---- MailScanner entry points ------------------------------------------------

sub InitMSFENGLogging {
    read_db_config();
    fork_logger();
    return;
}

sub EndMSFENGLogging {
    my $sock = client_socket();
    if ($sock) {
        print {$sock} "quit\n";
        close $sock;
    }
    return;
}

# Called for every message. Serializes the fields we log and hands them to the
# persistent logger over the localhost socket, so scanning is never blocked on
# the database.
sub MSFENGLogging {
    my ($message) = @_;
    return unless defined $message && defined $message->{id};

    my %row = extract_row($message);
    my $frozen = eval { freeze(\%row) };
    return unless defined $frozen;

    my $sock = client_socket() or return;
    print {$sock} unpack('H*', $frozen), "\n";
    print {$sock} "end\n";
    close $sock;
    return;
}

# ---- config ------------------------------------------------------------------

# Parse the flat db_* keys out of /etc/msfe-ng/config.toml (same tiny subset the
# Rust side writes: `key = value`, optional quotes, # comments).
sub read_db_config {
    %DB = (
        db_host => 'localhost',
        db_port => 3306,
        db_name => 'msfe_ng',
        db_user => 'msfe_ng',
        db_pass => '',
    );
    open my $fh, '<', $CONF_FILE or return;
    while (my $line = <$fh>) {
        $line =~ s/\r?\n$//;
        $line =~ s/^\s+//;
        next if $line eq '' || $line =~ /^[#\[]/;
        my ($k, $v) = split /\s*=\s*/, $line, 2;
        next unless defined $v;
        $v =~ s/\s*#.*$//;            # strip trailing comment (no quotes handled here)
        $v =~ s/^\s+|\s+$//g;
        $v =~ s/^["'](.*)["']$/$1/;   # unquote
        $DB{$k} = $v if exists $DB{$k};
    }
    close $fh;
    return;
}

# ---- forked persistent logger ------------------------------------------------

sub client_socket {
    return IO::Socket::INET->new(
        PeerAddr => $LISTEN_IP,
        PeerPort => $LISTEN_PORT,
        Proto    => 'tcp',
        Timeout  => 5,
    );
}

# Double-fork a detached logger that owns the single DB connection.
sub fork_logger {
    my $pid = fork();
    if (!defined $pid) {
        _log("MSFE-NG: cannot fork logger: $!");
        return;
    }
    if ($pid) {
        waitpid $pid, 0;
        _log('MSFE-NG: started logging daemon');
        return;
    }

    POSIX::setsid();
    exit 0 if fork();               # detach; grandchild is the daemon

    $SIG{HUP} = $SIG{INT} = $SIG{PIPE} = $SIG{TERM} = $SIG{ALRM} = \&_shutdown;
    $0 = 'MSFE-NG: maillog';
    logger_connect();
    logger_serve();
    exit 0;
}

sub logger_connect {
    require DBI;
    my $dsn = "DBI:mysql:database=$DB{db_name};host=$DB{db_host};port=$DB{db_port}";
    $DBH = DBI->connect($dsn, $DB{db_user}, $DB{db_pass},
        { PrintError => 0, RaiseError => 0, mysql_enable_utf8mb4 => 1 });
    unless ($DBH) {
        _log("MSFE-NG: DB connect failed: $DBI::errstr");
        return;
    }
    my @cols = maillog_columns();
    my $ph = join ',', ('?') x scalar(@cols);
    my $sql = 'INSERT INTO maillog (' . join(',', @cols) . ") VALUES ($ph)";
    $INSERT = $DBH->prepare($sql);
    _log("MSFE-NG: connected to maillog database $DB{db_name}");
    return;
}

sub logger_serve {
    my $server = IO::Socket::INET->new(
        LocalAddr => $LISTEN_IP,
        LocalPort => $LISTEN_PORT,
        Proto     => 'tcp',
        Listen    => POSIX::INT_MAX > 0 ? 128 : 5,
        ReuseAddr => 1,
    ) or do { _log("MSFE-NG: cannot listen: $!"); return; };

    while (my $client = $server->accept()) {
        alarm($IDLE_TIMEOUT);
        my $peer = $client->peerhost() // '';
        if ($peer ne $LISTEN_IP) { close $client; next; }   # localhost only

        my $hex = '';
        while (my $l = <$client>) {
            $l =~ s/\r?\n$//;
            last if $l eq 'end';
            _shutdown() if $l eq 'quit';
            $hex .= $l;
        }
        close $client;
        next if $hex eq '';

        my $row = eval { thaw(pack('H*', $hex)) };
        next unless ref $row eq 'HASH';
        insert_row($row);
    }
    return;
}

sub insert_row {
    my ($row) = @_;
    return unless $INSERT;
    unless ($DBH && $DBH->ping) { logger_connect(); return unless $INSERT; }
    my @vals = map { $row->{$_} } maillog_columns();
    unless ($INSERT->execute(@vals)) {
        _log("MSFE-NG: insert failed: $DBI::errstr");
    }
    return;
}

sub _shutdown {
    $SIG{INT} = $SIG{TERM} = 'IGNORE';
    $DBH->disconnect if $DBH;
    exit 0;
}

# ---- message → row -----------------------------------------------------------

# The maillog columns we populate, in a fixed order shared by prepare/execute.
sub maillog_columns {
    return qw(
        msg_ts message_id size from_address from_domain to_address to_domain
        to_domains subject clientip archive isspam ishighspam issaspam isrblspam
        spamwhitelisted spamblacklisted sascore spamreport rblspamreport
        virusinfected nameinfected otherinfected report ismcp ishighmcp issamcp
        mcpwhitelisted mcpblacklisted mcpsascore mcpreport hostname headers
        quarantined
    );
}

sub extract_row {
    my ($m) = @_;

    my @to        = @{ $m->{to}        || [] };
    my @todomain  = @{ $m->{todomain}  || [] };
    my @archive   = @{ $m->{archiveplaces} || [] };
    my @quarant   = @{ $m->{quarantineplaces} || [] };
    my @spamarch  = @{ $m->{spamarchive} || [] };

    my $spamreport = clean($m->{spamreport});
    my $mcpreport  = clean($m->{mcpreport});
    my $clientip   = $m->{clientip} // '';
    $clientip =~ s/^(\d+\.\d+\.\d+\.\d+)\.\d+$/$1/;   # strip trailing port octet

    my @ts = localtime();
    my $msg_ts = sprintf('%04d-%02d-%02d %02d:%02d:%02d',
        $ts[5] + 1900, $ts[4] + 1, $ts[3], $ts[2], $ts[1], $ts[0]);

    my $quarantined = (scalar(@quarant) + scalar(@spamarch)) > 0 ? 1 : 0;

    return (
        msg_ts          => $msg_ts,
        message_id      => $m->{id} // '',
        size            => $m->{size} // 0,
        from_address    => $m->{from} // '',
        from_domain     => $m->{fromdomain} // '',
        to_address      => join(', ', @to),
        to_domain       => ($todomain[0] // ''),
        to_domains      => join(',', @todomain),
        subject         => $m->{subject} // '',
        clientip        => $clientip,
        archive         => join(',', @archive),
        isspam          => $m->{isspam} // 0,
        ishighspam      => $m->{ishigh} // 0,
        issaspam        => $m->{issaspam} // 0,
        isrblspam       => $m->{isrblspam} // 0,
        spamwhitelisted => $m->{spamwhitelisted} // 0,
        spamblacklisted => $m->{spamblacklisted} // 0,
        sascore         => defined $m->{sascore} ? sprintf('%.2f', $m->{sascore}) : 0,
        spamreport      => $spamreport,
        rblspamreport   => clean($m->{rblspamreport}),
        virusinfected   => $m->{virusinfected} // 0,
        nameinfected    => $m->{nameinfected} // 0,
        otherinfected   => $m->{otherinfected} // 0,
        report          => clean($m->{report}),
        ismcp           => $m->{ismcp} // 0,
        ishighmcp       => $m->{ishighmcp} // 0,
        issamcp         => $m->{issamcp} // 0,
        mcpwhitelisted  => $m->{mcpwhitelisted} // 0,
        mcpblacklisted  => $m->{mcpblacklisted} // 0,
        mcpsascore      => defined $m->{mcpsascore} ? sprintf('%.2f', $m->{mcpsascore}) : 0,
        mcpreport       => $mcpreport,
        hostname        => hostname(),
        headers         => join("\n", @{ $m->{headers} || [] }),
        quarantined     => $quarantined,
    );
}

sub clean {
    my ($s) = @_;
    return '' unless defined $s;
    $s =~ s/[\r\n\t]+/ /g;
    return $s;
}

sub _log {
    my ($msg) = @_;
    if (defined &MailScanner::Log::InfoLog) {
        MailScanner::Log::InfoLog('%s', $msg);
    }
    return;
}

1;
