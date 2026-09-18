package MailScanner::CustomConfig;

# MSFE-NG MailScanner logging plugin (clean-room reimplementation).
#
# Purpose: log one row per scanned message into the `maillog` MySQL table that
# backs MSFE-NG's reporting and quarantine views. Written from scratch; the
# maillog column set follows the MailScanner logging contract and is compatible
# with MailWatch's schema. No original ConfigServer or MailWatch code is copied.
#
# Activation (do NOT run automatically — see `msfe-ng mailscanner enable-logging`):
#   1. install this file into MailScanner's custom-functions directory, and
#   2. set in MailScanner.conf:  Always Looked Up Last = &MSFENGLogging
# MailScanner then calls InitMSFENGLogging at startup, MSFENGLogging per message,
# and EndMSFENGLogging at shutdown.
#
# Process model: MailScanner runs these in EVERY scanning child (Init when the
# child starts, End when it dies — every `Restart Every` seconds), so there is
# deliberately no shared logger daemon: each child owns one lazily opened,
# persistent DB connection. A shared singleton either gets started N times
# ("Address already in use") or is killed by the first child to exit while its
# siblings silently lose rows.

use strict;
use warnings;

use Sys::Hostname qw(hostname);

# DBI and a MySQL driver are only needed once a message is logged, and only in
# the live MailScanner environment. require (not use) so `perl -c` passes on
# CI hosts without the driver installed. Either DBD::mysql or DBD::MariaDB
# works: on a cPanel host running MariaDB from the MariaDB repo, EL9's
# perl-DBD-MySQL is uninstallable (it needs mysql-libs, which MariaDB-common
# obsoletes), so perl-DBD-MariaDB is what gets installed there.

my $CONF_FILE = $ENV{MSFE_NG_CONFIG} || '/etc/msfe-ng/config.toml';
our @COLS;   # insert column list, intersected with the live table at connect
my $RETRY_AFTER = 60;             # seconds between connect attempts while the DB is down

my %DB;                           # db_host/db_port/db_name/db_user/db_pass
my $DBH;
my $INSERT;
my $LAST_FAIL = 0;

# ---- MailScanner entry points ------------------------------------------------

sub InitMSFENGLogging {
    read_db_config();
    return;
}

sub EndMSFENGLogging {
    db_disconnect();
    return;
}

# Called for every message: insert the row over this child's own connection.
sub MSFENGLogging {
    my ($message) = @_;
    return unless defined $message && defined $message->{id};
    my %row = extract_row($message);
    insert_row(\%row);
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

# ---- per-child persistent connection ----------------------------------------

# The installed driver: DBD::mysql, else DBD::MariaDB (same wire protocol,
# same DSN keys). Undef when neither loads — connect then fails and logs it.
sub db_driver {
    for my $d (qw(mysql MariaDB)) {
        return $d if eval { require "DBD/$d.pm"; 1 };
    }
    return;
}

sub db_dsn {
    my $driver = db_driver() || 'mysql';
    return "DBI:$driver:database=$DB{db_name};host=$DB{db_host};port=$DB{db_port}";
}

sub db_connect {
    db_disconnect();
    require DBI;
    # AutoInactiveDestroy: MailScanner children fork helpers (virus scanners
    # etc.); their exit must not tear down the connection they inherited.
    # DBD::MariaDB speaks utf8mb4 by default; DBD::mysql must be told.
    my %attr = ( PrintError => 0, RaiseError => 0, AutoInactiveDestroy => 1 );
    $attr{mysql_enable_utf8mb4} = 1 if (db_driver() || '') eq 'mysql';
    $DBH = DBI->connect(db_dsn(), $DB{db_user}, $DB{db_pass}, \%attr);
    unless ($DBH) {
        $LAST_FAIL = time;
        _log("MSFE-NG: DB connect failed: $DBI::errstr");
        return;
    }
    # Intersect with the columns the database actually has: during an upgrade
    # this plugin can load before `msfe-ng db-migrate` runs, and a mismatched
    # INSERT would silently fail for every message.
    my $have = eval { $DBH->selectcol_arrayref('SHOW COLUMNS FROM maillog') } || [];
    my %present = map { $_ => 1 } @$have;
    @COLS = grep { $present{$_} } maillog_columns();
    unless (@COLS) { @COLS = maillog_columns() }   # SHOW COLUMNS failed; try anyway
    my $ph = join ',', ('?') x scalar(@COLS);
    my $sql = 'INSERT INTO maillog (' . join(',', @COLS) . ") VALUES ($ph)";
    $INSERT = $DBH->prepare($sql);
    $LAST_FAIL = 0;
    _log("MSFE-NG: connected to maillog database $DB{db_name}");
    return;
}

sub db_disconnect {
    $INSERT = undef;
    if ($DBH) {
        eval { $DBH->disconnect };
        $DBH = undef;
    }
    return;
}

sub insert_row {
    my ($row) = @_;
    unless ($DBH && $DBH->ping) {
        # While the DB is down, one attempt per minute keeps the log readable.
        return if $LAST_FAIL && time - $LAST_FAIL < $RETRY_AFTER;
        db_connect();
        return unless $INSERT;
    }
    my @vals = map { $row->{$_} } @COLS;
    unless ($INSERT->execute(@vals)) {
        _log("MSFE-NG: insert failed: $DBI::errstr");
    }
    return;
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
        quarantined body_path
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
    # MailScanner writes archived copies to <archive-dir>/<date>/<id>; build
    # the same date the message row uses so the recorded path is exact.
    my $datedir = sprintf('%04d%02d%02d', $ts[5] + 1900, $ts[4] + 1, $ts[3]);
    my $body_path = body_path_of($m->{id} // '', $datedir, \@quarant, \@spamarch, \@archive);

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
        body_path       => $body_path,
    );
}

# Where this message's copy landed, so the front-end can open it directly
# instead of scanning the spool. Quarantine/spam-archive entries are full
# paths; archive entries may be a directory (one file per message), an mbox
# file, or an email address (skipped).
sub body_path_of {
    my ($id, $datedir, $quar, $spam, $arch) = @_;
    return '' unless defined $id && $id ne '';
    # quarantine/spam entries are already full paths incl. their date dir
    for my $p (@$quar, @$spam) {
        next unless defined $p && $p =~ m{^/};
        return $p if -e $p;
        return "$p/$id" if -d $p && -e "$p/$id";
    }
    # archive entries are the target directory; MailScanner appends <date>/<id>
    my $first = '';
    for my $p (@$arch) {
        next unless defined $p && $p =~ m{^/};   # skip forwarding addresses
        my $cand = -d $p ? "$p/$datedir/$id" : $p;
        return $cand if -e $cand;
        $first ||= $cand;
    }
    return $first;   # not flushed to disk yet, but this is where it will be
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
