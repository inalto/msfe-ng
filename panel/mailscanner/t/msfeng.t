#!/usr/bin/perl
# Behavioural test for the MailScanner logging plugin, run against SQLite so
# it needs no MySQL: perl panel/mailscanner/t/msfeng.t
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;

BEGIN {
    for my $m (qw(DBI DBD::SQLite)) {
        eval "require $m; 1" or plan skip_all => "$m not installed";
    }
}

my $dir = tempdir(CLEANUP => 1);
my $db  = "$dir/maillog.sqlite";

# The plugin reads DB credentials from config.toml; point it at a scratch one.
open my $cf, '>', "$dir/config.toml" or die $!;
print {$cf} qq{db_name = "msfe_ng"\ndb_user = "u"\ndb_pass = "p"\n};
close $cf;
$ENV{MSFE_NG_CONFIG} = "$dir/config.toml";

# Stand-in for MailScanner's logger: collect what the plugin logs.
my @log;
{
    no strict 'refs';
    *{'MailScanner::Log::InfoLog'} = sub { my ($fmt, @a) = @_; push @log, sprintf($fmt, @a) };
}

require "$FindBin::Bin/../MSFENG.pm";

# Test seam: the only MySQL-specific piece is the DSN.
{
    no warnings qw(redefine once);
    *MailScanner::CustomConfig::db_dsn = sub { "dbi:SQLite:dbname=$db" };
}

# A maillog table with every column the plugin knows.
{
    my $dbh = DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 1 });
    my $cols = join ', ', map { "$_ TEXT" } MailScanner::CustomConfig::maillog_columns();
    $dbh->do("CREATE TABLE maillog ($cols)");
    $dbh->disconnect;
}

sub rows {
    my $dbh = DBI->connect("dbi:SQLite:dbname=$db", '', '', { RaiseError => 1 });
    my $r = $dbh->selectcol_arrayref('SELECT message_id FROM maillog ORDER BY rowid');
    $dbh->disconnect;
    return @$r;
}

sub message {
    my ($id) = @_;
    return {
        id => $id, from => 'a@example.com', fromdomain => 'example.com',
        to => ['b@example.net'], todomain => ['example.net'], subject => 'hi',
        size => 10, headers => ['Subject: hi'], sascore => 0.5,
    };
}

sub port_47712_listening {
    return IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 47_712, Proto => 'tcp', Timeout => 1) ? 1 : 0;
}
require IO::Socket::INET;

# --- every MailScanner child calls Init: no daemon may be spawned -------------
MailScanner::CustomConfig::InitMSFENGLogging() for 1 .. 3;
sleep 1;   # give a (wrong) forked daemon time to bind
is(port_47712_listening(), 0, 'Init spawns no listener on 47712');
ok(!(grep { /cannot listen|started logging daemon/ } @log), 'no daemon noise in the log')
    or diag explain \@log;
my @daemons = grep { /MSFE-NG: maillog/ } `ps -eo args`;
is(scalar @daemons, 0, 'no detached logger process');

# --- a message is inserted by the worker itself --------------------------------
MailScanner::CustomConfig::MSFENGLogging(message('m1'));
is_deeply([rows()], ['m1'], 'row inserted for the first message');
ok((grep { /connected to maillog database msfe_ng/ } @log), 'logs the connection once');

MailScanner::CustomConfig::MSFENGLogging(message('m2'));
is_deeply([rows()], ['m1', 'm2'], 'second message reuses the connection');
is(scalar(grep { /connected to maillog database/ } @log), 1, 'connected only once');

# --- one worker ending must not stop another worker's logging -----------------
my $pid = fork();
die "fork: $!" unless defined $pid;
if ($pid == 0) {
    # a sibling worker: its own Init/insert/End lifecycle
    MailScanner::CustomConfig::InitMSFENGLogging();
    MailScanner::CustomConfig::MSFENGLogging(message('sibling'));
    MailScanner::CustomConfig::EndMSFENGLogging();
    exit 0;
}
waitpid $pid, 0;
is($? >> 8, 0, 'sibling worker exited cleanly');
MailScanner::CustomConfig::MSFENGLogging(message('m3'));
is_deeply([sort(rows())], [sort qw(m1 m2 sibling m3)], 'this worker still logs after a sibling ended');

# --- End releases the connection; a later message reconnects -------------------
MailScanner::CustomConfig::EndMSFENGLogging();
MailScanner::CustomConfig::MSFENGLogging(message('m4'));
ok((grep { $_ eq 'm4' } rows()), 'reconnects after End');

# --- the scan report is MailScanner's per-attachment verdicts ------------------
# MailScanner keeps them in {allreports} (filename => text, after CombineReports);
# the row stores one line per attachment, in filename order, so the front-end
# can show why a message was flagged.
{
    my %row = MailScanner::CustomConfig::extract_row({ %{ message('m5') },
        nameinfected => 1,
        allreports   => {
            'x.pdf.exe' => "MailScanner: Attempt to hide real filename extension (x.pdf.exe)\n",
            'eicar.com' => "ClamAV: eicar.com contains Eicar-Test-Signature\n",
        },
    });
    is($row{report},
        "ClamAV: eicar.com contains Eicar-Test-Signature\n"
      . "MailScanner: Attempt to hide real filename extension (x.pdf.exe)",
        'report is one line per flagged attachment');
    my %clean = MailScanner::CustomConfig::extract_row(message('m6'));
    is($clean{report}, '', 'a clean message has an empty report');
}

# Release the plugin's connection before global destruction: DBD::SQLite on
# perl 5.26 (EL8) can segfault when a live handle is torn down at exit,
# which would fail the run after every test passed.
MailScanner::CustomConfig::EndMSFENGLogging();

done_testing;
