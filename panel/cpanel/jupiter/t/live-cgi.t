#!/usr/bin/perl
# Contract test for the cPanel end-user entry point, run outside cPanel:
#   perl panel/cpanel/jupiter/t/live-cgi.t
# cPanel executes *.live.cgi under its LiveAPI engine and kills the child
# unless it connects back (Cpanel::LiveAPI->new) before writing output and
# closes the session (->end) when done. A stub Cpanel::LiveAPI records those
# calls; a stub daemon on a unix socket records the proxied request.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);

my $cgi = "$FindBin::Bin/../msfe-ng.live.cgi";
my $dir = tempdir(CLEANUP => 1);

# --- stub Cpanel::LiveAPI that logs its lifecycle to a file ------------------
mkdir "$dir/Cpanel" or die $!;
open my $m, '>', "$dir/Cpanel/LiveAPI.pm" or die $!;
print {$m} <<"EOM";
package Cpanel::LiveAPI;
sub _note { open my \$f, '>>', '$dir/liveapi.log' or die; print {\$f} "\@_\\n"; close \$f }
sub new { _note('new'); return bless {}, shift }
sub cpanelprint { my (\$s, \$v) = \@_; _note("print \$v"); return \$v eq '\$user' ? 'acct1' : '' }
sub end { _note('end'); return 1 }
1;
EOM
close $m;

# --- stub msfe-ngd: one request in, canned response out ----------------------
my $sockpath = "$dir/d.sock";
my $server = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $sockpath, Listen => 1)
    or die "listen: $!";
my $pid = fork() // die "fork: $!";
if ($pid == 0) {
    my $c = $server->accept or exit 1;
    my $req = '';
    while (my $l = <$c>) { $req .= $l; last if $l eq "\r\n" }
    open my $f, '>', "$dir/request" or die; print {$f} $req; close $f;
    print {$c} "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 6\r\n\r\n<p>hi\n";
    close $c;
    exit 0;
}
close $server;

# --- run the CGI the way cPanel would (REMOTE_USER unset in the live engine) --
local $ENV{MSFE_NG_SOCKET}  = $sockpath;
local $ENV{PERL5LIB}        = $dir;
local $ENV{REQUEST_METHOD}  = 'GET';
local $ENV{HTTP_X_MSFE_PATH} = '/api/user/summary';
delete $ENV{REMOTE_USER};
my $out = `/usr/bin/perl "$cgi"`;
waitpid $pid, 0;

like($out, qr{^Status: 200 OK\r\n}, 'status relayed from the daemon');
like($out, qr{<p>hi}, 'body relayed from the daemon');

my $req = do { local (@ARGV, $/) = "$dir/request"; <> } // '';
like($req, qr{^GET /api/user/summary HTTP/1\.1\r\n}, 'sub-path taken from X-MSFE-Path');
like($req, qr{^X-MSFE-User: acct1\r\n}m, 'account name comes from LiveAPI when REMOTE_USER is unset');

my @calls = do { local @ARGV = "$dir/liveapi.log"; <> };
chomp @calls;
is($calls[0], 'new', 'LiveAPI session opened first');
is($calls[-1], 'end', 'LiveAPI session closed last');

done_testing;
