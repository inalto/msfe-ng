#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:msfe_ng:MailscannerNG
#ACLS:all
#
# MSFE-NG WHM entry CGI (clean-room; not derived from any ConfigServer code).
#
# Transparent proxy to the msfe-ngd daemon over its Unix socket. Enforces the WHM
# root ACL, then forwards the request and relays the daemon's response verbatim.
#
# The daemon sub-path comes from the `X-MSFE-Path` request header (set by the
# SPA's fetch calls, e.g. "/api/stats/summary?days=7"), falling back to PATH_INFO
# and finally to "/whm" for the initial page load. Using a header keeps the same
# shim working on cPanel and DirectAdmin without relying on PATH_INFO plumbing.
use strict;
use warnings;
use lib '/usr/local/cpanel';
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);
require Whostmgr::ACLS;

my $SOCKET = $ENV{MSFE_NG_SOCKET} || '/var/run/msfe-ng/msfe-ng.sock';

Whostmgr::ACLS::init_acls();
unless ( Whostmgr::ACLS::hasroot() ) {
    print "Status: 403 Forbidden\r\nContent-type: text/plain\r\n\r\nNo access to MSFE-NG.\n";
    exit;
}

my $path   = $ENV{HTTP_X_MSFE_PATH} || $ENV{PATH_INFO} || '/whm';
my $method = $ENV{REQUEST_METHOD} || 'GET';

# Read the request body (for PUT/POST) from STDIN.
my $body = '';
if ( ( $ENV{CONTENT_LENGTH} || 0 ) > 0 ) {
    read( STDIN, $body, $ENV{CONTENT_LENGTH} );
}

proxy( $method, $path, $body );

# Forward to the daemon and relay status + Content-Type + body back to the browser.
sub proxy {
    my ( $method, $path, $body ) = @_;
    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $SOCKET,
    );
    unless ($sock) {
        print "Status: 502 Bad Gateway\r\nContent-type: text/html\r\n\r\n";
        print "<h2>MSFE-NG daemon is not responding</h2>"
          . "<p>Try <code>systemctl restart msfe-ng</code>.</p>";
        return;
    }
    my $clen = length $body;
    print {$sock}
      "$method $path HTTP/1.1\r\nHost: localhost\r\nContent-Length: $clen\r\nConnection: close\r\n\r\n$body";

    local $/;
    my $raw = <$sock>;
    close $sock;
    my ( $head, $rbody ) = split /\r\n\r\n/, ( $raw // '' ), 2;
    $head  //= '';
    $rbody //= '';

    my ($status) = $head =~ m{^HTTP/1\.\d\s+(\d{3}[^\r\n]*)};
    my ($ctype)  = $head =~ m{^Content-Type:\s*([^\r\n]+)}im;
    $status ||= '200 OK';
    $ctype  ||= 'text/html; charset=utf-8';

    print "Status: $status\r\nContent-type: $ctype\r\n\r\n";
    print $rbody;
}
