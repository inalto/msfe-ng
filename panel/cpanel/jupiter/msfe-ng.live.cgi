#!/usr/local/cpanel/3rdparty/bin/perl
# MSFE-NG cPanel end-user entry (clean-room; not derived from any ConfigServer code).
#
# Transparent proxy to msfe-ngd for the logged-in cPanel account. Runs in the
# user's cPanel session, so it injects the authenticated account name as
# X-MSFE-User; the daemon then scopes everything to that user's domains. The
# daemon sub-path comes from the SPA's X-MSFE-Path header, else PATH_INFO, else
# /user (the initial page).
use strict;
use warnings;
use IO::Socket::UNIX ();

my $SOCKET = $ENV{MSFE_NG_SOCKET} || '/var/run/msfe-ng/msfe-ng.sock';

# The authenticated cPanel account (cPanel sets REMOTE_USER for user CGIs).
my $user = $ENV{REMOTE_USER} || $ENV{USER} || '';
$user =~ s/[^A-Za-z0-9_.\-]//g;    # defensive: safe charset only

my $path   = $ENV{HTTP_X_MSFE_PATH} || $ENV{PATH_INFO} || '/user';
my $method = $ENV{REQUEST_METHOD} || 'GET';
my $body   = '';
read( STDIN, $body, $ENV{CONTENT_LENGTH} ) if ( $ENV{CONTENT_LENGTH} || 0 ) > 0;

my $sock = IO::Socket::UNIX->new(
    Type => IO::Socket::UNIX::SOCK_STREAM(),
    Peer => $SOCKET,
);
unless ($sock) {
    print "Status: 502 Bad Gateway\r\nContent-type: text/html\r\n\r\n";
    print "<p>MSFE-NG is temporarily unavailable.</p>";
    exit;
}
my $clen = length $body;
print {$sock} "$method $path HTTP/1.1\r\nHost: localhost\r\n"
  . "X-MSFE-User: $user\r\nContent-Length: $clen\r\nConnection: close\r\n\r\n$body";

local $/;
my $raw = <$sock>;
close $sock;
my ( $head, $rbody ) = split /\r\n\r\n/, ( $raw // '' ), 2;
$head  //= '';
$rbody //= '';
my ($status) = $head =~ m{^HTTP/1\.\d\s+(\d{3}[^\r\n]*)};
my ($ctype)  = $head =~ m{^Content-Type:\s*([^\r\n]+)}im;
print "Status: " . ( $status || '200 OK' ) . "\r\n";
print "Content-type: " . ( $ctype || 'text/html; charset=utf-8' ) . "\r\n\r\n";
print $rbody;
