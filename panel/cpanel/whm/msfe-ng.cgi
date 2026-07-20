#!/usr/local/cpanel/3rdparty/bin/perl
#WHMADDON:msfe_ng:MSFE-NG MailScanner Front-End
#ACLS:all
#
# MSFE-NG WHM entry CGI (clean-room; not derived from any ConfigServer code).
#
# This is a thin proxy: it enforces the WHM root ACL, then forwards the request
# to the msfe-ngd daemon over its Unix socket and streams back the HTML. All
# real logic lives in the Rust daemon.
use strict;
use warnings;
use lib '/usr/local/cpanel';
use IO::Socket::UNIX ();
require Whostmgr::ACLS;

my $SOCKET = $ENV{MSFE_NG_SOCKET} || '/var/run/msfe-ng/msfe-ng.sock';

Whostmgr::ACLS::init_acls();
unless ( Whostmgr::ACLS::hasroot() ) {
    print "Content-type: text/html\r\n\r\n";
    print "You do not have access to MSFE-NG.\n";
    exit;
}

print "Content-type: text/html; charset=utf-8\r\n\r\n";
print proxy('/whm');

# Minimal HTTP/1.1 GET over the daemon's Unix socket; returns the response body.
sub proxy {
    my ($path) = @_;
    my $sock = IO::Socket::UNIX->new( Type => IO::Socket::UNIX::SOCK_STREAM(), Peer => $SOCKET );
    return _daemon_down() unless $sock;
    print {$sock} "GET $path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    local $/;
    my $raw = <$sock>;
    close $sock;
    return _daemon_down() unless defined $raw;
    my ( undef, $body ) = split /\r\n\r\n/, $raw, 2;
    return defined $body ? $body : _daemon_down();
}

sub _daemon_down {
    return
        "<h2>MSFE-NG daemon is not responding</h2>"
      . "<p>The <code>msfe-ngd</code> service does not appear to be running. "
      . "Try <code>systemctl restart msfe-ng</code>.</p>";
}
