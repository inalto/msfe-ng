package Cpanel::API::MSFE_NG;

# MSFE-NG cPanel UAPI module (clean-room; not derived from any ConfigServer code).
#
# Installed to /usr/local/cpanel/Cpanel/API/MSFE_NG.pm and invoked from the
# Jupiter template as Uapi.execute('MSFE_NG', 'msDisplay', ...). It is a thin
# proxy to the msfe-ngd daemon: it forwards the (unprivileged, per-user) request
# to the daemon over its Unix socket and returns the rendered HTML in
# result.data.output. Per-user context/privilege separation is added in M4.

use strict;
use warnings;
use IO::Socket::UNIX ();
use Socket qw(SOCK_STREAM);

our $VERSION = '0.0.1';

my $SOCKET = $ENV{MSFE_NG_SOCKET} || '/var/run/msfe-ng/msfe-ng.sock';

sub msDisplay {
    my ( $args, $result ) = @_;
    my $html = _proxy('/user');
    $result->data( { output => $html } );
    $result->message('ok') if $result->can('message');
    return 1;
}

sub _proxy {
    my ($path) = @_;
    my $sock = IO::Socket::UNIX->new(
        Type => SOCK_STREAM,
        Peer => $SOCKET,
    );
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
    return '<p>MSFE-NG is temporarily unavailable. Please try again shortly.</p>';
}

1;
