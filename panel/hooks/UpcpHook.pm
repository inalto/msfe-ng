package MSFE_NG::UpcpHook;

# MSFE-NG cPanel managed hook (clean-room; not derived from any ConfigServer code).
#
# Installed to /var/cpanel/perl5/lib/MSFE_NG/UpcpHook.pm and registered with:
#   /usr/local/cpanel/bin/manage_hooks add module MSFE_NG::UpcpHook
# Removed with:
#   /usr/local/cpanel/bin/manage_hooks delete module MSFE_NG::UpcpHook
#
# M0 SCOPE: this is intentionally a safe no-op that only records that it ran.
# Its purpose in the skeleton is to prove the hook register/deregister path so
# uninstall is verifiably clean. The real work (keeping MailScanner's Perl deps
# installed across cPanel updates) lands in M2, alongside the Exim hooks which
# are deliberately NOT shipped yet because they patch the live mail flow.

use strict;
use warnings;

sub describe {
    return [
        {
            category => 'System',
            event    => 'upcp',
            stage    => 'post',
            hook     => 'MSFE_NG::UpcpHook::run',
            exectype => 'module',
        },
    ];
}

sub run {
    my ( $context, $data ) = @_;
    # No-op in M0. Log best-effort; never block the upcp run.
    if ( open my $fh, '>>', '/var/log/msfe-ng.log' ) {
        print {$fh} scalar(localtime) . " upcp post-hook ran (M0 no-op)\n";
        close $fh;
    }
    return ( 1, 'MSFE-NG upcp hook ok' );
}

1;
