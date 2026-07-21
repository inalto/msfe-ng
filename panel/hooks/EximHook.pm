package MSFE_NG::EximHook;

# MSFE-NG cPanel managed hook (clean-room; not derived from any ConfigServer code).
#
# Fires when cPanel rebuilds Exim (RPM::Versions/exim) and re-syncs the
# MailScanner rule files so a rebuild never leaves them stale. It shells out to
# the MSFE-NG CLI; all logic lives there.
#
# Registered with:  /usr/local/cpanel/bin/manage_hooks add module MSFE_NG::EximHook
# Removed with:     /usr/local/cpanel/bin/manage_hooks delete module MSFE_NG::EximHook
#
# NOTE: this does NOT patch cPanel's Exim.pm. Toggling MailScanner scanning via
# Exim (the legacy /etc/exiscandisable mechanism) is mail-flow management and is
# deferred to M5, where it can be validated on a real cPanel host.

use strict;
use warnings;

sub describe {
    return [
        {
            category => 'RPM::Versions',
            event    => 'exim',
            stage    => 'pre',
            hook     => 'MSFE_NG::EximHook::run',
            exectype => 'module',
        },
    ];
}

sub run {
    my ( $context, $data ) = @_;
    system('/opt/msfe-ng/bin/msfe-ng', 'sync');
    return ( 1, 'MSFE-NG exim hook: rules synced' );
}

1;
