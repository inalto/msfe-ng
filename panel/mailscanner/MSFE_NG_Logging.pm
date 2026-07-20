package MailScanner::CustomConfig;

# MSFE-NG MailScanner logging plugin (clean-room).
#
# STATUS: M0 stub — SHIPPED BUT NOT WIRED IN. The M0 installer does NOT edit
# MailScanner.conf, so this file is inert until M1. In M1 this becomes the real
# per-message logger that INSERTs into the `maillog` MySQL table, modeled on
# MailWatch's MailScanner_perl_scripts/MailWatch.pm (reference only — no code
# copied). It will hand message metadata to the msfe-ngd daemon (or INSERT via
# DBI) at scan time.
#
# MailScanner loads this by calling the hook sub names below; they must exist
# with these exact names. In M0 they are safe no-ops.

use strict;
use warnings;

sub InitMSFENGLogging {
    my ($config) = @_;
    MailScanner::Log::InfoLog("MSFE-NG logging: M0 stub loaded (no-op)")
      if defined &MailScanner::Log::InfoLog;
    return;
}

sub EndMSFENGLogging {
    return;
}

sub MSFENGLogging {
    my ($message) = @_;
    # M1: serialize $message metadata → maillog. No-op for now.
    return;
}

1;
