#!/bin/sh
# MSFE-NG preflight check (csftest.pl-style). Verifies the host can run MSFE-NG
# before install touches anything. Safe to run standalone: it changes nothing.
# Exit 0 = good to go; non-zero = a hard requirement is missing.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

fail=0
check() { # check "label" "command..."
    label="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$label"; else err "$label"; fail=1; fi
}
softcheck() {
    label="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$label"; else warn "$label (optional — needed later)"; fi
}

info "MSFE-NG preflight"

check   "running as root"            test "$(id -u)" = "0"
check   "perl present"               command -v perl
check   "perl IO::Socket::UNIX"      perl -MIO::Socket::UNIX -e1
check   "systemd (systemctl) present" command -v systemctl

panel="$(detect_panel)"
if [ "$panel" = "none" ]; then
    warn "no cPanel or DirectAdmin detected — daemon will install but no panel UI will be wired"
else
    ok "control panel: $panel"
fi

# MailScanner engine is an external dependency (not shipped). Warn only.
softcheck "MailScanner engine present" sh -c 'command -v MailScanner || test -d /etc/MailScanner || test -d /usr/local/cpanel/3rdparty/mailscanner'
softcheck "MySQL/MariaDB client present" sh -c 'command -v mysql || command -v mariadb'

if [ "$fail" -ne 0 ]; then
    err "preflight failed — resolve the items marked 'err' above"
    exit 1
fi
ok "preflight passed"
