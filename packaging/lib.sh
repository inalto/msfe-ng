#!/bin/sh
# Shared constants and helpers for the MSFE-NG install/uninstall scripts.
# POSIX sh. Sourced by install.sh and uninstall.sh — do not run directly.

# ----- install locations (our own namespace; never /usr/msfe) -----------------
PREFIX="/opt/msfe-ng"
BINDIR="$PREFIX/bin"
WEBROOT="$PREFIX/web"
CONFDIR="/etc/msfe-ng"
LOGFILE="/var/log/msfe-ng.log"
SOCKET_DIR="/var/run/msfe-ng"
SOCKET="$SOCKET_DIR/msfe-ng.sock"
SYSTEMD_UNIT="/etc/systemd/system/msfe-ng.service"
MANIFEST="$CONFDIR/install.manifest"

# ----- cPanel paths -----------------------------------------------------------
CP_MARKER="/usr/local/cpanel/version"
CP_APPCONF="/var/cpanel/apps/msfe-ng.conf"
CP_WHM_CGI_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/msfe-ng"
CP_UAPI="/usr/local/cpanel/Cpanel/API/MSFE_NG.pm"
CP_JUP_DIR="/usr/local/cpanel/base/frontend/jupiter/msfe_ng"
CP_DYNUI="/usr/local/cpanel/base/frontend/jupiter/dynamicui/dynamicui_msfe_ng.conf"
CP_HOOK_DIR="/var/cpanel/perl5/lib/MSFE_NG"

# ----- DirectAdmin paths ------------------------------------------------------
DA_MARKER="/usr/local/directadmin/directadmin"
DA_PLUGIN_DIR="/usr/local/directadmin/plugins/msfe_ng"

# ----- logging ----------------------------------------------------------------
if [ -t 1 ]; then
    C_OK="\033[32m"; C_WARN="\033[33m"; C_ERR="\033[31m"; C_DIM="\033[2m"; C_OFF="\033[0m"
else
    C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_OFF=""
fi
info() { printf "%b==>%b %s\n" "$C_DIM" "$C_OFF" "$*"; }
ok()   { printf "%b ok %b %s\n" "$C_OK" "$C_OFF" "$*"; }
warn() { printf "%bwarn%b %s\n" "$C_WARN" "$C_OFF" "$*" >&2; }
err()  { printf "%berr %b %s\n" "$C_ERR" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
    [ "$(id -u)" = "0" ] || die "must run as root"
}

# Detect the control panel. Echoes: cpanel | directadmin | none
detect_panel() {
    if [ -e "$CP_MARKER" ]; then
        echo cpanel
    elif [ -e "$DA_MARKER" ]; then
        echo directadmin
    else
        echo none
    fi
}

# Locate the built binaries. Checks, in order: a sibling dist/ dir (release
# tarball), the cargo target/release dir (dev checkout), then $PATH. Echoes the
# directory containing msfe-ngd, or empty if not found.
find_bindir() {
    _here="$1"   # repo/tarball root
    # release tarball ships bin/; dev checkout builds target/release
    for d in "$_here/bin" "$_here/dist/bin" "$_here/../dist/bin" "$_here/target/release" "$_here/../target/release"; do
        # -f, not -x: on noexec mounts (cPanel securetmp /tmp) -x is false even
        # with the exec bit set. install(1) sets 0755 on the copies anyway.
        if [ -f "$d/msfe-ngd" ] && [ -f "$d/msfe-ng" ]; then
            echo "$d"; return 0
        fi
    done
    return 1
}
