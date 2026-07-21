#!/bin/sh
# MSFE-NG uninstaller (M0). Reverses install.sh completely and leaves the system
# as it was. Unlike the original MSFE uninstaller, the AppConfig removal here is
# unconditional (the original's test was inverted and only removed the conf when
# it was already gone).
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

require_root

panel="$(detect_panel)"
info "MSFE-NG uninstall (panel: $panel)"

# ---- stop service ------------------------------------------------------------
if [ -e "$SYSTEMD_UNIT" ]; then
    info "stopping service"
    systemctl disable --now msfe-ng.service 2>/dev/null || true
    rm -f "$SYSTEMD_UNIT"
    systemctl daemon-reload 2>/dev/null || true
    ok "service removed"
fi

# ---- panel deregistration ----------------------------------------------------
cpanel_uninstall() {
    info "deregistering cPanel plugin"
    /usr/local/cpanel/bin/manage_hooks delete module MSFE_NG::UpcpHook 2>/dev/null || true
    /usr/local/cpanel/bin/manage_hooks delete module MSFE_NG::EximHook 2>/dev/null || true
    if [ -x /usr/local/cpanel/bin/unregister_appconfig ]; then
        /usr/local/cpanel/bin/unregister_appconfig msfe_ng 2>/dev/null || true
    fi
    # Unconditionally remove the AppConfig file (fixes the original's inverted test).
    rm -f "$CP_APPCONF"
    rm -rf "$CP_WHM_CGI_DIR" "$CP_JUP_DIR" "$CP_HOOK_DIR"
    rm -f  "$CP_UAPI" "$CP_DYNUI"
    [ -x /usr/local/cpanel/scripts/rebuild_sprites ] && /usr/local/cpanel/scripts/rebuild_sprites jupiter || true
    ok "cPanel plugin removed"
}

da_uninstall() {
    info "removing DirectAdmin plugin"
    rm -rf "$DA_PLUGIN_DIR"
    ok "DirectAdmin plugin removed"
}

# Deregister for the panel present now. If none is detected (e.g. panel later
# removed), still sweep any leftover plugin files from a prior install.
case "$panel" in
    cpanel)      cpanel_uninstall ;;
    directadmin) da_uninstall ;;
    none)
        if [ -e "$CP_APPCONF" ] || [ -d "$CP_JUP_DIR" ] || [ -d "$CP_HOOK_DIR" ]; then
            cpanel_uninstall
        fi
        if [ -d "$DA_PLUGIN_DIR" ]; then
            da_uninstall
        fi
        ;;
esac

# ---- unhook MailScanner logging (best effort, restores MailScanner.conf) -----
if [ -x "$BINDIR/msfe-ng" ]; then
    info "disabling MailScanner logging (if enabled)"
    "$BINDIR/msfe-ng" mailscanner disable-logging >/dev/null 2>&1 || true
fi

# ---- core files --------------------------------------------------------------
info "removing core files"
rm -f  /usr/local/bin/msfe-ng
rm -f  /etc/cron.d/msfe-ng
rm -rf "$PREFIX"
rm -f  "$SYSTEMD_UNIT"
rm -rf "$SOCKET_DIR"

# ---- config (prompt-free: keep unless --purge) -------------------------------
# The MySQL database holds the mail log (user data) and is NEVER dropped
# automatically. Surface the manual command instead.
db_name="$(sed -n 's/^[[:space:]]*db_name[[:space:]]*=[[:space:]]*"\{0,1\}\([^"#]*\)"\{0,1\}.*/\1/p' "$CONFDIR/config.toml" 2>/dev/null | head -1)"
[ -n "$db_name" ] && info "to also drop the mail-log database:  mysql -e 'DROP DATABASE \`$db_name\`;'"

if [ "${1:-}" = "--purge" ]; then
    rm -rf "$CONFDIR" "$LOGFILE"
    ok "config and logs purged (database left intact — drop it manually if desired)"
else
    info "keeping config in $CONFDIR (use --purge to remove)"
    rm -f "$MANIFEST"
fi

echo
ok "MSFE-NG uninstalled."
