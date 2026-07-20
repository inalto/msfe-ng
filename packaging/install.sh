#!/bin/sh
# MSFE-NG installer (M0). Installs the daemon + CLI, wires the control-panel
# plugin, and starts the service. Idempotent: safe to re-run. Reverse with
# uninstall.sh. Installs only under our own namespace (/opt/msfe-ng, /etc/msfe-ng,
# panel plugin dirs) so removal is unambiguous.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
# shellcheck source=lib.sh
. "$HERE/lib.sh"

require_root

# ---- preflight ---------------------------------------------------------------
sh "$HERE/preflight.sh" || die "preflight failed"

# ---- locate or build binaries ------------------------------------------------
BINSRC="$(find_bindir "$REPO" || true)"
if [ -z "${BINSRC:-}" ]; then
    if command -v cargo >/dev/null 2>&1; then
        info "binaries not found — building with cargo (release)"
        ( cd "$REPO" && cargo build --release --workspace )
        BINSRC="$REPO/target/release"
    else
        die "no prebuilt binaries and cargo not installed. Build on a dev box (cargo build --release) or ship a dist/ dir."
    fi
fi
[ -x "$BINSRC/msfe-ngd" ] || die "msfe-ngd not found in $BINSRC"
info "using binaries from $BINSRC"

panel="$(detect_panel)"
info "control panel: $panel"

# ---- core install ------------------------------------------------------------
info "installing core files"
mkdir -p "$BINDIR" "$WEBROOT" "$CONFDIR" "$SOCKET_DIR"
install -m 0755 "$BINSRC/msfe-ngd" "$BINDIR/msfe-ngd"
install -m 0755 "$BINSRC/msfe-ng"  "$BINDIR/msfe-ng"
# convenience symlink so admins can just run `msfe-ng`
ln -sf "$BINDIR/msfe-ng" /usr/local/bin/msfe-ng
cp -a "$REPO/web/." "$WEBROOT/"
[ -f "$LOGFILE" ] || { : > "$LOGFILE"; chmod 0640 "$LOGFILE"; }
# seed a default config only if absent (never clobber operator changes)
if [ ! -f "$CONFDIR/config.toml" ]; then
    cat > "$CONFDIR/config.toml" <<EOF
# MSFE-NG configuration (M0 skeleton). Real options land in M1.
panel = "$panel"
socket = "$SOCKET"
webroot = "$WEBROOT"
EOF
fi
ok "core files installed to $PREFIX"

# ---- service -----------------------------------------------------------------
info "installing systemd service"
install -m 0644 "$REPO/packaging/systemd/msfe-ng.service" "$SYSTEMD_UNIT"
systemctl daemon-reload
systemctl enable --now msfe-ng.service
ok "service enabled and started"

# ---- panel wiring ------------------------------------------------------------
cpanel_install() {
    info "registering WHM plugin (cPanel)"
    mkdir -p "$CP_WHM_CGI_DIR" "$CP_JUP_DIR" "$CP_HOOK_DIR" "$(dirname "$CP_UAPI")" "$(dirname "$CP_DYNUI")"
    install -m 0700 "$REPO/panel/cpanel/whm/msfe-ng.cgi" "$CP_WHM_CGI_DIR/msfe-ng.cgi"
    install -m 0644 "$REPO/panel/cpanel/msfe-ng.png"     "$CP_WHM_CGI_DIR/msfe-ng.png"
    install -m 0644 "$REPO/panel/cpanel/msfe-ng.conf"    "$CP_APPCONF"
    install -m 0644 "$REPO/panel/cpanel/uapi/MSFE_NG.pm" "$CP_UAPI"
    install -m 0644 "$REPO/panel/cpanel/jupiter/index.html.tt" "$CP_JUP_DIR/index.html.tt"
    install -m 0644 "$REPO/panel/cpanel/jupiter/install.json"  "$CP_JUP_DIR/install.json"
    install -m 0644 "$REPO/panel/cpanel/msfe-ng.png"           "$CP_JUP_DIR/msfe-ng.png"
    install -m 0644 "$REPO/panel/cpanel/jupiter/dynamicui_msfe_ng.conf" "$CP_DYNUI"
    install -m 0644 "$REPO/panel/hooks/UpcpHook.pm"      "$CP_HOOK_DIR/UpcpHook.pm"

    /usr/local/cpanel/bin/register_appconfig "$CP_APPCONF" || warn "register_appconfig failed"
    /usr/local/cpanel/bin/manage_hooks add module MSFE_NG::UpcpHook || warn "manage_hooks add failed"
    [ -x /usr/local/cpanel/scripts/rebuild_sprites ] && /usr/local/cpanel/scripts/rebuild_sprites jupiter || true
    [ -x /usr/local/cpanel/bin/build_locale_databases ] && /usr/local/cpanel/bin/build_locale_databases || true
    warn "enable the 'msfe_ng' feature in the accounts' Feature List to show the user icon"
    ok "cPanel plugin registered"
}

da_install() {
    info "registering DirectAdmin plugin"
    mkdir -p "$DA_PLUGIN_DIR/admin" "$DA_PLUGIN_DIR/user"
    install -m 0644 "$REPO/panel/directadmin/plugin.conf"     "$DA_PLUGIN_DIR/plugin.conf"
    install -m 0755 "$REPO/panel/directadmin/admin/index.raw" "$DA_PLUGIN_DIR/admin/index.raw"
    install -m 0755 "$REPO/panel/directadmin/user/index.raw"  "$DA_PLUGIN_DIR/user/index.raw"
    ok "DirectAdmin plugin installed to $DA_PLUGIN_DIR"
}

case "$panel" in
    cpanel)      cpanel_install ;;
    directadmin) da_install ;;
    none)        warn "no panel detected — skipping plugin registration (daemon still installed)" ;;
esac

# ---- cron (schedule disabled until M2) ---------------------------------------
install -m 0644 "$REPO/packaging/cron/msfe-ng" /etc/cron.d/msfe-ng

# ---- manifest ----------------------------------------------------------------
{
    echo "# MSFE-NG install manifest — $(date)"
    echo "panel=$panel"
    echo "$PREFIX"
    echo "$CONFDIR"
    echo "$SYSTEMD_UNIT"
    echo "/usr/local/bin/msfe-ng"
    echo "/etc/cron.d/msfe-ng"
    if [ "$panel" = cpanel ]; then
        echo "$CP_APPCONF"; echo "$CP_WHM_CGI_DIR"; echo "$CP_UAPI"
        echo "$CP_JUP_DIR"; echo "$CP_DYNUI"; echo "$CP_HOOK_DIR"
    elif [ "$panel" = directadmin ]; then
        echo "$DA_PLUGIN_DIR"
    fi
} > "$MANIFEST"

# ---- verify ------------------------------------------------------------------
info "verifying daemon health"
i=0
while [ "$i" -lt 10 ]; do
    if "$BINDIR/msfe-ng" health >/dev/null 2>&1; then
        ok "daemon healthy: $("$BINDIR/msfe-ng" health)"
        break
    fi
    i=$((i + 1)); sleep 0.3
done
[ "$i" -lt 10 ] || die "daemon did not become healthy — check: journalctl -u msfe-ng"

echo
ok "MSFE-NG installed."
case "$panel" in
    cpanel)      info "Open WHM > Plugins > 'MSFE-NG MailScanner Front-End'." ;;
    directadmin) info "Open DirectAdmin > Admin/User level > MSFE-NG." ;;
esac
info "Remove everything with: $HERE/uninstall.sh"
