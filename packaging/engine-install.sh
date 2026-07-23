#!/bin/sh
# MSFE-NG MailScanner engine installer (RHEL-family).
#
# Installs the official MailScanner v5 engine from the MailScanner project's
# GitHub releases (rpm + sha256 verification) and its dependencies via the
# engine's own ms-configure in unattended mode, with cPanel-safe choices:
# no MTA is ever installed (cPanel ships its own Exim), ClamAV and SELinux
# are left alone. The engine service is left DISABLED — mail flow does not
# change until the explicit Exim wiring step.
#
# Safe to re-run. Env overrides:
#   MSFE_NG_MS_VERSION    engine version tag (default below)
#   MSFE_NG_ENGINE_FORCE  =1 reinstall even if the engine is present
#   MSFE_NG_ENGINE_DRYRUN =1 print what would run without changing anything
set -eu

MS_VERSION="${MSFE_NG_MS_VERSION:-5.5.3-2}"
BASE="https://github.com/MailScanner/v5/releases/download/$MS_VERSION"
RPM="MailScanner-$MS_VERSION.rhel.noarch.rpm"
DRY="${MSFE_NG_ENGINE_DRYRUN:-0}"

info() { printf '==> %s\n' "$*"; }
die()  { printf 'err  %s\n' "$*" >&2; exit 1; }
run()  {
    if [ "$DRY" = 1 ]; then printf 'dry-run: %s\n' "$*"; else "$@"; fi
}

[ "$(id -u)" = 0 ] || [ "$DRY" = 1 ] || die "run as root"
command -v curl >/dev/null 2>&1 || die "curl is required"
if command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum
else die "dnf/yum not found — this installer supports RHEL-family systems only"
fi

if command -v MailScanner >/dev/null 2>&1 || [ -x /usr/sbin/MailScanner ]; then
    info "MailScanner engine already installed"
    if [ "${MSFE_NG_ENGINE_FORCE:-0}" != 1 ]; then
        info "nothing to do (set MSFE_NG_ENGINE_FORCE=1 to reinstall)"
        exit 0
    fi
fi

# Work under $HOME (/root in real runs), not /tmp (cPanel securetmp noexec).
work="${HOME:-/root}/.msfe-ng-engine.$$"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"
cd "$work"

info "downloading MailScanner $MS_VERSION"
curl -fsSL -o "$RPM" "$BASE/$RPM"
curl -fsSL -o sha256sums "$BASE/sha256sums"
grep -E "[[:space:]]$RPM\$" sha256sums | sha256sum -c - || die "checksum FAILED for $RPM"
info "checksum OK"

info "installing engine package"
run "$PKG" -y install "./$RPM"

info "installing engine dependencies (ms-configure, unattended)"
# Every flag is passed so ms-configure never prompts. cPanel-safe choices:
#   --MTA=none          cPanel ships its own Exim; never install a distro MTA
#   --installClamav=N   leave AV to the admin (clamd is picked up if present)
#   --SELPermissive=N   never weaken SELinux as a side effect
run /usr/sbin/ms-configure \
    --MTA=none \
    --installEPEL=Y \
    --installPowerTools=Y \
    --installCPAN=Y \
    --installClamav=N \
    --configClamav=N \
    --installTNEF=Y \
    --installUnrar=N \
    --installidn=Y \
    --SELPermissive=N \
    --ramdiskSize=0

# Mail flow must not change on install: the engine stays disabled until the
# admin wires it into Exim and starts it deliberately.
run systemctl disable --now mailscanner 2>/dev/null || true

info "MailScanner engine installed (service left disabled)"
info "verify the configuration with:  MailScanner --lint"
info "mail flow is UNCHANGED — Exim wiring is a separate, explicit step"
