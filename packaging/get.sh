#!/bin/sh
# MSFE-NG bootstrap installer.
#
#   curl -sSfL https://raw.githubusercontent.com/OWNER/msfe-ng/main/packaging/get.sh | sh
#
# Downloads the latest release tarball, verifies its checksum, and runs the
# installer. Run as root on a cPanel or DirectAdmin host. Set MSFE_NG_VERSION to
# pin a version, or MSFE_NG_REPO to use a fork.
set -eu

REPO="${MSFE_NG_REPO:-OWNER/msfe-ng}"
VERSION="${MSFE_NG_VERSION:-latest}"

[ "$(id -u)" = "0" ] || { echo "run as root"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required"; exit 1; }
command -v tar  >/dev/null 2>&1 || { echo "tar is required"; exit 1; }

if [ "$VERSION" = "latest" ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/v$VERSION"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

echo "== downloading MSFE-NG ($VERSION) from $REPO =="
# The release publishes a single versioned tarball; resolve its name if pinned.
name="msfe-ng.tar.gz"
if [ "$VERSION" != "latest" ]; then name="msfe-ng-$VERSION.tar.gz"; fi
curl -sSfL "$base/$name" -o msfe-ng.tar.gz
if curl -sSfL "$base/$name.sha256" -o sums 2>/dev/null; then
    sed "s#$name#msfe-ng.tar.gz#" sums | sha256sum -c - || { echo "checksum FAILED"; exit 1; }
    echo "checksum OK"
fi

tar xzf msfe-ng.tar.gz
dir="$(find . -maxdepth 1 -type d -name 'msfe-ng-*' | head -1)"
[ -n "$dir" ] || { echo "unexpected tarball layout"; exit 1; }

echo "== installing =="
sh "$dir/packaging/install.sh"
