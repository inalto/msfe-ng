#!/bin/sh
# Build a self-contained MSFE-NG release tarball:
#   dist/msfe-ng-<version>.tar.gz  →  extract, run packaging/install.sh
# Layout inside the tarball: bin/ web/ panel/ db/ packaging/ VERSION
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
cd "$REPO"

VER="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' Cargo.toml | head -1)"
[ -n "$VER" ] || { echo "cannot read version from Cargo.toml"; exit 1; }

echo "== building release binaries =="
cargo build --release --workspace

OUT="$REPO/dist/msfe-ng-$VER"
rm -rf "$OUT"
mkdir -p "$OUT/bin"
cp target/release/msfe-ngd target/release/msfe-ng "$OUT/bin/"
cp -r web panel db packaging "$OUT/"
cp LICENSE README.md "$OUT/" 2>/dev/null || true
echo "$VER" > "$OUT/VERSION"

TARBALL="$REPO/dist/msfe-ng-$VER.tar.gz"
tar czf "$TARBALL" -C "$REPO/dist" "msfe-ng-$VER"
( cd "$REPO/dist" && sha256sum "msfe-ng-$VER.tar.gz" > "msfe-ng-$VER.tar.gz.sha256" )

echo "== built $TARBALL =="
ls -l "$TARBALL" "$TARBALL.sha256"
