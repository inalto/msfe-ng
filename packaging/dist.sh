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

# Build fully static binaries (musl) so the release runs on any glibc,
# old or new (EL8 servers ship glibc 2.28 and reject EL9-built binaries).
TARGET="x86_64-unknown-linux-musl"
rustup target add "$TARGET" >/dev/null 2>&1 || true

echo "== building release binaries ($TARGET) =="
cargo build --release --workspace --target "$TARGET"

OUT="$REPO/dist/msfe-ng-$VER"
rm -rf "$OUT"
mkdir -p "$OUT/bin"
cp "target/$TARGET/release/msfe-ngd" "target/$TARGET/release/msfe-ng" "$OUT/bin/"
cp -r web panel db packaging "$OUT/"
cp LICENSE README.md "$OUT/" 2>/dev/null || true
echo "$VER" > "$OUT/VERSION"

TARBALL="$REPO/dist/msfe-ng-$VER.tar.gz"
tar czf "$TARBALL" -C "$REPO/dist" "msfe-ng-$VER"
( cd "$REPO/dist" && sha256sum "msfe-ng-$VER.tar.gz" > "msfe-ng-$VER.tar.gz.sha256" )

echo "== built $TARBALL =="
ls -l "$TARBALL" "$TARBALL.sha256"
