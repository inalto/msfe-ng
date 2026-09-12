#!/bin/sh
# Publish docs/wiki/*.md to the GitHub wiki (a separate git repo).
# GitHub only creates the wiki repo once a first page has been made in the
# web UI, so do that once (Wiki tab → "Create the first page" → Save), then:
#   packaging/publish-wiki.sh
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
WIKI_URL="${MSFE_NG_WIKI_URL:-git@github.com:inalto/msfe-ng.wiki.git}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q "$WIKI_URL" "$TMP/wiki"
cp "$REPO"/docs/wiki/*.md "$TMP/wiki/"
cd "$TMP/wiki"
git add -A
if git diff --cached --quiet; then
    echo "wiki already up to date"
    exit 0
fi
git -c user.name="MSFE-NG" -c user.email="noreply@inalto.com" \
    commit -q -m "Sync wiki from docs/wiki ($(git -C "$REPO" rev-parse --short HEAD))"
git push -q origin HEAD
echo "wiki published"
