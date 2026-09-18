#!/bin/sh
# Contract test for packaging/lib.sh's detect_ms_conf: the installer must seed
# config.toml with the conf of the engine actually present (a ConfigServer
# install keeps it under /usr/mailscanner) and must respect an operator's own
# value only while that file exists — never lint a path that is not there.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# operator's value is kept while that file exists
printf 'MTA = exim\n' > "$TMP/MailScanner.conf"
printf 'mailscanner_conf = "%s"\n' "$TMP/MailScanner.conf" > "$TMP/config.toml"
got="$(detect_ms_conf "$TMP/config.toml")"
[ "$got" = "$TMP/MailScanner.conf" ] || { echo "FAIL: expected the configured conf, got $got"; fails=1; }

# a configured path that does not exist falls through to the known locations
printf 'mailscanner_conf = "%s"\n' "$TMP/missing.conf" > "$TMP/config.toml"
got="$(detect_ms_conf "$TMP/config.toml")"
case "$got" in
    /etc/MailScanner/MailScanner.conf|/usr/mailscanner/etc/MailScanner.conf) ;;
    *) echo "FAIL: expected a known location, got $got"; fails=1 ;;
esac

# no config.toml at all: same fallback, never an empty string
got="$(detect_ms_conf "$TMP/absent.toml")"
[ -n "$got" ] || { echo "FAIL: empty conf path without config.toml"; fails=1; }

[ "$fails" = 0 ] && echo "OK: detect_ms_conf follows the installed engine"
exit "$fails"
