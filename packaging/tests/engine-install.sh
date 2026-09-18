#!/bin/sh
# Contract test for packaging/engine-install.sh: the installer must recognise
# an engine that is not the RPM's /usr/sbin/MailScanner (ConfigServer's
# /usr/mailscanner tree, issue #8) instead of installing a second one next to
# it, and must verify perl modules with the perl that engine runs under.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../engine-install.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# a ConfigServer-style engine whose shebang names its own perl + lib
FAKE_PERL="$TMP/perl"
printf '#!/bin/sh\necho "fake-perl $*" >> "%s/perl.log"\n' "$TMP" > "$FAKE_PERL"
chmod 0755 "$FAKE_PERL"
ENGINE="$TMP/usr/mailscanner/usr/sbin/MailScanner"
mkdir -p "$(dirname "$ENGINE")"
printf '#!%s -U -I %s/lib\n' "$FAKE_PERL" "$TMP" > "$ENGINE"
chmod 0755 "$ENGINE"

out="$(MSFE_NG_ENGINE_DRYRUN=1 MSFE_NG_MS_BIN="$ENGINE" HOME="$TMP" sh "$SCRIPT" 2>&1)" || {
    echo "FAIL: installer exited non-zero:"; echo "$out"; exit 1
}
case "$out" in
    *"already installed"*"$ENGINE"*) ;;
    *) echo "FAIL: expected 'already installed at $ENGINE', got:"; echo "$out"; fails=1 ;;
esac

# the perl modules are verified with the perl that engine runs under
case "$out" in
    *"engine perl: $FAKE_PERL -I $TMP/lib"*) ;;
    *) echo "FAIL: expected the engine's perl to be reported, got:"; echo "$out"; fails=1 ;;
esac

[ "$fails" = 0 ] && echo "OK: engine-install.sh adapts to the installed engine"
exit "$fails"
