#!/bin/sh
# Contract test for packaging/exim-shim.sh: MailScanner (usr/sbin/MailScanner,
# 5.5.3) decides "long Exim message ids" with
#     @out = `$eximcommand -bV`; $ver = (split / /, $out[0])[2]; $ver >= 4.97
# Perl numifies "4.100" to 4.1, so from Exim 4.100 that probe silently flips to
# short ids and MailScanner misfiles every outgoing spool file. The shim must
# make that exact Perl expression true for every Exim >= 4.97 and false below.
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
SHIM="$HERE/../exim-shim.sh"
[ -f "$SHIM" ] || { echo "FAIL: $SHIM missing"; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAKE="$TMP/exim"
fails=0

# MailScanner's probe, verbatim.
probe() {
    perl -e '@out = `$ARGV[0] -bV`; @line = split(/ /, $out[0]); $ver = $line[2];
             print(($ver >= 4.97) ? "long" : "short")' "$SHIM"
}

# fake_exim <first line> : a stand-in /usr/sbin/exim printing that -bV banner
fake_exim() {
    printf '#!/bin/sh\n[ "$1" = "-bV" ] && { printf "%%s\\n" "%s"; printf "Support for: TLS\\n"; exit 0; }\necho "args: $*"\n' "$1" > "$FAKE"
    chmod 0755 "$FAKE"
}

check() { # check <expected> <banner>
    fake_exim "$2"
    got="$(MSFE_NG_REAL_EXIM="$FAKE" probe)"
    if [ "$got" = "$1" ]; then
        echo "ok   $1 <- $2"
    else
        echo "FAIL want $1 got $got <- $2"; fails=$((fails + 1))
    fi
}

check long  "Exim version 4.100 #2 built 20-Aug-2026 10:00:00"
check long  "Exim version 4.100.1 #2 built 20-Aug-2026 10:00:00"
check long  "Exim version 4.99.2 #2 built 01-Jun-2026 10:00:00"
check long  "Exim version 4.98 #2 built 01-Jul-2024 10:00:00"
check long  "Exim version 4.97 #2 built 01-Nov-2023 10:00:00"
check long  "Exim version 5.0 #1 built 01-Jan-2027 10:00:00"
check short "Exim version 4.96 #2 built 01-Jun-2022 10:00:00"
check short "Exim version 4.9 #2 built 01-Jan-2020 10:00:00"

# A banner the shim does not understand must pass through untouched.
fake_exim "Something unexpected here"
out="$(MSFE_NG_REAL_EXIM="$FAKE" sh "$SHIM" -bV | head -1)"
[ "$out" = "Something unexpected here" ] && echo "ok   passthrough" \
    || { echo "FAIL passthrough: $out"; fails=$((fails + 1)); }

# Lines after the banner survive.
fake_exim "Exim version 4.100 #2 built 20-Aug-2026 10:00:00"
MSFE_NG_REAL_EXIM="$FAKE" sh "$SHIM" -bV | grep -q '^Support for: TLS$' && echo "ok   rest of -bV kept" \
    || { echo "FAIL rest of -bV lost"; fails=$((fails + 1)); }

# The real version stays visible in the banner (for humans reading logs).
MSFE_NG_REAL_EXIM="$FAKE" sh "$SHIM" -bV | head -1 | grep -q '4\.100' && echo "ok   real version shown" \
    || { echo "FAIL real version hidden"; fails=$((fails + 1)); }

# Any other invocation is exec'd through unchanged.
out="$(MSFE_NG_REAL_EXIM="$FAKE" sh "$SHIM" -bp -C /etc/exim.conf)"
[ "$out" = "args: -bp -C /etc/exim.conf" ] && echo "ok   other args exec'd" \
    || { echo "FAIL other args: $out"; fails=$((fails + 1)); }

[ "$fails" -eq 0 ] && echo "all shim checks passed" || { echo "$fails check(s) failed"; exit 1; }
