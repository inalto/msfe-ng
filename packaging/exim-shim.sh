#!/bin/sh
# msfe-ng-exim: the `Exim Command` MailScanner.conf points at (installed to
# /opt/msfe-ng/bin/msfe-ng-exim by install.sh, set by `msfe-ng engine configure`).
#
# MailScanner uses `Exim Command` for exactly one thing: `exim -bV` at startup,
# to decide whether Exim writes long message ids (>= 4.97). Its test is
#     $ver = (split / /, $out[0])[2];  $ver >= 4.97
# and Perl numifies "4.100" to 4.1 — so from Exim 4.100 (cPanel 138) MailScanner
# silently falls back to short ids: every outgoing spool file lands in the
# wrong split-spool subdirectory (nothing delivers) and every quarantined or
# archived body is copied from the wrong offset. MailScanner 5.5.3 is the
# pinned engine and carries no fix, so the banner is normalised here instead of
# patching rpm-owned Perl.
#
# Only the `-bV` banner line is touched, and only when the naive numeric read
# would be wrong; everything else is exec'd through to the real binary.
EXIM="${MSFE_NG_REAL_EXIM:-/usr/sbin/exim}"

if [ "$#" -eq 1 ] && [ "$1" = "-bV" ]; then
    out="$("$EXIM" -bV)"
    rc=$?
    printf '%s\n' "$out" | awk '
        NR == 1 && $1 == "Exim" && $2 == "version" {
            n = split($3, v, ".")
            major = v[1] + 0; minor = (n >= 2) ? v[2] + 0 : 0
            # Perl reads the leading numeric prefix: "4.100" -> 4.1. Rewrite
            # only when that reading disagrees with the real version.
            if ((major > 4 || (major == 4 && minor >= 97)) && ($3 + 0) < 4.97) {
                real = $3
                $3 = "4.99"
                print $0 " (msfe-ng shim: real " real ")"
                next
            }
        }
        { print }'
    exit "$rc"
fi

exec "$EXIM" "$@"
