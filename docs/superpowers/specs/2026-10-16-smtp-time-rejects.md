# Reject at SMTP time (match rules in Exim's DATA ACL)

Today a match rule acts inside MailScanner: the message is accepted, queued,
scanned, scored 100 and then dropped by the high-spam action, and the source
is banned a minute later from the log. A bot that sends the same subject a
thousand times still costs a thousand accepted messages and scans. The
reporter wants the rule to bite **on the connection**: Exim refuses the
message at `DATA` with a 550, nothing is queued, MailScanner never sees it,
and the source is banned from the reject log.

## Rule flag

`MatchRule` gets `smtp: bool` ("Also reject at SMTP time"). Allowed for
`subject`, `from`, `to`, `header:<Name>`; **not** for `body` (the DATA ACL
sees only `$message_body`'s first bytes — refuse the combination in the
form and in the API validation). Default off; existing rules unchanged.
`block` and `ban_secs` keep their meaning: the SA rule stays in place as the
second line of defence (a message that slipped past Exim, e.g. via an
authenticated hop, still scores 100).

## Exim fragment (`crates/msfe-core/src/smtpdeny.rs`)

Generated on every rules save and on `sync`, to
`/etc/msfe-ng/exim/smtp-deny.conf` (0644, root), included from cPanel's
custom ACL hook for the message check **before** cPanel's own scans:
`/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_begin_check_message_pre`
containing one line `.include_if_exists /etc/msfe-ng/exim/smtp-deny.conf`
(the same mechanism as the named-queue hook in `ACL_MAIL_PRE_BLOCK`;
**verify the directory name on a host first** — `ls
/usr/local/cpanel/etc/exim/acls/` — and that the block sits in `acl_smtp_data`
of the built `exim.conf`, after `buildeximconf`). Deleting the fragment is
the kill switch; the hook file is harmless without it.

Fragment, one stanza per enabled rule with `smtp = true`:

```
# Managed by MSFE-NG (Rules → Auto-ban match rules); edits are overwritten.
deny  !authenticated = *
      !hosts         = : 127.0.0.0/8 : ::1
      !senders       = wildlsearch;/etc/msfe-ng/exim/smtp-deny-whitelist
      condition      = ${if match{$h_subject:}{<regex>}}
      message        = Rejected by local policy (MSFE-NG rule #<id>)
      log_message    = MSFE-NG rule #<id>: <field> <matcher> <pattern, clipped>
```

- `<regex>`: the same `pattern_to_regex` output autoban uses for SA, as a
  Perl/PCRE regex Exim's `match` takes; `contains` → quoted literal with
  `(?i)`; `$h_subject:` is the decoded header (RFC 2047) — document that
  Exim decodes to the configured charset. `from` → `$h_from:` **and**
  `$sender_address` (either matches); `to` → `$h_to:`/`$h_cc:` plus
  `$recipients`; `header:X` → `$h_X:`. Escape `}`/`\\`/`$` so a pattern can
  never break out of the string expansion (test with hostile patterns).
- `smtp-deny-whitelist`: one line per pattern of the global whitelist
  (`spam.whitelist.rules` patterns, `*@domain` and `user@domain`), so
  whitelisted senders are never refused. Regenerated with the fragment.
- Authenticated submissions and loopback are exempt — a local user's reply
  quoting a banned subject must still go out.
- Exim's `message` is what the sender's MTA sees; keep it short and neutral.

## Validation and install (like localsub)

`smtpdeny::install(cfg, dry)` writes the hook line (idempotent), writes the
fragment, runs `/scripts/buildeximconf`, requires `exim -bV` to pass and the
fragment to appear in `exim -bP -C` … no: check the built `/etc/exim.conf`
contains the `.include_if_exists` line; on failure remove the fragment,
rebuild, report. `exim -bV` alone does not expand includes' regexes at parse
time for `condition`, so also run `exim -bh 203.0.113.5` with a scripted
session? Too heavy — instead expand each stanza's `condition` once with
`exim -be` on a sample subject to catch a broken regex before writing
(reject the save with the Exim error, as the SA save already rejects a bad
regex via perl). `MSFE_NG_SKIP_EXIM_CMDS`, `MSFE_NG_EXIM_ACL_DIR` for tests.

Saving rules (`PUT /api/autoban/rules`) regenerates the fragment when any
rule has `smtp = true`, else removes it (and the hook line stays). A reload
of Exim is **not** needed: Exim reads its configuration per connection;
`.include_if_exists` is read when the daemon starts, so the fragment's
*content* is re-read… verify: Exim reads the whole configuration at daemon
start and per `-bd` child? (It re-reads on SIGHUP; a running daemon does not
notice a changed included file.) → run `/scripts/restartsrv_exim` after a
change to the fragment, and say so in the UI ("Exim restarted").

## Ban from the reject log

`autoban::run` (the minute cron) gains a second source: tail
`/var/log/exim_rejectlog` since the last offset (`kv autoban_rejectlog_pos`
+ inode; `deliverylog::parse_rejectlog_line` already parses lines) for
`MSFE-NG rule #<id>` and bans the `H=[ip]` for that rule's `ban_secs` with
the same exclusions (own IPs, private, csf.allow, already denied) and the
same `autoban` table row (reason `smtp`, `sample_id` null, detail the
subject). Count 1: the first refused message bans. Telegram line as usual.

## Visibility

Refused messages never reach the Messages tab. The Rules tab card gets a
column **SMTP** (✓ when the rule rejects at SMTP time) and a block **Refused
at SMTP time** under the table: the last 50 rejects with our tag from
`exim_rejectlog` (time, IP with ipLink, rule #, subject), via
`GET /api/autoban/rejects?limit=50`, and a per-rule count for the last 24 h
in the table. The Config card shows the same column.

## Doctor

"SMTP-time rejects wired": fragment present but the hook line missing from
the built `exim.conf` (cPanel moved the include point) → Warn with the
rebuild as fix; Ok otherwise; silent when no rule uses it.

## Docs

Wiki Rules (new section), Config → Auto-ban, Troubleshooting ("a sender
gets 550 Rejected by local policy"), CLI (`msfe-ng autoban rejects`).

## Tests

Fragment text for each field; hostile patterns cannot escape the
expansion; whitelist file from patterns; rejectlog tailing with rotation
(inode change → start from 0); API refuses `smtp` on `body`; install under
the env vars with a tempdir.
