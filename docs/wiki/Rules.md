# Rules

![Rules](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/rules.png)

MailScanner decides most things through *ruleset* files
(`/etc/MailScanner/rules/*.rules`). MSFE-NG generates them from policy on
every sync, so hand edits would be overwritten — this tab is how you add rules
that survive.

Pick a **ruleset** (spam.scanning, virus.scanning, spam.action, spamhigh.action,
virus.delivery, spam.score, spamhigh.score, archive, spam.whitelist,
spam.blacklist).

## Auto-ban match rules

The first card lists the auto-ban **match rules** — the ones **Ban rule…**
creates from a message in the Messages list or from the sender view: a
pattern on the subject, the sender, the recipient, a header or the body,
whether a match blocks delivery (the message scores 100 and follows the
domain's high-spam action) and for how long the sending IP is banned in csf
by the minute cron. Edit, delete or add rules here; the same table sits in
the Config tab's *Auto-ban spam sources* card next to the thresholds, the dry
run and the recent bans, and both ban modals link straight to this card
(**All match rules →**). Details on how the rules work: [Config →
Auto-ban](Config#auto-ban-spam-sources-csf).

### Reject at SMTP time

A match rule normally acts inside MailScanner: the message is accepted,
queued, scanned, scored 100 and dropped by the high-spam action, and the
source is banned a minute later from the log. A bot that sends the same
subject a thousand times still costs a thousand accepted messages and
scans. **Also reject at SMTP time** (in the rule form; column **SMTP** in
the table) makes the rule bite on the connection instead: Exim refuses the
message at `DATA` with

```
550 Rejected by local policy (MSFE-NG rule #3)
```

nothing is queued, MailScanner never sees it, and the minute cron bans the
source from `/var/log/exim_rejectlog` (reason `smtp` in the ban history,
the same exclusions as every other ban: own, loopback and private
addresses, `csf.allow`, already denied). The SpamAssassin rule stays in
place as the second line of defence — a message that slips past Exim (an
authenticated hop, a server not running the fragment) still scores 100.

What is refused and what is not:

- The flag is allowed for **subject**, **from**, **to** and **header**
  rules, not for **body** (Exim's DATA ACL sees the headers and the
  envelope; `$message_body` is only the first few hundred bytes). The form
  greys the box out for a body rule and the API refuses the combination.
- *From* matches the `From:` header **or** the envelope sender; *to*
  matches `To:`, `Cc:` **or** the envelope recipients; *subject* and a
  named header match the decoded header (RFC 2047 words decoded by Exim
  into its `headers_charset`, ISO-8859-1 by default — a pattern on
  non-Latin text may not match at SMTP time while the SpamAssassin rule
  still does).
- **Never refused**: authenticated submissions (a local user replying to a
  banned subject still sends), connections from loopback, and every
  sender on the global whitelist or a domain's whitelist (Lists tab),
  written to `/etc/msfe-ng/exim/smtp-deny-whitelist` as `user@domain`,
  `*@domain` and `*@*.domain` keys. IP and regex whitelist entries do not
  carry over (the file says which were skipped).
- The pattern is the same regex the SpamAssassin rule uses (*contains* is a
  case-insensitive literal), checked by perl **and** by `exim -be` when you
  save, and escaped so that nothing in it can reach Exim's string
  expansion.

How it is wired: every save (and every `msfe-ng sync`) writes one `deny`
stanza per flagged rule to `/etc/msfe-ng/exim/smtp-deny.conf`, puts the
line `.include_if_exists /etc/msfe-ng/exim/smtp-deny.conf` into cPanel's
custom ACL hook for the message check
(`/usr/local/cpanel/etc/exim/acls/ACL_CHECK_MESSAGE_PRE_BLOCK/custom_begin_check_message_pre`,
once; `/scripts/buildeximconf` is run that first time), validates with
`exim -bV` (a refused configuration is rolled back) and **restarts Exim**
(`/scripts/restartsrv_exim`) whenever the fragment or the whitelist
changed — a running Exim does not re-read an included file. The toast
says "Exim restarted". When no rule carries the flag any more the two
files are removed and Exim restarted; the include line stays and includes
nothing. The block **Refused at SMTP time** under the table shows the
wiring state and the last 50 refused messages from the reject log (time,
IP, rule, sender, subject); the SMTP column counts the last 24 hours.

**Verify on your host before relying on it.** The block directory above is
cPanel's documented hook point for `acl_smtp_data`, but MSFE-NG cannot
check its name from a build machine. The first time you flag a rule, run
`msfe-ng doctor`: *SMTP-time rejects wired* says **ok** when the built
`/etc/exim.conf` includes the fragment, and warns with the checklist when
it does not — `ls /usr/local/cpanel/etc/exim/acls/` must list
`ACL_CHECK_MESSAGE_PRE_BLOCK`; if cPanel names the block differently, set
`MSFE_NG_SMTP_DENY_BLOCK=<name>` in the daemon's environment and the cron,
re-save a rule and rebuild. Then send yourself a test message with the
banned subject from an outside account: it must bounce with the 550 and
appear in the block, never in the Messages tab.

Kill switch: `msfe-ng autoban smtp-off` removes the fragment and restarts
Exim (the rules keep their flag and the next save or sync puts the
fragment back — untick the box to keep them off). CLI: `msfe-ng autoban
rejects [--limit n] [--json]` lists the refused messages; `msfe-ng
autoban rules` ends with the wiring verdict.

## Custom rules

A structured editor — no tabs to get wrong. Each rule has a **direction**
(`To:`, `From:`, `FromOrTo:`, `FromAndTo:`), a **pattern** (`*@domain`,
`user@domain`), an optional **and-direction / and-pattern**, and the **value**
(`yes`, `no`, `deliver`, `delete`, `forward addr@x delete`, a score…).
Custom rules are merged *ahead of* the generated domain rules (first match
wins). **Save & apply** rewrites the file and reloads MailScanner if it changed.

Every generated ruleset ends with an explicit `FromOrTo: default …` line, so
mail matching no rule is decided in the file and the config test has nothing
to warn about: the whitelist and blacklist end with `default no` (a sender on
no list is simply not listed — the same decision MailScanner would take
without the line). The one exception is `archive.rules`: `Archive Mail` takes
a path and has no value meaning *off*, so leaving `default` out is the only
way to archive nothing but the configured domains; the config test reports
that as OK *by design*.

## Live ruleset file

The file as MailScanner currently reads it, parsed. Lines that are neither
generated from policy nor in the custom store are flagged **stray** — they were
edited by hand and the next sync will wipe them. **Adopt strays as custom
rules** copies them into the custom store (normalised); **Borrow all current
rules** does the same for every ruleset at once. Unparsable lines are flagged
**bad**.

Related CLI: `msfe-ng sync [--dry-run]`, `msfe-ng rules lint`,
`msfe-ng rules adopt [--from <dir>]`.
