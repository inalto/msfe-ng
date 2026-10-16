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
