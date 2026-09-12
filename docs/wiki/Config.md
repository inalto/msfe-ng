# Config

Server-side files and maintenance. Everything here is also available from the
[CLI](CLI).

## Configuration files

![Configuration files](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/config-files.png)

Edit `MailScanner.conf` or MSFE-NG's own `config.toml` in place. The
**visual editor** shows every setting as a labelled field with the file's
comments in between and a filter box; changed fields are outlined and **Save
changes** lists them for confirmation — only those lines are rewritten,
comments and everything else stay untouched. **Raw text** switches to a plain
full-file editor. A one-time `.msfe-ng.bak` backup of each file is kept next
to it. MailScanner reads its config only at startup, so reload it from the
[Service](Service) tab after changing `MailScanner.conf`.

## Generated rulesets

The `*.rules` files MSFE-NG writes on every sync, read-only — click one to
view it. To add rules, use the [Rules](Rules) tab; to change what is generated,
change the policy in [Settings](Settings).

## Spam checks

**Enable spam checks for all domains** sets MailScanner's global
`Spam Checks = yes` (the authoritative switch that overrides any per-domain
rule) and restarts MailScanner.

![Maintenance cards](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/config-maintenance.png)

## Database & Bayes maintenance

- **Backup now** — timestamped SQL dump into `backup_dir`
  (default `/opt/msfe-ng/backups`).
- **Fix common problems** — applies pending migrations, then OPTIMIZE/ANALYZE
  on the MSFE-NG tables.
- **Bayes repair** — expires old tokens and syncs the SpamAssassin Bayes DB.
- **Bayes recreate** — takes a database backup, then wipes Bayes so it retrains
  from scratch (all ham/spam training is lost).

## Queue auto-clean

Every 5 minutes the monitor cron removes messages from the **delivery queue**
that match an enabled rule:

| Rule | Removes |
|---|---|
| Remove frozen messages older than N hours | frozen (undeliverable, unbounceable) mail |
| Remove bounces older than N hours | null-sender (∅) mail |
| Remove messages with spam score ≥ N | mail the cPanel SpamAssassin ACL scored at or above N |

`0` disables a rule; **everything ships off**. The scanning queue is never
touched, so unscanned mail cannot be deleted. **Preview (dry-run)** lists what
would go right now; **Clean now** runs the rules immediately; **Save rules**
stores them for the cron. The last automatic run is summarised above the
fields.

## Telegram alerts

Create a bot with @BotFather and paste its **token** (never shown again once saved —
the field just says *configured*; leave it empty to keep it) and the **chat id** (your own
id or a group). Then set thresholds (`0` = off):

- **delivery queue reaches N messages**
- **scanning queue stuck for N minutes** — mail waiting for MailScanner that
  never gets scanned (the classic "scanner wedged" incident)
- **one account sends N messages/hour** — outbound bursts, the usual sign of a
  compromised mailbox; the alert names the account
- **repeat the same alert at most every N minutes**

**Send test message** confirms the bot and chat id work. The doctor warns if
Telegram is only half configured.
