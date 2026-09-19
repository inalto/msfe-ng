# Config

Every configuration file of the scanning chain, edited in place with
validation, history and a tester — plus the maintenance tools. Everything here
is also available from the [CLI](CLI).

![Configuration files](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/config-files.png)

## The file tree

The left column lists every file under MailScanner's configuration directory
(`/etc/MailScanner`, or `/usr/mailscanner/etc` on a ConfigServer layout) plus
MSFE-NG's own `config.toml`, grouped by directory: the main files, `conf.d/`
fragments, `mcp/`, `rules/`, `custom/` and the `reports/<language>/`
notification templates. Each file carries a badge for the editor it gets and a
lock when it is read-only:

| Badge | Files | Editor |
|---|---|---|
| settings | `MailScanner.conf`, `conf.d/*.conf`, `config.toml` | form: one field per setting, comments shown in between |
| ruleset | `rules/*.rules` that sync does not generate | table: direction, pattern, value |
| file rules | `filename.rules.conf`, `filetype.rules.conf`, `archives.*` | table: action, pattern, log text, user text |
| RBL list | `spam.lists.conf` | table: name, DNS zone |
| scanners | `virus.scanners.conf` | table: name, wrapper, install dir |
| hosts | `phishing.*.custom` | one hostname per row (paste many at once) |
| text | `spamassassin.conf`, `mcp/*`, `country.domains.conf`, `reports/*` | raw text |
| 🔒 | the ten rulesets sync generates, `phishing.*.conf` (ms-update-phishing), `custom/*.pm`, `defaults`, `*.rpmnew` | view only — the lock's tooltip says who owns the file |

**Form ⇄ Raw text** switches any editor to the plain file. **+ New** creates a
`conf.d/<name>.conf` fragment (read after `MailScanner.conf`, so it overrides
it) or a new `rules/<name>.rules` ruleset. The filter box finds a file by name.

### MailScanner.conf settings

With the engine installed, every setting is typed from MailScanner's own
`ConfigDefs.pl`: yes/no settings are selects, numbers are number fields, and
settings that may take a ruleset get a **ruleset…** picker listing
`rules/*.rules`. **≠ default** marks a value that differs from the engine
default (click it to reset), **unknown** a directive the engine does not know
(a typo — MailScanner ignores it silently), **overridden in …** a setting a
`conf.d` fragment sets again. *Only settings that differ from the engine
default* shows what this host actually changed.

## Saving

Every save goes through the same pipeline, for every file kind:

1. the file's own parser checks the syntax (a table cannot hold a line
   MailScanner would misread);
2. the change is validated on a **staged copy** of the whole configuration
   directory: `MailScanner --lint` for MailScanner.conf, rulesets, file rules,
   spam lists and scanner definitions, `spamassassin --lint -p` for
   `spamassassin.conf` — the live file is untouched until the lint passes
   (`conf.d` fragments, which the engine always reads from the live directory,
   are linted right after apply and put back if that fails);
3. the previous version is copied into the file's **History**
   (`backup_dir/conf/…`, the newest 50 kept);
4. the file is written atomically, mode and owner preserved;
5. MailScanner is **restarted** for files it reads only at start
   (`MailScanner.conf`, `spamassassin.conf`, `spam.lists.conf`,
   `virus.scanners.conf`, `conf.d`, `mcp`) or **reloaded** for the ones it
   re-reads per batch (rulesets, file rules, phishing lists); the badge next to
   the file name says which.

The report under the editor shows the lint findings, the transcript and the
restart outcome. *save without lint* skips step 2 (the syntax check still
runs); *apply without restart/reload* skips step 5 — the tab then shows a
**Restart pending** banner naming the files the running engine has not read,
and the doctor warns about it. A file that changed on disk while you were
editing is refused and reloaded (`stale`), never overwritten.

**History** lists every kept version with a line diff against the current file;
**Restore this version** goes through the same pipeline, so the file you replace
is kept too. The one-time `.msfe-ng.bak` older releases wrote appears as
*original*.

## Configuration test

**Test configuration** runs `MailScanner --lint`, `spamassassin --lint` and
MSFE-NG's own cross-file checks and turns them into one list of findings,
each naming the file and setting it is about — click one to open it there:

- from **MailScanner --lint**: rulesets it cannot open, values that cannot be
  rulesets, syntax errors with line numbers, the virus scanners it found versus
  the ones `Virus Scanners` names, the phishing list sizes, whether
  SpamAssassin loaded cleanly, whether the EICAR test batch was caught;
- from **spamassassin --lint** with MailScanner's `spamassassin.conf`: lines it
  cannot parse, unknown options;
- from **MSFE-NG**: every file, directory and command a setting names exists;
  every ruleset parses and its values fit the setting's type; the scanners and
  spam lists named are defined (defunct blocklists flagged); filename patterns
  compile; `conf.d` fragments and phishing lists parse; directives the engine
  does not know (typos); files the scanning user cannot read; and the doctor
  checks that judge the same chain.

**Test with my changes** on the editor runs the same test on a staged copy
that includes what you typed but did not save — nothing goes live. The lint
runs a real test batch through the scanners, so a test takes 5–20 s.

### Test message (simulation)

Under *Maintenance & tools*: pick a sample (clean, the GTUBE spam string, the
EICAR test file as an attachment) or upload a `.eml`, and **Run simulation**
asks each stage directly — SpamAssassin with MailScanner's `spamassassin.conf`
as the scanning user (*offline* skips DNS, Razor and Pyzor), the virus scanner
through `clamdscan`, the filename/filetype rules over the attachments — then
predicts MailScanner's actions for that sender and recipient from your
rulesets (spam checks, scores, spam/high/non-spam actions, virus handling).
It is a simulation: nothing is delivered. **Send real test mail** submits the
three test messages through the MTA instead; their real verdicts appear on the
[Messages](Messages) tab once scanned.

## Snapshots: export and import

**Export snapshot** downloads one `tar.gz` holding MailScanner's configuration
directory (everything except the generated phishing lists) and `/etc/msfe-ng`
(config and policy), with a manifest; a copy stays in `backup_dir/snapshots`.
It contains `config.toml` with the database password — keep it private.

**Import snapshot** takes an uploaded file (up to about 2.9 MB through the
panel; larger ones: `msfe-ng snapshot import` on the server) or a snapshot kept
on this server, and shows every file with its status (same, changed, new,
read-only) and a diff on click. Changed and new files are preselected;
`config.toml` is not, because it is host-specific. The selection is imported as
one set — validated on a staged copy, one history copy per file, one restart or
reload — and refused as a whole if the lint fails. Policy files regenerate the
rulesets. Old `msfe-ng backup` tarballs import too.

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
