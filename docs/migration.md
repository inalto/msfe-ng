# Migrating from the original ConfigServer MSFE

MSFE-NG is a clean-room replacement for the discontinued ConfigServer MailScanner
Front-End (MSFE). It reads MSFE's flat-file settings so you can carry your policy
across, then takes over rule generation and the UI. It shares MailScanner and the
`maillog` database conventions, so it slots into an existing MailScanner install.

> No original MSFE code is used or required. MSFE-NG only *reads* the old config
> files as data. See `CONTRIBUTING.md`.

## Before you start

- Take a backup of `/usr/msfe`, `/etc/MailScanner`, and your MailScanner rules dir.
- Note your DB credentials (the original stored them in
  `/usr/msfe/mailcontrol/mailcontrol.txt`); MSFE-NG uses its own
  `/etc/msfe-ng/config.toml`.

## Steps

1. **Install MSFE-NG** (see `admin-guide.md`). It installs under its own
   namespace (`/opt/msfe-ng`, `/etc/msfe-ng`) and does not touch `/usr/msfe`.
   It detects ConfigServer's engine (`/usr/mailscanner/etc/MailScanner.conf`)
   and writes the rules where that engine reads them.

2. **Point it at the database.** Set `db_*` in `/etc/msfe-ng/config.toml`. You can
   reuse the existing `mailscanner`/MailWatch database (the `maillog` schema is
   compatible) or create a fresh `msfe_ng` database. Then:
   ```sh
   msfe-ng db-migrate
   ```
   Migrations use `CREATE TABLE IF NOT EXISTS`, so pointing at an existing
   compatible database is safe.

3. **Import the old policy:**
   ```sh
   msfe-ng import /usr/msfe --save
   ```
   This reads `msconfig.txt` (global settings), `mailscannerbw` (system
   white/black lists, de-duplicated), `digestdomains`, and the language file, and
   writes them as MSFE-NG policy under `/etc/msfe-ng/policy/`. Run without
   `--save` first to preview the parsed result as JSON.

4. **Generate the rules and switch logging over:**
   ```sh
   msfe-ng sync                       # writes MailScanner rule files
   msfe-ng mailscanner enable-logging # swaps logging to MSFE-NG's plugin
   systemctl restart mailscanner
   ```

5. **Verify:** `msfe-ng selftest`, then open the WHM dashboard and confirm new
   mail is logged and the dashboard populates. Check a couple of domains in the
   user UI.

6. **Decommission the old front-end.** Once satisfied, remove the legacy plugin
   with its own uninstaller (`/usr/msfe/uninstall.msfe.sh`). MSFE-NG does not
   depend on any `/usr/msfe` file after import — but **that uninstaller also
   removes the bundled `/usr/mailscanner` engine and drops the `mailscanner`
   MySQL database (the MailControl history)**: run `msfe-ng db import-legacy`
   before it, or use the guided migration, which does. Then install the MailScanner
   RPM right after it (`msfe-ng engine install`, `msfe-ng engine configure`,
   check the wiring with `msfe-ng doctor`, re-run `msfe-ng mailscanner
   enable-logging`). The wiki's *Migration* page has the exact order; the
   doctor's *legacy ConfigServer front-end* warning reminds you until it is done.

## What carries over vs. not

| Carries over (via `import`) | Not imported |
|---|---|
| Global scan/action/score settings (`msconfig.txt`) | The obfuscated UI/licensing (gone by design) |
| System white/black lists (`mailscannerbw`) | Per-user `~/.mailscanner*` dotfiles (set per-domain in the new UI) |
| Digest domains (`digestdomains`) | The old MailControl logger (replaced by MSFE-NG's plugin) |
| Existing `maillog` history — the guided migration dumps the `mailscanner` database and copies its rows into MSFE-NG's `maillog` before ConfigServer's uninstaller drops it (`msfe-ng db import-legacy` does the same by hand) | — |

Per-domain overrides are now managed by account holders in the user UI (or by the
admin), and stored under `/etc/msfe-ng/policy/domains/`.
