# MSFE-NG administrator guide

MSFE-NG is an open-source MailScanner front-end for cPanel/WHM and DirectAdmin.
This guide covers install, configuration, and day-to-day operation. Run all
commands as root on the mail server.

## Install

```sh
# one-liner bootstrap (downloads + verifies the latest release tarball):
curl -sSfL https://raw.githubusercontent.com/OWNER/msfe-ng/main/packaging/get.sh | sh

# …or from a checkout:
cargo build --release --workspace
sudo packaging/install.sh
```

The installer runs a preflight check, installs the daemon + CLI under
`/opt/msfe-ng`, writes `/etc/msfe-ng/config.toml`, starts the `msfe-ng` service,
registers the WHM/DA plugin, and installs the cron jobs. Re-running it upgrades
in place (keeps config, applies new DB migrations, restarts the service).

Verify: `msfe-ng health` and **WHM → Plugins → MSFE-NG**.

## First-time setup

1. **Database** — create a MySQL/MariaDB database and user, then set the creds in
   `/etc/msfe-ng/config.toml` (`db_name`, `db_user`, `db_pass`, …) and apply the
   schema:
   ```sh
   msfe-ng db-migrate            # msfe-ng db-migrate --status to inspect
   ```
2. **Message logging** — hook the logging plugin into MailScanner (edits
   `MailScanner.conf`, backing it up), then restart MailScanner:
   ```sh
   msfe-ng mailscanner enable-logging
   systemctl restart mailscanner
   ```
3. **Import an existing MSFE (optional)** — see `migration.md`:
   ```sh
   msfe-ng import /usr/msfe --save
   ```
4. **Generate rules** — `msfe-ng sync` (also runs every 10 minutes via cron).

## Daily operation

- **WHM dashboard** — traffic tiles + volume/top-sender charts over the mail log.
- **Settings** — global spam/virus policy (scores, actions, SpamBox). Saving
  regenerates the MailScanner rules and reloads the scanner.
- **Lists** — system-wide white/black lists.
- **SpamBox** — `msfe-ng spambox enable` writes an Exim fragment; include it with
  `.include_if_exists /etc/msfe-ng/spambox.exim` and rebuild Exim.
- **Digests** — configured per domain (`digestdomains`); `msfe-ng digest` runs
  daily via cron. Preview with `msfe-ng digest --dry-run`.
- **Housekeeping** — `msfe-ng housekeeping` prunes old log rows (retention from
  the `cleanmysql` setting); runs nightly.
- **Scanning toggle** — `msfe-ng exim status | enable-scanning | disable-scanning`
  (uses `/etc/exiscandisable`).
- **Self-test** — `msfe-ng selftest` sends GTUBE/EICAR/clean mail through the MTA.

## Backup / upgrade / uninstall

```sh
msfe-ng backup /root/msfe-ng-backup.tar.gz     # config + policy
msfe-ng restore /root/msfe-ng-backup.tar.gz

sudo packaging/install.sh                       # upgrade in place
sudo packaging/uninstall.sh                     # remove (add --purge for config)
```

Uninstall unhooks MailScanner logging, deregisters the plugin, and removes all
MSFE-NG files. It never drops the database automatically — it prints the
`DROP DATABASE` command for you to run if you want the mail log gone.

## Config reference (`/etc/msfe-ng/config.toml`)

`db_host/db_port/db_name/db_user/db_pass`, `mailscanner_conf`,
`mailscanner_custom_dir`, `mailscanner_rules_dir`, `spambox_conf`,
`quarantine_dir`, `socket`, `webroot`. See comments in the seeded file.
