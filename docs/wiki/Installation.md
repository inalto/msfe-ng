# Installation

Everything runs as **root on the mail server** (cPanel/WHM or DirectAdmin, with
Exim). The installer is idempotent: re-running it upgrades in place.

## Install or upgrade

```sh
# download + verify the latest release, then install
curl -fsSL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | sh

# no MailScanner on the box yet? let the installer set it up too
curl -fsSL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | MSFE_NG_WITH_ENGINE=1 sh
```

What it does: preflight check, installs the daemon + CLI under `/opt/msfe-ng`,
seeds `/etc/msfe-ng/config.toml`, starts the `msfe-ng` systemd service,
registers the WHM/DA plugin and the cron jobs (rule sync every 10 min, queue
monitor every 5 min, digests and housekeeping nightly). On upgrade it keeps
your config, applies new DB migrations and restarts the daemon.

Check it: `msfe-ng health`, then open **WHM → Plugins → MSFE-NG**.

## First-time setup

Until the mail log has data, the Dashboard shows a **Finish setup** card with
two buttons — both safe to re-run:

1. **Create database & apply schema** — creates a MySQL/MariaDB database and
   user (default `msfe_ng`) with a generated password, saves it into the
   MSFE-NG config and applies the schema. Nothing outside MSFE-NG's own
   database is touched. (CLI: set `db_*` in `config.toml`, then `msfe-ng db-migrate`.)
2. **Enable message logging** — installs the MSFE-NG logging plugin into
   MailScanner (a one-time backup of `MailScanner.conf` is kept) and restarts
   MailScanner, so every scanned message is recorded. (CLI:
   `msfe-ng mailscanner enable-logging`.)

Then, on the [Service](Service) tab:

3. **Configure for Exim** — points `MailScanner.conf` at Exim's queues, run-as
   user and sendmail paths (backup kept).
4. **Wire Exim → MailScanner** — routes incoming mail through an Exim named
   queue that MailScanner scans. Use **Preview wiring (dry-run)** first if you
   want to see the exact changes. Instantly reversible with **Unwire**.
5. **Test that everything is OK** — MailScanner's own self-check.

The doctor banner at the top of every tab tells you if any link of the chain
is still unhealthy, with the fix.

Migrating from the original ConfigServer MSFE? `msfe-ng import /usr/msfe --save`
reads its old config files — see `docs/migration.md` in the repository.

## Backup, uninstall

```sh
msfe-ng backup /root/msfe-ng-backup.tar.gz     # config + policy
msfe-ng restore /root/msfe-ng-backup.tar.gz
/opt/msfe-ng/packaging/uninstall.sh            # add --purge to remove config too
```

Uninstall unhooks the logging plugin, deregisters the plugin and removes all
MSFE-NG files. It never drops the database — it prints the `DROP DATABASE`
command for you to run if you want the mail log gone.

If a server was uninstalled with a release older than 0.0.39 and WHM still
shows *Plugins → MailscannerNG*, the menu cache was rebuilt before the last
descriptor was removed. Refresh it once:

```sh
rm -f /var/cpanel/apps/msfe-ng.conf /var/cpanel/apps/msfe_ng.conf
/usr/local/cpanel/bin/refresh_plugin_cache && /usr/local/cpanel/scripts/rebuild_whm_chrome
```
