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

The engine installer (also `msfe-ng engine install`) fetches the MailScanner
v5 RPM from the project's GitHub release, verifies it, runs `ms-configure`
unattended and fills in perl modules EL does not package. ClamAV: cPanel's
own (`cpanel-clamav`) is kept when present — EPEL's packages conflict with
it; otherwise EPEL's clamd + freshclam are installed. `engine configure`
points MailScanner at whichever clamd socket exists.

What it does: preflight check, installs the daemon + CLI under `/opt/msfe-ng`,
seeds `/etc/msfe-ng/config.toml` (pointing `mailscanner_conf` at the engine it
finds: the MailScanner RPM's `/etc/MailScanner`, or ConfigServer's
`/usr/mailscanner` tree), starts the `msfe-ng` systemd service,
registers the WHM/DA plugin and the cron jobs (rule sync every 10 min, queue
monitor every 5 min, digests and housekeeping nightly). On upgrade it keeps
your config, applies new DB migrations (`msfe-ng db-migrate --status` lists
them; 1.0 adds the delivery-monitor tables) and restarts the daemon.

Check it: `msfe-ng health`, then open **WHM → Plugins → MSFE-NG**. Later
upgrades: the same one-liner, `msfe-ng upgrade`, or **Service → Updates →
Upgrade MSFE-NG now** in the UI.

## First-time setup

Until the mail log has data, the Dashboard shows a **Finish setup** card with
two buttons — both safe to re-run:

1. **Create database & apply schema** — creates a MySQL/MariaDB database and
   user (default `msfe_ng`) with a generated password, saves it into the
   MSFE-NG config and applies the schema. Nothing outside MSFE-NG's own
   database is touched. (CLI: set `db_*` in `config.toml`, then `msfe-ng db-migrate`.)
2. **Enable message logging** — installs the MSFE-NG logging plugin into
   MailScanner's `Custom Functions Dir` (read from `MailScanner.conf`, so
   ConfigServer-style layouts under `/usr/mailscanner` work too; a one-time
   backup of `MailScanner.conf` is kept) and restarts MailScanner, so every
   scanned message is recorded. (CLI: `msfe-ng mailscanner enable-logging`.)

Then, on the [Service](Service) tab:

3. **Configure for Exim** — points `MailScanner.conf` at Exim's queues, run-as
   user and sendmail paths (backup kept).
4. **Wire Exim → MailScanner** — routes incoming mail through an Exim named
   queue that MailScanner scans. Use **Preview wiring (dry-run)** first if you
   want to see the exact changes. Instantly reversible with **Unwire**.
5. **Test that everything is OK** — MailScanner's own self-check.

The doctor banner at the top of every tab tells you if any link of the chain
is still unhealthy, with the fix.

Migrating from the original ConfigServer MSFE? Install on top of it — the
installer finds its engine's `MailScanner.conf` under `/usr/mailscanner` —
then `msfe-ng import /usr/msfe --save` reads the old config files. See
[Migration](Migration), including the order for decommissioning the old
front-end (its uninstaller removes the engine too).

## Backup, uninstall

```sh
msfe-ng snapshot export /root/msfe-ng-snapshot.tar.gz   # MailScanner etc tree + /etc/msfe-ng, with a manifest
msfe-ng snapshot import /root/msfe-ng-snapshot.tar.gz --dry-run   # compare first, then without --dry-run
msfe-ng backup /root/msfe-ng-backup.tar.gz     # /etc/msfe-ng only (alias of snapshot export --only msfe)
msfe-ng restore /root/msfe-ng-backup.tar.gz
/opt/msfe-ng/packaging/uninstall.sh            # add --purge to remove config too
```

A snapshot is also what moves a setup to another server: export here, import
there (the [Config](Config) tab does both with a per-file diff).

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
