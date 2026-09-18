# Migrating from ConfigServer MSFE

MSFE-NG is a clean-room replacement for the discontinued ConfigServer
MailScanner Front-End. It reads the old flat-file settings so your policy
carries across, then takes over rule generation and the UI. It runs fine on
top of the engine ConfigServer bundled (`/usr/mailscanner`, MailScanner 5.4
under cPanel's perl) — the installer detects that tree and points
`config.toml` at its `MailScanner.conf`; the rules dir follows the conf's
`%rules-dir%`. Nothing under `/usr/msfe` is modified.

## Steps

1. **Install MSFE-NG** with the legacy front-end still in place (the import
   in step 3 needs it):
   ```sh
   curl -fsSL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | sh
   ```
   The installer prints which `MailScanner.conf` it found; the doctor's first
   line names the engine and version it will manage.
2. **Database** — Dashboard → *Create database & apply schema* (or set `db_*`
   in `/etc/msfe-ng/config.toml`, then `msfe-ng db-migrate`). You can reuse
   the existing `mailscanner` / MailWatch database: the `maillog` schema is
   compatible and migrations use `CREATE TABLE IF NOT EXISTS`.
3. **Import the old policy:**
   ```sh
   msfe-ng import /usr/msfe         # preview, as JSON
   msfe-ng import /usr/msfe --save  # write it under /etc/msfe-ng/policy
   ```
   Reads `msconfig.txt` (global settings), `mailscannerbw` (system
   white/black lists, de-duplicated), `digestdomains` and the language file.
4. **Generate the rules and switch logging over:**
   ```sh
   msfe-ng sync                        # rule files into the engine's %rules-dir%
   msfe-ng mailscanner enable-logging  # MSFE-NG's logging plugin (backup kept)
   msfe-ng service restart
   ```
5. **Verify:** `msfe-ng doctor`, `msfe-ng selftest`, then the WHM dashboard —
   new mail is logged, the Messages tab fills, a couple of domains look right
   in the user UI. Both front-ends are installed at this point; MSFE-NG's cron
   rewrites the managed rule files every 10 minutes, so make policy changes in
   MSFE-NG only from here on.

## Decommissioning ConfigServer MSFE

The doctor's *legacy ConfigServer front-end* warning stays until `/usr/msfe`,
its cron entries and its WHM registration are gone. **Its uninstaller
(`/usr/msfe/uninstall.msfe.sh`) removes the bundled MailScanner engine too**,
so pair it with installing the MailScanner RPM — in this order, which keeps
mail spooling meanwhile (Exim keeps queuing into `/var/spool/exim_incoming`;
nothing is lost, it is scanned once the new engine is up):

```sh
msfe-ng backup /root/msfe-ng-before-decommission.tar.gz
sh /usr/msfe/uninstall.msfe.sh      # legacy front-end + /usr/mailscanner engine
msfe-ng engine install              # MailScanner 5.5 RPM (refuses to run beside /usr/mailscanner — hence the order)
msfe-ng engine configure            # MailScanner.conf for Exim, shared SA state, Razor/Pyzor homes
msfe-ng doctor                      # "Exim wired to MailScanner" — if not, msfe-ng engine wire
msfe-ng mailscanner enable-logging  # the new conf needs the plugin hooked again
msfe-ng sync && msfe-ng service restart
```

`config.toml` still names `/usr/mailscanner/etc/MailScanner.conf`; MSFE-NG
follows the RPM's `/etc/MailScanner/MailScanner.conf` on its own once the
old file is gone (the doctor's first line shows which conf is in use). Tidy
the `mailscanner_conf` line when convenient.

If the legacy uninstaller also undid the two-configuration Exim wiring, the
doctor reports *Exim wired to MailScanner* as failed — `msfe-ng engine wire`
sets up the named-queue method instead.

## What carries over

| Carries over (via `import`) | Not imported |
|---|---|
| Global scan/action/score settings (`msconfig.txt`) | Per-user `~/.mailscanner*` dotfiles (set per-domain in the new UI) |
| System white/black lists (`mailscannerbw`) | The old MailControl logger (replaced by MSFE-NG's plugin) |
| Digest domains (`digestdomains`) | — |
| Existing `maillog` history (if you reuse the DB) | — |

Per-domain overrides are managed by account holders in the user UI (or by the
admin) and stored under `/etc/msfe-ng/policy/domains/`.
