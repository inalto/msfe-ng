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

Once the import is verified (`msfe-ng import /usr/msfe --save`, or the
Settings tab shows your policy), the old front-end can go. Which tool depends
on the engine:

- **Still on ConfigServer's bundled engine (`/usr/mailscanner` exists)?**
  Use the guided migration below — its uninstaller removes the engine as
  well, and the RPM cannot be installed beside it, so the two happen in one
  sequence.
- **Already on the MailScanner RPM (or any other engine)?** **Service →
  Decommission ConfigServer MSFE**, or `msfe-ng legacy decommission --run`
  (`msfe-ng legacy decommission` alone prints what would happen). It removes
  the front-end and *only* the front-end — the engine keeps scanning, nothing
  is restarted:

  1. backup: `/usr/msfe`, every cron file that runs it (`/etc/cron.d/msfe.sh`,
     `/etc/cron.hourly/msdigest.pl`, `/etc/cron.daily/mailscanner_daily.cron`,
     …), the WHM app registration file and root's crontab (as `root.crontab`)
     go into `<backup_dir>/legacy-msfe-<time>.tar.gz` — nothing is removed
     if that fails
  2. `/usr/msfe` removed
  3. those cron files removed (`csget`, ConfigServer's shared updater used by
     csf, is never touched)
  4. the `/usr/msfe` lines dropped from root's crontab
  5. the legacy WHM plugin unregistered
  6. re-scan: *decommissioned*, or whatever is still present for your hands

  Restore everything with `tar xzf <backup> -C /` (root's crontab from the
  `root.crontab` member: `crontab root.crontab`). ConfigServer's own
  `uninstall.msfe.sh` is never run by this tool. On a host still on the
  ConfigServer engine the command works too (the engine is left alone, with a
  note that the migration is the way to switch it), but the Service tab shows
  the migration card instead of this one.

The doctor's *legacy ConfigServer front-end* notice links here.

## The guided migration — ConfigServer engine → MailScanner RPM

**ConfigServer's uninstaller (`/usr/msfe/uninstall.msfe.sh`) removes the
bundled MailScanner engine too**, and the RPM installer refuses to install
beside `/usr/mailscanner`, so the two have to happen in one sequence. **Service → Migrate from ConfigServer
MailScanner** (shown while `/usr/mailscanner` exists) does it as one
background job and follows its log; `msfe-ng engine migrate-legacy` prints
the preflight, `--run` does the same from a shell. Mail keeps spooling
meanwhile (Exim queues into the scanning spool; nothing is lost, it is
scanned once the new engine runs). The steps, each logged, stopping at the
first failure:

1. backup of `/etc/msfe-ng` into the backup dir (`pre-migration-<time>.tar.gz`)
2. copy of `/usr/mailscanner/etc` to `/etc/msfe-ng/legacy-engine-etc` (org
   name, custom rules, `spamassassin.conf` — for reference afterwards)
3. stop the legacy MailScanner
4. ConfigServer's uninstaller (any `/usr/msfe/uninstall*.sh`, answering *yes*
   to its prompts), then whatever it left: `/usr/mailscanner`, `/usr/msfe`,
   every cron entry referencing `/usr/msfe` (`/etc/cron.d/msfe.sh`,
   `/etc/cron.hourly/msdigest.pl`, `/etc/cron.daily/mailscanner_daily.cron`,
   …), `/etc/init.d/MailScanner`, a hand-written `MailScanner.service`
   pointing at the removed tree (disabled and parked under
   `/etc/msfe-ng/legacy-engine-etc/`), root's crontab lines, the legacy WHM
   plugin registration. `csget` (ConfigServer's shared updater, used by csf
   too) is never touched.
5. `msfe-ng engine install` at the latest MailScanner v5 release
6. `config.toml` pointed at `/etc/MailScanner/MailScanner.conf`
7. `%org-name%`, `%org-long-name%`, `%web-site%` carried over from the legacy conf
8. `msfe-ng engine configure` (queues, run-as user, shared SA state, Razor/Pyzor
   homes, `envelope_sender_header`)
9. `msfe-ng mailscanner enable-logging`
10. `msfe-ng sync`
11. Exim wiring: the two-config layout is kept if the uninstaller left it;
    otherwise the named-queue wiring is set up
12. startup latch on, unit enabled, MailScanner (re)started
13. `msfe-ng doctor --fix` — the mechanical repairs first (among them the
    upstream SpamAssassin ruleset for the SpamAssassin the new engine loads,
    see below), then anything still not OK is printed with its fix

Preflight notes worth acting on before starting: *no policy imported yet*
(the legacy settings vanish with `/usr/msfe` — run the import first) and
*database not configured*.

### What a migrated host looks like, from one that was done

A ConfigServer host migrated on 2026-09-20 kept its **two-config Exim
wiring** (`/etc/exim.conf` spooling into `/var/spool/exim_incoming`,
`exim_outgoing.conf` delivering) — expected, and the doctor reports it as
wired; there is no kill switch on that layout and queue commands must go
through `-C /etc/exim_outgoing.conf` (the Queues tab does; see
Troubleshooting). Things the doctor then found and now repairs:

- **`/etc/exiscandisable`** left by ConfigServer: not a MailScanner bypass on
  a stock cPanel, only its *exiscan* (ClamAV in Exim) switch — kept as is.
- a **stale `MailScanner.service`** from 2020, enabled, failing at every
  boot beside the RPM's `mailscanner.service`.
- **SpamAssassin from CPAN** (`/usr/local/share/perl5`, version 4.0.2) whose
  upstream ruleset had never been fetched: cPanel's nightly `sa-update` feeds
  its own bundled 4.0.1, so MailScanner had been scoring with the site rules
  (KAM + cPanel's few picked rules) for a year. The RPM engine's daily cron
  (`ms_cron_sa=1` in `/etc/MailScanner/defaults`) runs `ms-update-sa` from
  the first night; `doctor --fix` does it at once.
- the **private DNS resolver** install on a Hetzner host, where the same
  IPv4 is listed twice: fixed in the installer, and the doctor now restarts
  a dead loopback resolver.

If you already removed the front-end by hand (or its uninstaller took the
engine with it), just run `msfe-ng engine install`, `msfe-ng engine
configure`, `msfe-ng mailscanner enable-logging`, `msfe-ng sync` and check
`msfe-ng doctor` for the wiring — the same steps, without the removal.

## What carries over

| Carries over (via `import`) | Not imported |
|---|---|
| Global scan/action/score settings (`msconfig.txt`) | Per-user `~/.mailscanner*` dotfiles (set per-domain in the new UI) |
| System white/black lists (`mailscannerbw`) | The old MailControl logger (replaced by MSFE-NG's plugin) |
| Digest domains (`digestdomains`) | — |
| Existing `maillog` history (if you reuse the DB) | — |

Per-domain overrides are managed by account holders in the user UI (or by the
admin) and stored under `/etc/msfe-ng/policy/domains/`.
