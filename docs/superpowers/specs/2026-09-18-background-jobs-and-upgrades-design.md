# Background jobs and upgrades from the UI

*2026-09-18 — design for "upgrade MSFE-NG and MailScanner from the UI"; the guided
ConfigServer → RPM migration builds on this and is specified separately.*

## Problem

The Updates card only says "vX available — release notes". Upgrading MSFE-NG means
an ssh session and the `curl | sh` one-liner; upgrading the MailScanner engine means
`msfe-ng engine install` by hand. Neither can be a plain request handler:

- `install.sh` restarts `msfe-ngd`, and systemd kills every process in the daemon's
  cgroup on restart — a child spawned by the daemon would die mid-install.
- `engine-install.sh` runs `dnf` and `ms-configure` for several minutes; the WHM CGI
  proxy and the daemon's request threads must not sit on that.

## Design

### Job runner — `msfe-core::jobs`

A *job* is a shell command run detached from the daemon as a **transient systemd
unit** (`systemd-run --unit msfe-ng-job-<name> --collect --quiet …`), so it lives in
its own cgroup and survives the daemon restarting or the request ending. The runner is
the only privileged spawn path; jobs are a fixed set (`upgrade`, `engine-upgrade`),
never a free command from the API.

Files under `/var/log/msfe-ng/jobs/` (`MSFE_NG_JOBS_DIR` overrides; tests use a
tempdir): `<name>.log` (stdout+stderr, truncated at start), `<name>.pid` (the
wrapper shell's pid, written first), `<name>.status` (`exit=N`, written last).

- `start(name, script)`: refuses when the job is running; resets a failed leftover
  unit; runs `sh -c 'echo $$ > pid; { script; } >> log 2>&1; echo exit=$? > status'`
  under `systemd-run` when `/usr/bin/systemd-run` exists, else (tests,
  `MSFE_NG_JOBS_RUNNER=direct`) as a detached `sh -c`. Environment: `PATH` with the
  sbin dirs, `HOME=/root`, plus per-job variables.
- `status(name) → JobStatus { running, exit: Option<i32>, log_tail }`: running when
  the pid file exists, the status file does not, and `/proc/<pid>` is alive — so a
  reboot mid-job reads as "interrupted" (`exit = None`, `running = false`), never as
  running forever. `log_tail` is the last 64 KB.

### Jobs

- **`upgrade`** — `sh /opt/msfe-ng/bin/msfe-ng-get` (get.sh, now installed by
  install.sh next to the engine installer): download the latest release, verify
  sha256, run `install.sh`. `MSFE_NG_VERSION` may pin a version. The daemon that
  started it is replaced by the new one; the UI keeps polling until `/api/health`
  reports the new version, then reloads.
- **`engine-upgrade`** — `MSFE_NG_ENGINE_FORCE=1 MSFE_NG_MS_VERSION=<latest> sh
  /opt/msfe-ng/bin/msfe-ng-engine-install && msfe-ng engine configure && msfe-ng
  service restart`. Offered only for the RPM engine (`/usr/sbin/MailScanner`) when
  the MailScanner/v5 GitHub release is newer than the installed `a.b.c` (the RPM
  re-release suffix `-N` is not compared). A ConfigServer engine is not upgraded in
  place — that is the migration.

### API

- `GET /api/service/update` grows `engine: { version, latest, upgradable, rpm }`
  next to `current`/`latest`/`upgradable`. Latest tags come from the GitHub
  `releases/latest` redirect (existing helper, now accepting tags without `v`).
- `GET /api/jobs/<name>` → status JSON; `POST /api/jobs/<name>` → starts it
  (409 when running, 404 for unknown names).

### UI (Service tab → Updates)

Two status lines (MSFE-NG, MailScanner engine) each with *Check* and, when
upgradable, an *Upgrade now* button (confirm dialog). Starting a job opens the
**job console**: a `pre` following `GET /api/jobs/<name>` every 2 s; request
failures during the daemon restart are shown as "daemon restarting…" and polling
continues; on `exit=0` for `upgrade` the page reloads once `/api/health` shows a
different version; non-zero exit shows the tail and the log path.

### CLI

`msfe-ng upgrade [--check]` — foreground `get.sh` (or just print current/latest),
for admins on ssh. `msfe-ng engine install` already covers the engine.

## Testing

- `jobs` unit tests (direct runner, tempdir): a job's log and exit code; refusal
  while running; interrupted detection with a dead pid.
- `service` unit tests: tag extraction with/without `v`, version comparison.
- API handler tests: unknown job → 404, status shape.
- Manual on ncc: Upgrade now from 0.0.49 → 0.0.50 through the console.

## Out of scope

Rollback (backup runs as part of install.sh already); scheduling automatic upgrades.
