# MSFE-NG — MailScanner Front-End (Next Generation)

A modern, open-source (GPLv3) front-end for **MailScanner** on **cPanel/WHM** and
**DirectAdmin**. It gives administrators and end-users a clean UI to manage spam
and virus filtering — global and per-domain policy, black/white lists, SpamBox,
quarantine review and release, message archive, queue management, and digests —
backed by a small Rust daemon.

MSFE-NG is a **clean-room replacement** for the discontinued, proprietary
ConfigServer MailScanner Front-End (MSFE). It reads MSFE's old config files so
you can migrate, but ships **no licensing, no phone-home, and no obfuscation** —
just maintainable, auditable code.

> **Status: v0.0.33 — in production.** Runs on a live cPanel/Exim server:
> installs (optionally including MailScanner itself), wires Exim to the scanner,
> logs and archives every message to MySQL, manages the queues, and alerts via
> Telegram. Releases are tagged continuously; upgrade in place with the same
> one-liner as the install.

## Features

- **WHM/DA admin UI** — reporting dashboard (traffic, top senders, categories,
  client IPs with geolocation and one-click CSF block), global spam/virus
  policy, per-domain overrides, system white/black lists, config editor, and a
  live health banner. Light/dark theme.
- **End-user UI** — per-domain spam/virus preferences, personal white/black
  lists, and a quarantine browser (view + release), scoped to the account's own
  domains.
- **Message log & archive** — a clean `MailScanner::CustomConfig` plugin logs
  every message to MySQL (MailWatch-schema compatible); optional full-message
  archive gives you the complete content of *every* message, not just
  quarantined mail, with per-domain opt-out and retention windows.
- **Quarantine & release** — release as resend, forward, or direct-to-inbox
  (Dovecot LDA); SpamAssassin learn on reclassify; SpamCop reporting; daily
  quarantine digests.
- **Engine management** — install MailScanner from the UI or CLI, point it at
  Exim (`engine configure`), and wire mail flow through an **Exim named queue**
  (`engine wire`) — no second Exim config, instantly reversible.
- **Queue management** — both queues parsed straight from the Exim spool
  (sender, recipients, subject, spam score, frozen state), multi-select bulk
  delete/deliver, one-click delete-all-spam/bounces, and configurable
  **auto-clean rules** (frozen/bounce age, spam score) for the delivery queue.
- **Monitoring & alerts** — a 5-minute monitor cron applies the auto-clean
  rules and sends **Telegram alerts**: queue growth, stuck scanning queue, and
  per-account outbound sending bursts (compromised-account detection).
- **Doctor** — `msfe-ng doctor` checks every link of the scanning chain (engine,
  wiring, queue flow, spool placement, quarantine writability, DB, logging,
  Telegram) and pairs each finding with the exact command that fixes it.
- **Ops** — one-command install/uninstall/in-place upgrade, DB backup/repair,
  Bayes repair/rebuild, config backup/restore, spool repair, self-test
  (GTUBE/EICAR/clean), scanning on/off toggle, and migration from the original
  MSFE via `msfe-ng import /usr/msfe --save`.

## Quick start (as root on a cPanel or DirectAdmin server)

```sh
# bootstrap: download + verify the latest release, then install
curl -fsSL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | sh

# no MailScanner yet? let the installer set it up too:
curl -fsSL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | MSFE_NG_WITH_ENGINE=1 sh

# …or from a checkout:
git clone https://github.com/inalto/msfe-ng && cd msfe-ng
cargo build --release --workspace       # or: packaging/dist.sh to build a tarball
sudo packaging/install.sh               # re-run any time to upgrade in place
```

Then set the database credentials in `/etc/msfe-ng/config.toml` and run:

```sh
msfe-ng db-migrate                 # create the schema
msfe-ng mailscanner enable-logging # hook logging into MailScanner (restart it after)
msfe-ng sync                       # generate the rules
msfe-ng engine wire                # route incoming mail through MailScanner
msfe-ng doctor                     # verify the whole chain, with fixes per finding
```

Open **WHM → Plugins → MSFE-NG** (or **DirectAdmin → MSFE-NG**). Check the daemon
any time with `msfe-ng health`.

Full documentation: **[Admin guide](docs/admin-guide.md)** ·
**[User guide](docs/user-guide.md)** · **[Migration guide](docs/migration.md)** ·
**[Architecture](docs/architecture.md)**.

## Architecture

A **Rust core** does the work; a **thin Perl layer** exists only where cPanel and
MailScanner insist on loading code by package name. Everything talks to the daemon
over a local Unix socket.

```
Browser ─► panel shim (WHM CGI · cPanel UAPI/live-CGI · DA CGI)
                │  forwards method + body + authenticated user
                ▼
          msfe-ngd (Rust daemon, root)  ── Unix socket /var/run/msfe-ng/msfe-ng.sock
                │
                ├─ rule engine  → MailScanner rule files
                ├─ engine wiring → Exim named queue "mailscanner" → MailScanner → delivery
                ├─ reporting/policy API → MySQL (maillog + bodies, quarantine, config)
                ├─ queue view/actions → Exim spool (-H files parsed directly)
                └─ digests · housekeeping · monitor (auto-clean + Telegram) · doctor
```

- `crates/msfe-ngd` — daemon: serves the UI + JSON API.
- `crates/msfe-cli` — `msfe-ng` CLI (install/cron/hooks and admin use).
- `crates/msfe-core` — rule engine, engine wiring, queue view, monitor, doctor,
  config/policy, DB, stats, panel abstraction.
- `crates/msfe-api` — shared types/constants.
- `panel/` — cPanel + DirectAdmin integration files and Perl shims (incl. the
  MailScanner logging plugin).
- `web/` — the admin and user single-page apps (precompiled Tailwind, served
  inline by the daemon).
- `db/` — SQL migrations. `packaging/` — installer, service, cron, release tools.

The Rust workspace is intentionally **dependency-free** (std only), so it builds
fully offline; MySQL is reached through the system `mysql` client, Telegram
through `curl`. Installed cron jobs: rule sync every 10 min (reloads MailScanner
only when the ruleset actually changed), queue monitor every 5 min, digests and
housekeeping daily.

## CLI at a glance

```
msfe-ng health | panel | config | doctor
msfe-ng import <dir> [--save]        # migrate legacy MSFE config
msfe-ng sync [--dry-run]             # policy → MailScanner rules
msfe-ng engine <status|install|configure|enable|disable|lint|wire|unwire>
msfe-ng service <status|start|stop|reload|restart|queue-fix|spool-repair>
msfe-ng monitor [--dry-run]          # auto-clean rules + Telegram alerts
msfe-ng rules <lint|adopt [--from <dir>]>
msfe-ng db-migrate [--status]
msfe-ng db <backup|fix|bayes-repair|bayes-recreate>
msfe-ng mailscanner <status|enable-logging|disable-logging>
msfe-ng spambox <enable|disable|status>
msfe-ng digest [--dry-run] | housekeeping | selftest
msfe-ng exim <status|enable-scanning|disable-scanning>
msfe-ng backup <file.tgz> | restore <file.tgz>
```

## Testing status

The Rust core is unit-tested (`cargo test --workspace`) and CI enforces
rustfmt, clippy `-D warnings`, shellcheck, `perl -c`, and a reproducible web
build. MSFE-NG runs in production on a live cPanel/Exim/MailScanner host;
integration test results from other cPanel/DA environments are welcome.

## Contributing

MSFE-NG is a clean-room project — please read the **[clean-room policy](CONTRIBUTING.md)**
before contributing. In short: never copy original MSFE code; read it only to
understand behavior, then write fresh code.

```sh
cargo build --workspace && cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
shellcheck packaging/*.sh          # perl -c on the panel/*.pm|*.cgi shims
```

## License & attribution

Copyright © 2026 **Martini Multimedia s.a.s.** — Alain Martini.
Licensed under the **GNU General Public License v3.0 or later** — see [LICENSE](LICENSE).

MSFE-NG is an independent, clean-room reimplementation. It is **not** affiliated
with, endorsed by, or derived from ConfigServer / Way to the Web, and contains
none of their code. "MailScanner", "cPanel", and "DirectAdmin" are trademarks of
their respective owners.
