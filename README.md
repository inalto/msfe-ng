# MSFE-NG — MailScanner Front-End (Next Generation)

A modern, open-source (GPLv3) front-end for **MailScanner** on **cPanel/WHM** and
**DirectAdmin**. It gives administrators and end-users a clean UI to manage spam
and virus filtering — global and per-domain policy, black/white lists, SpamBox,
quarantine review, and digests — backed by a small Rust daemon.

MSFE-NG is a **clean-room replacement** for the discontinued, proprietary
ConfigServer MailScanner Front-End (MSFE). It reads MSFE's old config files so
you can migrate, but ships **no licensing, no phone-home, and no obfuscation** —
just maintainable, auditable code.

> **Status: v0.0.1 — feature-complete.** Installs and cleanly uninstalls, logs
> mail to MySQL, generates the MailScanner ruleset, and provides both an admin
> dashboard and an end-user self-service UI. See [Roadmap](#roadmap).
>
> ⚠️ Integration testing on a live cPanel/DirectAdmin + MailScanner host is the
> recommended next step before production use (see [Testing status](#testing-status)).

## Features

- **WHM/DA admin UI** — reporting dashboard (traffic, top senders, categories),
  global spam/virus policy, and system white/black lists.
- **End-user UI** — per-domain spam/virus preferences, personal white/black
  lists, and a **quarantine browser** (view + release), scoped to the account's
  own domains.
- **Rule engine** — generates MailScanner rule files from policy + local domains,
  idempotently, on save and on a 10-minute cron.
- **Mail logging** — a clean `MailScanner::CustomConfig` plugin logs every
  message to a MySQL `maillog` table (MailWatch-schema compatible).
- **Quarantine digests**, **log housekeeping**, **SpamBox**, a **self-test**
  (GTUBE/EICAR/clean), and a **scanning on/off** toggle.
- **Migration** from the original MSFE via `msfe-ng import /usr/msfe --save`.
- **Ops** — one-command install/uninstall/upgrade, config backup/restore, signed
  release tarball, and a bootstrap `get.sh`.

## Quick start (as root on a cPanel or DirectAdmin server)

```sh
# bootstrap: download + verify the latest release, then install
curl -sSfL https://raw.githubusercontent.com/inalto/msfe-ng/main/packaging/get.sh | sh

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
```

Open **WHM → Plugins → MSFE-NG** (or **DirectAdmin → MSFE-NG**). Check the daemon
any time with `msfe-ng health`.

Full documentation: **[Admin guide](docs/admin-guide.md)** ·
**[User guide](docs/user-guide.md)** · **[Migration guide](docs/migration.md)**.

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
                ├─ reporting/policy API  → MySQL (maillog, quarantine, config)
                └─ digests · housekeeping · quarantine release
```

- `crates/msfe-ngd` — daemon: serves the UI + JSON API.
- `crates/msfe-cli` — `msfe-ng` CLI (install/cron/hooks and admin use).
- `crates/msfe-core` — rule engine, config/policy, DB, stats, panel abstraction.
- `crates/msfe-api` — shared types/constants.
- `panel/` — cPanel + DirectAdmin integration files and Perl shims.
- `web/` — the admin and user single-page apps (served by the daemon).
- `db/` — SQL migrations. `packaging/` — installer, service, cron, release tools.

The Rust workspace is intentionally **dependency-free** (std only), so it builds
fully offline; MySQL is reached through the system `mysql` client.

## CLI at a glance

```
msfe-ng health | panel | config
msfe-ng import <dir> [--save]        # migrate legacy MSFE config
msfe-ng sync [--dry-run]             # policy → MailScanner rules
msfe-ng db-migrate [--status]
msfe-ng mailscanner <status|enable-logging|disable-logging>
msfe-ng spambox <enable|disable|status>
msfe-ng digest [--dry-run] | housekeeping | selftest
msfe-ng exim <status|enable-scanning|disable-scanning>
msfe-ng backup <file.tgz> | restore <file.tgz>
```

## Roadmap

| Milestone | Delivered |
|-----------|-----------|
| M0 | Installable skeleton: daemon, panel wiring, install/uninstall |
| M1 | MySQL schema + migrations, logging plugin, legacy importer |
| M2 | Rule engine (`sync` + cron), lists, SpamBox, `selftest` |
| M3 | Admin SPA + reporting API, transparent panel proxies |
| M4 | End-user SPA + scoped user API + quarantine (per-domain overrides) |
| M5 | Digests, housekeeping, scanning toggle, i18n |
| M6 | Hardened DB creds, backup/restore, upgrade, release tooling, docs |

## Testing status

The Rust core is unit-tested and the JSON API is exercised over the socket.
Because the plugin integrates with live infrastructure, these paths require a real
server to validate end-to-end: panel plugin registration, MailScanner scanning &
logging, the SQL-backed dashboards, quarantine spool operations, and in-browser UI
QA. Contributions of integration test results on real cPanel/DA hosts are welcome.

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
