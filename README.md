# MSFE-NG — open-source MailScanner Front-End

A modern, free (GPLv3) reimplementation of a MailScanner management front-end for
**cPanel/WHM** and **DirectAdmin**, in the spirit of the community CSF fork. It
replaces the now-defunct, proprietary ConfigServer MailScanner Front-End (MSFE)
with a clean-room codebase — **no licensing phone-home, no obfuscation**.

> **Status: milestone M2 — rule engine.** On top of M0/M1, MSFE-NG now generates
> the MailScanner ruleset from policy + local domains (`msfe-ng sync`, also on a
> 10-min cron), manages the system white/black lists and the SpamBox Exim
> fragment (`msfe-ng spambox`), and can send GTUBE/EICAR/clean test mail
> (`msfe-ng selftest`). Admin/user UIs arrive in M3–M4.

## Why

MailScanner is still a solid spam/virus mail filter, but its best cPanel/DA UI
(MSFE) is abandonware and license-locked. MSFE-NG rebuilds that UI as maintainable
open source. See [`docs/feature-parity.md`](docs/feature-parity.md) for the plan.

## Architecture

A **Rust** core does the real work; a **thin Perl layer** exists only where cPanel
and MailScanner insist on loading code by package name.

```
Browser ─► panel shim (WHM CGI / cPanel UAPI / DA CGI) ─► msfe-ngd (Rust daemon)
                                                            └─ Unix socket /var/run/msfe-ng/msfe-ng.sock
```

- `crates/msfe-ngd` — daemon: serves the UI + API over a Unix socket.
- `crates/msfe-cli` — `msfe-ng` CLI (health, panel, sync, selftest).
- `crates/msfe-core` — panel abstraction, and later the rule engine & config.
- `crates/msfe-api` — shared types/constants.
- `panel/` — cPanel + DirectAdmin integration files and Perl shims.
- `web/` — placeholder SPA (served from `/opt/msfe-ng/web`).
- `packaging/` — `install.sh`, `uninstall.sh`, preflight, systemd unit, cron.

## Install (on a cPanel or DirectAdmin server, as root)

```sh
git clone https://github.com/OWNER/msfe-ng && cd msfe-ng
cargo build --release --workspace      # or ship a prebuilt dist/
sudo packaging/install.sh
```

Then open **WHM → Plugins → MSFE-NG** (or DirectAdmin → MSFE-NG). Verify the
daemon any time with `msfe-ng health`.

## Uninstall (leaves the system as it was)

```sh
sudo packaging/uninstall.sh            # add --purge to also remove /etc/msfe-ng
```

## Roadmap

| Milestone | Delivers |
|-----------|----------|
| **M0** ✅ | Installable skeleton: daemon, panel wiring, install/uninstall |
| **M1** ✅ | MySQL schema + migrations, MailScanner logging plugin, config model + legacy importer |
| **M2** ✅ | Rule engine (`sync` + cron), white/black lists, SpamBox fragment, Exim rebuild hook, `selftest` |
| M3 | Admin UI: settings, lists, reports/graphs |
| M4 | User UI + quarantine browse/release |
| M5 | Digests, housekeeping, mailflow management, i18n |
| M6 | Hardening, upgrade path, signed releases, migration guide |

## Legal

Clean-room reimplementation under **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)).
Not affiliated with, endorsed by, or derived from ConfigServer / Way to the Web.
No original MSFE code is used — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
"MailScanner", "cPanel", and "DirectAdmin" are trademarks of their respective owners.
