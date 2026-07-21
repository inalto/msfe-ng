# MSFE-NG — open-source MailScanner Front-End

A modern, free (GPLv3) reimplementation of a MailScanner management front-end for
**cPanel/WHM** and **DirectAdmin**, in the spirit of the community CSF fork. It
replaces the now-defunct, proprietary ConfigServer MailScanner Front-End (MSFE)
with a clean-room codebase — **no licensing phone-home, no obfuscation**.

> **Status: milestone M6 — hardening & release (feature-complete).** All planned
> milestones are done. M6 adds: DB credentials passed via a private 0600
> defaults-file (never on argv), `msfe-ng backup`/`restore`, in-place upgrades,
> a signed release tarball (`packaging/dist.sh`) + bootstrap (`get.sh`) + release
> CI, and admin/user/migration guides.

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
# bootstrap: download + verify the latest release tarball, then install
curl -sSfL https://raw.githubusercontent.com/OWNER/msfe-ng/main/packaging/get.sh | sh

# …or from a checkout:
git clone https://github.com/OWNER/msfe-ng && cd msfe-ng
cargo build --release --workspace       # or: packaging/dist.sh to build a tarball
sudo packaging/install.sh               # re-run to upgrade in place
```

Then open **WHM → Plugins → MSFE-NG** (or DirectAdmin → MSFE-NG). Verify the
daemon any time with `msfe-ng health`. Full docs: [`docs/admin-guide.md`](docs/admin-guide.md),
[`docs/user-guide.md`](docs/user-guide.md), [`docs/migration.md`](docs/migration.md).

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
| **M3** ✅ | Admin SPA (dashboard/settings/lists) + reporting API over `maillog`, transparent panel proxies |
| **M4** ✅ | End-user SPA (per-domain prefs, personal lists, quarantine view/release) + scoped `/api/user/*` |
| **M5** ✅ | Quarantine digests, mail-log housekeeping, scanning toggle (exiscandisable), i18n framework + daily crons |
| **M6** ✅ | Hardened DB creds, backup/restore, in-place upgrade, release tarball + `get.sh` + release CI, guides |

## Legal

Clean-room reimplementation under **GPL-3.0-or-later** (see [`LICENSE`](LICENSE)).
Not affiliated with, endorsed by, or derived from ConfigServer / Way to the Web.
No original MSFE code is used — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
"MailScanner", "cPanel", and "DirectAdmin" are trademarks of their respective owners.
