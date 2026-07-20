# MSFE-NG architecture

## Principle: Rust core, thin Perl edge

cPanel and MailScanner load integration code *by Perl package name*, so a small
Perl layer is unavoidable. Everything else is Rust. The Perl shims contain no
business logic — each just forwards the request to the daemon over a Unix socket.

```
                 ┌──────────────────── msfe-ngd (Rust daemon, root) ───────────────────┐
  WHM CGI ──┐    │  HTTP/JSON over Unix socket  /var/run/msfe-ng/msfe-ng.sock          │
  UAPI shim ┼──► │  routing · panel abstraction · (M1+) rule engine, config, DB, jobs  │
  DA CGI  ──┘    └───────┬───────────────┬───────────────┬───────────────┬────────────┘
                    MailScanner rules   MySQL         MailScanner+Exim   digest/cron
                    (*.rules, *.conf)  (maillog…)     (reload, patch)    schedulers
```

### The unavoidable Perl shims (`panel/`)
| Shim | Why it must be Perl |
|------|---------------------|
| `panel/cpanel/uapi/MSFE_NG.pm` | cPanel calls `Uapi.execute('MSFE_NG','msDisplay')` → a `Cpanel::API::*` package |
| `panel/cpanel/whm/msfe-ng.cgi` | WHM AppConfig `url` points at a CGI; enforces the root ACL |
| `panel/hooks/*.pm` | `manage_hooks add module …` loads Perl packages on cPanel events |
| `panel/mailscanner/*.pm` | MailScanner loads `MailScanner::CustomConfig` in-process at scan time |
| `panel/cpanel/cpwrapd/*` (M4) | privilege bridge: unprivileged user → root action (quarantine release) |

### Rust crates (`crates/`)
- `msfe-api` — shared constants (socket path, install prefix) and wire types.
- `msfe-core` — `Panel` trait (cPanel/DirectAdmin/None) hiding every path/command
  that differs; later: config model + rule engine + MailScanner/Exim ops.
- `msfe-ngd` — daemon: Unix-socket HTTP server; serves UI + API.
- `msfe-cli` — `msfe-ng`: `health`, `panel`, `sync` (M2), `selftest` (M2).

## Install layout (own namespace, clean removal)
```
/opt/msfe-ng/bin/{msfe-ngd,msfe-ng}   binaries
/opt/msfe-ng/web/{whm,user}/…          UI assets
/etc/msfe-ng/config.toml               config (+ install.manifest)
/var/run/msfe-ng/msfe-ng.sock          daemon socket (systemd RuntimeDirectory)
/etc/systemd/system/msfe-ng.service    service
/etc/cron.d/msfe-ng                    cron (sync job; disabled until M2)
```
Nothing is written under `/usr/msfe`. The manifest + fixed namespace make
uninstall exact and unambiguous.

## Panel wiring reused (facts, not code)
- **cPanel register**: `register_appconfig`, `manage_hooks add module`,
  Jupiter `dynamicui` + `install.json`, `rebuild_sprites jupiter`,
  `build_locale_databases`, the `msfe_ng` feature flag.
- **cPanel remove**: `manage_hooks delete module`, `unregister_appconfig msfe_ng`
  **and** unconditional conf removal (the original's test was inverted), then
  delete our files and restore `Cpanel/Exim.pm` from backup (once M2 patches it).
- **DirectAdmin**: `plugins/msfe_ng/{plugin.conf,admin,user}` with CGI entrypoints.
