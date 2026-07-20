# Feature parity map

Target = the behavior of the original MSFE. Each original responsibility is
reimplemented clean-room in the component named on the right. Original files are
listed only to name the *behavior* being matched — no code is reused.

| Original responsibility (reference file) | MSFE-NG component | Milestone |
|---|---|---|
| WHM admin UI, reporting, graphs (`mailscannerUI.pm`, obfuscated) | `web/whm` SPA + `msfe-ngd` API; JS charts (no GD::Graph) | M3 |
| End-user cPanel UI (`Cpanel::API…msDisplay`, obfuscated) | `web/user` SPA + `MSFE_NG.pm` UAPI shim → daemon | M4 |
| Per-user → MailScanner rule sync, domain ownership (`msbe.pl`) | `msfe-core` rule engine + `Panel` trait; `msfe-ng sync` on cron | M2 |
| Rule reconciliation + root email report (`msrules.pl`) | `msfe-core` reconcile; daemon-sent report | M2 |
| Queue-method switch / Exim+MailScanner wiring (`mschange.pl`) | `msfe-core` mailflow + Exim patch hooks | M5 |
| Per-message DB logging (`MailControl.pm`, obfuscated) | clean `MailScanner::CustomConfig` plugin → `maillog` (ref: MailWatch) | M1 |
| Quarantine viewer + release/download (`msdl.live.cgi` + cpwrapd) | daemon quarantine API + cpwrapd Perl bridge | M4 |
| Digest emails (`msdigest.pl`, `digest.html`) | Rust digest scheduler + templated mail | M5 |
| DB log housekeeping (`mssql.pl`) | daemon scheduled task | M5 |
| DB / MailScanner provisioning (`dbadd.pl`) | installer step + `msfe-core` (ref: MailWatch schema) | M1 |
| Black/white/restricted lists (`mailscannerbw`, `spam.*.rules`, `restricted.txt`) | config model + rule generation | M2 |
| SpamBox Exim fragment (`spambox.conf`) | generated Exim include, config-toggled | M2 |
| i18n (`mslang.*.txt`) | JS i18n bundles | M5 |
| Self-test (`mailtest.pl`, GTUBE/EICAR) | `msfe-ng selftest` | M2 |
| Phone-home licensing (`servers`, base64 blobs) | **dropped — intentionally not reimplemented** | — |

## Config formats to import (facts, safe to reuse)
The M1 importer reads legacy MSFE flat files so existing installs can migrate:
- `msconfig.txt` — `key=value`
- `mailscannerbw` — line 1 whitelist, line 2 blacklist; comma-separated patterns
- `spam.{white,black}list.rules` — MailScanner TAB rules
- `digestdomains` — `domain:on:to:freq:dvirus:spambox`
- `mslang.*.txt` — `English=Translation`

Output to MailScanner stays in its native `etc/rules/*.rules` TAB format — that is
the engine's contract, not something we invent.
