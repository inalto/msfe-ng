# MSFE-NG — usage wiki

MSFE-NG is an open-source (GPLv3) front-end for **MailScanner** on **cPanel/WHM**
and **DirectAdmin**: a small Rust daemon plus a WHM admin UI and a cPanel
end-user UI for spam/virus policy, lists, quarantine, message log, queues and
alerts. It is a clean-room replacement for the discontinued ConfigServer MSFE.

![Dashboard](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/dashboard.png)

## Pages

**Getting started**
- [Installation](Installation) — one-line install, first-time setup, upgrade, uninstall
- [Navigating the admin UI](Admin-UI-basics) — the rail, health dot, doctor banner, theme

**Admin UI, tab by tab** (WHM → Plugins → MSFE-NG)
- [Dashboard](Dashboard)
- [Settings](Settings) — global scanning policy, retention, interface & release preferences
- [Lists](Lists) — system-wide whitelist / blacklist
- [Messages](Messages) — message log, search, message view, learn, release, sender & IP actions
- [Rules](Rules) — custom MailScanner rules and the live ruleset files
- [Service](Service) — MailScanner control, Exim wiring, health check, mail queues
- [Logs](Logs)
- [Queues](Queues) — Exim spool browser, bulk delete/deliver, spool repair
- [Quarantine](Quarantine) — what is on disk, purge
- [Config](Config) — config file editor, rulesets, DB & Bayes maintenance, queue auto-clean, Telegram alerts

**Other**
- [End-user panel](End-user-panel) — what account owners see in cPanel
- [CLI reference](CLI)
- [Troubleshooting](Troubleshooting) — doctor, common incidents, Exim 4.100

Source, releases and issues: <https://github.com/inalto/msfe-ng>.
