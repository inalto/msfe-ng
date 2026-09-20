# MSFE-NG — usage wiki

MSFE-NG is an open-source (GPLv3) front-end for **MailScanner** on **cPanel/WHM**
and **DirectAdmin**: a small Rust daemon plus a WHM admin UI and a cPanel
end-user UI for spam/virus policy, lists, quarantine, message log, queues,
alerts, the whole MailScanner configuration (edited, tested, snapshotted) and
a deliverability diagnostic for any address. It is a clean-room replacement for
the discontinued ConfigServer MSFE.

![Dashboard](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/dashboard.png)

## Pages

**Getting started**
- [Installation](Installation) — one-line install, first-time setup, upgrade, uninstall
- [Migration from ConfigServer MSFE](Migration) — import the old policy, decommission the old front-end
- [Navigating the admin UI](Admin-UI-basics) — the rail, health dot, doctor banner, theme

**Admin UI, tab by tab** (WHM → Plugins → MSFE-NG)
- [Dashboard](Dashboard)
- [Settings](Settings) — global scanning policy, retention, interface & release preferences
- [Lists](Lists) — system-wide whitelist / blacklist
- [Messages](Messages) — message log, search, message view, learn, release, sender & IP actions, ban rule from a message
- [Rules](Rules) — custom MailScanner rules and the live ruleset files
- [Service](Service) — MailScanner control, Exim wiring, health check, mail queues, updates, private DNS resolver, migration
- [Logs](Logs) — tail the mail log / Exim mainlog, search the whole log file
- [Queues](Queues) — both Exim queues, bulk delete/deliver, spool repair
- [Delivery test](Delivery-test) — deliverability diagnostic for an address: DNS, SPF/DKIM/DMARC, MX and TLS, MTA-STS/DANE, blocklists; cPanel audit, message/bounce analysis, diagnostic inbox, test message, monitors
- [Quarantine](Quarantine) — what is on disk, purge
- [Config](Config) — every MailScanner configuration file with validation, history and a tester; snapshots; DB & Bayes maintenance, queue auto-clean, auto-ban of spam sources (csf) and match rules, Telegram alerts

**Other**
- [End-user panel](End-user-panel) — what account owners see in cPanel
- [CLI reference](CLI)
- [Troubleshooting](Troubleshooting) — doctor, common incidents, Exim 4.100

Source, releases and issues: <https://github.com/inalto/msfe-ng>.
