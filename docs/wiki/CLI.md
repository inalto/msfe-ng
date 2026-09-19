# CLI reference

`msfe-ng` is installed in `/opt/msfe-ng/bin` and on root's PATH. Everything
the UI does is also a command, which is what the cron jobs and the doctor's
"fix" hints use.

```
msfe-ng health                      check the running daemon via its Unix socket
msfe-ng panel                       report the detected control panel
msfe-ng config                      print the effective config as JSON (password redacted)
msfe-ng doctor [--fix]              check every link of the scanning chain; names each fix (--fix applies the mechanical ones)
msfe-ng resolver <status|install>   private DNS resolver (unbound on loopback) so the blocklists answer this host
msfe-ng upgrade [--check]           upgrade MSFE-NG to the latest release (or just compare versions)
msfe-ng version | help

msfe-ng sync [--dry-run]            policy → MailScanner rule files (cron: every 10 min)
msfe-ng rules lint                  check managed ruleset files for unparsable lines
msfe-ng rules adopt [--from <dir>]  borrow existing on-disk rules into the custom store
msfe-ng import <dir> [--save]       import a legacy ConfigServer MSFE dir (e.g. /usr/msfe)

msfe-ng engine <status|install|configure|enable|disable|lint>
msfe-ng engine migrate-legacy [--run]        ConfigServer MailScanner → the RPM (preflight without --run)
msfe-ng engine <wire|unwire> [--dry-run]     route mail through MailScanner via Exim (or undo)
msfe-ng service <status|start|stop|reload|restart|queue-fix|spool-repair>
msfe-ng exim <status|enable-scanning|disable-scanning>   the mailflow kill switch
msfe-ng exim <enable|disable>-cpanel-spamassassin        cPanel's own SpamAssassin (double scan; Forced Global OFF)
msfe-ng mailscanner <status|enable-logging|disable-logging>

msfe-ng monitor [--dry-run]         auto-clean rules, spool repair, Telegram alerts (cron: every 5 min)
msfe-ng digest [--dry-run]          quarantine digests to digest-enabled domains (cron: daily)
msfe-ng housekeeping                prune old log rows and bodies per retention (cron: nightly)
msfe-ng selftest                    send GTUBE / EICAR / clean test mail through the MTA
msfe-ng spambox <enable|disable|status>

msfe-ng db-migrate [--status]       apply / list SQL migrations
msfe-ng db <backup|fix|bayes-repair|bayes-recreate>
msfe-ng backup <file.tgz> | restore <file.tgz>      config + policy
```

Environment: `MSFE_NG_SOCKET` (daemon socket), `MSFE_NG_CONFIG` (config file),
`MSFE_NG_MIGRATIONS` (migrations dir).

## `/etc/msfe-ng/config.toml`

Seeded by the installer with comments; editable from the [Config](Config) tab.

| Group | Keys |
|---|---|
| Database | `db_host`, `db_port`, `db_name`, `db_user`, `db_pass` |
| Paths | `mailscanner_conf`, `mailscanner_custom_dir`, `mailscanner_rules_dir`, `mailscannerq_conf`, `spambox_conf`, `quarantine_dir`, `archive_dir`, `maillog_path`, `exim_mainlog_path`, `backup_dir`, `socket`, `webroot` |
| Interface & release | `refresh_secs`, `rows_per_page`, `view_new_window`, `learn_updates_db`, `forward_subject`, `forward_body`, `release_from`, `spamcop_address`, `dovecot_lda`, `csf_comment_default`, `geoip_url` |
| Queue auto-clean | `queue_clean_frozen_hours`, `queue_clean_bounce_hours`, `queue_clean_spam_score` |
| Telegram | `telegram_bot_token`, `telegram_chat_id`, `alert_queue_size`, `alert_scan_stuck_mins`, `alert_burst_per_hour`, `alert_cooldown_mins` |

`mailscanner_conf` is seeded with the engine's conf found at install time
(`/etc/MailScanner/MailScanner.conf`, or ConfigServer's
`/usr/mailscanner/etc/MailScanner.conf`); when the file it names is missing,
MSFE-NG falls back to whichever of those exists. `mailscanner_rules_dir` is
normally left out: `sync` then writes into that conf's `%rules-dir%`. Set it
only to write somewhere else on purpose. `msfe-ng config` prints the values
in effect.

Policy (scores, actions, retention, lists, per-domain overrides) lives under
`/etc/msfe-ng/policy/` and is what `sync` turns into rule files.
