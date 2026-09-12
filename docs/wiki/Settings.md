# Settings

![Settings](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/settings.png)

## Global scanning policy

The server-wide defaults; account owners can override most of them per domain
in the [end-user panel](End-user-panel). **Save & apply** regenerates the
MailScanner rule files and reloads the scanner only if something changed.

| Field | Meaning |
|---|---|
| High / Low spam score | SpamAssassin thresholds for *high spam* and *spam* |
| Scan for spam / viruses | master switches |
| Low-spam / High-spam action | `deliver`, `delete`, `spambox` (Junk folder) or `forward` |
| Deliver disinfected | pass on messages ClamAV could clean |
| Store copies (quarantine) | keep held mail on disk so it can be reviewed and released |
| Keep a copy of every message | archive **all** mail (not only held mail) so Messages can show and re-send it — see below |
| Keep message log for (days) | retention of log rows (scores, reports, headers); pruned nightly |
| Keep message bodies for (days) | retention of stored copies; `0` = forever |

### What is stored

The line under the card tells you exactly what is on disk: whether full copies
are kept and where (`archive_dir`, default `/var/spool/MailScanner/archive`,
laid out as `<YYYYMMDD>/<message-id>`), the retention, the current volume
(messages/day × average size), the projected size and the free disk.

Copies are the largest thing MSFE-NG stores, and archiving everyone's mail can
carry legal obligations — keep the retention as short as is useful and use the
per-domain opt-out (`archive=no` in `/etc/msfe-ng/policy/domains/<domain>.txt`)
where it is not wanted.

## Interface & release

Stored in `/etc/msfe-ng/config.toml`.

| Field | Meaning |
|---|---|
| Messages auto-refresh (seconds) | `0` = off; otherwise the Messages list reloads on that interval |
| Rows per page | message list page size |
| Open message details in a new window | otherwise the message view replaces the list (deep-linkable as `#msg=<id>`) |
| Reclassify the database on Learn as ham/spam | training Bayes also flips the message's spam flag in the log |
| Release (forward) subject / intro line | applied when releasing with *forward* |
| Release from address | envelope sender for released mail; blank = `postmaster@<host>` |
| SpamCop reporting address | enables the **Report to SpamCop** button in the message view |
| Default reason when blocking an IP | pre-fills the csf comment in the IP modal |
