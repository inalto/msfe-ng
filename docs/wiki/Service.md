# Service

![Service](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/service.png)

## MailScanner service

The status line answers three questions: is mail **routed through
MailScanner** (Exim wiring), is the service **running** (with process count)
and is **scanning enabled** (the mailflow toggle). Queue counts are shown on
the right.

- **Safety switch** — MailScanner's own run/no-run latch. OFF means the service
  refuses to start; turn it ON before starting. Changing it does not alter mail
  flow.
- **Start / Stop / Reload / Restart** — the service itself. *Stop* warns you:
  while MailScanner is stopped, wired mail waits in the scanning queue and is
  not delivered.
- **Configure for Exim** — sets up `MailScanner.conf` for this server (queue
  directories, run-as user, sendmail paths; original backed up) and creates the
  incoming spool directory. Safe to re-run.
- **Enable / Disable MailScanner (mailflow)** — the instant kill switch: with
  scanning disabled, mail bypasses MailScanner entirely (Exim delivers directly).
- **Update rules now** — runs a sync immediately (also every 10 min by cron).
- **Wire Exim → MailScanner / Unwire** — adds (or removes) the Exim named queue
  that holds incoming mail for scanning. **Preview wiring (dry-run)** prints
  the exact changes without applying them.

The **Activity console** below shows each command and its output, then follows
the MailScanner journal for ~20 s so startup progress and errors are visible.

## Health check

**Test that everything is OK** runs MailScanner's built-in self-check
(`--lint`: configuration, Perl modules, virus scanner, spam engine). It does
not touch mail and can take up to a minute. A red verdict shows the full output.

## Mail queues

Incoming (waiting for scan) and outgoing (delivery) counts with the age of the
oldest message, plus a scan for **incorrectly queued files** — spool files that
sit where Exim will never look. **Fix queues & force delivery run** moves them
aside into `msfe-ng-badqueue` (never deletes) and kicks a queue run. The
last automatic clean is noted here too. Per-message work happens on the
[Queues](Queues) tab.

## View as user

Opens the [end-user panel](End-user-panel) impersonating an account (root only)
— handy to see exactly what a customer sees.

## Updates

**Check for updates** compares the installed version with the latest GitHub
release. Upgrade with the same one-liner as the install ([Installation](Installation)).
