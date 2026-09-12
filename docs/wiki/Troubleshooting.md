# Troubleshooting

## Start with the doctor

```sh
msfe-ng doctor
```

It checks every link of the chain — engine installed and configured, Exim
wiring, queue flow, spool placement, quarantine writable by the scan user,
ClamAV socket actually connectable, database, logging plugin, Telegram — and
prints a fix for each failing check. The same result drives the banner at the
top of the admin UI and the health dot in the rail.

## Mail stops flowing

1. **Service tab** — is MailScanner *running*, *wired*, *scanning enabled*, and
   the safety switch ON? A stopped or unwired scanner with wired Exim means mail
   sits in the scanning queue.
2. **Queues tab → MailScanner queue** — messages older than a few seconds are
   waiting for a scan that never happens. Run **Test that everything is OK**
   (`MailScanner --lint`): a wedged virus scanner or a missing Perl module
   shows up there, not in the mail log.
3. **Activity console** on the Service tab follows the systemd journal; a child
   crash-loop shows there as *Process did not exit cleanly*.
4. Kill switch: **Disable MailScanner (mailflow)** delivers mail directly until
   the scanner is fixed — nothing is lost, it just isn't scanned.

Turn on the *scanning queue stuck* Telegram alert so this pages you instead of
your users.

## ClamAV socket moved (cPanel update)

cPanel's clamav package can move the clamd socket. MailScanner's stale
`Clamd Socket` then wedges every batch silently. `msfe-ng doctor` now
*connects* to the socket and names the live one; set it in Config →
MailScanner.conf and restart MailScanner.

## Messages queued in the wrong spool subdirectory

**Exim 4.100** (cPanel 138) is read by MailScanner's version probe as 4.1, so
it files outgoing spool files under `input/0/` where Exim never looks and
copies quarantined bodies from the wrong offset. MSFE-NG handles this without
patching MailScanner: *Configure for Exim* points `Exim Command` at a shim that
normalises the version banner, the doctor fails the check *MailScanner reads
the Exim message-id format* when the probe would go wrong, and the monitor
cron moves misfiled files every 5 minutes (**Queues → Fix misplaced spool
files** / `msfe-ng service spool-repair` do it by hand).

## Quarantine writes fail / gaps in the date directories

The quarantine must be owned by the user MailScanner runs as. *Configure for
Exim* (`msfe-ng engine configure`) sets it; the doctor check *quarantine
writable by scan user* catches regressions.

## MailScanner restarts too often

MailScanner only reads its configuration at startup, so MSFE-NG reloads it
only when a generated rule file actually changed. If you see restarts every
10 minutes, something else is rewriting the rules — check the *stray* flags on
the [Rules](Rules) tab.

## Getting the daemon's view directly

```sh
msfe-ng health                      # version + panel, over the socket
systemctl status msfe-ng            # the daemon
journalctl -u msfe-ng -n 50
```

The UI talks to the daemon through the panel's CGI shim over a Unix socket;
*MSFE-NG daemon is not responding* in the browser means `systemctl restart
msfe-ng`.
