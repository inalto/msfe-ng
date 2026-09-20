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

`msfe-ng doctor --fix` (the banner's **Fix what can be fixed**) applies the
mechanical fixes first, then reports: installs the logging plugin's perl
modules (`DBI` and a MySQL driver — `DBD::mysql`, or `DBD::MariaDB` where
`perl-DBD-MySQL` cannot be installed beside the MariaDB repo's packages) and
restarts MailScanner; re-runs *Configure for
Exim* for anything it owns (Razor identity, Pyzor/Bayes homes, envelope-sender
header, archive dir, spam-check size, the Exim message-id shim) — only on an
engine already set to `MTA = exim`; runs the phishing-list updater; `sync`
when archive rules are missing; spool repair; starts MailScanner when it is
wired and the startup latch is on but it is stopped; disables and parks a
`MailScanner.service` whose binary is gone (a ConfigServer-era unit failing at
every boot, kept under `/etc/msfe-ng/legacy-engine-etc`); fetches the
upstream SpamAssassin ruleset when it is missing or older than 30 days
(*SpamAssassin upstream rules* — the engine's own `ms-update-sa`: sa-update,
sa-compile, MailScanner restart); turns off cPanel SpamAssassin plugins the
engine's perl cannot load, while cPanel's own spamd is disabled; takes the
first configuration snapshot. Decisions are never made for you: the mailflow kill
switch, cPanel SpamAssassin, cPanel's own ClamAV pass in Exim (*cPanel virus
scan in Exim (exiscan)* — `touch /etc/exiscandisable` and rebuild Exim to
stop the double virus scan, or keep it to reject infected mail at SMTP time),
the DNS resolver, database creation, enabling message logging and config
paths stay listed with their fix. The installer runs `doctor --fix` at the end of every install and
upgrade, and the guided migration runs it as its last step.

## `spamassassin -r` says "no rules were found" / scores look thin

SpamAssassin loads the upstream ruleset from `/var/lib/spamassassin/<its
version>/updates_spamassassin_org`, written by `sa-update` for that exact
version. A SpamAssassin installed from CPAN (`/usr/local/share/perl5`, version
`4.000002` say) is not fed by cPanel's nightly `sa-update`, which serves its
own bundled copy (`4.000001`): MailScanner then scans with the site rules
alone (`/etc/mail/spamassassin`: KAM plus cPanel's few picked rules) and the
`spamassassin` command, which insists on rules, refuses to report or learn.
The doctor check *SpamAssassin upstream rules* fails on the missing directory
and warns when it is over 30 days old; `doctor --fix` runs the engine's
`ms-update-sa`. The RPM engine's daily cron keeps it updated afterwards.
The `P0f.pm … IO/SigGuard.pm` lines in a learn transcript are cPanel's
SpamAssassin plugin (`/etc/mail/spamassassin/P0f.cf`, symlinked in by WHM →
Exim Configuration Manager → *Apache SpamAssassin: P0f*) failing to load
under the system perl: it needs cPanel's private perl and serves cPanel's own
spamd only. Noise, not a failure — but logged at every scan. The doctor check
*cPanel SpamAssassin plugins load* names any of cPanel's plugins the engine's
perl cannot load; while cPanel's spamd is off (`/etc/spamddisable`) `doctor
--fix` turns them off through `whmapi1 set_tweaksetting module=Mail
key=spamassassin_plugin_<Name> value=0`, otherwise the command is left to
you.

## An auto-ban hit a legitimate sender

Open Config → *Auto-ban spam sources* → **Recent auto-bans** and click
**unban** (or `csf -tr <ip>`); the row tells you which rule fired. A
threshold that bans on the first message is fast and blunt: the clean-mail
safeguard protects an IP only when it also delivered clean mail *inside the
window*, so a shared relay whose only recent message scored as spam is not
protected by it. Raise the count, shorten the ban, or add the address to
`csf.allow` (never banned again). Match rules are checked with **Test
against recent mail** before saving for exactly this reason.

## A configuration change did not take effect

MailScanner reads `MailScanner.conf`, `spamassassin.conf`, `spam.lists.conf`,
`virus.scanners.conf`, `conf.d/` and `mcp/` only at start. A save from the
[Config](Config) tab restarts it unless *apply without restart* was ticked; a
hand edit does not. The doctor's *MailScanner config newer than the running
service* names the files the running engine has not read — `msfe-ng service
restart` (or the tab's **Restart MailScanner now** banner) applies them.
Rulesets, filename rules and phishing lists are re-read per batch and only
need a reload.

## A save was refused or rolled back

Every save is linted on a staged copy first; the report under the editor shows
the exact `MailScanner --lint` / `spamassassin --lint` lines. **Test
configuration** on the Config tab lists the same findings for the files on disk
with links to the file and setting; `msfe-ng conf test` prints them. A `conf.d`
fragment is the one kind validated after apply — if that lint fails the
previous file is written back and the report says *rolled back*. Every replaced
version is in the file's **History**.

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

## Two MailScanner engines (ConfigServer's `/usr/mailscanner` tree)

Servers migrated from ConfigServer MSFE often still run its bundled engine —
`/usr/mailscanner/usr/sbin/MailScanner` (5.4.x, under cPanel's perl) with
`/usr/mailscanner/etc/MailScanner.conf` — while `msfe-ng engine install` put
the MailScanner 5.5 RPM at `/usr/sbin/MailScanner`. MSFE-NG follows the engine
the service actually runs: it takes the binary from `MailScanner.service`'s
`ExecStart` (or the tree next to `mailscanner_conf`), and reads that engine's
perl, `ms-update-phishing` and `defaults` file from the same place. The conf
follows suit: when the `mailscanner_conf` in `/etc/msfe-ng/config.toml` does
not exist, MSFE-NG uses the first of `/etc/MailScanner/MailScanner.conf` and
`/usr/mailscanner/etc/MailScanner.conf` that does, and `sync` writes the rule
files into that conf's `%rules-dir%` (unless `mailscanner_rules_dir` is set).
Set `mailscanner_conf` explicitly to pick one engine when both confs exist.
`msfe-ng engine status` and the doctor's first line print which engine,
version and conf were found; the doctor checks *MailScanner.conf found* and
*rules dir is the engine's %rules-dir%* fail when they disagree with the
engine — before that, a missing conf showed up as "still carries sendmail
defaults", "unknown version" and rules the engine never read.

A 5.4 engine has no `Exim Command` directive (it is a syntax error there), so
*Configure for Exim* leaves it out — and comments out one left by an older
MSFE-NG. It also has no support for Exim ≥ 4.97 long message ids at all; the
doctor warns about that and the monitor keeps re-filing misplaced spool
files, but the real fix is the 5.5 engine.

## Exim already wired the ConfigServer way (`exim_outgoing.conf`)

The original MSFE's "old method" routes mail with two Exim configurations:
`/etc/exim.conf` spools into `/var/spool/exim_incoming` with `queue_only`, and
`/etc/exim_outgoing.conf` delivers from `/var/spool/exim`. MSFE-NG recognises
that layout — the doctor reports *Exim wired to MailScanner (two-config
method)* — and *Configure for Exim* keeps what it needs:

```
Incoming Queue Dir = /var/spool/exim_incoming/input/*   (the /* takes the split subdirs)
Split Exim Spool   = yes
Sendmail2          = /usr/sbin/exim -C /etc/exim_outgoing.conf
```

Without the `-C`, MailScanner hands released messages to an Exim that looks
for them in the *incoming* spool and logs `Spool file … -D not found`. The
same applies to every queue command: a bare `exim -Mrm <id>` (or `-bp`,
`-Mvh`, `-M`) on this layout only sees the scanning spool and answers `Spool
file <id>-D not found` for a message waiting in the delivery queue. The
Queues tab and the monitor's auto-clean select the queue for you — `-C
/etc/exim_outgoing.conf` for the delivery queue, bare for the scanning queue
(with the named-queue wiring it is `-qGmailscanner` and bare) — and the
transcript shows the arguments used. By hand:

```sh
/usr/sbin/exim -C /etc/exim_outgoing.conf -bp          # the delivery queue
/usr/sbin/exim -C /etc/exim_outgoing.conf -Mrm <id>    # delete from it
/usr/sbin/exim -bp                                     # the scanning queue
```

There is **no mailflow kill switch** on this layout: `/etc/exim.conf` itself
spools into the scanning queue, so mail always passes through MailScanner.
The Service tab does not show the toggle, `msfe-ng exim disable-scanning`
refuses, and the doctor says so. **Wire** and **Unwire** refuse to touch
that layout: MSFE-NG never layers its named queue over it. To switch to the
named-queue method, undo the two-config setup with the tools that created it
first.

## `/etc/exiscandisable` — the kill switch that is not one

With ConfigServer's front-end, `/etc/exiscandisable` bypassed MailScanner —
through ConfigServer's *patch* of `Cpanel::Exim`, long since overwritten by
cPanel updates. On a stock cPanel that file does exactly one thing: it turns
off cPanel's own *exiscan*, the ClamAV pass in Exim's SMTP `DATA` ACL
(`av_scanner` in exim.conf). MSFE-NG's kill switch is the named-queue ACL
fragment renamed to `.disabled` (see the Service page) and never touches that
file, so a ConfigServer-era `/etc/exiscandisable` stays as it is — which is
the right setting with MailScanner scanning for viruses. Where the file is
absent, cPanel's Exim scans every message with ClamAV at SMTP time and
MailScanner scans it again: the doctor check *cPanel virus scan in Exim
(exiscan)* warns about the double scan. Stopping it is a policy choice, so
`doctor --fix` leaves it alone — SMTP-time rejection of infected mail is the
upside of keeping it:

```sh
touch /etc/exiscandisable && /scripts/buildeximconf && /scripts/restartsrv_exim
```

## A `MailScanner.service` that fails at every boot

The RPM engine runs as `mailscanner.service`, generated from its LSB
`ms-init`. A hand-written `/usr/lib/systemd/system/MailScanner.service` (or
one under `/etc/systemd/system`) from another era — ConfigServer's, pointing
at `/usr/mailscanner/usr/sbin/MailScanner` — survives the migration, stays
*enabled*, and fails with status 203 at every boot next to the working unit.
The doctor check *stale MailScanner service unit* finds any
`MailScanner.service` whose `ExecStart` binary is gone; `doctor --fix`
disables it and parks the file under `/etc/msfe-ng/legacy-engine-etc/`
(the guided migration does the same).

## cPanel Spam Filters: a double scan that is not happening

The doctor check *cPanel SpamAssassin double scan* counts accounts whose home
holds `.spamassassinenable` — but two WHM switches sit above those flags and
are honoured: the *Apache SpamAssassin* service off in **Service Manager**
(`/etc/spamddisable`, tested by cPanel's Exim ACL before every SpamAssassin
step) and *Enable Apache SpamAssassin spam filter* off in **Tweak Settings**
(`skipspamassassin=1`, which removes the feature; accounts created afterwards
still get the flag, and `uapi … disable_spam_assassin` answers *feature is
not enabled on this system*). With either off the check passes as *off
server-wide … the stale Spam Filters flag on N account(s) is ignored* and the
Service tab's button does nothing.

## Daily cron mail: `gzip: phishing.bad.sites.conf.master.gz: not in gzip format`

MailScanner's `cron.daily` job (`ms-cron DAILY` → `ms-update-phishing`) fetches
the phishing site lists from `phishing.mailscanner.info`, which sits behind
Cloudflare. Cloudflare answers the HTTP/2 fingerprint of older `curl` builds
with a 403 challenge page; the upstream script saves that HTML as the `.gz`,
`gunzip` rejects it, and the lists silently stay at whatever the RPM shipped.
The same request over HTTP/1.1 is served, so *Configure for Exim* (`msfe-ng
engine configure`, also run on every upgrade) patches `ms-update-phishing` to
use `curl -f --http1.1` (backup in `ms-update-phishing.msfe-ng.bak`) and
deletes the HTML saved as `.gz`, whose timestamp would otherwise keep the
next download answering *304 Not Modified*. The
doctor check *phishing site lists updating* warns when
`phishing.bad.sites.conf` is more than three days old and names the fix; a
MailScanner package upgrade reverts the patch, which the next `engine
configure` reapplies. Set `ms_cron_ps=0` in `/etc/MailScanner/defaults` to turn
the daily update off instead — the doctor then reports the check as OK.

## Spam report: `razor2 report failed: ... report requires authentication`

`spamassassin -r` (the *spam & report* action) submits the message to Razor
and Pyzor. Razor only accepts reports from a registered identity, and
SpamAssassin's Bayes DB and the Razor/Pyzor client state all live in the
*home directory of whoever runs them* — a problem on cPanel, where
MailScanner's scanning children run as `mailnull` but inherit root's `HOME`,
which they cannot read. The symptoms: `BAYES_*` and `PYZOR_CHECK` never fire
under MailScanner, training from the UI goes into root's `~/.spamassassin`
(a DB MailScanner never opens), and reports fail as above.

*Configure for Exim* (`msfe-ng engine configure`, also run on every upgrade)
sets it up the way MailScanner documents it:

- `SpamAssassin User State Dir = /var/spool/MailScanner/spamassassin`, owned by
  the scan user — the one Bayes DB that MailScanner scans with and every UI
  learn action trains (`sa-learn --dbpath` on that DB).
- Shared, world-readable `.razor` and `.pyzor` homes under
  `/etc/mail/spamassassin`, referenced from `spamassassin.conf` via
  `razor_config` and `pyzor_options --homedir` (managed block, backup kept).
  `razor-admin -register` runs once to create the reporting identity.

The doctor checks *Bayes DB shared with MailScanner*, *Razor reporting
identity* and *Pyzor shared home* warn when any piece is missing. DCC is
not set up: it is not open source and not packaged for EL.

## DNS blocklists: `RCVD_IN_ZEN_BLOCKED_OPENDNS`, `URIBL_BLOCKED`, `RCVD_IN_DNSWL_BLOCKED`

Those 0.0 "ADMINISTRATOR NOTICE" rules mean the blocklist answered the query
with a *refusal* code rather than data: Spamhaus (ZEN, DBL) and DNSWL reject
queries relayed through shared or public resolvers (a hosting provider's
resolver, 8.8.8.8, OpenDNS…), and URIBL rate-limits them. SpamAssassin then
scores without its most valuable lists, silently. The doctor check *DNS
blocklists answering* asks each list (Spamhaus ZEN and DBL, DNSWL, URIBL, and
every entry of MailScanner's `Spam List`) for its documented test record
through the system resolver and reports which ones refuse or never answer,
plus the resolver in use when it is not on loopback. The lists are probed at
most every ten minutes; each change of verdict is logged by the daemon
(`journalctl -u msfe-ng | grep 'DNS blocklists'`).

The fix is a private recursive resolver on the server itself. **Service →
Private DNS resolver → Install** (or `msfe-ng resolver install`; `msfe-ng
resolver status` first) does it as a logged job: installs unbound, binds
PowerDNS to the public addresses when it holds port 53 (each address once —
Hetzner hosts list the same IPv4 as a peer route and as a /32, and PowerDNS
refuses to bind one address twice; if PowerDNS does not come back with the
new `local-address`, its previous config is restored and the job stops
there), configures unbound on loopback with `Restart=always`, **verifies a
Spamhaus test query through 127.0.0.1 before touching anything else**, then
points resolv.conf — and NetworkManager or the ifcfg files, so it is not
written back — at loopback only. Every file edited keeps a `.msfe-ng.bak`.
BIND (`named`) on port 53 is reported as a blocker: set its `listen-on` to
the public addresses first.

`Restart=always` matters on cPanel: when a service fails, chkservd restarts
it with cPanel's `restartsrv`, which first kills whatever holds the
service's port — a PowerDNS that cannot start therefore takes unbound off
port 53 with a plain SIGTERM (exit 0, not a "failure"), and resolv.conf
keeps pointing at a dead 127.0.0.1: every lookup on the server fails, mail
delivery included. The doctor check *local DNS resolver answering* fails in
that state and `doctor --fix` starts unbound again. By hand, the same steps
are:

```sh
dnf -y install unbound
# /etc/pdns/pdns.conf — cPanel keeps custom lines across updates
echo "local-address=<public IPv4>, <public IPv6>" >> /etc/pdns/pdns.conf
/scripts/restartsrv_pdns
# /etc/unbound/local.d/local.conf
#   interface: 127.0.0.1
#   interface: ::1
#   access-control: 127.0.0.0/8 allow
#   access-control: ::1 allow
systemctl enable --now unbound
# /etc/resolv.conf: nameserver 127.0.0.1 ONLY — do not keep the provider's
# resolver as a fallback: glibc and SpamAssassin switch to it on any error
# and the lists' refusal codes come back. With network-scripts set
# PEERDNS=no and DNS1=127.0.0.1 in ifcfg-eth0 so dhclient does not write it
# back; give unbound Restart=always (a drop-in under
# /etc/systemd/system/unbound.service.d/).
dig +short 2.0.0.127.zen.spamhaus.org   # expect 127.0.0.2/4/10, not 127.255.255.254
```

Lists that never answer are dead: SORBS shut down in 2024, yet MailScanner
5.5.3 ships `Spam List = BARRACUDA SORBS SPAMCOP` (and no longer defines
SORBS), so every message waited on it until `Spam List Timeout`. *Configure
for Exim* drops undefined and known-defunct entries from `Spam List`.

## Lint: `envelope_sender_header … should match X-YourOrg-MailScanner-From`

MailScanner stamps the envelope sender into the header named by its
`Envelope From Header` directive (`X-%org-name%-MailScanner-From`) and
SpamAssassin must be told the same name in `spamassassin.conf`
(`envelope_sender_header`), or SPF and `whitelist_from` look at the wrong
sender. *Configure for Exim* / `msfe-ng engine configure` sets it from the
directive; the doctor check *SpamAssassin envelope-sender header* warns while
they differ.

## A spam shows as `not spam (too large)`

MailScanner skips *every* spam check — RBLs and SpamAssassin — for messages
bigger than `Max Spam Check Size`, and 5.5.3 ships that at `200k`, a size any
HTML newsletter with inline images exceeds. Such mail is logged with the
report `not spam (too large)` and delivered unscored (on cPanel the
account's own Apache SpamAssassin may still tag it — that is the
`X-Spam-Status` header, not MailScanner's). *Configure for Exim* raises a
stock-sized limit to `2M`; a larger or ruleset value set by hand is kept.
SpamAssassin itself still only reads the first `Max SpamAssassin Size`
(200k) of each message, so the cost is small. The doctor check *large
messages get spam-checked* reads the size distribution of the last 30 days'
mail. At the stock size a single message over the limit is a warning, since
the fix is mechanical; once the limit is raised, mail over it is attachments
rather than spam, so the check only warns when 1 % or more of the month's
mail went unscored — a message or two is the trade-off the limit exists
for, and the check stays green (*covers 99.9 % of the last 30 days' mail*).
When it does warn, it names the smallest limit from `1M 2M 3M 5M 10M 20M
50M` that would cover more than 99 % of that mail (*5M would cover
99.4 %*); set it in the Config tab and restart MailScanner.

## Quarantine writes fail / gaps in the date directories

The quarantine must be owned by the user MailScanner runs as. *Configure for
Exim* (`msfe-ng engine configure`) sets it; the doctor check *quarantine
writable by scan user* catches regressions.

## MailScanner restarts too often

MailScanner only reads its configuration at startup, so MSFE-NG reloads it
only when a generated rule file actually changed. If you see restarts every
10 minutes, something else is rewriting the rules — check the *stray* flags on
the [Rules](Rules) tab.

## "Mail to/from an address does not arrive"

Run a [Delivery test](Delivery-test) for the address (Delivery test tab, the
`test` link next to a recipient in Messages, or `msfe-ng delivery test
<address> --audit`). It separates what the world sees (DNS, SPF/DKIM/DMARC,
the MX hosts and their TLS, blocklists) from what this server does with the
address (routing, mailbox, forwarders, outbound identity, limits, the Exim
and Dovecot logs, the queues), and every finding carries the fix. A bounce
the sender received can be uploaded and is classified (Gmail, Microsoft,
Yahoo, blocklists, cPanel limits…); the diagnostic inbox shows how a message
from the other side arrives here.

## Following one message through the logs

The [Logs](Logs) tab searches the **whole** mail log or Exim mainlog —
rotated weeks included — for a message id, address or host, no need to `grep`
on the server. Start from the newest hit and step **◀ older** to see the
message arrive, get scanned and be delivered or deferred; every occurrence is
highlighted in context. If you know roughly when it happened, pick the day
from the **📅** calendar first.

## Getting the daemon's view directly

```sh
msfe-ng health                      # version + panel, over the socket
systemctl status msfe-ng            # the daemon
journalctl -u msfe-ng -n 50
```

The UI talks to the daemon through the panel's CGI shim over a Unix socket;
*MSFE-NG daemon is not responding* in the browser means `systemctl restart
msfe-ng`.
