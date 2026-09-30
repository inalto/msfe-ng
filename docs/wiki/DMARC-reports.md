# DMARC reports

The **Delivery** tab's third view, *DMARC reports*, answers **who is sending
mail as my domains, and is it me?**

A domain whose DMARC record carries `rua=mailto:<address>` gets a report every
day from each large receiver: Google, Microsoft, Yahoo and others. The report
lists every IP that sent mail with the domain in the From address, how many
messages it sent, and whether SPF and DKIM passed *for that domain*. MSFE-NG
reads those reports from a mailbox, stores them, and shows them as a chart and
a set of lists.

## Setting it up

1. Create a mailbox for the reports, for example `dmarc@yourdomain`. It can be
   hosted on this server or anywhere else that speaks IMAP.
2. Point every domain's DMARC record at it: `rua=mailto:dmarc@yourdomain`. The
   DMARC form in [Account DNS](Account-DNS) sets it. A mailbox at a *different*
   domain also needs an authorisation record at that domain
   (`<domain>._report._dmarc.<mailbox domain>`, Account DNS explains).
3. In **Config → DMARC report mailbox**, enter the IMAP server, port, user,
   password and folder, then **Test connection** and **Save**. The test uses
   what is typed in the form, so it can be run before saving.

| Setting | Default | Meaning |
|---|---|---|
| IMAP server / Port | — / 993 | a mailbox on this server: its host name and 993 |
| TLS from the start | yes | *yes* is imaps (993); *no* is STARTTLS on 143 — the login is never sent in clear |
| Verify the certificate | yes | turn off only when connecting by a name the certificate does not carry (`localhost`) |
| Folder | INBOX | where the reports land |
| Delete report mails once stored | yes | see below |
| Keep report data for | 180 days | older rows are pruned by each fetch |
| Alert on a new spoofing source | yes | Telegram, when [configured](Config) |
| …from this many failing messages | 5 | smaller one-offs are not alerted |

The password is stored in `/etc/msfe-ng/config.toml` (root only) and is never
sent back to the browser. When the mailbox is used through curl, the login goes
in a private temporary file, not on the command line.

## What a fetch does

`msfe-ng dmarc fetch` runs **every hour** from cron, and **Fetch now** in the
view runs it on demand. For each mail in the folder:

- The report attachments are read: `.xml`, `.xml.gz`/`.gz` and `.zip`,
  recognised by their content rather than their name.
- Each report is stored in one database transaction. A report already stored
  (same receiver and report id) is recognised and not stored twice.
- **Only then is the mail deleted.** A mail is deleted only when *all* its
  reports were stored or already known.
- A mail that is not a report (spam, a forensic `ruf` report, a broken
  attachment) is **left in the mailbox**, marked read, and skipped by later
  runs. The status line counts these as *kept*, and one that failed to parse
  shows why.

The status line shows the last fetch: how long ago, how many reports were
stored, how many mails were kept, and any error, such as a refused login.

## Reading the view

| Class | Meaning | What to do |
|---|---|---|
| **pass** | DMARC passed: SPF or DKIM passed for the From domain | nothing |
| **forwarded** | failed, but the receiver says the mail was forwarded or came through a mailing list (or trusted its ARC chain) — or you marked the source a forwarder | nothing; this is normal |
| **this server, failing** | failed although it came from one of this server's IPs | fix it here — usually the DKIM key in DNS is not the key cPanel signs with, or SPF does not list this IP. [Account DNS](Account-DNS) shows which |
| **legitimate, failing** | failed from a source you marked legitimate | authorise it: add its SPF `include:` (or its IP) to the domain's SPF record, or have the service sign with DKIM for your domain |
| **suspect** | failed from an unknown source | either a service of yours not yet authorised — mark it *legitimate* — or someone spoofing the domain — mark it *abuse* |

From top to bottom, the view shows:

- **Tiles**: messages reported, the DMARC pass rate, suspect messages and
  sources (with how many are new this week), this server's failures, and the
  number of sources, reporters and reports.
- **Messages per day**, stacked by class. **Click a day** to list only that
  day's sources; click the chip next to the filters to go back to the whole
  period.
- **Messages by reporter** and **Top suspect sources**. Clicking a suspect
  source opens its row below.
- **Domains**: volume, pass rate, suspect messages, the policy the reports say
  is published, and the **next step**. A domain is *ready* for a stricter policy
  when:
  - at least 14 days of reports exist;
  - its own and its legitimate senders pass DMARC on 98 % or more of their mail;
  - this server did not fail in the last 7 days.

  The steps are `p=none` → `p=quarantine; pct=25` → 50 → 100 → `p=reject`.
  **Tighten policy…** opens the [Account DNS](Account-DNS) DMARC form with the
  next step filled in, and publishes the record with cPanel's installer. For a
  domain whose DNS is hosted elsewhere, it shows the record to publish there.
- **Sources**: every IP that sent as each domain, suspect first, with its
  reverse DNS, the DKIM and SPF results, the reporters and when it was last
  seen. Click a row for its individual records (each reporter, each day, the
  raw DKIM and SPF results) and to triage it:
  - **Legitimate**: a service of yours. Its failures show as *legitimate,
    failing* until it is authorised.
  - **Forwarder**: a list or forwarding service. Its failures are expected.
  - **Abuse → report…**: marks it and opens the IP view, where it can be
    reported to AbuseIPDB or blocked in csf. Both are manual; nothing is ever
    reported automatically.
  - **Clear**: back to *not triaged*.

  *for every domain it sent as* applies the triage to all your domains at once.
  Triage reclassifies the whole history straight away.
- **Stored reports**: every report, each openable as its own records table.

IP addresses in every table can be clicked for the IP view, and have a copy
icon.

## Alerts and the doctor

- The first time an unknown source fails DMARC on at least *N* messages (the
  threshold above) in one report, a **Telegram** message names the IP, its
  reverse DNS, the domain and the reporter. Each source is alerted once.
- `msfe-ng doctor` gains two checks once a mailbox is configured:
  - **DMARC report mailbox fetching** fails when the last fetch could not read
    the mailbox, or ran more than 3 hours ago.
  - **no unknown sources spoofing your domains** warns when unknown sources
    failed DMARC on 20 or more messages in the last 7 days. Like every notice,
    it can be [acknowledged](Admin-UI-basics).

## CLI

```
msfe-ng dmarc fetch [--dry-run] [--keep] [--json]   read the mailbox now (cron: hourly)
msfe-ng dmarc import <file>...                        store report files (.xml, .xml.gz, .zip) or saved mails (.eml)
msfe-ng dmarc status [--json]                         the last fetch and what is stored
msfe-ng dmarc test                                    log in to the mailbox
msfe-ng dmarc prune                                   drop rows older than the retention
```

`--dry-run` fetches and parses, but stores nothing and leaves the mailbox
alone. `--keep` stores but never deletes. `import` is the way to load reports
saved elsewhere, such as an archive from another tool.

## Notes

- curl older than 7.62 (AlmaLinux 8 ships 7.61) addresses messages by
  position rather than by UID. There each message is checked against its UID's
  size before anything acts on it. If the folder changed during the run, the
  message is left for the next one.
- Reports cover the receivers that send them. Most small providers do not, so
  the volumes are a sample of your mail, not all of it.
