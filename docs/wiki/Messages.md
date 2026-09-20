# Messages

![Messages](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/messages.png)

The message log: one row per message MailScanner scanned, with time, score,
From/To, client IP, subject, size and a status badge (*clean*, *spam*, *high
spam*, *infected*, *whitelist*, *blacklist*, *held*; a 🔒 means a copy is in
quarantine).

## Finding messages

- **Status filters** — All, Blocked (releasable), Clean, Low Spam, High Spam,
  Infected, Attachments, Whitelist, Blacklist, Quarantined.
- **Search** by From, To, Subject, Message ID or Client IP, combined with a
  time window (24 hours … 90 days). For what MailScanner and Exim actually
  *did* with a message, search its id on the [Logs](Logs) tab.
- **Refresh** / **auto-refresh** (interval from Settings).
- Paging: prev / next / jump to page; page size from Settings.

## Tools

- **Daily summary** — per-day totals (clean/spam/high/infected/quarantined,
  volume) over 7–90 days.
- **SpamAssassin Bayes** — token counts and training state of the Bayes DB.
- **SpamAssassin lint** — runs `spamassassin --lint` and shows the verdict.

## Bulk release

Messages whose body is still on disk have a checkbox. Select some, optionally
type a forward address, and **Release selected**: they are re-sent through
Exim to their original recipients (or forwarded). A per-message result list is
shown for anything that could not be released.

## Message view

Click a row (opens in place, or in a new window per Settings). It shows the
scan status, envelope, size, client IP, spam report and RBL report, the
SpamAssassin **component scores** (rule, score, description), the **header
IPs** from the `Received:` chain (only the last one outside your network can
be trusted) and the full **headers**.

**Message content** (needs a stored copy — quarantine or archive):
- **View source** — the raw message, escaped, in a new tab.
- **View rendered** — the decoded message in a sandboxed tab, transfer
  encodings and charsets decoded, inline `cid:` images embedded; scripts and
  any network access are blocked by a Content-Security-Policy. Alternative
  parts show HTML over plain text; everything else is shown in order, so a
  bounce reads as notification → delivery status → returned headers, a
  forwarded/encapsulated message gets a From/To/Date/Subject summary plus its
  own rendered body, and other attachments are listed by name, type and size.

**Actions** (also need the stored copy):
- **Learn as ham / spam / spam & report / Forget** — trains SpamAssassin's Bayes
  filter (*report* also submits to Razor/Pyzor — see Troubleshooting for the
  one-time setup `engine configure` does). With "Reclassify the
  database" on, the log entry's spam flag follows.
- **Release (resend)** — to the original recipients. **Release (forward)** —
  to the address typed in the box. **Deliver to INBOX** — straight into a local
  account's mailbox via Dovecot LDA.
- **Report to SpamCop** — appears when a SpamCop address is configured.

## Delivery test from a row

The small **test** link next to the recipient runs a [Delivery test](Delivery-test)
for that address: it opens the tab with the address filled in and starts the
run at once, with the server audit included when the domain is hosted here —
the quickest way from "this message did not arrive" to the report.

## Ban rule from a message

Each row has a **ban rule** link next to the subject, and the message view a
**Ban rule…** button. Pick what to act on: *Subject contains ⟨this
subject⟩* or *From address ⟨this sender⟩* opens the match-rule editor
prefilled (block delivery on, ban the source for a day — change anything,
test it against recent mail, save: it is live after the reload); *Ban the
client IP now* opens the client-IP modal for a one-off csf block. See
[Config](Config), *Auto-ban spam sources*.

## Sender modal

Click any **From** address: 30-day history for that address and its whole
domain, current list status, and buttons to **blacklist / whitelist the
address** or **the whole domain** (`*@domain`). Changes regenerate the rules
and reload MailScanner immediately.

## Client IP modal

Click a **client IP**: reverse DNS, 30-day activity (messages, spam ratio,
average score, first/last seen, top senders and recipients), **location**
(third-party lookup via the configured `geoip_url`, cached 30 days; clear the
key to disable) and the **ConfigServer csf** section: current deny status,
then **Block in firewall** for the address, its /24 or /16 (wider than /24
asks twice), permanent or for 1 h / 24 h / 7 days, with a reason that goes into
`csf.deny`, optionally restarting csf. **Unblock** removes the entry.
