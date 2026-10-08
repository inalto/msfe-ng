# Quarantine

![Quarantine](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/quarantine.png)

What is **actually on disk** in the quarantine directory — including files no
database row knows about — one line per stored copy with date, message id,
type (*spam* or held), size, and, when the log has it, sender, recipient,
subject and score. Click a row to open the same full message screen as in
[Messages](Messages) — scan report, spam components, header IPs, headers,
source and rendered views, Bayes training and release actions — with
**Back to quarantine** returning to the list and its search. A copy that no
database row knows about has no detail to show, so its click shows the stored
headers instead. A held entry that holds only a removed attachment
(MailScanner's *Quarantine Whole Message = no* keeps just the blocked file)
says so, lists the file(s), and shows the headers of the archive copy of the
message when the archive has one.

**Search** covers the whole quarantine, not only the rows on screen: type a
sender, recipient, subject fragment or message id (the id is matched on disk,
the rest in the message log, so a copy without a log row is found by its id
only), narrow to *spam only* / *held only*, or set a date window. The totals
line then shows the matches against everything on disk. *Purge selected*
works on the matches, which makes "everything from this sender" or "all held
mail of that week" a two-click clean-up. Enter searches at once, Esc clears
the text.

- **Copy to INBOX** — put the chosen messages straight into the INBOX of
  their recipients, with a confirmation that lists each message and its
  recipients. The copy is handed to Dovecot's delivery agent: it is not
  re-scanned, so a message held for a false positive (a blocked attachment,
  a spam score) arrives exactly as it was sent, and it is not re-sent, so
  nothing leaves the server. Only recipients whose domain is hosted here get
  a copy; the others are listed as skipped in the output below the buttons,
  as is an address that has no mailbox. When a held entry holds only the
  removed attachment, the archive copy of the message is what gets
  delivered; without one the row says the message is no longer available.
  For a recipient that is not the logged one, use **Deliver to INBOX** in
  [Messages](Messages) and type the account.
- **Purge selected** — delete the chosen copies permanently.
- **Older than N days → Preview** — a dry-run that counts what would go;
  **Purge older** then deletes it.

Purging removes the stored copy only; the message's log entry, headers and
reports stay in [Messages](Messages) — just without content, release or Bayes
actions. Reviewing and releasing individual held messages is done from the
Messages tab (filter **Blocked (releasable)**).

Retention (*Keep message bodies for*) in [Settings](Settings) prunes both the
quarantine and the archive nightly, so manual purging is only needed to free
disk early.
