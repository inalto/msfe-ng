# Quarantine

![Quarantine](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/quarantine.png)

What is **actually on disk** in the quarantine directory — including files no
database row knows about — one line per stored copy with date, message id,
type (*spam* or held), size, and, when the log has it, sender, recipient,
subject and score. Click a row to see the stored headers.

**Search** covers the whole quarantine, not only the rows on screen: type a
sender, recipient, subject fragment or message id (the id is matched on disk,
the rest in the message log, so a copy without a log row is found by its id
only), narrow to *spam only* / *held only*, or set a date window. The totals
line then shows the matches against everything on disk. *Purge selected*
works on the matches, which makes "everything from this sender" or "all held
mail of that week" a two-click clean-up. Enter searches at once, Esc clears
the text.

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
