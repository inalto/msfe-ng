# Logs

![Logs](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/logs.png)

A tail of either the **mail log** (MailScanner / syslog) or the **Exim
mainlog** (deliveries), 100 / 300 / 1000 lines. **Refresh** reloads; **follow
(5s)** keeps the view scrolled to the newest lines.

## Searching the whole log

The search box below the tail works like `grep -i` over the **entire current
log file**, not just the lines on screen: type a message id, an address, a
host name — plain text, case-insensitive — and press **Enter** or **Search**.
The counter shows which hit you are on and how many there are; the viewer
jumps to the **newest** hit with a few hundred lines of context, every
occurrence highlighted and the current line emphasised.

- **◀ older** / **newer ▶** (or **Enter** / **Shift+Enter** in the box) walk
  through the hits; the window follows you through the file.
- **✕** (or **Esc**) clears the search and goes back to the tail.
- Following pauses while a search is active; tick **follow (5s)** again after
  clearing.
- Only the current file is searched (not rotated `maillog-YYYYMMDD` files).
  If there are more than 5000 hits, the newest 5000 are listed.

Where to look for what:

- *Was a message scanned, what score, what happened to it?* — mail log; paste
  the message id from the [Messages](Messages) tab into the search box.
- *Was it delivered, deferred, bounced?* — Exim mainlog.
- *MailScanner won't start / crashes?* — the Activity console on the
  [Service](Service) tab follows the systemd journal, which the mail log does
  not show.
