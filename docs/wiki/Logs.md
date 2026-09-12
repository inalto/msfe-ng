# Logs

![Logs](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/logs.png)

A tail of either the **mail log** (MailScanner / syslog) or the **Exim
mainlog** (deliveries), 100 / 300 / 1000 lines. **Refresh** reloads; **follow
(5s)** keeps the view scrolled to the newest lines.

Where to look for what:

- *Was a message scanned, what score, what happened to it?* — mail log; search
  the message id from the [Messages](Messages) tab.
- *Was it delivered, deferred, bounced?* — Exim mainlog.
- *MailScanner won't start / crashes?* — the Activity console on the
  [Service](Service) tab follows the systemd journal, which the mail log does
  not show.
