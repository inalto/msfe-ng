# Dashboard

![Dashboard](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/dashboard.png)

A summary of the mail log over a **window** of 7, 30 or 90 days:

- **Tiles** — Total, Clean, Spam, High spam, Infected, Quarantined.
- **Daily volume** — messages per day (hover a bar for the exact count).
- **Top sender domains** — the eight busiest sending domains in the window.

**Refresh** reloads on demand; **auto-refresh (30s)** keeps it live while the
tab is visible. The timestamp on the right shows the last update.

If the mail log is empty the tiles are replaced by the **Finish setup** card
(see [Installation](Installation)). Statistics start from the moment logging
is enabled — history before that is not imported.
