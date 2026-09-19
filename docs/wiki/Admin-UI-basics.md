# Admin UI basics

Open **WHM → Plugins → MSFE-NG**. The app is a single page with a left rail;
every tab is described on its own wiki page.

![Service tab, showing the rail and the health indicator](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/service.png)

## The rail

- **Tabs** — Dashboard, Service, Messages, Lists, Rules, Queues, Delivery test,
  Quarantine, Logs, Settings, Config.
- **Health dot** (bottom) — mirrors `msfe-ng doctor`, refreshed every minute:
  green *all systems ok*, amber *N notices*, red *N problems*.
- **Theme** — cycles Auto → Light → Dark; remembered in the browser.
- **Version** — the running daemon's version.

## The doctor banner

When any doctor check is not OK, a banner appears above the content on every
tab. Expand it to see each finding with its level (fail / warn), a one-line
explanation and the **fix** — usually the exact CLI command or the button to
click. **Fix what can be fixed** applies the mechanical ones in one go (see
[Troubleshooting](Troubleshooting), *Start with the doctor*); what needs a
decision stays listed. It disappears on its own once every check passes.

## Conventions

- Destructive actions (stop, delete, purge, block, wire/unwire) always ask for
  confirmation and say what will happen.
- Long-running actions write a transcript into a console box under the button
  (the exact commands run and their output) — copy it into an issue if something
  fails.
- Values shown in monospace (message ids, IPs, scores) are data; clicking a
  sender address or a client IP opens an action modal (see [Messages](Messages)).
- Preferences such as rows per page, auto-refresh and "open details in a new
  window" live in [Settings → Interface & release](Settings).
