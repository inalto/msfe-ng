# MSFE-NG user guide

If your hosting provider runs MSFE-NG, you can manage how spam and viruses are
handled for your own domains, and review mail that was held in quarantine.

## Opening MailScanner

- **cPanel:** log in and open **Email → MailScanner**.
- **DirectAdmin:** log in and open **MSFE-NG / MailScanner** in the user menu.

A domain selector at the top right switches between the domains on your account.
Every setting applies to the selected domain.

## Spam & virus

Each option can be left on **“inherit default”** (the server-wide setting, shown
in brackets) or overridden for your domain:

- **Spam scanning / Virus scanning** — turn scanning on or off.
- **Low-spam action / High-spam action** — what happens to spam: deliver, delete,
  send to your SpamBox folder, or forward.
- **Low / High spam score** — the SpamAssassin thresholds.

Click **Save & apply**; changes take effect within a few minutes.

## My lists

- **Whitelist** — senders that should always be allowed (never marked spam).
- **Blacklist** — senders that should always be treated as spam.

One address or pattern per line, e.g. `*@partner.example` or `boss@work.example`.
These apply only to mail addressed to your domain.

## Quarantine

The **Quarantine** tab lists messages held for your domains (spam / high spam /
virus). For each you can:

- **view** — see the raw message safely, without delivering it.
- **release** — deliver it to the inbox if it was caught by mistake.

If digests are enabled for your domain, you'll also get a periodic email
summarizing what was held, so you can log in and release anything legitimate.
