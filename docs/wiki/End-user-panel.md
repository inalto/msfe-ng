# End-user panel

Account owners manage their own domains without admin access.

- **cPanel:** log in and open **Email → MailScanner**.
- **DirectAdmin:** open **MSFE-NG / MailScanner** in the user menu.
- **Admins** can open it for any account from [Service → View as user](Service).

A domain selector at the top right switches between the account's domains;
every setting applies to the selected domain.

## Spam & virus

Each option can stay on **inherit default** (the server-wide value from
[Settings](Settings), shown in brackets) or be overridden:

- Spam scanning / Virus scanning on or off.
- Low-spam / High-spam action — deliver, delete, SpamBox (Junk folder) or forward.
- Low / High spam score thresholds.

(Opting a domain out of message archiving is an admin setting:
`archive=no` in `/etc/msfe-ng/policy/domains/<domain>.txt`.)

**Save & apply** — the rules are regenerated within a few minutes (the sync
cron) or immediately when an admin clicks **Update rules now**.

## My lists

Whitelist (never spam) and blacklist (always spam), one address or pattern per
line, e.g. `*@partner.example`. These apply only to mail addressed to the
domain.

## Quarantine

Messages held for the account's domains (spam / high spam / virus):
**view** the raw message safely without delivering it, or **release** it to
the inbox if it was caught by mistake. Domains enabled for digests also get a
periodic email summarising what was held.
