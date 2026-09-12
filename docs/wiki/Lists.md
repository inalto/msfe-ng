# Lists

![Lists](https://raw.githubusercontent.com/inalto/msfe-ng/main/docs/img/lists.png)

System-wide sender lists, one address or pattern per line:

- **Whitelist** — never marked as spam (`*@partner.example`, `boss@work.example`).
- **Blacklist** — always treated as spam.

**Save & apply** writes `spam.whitelist.rules` / `spam.blacklist.rules` and
reloads MailScanner if they changed. The same lists can be edited one entry at
a time from the sender modal in [Messages](Messages) (click a From address →
blacklist/whitelist the address or its whole domain).

Per-domain lists are managed by the account owner in the
[end-user panel](End-user-panel) and only apply to mail addressed to that domain.
