# OSINT

The **Delivery** tab's fourth view, *OSINT*, collects publicly available
information about one email address, so an operator can judge a suspicious
sender or recipient. Reach it from the *OSINT* pill, or from the magnifying
glass beside the recipient in the Messages list and beside the sender and
recipient in the queue, and the **Investigate address**
button on an Address test result.

Eight sources ship, listed in this order: **Delivery test context** (the linked
Delivery report, nothing leaves the server), **Gravatar**, **RDAP domain
registration**, **GitHub public-email profile**, **OpenPGP key**, **Have I Been
Pwned** (HIBP, breach exposure), **Web search** (Brave Search) and **Hunter email
verification**. Each is listed with exactly what it is sent before you run it,
see [What each source receives](#what-each-source-receives). A synthetic *fixture*
source exists only for tests and demos (it appears when the environment variable
`MSFE_NG_OSINT_FIXTURE` is set, makes no network request and returns invented
data).

> **Privacy.** An investigated email address is personal data, and a lookup
> sends it (or a hash or prefix of it) to a third party. Review the providers'
> terms and your data-protection obligations before you enable OSINT. The
> feature is meant for support and security investigation of addresses you
> have a reason to look at.

## What a result does and does not prove

- **No match is not "safe".** A source that finds nothing only says it found
  nothing: the address may be new, private, or simply unknown to that source.
  The report never words an empty result as clean.
- **A breach is history.** An address that appeared in an old data breach was
  exposed at some point; it says nothing about who is using it now. Old
  breaches are labelled as historical.
- **Candidates are not verified.** A name or profile inferred from an address
  is a lead to check, not a fact. Web search results are search snippets only:
  the pages are not fetched or checked, so they are candidates. A GitHub result is
  stronger (GitHub matched the address against the profile's public email field)
  but is still a candidate: the search answer does not include the email and
  MSFE-NG does not check it. A published OpenPGP key only shows that its owner verified
  the address with the key server. Hunter's answer is a vendor assertion, never
  proof.
- **Nothing changes mail handling.** The view never alters scanning, blocklists,
  whitelists, quarantine or delivery, and a finding does not change a CLI exit
  code. It is information for a person to read.
- Sources that failed, were restricted, or are not configured stay visible in
  *Source coverage*, so a gap is never hidden. A source without its key
  reports **not configured**, and the run is then **partial**, never clean.
- **HIBP data classes are incident-wide.** The list of data types (passwords,
  phone numbers, ...) describes what the breach exposed overall, not what was
  exposed for this address.

## Switching it on

OSINT is off by default. Tick **OSINT lookups** in the **OSINT providers** card
of the Config tab (it writes `osint_enabled = true`; the key can also be set in
`config.toml`). The keyless sources then work at once; HIBP, Web search and Hunter each need their own key, see
[Sources and keys](#sources-and-keys).

With it off, the view still opens and lists the sources, but a run is refused.
**A lookup never starts by itself**: opening the view from an address link only
fills the address in; you choose the sources and press **Run**. Only an admin
can use it.

## Limits

| Key | Default | Meaning |
|---|---|---|
| `osint_runs_per_min` | 3 | runs accepted per minute (1-30) |
| `osint_max_concurrent` | 2 | runs at the same time (1-8) |
| `osint_deadline_secs` | 60 | a run is stopped after this long (5-120); what finished is kept as a partial report |
| `osint_max_external_queries` | 8 | most outside lookups one run may make (1-20) |
| `osint_cache_secs` | 3600 | a repeat of the same lookup inside this time reuses the earlier report; *Fresh lookup* bypasses it |
| `osint_retention_hours` | 24 | how long a report and its avatar are kept (1-720) |
| `osint_max_monitors` | 10 | monitors that may exist (1-100); see [Monitoring an address](#monitoring-an-address) |
| `osint_history_days` | 90 | how long stored monitor runs are kept (1-730) |
| `osint_monitor_budget` | 300 | provider units per calendar month for all monitors (0 = unlimited, up to 100000) |

Only configured outside sources use the per-run query budget. A source whose key
is missing is reported as **not configured** without spending any of it (and makes
the run partial), and the **Delivery test context** source never leaves the server
so it is exempt too; neither can crowd out a later source.

Defaults differ between the two front ends. In the **web view** every source is
ticked by default except **Hunter** (its paid mailbox check is chosen for each
run) and, unless the view was opened from a linked Address test, **Delivery test
context**; a source without a key stays ticked and simply reports *not
configured*. The **CLI** without `--providers` runs the configured sources
except `delivery` and `hunter`; name them in `--providers` to use them. Naming
`delivery` in the CLI links no Delivery run, so it reports *not requested* and
the run is partial.

The sources run one after another, so a slow source (RDAP may make two requests,
Hunter may take up to 20 seconds) can push later ones past the deadline; those
are then reported as not finished and the run is partial. Raise
`osint_deadline_secs` if that happens often.

A run request may carry `external_query_limit` to lower the outside-lookup budget
for that run; it is clamped to `osint_max_external_queries` and never raises it. The CLI runs the controller in its own process, so its rate and concurrency limits are separate from the daemon's.

## Sources and keys

| Source (id) | Needs | Returns |
|---|---|---|
| Delivery test context (`delivery`) | nothing | the linked Address test's inputs and verdict counts, next to the OSINT result |
| Gravatar (`gravatar`) | nothing | whether a public avatar exists for the address, and the image |
| RDAP domain registration (`rdap`) | nothing | the domain's registrar and technical registration facts; registrant details are never shown |
| GitHub public-email profile (`github`) | nothing | profiles whose public email field GitHub matched to this address: candidates |
| OpenPGP key (`openpgp`) | nothing | whether a published, owner-verified key exists for the address |
| Have I Been Pwned (`hibp`) | a paid HIBP API key | the breaches the address appears in (name, date, data classes, link) |
| Web search (`search`) | a Brave Search API key | search snippets that mention the address: candidates only |
| Hunter email verification (`hunter`) | a Hunter API key | Hunter's own verdict on the mailbox: a vendor assertion, never proof |

The keyless sources need no configuration. Rate limits to expect: GitHub allows
10 unauthenticated requests per minute, Hunter about 10 per second; a refused
request shows in *Source coverage* and makes the run partial.

Set the three keys (HIBP, Search, Validation) in **Config -> OSINT providers**, each in its own row with its own **Clear** button. A key is write-only in the
page: once saved the label says *configured*, a blank field keeps it, and
**Clear key** removes it. It is stored in `config.toml`, which is readable by
root and by the `mail` group (the MailScanner logging plugin runs in that group
and needs the file). Like the AbuseIPDB and Telegram secrets, it is also visible
in the Config tab's raw view, its history and snapshot exports, so treat those
as secrets. It is passed to the lookup on standard input,
not on a command line, and is redacted from error text.

HIBP has two modes (`osint_hibp_mode`):

- **direct** (default): the full address is sent to haveibeenpwned.com and the
  answer lists the breaches with their details.
- **range**: only a 6-character SHA-1 prefix is sent; HIBP returns every
  matching hash suffix and the server keeps only the rows matching this
  address and discards the rest. It needs the Pro or High RPM plan, returns
  breach names only, and gives no per-incident detail.

## What each source receives

- **Delivery test context**: nothing leaves the server; it reads the linked
  Delivery report.
- **Gravatar**: only a SHA-256 hash of the lower-cased address, sent to
  `gravatar.com`, asking for an avatar at rating G, 256 px. A 404 answer means
  there is no avatar at that rating (one may exist at a higher, more mature rating). No
  Gravatar profile data is queried.
- **RDAP**: only the **domain** (never the full address). The bootstrap file is
  fetched from `data.iana.org`, and the domain is then sent to whichever registry
  RDAP server that file names for the domain's TLD (many different registries,
  including country-code operators; the host is validated, public-address-only and
  HTTPS-only). A TLD with no RDAP service is reported as inconclusive. Registrar and technical
  facts only; registrant details are never shown.
- **GitHub**: the full address, sent to `api.github.com`. GitHub matches it
  against the public email field of profiles; the search answer does not include
  the email and MSFE-NG does not check it, so the profiles are candidates, at
  most three are shown, and a note says when GitHub reports more. The
  unauthenticated limit is 10 requests per minute.
- **OpenPGP**: the full address, sent to `keys.openpgp.org`. Only the presence of
  a published, owner-verified key is reported; the key is not parsed or stored.
- **HIBP, direct mode**: the full email address, sent to `haveibeenpwned.com`.
- **HIBP, range mode**: only a 6-character SHA-1 prefix of the address.
- **Web search**: the full address in quotes, sent to `api.search.brave.com`. The
  results are search snippets only; the pages themselves are not fetched or
  verified, so they are candidates.
- **Hunter**: the full address, sent to Hunter. Hunter performs its own checks of
  the recipient's mail server and uses paid quota. The result is a vendor
  assertion, never proof. It is unticked by default and chosen per run.
- the **fixture** source (only with `MSFE_NG_OSINT_FIXTURE`) receives nothing.

Outbound lookups go only to the hosts above (for RDAP, `data.iana.org` and the
registry host the bootstrap file names), over HTTPS, without
following redirects, and only to public addresses (the process doing the lookup,
the daemon or the CLI, checks the address it actually connects to). Nothing else
leaves the server.

## Delivery context and Investigate buttons

The **Investigate address** buttons (the magnifying glass in the Messages list
and queue, the buttons in the message and queue details, and the button on an
Address test result) only open the OSINT view with the address filled in; nothing
runs until you press **Run**. When opened from an Address test result, the view
links that run, and the **Delivery test context** card shows that run's inputs
(address, sending IP, DKIM selector, log days, server audit) and its verdict
counts per scope (fail, warn, unknown, pass, not applicable) next to the
public-information results. Its **Run Address test** button starts a new Address
test for the address. Reading it makes no outside
request.

## What is deliberately not included

- **Passive DNS and Certificate Transparency**: the data is licensed or
  unreliable, and it describes domains, not one address.
- **HIBP stealer-log metadata**: needs a verified domain and a qualifying
  subscription.
- **GitHub commit search**: needs an authenticated token.
- **OpenPGP key parsing**: a root daemon does not parse untrusted key packets, so
  only presence is reported.
- **Page crawling**: search hits are never fetched.

## Avatars

The server fetches the avatar itself (at most 256 KiB, PNG, JPEG or WebP only,
checked by content), keeps a local copy and shows it from there. The browser
never loads an image from Gravatar, and the HTML export does not embed
avatars. Avatars are removed together with their report.

## Failures and limits of the data

- A provider failure (timeout, refused key, rate limit, bad answer) shows in
  *Source coverage* and makes the run partial. It never affects the Delivery
  tab's other views or mail flow.
- Each source is capped: HIBP 100 findings, Web search 10 results, GitHub 3
  profiles; an avatar is at most 256 KiB. Capped sources say so in their detail.
- The RDAP answer's registrant details are never shown; a limitation says so.
- HIBP's public search may omit findings from breaches it flags as sensitive
  or retired, so a missing breach is not proof of absence.
- Range mode has no per-incident detail.
- Testing, stated plainly: Web search (Brave) and Hunter were exercised only
  against stand-in servers (no keys were available), and HIBP likewise. RDAP,
  GitHub, OpenPGP and Gravatar's no-avatar answer were exercised with live keyless
  lookups of documentation-example addresses and domains. The Delivery context
  finding was verified by Rust tests; the browser check of its card used stubbed
  data.

## Reports and export

Each interactive run is stored as a report under `/var/cache/msfe-ng/osint` (directory mode
`0700`, files `0600`) and deleted after `osint_retention_hours` (24 h by
default); the same applies to avatars. Expired items are swept when the daemon
starts, by `msfe-ng housekeeping` (run daily by cron), and by
`delivery osint sweep`. Only the normalised findings and minimal evidence are
kept, never raw provider replies. A report can be downloaded as JSON or as a standalone HTML
page. The view works without the database. The one exception to the 24-hour rule
is a **monitor run**, which is stored in the database and kept longer, see
[Monitoring an address](#monitoring-an-address).

## Monitoring an address

A **monitor** re-runs the lookup for one address on a schedule and tells you on
Telegram when something new shows up. It is **opt-in** and checks only the
addresses you add. Nothing is watched until you create a monitor, and the whole
feature stays silent (no error, no lookup) when `osint_enabled` is false, when no
database is configured, or when the migration has not been applied
(`msfe-ng db-migrate`; it is applied automatically on upgrade).

- **Schedule.** Interval 24 h, 48 h or 7 days (any value is clamped to 1440-10080
  minutes, so a monitor runs at most daily). The scheduled pass rides the existing
  5-minute `msfe-ng monitor` cron (step 5 of that pass); there is no separate
  timer. A pass runs at most **2** monitors, oldest last run first, and only one pass
  runs at a time (a second one answers "previous pass still running"; a pass that
  died is considered stale after 10 minutes). Monitors still due are picked up on
  the next 5-minute pass.
- **Sources.** The source set you tick is stored with the monitor when it is
  created and is what every run uses. `delivery` can never be monitored, and
  `hunter` (paid quota) is included only if you name it. Each run is a fresh
  lookup, never served from the interactive cache. Adding the same address again
  updates its sources and interval and resumes it.
- **Limit.** At most `osint_max_monitors` monitors (default 10).
- **Admin only.** Monitors, their history and the API are for the WHM admin.

### What is stored

Migration `0006_osint_monitors.sql` adds three tables:

| Table | Holds |
|---|---|
| `osint_monitors` | the address, the approved source set, the interval, enabled or paused, the last run time and a one-line summary |
| `osint_runs` | one row per stored run: time, duration, state, counts and the report (normalised findings and minimal evidence, **without avatars**) |
| `osint_usage` | the provider units charged per calendar month, one row per run |

Monitor runs are the exception to "reports are only files for 24 h": they are
kept for `osint_history_days` (default 90) and at most 100 per monitor, pruned by
the daily `msfe-ng housekeeping`. The daily prune spares only the newest run of
each monitor. The comparison baseline is a pointer to the run last compared
against, which can be older than the newest run and can be removed by the
100-run trim or by the prune; a missing baseline falls back to the run just
before the one being compared. Usage rows are kept for 400 days.
Opening a stored run shows it like any report; its HTML export is a download.

### Monthly budget

Every run spends provider quota, so a monthly cap applies to all monitors
together: `osint_monitor_budget` units per calendar month (UTC), default **300**,
**0 = unlimited**. A unit is one of the monitor's configured sources (a source
without its key is not counted). The units are **reserved before the run** and
**settled afterwards** to the sources that actually took part (not "not
configured" or "not requested"), so a run that did less than planned gives the rest
back. A **failed or timed-out run is charged** in full, because providers may
already have been queried. A run that never started (busy, rate limited, too many
runs, invalid input) is not charged.

When the next monitor would push the month over the cap it is skipped, and stays
due. One **budget alert per month** is sent for that, and only when Telegram is
configured at that moment; if it is not, none is sent that month. Monitoring
resumes next month or when you raise the cap.

### What counts as a change

- **The first run is a baseline** and never alerts. When the baseline run has
  been removed, the comparison falls back to the previous stored run, which can
  alert; only a monitor with no earlier run at all stores a new baseline
  silently.
- A finding is identified by its source, its group and its URL (normalised:
  lower-case scheme and host, no fragment, no trailing slash) or, with no URL, its
  title. Observation time, evidence, confidence and severity do not make a
  finding "new". A finding counts as new
  only when its source answered in the run compared against (or in one of the
  last 10 earlier runs, when the baseline run had no answer from it), so a source
  that missed a run does not re-announce its old findings when it recovers.
  Providers cap their result lists (Brave top 10, HIBP 100, GitHub 3), so a
  list that reorders can occasionally raise a spurious "new" alert.
- A finding that is **new** and in the group exposure, profile, reference or domain
  is alerted. Hunter's validation verdicts and context findings are recorded in
  the history but **never alerted**.
- A finding that is **no longer listed** and a source that **recovers** are history
  only: no alert. A source that did not answer this time never makes its earlier
  findings "gone".
- A source that answered before (matched or no match) and is now **failed or
  restricted** raises one *source problem* alert. Rate limited, inconclusive and
  not configured never alert.

### Alerts

Alerts go to Telegram only (`telegram_bot_token`, `telegram_chat_id`) and are
separate from the Delivery alerts: they have their own keys and texts and never
appear in a Delivery message. A *new items* message names the **address**, the
**host** and up to **5 titles** (with "...and n more"); a *source problem* message
names the address, the host and the source. **This is personal data about the
address, sent to Telegram.** Evidence and links are not included. Use a chat you
control and that fits your data-protection obligations.

No duplicates, no lost alerts: a monitor keeps a baseline pointer to the run it
last compared against. It advances only when every alert it needed was sent (or
Telegram is not configured). A failed send, or a change held back by the cooldown,
leaves the baseline in place so the change is raised again on the next run. Each
monitor and each kind (new items, source problem) has its own cooldown
`alert_cooldown_mins` (default 60), recorded only after a send succeeded.

### Failures, removal and disabling

- Busy, rate limited or too many OSINT runs: nothing was started, nothing is
  charged, and the monitor is tried again on the next pass.
- A run that fails or times out waits a full interval before the next try, is
  charged and stores no report; an invalid one (for example a stored address that
  no longer validates) also waits a full interval, but is not charged.
- A run that cannot be stored is charged and waits a full interval.
- **Remove** deletes the monitor with its runs, usage rows and alert keys.
  **Disable** (pause) keeps the history. A run in flight when its monitor is
  removed or disabled **stores nothing and alerts nothing**, and its reservation is
  released.

### From the shell

```
msfe-ng delivery osint monitor list [--json]
msfe-ng delivery osint monitor add <address> [--sources a,b] [--interval-mins n]
msfe-ng delivery osint monitor remove <id|address>
msfe-ng delivery osint monitor enable <id>
msfe-ng delivery osint monitor disable <id>
msfe-ng delivery osint monitor run [--dry-run] [--id n]
msfe-ng delivery osint monitor history <id> [--json]
```

`add` without `--sources` takes the configured sources except `delivery` and
`hunter`; the interval defaults to 1440 minutes. `run` makes a pass now (with
`--id n` that monitor is made due first; `--dry-run` only lists what is due) and is
subject to the same 2-per-pass, budget and one-pass-at-a-time rules; `remove` takes
an id or the exact address.

| Exit | Meaning |
|---|---|
| 0 | done |
| 1 | the database is unavailable or the migration is missing, the monitor limit is reached, or no such monitor |
| 2 | usage error |
| 3 | invalid input (address, sources, interval) |

### In the WHM view

The **Monitors** card of the OSINT view lists the monitors with their sources,
interval, last run and result. It shows the month's budget use and whether Telegram
is configured; the add form has the address, an interval and the sources (the same
defaults as the Run form, Hunter unticked). Each row has *run now*, *history*
(each stored run can be opened in the view, avatars are not kept, or downloaded as
HTML), *pause*/*resume* and *remove*. Opening the card queries no provider.

### API

Admin only, under `/api/delivery/osint/monitors`:

| Request | Meaning |
|---|---|
| `GET` | the monitors, the limit, the month's budget (`cap`, `used`, `period`), whether Telegram is configured and whether OSINT is on |
| `POST` `{address, sources[], interval_mins}` | add (201); 403 when OSINT is off; 400 for a bad address, source list or the monitor limit |
| `DELETE ?id=` or `POST /remove {id}` | remove (404 when unknown) |
| `POST /enable {id, enabled}` | pause or resume |
| `POST /run {id}` | make it due and start a pass (202); 403 when OSINT is off, 409 when paused or a pass is already running |
| `GET /runs?id=&limit=` | the stored runs (limit 1-200, default 50) |
| `GET /report?run=[&format=html]` | one stored report, as JSON or an HTML download |

Without the database or the migration these answer 503 with a hint; an SQL
error on a write is a 500 with a fixed message.

### Privacy and provider terms

Monitoring multiplies what each provider sees: the same address is sent again every
day or week, and the providers (and your history table) hold that data for longer
than a one-off lookup. Check each provider's terms for **monitoring and
automated use**, and your own data-protection obligations: how long you keep the
history (`osint_history_days`), your lawful basis for watching a person's
address, and informing the person where the law requires it. Add only addresses
you have a reason to watch.

### Testing, stated plainly

The monitor logic (change detection, budget, alerts, retry, cooldown, removal in
flight) is unit-tested with fakes. The SQL and the scheduler were exercised against
a private scratch MariaDB with the fixture provider. Telegram sending was exercised
only through the existing sender and a fake in the tests. No real provider keys
were used for monitoring, so real provider behaviour over repeated runs is
untested.

## From the shell

```
msfe-ng delivery osint <address> [--providers a,b] [--json | --html] [--force]
msfe-ng delivery osint providers [--json]
msfe-ng delivery osint sweep
```

`providers` prints one line per source (tab-separated: id, name,
`configured` or `not configured`, and what it receives, for every source above; `--json` has a
`configured` field); `sweep` deletes reports
older than the retention time. The first form runs the lookup, waits for it and
prints the report (text, or `--json` / `--html`); `--force` skips the cache.

| Exit | Meaning |
|---|---|
| 0 | the run completed |
| 2 | usage error |
| 3 | invalid input, OSINT switched off, or the run failed |
| 4 | partial: some sources did not finish, or the run was cancelled |

A breach or any other finding never changes the exit code.

See also [Delivery test](Delivery-test) and the [CLI reference](CLI).
