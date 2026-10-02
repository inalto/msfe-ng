# OSINT

The **Delivery** tab's fourth view, *OSINT*, collects publicly available
information about one email address, so an operator can judge a suspicious
sender or recipient. Reach it from the *OSINT* pill, or from the magnifying
glass beside the recipient in the Messages list and beside the sender and
recipient in the queue, and the **Investigate address**
button on an Address test result.

Two sources ship: **Have I Been Pwned** (HIBP, breach exposure) and
**Gravatar** (a public avatar). Each is listed with exactly what it is sent
before you run it, see [What each source receives](#what-each-source-receives).
A synthetic *fixture* source exists only for tests and demos (it appears when
the environment variable `MSFE_NG_OSINT_FIXTURE` is set, makes no network
request and returns invented data).

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
- **Guessed identities are candidates.** A name or profile inferred from an
  address is a lead to check, not a fact.
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
`config.toml`). HIBP additionally needs an API key, see
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
| `osint_deadline_secs` | 30 | a run is stopped after this long (5-120); what finished is kept as a partial report |
| `osint_max_external_queries` | 8 | most outside lookups one run may make (1-20) |
| `osint_cache_secs` | 3600 | a repeat of the same lookup inside this time reuses the earlier report; *Fresh lookup* bypasses it |
| `osint_retention_hours` | 24 | how long a report and its avatar are kept (1-720) |

Only configured outside sources use this budget; a source with no key is reported as not configured without spending it. In the shell every configured source is ticked by default except Hunter, whose paid mailbox check you tick for the runs where you want it.

A run request may carry `external_query_limit` to lower the outside-lookup budget
for that run; it is clamped to `osint_max_external_queries` and never raises it. The shell runs the controller in its own process, so the
CLI's rate and concurrency limits are separate from the daemon's.

## Sources and keys

| Source | Needs | Returns |
|---|---|---|
| Have I Been Pwned | a paid HIBP API key | the breaches the address appears in (name, date, data classes, link) |
| Gravatar | nothing | whether a public avatar exists for the address, and the image |

Set the HIBP key in **Config -> OSINT providers**. The key is write-only in the
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

- **HIBP, direct mode**: the full email address, sent to `haveibeenpwned.com`.
- **HIBP, range mode**: only a 6-character SHA-1 prefix of the address.
- **Gravatar**: only a SHA-256 hash of the lower-cased address, sent to
  `gravatar.com`, asking for an avatar at rating G, 256 px. A 404 answer means
  there is no avatar at that rating (one may exist at a higher, more mature rating). No
  Gravatar profile data is queried.
- the **fixture** source (only with `MSFE_NG_OSINT_FIXTURE`) receives nothing.

Outbound lookups go only to those two fixed hosts, over HTTPS, without
following redirects, and only to public addresses (the process doing the lookup,
the daemon or the CLI, checks the address it actually connects to). Nothing else
leaves the server.

## Avatars

The server fetches the avatar itself (at most 256 KiB, PNG, JPEG or WebP only,
checked by content), keeps a local copy and shows it from there. The browser
never loads an image from Gravatar, and the HTML export does not embed
avatars. Avatars are removed together with their report.

## Failures and limits of the data

- A provider failure (timeout, refused key, rate limit, bad answer) shows in
  *Source coverage* and makes the run partial. It never affects the Delivery
  tab's other views or mail flow.
- HIBP answers are capped at 100 findings per source.
- HIBP's public search may omit findings from breaches it flags as sensitive
  or retired, so a missing breach is not proof of absence.
- Range mode has no per-incident detail.
- The real-provider code paths were exercised against stand-in servers and,
  for Gravatar's no-avatar answer, one live request; they have not been tried
  with a real HIBP key.

## Reports and export

Each run is stored as a report under `/var/cache/msfe-ng/osint` (directory mode
`0700`, files `0600`) and deleted after `osint_retention_hours` (24 h by
default); the same applies to avatars. Expired items are swept when the daemon
starts, by `msfe-ng housekeeping` (run daily by cron), and by
`delivery osint sweep`. Only the normalised findings and minimal evidence are
kept, never raw provider replies. A report can be downloaded as JSON or as a standalone HTML
page. The view works without the database.

## From the shell

```
msfe-ng delivery osint <address> [--providers a,b] [--json | --html] [--force]
msfe-ng delivery osint providers [--json]
msfe-ng delivery osint sweep
```

`providers` prints one line per source (tab-separated: id, name,
`configured` or `not configured`, and what it receives; `--json` has a
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
