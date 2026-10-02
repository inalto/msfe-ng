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
