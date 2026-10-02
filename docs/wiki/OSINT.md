# OSINT

The **Delivery** tab's fourth view, *OSINT*, collects publicly available
information about one email address, so an operator can judge a suspicious
sender or recipient. Reach it from the *OSINT* pill, or from the magnifying
glass beside the recipient in the Messages list and beside the sender and
recipient in the queue, and the **Investigate address**
button on an Address test result.

> **This release is the groundwork.** The view, the report format, the limits,
> the cache, the export and the CLI are all in place, but no real information
> source ships yet. The only source is a synthetic fixture that appears when
> the environment variable `MSFE_NG_OSINT_FIXTURE` is set (it exists to test
> the plumbing and returns invented data). On a normal install the view lists
> no sources, and a run has nothing to ask. Real providers arrive in later
> releases; this page will say what each one receives when they do.

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
  *Source coverage*, so a gap is never hidden.

## Switching it on

OSINT is off by default. Set it in `config.toml`:

```
osint_enabled = true
```

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
| `osint_max_external_queries` | 5 | most outside lookups one run may make (1-20) |
| `osint_cache_secs` | 3600 | a repeat of the same lookup inside this time reuses the earlier report; *Fresh lookup* bypasses it |
| `osint_retention_hours` | 24 | how long a report is kept (1-720) |

## What each source receives

Each source lists in the view exactly what it is sent (the full address, only
the domain, or a hash prefix) before you run it. In this release:

- the **fixture** source (only with `MSFE_NG_OSINT_FIXTURE`) receives nothing:
  it makes no network request and returns invented data.

No other source exists yet, so nothing leaves the server.

## Reports and export

Each run is stored as a report under `/var/cache/msfe-ng/osint` (directory mode
`0700`, files `0600`) and deleted after `osint_retention_hours` (24 h by
default). Only the normalised findings and minimal evidence are kept, never raw
provider replies. A report can be downloaded as JSON or as a standalone HTML
page. A report simply expires after that time. The view works without the database.

## From the shell

```
msfe-ng delivery osint <address> [--providers a,b] [--json | --html] [--force]
msfe-ng delivery osint providers [--json]
msfe-ng delivery osint sweep
```

`providers` lists the sources and what each receives; `sweep` deletes reports
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
