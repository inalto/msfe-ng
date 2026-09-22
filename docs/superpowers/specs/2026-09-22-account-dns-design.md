# Account DNS: SPF, DKIM and DMARC for every domain hosted here

*2026-09-22 — design for the "Account DNS" view of the Delivery tab: one scan
over all cPanel domains, a table that shows at a glance which domains have a
missing or wrong SPF, DKIM or DMARC record, and a one-click repair that uses
cPanel's own installers where DNS is hosted on this server.*


## Problem

The Delivery test answers "why does mail from this address fail?" for one
address at a time. Nothing answers the server-wide question an admin asks
after a migration, a DNS move or a customer complaint: "which of my accounts
have broken mail authentication right now?". cPanel's WHM → Email
Deliverability page lists domains but is slow, hides subdomain noise poorly and
gives no DMARC view. The user wants a tool in MSFE-NG that quickly spots DNS
misconfigurations on local accounts and offers an easy fix.

Decisions taken (design made autonomously at the user's request; assumptions
are called out):

- **Scope: SPF, DKIM and DMARC per domain.** SPF and DKIM were asked for; DMARC
  is added because Gmail/Yahoo bulk-sender rules make a missing DMARC record a
  delivery failure today and it is one more TXT record in the same zone. PTR is
  a per-IP property already covered by the delivery test and is left out.
- **Verdicts come from cPanel's own validators** (`whmapi1
  validate_current_spfs`, `validate_current_dkims`, `has_local_authority`; all
  accept several `domain=` arguments per call), so what the scan says "missing"
  is exactly what cPanel's *Repair* would install. The repo's own DNS client
  and parsers (`spf.rs`, `dkim.rs`, `dmarc.rs`) add what cPanel does not
  check: DMARC, SPF lookup count and `all` qualifier, DKIM key strength.
- **Fixes are cPanel's installers**, never hand-edited zone files:
  `install_spf_records`, `ensure_dkim_keys_exist` + `enable_dkim`,
  `addzonerecord` (DMARC). They work when the zone lives on this server; when
  DNS is hosted elsewhere the tool shows the exact record to publish there,
  with a copy button, and still generates a missing DKIM key.
- **It lives inside the Delivery tab**, which the rail now calls **Delivery**
  (the user's request). The tab gets two views: *Address test* (everything
  that exists today) and *Account DNS* (this feature).
- **cPanel only** for now. On DirectAdmin or a bare host the view says so; the
  module is written so a DirectAdmin backend can be added behind the same row
  model later.

Verified on the reference host (cPanel 138): `whmapi1 --output=json
validate_current_dkims domain=a domain=b` returns `data.payload[]` with
`{domain:"default._domainkey.a", state, expected, records:[{current,state}],
error}` and states `VALID | MISMATCH | MISSING | NOPUB` (NOPUB = no key on this
server, `expected` empty); `validate_current_spfs` returns `data.payload[]`
with `{domain, state, expected:"ip4:1.2.3.4", ip_address, ip_version,
records:[{current,state}], error}` and states `VALID | MISSING | MISMATCH`
(other strings are possible; unknown strings map to *unknown*);
`has_local_authority` returns `data.records[]` with `{domain, zone,
local_authority:0|1, nameservers:[..], error}` (`zone` is the local zone that
holds the name, e.g. the parent zone for a subdomain; `null` when no local
zone; a domain can have a local zone file and `local_authority:0` when its NS
records point elsewhere — a hidden primary or a stale copy). `getzonerecord`
needs a line number and is not usable for verification.
`/var/cpanel/userdata/<user>/main` (YAML-ish) lists `main_domain`,
`addon_domains` (addon → its service subdomain), `parked_domains`,
`sub_domains`. Every cPanel domain, subdomains included, gets a DKIM key and
is listed by cPanel's validators. The reference host has a real DKIM MISMATCH
on its main domain (zone here, NS elsewhere) and MISSING SPF/DKIM on every
subdomain — the two cases the UI must make readable.

Hard constraints (unchanged): zero external crates; every non-GET handler holds
`WRITE_LOCK`; subprocesses on a request path run through
`service::run_with_timeout`; the daemon runs as root and `whmapi1` is available
to it; no server names in commits, fixtures, comments or docs.


## Existing code reused

`cpaudit::Cp` (fixture-or-live host with `cmd`/`whmapi1` and
`MSFE_NG_CPANEL_ROOT` for tests), `cpaudit::domain_kind`,
`cpaudit::pem_to_der_b64`, `users::valid_username`, `netguard::valid_hostname`,
`dns::Client` (+ the fake UDP server in its tests), `spf::{parse, walk}`,
`dkim::parse_record`, `dmarc::lookup`, `json::Json`, `service::run_with_timeout`,
`sync::atomic_write`, the Delivery tab's SPA helpers (`el`, `api`, `modal`,
`toast`, `copyBtn`, `deliveryTestFor`, `.dlv-table` / `.dot` / `.chip` CSS).


## Module `acctdns.rs` (msfe-core)

```rust
pub enum Kind { Main, Addon, Parked, Sub }                 // "main"|"addon"|"parked"|"sub"
pub enum State { Ok, Missing, Mismatch, NoKey, Weak, Error, Unknown, NotApplicable }
// "ok"|"missing"|"mismatch"|"no_key"|"weak"|"error"|"unknown"|"na"
pub enum Level { Fail, Warn, Ok, Unknown }                  // the row colour
pub struct Domain { pub domain: String, pub user: String, pub kind: Kind, pub mail: cpaudit::DomainKind }
pub struct Zone { pub name: Option<String>, pub local_authority: bool, pub nameservers: Vec<String> }
pub struct Check {
    pub state: State, pub level: Level, pub raw_state: String,   // cPanel's word, "" for our own checks
    pub summary: String,          // ≤ 60 chars, the table cell ("not published", "server IP not authorized", "key differs from this server's", "1024-bit key", "p=none")
    pub detail: String,           // one paragraph for the expanded row
    pub current: Vec<String>,     // records seen in DNS
    pub expected: Option<String>, // cPanel's `expected` (SPF mechanism / DKIM record) or our own
    pub suggested: Option<String>,// the full record to publish, zone-file form: `name. 14400 IN TXT "…"`
    pub fixable: bool,            // an Apply button makes sense (zone is here, or DKIM key generation)
    pub fix_note: Option<String>, // "DNS is hosted elsewhere …", "the key must be generated first"
    pub notes: Vec<String>,       // extra findings: "SPF needs 12 DNS lookups (limit 10)", "+all", "t=y"
}
pub struct Row { pub domain: Domain, pub zone: Zone, pub spf: Check, pub dkim: Check, pub dmarc: Check, pub level: Level, pub checked_at: u64 }
pub struct Scan { pub id: String, pub started: u64, pub finished: Option<u64>, pub done: bool, pub total: usize, pub rows: Vec<Row>, pub errors: Vec<String>, pub panel: String, pub supported: bool }
```

Pure functions (unit-tested with captured JSON rewritten to documentation
domains):

- `list_domains(cp) -> Vec<Domain>`: `/etc/userdomains` (skip `*`), owner via
  the file, kind from `/var/cpanel/userdata/<user>/main` (`parse_userdata_main
  (text) -> UserdataMain{main, addon: Vec<(domain, service_sub)>, parked, subs}`;
  a domain not found in userdata is `Sub` when it is a proper subdomain of
  another domain of the same user, else `Main`), `mail` via
  `cpaudit::domain_kind`. Sorted: user, then main → addon → parked → sub, then
  name. The server hostname is not an account domain and is left out.
- `parse_validate_spfs(json) -> Vec<(domain, SpfResult{state, expected, ip, records, error})>`,
  `parse_validate_dkims(json)` (strips the `default._domainkey.` prefix),
  `parse_local_authority(json) -> Vec<(domain, Zone)>`. Tolerant: missing
  fields → *unknown* with the reason.
- `suggest_spf(current: &[String], expected: &str, out_ip: Option<IpAddr>) -> String`:
  no record → `v=spf1 +mx +a {expected} ~all` (cPanel's default shape);
  one record → the record with `{expected}` inserted before its `all` term
  (or `~all` appended when there is none), untouched when it already contains
  the mechanism; several records → their mechanisms merged in order, deduped,
  one `all` (the first seen; `~all` when none). Never produces two `v=spf1`.
- `spf_notes(client, domain, record) -> Vec<String>`: `spf::parse` error →
  "syntax: …" (level Fail); `+all` → Fail note; `?all` / no `all` → Warn;
  `spf::walk` lookups > 10 → Fail note, 9–10 → Warn; `ptr` → Warn.
- `dkim_notes(record) -> Vec<String>`: `dkim::parse_record` → RSA < 1024 →
  Fail, 1024–2047 → Warn "1024-bit key — regenerate with 2048 bits", `t=y` →
  Warn, revoked (`p=` empty) → Fail.
- `dkim_suggested(domain, expected_or_pem) -> String`:
  `default._domainkey.{domain}. 14400 IN TXT "v=DKIM1; k=rsa; p=…"` — from
  cPanel's `expected` when present, else from
  `/var/cpanel/domain_keys/public/{domain}` via `pem_to_der_b64`, else `None`.
- `suggest_dmarc(domain) -> String`: `_dmarc.{domain}. 14400 IN TXT "v=DMARC1; p=none; rua=mailto:postmaster@{domain}"`
  (assumption: `p=none` with reports to postmaster is the safe first record;
  the modal lets the admin edit it before applying).
- `dmarc_check(client, domain) -> Check`: `dmarc::lookup` → own record →
  `Ok` (`p=reject`/`quarantine`) or `Warn`-level `Ok` with summary `p=none`
  (state stays `Ok`, level Warn, note "monitor-only policy"); inherited from
  the organisational domain → `NotApplicable` for subdomains (summary
  "inherited from {org}: p=…"), `Missing` otherwise; ≥2 records or parse error →
  `Error`; DNS failure → `Unknown` ("could not look up: …").
- `classify_spf(res, notes) -> Check`, `classify_dkim(res, notes, key_exists) -> Check`:
  VALID → Ok; MISSING → Missing (Fail); MISMATCH → Mismatch (Fail); NOPUB →
  NoKey (Fail, summary "no key on this server", fixable = true — key
  generation works without local DNS); error / other → Unknown. A Warn-level
  note on an Ok state keeps state Ok and raises the level to Warn (e.g. Weak
  is a state only when cPanel says VALID and the key is < 2048 bits).
  `fixable` = zone.name.is_some() for SPF/DMARC; for DKIM also when NoKey.
  `fix_note` explains: no local zone → "DNS for this domain is hosted
  elsewhere ({nameservers}) — publish the record there"; local zone but not
  authoritative → "this server holds a copy of the zone but the domain's name
  servers are {ns}: cPanel updates the local copy; publish the record at those
  servers too unless they replicate from here".
- `row_level(spf, dkim, dmarc) -> Level`: worst of the three (`Fail > Warn >
  Unknown > Ok`; NotApplicable counts as Ok).

Live functions:

- `validate(cp, client, domains: &[Domain]) -> Vec<Row>`: chunks of 25 →
  `whmapi1 validate_current_spfs domain=… domain=…` (fixture name
  `acctdns_spfs`), `validate_current_dkims` (`acctdns_dkims`),
  `has_local_authority` (`acctdns_authority`), each through `cp.whmapi1` with
  a 120 s timeout (a chunk validates through DNS); a call that fails marks the
  chunk's checks *unknown* with the reason and pushes to `Scan.errors`. DMARC
  and the note functions run per domain through the shared `dns::Client`.
- Scan registry: `static SCAN: Mutex<Option<Arc<ScanState>>>`; `start(cfg,
  only: Option<Filter{user, domain}>) -> Result<String, StartError{Busy(id),
  Unsupported}>` spawns one thread, chunk by chunk, appending rows (progressive);
  `snapshot() -> Option<Scan>`; a finished full scan is written to
  `{cache_dir}/acctdns.json` (`MSFE_NG_ACCTDNS_FILE` overrides; default
  `/var/cache/msfe-ng/acctdns.json`, 0600) and `last() -> Option<Scan>` loads
  it when nothing is in memory (the tab shows the last result at once, with its
  age). A scan of one domain (after a fix, or from the CLI) runs inline:
  `check_one(cp, client, domain) -> Option<Row>`.
- `fix(cp, domain, what: What{Spf, Dkim, Dmarc}, record: Option<String>) -> Result<FixReport{actions: Vec<String>, row: Option<Row>}, String>`:
  - validates `domain` (`valid_hostname`, hosted here via `list_domains`),
    `record` (SPF must start with `v=spf1` and parse; DMARC must start with
    `v=DMARC1` and parse; ≤ 450 chars; no `"`);
  - Spf → `whmapi1 install_spf_records domain={d} record={record or suggested}`;
  - Dkim → `whmapi1 ensure_dkim_keys_exist domain={d}` then `whmapi1 enable_dkim domain={d}`
    (installs the record when the zone is local; enables signing);
  - Dmarc → `whmapi1 addzonerecord domain={zone} name=_dmarc.{d}. type=TXT ttl=14400 txtdata={record}`
    (only with a local zone; refused otherwise with the record to copy);
  - each call: `run_with_timeout` 60 s, `metadata.result == 1` else
    `Err(metadata.reason)`; the transcript lists the command (record values
    quoted) and cPanel's reason;
  - then `check_one` for the row; when the validator still reports the old
    state the report adds "installed — resolvers keep the old answer until the
    record's TTL expires; rescan later" and the row is returned as is with
    `checked_at`.
  Under `MSFE_NG_CPANEL_ROOT` the installers read `_cmd/acctdns_fix_<what>.txt`
  so the daemon and CLI paths are testable.

`to_json` / `from_json` for `Scan`, `Row`, `Check` (the conftest style).


## API (`acctdns_api.rs`, routed like `delivery_api` on `/api/acctdns/`)

| Route | Body/params | Response | Lock |
|---|---|---|---|
| `GET /api/acctdns/scan` | `id?` | the current or last `Scan` as JSON (`{supported, panel, id, started, finished, done, total, rows, errors, age_secs}`); `{supported:false, panel}` on non-cPanel; `404` when nothing has ever run | none |
| `POST /api/acctdns/scan` | `{user?, domain?}` | `202 {id}`; a scan already running → `200 {id, running:true}`; `{domain}` given → inline `200 {row}` (one domain, ≤ 20 s); `400` on a bad name; `501 {error}` when unsupported | brief (the full scan is a thread) |
| `POST /api/acctdns/fix` | `{domain, what:"spf"\|"dkim"\|"dmarc", record?}` | `200 {ok, actions, row}` / `400 {error, actions}` | WRITE_LOCK, ≤ 3 × 60 s |

Errors are `{error}`; the daemon never panics on missing fields
(`Json::get`). Admin surface only (no `/api/user/` variant yet).


## UI (`web/whm/index.html`, CSS in `web/src/app.css` then `npm run build`)

- Rail: the `data-tab="delivery"` label becomes **Delivery** (icon unchanged).
  Card titles, the row icon tooltip ("Run a delivery test for …") and the wiki
  page name keep "Delivery test" — the address test is still called that.
- `renderDelivery()` becomes a dispatcher: a pill row at the top of the view
  (`.dlv-views`: two buttons, `aria-selected`), `DLV_VIEW = 'test'|'accounts'`
  (module variable, default `test`); `deliveryTestFor()` sets `test`. The
  existing body moves unchanged into `renderDeliveryTest(v)`; the new view is
  `renderAcctDns(v)`.
- `renderAcctDns(v)`:
  - **Card** "Account DNS — SPF, DKIM and DMARC for every domain hosted here"
    with a two-line explanation (what is checked, that fixes use cPanel's own
    installers, that DNS hosted elsewhere gets a record to copy).
  - **Controls** (`.ctl`): **Scan** button (disabled while running; label
    "Scanning… 12/48" from `rows.length/total`), "last scan {fmtTime} · {n}
    domains" (or "never scanned"), filter input (domain or account, live),
    checkbox **only problems**, checkbox **hide subdomains** (default on; the
    hidden count shown as "· 7 subdomains hidden" — cPanel signs and validates
    every subdomain, most never send mail), summary chips (`dlvChips`-style:
    fail / warn / ok / unknown counts over the visible rows).
  - Unsupported (`supported:false`) → the card shows "Account DNS needs
    cPanel (this host: {panel})" and no controls.
  - **Table** `.dlv-table.acct-table`: columns *Domain* (name, `.muted`
    account, `.kb` chips `addon`/`parked`/`sub`, `.kb` "mail elsewhere" when
    `mail != local`, the paper-plane `dtlink` for `postmaster@{domain}`), *DNS*
    (`here` / `copy here, NS elsewhere` / `elsewhere`, title = name servers),
    *SPF*, *DKIM*, *DMARC* (each: `.dot {level}` + summary text), *Actions*
    (**Repair** button when any check is `fixable`, else "copy records" when a
    suggested record exists, else empty). Rows sorted fail → warn → unknown →
    ok, then domain. Row click opens the detail row (same mechanism as the
    delivery renderer): per check a block with the detail paragraph, the
    `notes` list, `current` records in `pre.log`, the suggested record in
    `.dlv-rec` with `copyBtn`, `fix_note` in `.muted`, and an **Apply** button
    when `fixable` (per check).
  - **Repair modal** (`modal('Repair ' + domain)`): one section per fixable
    check with a checkbox (checked), the action in words ("Install the SPF
    record", "Generate the DKIM key and publish it", "Add a DMARC record"),
    the record in a `textarea.mono` (editable for SPF and DMARC; read-only
    for DKIM), the `fix_note` when present, then **Apply selected**. Applies
    sequentially via `POST /api/acctdns/fix`, shows each transcript in a
    `pre.log` inside the modal, replaces the row from the returned `row`,
    toasts "Repaired — rescan later if a resolver still shows the old record".
  - Polling: `dlvAcctTimer` (declared next to `dlvTimer`, cleared in the
    tab-switch handler) every 1.5 s while `!done`; rows are added
    incrementally (keyed by domain, no flicker).
  - Mobile: the table collapses to a 2-column grid per row (`Domain` spans,
    the three checks stack with their label); `.acct-table` overrides the
    `.card table` nowrap rule.
- CSS additions: `.dlv-views`, `.acct-table` column widths, `.acct-cell`
  (dot + text), `.acct-detail` blocks, `textarea.mono`.


## CLI

```
msfe-ng acctdns scan [--user <u>] [--domain <d>] [--all] [--json]
msfe-ng acctdns fix <domain> <spf|dkim|dmarc> [--record <r>] [--json]
```

`scan` prints one line per domain (`[FAIL] example.com  spf: not published  dkim: ok  dmarc: missing`), subdomains only with `--all`, then a summary; exit 0 / 1 when any row is Fail / 2 usage / 3 unsupported panel. `fix` prints the transcript and the re-checked row; exit 0 / 1 on error / 2 usage. `accepted_flags`, `usage_of("acctdns")`, `print_help` lines as for `delivery`.


## Wiki / docs

- New page `docs/wiki/Account-DNS.md` (what is checked, the three states and
  what cPanel's installers do, the "DNS elsewhere" case, subdomains, safety:
  only cPanel's own API calls, nothing hand-edited, every apply confirmed),
  linked from `_Sidebar.md` under *Delivery test*, `Home.md`, `README.md`
  feature list and the rail label in `Admin-UI-basics.md` ("Delivery" tab with
  its two views). `CLI.md` gains the two commands. A screenshot
  `docs/img/account-dns.png` is taken by the user later.


## Tests

- `acctdns.rs`: parsers on captured JSON (VALID/MISSING/MISMATCH/NOPUB,
  subdomain zone, `zone:null`, `error` set, `payload` missing); `suggest_spf`
  (none / one without all / one with `-all` / already contains / two records /
  `redirect=`); `dkim_suggested` from PEM; `suggest_dmarc`; `dmarc_check`
  against the fake DNS server (own, inherited for a subdomain, none, two
  records, timeout → unknown); `classify_*` levels; `row_level`;
  `parse_userdata_main` on the captured layout; `list_domains` on a fixture
  tree (`MSFE_NG_CPANEL_ROOT` with `etc/userdomains`, `etc/trueuserdomains`,
  `etc/localdomains`, `var/cpanel/userdata/<u>/main`, `_cmd/*.txt`);
  `validate` end to end on the fixture tree (chunking asserted by a fixture
  that holds every domain); `fix` argument validation (bad record, unknown
  domain, DMARC without a local zone → Err with the record in `actions`);
  `to_json`/`from_json` round trip; the registry (`start` twice → Busy,
  snapshot progressive, `last()` from the file).
- Daemon: `GET` before any scan → 404, `POST` bad domain → 400, unsupported
  panel → 501, fix without `what` → 400.
- CLI: `acctdns scan --bogus` → 2 with usage; `acctdns fix` without args → 2;
  `acctdns scan --json` under a fixture root prints rows.
- Reference host (by the user, after "go"): full scan, the main domain's DKIM
  MISMATCH row explains the "copy here, NS elsewhere" case, a subdomain's
  SPF/DKIM MISSING rows are hidden by default, Repair on an addon domain with
  a local zone installs SPF + DMARC and the row turns green after the TTL.


## Step sequence (each: code + tests + `cargo test --workspace` + clippy + `npm run build` when UI + commit)

1. `acctdns.rs` (model, parsers, suggestions, classification, DMARC check,
   `list_domains`, `validate`, `check_one`, `fix`, registry, persistence,
   JSON) + fixtures + `lib.rs`.
2. `acctdns_api.rs` + routing in `api.rs`; CLI `acctdns scan|fix`; tests.
3. UI (rail label, view pills, `renderAcctDns`, repair modal, CSS) + wiki,
   README, CLI.md, sidebar.

Steps 2 and 3 are independent once step 1's JSON contract exists.


## Risks and mitigations

| Risk | Mitigation |
|---|---|
| `whmapi1` validators are slow on big hosts (they resolve every domain) | chunks of 25 in a background thread, progressive rows, the last scan cached on disk and shown at once |
| Negative DNS caching makes a fresh fix still read "missing" | the fix report says so and the row keeps the applied note; the admin rescans later; the installer's own `metadata.reason` is the proof of the write |
| A "fix" on a domain whose zone is a stale local copy | the DNS column names the case, the modal repeats it, the record to copy is always shown |
| cPanel state strings beyond the four observed | unknown strings → *unknown* with `raw_state` shown, never a fix |
| Subdomain noise | hidden by default with a count; `sub` chip; sorted last |
| Record injection via `record` | validated (`v=spf1`/`v=DMARC1` prefix, parser accepts, no quotes, length cap); passed as one argv element, never through a shell |
| Non-cPanel hosts | `supported:false` end to end; nothing runs |
