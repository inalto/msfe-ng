# Delivery → OSINT, Phases 3, 4 and 6 (more sources) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the remaining spec sources on the phase 2 transport: RDAP domain context, the linked-Delivery-run context card and entry points (phase 3); exact-address web search via Brave Search (phase 3) and Hunter email validation (phase 4); GitHub public-email profile and OpenPGP public-key presence (phase 6).

**Architecture:** Each source is one adapter in `osintproviders.rs` using `providerhttp::fetch`, returning the existing `Outcome` (one `SourceStatus` plus `Finding`s). New secrets follow the `osint_hibp_key` template. RDAP is the only source with dynamically discovered hosts (from the IANA bootstrap), so `providerhttp::Request.host` becomes a validated `String`; every connection still goes through `outbound_allowed(ip, false)`, pinning, HTTPS-only, no redirects.

**Tech Stack:** Rust 1.74 std only, system `curl`, vanilla JS.

**Spec:** `docs/superpowers/specs/2026-10-02-delivery-osint-design.md` (§3 results/Delivery context, §4, §8 phases 3, 4, 6, §12, §18). Earlier plans: phase 1 and phase 2 in `docs/superpowers/plans/`. Phase 5 (history and monitoring) has its own plan.

**Branch policy:** the user asked for phases to be committed directly on `main`. Commit each task to `main`; do not push, tag or release unless the user asks.

## Scope rulings (recorded; the user can reverse them)

- **Included:** RDAP, linked Delivery context card, entry points from message/queue details, Brave Search (exact-address snippets), Hunter validation, GitHub public-email user search, OpenPGP key presence.
- **Excluded, with reasons:** SecurityTrails-style passive DNS (licensed, paid contract, domain-level only); Certificate Transparency lookup (crt.sh is unreliable, large and domain-level, no stable contract); HIBP stealer-log metadata (requires a verified domain and a qualifying subscription); GitHub commit search (requires an authenticated token); OpenPGP key packet parsing (a root daemon must not parse untrusted rich documents; only presence is reported); fetching or crawling pages named by search results (spec: no general crawling in the first versions).
- **Providers chosen by me, where the spec left it open:** Brave Search API for exact-address search, Hunter for validation. Both are optional, key-gated and off until a key is saved.

## Global Constraints

- Rust 1.74, edition 2021, std only; `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; no test touches the network or needs a real key (stand-in servers via `MSFE_NG_OSINT_BASE_<PROVIDER>`).
- Every OSINT destination: `outbound_allowed(ip, false)`, pin, HTTPS only, no redirects, credentials only on curl's stdin to the provider's own origin; the connected IP is verified (phase 2 transport).
- Secrets (`osint_search_key`, `osint_validation_key`) follow the `osint_hibp_key` template: never in `to_public_json` (only `*_set`), blank-keeps, Clear key, save-time validation (ASCII alphanumerics, `-`, `_`, ≤128 chars), never in argv, logs, reports, errors.
- External text (titles, snippets, bios, names, registrar strings) is untrusted: strip control characters and HTML tags, cap lengths, render as text only; only `http://`/`https://` URLs become links.
- "No match", `not_configured` and a failed source are never worded as safe; a candidate stays a candidate (confidence Low/Medium with a reason); nothing is verified against a page we did not fetch.
- Each source returns at most the caps below; truncation is stated in the result.
- No SMTP probing from MSFE-NG; Hunter's check is a vendor assertion and is labelled as such.
- A source never changes mail filtering or the CLI exit code (0/2/3/4 unchanged).
- Defaults: new sources are listed in `providers` always; unconfigured keyed sources report `not_configured`; keyless sources (RDAP, GitHub, OpenPGP) work immediately; `osint_enabled` still gates everything.
- No server names (the user's production hostnames) in commits, docs, code or comments (public repo). Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- If a Tailwind class is added, `npm run build` in `web/` and commit `web/whm/app.css` and `web/user/app.css`.

## Review Focus

- A search snippet or bio containing `<script>`, `<b>`, control characters or a 5 KB string must come out as short plain text. Pinned in Tasks 5 and 7.
- An RDAP bootstrap entry pointing at `http://…`, an IP literal, `localhost`, a host with spaces/uppercase tricks or a port must be refused, never fetched. Pinned in Task 3.
- Hunter 202 (pending), 222, 403 vs 429, 451 each map to a distinct honest state; never "valid". Pinned in Task 6.
- GitHub 403/429 (rate limit) must be `rate_limited`, not `failed`, with a sensible `retry_after` when the header is present. Pinned in Task 7.
- An address with `+`, `%`, `:`, `/` in the local part must be percent-encoded in every query/path. Pinned in Tasks 5–7.
- A linked Delivery run that has expired must give an honest "no longer available", never stale data from a different run. Pinned in Task 4.
- A domain whose RDAP says "redacted for privacy" must be reported as redacted, not guessed. Pinned in Task 3.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/msfe-core/src/providerhttp.rs` (modify) | `Request.host: String`, hostname validation helper (Task 1) |
| `crates/msfe-core/src/config.rs` (modify) | `osint_search_key`, `osint_validation_key`, `_set` flags (Task 2) |
| `crates/msfe-ngd/src/api.rs` (modify) | Save-time validation of the two keys (Task 2) |
| `crates/msfe-core/src/osintproviders.rs` (modify) | `rdap`, `delivery`, `search`, `hunter`, `github`, `openpgp` adapters + `infos` (Tasks 3–7) |
| `crates/msfe-core/src/osintrun.rs` (modify) | Pass the linked Delivery run id into `QueryCtx` (Task 4) |
| `web/whm/index.html` (modify) | Config card rows (Task 2), Delivery-context card + entry buttons (Task 4), source list text |
| `docs/wiki/OSINT.md`, `Config.md`, `CLI.md`, `Home.md` (modify) | Operator docs (Task 8) |

---

### Task 1: Dynamic hosts in the transport

**Files:** Modify `crates/msfe-core/src/providerhttp.rs` and every caller (`osintproviders.rs`).

**Interfaces:**
- `Request.host` changes from `&'static str` to `String`. Add `pub fn valid_public_hostname(h: &str) -> bool`: ASCII letters/digits/`-`/`.`, lower-case only, 3–253 chars, contains at least one `.`, no label empty/longer than 63/starting or ending with `-`, not all-numeric (no IP literals), no `localhost`, no trailing dot. `fetch` returns `HttpError::Refused("invalid host")` when it fails (also when the override is in use, keep the check).
- Existing callers (`hibp`, `gravatar`) pass `"haveibeenpwned.com".to_string()` etc. Tests that construct `Request` literals are updated.

- [ ] **Step 1: Failing tests** (providerhttp tests): `valid_public_hostname` accepts `rdap.verisign.com`, `a-b.example.org`; rejects `""`, `localhost`, `LOCALHOST.com`, `Example.org`, `1.2.3.4`, `[::1]`, `a b.com`, `a..b.com`, `-a.com`, `a-.com`, `host:8080`, `host.com.`, `host.com/path`, `x`, a 254-character name, a 64-character label, and non-ASCII; and `fetch` with `host: "127.0.0.1".into()` (no override) returns `Refused`.
- [ ] **Step 2: Run to verify failure:** `PATH=$HOME/.cargo/bin:$PATH cargo test -p msfe-core providerhttp:: 2>&1 | tail`.
- [ ] **Step 3: Implement** the type change and helper; fix compile errors in callers and tests.
- [ ] **Step 4: Gates + commit:** fmt, clippy, `cargo test --workspace`.

```bash
git add -A crates
git commit -m "OSINT: validated dynamic hosts in the provider transport (phase 3)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Search and validation key settings

**Files:** Modify `crates/msfe-core/src/config.rs`, `crates/msfe-ngd/src/api.rs` (`osint_setting_error`), `web/whm/index.html` (OSINT providers card), `packaging/install.sh` (seed), tests.

**Interfaces:** `Config.osint_search_key: String`, `Config.osint_validation_key: String` (default empty); public JSON `osint_search_set`, `osint_validation_set` (bools; never the values). Follow the `osint_hibp_key` implementation of phase 2 exactly (struct/Default/parser/`to_public_json`/card input with `dataset.secret='1'`/Clear key button/install.sh seed/save validation/test that the keys never appear in public JSON and bad characters are refused with 400 and the file unchanged).

- [ ] **Step 1: Failing tests** modelled on the existing HIBP key tests (config round trip + redaction; `conf_apply` 400s for backslash, quote, newline, and a non-alphanumeric character; clean 32-char keys accepted).
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement.** In the card, add two password rows: "Search key (Brave Search API)" and "Validation key (Hunter)", each with "(configured — leave empty to keep)" from the `_set` flag and a Clear key button after `confirm()`, rendered with `el()` text children. Extend the card's explanatory text: search sends the full address in quotes to Brave; validation sends the full address to Hunter and uses paid quota.
- [ ] **Step 4: Gates (incl. web build/node --check as in phase 2) + commit**

```bash
git add -A crates web packaging
git commit -m "OSINT: search and validation key settings with redaction and Config card rows (phase 3/4)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: RDAP domain context (`rdap`)

**Files:** Modify `crates/msfe-core/src/osintproviders.rs` (+ tests there).

**Behaviour:** id `rdap`, group `Domain`, keyless. Disclosure: "the domain of the address (not the full address) is sent to the registry's RDAP server (found through the IANA bootstrap file)".
1. Fetch the IANA bootstrap `GET https://data.iana.org/rdap/dns.json` (host `data.iana.org`, `max_body` 512 KiB), cached in a static `Mutex<Option<(Instant, Vec<(Vec<String>, Vec<String>)>)>>` for 24 h. Parse `{"services":[[["com","net"],["https://rdap.verisign.com/com/v1/"]],…]}`; a malformed document is `Failed("unexpected bootstrap answer")`.
2. Take the TLD of the address's domain (last label, lower-case); find the service whose TLD list contains it; take the first URL; accept only `https://<host>/<path>` where `valid_public_hostname(host)` and there is no port, userinfo, query or fragment; otherwise `Failed("no usable RDAP server for .tld")`.
3. `GET {base}domain/{pct_encode(registrable domain)}` with header `Accept: application/rdap+json` (the domain from the address, lower-cased; no PSL logic in this phase: query the address's full domain; a 404 for a subdomain-only domain is reported as NoMatch with the limitation text "RDAP answers for registered domains; the address's domain may be a subdomain"). `max_body` 512 KiB.
4. Map: 200 → Matched; 404 → NoMatch; 429 → RateLimited (+retry_after); 400/501 → Inconclusive ("the registry does not answer this query"); other/HttpError → Failed (redacted).
5. Findings (all `Domain`, confidence `High` for registry data with reason "published by the domain's registry", `event_at` from the event date): one summary finding with title `Registration: <ldhName>`, evidence built from plain-text pieces: registrar (entity with role `registrar`, vcard `fn`), events (`registration`, `last changed`, `expiration`, `YYYY-MM-DD`), status values (≤8), nameservers (≤8 `ldhName`), `secureDNS.delegationSigned` → "DNSSEC: signed/not signed". If no registrant entity details or the remarks contain "redacted"/"privacy", add the limitation "Registrant details are redacted by the registry; no owner identity is shown." Never print registrant personal data even if present (this release shows registrar and technical facts only). Define `pub(crate) fn clean_text(s: &str, max: usize) -> String` in this task (remove HTML tags — everything between `<` and `>`; decode only `&amp; &lt; &gt; &quot; &#39;`; drop control characters; collapse whitespace; truncate on a char boundary with `…`) with its own unit tests (tags, entities, control characters, 5 KB input, multi-byte truncation never panics), and use it to strip/cap every string (≤200 chars). `source_url`: `{base}domain/<domain>` only if it passes `safe_url`.
6. Add `rdap` to `infos`/`is_known`; `configured` is always true.

- [ ] **Step 1: Failing tests:** bootstrap parsing (longest/exact TLD match, multiple URLs → first, malformed JSON → error); `rdap_base_for("co.uk"-style multi-label TLD maps by last label "uk")`; refusal of `http://…`, IP literal, `localhost`, `host:8080`, `https://user@host/`, an uppercase host (`https://Rdap.Example.COM/`), empty URL lists; domain-JSON parsing for a sample with registrar vcard, events, statuses, nameservers, `secureDNS`, and a redacted registrant (assert no registrant name appears in the evidence); HTML/`<script>`/control characters in a registrar name are stripped; a 404/429/501 stand-in table (two stand-in servers: one serving the bootstrap JSON pointing at the second; because the override only allows `http://127.0.0.1:<port>` the bootstrap-selected base cannot be used in a stand-in test — structure the code so the registry fetch goes through a function taking the validated base URL and, under the override for provider `rdap_registry`, replaces that base with the loopback stand-in; document this in a comment).
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Real-network smoke (allowed, keyless):** from a scratch crate OUTSIDE the repo (scratchpad `smoke3`, path dependency on `crates/msfe-core`, own `CARGO_TARGET_DIR`) run the `rdap` adapter for `nobody@example.org` and `nobody@example.com`; paste the results (state, evidence).
- [ ] **Step 5: Gates + commit**

```bash
git add -A crates
git commit -m "OSINT: RDAP domain context via the IANA bootstrap (phase 3)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Delivery context card and entry points

**Files:** Modify `crates/msfe-core/src/osintproviders.rs`, `crates/msfe-core/src/osintrun.rs`, `web/whm/index.html`.

**Behaviour:**
- `QueryCtx` gains `pub delivery_run_id: Option<&'a str>`; `worker` passes `inputs.delivery_run_id`.
- New pseudo-source `delivery` (group `Context`, no network): present in `infos` (disclosure "reads the linked Delivery test report on this server; nothing leaves it", `configured` true) and selectable; it is auto-added to the plan when `delivery_run_id` is set (the UI also ticks it). `run("delivery")`: if no id → `NotRequested`("no Delivery run is linked"); `crate::deliveryrun::snapshot(id)` → None → `Inconclusive` ("the linked Delivery run is no longer available; run a new Address test"); else `Matched` with one `Context` finding: title `Delivery test of <address> (run <id>)`, evidence = the run's inputs (address, ip, selector, days) and verdict counts per scope using the existing `Report::summary()` (read `crates/msfe-core/src/delivery.rs`), `event_at = report.started`, confidence `High` reason "recorded by this server's Address test", limitation "Delivery results describe mail routing and authentication, not exposure; they are shown here for context only and are not combined with OSINT findings."
- Never match a Delivery run by address alone (the id comes only from the request).
- UI: the existing "Delivery context" group in `OSINT_GROUPS` already renders `context` findings; add an **Open Address test** button on that card (calls `deliveryTestFor(r.address)`), and tick/disable the `delivery` checkbox when a `delivery_run_id` prefill exists.
- Entry points: add an "Investigate address" button to the message-detail modal and the queue-detail modal (find them: `grep -n "modal(" web/whm/index.html` for the Messages and Queues detail renderers; the paper-plane Delivery test action stays untouched), calling `osintFor(address)` for the sender and, where one recipient is shown, the recipient. Empty/bounce senders render nothing.

- [ ] **Step 1: Failing tests:** `delivery` source with no id → NotRequested; unknown id → Inconclusive and no finding; a real `deliveryrun` report inserted via the existing test helpers (look at how `deliveryrun` tests create a finished `Report`; if none exists, add a `#[cfg(test)] pub fn insert_for_test(report)` in `deliveryrun.rs`) → Matched with the counts and the run's own timestamp; a different address in the OSINT request than in the Delivery run is still shown with both addresses (no silent merge).
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (Rust, then the UI; text via `el()` only).
- [ ] **Step 4: Gates + jsdom or real-browser check of the modal buttons if tooling from earlier work exists in the scratchpad (state plainly which); commit**

```bash
git add -A crates web
git commit -m "OSINT: linked Delivery context card and Investigate entry points in message and queue details (phase 3)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Exact-address web search (`search`, Brave)

**Files:** Modify `crates/msfe-core/src/osintproviders.rs`.

**Provider facts (checked against the docs):** `GET https://api.search.brave.com/res/v1/web/search?q=<query>&count=10&safesearch=moderate`, headers `X-Subscription-Token: <key>` and `Accept: application/json`; response `{"web":{"results":[{"title","url","description","age","page_age"}]},"query":{…}}`; 401/403 auth failure, 422 invalid parameters, 429 rate limit; quoted phrases are supported.

**Behaviour:** id `search`, group `Reference`, key-gated by `osint_search_key` (empty → `NotConfigured`, no request). Disclosure: "the full address, in quotes, is sent to api.search.brave.com". Query is `"<address>"` (quotes included, address trimmed), percent-encoded by the transport. `max_body` 512 KiB. Map: 200 with ≥1 usable results → Matched (`"N result(s)"`); 200 with none → NoMatch ("no public page found by this search engine"); 401/403 → Restricted (status code in detail); 422 → Failed ("the search provider rejected the query"); 429 → RateLimited (+retry_after); others/HttpError → Failed.
Findings (≤10): group `Reference`, confidence `Low` with reason "a search snippet only: the page was not fetched, so it was not confirmed to contain this address", title = cleaned result title (≤120 chars), evidence = cleaned description (≤300 chars) with the leading text "Search snippet: ", `source_url` only when `safe_url`, `event_at` None, `limitations`: `["A search engine's coverage is incomplete.", "Snippets can be stale or mis-attributed; open the page to confirm."]`. `clean_text(s, max)` helper (defined in Task 3, reused here and in Tasks 6–7 — do not redefine): remove HTML tags (everything between `<` and `>`), decode only `&amp; &lt; &gt; &quot; &#39;`, drop control characters, collapse whitespace, truncate on a char boundary with `…`. Results whose `url` is not http(s) are dropped; duplicates by URL dropped; if the provider returns more than 10 usable results note the cap.

- [ ] **Step 1: Failing tests:** `clean_text` (tags, entities, control characters, 5 KB input, multi-byte truncation never panics); parsing a sample response (3 results, one `javascript:` URL, one duplicate, one with `<strong>` tags and `<script>`); malformed JSON / missing `web` → `Failed("unexpected answer")` vs `{"web":{"results":[]}}` → NoMatch; status table via the stand-in (path starts `/res/v1/web/search?`, query contains `q=%22a%2Bb%40example.org%22`, header `x-subscription-token` received, key absent from the detail); `not_configured` sends nothing; disclosure text.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (`SEARCH_LOCK` for tests that set `MSFE_NG_OSINT_BASE_SEARCH`; provider name for the override is `search`).
- [ ] **Step 4: Gates + commit**

```bash
git add -A crates
git commit -m "OSINT: exact-address web search through Brave Search (phase 3)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Email validation (`hunter`)

**Files:** Modify `crates/msfe-core/src/osintproviders.rs`.

**Provider facts (checked against the docs):** `GET https://api.hunter.io/v2/email-verifier?email=<address>` with header `X-API-KEY: <key>` (the key is NOT put in the query string); 200 → `{"data":{"status":"valid|invalid|accept_all|webmail|disposable|unknown","score":0-100,"regexp":bool,"gibberish":bool,"disposable":bool,"webmail":bool,"mx_records":bool,"smtp_server":bool,"smtp_check":bool,"accept_all":bool,"block":bool,"sources":[…],"verification":{"date","status"}}}`; 202 = verification in progress (retry later); 222 = remote SMTP server error; 400 malformed; 401 invalid key; 403 rate limit; 429 usage quota; 451 the person asked to stop processing; limits 10 req/s, 300/min.

**Behaviour:** id `hunter`, group `Validation`, key-gated by `osint_validation_key`. Disclosure: "the full address is sent to Hunter, which checks the mailbox itself and uses paid quota". One request, no retries. Map: 200 → Matched (detail `"Hunter status: <status>"`); 202 → Inconclusive ("Hunter is still verifying this address; try again later"); 222 → Inconclusive ("the recipient's mail server gave Hunter an error"); 400 → Failed; 401 → Restricted (status in detail); 403 → RateLimited (detail "Hunter rate limit"); 429 → RateLimited (detail "Hunter usage quota used up"); 451 → Restricted ("Hunter declined: this person asked it to stop processing their data"); others/HttpError → Failed.
Finding (one, group `Validation`): title `Hunter's verdict: <status>` (status from a fixed whitelist; unknown status strings are shown as `unknown value` and the raw token is dropped), evidence lists only the booleans/score present (`MX records: yes`, `SMTP check: yes`, `accept-all server: no`, `blocked: no`, `disposable: no`, `webmail: yes`, `looks auto-generated: no`, `score: 87`), confidence `Medium` with reason "a vendor assertion from Hunter's own checks; MSFE-NG did not probe this mailbox", severity `Info`, limitations: `["This does not prove the mailbox exists or is read by its owner.", "Servers that accept all recipients cannot be verified remotely.", "MSFE-NG's own Delivery tests remain the evidence for this server's mail routing."]`. Do not copy `sources[]` (web pages) into the report in this release; mention only the count ("Hunter lists N public page(s) for this address") when ≥1.

- [ ] **Step 1: Failing tests:** every status in the table above via the stand-in (including 202 and 222), asserting state and that the request carried `x-api-key` and the address percent-encoded in `email=`, and that the key is absent from the query string and from `detail`; response parsing: missing `data` → Failed, non-bool fields ignored, unknown `status` string; `not_configured` sends nothing; the `Validation` finding is never `High` confidence.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (`HUNTER_LOCK`; override provider name `hunter`).
- [ ] **Step 4: Gates + commit**

```bash
git add -A crates
git commit -m "OSINT: optional Hunter email validation, labelled as a vendor assertion (phase 4)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: GitHub public-email profile and OpenPGP key presence (`github`, `openpgp`)

**Files:** Modify `crates/msfe-core/src/osintproviders.rs`. Two small adapters, one task.

**GitHub (keyless):** `GET https://api.github.com/search/users?q=<address>%20in%3Aemail&per_page=3` with headers `Accept: application/vnd.github+json` and `X-GitHub-Api-Version: 2022-11-28`; unauthenticated limit 10 requests/minute; 200 → `{"total_count":N,"items":[{"login","html_url","name","bio","avatar_url",…}]}`; 403/429 rate limit (Retry-After or `x-ratelimit-reset`; the transport returns only `Retry-After`, so use it when present, else `None`); 422 validation failed. Disclosure: "the full address is sent to api.github.com; only profiles that publish this exact address are matched". Map: 200 with items → Matched; 200 with `total_count` 0 → NoMatch ("no GitHub profile publishes this address"); 403/429 → RateLimited; 422 → Failed; others/HttpError → Failed. Findings (≤3), group `Profile`: title `GitHub profile: <login>` (login whitelisted to `[A-Za-z0-9-]{1,39}`, else dropped), evidence `Public name: <clean 80>. Bio: <clean 200>.` when present, `source_url` = `https://github.com/<login>` built by us (never the API's `html_url` verbatim), confidence `Medium` with reason "GitHub matched this address against the profile's public email field; the owner chose to publish it, but that does not prove current control of the mailbox", limitations `["Private emails are not searchable this way.", "A profile is a candidate association, not a verified identity."]`. No avatar fetching (third-party images are not retrieved in this release).

**OpenPGP (keyless):** `GET https://keys.openpgp.org/vks/v1/by-email/<pct_encode(address)>` with `Accept: application/pgp-keys`, `max_body` 256 KiB. 200 → body must start with `-----BEGIN PGP PUBLIC KEY BLOCK-----` (else Failed "unexpected answer") → Matched with one `Profile` finding: title "Public OpenPGP key published", evidence `A key for this address is published on keys.openpgp.org (<N> bytes, armored). The key is not parsed or stored.`, `source_url` `https://keys.openpgp.org/search?q=<pct_encode(address)>`, confidence `Medium` with reason "keys.openpgp.org publishes an address only after its owner confirmed it by email, so this shows historical control of the mailbox", limitations `["Expiry and revocation are not checked here.", "Historical control is not current control or legal identity."]`; 404 → NoMatch; 429 → RateLimited (+retry_after); 400 → Failed; others/HttpError → Failed. Disclosure: "the full address is sent to keys.openpgp.org". The key bytes are discarded.

- [ ] **Step 1: Failing tests** (stand-ins `GITHUB_LOCK`/`PGP_LOCK`): GitHub — sample with 2 items incl. a login `bad/login` and an `html_url` pointing elsewhere (our URL is built from the login; the bad login is dropped), `<script>` in bio stripped and 5 KB bio capped, `total_count: 0`, 403 with `Retry-After: 30` → RateLimited(30), 403 without header → RateLimited(None), 422 → Failed, request path starts `/search/users?q=` with `%40` and `in%3Aemail` (`%20` between), headers sent; OpenPGP — 200 armored → Matched with size, 200 HTML → Failed, 404 → NoMatch, 429, request path `/vks/v1/by-email/a%2Bb%40example.org`, the key bytes never appear in the finding.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** both adapters and register them in `infos`/`is_known`.
- [ ] **Step 4: Real-network smoke (keyless, documentation-example address only):** scratch crate OUTSIDE the repo (`smoke3`): run `github` and `openpgp` for `nobody@example.org` (expect NoMatch for both) and paste results. Do not look up any real person's address.
- [ ] **Step 5: Gates + commit**

```bash
git add -A crates
git commit -m "OSINT: GitHub public-email profile and OpenPGP key presence (phase 6)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Documentation, UI source list and a real-browser pass

**Files:** Modify `docs/wiki/OSINT.md`, `Config.md`, `CLI.md`, `Home.md`, `web/whm/index.html` (provider list wording only if needed).

- [ ] **Step 1: Update the docs** to the real behaviour: the full source list with what each source sends (RDAP: the domain only; Brave: the address in quotes; Hunter: the full address, paid quota, vendor assertion; GitHub: the full address, public-email match only; OpenPGP: the full address; Delivery context: nothing leaves the server); keys and the card rows; candidate/confidence wording; the exclusions and why (passive DNS, Certificate Transparency, stealer logs, GitHub commit search, OpenPGP packet parsing, page crawling); rate limits to expect (GitHub 10/min unauthenticated; Hunter 10/s); that the keyless sources work without any key; honest testing statement: Brave and Hunter were exercised only against stand-in servers (no keys), RDAP/GitHub/OpenPGP were exercised with one keyless live lookup of a documentation-example address. Keep the privacy note (an investigated address is personal data) and the statement that nothing changes mail handling. No server names.
- [ ] **Step 2: Real-browser pass** (headless Firefox over Marionette as in phase 2; reuse the scratchpad tooling): the source list shows all sources with disclosures and "not configured" for the keyed ones; a fixture run still works; the Config card shows the two new key rows with "(configured…)" after a save and an empty save keeps the key; the new modal "Investigate address" buttons open the OSINT view prefilled without starting a run. State plainly what was and was not checked.
- [ ] **Step 3: Final gates** (paste in the report): `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `(cd web && npm run build) && git diff --exit-code web/whm/app.css web/user/app.css`; `node --check` of the extracted script blocks of web/whm/index.html and web/user/index.html as CI does; a `grep -rniE` over docs/wiki/OSINT.md crates/msfe-core/src/osint*.rs crates/msfe-core/src/providerhttp.rs crates/msfe-ngd/src/osint_api.rs for the user\'s production hostnames listed in the project memory prints nothing; `git grep -n "osint_search_key\|osint_validation_key" -- crates web packaging` shows the keys only where intended.
- [ ] **Step 4: Commit**

```bash
git add -A docs web
git commit -m "OSINT: phase 3, 4 and 6 documentation (sources, privacy, limits)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

Do not push, tag or release.

---

## Self-Review

**Spec coverage (§8):** phase 3 — address-test/message/queue links (T4), exact-address search (T5), RDAP (T3); phase 4 — one validation vendor with native-status mapping kept separate (T6); phase 6 — GitHub public metadata (T7), public keys (T7); passive DNS, CT, stealer-log excluded with reasons. Delivery-context card (§3) in T4. Secrets (T2) follow the phase 2 template.

**Placeholder scan:** adaptation points are explicit (`deliveryrun` test helper, modal locations, `Report::summary()` use, the override mechanism for the registry stand-in).

**Type consistency:** `Request.host: String` (T1) is used by T3–T7; `QueryCtx.delivery_run_id` (T4); `clean_text` is defined in T5 and reused in T6/T7 (T3 needs it first — define it in T3 and reuse; if T5 finds it missing, it must not redefine it).
