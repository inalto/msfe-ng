# Delivery → OSINT — design

Date: 2026-10-02. Base revision: `main` at workspace version 1.0.80.
Status: draft for review. Umbrella spec for phases 1–6; each phase gets its own implementation plan.

## 1. Goal and non-goals

Add a fourth **Delivery** view, **OSINT**, for investigating an email address's public footprint: breach exposure (HIBP), public avatar (Gravatar), and later exact-address public references, RDAP, optional validation and advanced sources. It is built natively in the existing Rust daemon, CLI and vanilla-JS WHM UI.

Constraints:

- Admin (root peer) surface only. Nothing under `/api/user/`.
- Standard-library-only Rust (1.74 minimum); no new runtime, framework or database engine.
- A separate `OsintReport`; the existing `delivery::Report`, its JSON, monitors and CLI exits are unchanged.
- Operator-driven only: no automatic lookups when loading Messages or scanning mail, and no OSINT call in MailScanner hooks or Exim routing.
- OSINT never changes spam scores, allow/block lists, csf, quarantine or delivery. A breach is a security observation, not a delivery failure.
- No SMTP RCPT enumeration, no account-existence probing, no credential testing, no test mail from OSINT.
- No server names in commits, docs or code comments (public repo).

Success: a synthetic end-to-end run works with Delivery untouched (phase 1); real HIBP and Gravatar work with absent keys, 429s and partial coverage shown honestly (phase 2); CI needs no live keys.

## 2. Verified baseline and differences from the source spec

- `httpclient::get()` is MTA-STS-only: no custom headers, no `Retry-After`, no binary body (`CmdOutput.stdout` is a lossy `String`). Not extended; a new `providerhttp.rs` is added.
- `report.rs` (AbuseIPDB) keeps its key in a private curl config, not argv, but has none of the SSRF controls. It is the secret-handling precedent only.
- No Rust SHA exists. `sha256sum` and `sha1sum` are used through `service::run_with_stdin`.
- Routing: `/api/delivery/*` is one prefix arm in `api.rs`; OSINT gets its own arm before it.
- The daemon write lock serialises only non-GET requests, with one thread per connection (the "one at a time" comment in `service.rs` is stale).
- CLI exit codes today: 1 failed check, 2 usage, 3 input/runtime. `rejected_flag` rejects unlisted flags.
- A new secret touches about nine places (see section 6).
- Next migration number is `0006`.

## 3. Models and run controller

Modules in `msfe-core`: `osint.rs` (types, JSON, no I/O), `osintrun.rs` (registry, scheduling, cache, cancel, persistence), `osintproviders.rs` (one adapter per source behind a small trait), `osinthtml.rs` (escaped export), `providerhttp.rs`.

`OsintReport`: `schema_version` 1, `kind` "osint", `run_id`, `address`, `started`, `finished`, `state` (running, complete, partial, cancelled, failed), `cached`, `planned`, `sources`, `findings`, `delivery_run_id`, `limitations`.

`SourceStatus`: `source_state` of matched, no_match, inconclusive, restricted, not_configured, not_requested, rate_limited, failed; plus `retry_after` and a vendor code kept as diagnostic metadata.

`Finding`: `group` (exposure, profile, reference, domain, validation, context), `confidence` with reason, `severity` (independent of mail filtering), `observed_at`, `event_at`, `source_id`, `source_url`, `title`, `evidence`, `limitations`.

Rules: unknown enum strings parse to an `Unknown(String)` variant, never to success; unknown JSON fields are ignored. Provider normalization is per provider and separate from transport identity. A cancelled run is stored as `cancelled`; `complete` is reachable only when every planned source reached a terminal state.

Controller: an independent in-memory registry plus a start-time window (the `deliveryrun` shape), 16-hex run IDs. `start()` validates the address with the existing parser, clamps source names to a fixed list, resolves `delivery_run_id` itself, checks cache, rate and concurrency, registers the run and spawns a thread. No network I/O happens under the write lock.

Default limits, configurable within bounds: 2 concurrent runs per server, 3 runs per minute, 30 s run deadline, 10 s per request, 5 external queries per run, 2 provider calls in flight per run. Status codes: 201 started, 200 cached, 400 invalid, 409 same address already running, 429 over a limit.

Cache key (digested, never an auth token): exact address, per-provider normalization and version, requested sources, provider config revision, schema version. The Delivery cache's lowercase equivalence is not inherited. A `delivery_run_id` link keeps the Delivery run's inputs and timestamp and is never matched by address alone.

## 4. Provider transport, secrets and avatars

`providerhttp.rs`: fixed provider ids and hostnames compiled in; no URL or host from UI or API. Each destination is resolved, every IP passes `outbound_allowed(ip, false)` (never the local-audit exception), and the first passing IP is pinned with `--resolve`. Curl flags: `--proto =https`, `--max-redirs 0`, `--http1.1`, `--max-time`, `-q`, no proxy unless configured, `-D -` for status and selected headers (`Retry-After`, `Content-Type`). Response size is capped while reading through a bounded reader, killing the process group on overflow, so chunked responses without Content-Length are covered. Processes are built with `Command` and run under `run_with_timeout`; no shell. Per-provider env overrides point tests at a loopback stand-in.

Secrets: the credential header is passed as curl config on stdin (`--config -`), so no file exists. This must be verified on the EL8 curl (7.61); if it fails there, fall back to a `0600` file in the root-only OSINT dir with a Drop guard, as `report.rs` does. Stderr is captured bounded and scrubbed of keys and of full-address path or query before it reaches errors or logs.

Hashing: SHA-256 (Gravatar) and SHA-1 (HIBP range prefix) via `sha256sum`/`sha1sum` with input on stdin. A missing binary makes that source `failed` with an honest reason.

HIBP: direct mode sends the full address (disclosed in the UI); range mode sends a 6-character SHA-1 prefix and matches locally, dropping non-matching rows immediately and never persisting them. 404 is no_match, 401/403 is restricted, 429 is rate_limited with `Retry-After` kept. Categories are labelled incident-wide.

Gravatar: metadata via `d=404&s=256&r=g`; a 404 is reported as "no avatar at this rating". The profile API is used only when its key is set.

Avatars: the daemon fetches only from approved image hosts, 256 KiB cap, PNG/JPEG/WebP magic-byte check, no SVG or HTML, dimensions read from the header and rejected above 256 px. Bytes are stored under an opaque asset ID with no decode or re-encode in the root daemon. `GET asset` returns JSON with base64; the UI makes a Blob URL and revokes it on navigation. The browser never contacts Gravatar.

## 5. API, CLI and UI

Routes (root only, via the existing proxy and Unix socket), handled in `msfe-ngd/src/osint_api.rs`, dispatched by a new prefix arm before `/api/delivery/`:

- `GET /api/delivery/osint/providers`: sources, configured state, what each receives (full address, domain, hash prefix), limits.
- `POST .../run`, `GET .../run?id=`, `POST .../run/cancel`.
- `GET .../report?id=&format=json|html`, `GET .../recent`, `POST .../remove`, `GET .../asset?id=`.

The body accepts only `address`, `providers`, `force`, `context.delivery_run_id`, `external_query_limit`; the server clamps and validates. No path, URL, key or command is accepted. With `osint_enabled=false`, `run` returns 403 and `providers` still answers.

CLI: `delivery osint <address> [--providers a,b] [--json|--html] [--force]`, `delivery osint providers [--json]`, `delivery osint sweep`, added to `cmd_delivery`, `rejected_flag` and `usage_of("delivery")`. Exit codes: 0 complete, 2 usage, 3 invalid input or runtime failure, 4 partial. A breach finding never changes the exit code.

UI (`web/whm/index.html`): `['osint','OSINT']` in `DLV_VIEWS`; `renderOsint` in the dispatch map; `dlvOsintTimer` cleared in both timer-clear lists; `osintFor(address, context)` and `OSINT_PREFILL` following `deliveryTestFor`, prefill only. A distinct "Investigate address" action (not the paper plane) goes in Message details, sender/recipient menus, queue details and Address-test results. The input card lists sources grouped by exposure, avatar/profile, public web, domain, validation, each with its disclosure, plus an optional Delivery run link and a Fresh lookup switch. Result cards: summary, Exposure, Public identity and avatar, Public references, Domain context, Delivery context (with an **Open Address test** action, its counts never mixed in), Source coverage. Empty, failed, restricted and unconfigured sources stay visible; "no match" is never worded as safe; old breaches are labelled historical; guessed identities are candidates. Evidence renders as text through the existing safe DOM helpers; URLs are restricted to http(s). Any new CSS classes require `npm run build` and the generated `app.css` committed.

Docs: new `docs/wiki/OSINT.md`, linked from Delivery, Home and the sidebar.

## 6. Configuration

New settings: `osint_enabled` (false), `osint_runs_per_min` (3), `osint_max_concurrent` (2), `osint_deadline_secs` (30), `osint_max_external_queries` (5), `osint_cache_secs` (3600), `osint_retention_hours` (24), `osint_hibp_key`, `osint_hibp_mode` (direct|range), `osint_gravatar_key`, `osint_search_provider`, `osint_search_key`, `osint_validation_provider`, `osint_validation_key`. The config parser is a flat TOML subset, so each is an individual key.

Per secret, register in: config struct, `Default`, parser arm, `to_public_json` flag (`osint_*_set`, following `db_pass_set`), the Config-tab card, the SPA's blank-keeps list (replaced by a data attribute so new keys do not extend a hardcoded list), a separate Clear action, the `install.sh` seed, consumer empty checks, tests, and docs. `conffile` does not escape backslashes, so secret values are validated to printable characters without `\` or `"` before saving. Config-tab file views and snapshots show raw config today (admin only; snapshot tarball `0600`); this is documented and a test keeps the keys out of `to_public_json`, reports and exports.

## 7. Storage and monitoring

Phases 1–2: `/var/cache/msfe-ng/osint` at `0700` (override `MSFE_NG_OSINT_DIR`), atomic `0600` writes, opaque IDs validated against `[0-9a-f]{16}`, symlinks rejected, no path built from the address. Only normalized findings, outcomes and minimal evidence are kept; no raw provider payloads. Sweep at daemon start and by `delivery osint sweep` after `osint_retention_hours`. `remove` deletes the run and assets and leaves a registry tombstone so a late worker cannot recreate it. Works without a database.

Phase 5 (opt-in MySQL): migration `0006_osint.sql` (number rechecked at coding time) with `osint_monitors`, `osint_runs`, `osint_usage` (provider, period, reserved and final units, run id; no credentials). A new `osintmon.rs` is called from the existing `*/5` monitor step beside `deliverymon::run_due`, no-ops without a DB, minimum interval 1440 minutes, reserves provider budget before each run, and compares stable incident/source IDs. Alerts are separate kinds (new exposure, changed public reference, provider unavailable), deduplicated through `db::kv_set`, sent only to already-configured destinations, and never mixed into Delivery-health alerts.

## 8. Phases

1. Models and controller; routes, UI pill, poll/cancel, JSON/HTML export on a fixture adapter.
2. `providerhttp` and secrets; HIBP; Gravatar with avatars.
3. Context links; exact-address search (one provider, snippets and URLs only); RDAP.
4. One validation vendor, mapped to native statuses, in its own group, with no SMTP probing. The vendor is chosen when the phase starts.
5. Migration, history, `osintmon`.
6. Advanced sources, one per PR: GitHub public email/commit metadata, OpenPGP, passive DNS and certificate transparency, stealer-log metadata where the plan permits. JSON only; any HTML, PDF or image conversion needs a restricted subprocess in a later spec.

Deferred: the password checker, account enumeration, general crawling, an end-user surface. Separate follow-ups, not part of this work: DMARC compatibility with RFC 9989, and what `.eml` DKIM checks do and do not prove.

## 9. Testing and release gates

Fixtures only, no live keys. `providerhttp` talks to a loopback stand-in through env overrides, with a test-only loopback allowance; a test asserts the production path uses `outbound_allowed(ip, false)`.

- Models: round trips, unknown states and fields.
- Providers: match, no match, 401/403, 404, 429 with `Retry-After`, 500, malformed JSON, timeout, oversize, partial coverage.
- HIBP: incident-wide categories, range rows dropped, no password inference.
- Gravatar: rating-qualified 404, bad magic bytes, oversize or over-dimension image, asset cleanup.
- Transport: private, loopback and own-server targets blocked, pin used, no redirect follow, key absent from argv, stderr redaction, size cap on chunked response.
- Auth: non-root denied, forged user header ignored.
- Runs: nothing slow under the write lock, cancel, ceilings, cache scope, cancelled never complete.
- Storage: modes, symlink and traversal rejection, expiry, remove-versus-late-worker race.
- Config: secrets absent from public JSON, reports, exports; blank-keeps; clear; bad characters rejected.
- CLI: flags accepted, exit codes 0/2/3/4, breach match exits 0.
- UI: `node --check` plus a manual browser pass (four pills, no stale poller, partial results, Blob revoked).
- Regression: Delivery JSON, CLI exits, monitors, Account DNS, DMARC unchanged.

Every PR passes the existing CI: `cargo fmt --check`, Clippy `-D warnings`, `cargo test --workspace` on 1.74-compatible code, `npm run build` with a clean generated-CSS diff, the JS syntax check, and the shell/Perl checks when packaging changes. Release gates: opening a message or the OSINT view runs no lookups; missing provider access never reads as clean; a breach never alters filtering; keys never appear in process listings, public config, reports or logs; Delivery stays responsive during slow providers; an OSINT run sends no mail. Nothing is released until the user says "go".

## 10. Open items

- Phase 3 search provider and phase 4 validation vendor: chosen when those phases start.
- `curl --config -` on EL8 curl 7.61 must be verified in phase 2; the file fallback is specified above.
- Source terms, retention and personal-data processing (including GDPR) should be reviewed for the deployment before enabling any provider.
