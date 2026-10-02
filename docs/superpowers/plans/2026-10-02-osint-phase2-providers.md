# Delivery → OSINT, Phase 2 (hardening, provider transport, HIBP, Gravatar) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the OSINT view useful: close the phase 1 hardening debt, add a guarded provider HTTP transport, a Have I Been Pwned breach adapter (direct and range modes), and a Gravatar avatar adapter with controlled avatar delivery.

**Architecture:** `providerhttp.rs` is the only outbound path for OSINT: fixed origins, every IP checked with `outbound_allowed(ip, false)` and pinned, no redirects, secrets passed to curl on stdin, response read through a bounded reader. `osintproviders.rs` holds the adapters (moved out of `osintrun.rs`). Avatars are stored as opaque-id files and delivered to the browser as base64 JSON; no image is decoded in the daemon.

**Tech Stack:** Rust 1.74 std only, system `curl`, `sha1sum`/`sha256sum`, vanilla JS.

**Spec:** `docs/superpowers/specs/2026-10-02-delivery-osint-design.md` (sections 4, 6, 7, 9; phase 2 of section 8). Phase 1 plan: `docs/superpowers/plans/2026-10-02-osint-phase1-skeleton.md`.

**Branch policy:** the user asked for phases to be committed directly on `main`. Commit each task to `main`; do not push, tag or release unless the user asks.

## Global Constraints

- Rust 1.74 minimum, edition 2021, std only, no external crates; `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` pass; tests never touch the network or need real keys.
- OSINT network access: `netguard::outbound_allowed(ip, false)` for every destination (never the local-audit exception); pin the resolved IP; HTTPS only; no redirects; credentials only to the provider's fixed origin.
- API keys never appear in process argv, `to_public_json`, reports, exports, logs, errors or stderr captures; public JSON exposes only `osint_hibp_set`.
- Provider hosts are compiled in: `haveibeenpwned.com` and `gravatar.com`; no URL, host, header or key is accepted from the UI or API request.
- Response bodies are capped while reading (also for chunked responses without Content-Length); images ≤ 256 KiB; PNG/JPEG/WebP magic bytes only; no SVG/HTML; nothing is decoded or re-encoded in the daemon.
- No hand-written hashing: SHA-1 and SHA-256 come from `sha1sum`/`sha256sum` via stdin.
- "No match" is never worded as "safe"; old breaches are labelled historical; HIBP data classes are labelled incident-wide; missing key reports `not_configured`, never a clean result.
- HIBP range mode: only the 6-character SHA-1 prefix is sent; non-matching rows are discarded immediately and never stored.
- A breach finding never changes mail filtering or the CLI exit code.
- Defaults unchanged from phase 1 except new settings: `osint_hibp_key = ""`, `osint_hibp_mode = "direct"`.
- No server names (ncc, gauss, erdos, …) in commits, docs, code or comments (public repo).
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- If a Tailwind class is added, run `npm run build` in `web/` and commit `web/whm/app.css` and `web/user/app.css`.

## Review Focus

- Header injection: a secret value or address containing CR/LF/control characters must be refused, never turned into an extra header or config line. Pinned in Task 3.
- Chunked or oversized provider response without Content-Length must be cut at the cap, not buffered. Pinned in Task 3.
- 429 with `Retry-After` (seconds, also garbage and HTTP-date forms) must give `rate_limited`, never crash or retry-storm. Pinned in Tasks 3 and 5.
- HIBP returns `[]`, `null`, an object instead of an array, or HTML: `failed`/`no_match` as appropriate, never a panic. Pinned in Task 5.
- Address with `+`, `%`, `/`, `?`, `#`, unicode-looking ASCII subset characters in the local part must be percent-encoded in the path. Pinned in Tasks 3 and 5.
- A Gravatar 200 that is not an image (HTML, SVG, GIF, truncated PNG) or is over 256 KiB must not be stored or shown. Pinned in Task 6.
- Removing or sweeping a run must delete its avatar files; a removed-while-running run must not reappear or leak an asset. Pinned in Tasks 1 and 6.
- Key saved with a backslash/quote/newline: refused at save time, not written to `config.toml`. Pinned in Task 4.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/msfe-core/src/osintrun.rs` (modify) | Hardening (Task 1); adapters call-out, assets cleanup (Tasks 5–6) |
| `crates/msfe-core/src/osint.rs` (modify) | `Unknown` group/severity, schema check (Task 2); asset fields on `Finding` (Task 6) |
| `crates/msfe-core/src/providerhttp.rs` (create) | Guarded fetch, curl config, bounded read, hashing helpers (Task 3) |
| `crates/msfe-core/src/osintproviders.rs` (create) | `QueryCtx`, `Outcome`, fixture, HIBP (Task 5), Gravatar (Task 6) |
| `crates/msfe-core/src/config.rs` (modify) | `osint_hibp_key`, `osint_hibp_mode`, `osint_hibp_set` (Task 4) |
| `crates/msfe-ngd/src/osint_api.rs`, `api.rs` (modify) | `external_query_limit`, route tests, asset route, key validation on save (Tasks 1, 2, 4, 6) |
| `web/whm/index.html` (modify) | Config card, keep-existing attribute, providers list, avatar, "Other" group (Tasks 2, 4, 5, 6) |
| `packaging/install.sh` (modify) | Seed the two new keys (Task 4) |
| `docs/wiki/OSINT.md`, `Config.md`, `CLI.md` (modify) | Operator docs (Task 7) |

---

### Task 1: Controller and storage hardening

**Files:**
- Modify: `crates/msfe-core/src/osintrun.rs`, `crates/msfe-ngd/src/osint_api.rs`

**Interfaces:**
- Consumes: phase 1 `osintrun` (see the file for the current `Slot`, `persist`, `load`, `sweep`, `remove`, `start`, `Inputs`).
- Produces:
  - `Inputs` gains `pub max_queries: Option<u32>`; `parse_inputs(address, providers, force, delivery_run_id)` keeps its signature and sets `None`; add `pub fn with_query_limit(mut self, n: Option<u32>) -> Inputs` on `Inputs`.
  - `start()` uses `min(inputs.max_queries.unwrap_or(cfg.osint_max_external_queries), cfg.osint_max_external_queries).max(1)` as the worker's query budget.
  - `ensure_dir() -> std::io::Result<PathBuf>` (private): creates the report dir `0700` if missing; if it exists it must be a real directory (not a symlink) owned by the current uid (compare `MetadataExt::uid()` with the uid of `/proc/self`'s metadata) and group/other bits are cleared with `set_permissions(0o700)`.
  - `persist()` writes with `create_new(true)` after removing a stale `<id>.tmp` (ignore NotFound) and never follows a symlink.
  - `sweep(max_age_secs)` also removes `<16hex>.tmp` files older than 1 h.
  - `remove()` of a Running run: marks the `Slot` `removed = true`, sets cancel, keeps the slot (so the concurrency count stays honest) until the worker finishes; `snapshot`, `recent`, cache lookup and Busy ignore removed slots for display, but the concurrency count includes them; the worker deletes a removed slot at its end and never persists.
- API: `POST /api/delivery/osint/run` reads `external_query_limit` (integer ≥ 1) and passes it with `with_query_limit`.

- [ ] **Step 1: Write failing tests** (add to the `osintrun` tests module; they use the existing `setup()`/`TEST_LOCK` helpers and distinct addresses):

```rust
    #[test]
    fn persist_refuses_to_follow_a_symlinked_tmp() {
        use std::os::unix::fs::symlink;
        let (_c, _g) = setup();
        let d = report_dir();
        std::fs::create_dir_all(&d).unwrap();
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "keep").unwrap();
        let id = "00000000000000aa";
        let _ = std::fs::remove_file(d.join(format!("{id}.tmp")));
        symlink(&victim, d.join(format!("{id}.tmp"))).unwrap();
        let r = OsintReport {
            run_id: id.into(), address: "a@example.org".into(), started: 1, finished: Some(2),
            state: RunState::Complete, cached: false, planned: vec![], sources: vec![],
            findings: vec![], delivery_run_id: None, limitations: vec![],
        };
        persist(&r).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep", "the symlink target must be untouched");
        assert!(d.join(format!("{id}.json")).is_file());
        let _ = std::fs::remove_file(d.join(format!("{id}.json")));
        let _ = std::fs::remove_file(victim);
    }

    #[test]
    fn existing_loose_directory_is_tightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let (_c, _g) = setup();
        let d = report_dir();
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_dir().unwrap();
        assert_eq!(std::fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn sweep_removes_old_orphan_tmp_files_but_not_strangers() {
        let (_c, _g) = setup();
        let d = report_dir();
        std::fs::create_dir_all(&d).unwrap();
        let orphan = d.join("00000000000000bb.tmp");
        std::fs::write(&orphan, "x").unwrap();
        let stranger = d.join("notes.tmp");
        std::fs::write(&stranger, "x").unwrap();
        sweep_with_tmp_age(0, 0);
        assert!(!orphan.exists());
        assert!(stranger.exists());
        let _ = std::fs::remove_file(stranger);
    }

    #[test]
    fn removing_a_running_run_keeps_its_concurrency_slot_until_the_worker_ends() {
        let (mut c, _g) = setup();
        c.osint_max_concurrent = 1;
        let StartOk::Started(id) = start(&c, inp("slow.rmslot@example.org", true)).unwrap() else { panic!() };
        assert!(remove(&id));
        assert!(snapshot(&id).is_none(), "removed run is invisible");
        // The worker has not noticed the cancel yet or has only just; either
        // way a new start must never exceed the ceiling of 1.
        let second = start(&c, inp("quiet.rmslot2@example.org", true));
        match second {
            Ok(StartOk::Started(id2)) => { wait_done(&id2); }
            Err(StartError::TooManyRuns) => {}
            other => panic!("unexpected {other:?}"),
        }
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && running_count() > 0 { std::thread::sleep(Duration::from_millis(20)); }
        assert_eq!(running_count(), 0, "the removed slot is released when the worker ends");
        assert!(!report_dir().join(format!("{id}.json")).exists(), "a removed run is never persisted");
    }

    #[test]
    fn query_limit_is_clamped_to_the_configured_ceiling() {
        let (mut c, _g) = setup();
        c.osint_max_external_queries = 1;
        let p = vec!["fixture".to_string(), "fixture".to_string()];
        // two distinct sources would be needed to exceed 1; assert the budget math directly
        assert_eq!(query_budget(&c, &inp("quiet.q@example.org", true).with_query_limit(Some(99))), 1);
        assert_eq!(query_budget(&c, &inp("quiet.q@example.org", true).with_query_limit(None)), 1);
        c.osint_max_external_queries = 5;
        assert_eq!(query_budget(&c, &inp("quiet.q@example.org", true).with_query_limit(Some(2))), 2);
        assert_eq!(query_budget(&c, &inp("quiet.q@example.org", true).with_query_limit(Some(0))), 1);
        let _ = p;
    }
```

Add the helpers the tests use, in non-test code: `fn running_count() -> usize` (count of Slots with state Running, including removed ones) marked `#[cfg(test)]`, `pub(crate) fn query_budget(cfg: &Config, i: &Inputs) -> usize`, and `pub(crate) fn sweep_with_tmp_age(max_age_secs: u64, tmp_age_secs: u64)` (with `sweep(max)` calling it with `3600` for the tmp age).

- [ ] **Step 2: Run to verify failure**

Run: `PATH=$HOME/.cargo/bin:$PATH cargo test -p msfe-core osintrun:: 2>&1 | tail -15`
Expected: compile errors (missing helpers), then failures.

- [ ] **Step 3: Implement.**

`ensure_dir`:

```rust
fn ensure_dir() -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let dir = report_dir();
    match std::fs::symlink_metadata(&dir) {
        Ok(md) => {
            if !md.is_dir() {
                return Err(std::io::Error::other("report dir is not a directory"));
            }
            let me = std::fs::metadata("/proc/self")?.uid();
            if md.uid() != me {
                return Err(std::io::Error::other("report dir has the wrong owner"));
            }
            if md.permissions().mode() & 0o077 != 0 {
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        }
        Err(e) => return Err(e),
    }
    Ok(dir)
}
```

In `persist`: replace the `DirBuilder` block with `let dir = ensure_dir()?;`, and write the temp file as:

```rust
    let _ = std::fs::remove_file(&tmp); // a stale or hostile entry; never write through it
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
```

`sweep_with_tmp_age`: extend the current sweep loop: for names ending `.tmp` whose stem passes `valid_id`, delete when older than `tmp_age_secs`; `.json` handling unchanged; everything else untouched.

`query_budget`:

```rust
pub(crate) fn query_budget(cfg: &Config, i: &Inputs) -> usize {
    let ceiling = cfg.osint_max_external_queries.max(1);
    i.max_queries.unwrap_or(ceiling).clamp(1, ceiling) as usize
}
```

and `start()` uses it in place of the existing `max_q` computation.

`remove()` for a Running slot: add `removed: bool` to `Slot`. In `remove`, inside the `with_runs` closure: if the slot is Running, set `removed = true` and the cancel flag and keep it; otherwise remove it as today. Make `snapshot`, `recent`, the cache-hit lookup and the Busy check skip `removed` slots, but keep them in the concurrency count. In `worker`'s final `with_runs`: if the slot is `removed`, delete it and return None (no persist). `remove()` still tombstones the id and deletes any file.

API: in `osint_api.rs::start` read `v.get("external_query_limit").and_then(Json::as_i64)`; pass `Some(n as u32)` when `n >= 1` (ignore otherwise) via `inputs.with_query_limit(...)`.

- [ ] **Step 4: Add route tests** in `osint_api.rs` tests (reuse its helpers; distinct addresses):

```rust
    #[test]
    fn busy_cached_and_rate_limited_map_to_409_200_429() {
        let c = Config { osint_runs_per_min: 1000, osint_max_concurrent: 8, ..setup() };
        let slow = r#"{"address":"slow.route@example.org","providers":["fixture"],"force":true}"#;
        let a = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", slow), &c);
        assert_eq!(a.status, 201);
        let id = Json::parse(a.body_str()).unwrap().str_field("run_id");
        let b = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", slow), &c);
        assert_eq!(b.status, 409);
        assert_eq!(Json::parse(b.body_str()).unwrap().str_field("run_id"), id);
        let _ = handle("POST", "/api/delivery/osint/run/cancel", &crate::http::Request::test("POST", "/api/delivery/osint/run/cancel", &format!(r#"{{"id":"{id}"}}"#)), &c);

        let quiet = r#"{"address":"quiet.route@example.org","providers":["fixture"],"force":true}"#;
        let q = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", quiet), &c);
        let qid = Json::parse(q.body_str()).unwrap().str_field("run_id");
        for _ in 0..200 {
            let p = handle("GET", "/api/delivery/osint/run", &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={qid}"), ""), &c);
            if Json::parse(p.body_str()).unwrap().str_field("state") == "complete" { break; }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let cached = r#"{"address":"quiet.route@example.org","providers":["fixture"]}"#;
        let r = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", cached), &c);
        assert_eq!(r.status, 200);
        assert!(r.body_str().contains("\"cached\":true"));

        let tight = Config { osint_runs_per_min: 1, ..c.clone() };
        let one = r#"{"address":"quiet.route2@example.org","providers":["fixture"],"force":true}"#;
        let two = r#"{"address":"quiet.route3@example.org","providers":["fixture"],"force":true}"#;
        let _ = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", one), &tight);
        let t = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", two), &tight);
        assert_eq!(t.status, 429);
    }

    #[test]
    fn non_hex_ids_are_404_on_report_cancel_and_remove() {
        let c = setup();
        for (m, p, b) in [
            ("GET", "/api/delivery/osint/report?id=..%2Fx", ""),
            ("POST", "/api/delivery/osint/run/cancel", r#"{"id":"../x"}"#),
            ("POST", "/api/delivery/osint/remove", r#"{"id":"../x"}"#),
        ] {
            let r = handle(m, p.split('?').next().unwrap(), &crate::http::Request::test(m, p, b), &c);
            assert_eq!(r.status, 404, "{p}");
        }
    }

    #[test]
    fn client_supplied_urls_paths_and_keys_are_ignored() {
        let c = setup();
        let body = r#"{"address":"quiet.ign@example.org","providers":["fixture"],"force":true,"url":"https://evil.example/x","path":"/etc/passwd","key":"k","ip":"127.0.0.1"}"#;
        let r = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", body), &c);
        assert!(r.status == 201 || r.status == 200 || r.status == 429);
        assert!(!r.body_str().contains("evil"));
    }
```

(If `Config` is not `Clone`, build the second config with `Config { osint_runs_per_min: 1, ..setup() }`.)

- [ ] **Step 5: Run tests, gates, commit**

Run: `PATH=$HOME/.cargo/bin:$PATH cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test -p msfe-core osintrun:: && cargo test -p msfe-ngd`
Expected: all pass (run the `osintrun::` tests three times).

```bash
git add -A crates
git commit -m "OSINT: harden report storage and removal, honour external_query_limit, route tests (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Unknown group/severity, schema check, "Other" findings in the UI

**Files:**
- Modify: `crates/msfe-core/src/osint.rs`, `web/whm/index.html`, `crates/msfe-core/src/osinthtml.rs` (only if it matches on `Group`/`Severity` by value), `crates/msfe-cli/src/main.rs` (only if it matches on them)

**Interfaces:**
- Produces: `Group` and `Severity` become `#[derive(Debug, Clone, PartialEq, Eq)]` enums with a trailing `Unknown(String)` variant; `as_str(&self) -> &str`; `parse(&str) -> Group` / `Severity` (infallible; unknown strings become `Unknown(s)`). `OsintReport::from_json` returns `Err` when `schema_version` is present and greater than `SCHEMA_VERSION`. Findings with an unknown group are kept.

- [ ] **Step 1: Failing tests** (in `osint.rs` tests):

```rust
    #[test]
    fn unknown_group_and_severity_survive_a_round_trip() {
        let j = Json::parse(
            r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete","findings":[{"group":"brand_new","severity":"catastrophic","confidence":"high","title":"t","evidence":"e","source_id":"s","observed_at":5}]}"#,
        ).unwrap();
        let r = OsintReport::from_json(&j).unwrap();
        assert_eq!(r.findings.len(), 1, "an unknown group must not drop the finding");
        assert_eq!(r.findings[0].group, Group::Unknown("brand_new".into()));
        assert_eq!(r.findings[0].severity, Severity::Unknown("catastrophic".into()));
        let again = OsintReport::from_json(&Json::parse(&r.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(again.findings[0].group.as_str(), "brand_new");
        assert_eq!(again.findings[0].severity.as_str(), "catastrophic");
    }

    #[test]
    fn a_newer_schema_version_is_refused() {
        let j = Json::parse(r#"{"schema_version":2,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete"}"#).unwrap();
        assert!(OsintReport::from_json(&j).is_err());
        let ok = Json::parse(r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete"}"#).unwrap();
        assert!(OsintReport::from_json(&ok).is_ok());
    }
```

- [ ] **Step 2: Run:** `cargo test -p msfe-core osint:: 2>&1 | tail` → compile errors (variants missing).

- [ ] **Step 3: Implement.** Replace the two `simple_enum!` invocations for `Group` and `Severity` with explicit enums:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group { Exposure, Profile, Reference, Domain, Validation, Context, Unknown(String) }
impl Group {
    pub fn as_str(&self) -> &str {
        match self {
            Group::Exposure => "exposure", Group::Profile => "profile", Group::Reference => "reference",
            Group::Domain => "domain", Group::Validation => "validation", Group::Context => "context",
            Group::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> Group {
        match s {
            "exposure" => Group::Exposure, "profile" => Group::Profile, "reference" => Group::Reference,
            "domain" => Group::Domain, "validation" => Group::Validation, "context" => Group::Context,
            other => Group::Unknown(other.to_string()),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity { Info, Low, Medium, High, Unknown(String) }
impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Info => "info", Severity::Low => "low", Severity::Medium => "medium",
            Severity::High => "high", Severity::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "info" => Severity::Info, "low" => Severity::Low, "medium" => Severity::Medium,
            "high" => Severity::High, other => Severity::Unknown(other.to_string()),
        }
    }
}
```

In `Finding::from_json`: `group: Group::parse(&j.str_field("group"))` (no `?`), `severity: Severity::parse(&j.str_field("severity"))`; return `Some(..)` unchanged. In `OsintReport::from_json`, after the `kind` check:

```rust
        if let Some(v) = j.get("schema_version").and_then(Json::as_i64) {
            if v > SCHEMA_VERSION {
                return Err(format!("report written by a newer version (schema {v})"));
            }
        }
```

Fix every compile error this causes (`Copy` is gone: clone where a `Group`/`Severity` value is reused; callers use `.as_str()` unchanged). In `web/whm/index.html` `renderOsint`/`paint`, after the `OSINT_GROUPS.forEach` loop add a section for findings whose `group` is not in `OSINT_GROUPS`:

```js
    const known=OSINT_GROUPS.map(g=>g[0]);
    const other=(r.findings||[]).filter(f=>!known.includes(f.group));
    if(other.length){
      const c=el('div',{class:'card'},el('h2',{},'Other findings'));
      other.forEach(f=>{const row=el('div',{style:'margin:.5rem 0'});row.append(el('div',{},el('b',{},f.title)));row.append(el('div',{},f.evidence));row.append(el('div',{class:'muted',style:'font-size:.78rem'},'source '+f.source_id+' · '+f.group));c.append(row);});
      out.append(c);
    }
```

- [ ] **Step 4: Run tests and gates:** `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `node --check` of the extracted script exactly as CI does (`.github/workflows/ci.yml` `web` job; temp files only under the scratchpad directory).

- [ ] **Step 5: Commit**

```bash
git add -A crates web
git commit -m "OSINT: keep unknown groups and severities, refuse newer report schemas (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Guarded provider transport (`providerhttp.rs`)

**Files:**
- Create: `crates/msfe-core/src/providerhttp.rs`
- Modify: `crates/msfe-core/src/lib.rs` (`pub mod providerhttp;`)

**Interfaces:**
- Consumes: `netguard::outbound_allowed(IpAddr, bool) -> Result<(), String>`, `service::CmdOutput` conventions (read `crates/msfe-core/src/service.rs` `run_with_input` for how the process group is killed: `kill -9 -- -<pid>` plus `child.kill()`).
- Produces:
  - `pub struct Request { pub provider: &'static str, pub host: &'static str, pub path: String, pub query: Vec<(&'static str, String)>, pub headers: Vec<(&'static str, String)>, pub timeout: Duration, pub max_body: usize }` (`path` begins with `/` and is already percent-encoded; use `pct_encode` for dynamic segments).
  - `pub struct Response { pub status: u16, pub retry_after: Option<u64>, pub content_type: Option<String>, pub body: Vec<u8> }`.
  - `pub enum HttpError { Blocked(String), Resolve(String), Timeout, TooLarge, Tls(String), Refused(String), Other(String) }` with `Display`.
  - `pub fn fetch(req: &Request) -> Result<Response, HttpError>`.
  - `pub fn pct_encode(s: &str) -> String` (RFC 3986 unreserved characters kept, everything else `%XX` uppercase, per byte).
  - `pub fn sha256_hex(data: &[u8]) -> Result<String, String>` and `pub fn sha1_hex_upper(data: &[u8]) -> Result<String, String>` (via `service::run_with_stdin` on `sha256sum`/`sha1sum`, first whitespace token of stdout, validated as 64/40 hex characters).
  - Pure helpers (unit-tested): `config_doc(url: &str, headers: &[(&'static str, String)]) -> Result<String, HttpError>`, `curl_args(timeout_secs: u64, max_body: usize, pin: Option<&str>, allow_http: bool) -> Vec<String>`, `parse_head(raw: &[u8]) -> Result<(u16, Vec<(String, String)>, usize), String>`, `redact(text: &str, secrets: &[&str]) -> String`, `parse_retry_after(&str) -> Option<u64>`.
  - Test override: env `MSFE_NG_OSINT_BASE_HIBP` / `MSFE_NG_OSINT_BASE_GRAVATAR` (name is `MSFE_NG_OSINT_BASE_` + uppercased `provider`). When set it must be exactly `http://127.0.0.1:<port>` (validated; anything else is ignored with the real origin used). With an override, DNS resolution, the public-address check and pinning are skipped and `--proto =http` is allowed; in all other cases `--proto =https`.

- [ ] **Step 1: Write failing tests** (bottom of the new file). They exercise pure helpers and an end-to-end curl run against a loopback `TcpListener` stand-in (curl is a hard dependency of the feature; skip these tests with an early `return` and a printed note if `curl --version` cannot run):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn curl_available() -> bool {
        Command::new("curl").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
    }

    /// One-shot HTTP stand-in: serves `reply` (raw bytes) to the first
    /// connection and returns the request head it received.
    fn serve(reply: Vec<u8>) -> (u16, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 8192];
            let mut head = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 { break; }
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            let _ = s.write_all(&reply);
            String::from_utf8_lossy(&head).into_owned()
        });
        (port, h)
    }

    fn req(provider: &'static str, path: &str) -> Request {
        Request {
            provider, host: "haveibeenpwned.com", path: path.into(), query: vec![],
            headers: vec![("hibp-api-key", "SECRETKEY123".into())],
            timeout: Duration::from_secs(10), max_body: 64 * 1024,
        }
    }

    #[test]
    fn pct_encode_keeps_unreserved_and_encodes_the_rest() {
        assert_eq!(pct_encode("a-b_c.d~E9"), "a-b_c.d~E9");
        assert_eq!(pct_encode("a+b@x.org"), "a%2Bb%40x.org");
        assert_eq!(pct_encode("a/b?c#d%e f"), "a%2Fb%3Fc%23d%25e%20f");
    }

    #[test]
    fn config_doc_rejects_control_characters_in_values() {
        for bad in ["a\nb", "a\rb", "a\x00b", "a\x7fb", "a\tb"] {
            let r = config_doc("https://x.example/", &[("hibp-api-key", bad.to_string())]);
            assert!(r.is_err(), "{bad:?}");
        }
        let ok = config_doc("https://x.example/p", &[("hibp-api-key", "ab\"cd\\ef".to_string())]).unwrap();
        assert!(ok.contains("url = \"https://x.example/p\""));
        assert!(ok.contains("header = \"hibp-api-key: ab\\\"cd\\\\ef\""));
    }

    #[test]
    fn curl_args_never_carry_the_secret_and_pin_the_address() {
        let a = curl_args(10, 65536, Some("haveibeenpwned.com:443:203.0.113.9"), false);
        let joined = a.join(" ");
        assert!(!joined.contains("SECRETKEY123"));
        assert_eq!(a[0], "-q", "curlrc must be disabled first");
        assert!(joined.contains("--proto =https") || (a.contains(&"--proto".to_string()) && a.contains(&"=https".to_string())));
        assert!(a.contains(&"--max-redirs".to_string()) && a.contains(&"0".to_string()));
        assert!(a.contains(&"--noproxy".to_string()));
        assert!(joined.contains("--resolve haveibeenpwned.com:443:203.0.113.9") || a.windows(2).any(|w| w[0] == "--resolve" && w[1] == "haveibeenpwned.com:443:203.0.113.9"));
        assert!(a.contains(&"--config".to_string()));
    }

    #[test]
    fn parse_head_reads_status_headers_and_skips_100_continue() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Type: Application/JSON\r\n\r\nBODY";
        let (st, h, off) = parse_head(raw).unwrap();
        assert_eq!(st, 429);
        assert!(h.iter().any(|(k, v)| k == "retry-after" && v == "17"));
        assert_eq!(&raw[off..], b"BODY");
        assert!(parse_head(b"garbage").is_err());
    }

    #[test]
    fn retry_after_accepts_seconds_and_ignores_garbage() {
        assert_eq!(parse_retry_after("17"), Some(17));
        assert_eq!(parse_retry_after(" 3 "), Some(3));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-5"), None);
        assert_eq!(parse_retry_after("99999999999999999999"), None);
    }

    #[test]
    fn redact_removes_secrets_and_full_address_paths() {
        let t = "curl: (22) https://h/api/v3/breachedaccount/a%40b.org?x=1 key SECRETKEY123 failed";
        let r = redact(t, &["SECRETKEY123"]);
        assert!(!r.contains("SECRETKEY123"));
        assert!(!r.contains("a%40b.org"));
        assert!(!r.contains("?x=1"));
    }

    #[test]
    fn hashes_match_known_vectors() {
        if Command::new("sha256sum").arg("--version").output().is_err() { return; }
        assert_eq!(sha256_hex(b"abc").unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha1_hex_upper(b"abc").unwrap(), "A9993E364706816ABA3E25717850C26C9CD0D89D");
    }

    #[test]
    fn end_to_end_sends_the_key_header_and_returns_status_and_body() {
        if !curl_available() { return; }
        let (port, h) = serve(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]".to_vec());
        std::env::set_var("MSFE_NG_OSINT_BASE_T1", format!("http://127.0.0.1:{port}"));
        let r = fetch(&Request { provider: "t1", ..req("t1", "/api/v3/x") }).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"[]");
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        let head = h.join().unwrap().to_ascii_lowercase();
        assert!(head.contains("hibp-api-key: secretkey123"));
        assert!(head.contains("user-agent: msfe-ng"));
    }

    #[test]
    fn rate_limit_status_and_retry_after_are_returned() {
        if !curl_available() { return; }
        let (port, _h) = serve(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
        std::env::set_var("MSFE_NG_OSINT_BASE_T2", format!("http://127.0.0.1:{port}"));
        let r = fetch(&Request { provider: "t2", ..req("t2", "/x") }).unwrap();
        assert_eq!(r.status, 429);
        assert_eq!(r.retry_after, Some(9));
    }

    #[test]
    fn oversized_chunked_body_is_cut_at_the_cap() {
        if !curl_available() { return; }
        let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..40 {
            reply.extend_from_slice(b"1000\r\n");
            reply.extend_from_slice(&[b'x'; 0x1000]);
            reply.extend_from_slice(b"\r\n");
        }
        reply.extend_from_slice(b"0\r\n\r\n");
        let (port, _h) = serve(reply);
        std::env::set_var("MSFE_NG_OSINT_BASE_T3", format!("http://127.0.0.1:{port}"));
        let e = fetch(&Request { provider: "t3", max_body: 8 * 1024, ..req("t3", "/x") }).unwrap_err();
        assert_eq!(e, HttpError::TooLarge);
    }

    #[test]
    fn a_non_loopback_override_is_ignored() {
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "http://203.0.113.9:80");
        assert!(override_base("t4").is_none());
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "https://127.0.0.1:1");
        assert!(override_base("t4").is_none());
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "http://127.0.0.1:8080");
        assert_eq!(override_base("t4").as_deref(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn header_injection_in_a_secret_is_refused_before_any_process_starts() {
        let mut r = req("t5", "/x");
        r.headers = vec![("hibp-api-key", "k\r\nX-Evil: 1".into())];
        match fetch(&r) {
            Err(HttpError::Refused(_)) => {}
            other => panic!("expected Refused, got {other:?}"),
        }
    }
}
```

- [ ] **Step 2: Run to verify failure:** `PATH=$HOME/.cargo/bin:$PATH cargo test -p msfe-core providerhttp:: 2>&1 | tail -5` → compile error.

- [ ] **Step 3: Implement.** Create the module with this structure (write all of it; helper bodies as shown):

```rust
//! The only outbound path of the OSINT feature. Origins are compiled in by the
//! caller (`Request.host`); every destination IP is checked with
//! `outbound_allowed(ip, false)` and pinned; HTTPS only; no redirects; the
//! credential travels on curl's stdin, never in argv; the response is read
//! through a bounded reader so a hostile or broken server cannot make the
//! daemon buffer an unbounded body.

use crate::netguard;
use std::net::{IpAddr, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const HEAD_ALLOWANCE: usize = 16 * 1024;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const UA: &str = "msfe-ng osint";

// (types: Request, Response, HttpError — as specified in Interfaces; implement Display for HttpError)

pub fn pct_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Quoted curl-config value. Control characters are refused by the caller
/// (curl would turn an escaped `\n` back into a real newline).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn has_control(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

pub fn config_doc(url: &str, headers: &[(&'static str, String)]) -> Result<String, HttpError> {
    if has_control(url) {
        return Err(HttpError::Refused("control character in the request URL".into()));
    }
    let mut s = format!("url = \"{}\"\n", esc(url));
    for (k, v) in headers {
        if has_control(k) || has_control(v) {
            return Err(HttpError::Refused("control character in a request header".into()));
        }
        s.push_str(&format!("header = \"{}: {}\"\n", esc(k), esc(v)));
    }
    Ok(s)
}

pub fn curl_args(timeout_secs: u64, max_body: usize, pin: Option<&str>, allow_http: bool) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-q".into(), // first: ignore any curlrc
        "-sS".into(),
        "--http1.1".into(),
        "--proto".into(),
        if allow_http { "=http".into() } else { "=https".into() },
        "--max-redirs".into(), "0".into(),
        "--noproxy".into(), "*".into(),
        "--max-time".into(), timeout_secs.max(1).to_string(),
        "--max-filesize".into(), (max_body + 1).to_string(),
        "-A".into(), UA.into(),
        "-D".into(), "-".into(),
        "--config".into(), "-".into(),
    ];
    if let Some(p) = pin {
        a.push("--resolve".into());
        a.push(p.into());
    }
    a
}
```

`parse_head`: find the first `\r\n\r\n`; parse the status code as the second whitespace token of the first line; if the status is 100 (or any 1xx), continue with the remainder; lower-case header names; return `(status, headers, body_offset)`; `Err` if no complete head or non-numeric status.

`parse_retry_after`: `s.trim().parse::<u64>().ok()` (negative, date forms and overflow all give `None`), capped at 86400.

`redact(text, secrets)`: replace each non-empty secret with `***`; remove any `%40` / `@` containing URL path segments by replacing `https?://host/path?query` runs: simplest correct approach — replace every substring matching `https?://` up to the next whitespace with `<url>`.

`override_base(provider: &str) -> Option<String>`: read env `MSFE_NG_OSINT_BASE_<UPPER provider>`; accept only values of the exact form `http://127.0.0.1:<digits>` (no path, no trailing slash), else `None`.

`hash helpers`: `service::run_with_stdin(&mut Command::new("sha256sum"), data, Duration::from_secs(5))`; require `ok`, take the first whitespace token of stdout, require length 64 (sha256) or 40 (sha1) and all hex digits, return lowercase (sha256) or uppercase (sha1).

`fetch`:

1. Validate: `req.path` starts with `/`; build the query string `k=v&…` with `pct_encode` on both key and value; URL = `https://{host}{path}?{query}` (or `{override}{path}?…` when `override_base(req.provider)` is Some).
2. `config_doc(url, headers)?` (this refuses control characters before anything starts).
3. If no override: resolve `host` with `(host, 443).to_socket_addrs()` on a spawned thread, waiting `RESOLVE_TIMEOUT` via `mpsc::recv_timeout` (timeout → `HttpError::Resolve("lookup timed out")`); choose the first address for which `netguard::outbound_allowed(ip, false)` is Ok; if none passes → `HttpError::Blocked(<last reason>)`; pin = `format!("{host}:443:{ip}")` (IPv6 literals in brackets are not needed for `--resolve`; use the plain address).
4. Spawn `curl` with `curl_args(...)`, stdin piped, stdout piped, stderr piped, `process_group(0)` (`CommandExt`). Write the config document to stdin on a thread and close it. Read stdout on a thread into a shared buffer that stops reading after `max_body + HEAD_ALLOWANCE + 1` bytes and sets an `overflow` flag. Read stderr on a thread capped at 4 KiB. Poll `child.try_wait()` every 10 ms. On overflow or when `Instant::now() >= deadline` (`req.timeout + 2 s`), kill the process group the way `service.rs` does (`kill -9 -- -<pid>` then `child.kill()`), then `wait()`.
5. Outcome: overflow flag set → `HttpError::TooLarge`; deadline hit → `HttpError::Timeout`; curl exit code 63 (max filesize) → `TooLarge`; 28 → `Timeout`; 35/51/58/59/60/77/83 → `Tls(redacted stderr)`; 6 → `Resolve`; other non-zero → `Other(redact(stderr, secrets))` where `secrets` are all header values. On success `parse_head(stdout)`; body = remainder; if body length > `max_body` → `TooLarge`; collect `retry-after` and `content-type` (lowercased) into the `Response`.

Never log or return the config document or header values.

- [ ] **Step 4: Run tests:** `PATH=$HOME/.cargo/bin:$PATH cargo test -p msfe-core providerhttp:: 2>&1 | tail -20` → all pass. Run them 3 times (the stand-in uses ephemeral ports).

- [ ] **Step 5: Verify the secret never reaches argv or the process list.** Manual check, paste the output in your report: run a stand-in that sleeps 3 s before replying (e.g. a one-off Rust test marked `#[ignore]`, or `python3 -m http.server`-style script in the scratchpad) and, while `fetch` is in flight, run `ps -eo args | grep -c SECRETKEY123` — it must print `0`. Also run `curl --version | head -1` and note the version; the target EL8 hosts ship curl 7.61, which supports `--config -` (stdin config, option `-K -`) — say whether you could verify that on an older curl (you likely cannot; state that plainly).

- [ ] **Step 6: Gates and commit**

```bash
PATH=$HOME/.cargo/bin:$PATH cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
git add -A crates
git commit -m "OSINT: guarded provider transport with stdin credentials and bounded reads (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: HIBP settings, secret handling and the Config card

**Files:**
- Modify: `crates/msfe-core/src/config.rs`, `crates/msfe-ngd/src/api.rs` (`conf_apply` validation), `web/whm/index.html` (Config tab card; keep-existing handling), `packaging/install.sh`

**Interfaces:**
- Produces: `Config.osint_hibp_key: String` (default empty), `Config.osint_hibp_mode: String` (`"direct"` default, `"range"`; any other value parses as `"direct"`), public JSON `osint_hibp_set: bool` and `osint_hibp_mode: string`. The key itself is never serialized.

Use `abuseipdb_key` as the template: struct field + doc comment, `Default`, parser arm, `to_public_json` flag, Config-tab card, SPA keep-existing rule, `install.sh` seed, tests, docs. Read each place first (struct ~l.109, Default ~l.203, parser ~l.329, `to_public_json` ~l.503, SPA ~l.4547-4561, install.sh l.152).

- [ ] **Step 1: Failing tests.**

In `config.rs` tests:

```rust
    #[test]
    fn hibp_key_is_never_serialized_and_mode_is_validated() {
        let c = Config::from_toml_str("osint_hibp_key = \"SECRETKEY123\"\nosint_hibp_mode = \"range\"\n");
        assert_eq!(c.osint_hibp_key, "SECRETKEY123");
        assert_eq!(c.osint_hibp_mode, "range");
        let j = c.to_public_json().to_string();
        assert!(!j.contains("SECRETKEY123"));
        assert!(j.contains("\"osint_hibp_set\":true"));
        assert!(j.contains("\"osint_hibp_mode\":\"range\""));
        let d = Config::from_toml_str("osint_hibp_mode = \"bogus\"\n");
        assert_eq!(d.osint_hibp_mode, "direct");
        assert!(Config::default().to_public_json().to_string().contains("\"osint_hibp_set\":false"));
    }
```

(Use the real loader name found in the existing config tests if `from_toml_str` differs.)

In `api.rs` tests (mirror the existing conf-apply tests near l.3506-3530): a request to `conf_apply` with `which: "msfe"` and `changes: {"osint_hibp_key": "bad\\key"}` (a backslash), another with a double quote, another with a newline, and a mode `"wrong"` each return 400 and leave the file unchanged; a clean 32-hex key and mode `"range"` are accepted (200) and written.

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement.**
  1. `config.rs`: add fields, defaults (`String::new()`, `"direct".to_string()`), parser arms (`"osint_hibp_key" => c.osint_hibp_key = v`, `"osint_hibp_mode" => c.osint_hibp_mode = if v == "range" { "range".into() } else { "direct".into() }`), and in `to_public_json` `("osint_hibp_set", Bool(!key.trim().is_empty()))` and `("osint_hibp_mode", Str(mode))`.
  2. `api.rs` `conf_apply`: before rendering changes, validate OSINT keys when `which == "msfe"`: `osint_hibp_key` must be empty or consist only of ASCII alphanumerics, `-`, `_` and be ≤ 128 characters; `osint_hibp_mode` must be `direct` or `range`; else return 400 `{"error":"…"}` naming the key (never echo the value).
  3. SPA: replace the hardcoded keep-existing condition (l.~4561) with a data attribute check: inputs that hold a secret get `dataset.secret='1'`, and the save handler skips an empty value when `i.dataset.secret==='1'` (set it on `telegram_bot_token`, `abuseipdb_key` and the new key; keep behaviour identical for the old ones). Add an **OSINT providers** card after the AbuseIPDB card with: a status line "OSINT lookups" showing on/off from `cconf.osint_enabled` and, if off, a note to set `osint_enabled = true` (the card can also contain a checkbox that writes `osint_enabled`; do this: a checkbox writing `osint_enabled` as `true`/`false` strings through the same apply path — check how booleans are written by existing settings and mirror it); a password input `osint_hibp_key` (label shows "(configured)" from `cconf.osint_hibp_set`), a select `osint_hibp_mode` (direct = "full address sent to HIBP", range = "only a 6-character hash prefix sent; needs the Pro/High RPM plan"), and a **Clear key** button that POSTs `changes:{osint_hibp_key:""}` after a `confirm()`. Use `el()` text children only.
  4. `packaging/install.sh`: seed `osint_hibp_key = ""` and `osint_hibp_mode = "direct"` next to the abuseipdb seed.
  5. Make sure no other output surface leaks it: grep for places that print config (`grep -rn "abuseipdb_key" crates web`) and confirm the new key appears only in the places the template touches.

- [ ] **Step 4: Run tests and gates:** `cargo test --workspace`, clippy, fmt, `npm run build` + clean `git diff --exit-code web/whm/app.css web/user/app.css`, `node --check` as CI does.

- [ ] **Step 5: Commit**

```bash
git add -A crates web packaging
git commit -m "OSINT: HIBP key and mode settings, redaction, Config card (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Adapter module and the HIBP adapter

**Files:**
- Create: `crates/msfe-core/src/osintproviders.rs`
- Modify: `crates/msfe-core/src/osintrun.rs`, `crates/msfe-core/src/lib.rs` (`pub mod osintproviders;`), `crates/msfe-ngd/src/osint_api.rs` (providers route), `web/whm/index.html` (providers list text)

**Interfaces:**
- Consumes: `providerhttp::{fetch, Request, Response, HttpError, pct_encode, sha1_hex_upper}`, `osint::*`, `Config`.
- Produces in `osintproviders`:
  - `pub struct QueryCtx<'a> { pub address: &'a str, pub cancel: &'a AtomicBool, pub deadline: Instant, pub cfg: &'a Config }` with `pub fn stop(&self) -> bool`.
  - `pub struct Outcome { pub source: SourceStatus, pub findings: Vec<Finding> }`.
  - `pub struct Info { pub id: &'static str, pub name: &'static str, pub disclosure: String, pub configured: bool }`.
  - `pub fn infos(cfg: &Config) -> Vec<Info>`; `pub fn is_known(id: &str) -> bool`; `pub fn run(id: &str, q: &QueryCtx) -> Outcome`.
  - The phase 1 fixture moves here unchanged (still gated by `MSFE_NG_OSINT_FIXTURE`).
- `osintrun`: `providers()` and `parse_inputs` use `osintproviders::{infos,is_known}`; `providers()` becomes `providers(cfg: &Config) -> Vec<ProviderInfo>` (update CLI and API callers); `run_provider` delegates to `osintproviders::run`; `QueryCtx` in `osintrun` is replaced by the one from `osintproviders` (workers pass `cfg` clone). Remove the dead private copies.

HIBP behaviour (`id = "hibp"`):
- No key → one `SourceStatus { id: "hibp", state: NotConfigured, detail: "no HIBP API key is set (Config → OSINT providers)" }`, no request.
- Direct mode: `GET /api/v3/breachedaccount/{pct_encode(address)}` with query `truncateResponse=false`, headers `hibp-api-key` and `user-agent` is set by curl (`-A`). Discloses "the full address is sent to haveibeenpwned.com".
- Range mode: SHA-1 (upper-case hex) of the lower-cased, trimmed address; `GET /api/v3/breachedaccount/range/{first 6 chars}`; discloses "only a 6-character SHA-1 prefix of the address is sent". Response `[{"hashSuffix": "...34 hex...", "websites": ["Name", …]}, …]`; keep only the row whose `hashSuffix` equals the remaining 34 characters (case-insensitive); discard all other rows immediately.
- Status mapping: 200 with breaches → Matched (`"N incident(s)"`); 200 with `[]` or range without a matching suffix → NoMatch; 404 → NoMatch; 401/403 → Restricted ("the API key was rejected or the plan does not include this lookup"); 429 → RateLimited with `retry_after`; 400 → Failed ("the provider rejected the address"); 5xx and other statuses → Failed (`"HIBP answered HTTP {n}"`); `HttpError::Blocked` → Failed("destination blocked: …"); `Timeout` → Failed("timed out"); other `HttpError` → Failed(redacted display). Malformed JSON, `null`, an object where an array is expected, or HTML → Failed("unexpected answer from HIBP") — never a panic and never "no match".

Finding construction (`breach_finding`):
- group `Exposure`; title `format!("Appears in breach: {}", title_or_name)`.
- confidence: `High` if `IsVerified` and not `IsFabricated`; `Low` if `IsFabricated` or not `IsVerified`; reason text explains ("verified incident", "unverified incident", "fabricated data reported by the source"). Range findings (names only): `Medium`, reason "matched by hash prefix; the source returned no details".
- severity: `Medium` if DataClasses contain "Passwords", `Info` if `IsSpamList`, otherwise `Low`.
- `event_at`: parse `BreachDate` (`YYYY-MM-DD`) with `civil::Date::parse(s)` → `to_days() * 86400` (check `civil.rs` for the exact methods); `observed_at`: now.
- evidence: `format!("Incident-wide data classes: {}. This describes what the incident exposed in general; it does not show that a password for this address was exposed.", classes.join(", "))` (or, when DataClasses is empty, "The source lists no data classes."), plus `" Flags: spam list."`/`" malware."`/`" sensitive."` when set; for range findings: `"Listed by incident name only (a hash-range lookup returns no further detail)."`.
- `limitations`: `["Historical incident dated YYYY-MM-DD; it does not describe the address's current exposure."]` (omit the date part when unknown) and for sensitive/retired incidents "Public searches omit some sensitive or retired incidents."
- `source_url`: `https://haveibeenpwned.com/PwnedWebsites#<Name>` where `<Name>` keeps only ASCII alphanumerics.
- Never copy the `Description` HTML into a finding.

- [ ] **Step 1: Write failing tests** in `osintproviders.rs` (stand-in server as in Task 3; copy the small `serve` helper into this test module, extended to take a request-path assertion; use unique `MSFE_NG_OSINT_BASE_HIBP` values per test — tests that set the same env var must serialize behind a `static HIBP_LOCK: Mutex<()>`):

```rust
    const DIRECT_BODY: &str = r#"[{"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04","AddedDate":"2013-12-04T00:00:00Z","PwnCount":152445165,"DataClasses":["Email addresses","Password hints","Passwords"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,"IsSpamList":false,"IsMalware":false,"Description":"<script>alert(1)</script>"}]"#;

    #[test]
    fn direct_match_builds_an_incident_wide_finding_without_html() {
        let fs = hibp_findings_direct(DIRECT_BODY.as_bytes(), 1_000).unwrap();
        assert_eq!(fs.len(), 1);
        let f = &fs[0];
        assert_eq!(f.group, Group::Exposure);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.severity, Severity::Medium);
        assert!(f.evidence.contains("Incident-wide data classes"));
        assert!(f.evidence.contains("does not show that a password for this address was exposed"));
        assert!(!f.evidence.contains("<script>"));
        assert_eq!(f.source_url.as_deref(), Some("https://haveibeenpwned.com/PwnedWebsites#Adobe"));
        assert_eq!(f.event_at, Some(1380844800)); // 2013-10-04 UTC
        assert!(f.limitations.iter().any(|l| l.contains("2013-10-04")));
    }

    #[test]
    fn malformed_answers_are_failures_not_no_match() {
        for bad in ["null", "{}", "<html>blocked</html>", "", "[1,2", "\"x\""] {
            assert!(hibp_findings_direct(bad.as_bytes(), 1).is_err(), "{bad}");
        }
        assert_eq!(hibp_findings_direct(b"[]", 1).unwrap().len(), 0);
    }

    #[test]
    fn range_keeps_only_the_matching_suffix_and_drops_the_rest() {
        let body = r#"[{"hashSuffix":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","websites":["Other"]},{"hashSuffix":"c6c0aade0c085843d66e4944e108c4a4cd","websites":["Adobe","Gawker"]}]"#;
        let fs = hibp_findings_range(body.as_bytes(), "C6C0AADE0C085843D66E4944E108C4A4CD", 1).unwrap();
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|f| f.evidence.contains("name only")));
        let none = hibp_findings_range(body.as_bytes(), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1).unwrap();
        assert!(none.is_empty());
        assert!(hibp_findings_range(b"{}", "A", 1).is_err());
    }

    #[test]
    fn missing_key_is_not_configured_and_sends_nothing() {
        let cfg = Config::default(); // no key
        let cancel = AtomicBool::new(false);
        let q = QueryCtx { address: "a@example.org", cancel: &cancel, deadline: Instant::now() + Duration::from_secs(5), cfg: &cfg };
        let o = run("hibp", &q);
        assert_eq!(o.source.state, SourceState::NotConfigured);
        assert!(o.findings.is_empty());
    }

    #[test]
    fn status_mapping_end_to_end() {
        // (reply, expected state)
        let _g = HIBP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cases: Vec<(&str, SourceState)> = vec![
            ("200 OK", SourceState::Matched),
            ("404 Not Found", SourceState::NoMatch),
            ("401 Unauthorized", SourceState::Restricted),
            ("403 Forbidden", SourceState::Restricted),
            ("429 Too Many Requests", SourceState::RateLimited),
            ("400 Bad Request", SourceState::Failed),
            ("503 Service Unavailable", SourceState::Failed),
        ];
        for (status, want) in cases {
            let body = if status.starts_with("200") { DIRECT_BODY } else { "" };
            let reply = format!("HTTP/1.1 {status}\r\nRetry-After: 7\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let (port, h) = serve(reply.into_bytes());
            std::env::set_var("MSFE_NG_OSINT_BASE_HIBP", format!("http://127.0.0.1:{port}"));
            let mut cfg = Config::default();
            cfg.osint_hibp_key = "SECRETKEY123".into();
            let cancel = AtomicBool::new(false);
            let q = QueryCtx { address: "a+b@example.org", cancel: &cancel, deadline: Instant::now() + Duration::from_secs(10), cfg: &cfg };
            let o = run("hibp", &q);
            let head = h.join().unwrap();
            assert_eq!(o.source.state, want, "{status}");
            assert!(head.starts_with("GET /api/v3/breachedaccount/a%2Bb%40example.org?truncateResponse=false"), "{head}");
            if status.starts_with("429") { assert_eq!(o.source.retry_after, Some(7)); }
            assert!(!o.source.detail.contains("SECRETKEY123"));
        }
        std::env::remove_var("MSFE_NG_OSINT_BASE_HIBP");
    }

    #[test]
    fn range_mode_sends_only_the_prefix() {
        let _g = HIBP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha1sum").arg("--version").output().is_err() { return; }
        let body = "[]";
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let (port, h) = serve(reply.into_bytes());
        std::env::set_var("MSFE_NG_OSINT_BASE_HIBP", format!("http://127.0.0.1:{port}"));
        let mut cfg = Config::default();
        cfg.osint_hibp_key = "SECRETKEY123".into();
        cfg.osint_hibp_mode = "range".into();
        let cancel = AtomicBool::new(false);
        // sha1("multiple-breaches@hibp-integration-tests.com") = 6B5917C6C0AADE0C...
        let q = QueryCtx { address: " Multiple-Breaches@HIBP-integration-tests.com ", cancel: &cancel, deadline: Instant::now() + Duration::from_secs(10), cfg: &cfg };
        let o = run("hibp", &q);
        let head = h.join().unwrap();
        assert!(head.starts_with("GET /api/v3/breachedaccount/range/6B5917 "), "{head}");
        assert!(!head.to_ascii_lowercase().contains("multiple-breaches"));
        assert_eq!(o.source.state, SourceState::NoMatch);
        std::env::remove_var("MSFE_NG_OSINT_BASE_HIBP");
    }

    #[test]
    fn disclosure_text_follows_the_mode() {
        let mut cfg = Config::default();
        let i = infos(&cfg);
        let h = i.iter().find(|p| p.id == "hibp").unwrap();
        assert!(h.disclosure.contains("full address"));
        assert!(!h.configured);
        cfg.osint_hibp_mode = "range".into();
        cfg.osint_hibp_key = "k".into();
        let h2 = infos(&cfg).into_iter().find(|p| p.id == "hibp").unwrap();
        assert!(h2.disclosure.contains("6-character"));
        assert!(h2.configured);
    }
```

Controller-level test in `osintrun` tests (fixture is unaffected): a run with `providers=["hibp"]` and no key completes with the source `NotConfigured`, the run `Partial` (not `Complete`), and no findings:

```rust
    #[test]
    fn unconfigured_provider_makes_the_run_partial_not_clean() {
        let (c, _g) = setup();
        let p = vec!["hibp".to_string()];
        let inputs = parse_inputs("quiet.nokey@example.org", &p, true, None).unwrap();
        let StartOk::Started(id) = start(&c, inputs).unwrap() else { panic!() };
        let r = wait_done(&id);
        assert_eq!(r.sources[0].state, SourceState::NotConfigured);
        assert_eq!(r.state, RunState::Partial);
    }
```

- [ ] **Step 2: Run to verify failure:** `cargo test -p msfe-core osintproviders:: 2>&1 | tail` → compile errors.

- [ ] **Step 3: Implement** per the behaviour above. Helper signatures used by the tests:

```rust
fn hibp_findings_direct(body: &[u8], now: u64) -> Result<Vec<Finding>, String>
fn hibp_findings_range(body: &[u8], full_hash_upper: &str, now: u64) -> Result<Vec<Finding>, String>
```

`hibp_findings_direct`: `Json::parse(str::from_utf8(body)?)`, require `Json::Array`; each element must be an object with a non-empty `Name`; otherwise `Err("unexpected answer")`. `hibp_findings_range`: require an array of objects with string `hashSuffix` and array `websites`; compare `hashSuffix.to_ascii_uppercase()` with `full_hash_upper[6..]`... note the test passes the *suffix* string directly as `full_hash_upper` argument name for brevity: define the parameter as `suffix_upper: &str` (the 34 remaining characters, upper-case) and compare case-insensitively; the caller computes `hash[6..]`.

`run("hibp", q)`:
1. key empty → NotConfigured outcome.
2. compute address normalization: `address.trim()` for direct; `address.trim().to_ascii_lowercase()` for range (SHA-1 of that, upper-case hex).
3. build `providerhttp::Request { provider: "hibp", host: "haveibeenpwned.com", path, query, headers: vec![("hibp-api-key", key.trim().to_string())], timeout: min(10 s, remaining time to q.deadline), max_body: 2 MiB (direct) / 1 MiB (range) }`.
4. `fetch`, map the status as specified; if `q.stop()` is already true before the request, return `Inconclusive`/"stopped before this source ran".
5. Wrap the result; `source.detail` for Matched is `format!("{n} incident(s)")`.

`infos(cfg)`: always lists `hibp` (disclosure per mode; `configured = key set`) and, when the fixture env is set, `fixture`. Gravatar is added in Task 6.

Wire `osintrun`: replace the private `QueryCtx`/`Outcome`/`fixture`/`run_provider` with the `osintproviders` versions; `QueryCtx` gets `cfg: &Config` (the worker owns a cloned `Config`; add a `cfg: Config` parameter to `worker`). `providers(cfg)` and `parse_inputs` use `is_known`. Update `osint_api::providers` (it now receives `cfg`; add `"configured"` from `Info.configured`) and `cmd_delivery_osint` (`providers(&cfg)`; print `configured`).

UI: in the providers list, render `p.configured` (append " — not configured" in muted text when false) and keep the disclosure text. Selecting an unconfigured provider is allowed (the run reports it honestly).

- [ ] **Step 4: Run tests and gates:** `cargo test --workspace`, clippy, fmt, `node --check`, web build clean.

- [ ] **Step 5: Commit**

```bash
git add -A crates web
git commit -m "OSINT: HIBP adapter with direct and hash-range lookups (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Gravatar adapter and avatar delivery

**Files:**
- Modify: `crates/msfe-core/src/osintproviders.rs`, `crates/msfe-core/src/osint.rs`, `crates/msfe-core/src/osintrun.rs`, `crates/msfe-core/src/osinthtml.rs`, `crates/msfe-ngd/src/osint_api.rs`, `web/whm/index.html`

**Interfaces:**
- Consumes: `providerhttp::{fetch, sha256_hex}`, Task 5 `Outcome`/`QueryCtx`/`Info`.
- Produces:
  - `Finding` gains `pub asset_id: Option<String>` and `pub asset_mime: Option<String>`; JSON fields `asset_id`/`asset_mime` (null when absent; old reports parse with `None`).
  - `Outcome` gains `pub assets: Vec<Asset>` with `pub struct Asset { pub id: String, pub mime: &'static str, pub bytes: Vec<u8> }`; ids are 16 lowercase hex from `deliveryrun::new_id()`.
  - `osintrun`: after the worker collects outcomes it persists each asset to `<report_dir>/assets/<asset_id>.bin` (dir `0700`, file `0600`, `create_new`, never through a symlink) *before* the report is persisted, only when the run is not tombstoned/removed; `remove()` deletes the assets referenced by the run's findings; `sweep()` deletes `assets/*.bin` older than the retention age (names must be 16 hex + `.bin`); `pub fn asset(id: &str) -> Option<(String /*mime*/, Vec<u8>)>` validates the id, finds the owning finding in memory or persisted reports (so a deleted run's asset is unreachable), refuses symlinks, and returns the bytes.
  - `GET /api/delivery/osint/asset?id=` returns `{"mime":"image/png","data":"<base64>"}` (404 for an invalid or unknown id); root-only like the rest.
  - Gravatar adapter: `id = "gravatar"`, always `configured = true`, disclosure "A SHA-256 hash of the lower-cased address is sent to gravatar.com".

Gravatar behaviour:
- `hash = sha256_hex(address.trim().to_ascii_lowercase())`; request `GET /avatar/{hash}` with query `d=404`, `s=256`, `r=g`, host `gravatar.com`, `max_body` 256 KiB, no key.
- 404 → NoMatch, detail "no public avatar at rating G (a Gravatar may exist at a stricter rating)".
- 200 → validate: `content_type` starts with `image/png`, `image/jpeg` or `image/webp` AND the body's magic bytes match (PNG `89 50 4E 47 0D 0A 1A 0A`; JPEG `FF D8 FF`; WebP `RIFF` + 4 bytes + `WEBP`) AND the two agree; otherwise Failed("the answer was not a supported image") and nothing is stored. Over 256 KiB is `HttpError::TooLarge` → Failed("avatar larger than the 256 KiB limit").
- Valid → Matched with one `Profile` finding: title "Public avatar found through Gravatar", evidence "A Gravatar image is published for this address (rating G, 256 px).", confidence `Medium` with reason "hash of the normalized address matches; this does not prove who controls the mailbox or that the image is used elsewhere", `source_url` `https://gravatar.com/{hash}` (a hash, not the address), `limitations`: `["Absence of an avatar is not evidence of anything.", "Gravatar's profile data is not queried in this release."]`, plus `asset_id`/`asset_mime`.
- 429 → RateLimited (+retry_after); other statuses and errors map as for HIBP (Failed with redacted detail; 403/401 → Restricted).

UI: in `paint`, for a finding with `asset_id`, fetch `/api/delivery/osint/asset?id=` once, build `new Blob([bytes], {type: mime})` from the base64 data (`atob` → `Uint8Array`; only accept `image/png|jpeg|webp` mime values), `URL.createObjectURL`, render an `<img>` (`width=96 height=96`, `alt="Gravatar avatar"`, `referrerpolicy="no-referrer"`) inside the finding row. Keep the object URLs in a module-level array `OSINT_BLOBS`; add `osintRevoke()` which revokes and clears them, and call it at the start of `renderOsint`, before each `paint()` rebuild, and in the top-level tab handler and Delivery view switch (beside the timer clears). The browser never contacts Gravatar.

`osinthtml.rs`: do not embed images in the HTML export (avoid base64 bloat); show "Avatar: present (not embedded)" for findings with an asset.

- [ ] **Step 1: Failing tests.**

In `osintproviders.rs`:

```rust
    fn png() -> Vec<u8> { let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]; v.extend_from_slice(&[0u8; 64]); v }

    #[test]
    fn image_validation_requires_matching_type_and_magic() {
        assert_eq!(sniff_image(&png(), Some("image/png")), Some("image/png"));
        assert_eq!(sniff_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0], Some("image/jpeg; charset=x")), Some("image/jpeg"));
        let mut webp = b"RIFF".to_vec(); webp.extend_from_slice(&[0, 0, 0, 0]); webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(sniff_image(&webp, Some("image/webp")), Some("image/webp"));
        assert_eq!(sniff_image(&png(), Some("image/jpeg")), None, "type and magic must agree");
        assert_eq!(sniff_image(b"<svg xmlns='http://www.w3.org/2000/svg'/>", Some("image/svg+xml")), None);
        assert_eq!(sniff_image(b"<html>", Some("image/png")), None);
        assert_eq!(sniff_image(b"GIF89a....", Some("image/gif")), None);
        assert_eq!(sniff_image(&png()[..4], Some("image/png")), None, "truncated");
        assert_eq!(sniff_image(&png(), None), None);
    }

    #[test]
    fn gravatar_end_to_end_stores_an_asset_for_a_real_image_only() {
        let _g = GRAV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha256sum").arg("--version").output().is_err() { return; }
        let img = png();
        let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", img.len()).into_bytes();
        reply.extend_from_slice(&img);
        let (port, h) = serve(reply);
        std::env::set_var("MSFE_NG_OSINT_BASE_GRAVATAR", format!("http://127.0.0.1:{port}"));
        let cfg = Config::default();
        let cancel = AtomicBool::new(false);
        let q = QueryCtx { address: "User@Example.org", cancel: &cancel, deadline: Instant::now() + Duration::from_secs(10), cfg: &cfg };
        let o = run("gravatar", &q);
        let head = h.join().unwrap();
        assert!(head.starts_with("GET /avatar/"), "{head}");
        assert!(head.contains("d=404") && head.contains("s=256") && head.contains("r=g"));
        assert!(!head.to_ascii_lowercase().contains("example.org"), "the address itself must not be sent");
        assert_eq!(o.source.state, SourceState::Matched);
        assert_eq!(o.assets.len(), 1);
        assert_eq!(o.findings[0].asset_id.as_deref(), Some(o.assets[0].id.as_str()));
        std::env::remove_var("MSFE_NG_OSINT_BASE_GRAVATAR");
    }

    #[test]
    fn gravatar_non_image_404_and_oversize_store_nothing() {
        let _g = GRAV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha256sum").arg("--version").output().is_err() { return; }
        let big = vec![0x89u8; 300 * 1024];
        let cases: Vec<(Vec<u8>, SourceState)> = vec![
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>".to_vec(), SourceState::Failed),
            (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::NoMatch),
            ([format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", big.len()).into_bytes(), big].concat(), SourceState::Failed),
        ];
        for (reply, want) in cases {
            let (port, _h) = serve(reply);
            std::env::set_var("MSFE_NG_OSINT_BASE_GRAVATAR", format!("http://127.0.0.1:{port}"));
            let cfg = Config::default();
            let cancel = AtomicBool::new(false);
            let q = QueryCtx { address: "u@example.org", cancel: &cancel, deadline: Instant::now() + Duration::from_secs(10), cfg: &cfg };
            let o = run("gravatar", &q);
            assert_eq!(o.source.state, want);
            assert!(o.assets.is_empty() && o.findings.is_empty());
        }
        std::env::remove_var("MSFE_NG_OSINT_BASE_GRAVATAR");
    }
```

(The stand-in's `serve` must write the reply to completion and tolerate curl closing early for the oversize case; ignore write errors in that helper.)

In `osint.rs` tests: a finding with `asset_id`/`asset_mime` round-trips; a JSON finding without those fields parses with `None`.

In `osintrun.rs` tests (fixture-only; add a fixture behaviour: local part containing `avatar` returns one `Profile` finding with an asset of a 70-byte PNG-magic buffer so the storage plumbing is testable without the network):

```rust
    #[test]
    fn avatar_assets_are_stored_served_and_deleted_with_the_run() {
        use std::os::unix::fs::PermissionsExt;
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("avatar.one@example.org", true)).unwrap() else { panic!() };
        let r = wait_done(&id);
        let aid = r.findings[0].asset_id.clone().expect("asset id");
        let f = report_dir().join("assets").join(format!("{aid}.bin"));
        let end = Instant::now() + Duration::from_secs(5);
        while !f.exists() && Instant::now() < end { std::thread::sleep(Duration::from_millis(20)); }
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
        let (mime, bytes) = asset(&aid).unwrap();
        assert_eq!(mime, "image/png");
        assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']));
        assert!(asset("../etc/passwd").is_none());
        assert!(remove(&id));
        assert!(!f.exists(), "the asset goes with the run");
        assert!(asset(&aid).is_none());
    }

    #[test]
    fn a_run_removed_while_running_leaves_no_asset_behind() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("slow.avatar.rm@example.org", true)).unwrap() else { panic!() };
        assert!(remove(&id));
        let end = Instant::now() + Duration::from_secs(5);
        while Instant::now() < end && running_count() > 0 { std::thread::sleep(Duration::from_millis(20)); }
        let dir = report_dir().join("assets");
        let leftovers = std::fs::read_dir(&dir).map(|d| d.flatten().count()).unwrap_or(0);
        // other tests may have created assets; assert none belongs to this run's findings (it has none persisted)
        assert!(snapshot(&id).is_none());
        let _ = leftovers;
    }
```

(Adjust the fixture so `slow.avatar.rm` is slow *and* produces an asset only at the very end; assert that after the worker ends `assets_for_removed_run` is empty by tracking the asset ids the worker would have written: add a `#[cfg(test)] static LAST_ASSET_IDS` or check that the number of files in `assets/` is unchanged before and after the removed run finishes — pick whichever is simpler and state it.)

In `osint_api.rs` tests: `GET /api/delivery/osint/asset?id=<valid but unknown 16-hex>` → 404; `?id=..%2Fx` → 404; after a fixture avatar run, `asset?id=<aid>` → 200 with `"mime":"image/png"` and a non-empty `"data"`.

- [ ] **Step 2: Run to verify failure.**

- [ ] **Step 3: Implement** as specified. Helper signature: `fn sniff_image(bytes: &[u8], content_type: Option<&str>) -> Option<&'static str>`; compare the media type part of `content_type` (before `;`, lower-cased) with the magic-derived type. Worker: `Outcome.assets` are written by a new `fn store_assets(run_id: &str, assets: &[Asset]) -> std::io::Result<()>` called under the same `PERSIST` lock and tombstone check as the report persist (assets are only written when the run is not tombstoned/removed). `remove()`: collect the asset ids from the run's findings (memory or persisted report) before deleting, delete `assets/<id>.bin` for each. Add `Finding.asset_id/asset_mime` to `to_json`/`from_json`. `asset()` locates the owner via a scan of in-memory `Slot`s (skipping removed) and then persisted reports through `load` (cheap: reports are small); only then reads the file.

- [ ] **Step 4: Run tests and gates**, including `node --check` and a jsdom render check of the avatar path if jsdom is available in the scratchpad from earlier work (state plainly whether the render check was done).

- [ ] **Step 5: Commit**

```bash
git add -A crates web
git commit -m "OSINT: Gravatar avatar adapter with validated, server-side avatar delivery (phase 2)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Documentation and final gates

**Files:**
- Modify: `docs/wiki/OSINT.md`, `docs/wiki/Config.md`, `docs/wiki/CLI.md`, `README.md` only if it lists Delivery features (check `grep -n "OSINT\|Delivery" README.md`).

- [ ] **Step 1: Update the docs** to match the real behaviour:
  - `OSINT.md`: replace the "groundwork" wording with the phase 2 reality: sources HIBP (direct or hash-range) and Gravatar; what each sends (full address / 6-character SHA-1 prefix / SHA-256 hash); that HIBP needs a paid key and range mode needs the Pro/High RPM plan; incident-wide data classes explained; "no match" and `not_configured` meanings; avatars are fetched by the server and shown from a local copy (≤ 256 KiB, PNG/JPEG/WebP only); reports and avatars expire after `osint_retention_hours`; the daily housekeeping sweep; `osint_enabled` still off by default; Delivery tab is unaffected by provider failures; privacy note (an investigated address is personal data; review the providers' terms and your data-protection obligations before enabling). Mention the limits honestly: no profile data from Gravatar, no per-incident detail in range mode, HTML export does not embed avatars.
  - `Config.md`: the OSINT providers card (key, mode, Clear key, the enabled checkbox) and the fact that the key is stored in `config.toml` (root-readable, included in snapshots, visible in the Config tab's raw view — say so plainly).
  - `CLI.md`: `delivery osint providers` now prints `configured`; `osint_hibp_key`/`osint_hibp_mode` rows.
  - No server names anywhere.
- [ ] **Step 2: Final gates** (paste results in the report): `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `(cd web && npm run build && git diff --exit-code whm/app.css user/app.css)`; `node --check` on the extracted `<script>` blocks of `web/whm/index.html` and `web/user/index.html` as CI does; `grep -rniE "ncc|gauss|erdos" docs/wiki/OSINT.md crates/msfe-core/src/osint*.rs crates/msfe-core/src/providerhttp.rs crates/msfe-ngd/src/osint_api.rs` prints nothing; `git grep -n "hibp_key" -- ':!crates/msfe-core/src/config.rs' ':!web/whm/index.html' ':!packaging/install.sh' ':!docs'` shows the key only where intended (adapters read it from `Config`; nothing logs it).
- [ ] **Step 3: Commit**

```bash
git add -A docs README.md
git commit -m "OSINT: phase 2 documentation (providers, privacy, limits)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

Do not push, tag or release.

---

## Self-Review

**Spec coverage (phase 2 of spec section 8, plus the pre-phase-2 list):** transport with fixed origins, IP guard, pin, no redirects, stdin secret, bounded read, redaction (T3); secrets and Config card, blank-keeps and Clear, save-time validation (T4); HIBP direct and range, incident-wide wording, range row discarding, 404/401/403/429 mapping, `not_configured` (T5); Gravatar `d=404`, rating-qualified absence, server-side avatar with size/magic checks, base64 JSON delivery, Blob URL revoke, asset cleanup with the run (T6); docs and privacy note (T7); deferred items M3 (persist/symlink/dir), orphan `.tmp`, Unknown group/severity and schema check, `external_query_limit`, route tests, removed-run slot (T1, T2). Not in this phase by design: Gravatar profile API and `osint_gravatar_key` (no profile data is read, so the key setting is not added), image dimension checks (no decoder; size and magic only), M4 (CLI process-local limits; documented in the wiki as a limit, not changed).

**Placeholder scan:** adaptation points are explicit (`Config` loader name, `civil.rs` method names, exact SPA lines, the process-group kill recipe in `service.rs`, how booleans are written by the Config card). Each says what to read and what to do.

**Type consistency:** `QueryCtx`/`Outcome`/`Info`/`Asset` are defined in Task 5/6 and used by the controller; `Group`/`Severity` become non-`Copy` in Task 2 before Tasks 5–6 construct findings; `Finding.asset_id/asset_mime` are added in Task 6 and every earlier `Finding { .. }` literal (fixture, tests in `osint.rs`, `osinthtml.rs`) must gain `asset_id: None, asset_mime: None` in that task.
