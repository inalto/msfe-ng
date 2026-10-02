# Delivery → OSINT, Phase 1 (native skeleton) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Delivery → OSINT view backed by a new `OsintReport` model, run controller, routes, CLI command and JSON/HTML export, proven end to end with a fixture provider and no real network access.

**Architecture:** A new `osint.rs` (pure types/JSON), `osintrun.rs` (independent registry, limits, cache, cancel, file persistence, fixture provider), `osinthtml.rs` (escaped export), `osint_api.rs` in the daemon (root-only routes, own prefix arm before `/api/delivery/`), a `delivery osint` CLI command, and an OSINT pill in the WHM Delivery view. Existing Delivery code is not modified except for registration points.

**Tech Stack:** Rust 1.74, std only, the in-repo `Json` type, vanilla JS in `web/whm/index.html`.

**Spec:** `docs/superpowers/specs/2026-10-02-delivery-osint-design.md` (sections 3, 5, 6, 7, 9 apply to phase 1; sections 4 and phases 2–6 are out of scope here).

## Global Constraints

- Rust 1.74 minimum, edition 2021; no external crates; std only.
- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` must pass; tests must not touch the network.
- Admin (root peer) surface only; nothing under `/api/user/`.
- Separate `OsintReport`; `delivery::Report`, its JSON, monitors and CLI exits are unchanged.
- No lookup runs unless the operator starts one; no OSINT call in MailScanner hooks or Exim; no test mail is sent.
- A breach finding never changes the CLI exit code. OSINT exit codes: 0 complete, 2 usage, 3 invalid input or runtime failure, 4 partial.
- Defaults: `osint_enabled=false`, 3 runs/min, 2 concurrent runs, 30 s deadline, 5 external queries, cache 3600 s, retention 24 h.
- Run IDs are 16 lowercase hex characters; no file path is built from the address.
- No server names (ncc, gauss, etc.) in commits, docs, code or comments (public repo).
- Commit message trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Nothing is released until the user says "go".
- If any CSS class is added, run `npm run build` in `web/` and commit the generated `web/whm/app.css` and `web/user/app.css`.

## Review Focus

- Address with uppercase, spaces, or no `@`: rejected (400) or normalized predictably; never panics. Pinned in Task 2.
- A second run of the same address while one is running: 409 with the running id. Pinned in Task 2.
- Unknown provider name in `providers`: 400, never silently dropped. Pinned in Task 2.
- Poll for an id that is not 16 hex characters (`../x`, empty): 404, no filesystem access. Pinned in Task 3.
- Daemon restarts mid-run: poll returns 404 with a restart hint; stale files are swept. Pinned in Tasks 3 and 5.
- `osint_enabled=false`: `run` is 403, `providers` still answers. Pinned in Task 5.
- Evidence containing `<script>` or quotes: escaped in HTML export and rendered as text in the UI. Pinned in Tasks 4 and 7.
- Cancelled run never reported as complete. Pinned in Task 2.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/msfe-core/src/osint.rs` (create) | Types: states, `Finding`, `SourceStatus`, `OsintReport`, `Inputs`; JSON conversion and parsing |
| `crates/msfe-core/src/osintrun.rs` (create) | Registry, limits, cache, cancel, persistence, sweep, fixture provider |
| `crates/msfe-core/src/osinthtml.rs` (create) | Self-contained escaped HTML export |
| `crates/msfe-core/src/lib.rs` (modify) | Register the three modules |
| `crates/msfe-core/src/config.rs` (modify) | Seven `osint_*` settings |
| `crates/msfe-ngd/src/osint_api.rs` (create) | Request handlers |
| `crates/msfe-ngd/src/main.rs`, `api.rs` (modify) | `mod osint_api;` and the route arm |
| `crates/msfe-cli/src/main.rs` (modify) | `delivery osint`, flag table, usage |
| `web/whm/index.html` (modify) | Pill, poller, `renderOsint`, `osintFor` |
| `docs/wiki/OSINT.md` (create) | Operator guide (phase 1 scope) |

---

### Task 1: Models and JSON (`osint.rs`)

**Files:**
- Create: `crates/msfe-core/src/osint.rs`
- Modify: `crates/msfe-core/src/lib.rs` (add `pub mod osint;` in alphabetical position)

**Interfaces:**
- Produces:
  - `enum SourceState { Matched, NoMatch, Inconclusive, Restricted, NotConfigured, NotRequested, RateLimited, Failed, Unknown(String) }` with `as_str()`, `parse(&str)`.
  - `enum Group { Exposure, Profile, Reference, Domain, Validation, Context }`, `Confidence { High, Medium, Low, Unknown }`, `Severity { Info, Low, Medium, High }`, `RunState { Running, Complete, Partial, Cancelled, Failed }` each with `as_str()`/`parse`.
  - `struct Finding { group, confidence, confidence_reason, severity, observed_at: u64, event_at: Option<u64>, source_id, source_url: Option<String>, title, evidence, limitations: Vec<String> }`.
  - `struct SourceStatus { id, state: SourceState, retry_after: Option<u64>, detail: String }`.
  - `struct OsintReport { run_id, address, started: u64, finished: Option<u64>, state: RunState, cached: bool, planned: Vec<String>, sources: Vec<SourceStatus>, findings: Vec<Finding>, delivery_run_id: Option<String>, limitations: Vec<String> }`.
  - `OsintReport::to_json(&self) -> Json`, `OsintReport::from_json(&Json) -> Result<OsintReport, String>`.
  - `pub const SCHEMA_VERSION: i64 = 1;`
  - `pub fn now_secs() -> u64`.

- [ ] **Step 1: Write the failing tests** (at the bottom of the new file)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "user@example.org".into(),
            started: 100,
            finished: Some(110),
            state: RunState::Partial,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![SourceStatus {
                id: "fixture".into(),
                state: SourceState::Matched,
                retry_after: Some(30),
                detail: "ok".into(),
            }],
            findings: vec![Finding {
                group: Group::Exposure,
                confidence: Confidence::Medium,
                confidence_reason: "fixture".into(),
                severity: Severity::Info,
                observed_at: 105,
                event_at: Some(50),
                source_id: "fixture".into(),
                source_url: Some("https://example.org/x".into()),
                title: "t".into(),
                evidence: "<b>\"q\"</b>".into(),
                limitations: vec!["l".into()],
            }],
            delivery_run_id: None,
            limitations: vec!["public sources are incomplete".into()],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let r = sample();
        let text = r.to_json().to_string();
        let back = OsintReport::from_json(&Json::parse(&text).unwrap()).unwrap();
        assert_eq!(back.to_json().to_string(), text);
        assert_eq!(back.findings[0].evidence, "<b>\"q\"</b>");
    }

    #[test]
    fn json_carries_schema_version_and_kind() {
        let j = sample().to_json();
        assert_eq!(j.get("schema_version").and_then(Json::as_i64), Some(1));
        assert_eq!(j.str_field("kind"), "osint");
    }

    #[test]
    fn unknown_source_state_is_preserved_not_success() {
        let s = SourceState::parse("brand_new");
        assert_eq!(s, SourceState::Unknown("brand_new".into()));
        assert_eq!(s.as_str(), "brand_new");
        assert_ne!(s, SourceState::NoMatch);
    }

    #[test]
    fn unknown_fields_and_missing_optionals_are_tolerated() {
        let j = Json::parse(
            r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"running","extra":{"x":1}}"#,
        )
        .unwrap();
        let r = OsintReport::from_json(&j).unwrap();
        assert!(r.finished.is_none() && r.findings.is_empty() && r.sources.is_empty());
    }

    #[test]
    fn rejects_a_non_osint_document() {
        let j = Json::parse(r#"{"kind":"delivery"}"#).unwrap();
        assert!(OsintReport::from_json(&j).is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p msfe-core osint:: 2>&1 | tail -5`
Expected: compile error (module/types missing).

- [ ] **Step 3: Implement.** Create the file with this content above the test module:

```rust
//! OSINT report model: what an address-footprint investigation found, where it
//! came from, and what that evidence does not prove. Pure data and JSON; no
//! I/O. Kept apart from `delivery::Report` so exposure never reads as mail
//! health.

use crate::json::Json;

pub const SCHEMA_VERSION: i64 = 1;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

macro_rules! simple_enum {
    ($name:ident { $($var:ident => $s:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($var),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$var => $s),+ }
            }
            pub fn parse(s: &str) -> Option<$name> {
                match s { $($s => Some($name::$var),)+ _ => None }
            }
        }
    };
}

simple_enum!(Group {
    Exposure => "exposure", Profile => "profile", Reference => "reference",
    Domain => "domain", Validation => "validation", Context => "context",
});
simple_enum!(Confidence { High => "high", Medium => "medium", Low => "low", Unknown => "unknown" });
simple_enum!(Severity { Info => "info", Low => "low", Medium => "medium", High => "high" });
simple_enum!(RunState {
    Running => "running", Complete => "complete", Partial => "partial",
    Cancelled => "cancelled", Failed => "failed",
});

/// Outcome of one source. Unknown strings are kept verbatim and never count as
/// success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceState {
    Matched,
    NoMatch,
    Inconclusive,
    Restricted,
    NotConfigured,
    NotRequested,
    RateLimited,
    Failed,
    Unknown(String),
}

impl SourceState {
    pub fn as_str(&self) -> &str {
        match self {
            SourceState::Matched => "matched",
            SourceState::NoMatch => "no_match",
            SourceState::Inconclusive => "inconclusive",
            SourceState::Restricted => "restricted",
            SourceState::NotConfigured => "not_configured",
            SourceState::NotRequested => "not_requested",
            SourceState::RateLimited => "rate_limited",
            SourceState::Failed => "failed",
            SourceState::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> SourceState {
        match s {
            "matched" => SourceState::Matched,
            "no_match" => SourceState::NoMatch,
            "inconclusive" => SourceState::Inconclusive,
            "restricted" => SourceState::Restricted,
            "not_configured" => SourceState::NotConfigured,
            "not_requested" => SourceState::NotRequested,
            "rate_limited" => SourceState::RateLimited,
            "failed" => SourceState::Failed,
            other => SourceState::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub group: Group,
    pub confidence: Confidence,
    pub confidence_reason: String,
    pub severity: Severity,
    /// When MSFE-NG retrieved the evidence.
    pub observed_at: u64,
    /// When the source says the event happened, if known.
    pub event_at: Option<u64>,
    pub source_id: String,
    pub source_url: Option<String>,
    pub title: String,
    pub evidence: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SourceStatus {
    pub id: String,
    pub state: SourceState,
    pub retry_after: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct OsintReport {
    pub run_id: String,
    pub address: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub state: RunState,
    pub cached: bool,
    pub planned: Vec<String>,
    pub sources: Vec<SourceStatus>,
    pub findings: Vec<Finding>,
    pub delivery_run_id: Option<String>,
    pub limitations: Vec<String>,
}

fn opt_u64(v: Option<u64>) -> Json {
    v.map(|n| Json::Int(n as i64)).unwrap_or(Json::Null)
}
fn opt_str(v: &Option<String>) -> Json {
    v.as_ref().map(Json::str).unwrap_or(Json::Null)
}
fn strs(v: &[String]) -> Json {
    Json::Array(v.iter().map(Json::str).collect())
}
fn str_list(j: Option<&Json>) -> Vec<String> {
    j.and_then(Json::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

impl Finding {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("group".into(), Json::str(self.group.as_str())),
            ("confidence".into(), Json::str(self.confidence.as_str())),
            ("confidence_reason".into(), Json::str(&self.confidence_reason)),
            ("severity".into(), Json::str(self.severity.as_str())),
            ("observed_at".into(), Json::Int(self.observed_at as i64)),
            ("event_at".into(), opt_u64(self.event_at)),
            ("source_id".into(), Json::str(&self.source_id)),
            ("source_url".into(), opt_str(&self.source_url)),
            ("title".into(), Json::str(&self.title)),
            ("evidence".into(), Json::str(&self.evidence)),
            ("limitations".into(), strs(&self.limitations)),
        ])
    }
    fn from_json(j: &Json) -> Option<Finding> {
        Some(Finding {
            group: Group::parse(&j.str_field("group"))?,
            confidence: Confidence::parse(&j.str_field("confidence")).unwrap_or(Confidence::Unknown),
            confidence_reason: j.str_field("confidence_reason"),
            severity: Severity::parse(&j.str_field("severity")).unwrap_or(Severity::Info),
            observed_at: j.get("observed_at").and_then(Json::as_i64).unwrap_or(0) as u64,
            event_at: j.get("event_at").and_then(Json::as_i64).map(|n| n as u64),
            source_id: j.str_field("source_id"),
            source_url: j.get("source_url").and_then(Json::as_str).map(String::from),
            title: j.str_field("title"),
            evidence: j.str_field("evidence"),
            limitations: str_list(j.get("limitations")),
        })
    }
}

impl SourceStatus {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::str(&self.id)),
            ("state".into(), Json::str(self.state.as_str())),
            ("retry_after".into(), opt_u64(self.retry_after)),
            ("detail".into(), Json::str(&self.detail)),
        ])
    }
    fn from_json(j: &Json) -> SourceStatus {
        SourceStatus {
            id: j.str_field("id"),
            state: SourceState::parse(&j.str_field("state")),
            retry_after: j.get("retry_after").and_then(Json::as_i64).map(|n| n as u64),
            detail: j.str_field("detail"),
        }
    }
}

impl OsintReport {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("schema_version".into(), Json::Int(SCHEMA_VERSION)),
            ("kind".into(), Json::str("osint")),
            ("run_id".into(), Json::str(&self.run_id)),
            ("address".into(), Json::str(&self.address)),
            ("started".into(), Json::Int(self.started as i64)),
            ("finished".into(), opt_u64(self.finished)),
            ("state".into(), Json::str(self.state.as_str())),
            ("cached".into(), Json::Bool(self.cached)),
            ("planned".into(), strs(&self.planned)),
            (
                "sources".into(),
                Json::Array(self.sources.iter().map(SourceStatus::to_json).collect()),
            ),
            (
                "findings".into(),
                Json::Array(self.findings.iter().map(Finding::to_json).collect()),
            ),
            ("delivery_run_id".into(), opt_str(&self.delivery_run_id)),
            ("limitations".into(), strs(&self.limitations)),
        ])
    }

    pub fn from_json(j: &Json) -> Result<OsintReport, String> {
        if j.str_field("kind") != "osint" {
            return Err("not an OSINT report".into());
        }
        Ok(OsintReport {
            run_id: j.str_field("run_id"),
            address: j.str_field("address"),
            started: j.get("started").and_then(Json::as_i64).unwrap_or(0) as u64,
            finished: j.get("finished").and_then(Json::as_i64).map(|n| n as u64),
            state: RunState::parse(&j.str_field("state")).unwrap_or(RunState::Failed),
            cached: matches!(j.get("cached"), Some(Json::Bool(true))),
            planned: str_list(j.get("planned")),
            sources: j
                .get("sources")
                .and_then(Json::as_array)
                .map(|a| a.iter().map(SourceStatus::from_json).collect())
                .unwrap_or_default(),
            findings: j
                .get("findings")
                .and_then(Json::as_array)
                .map(|a| a.iter().filter_map(Finding::from_json).collect())
                .unwrap_or_default(),
            delivery_run_id: j
                .get("delivery_run_id")
                .and_then(Json::as_str)
                .map(String::from),
            limitations: str_list(j.get("limitations")),
        })
    }
}
```

Add `pub mod osint;` to `lib.rs`.

- [ ] **Step 4: Run tests**

Run: `cargo test -p msfe-core osint:: 2>&1 | tail -8`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p msfe-core --all-targets -- -D warnings
git add crates/msfe-core/src/osint.rs crates/msfe-core/src/lib.rs
git commit -m "OSINT: report model and JSON (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Config settings and run controller (`osintrun.rs`)

**Files:**
- Modify: `crates/msfe-core/src/config.rs` (struct ~l.47, `Default` ~l.173, parser ~l.297, `to_public_json` ~l.401)
- Create: `crates/msfe-core/src/osintrun.rs`
- Modify: `crates/msfe-core/src/lib.rs` (`pub mod osintrun;`)

**Interfaces:**
- Consumes: `osint::*` (Task 1), `deliveryrun::new_id()`, `netguard::parse_address(&str) -> Result<(String, String), String>`.
- Produces in `osintrun`:
  - `pub struct Inputs { pub address: String, pub providers: Vec<String>, pub force: bool, pub delivery_run_id: Option<String> }`
  - `pub enum StartError { Disabled, Invalid(String), Busy(String), RateLimited(u64), TooManyRuns }`
  - `pub fn parse_inputs(address: &str, providers: &[String], force: bool, delivery_run_id: Option<&str>) -> Result<Inputs, String>`
  - `pub fn providers() -> Vec<ProviderInfo>` where `ProviderInfo { id: &'static str, name: &'static str, disclosure: &'static str }`
  - `pub fn start(cfg: &Config, inputs: Inputs) -> Result<StartOk, StartError>` where `pub enum StartOk { Started(String), Cached(String) }`
  - `pub fn snapshot(id: &str) -> Option<OsintReport>`, `pub fn cancel(id: &str) -> bool`, `pub fn recent(n: usize) -> Vec<OsintReport>`, `pub fn remove(id: &str) -> bool`, `pub fn sweep(max_age_secs: u64)`, `pub fn report_dir() -> PathBuf`, `pub fn valid_id(&str) -> bool`.
  - Config fields: `osint_enabled: bool`, `osint_runs_per_min: u32`, `osint_max_concurrent: u32`, `osint_deadline_secs: u64`, `osint_max_external_queries: u32`, `osint_cache_secs: u64`, `osint_retention_hours: u64`.

The fixture provider (id `fixture`) is listed only when env `MSFE_NG_OSINT_FIXTURE` is set. Behavior by local part: contains `breach` → one Exposure finding, source `matched`; contains `slow` → sleeps in 50 ms steps up to 2 s, returning early (source `inconclusive`) if cancelled; contains `fail` → source `failed`; otherwise `no_match`.

- [ ] **Step 1: Config fields.** Add to the struct (next to `delivery_cache_secs`):

```rust
    /// OSINT view (Delivery → OSINT). Off until the operator enables it.
    pub osint_enabled: bool,
    pub osint_runs_per_min: u32,
    pub osint_max_concurrent: u32,
    pub osint_deadline_secs: u64,
    pub osint_max_external_queries: u32,
    pub osint_cache_secs: u64,
    pub osint_retention_hours: u64,
```

`Default`: `osint_enabled: false, osint_runs_per_min: 3, osint_max_concurrent: 2, osint_deadline_secs: 30, osint_max_external_queries: 5, osint_cache_secs: 3600, osint_retention_hours: 24,`

Parser arms (match the existing style, e.g. next to `delivery_cache_secs`):

```rust
                "osint_enabled" => c.osint_enabled = truthy(&v),
                "osint_runs_per_min" => c.osint_runs_per_min = v.parse().unwrap_or(3).clamp(1, 30),
                "osint_max_concurrent" => c.osint_max_concurrent = v.parse().unwrap_or(2).clamp(1, 8),
                "osint_deadline_secs" => c.osint_deadline_secs = v.parse().unwrap_or(30).clamp(5, 120),
                "osint_max_external_queries" => {
                    c.osint_max_external_queries = v.parse().unwrap_or(5).clamp(1, 20)
                }
                "osint_cache_secs" => c.osint_cache_secs = v.parse().unwrap_or(3600),
                "osint_retention_hours" => c.osint_retention_hours = v.parse().unwrap_or(24).clamp(1, 720),
```

`to_public_json`: add `("osint_enabled".into(), Json::Bool(self.osint_enabled))` and an `Int` entry for each of the other six. Add a config test next to the existing ones:

```rust
    #[test]
    fn osint_defaults_and_clamps() {
        let d = Config::default();
        assert!(!d.osint_enabled);
        assert_eq!((d.osint_runs_per_min, d.osint_max_concurrent), (3, 2));
        let text = "osint_enabled = true\nosint_runs_per_min = 999\nosint_deadline_secs = 1\n";
        let dir = std::env::temp_dir().join(format!("msfe-osint-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        std::fs::write(&p, text).unwrap();
        let c = Config::load(&p);
        assert!(c.osint_enabled);
        assert_eq!(c.osint_runs_per_min, 30);
        assert_eq!(c.osint_deadline_secs, 5);
    }
```

(If `Config::load` takes a different argument type than `&Path`, mirror the existing config tests in that file.)

- [ ] **Step 2: Write the failing controller tests.** At the bottom of `osintrun.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;
    use std::time::{Duration, Instant};

    static INIT: Once = Once::new();
    fn setup() -> Config {
        INIT.call_once(|| {
            let d = std::env::temp_dir().join(format!("msfe-osint-test-{}", std::process::id()));
            std::env::set_var("MSFE_NG_OSINT_DIR", &d);
            std::env::set_var("MSFE_NG_OSINT_FIXTURE", "1");
        });
        let mut c = Config::default();
        c.osint_enabled = true;
        c.osint_runs_per_min = 30;
        c.osint_max_concurrent = 8;
        c
    }
    fn inp(addr: &str, force: bool) -> Inputs {
        parse_inputs(addr, &["fixture".to_string()], force, None).unwrap()
    }
    fn wait_done(id: &str) -> OsintReport {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let r = snapshot(id).expect("run exists");
            if r.state != RunState::Running || Instant::now() > end {
                return r;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn rejects_bad_addresses_and_unknown_providers() {
        let _ = setup();
        let p = vec!["fixture".to_string()];
        assert!(parse_inputs("no-at-sign", &p, false, None).is_err());
        assert!(parse_inputs("a b@example.org", &p, false, None).is_err());
        assert!(parse_inputs("a@example.org", &["nope".to_string()], false, None).is_err());
        assert!(parse_inputs("a@example.org", &[], false, None).is_err());
    }

    #[test]
    fn disabled_refuses_to_start() {
        let mut c = setup();
        c.osint_enabled = false;
        assert_eq!(start(&c, inp("off@example.org", false)).unwrap_err(), StartError::Disabled);
    }

    #[test]
    fn breach_fixture_produces_a_finding_and_completes() {
        let c = setup();
        let id = match start(&c, inp("breach.one@example.org", true)).unwrap() {
            StartOk::Started(id) => id,
            StartOk::Cached(_) => panic!("forced run must not be cached"),
        };
        let r = wait_done(&id);
        assert_eq!(r.state, RunState::Complete);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.sources[0].state, SourceState::Matched);
        assert!(r.finished.is_some());
    }

    #[test]
    fn no_match_is_not_a_clean_bill_of_health() {
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.one@example.org", true)).unwrap() else { panic!() };
        let r = wait_done(&id);
        assert_eq!(r.sources[0].state, SourceState::NoMatch);
        assert!(r.findings.is_empty());
        assert!(!r.limitations.is_empty(), "every report states its limits");
    }

    #[test]
    fn failed_source_makes_the_run_partial() {
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("fail.one@example.org", true)).unwrap() else { panic!() };
        assert_eq!(wait_done(&id).state, RunState::Partial);
    }

    #[test]
    fn second_run_for_a_running_address_is_busy() {
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("slow.busy@example.org", true)).unwrap() else { panic!() };
        match start(&c, inp("slow.busy@example.org", true)) {
            Err(StartError::Busy(b)) => assert_eq!(b, id),
            other => panic!("expected Busy, got {other:?}"),
        }
        cancel(&id);
        wait_done(&id);
    }

    #[test]
    fn cancelled_run_is_never_complete() {
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("slow.cancel@example.org", true)).unwrap() else { panic!() };
        assert!(cancel(&id));
        let r = wait_done(&id);
        assert_eq!(r.state, RunState::Cancelled);
    }

    #[test]
    fn finished_run_is_served_from_cache_unless_forced() {
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.cache@example.org", true)).unwrap() else { panic!() };
        wait_done(&id);
        match start(&c, inp("quiet.cache@example.org", false)).unwrap() {
            StartOk::Cached(cid) => assert_eq!(cid, id),
            other => panic!("expected cache hit, got {other:?}"),
        }
        assert!(matches!(
            start(&c, inp("quiet.cache@example.org", true)).unwrap(),
            StartOk::Started(_)
        ));
    }

    #[test]
    fn address_case_is_preserved_in_the_cache_key() {
        let c = setup();
        let StartOk::Started(a) = start(&c, inp("Quiet.Case@example.org", true)).unwrap() else { panic!() };
        wait_done(&a);
        // Different local-part case is a different subject: not a cache hit.
        assert!(matches!(
            start(&c, inp("quiet.case@example.org", false)).unwrap(),
            StartOk::Started(_)
        ));
    }

    #[test]
    fn concurrency_ceiling_returns_too_many_runs() {
        let mut c = setup();
        c.osint_max_concurrent = 1;
        let StartOk::Started(id) = start(&c, inp("slow.limit1@example.org", true)).unwrap() else { panic!() };
        let r = start(&c, inp("slow.limit2@example.org", true));
        assert_eq!(r.unwrap_err(), StartError::TooManyRuns);
        cancel(&id);
        wait_done(&id);
    }

    #[test]
    fn rate_limit_applies() {
        let mut c = setup();
        c.osint_runs_per_min = 1;
        // Use a fresh window: drain previous starts by waiting is impractical,
        // so this asserts the error shape when the window is full.
        let first = start(&c, inp("quiet.rate1@example.org", true));
        let second = start(&c, inp("quiet.rate2@example.org", true));
        assert!(matches!(first, Ok(_) | Err(StartError::RateLimited(_))));
        assert!(matches!(second, Err(StartError::RateLimited(s)) if s >= 1));
    }

    #[test]
    fn ids_are_validated_before_touching_disk() {
        let _ = setup();
        assert!(valid_id("0123456789abcdef"));
        for bad in ["", "../etc/passwd", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0"] {
            assert!(!valid_id(bad), "{bad}");
            assert!(snapshot(bad).is_none());
            assert!(!remove(bad));
        }
    }

    #[test]
    fn finished_report_is_persisted_0600_and_removal_deletes_it() {
        use std::os::unix::fs::PermissionsExt;
        let c = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.persist@example.org", true)).unwrap() else { panic!() };
        wait_done(&id);
        let f = report_dir().join(format!("{id}.json"));
        let end = Instant::now() + Duration::from_secs(5);
        while !f.exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mode = std::fs::metadata(&f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(remove(&id));
        assert!(!f.exists());
        assert!(snapshot(&id).is_none());
    }

    #[test]
    fn sweep_deletes_old_files_only() {
        let _ = setup();
        let d = report_dir();
        std::fs::create_dir_all(&d).unwrap();
        let old = d.join("aaaaaaaaaaaaaaaa.json");
        std::fs::write(&old, "{}").unwrap();
        sweep(0); // everything older than 0 s
        assert!(!old.exists());
        let other = d.join("notes.txt");
        std::fs::write(&other, "x").unwrap();
        sweep(0);
        assert!(other.exists(), "only <16hex>.json files are ours to delete");
        let _ = std::fs::remove_file(other);
    }
}
```

- [ ] **Step 3: Run to verify failure**

Run: `cargo test -p msfe-core osintrun:: 2>&1 | tail -5`
Expected: compile failure (module missing).

- [ ] **Step 4: Implement `osintrun.rs`.** Create above the test module:

```rust
//! OSINT run controller: independent of the Delivery registry. `start()` only
//! validates, reserves capacity, registers the run and spawns a worker, so the
//! daemon's write lock is never held across provider work. Finished reports
//! are persisted as root-only files under an opaque id; no path is ever built
//! from the address.

use crate::config::Config;
use crate::netguard;
use crate::osint::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EVICT_AFTER: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone)]
pub struct Inputs {
    pub address: String,
    pub providers: Vec<String>,
    pub force: bool,
    pub delivery_run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    Disabled,
    Invalid(String),
    /// A run for this address is in progress (its id).
    Busy(String),
    RateLimited(u64),
    TooManyRuns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOk {
    Started(String),
    Cached(String),
}

pub struct ProviderInfo {
    pub id: &'static str,
    pub name: &'static str,
    /// What the source receives, shown to the operator before a run.
    pub disclosure: &'static str,
}

pub fn providers() -> Vec<ProviderInfo> {
    let mut v = Vec::new();
    if fixture_enabled() {
        v.push(ProviderInfo {
            id: "fixture",
            name: "Fixture (synthetic, no network)",
            disclosure: "Nothing leaves this server.",
        });
    }
    v
}

fn fixture_enabled() -> bool {
    std::env::var_os("MSFE_NG_OSINT_FIXTURE").is_some()
}

pub fn report_dir() -> PathBuf {
    std::env::var("MSFE_NG_OSINT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/cache/msfe-ng/osint"))
}

/// A run id is exactly 16 lowercase hex characters; anything else never
/// reaches the filesystem.
pub fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn parse_inputs(
    address: &str,
    providers_req: &[String],
    force: bool,
    delivery_run_id: Option<&str>,
) -> Result<Inputs, String> {
    let address = address.trim();
    // Reuse the Delivery parser for consistent MVP behavior; it is an ASCII
    // subset and not a complete RFC mailbox parser.
    let (local, domain) = netguard::parse_address(address)?;
    let known: Vec<&str> = providers().iter().map(|p| p.id).collect();
    if providers_req.is_empty() {
        return Err("choose at least one source".into());
    }
    let mut chosen: Vec<String> = Vec::new();
    for p in providers_req {
        if !known.contains(&p.as_str()) {
            return Err(format!("unknown or unavailable source '{p}'"));
        }
        if !chosen.contains(p) {
            chosen.push(p.clone());
        }
    }
    let delivery_run_id = match delivery_run_id.map(str::trim).filter(|s| !s.is_empty()) {
        Some(d) if crate::deliveryrun::snapshot(d).is_some() => Some(d.to_string()),
        Some(_) => return Err("that Delivery run does not exist (it may have expired)".into()),
        None => None,
    };
    Ok(Inputs {
        address: format!("{local}@{domain}"),
        providers: chosen,
        force,
        delivery_run_id,
    })
}

// ---- registry ----------------------------------------------------------------

struct RunState_ {
    report: OsintReport,
    key: String,
    finished_at: Option<Instant>,
    cancel: Arc<AtomicBool>,
}

static RUNS: Mutex<Option<HashMap<String, RunState_>>> = Mutex::new(None);
static STARTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
/// Ids removed while a worker may still be running: a late worker must not
/// recreate the run or its file.
static TOMBS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn with_runs<T>(f: impl FnOnce(&mut HashMap<String, RunState_>) -> T) -> T {
    let mut g = RUNS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

fn tombstoned(id: &str) -> bool {
    TOMBS.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|t| t == id)
}

/// Cache identity: exact subject representation, sorted sources, schema
/// version. Kept in memory only; never persisted or used as a credential.
fn cache_key(i: &Inputs) -> String {
    let mut p = i.providers.clone();
    p.sort();
    format!("v{SCHEMA_VERSION}|{}|{}", i.address, p.join(","))
}

pub fn start(cfg: &Config, inputs: Inputs) -> Result<StartOk, StartError> {
    if !cfg.osint_enabled {
        return Err(StartError::Disabled);
    }
    sweep_memory();
    let key = cache_key(&inputs);
    if !inputs.force {
        let hit = with_runs(|runs| {
            runs.values()
                .filter(|s| s.key == key && s.report.state == RunState::Complete)
                .filter(|s| {
                    s.finished_at
                        .map(|t| t.elapsed() < Duration::from_secs(cfg.osint_cache_secs))
                        .unwrap_or(false)
                })
                .map(|s| s.report.run_id.clone())
                .next()
        });
        if let Some(id) = hit {
            return Ok(StartOk::Cached(id));
        }
    }
    // Busy and concurrency are checked together with registration so two
    // simultaneous starts cannot both pass.
    let id = crate::deliveryrun::new_id();
    let cancel = Arc::new(AtomicBool::new(false));
    let max_conc = cfg.osint_max_concurrent.max(1) as usize;
    let rejected = with_runs(|runs| {
        if let Some(s) = runs
            .values()
            .find(|s| s.report.state == RunState::Running && s.report.address == inputs.address)
        {
            return Some(StartError::Busy(s.report.run_id.clone()));
        }
        if runs.values().filter(|s| s.report.state == RunState::Running).count() >= max_conc {
            return Some(StartError::TooManyRuns);
        }
        None
    });
    if let Some(e) = rejected {
        return Err(e);
    }
    {
        let per_min = cfg.osint_runs_per_min.max(1) as usize;
        let mut g = STARTS.lock().unwrap_or_else(|e| e.into_inner());
        let cutoff = Instant::now() - Duration::from_secs(60);
        g.retain(|t| *t > cutoff);
        if g.len() >= per_min {
            let oldest = g.iter().min().copied().unwrap_or_else(Instant::now);
            let retry = 60u64.saturating_sub(oldest.elapsed().as_secs()).max(1);
            return Err(StartError::RateLimited(retry));
        }
        g.push(Instant::now());
    }
    let report = OsintReport {
        run_id: id.clone(),
        address: inputs.address.clone(),
        started: now_secs(),
        finished: None,
        state: RunState::Running,
        cached: false,
        planned: inputs.providers.clone(),
        sources: Vec::new(),
        findings: Vec::new(),
        delivery_run_id: inputs.delivery_run_id.clone(),
        limitations: vec![
            "Public sources are incomplete: no match does not mean the address is unexposed or safe."
                .into(),
            "Breach and profile data describe what a source indexed, not who controls the mailbox today."
                .into(),
        ],
    };
    // Re-check Busy under the same lock as the insert.
    let busy = with_runs(|runs| {
        if let Some(s) = runs
            .values()
            .find(|s| s.report.state == RunState::Running && s.report.address == inputs.address)
        {
            return Some(s.report.run_id.clone());
        }
        runs.insert(
            id.clone(),
            RunState_ { report, key, finished_at: None, cancel: cancel.clone() },
        );
        None
    });
    if let Some(b) = busy {
        return Err(StartError::Busy(b));
    }
    let deadline = Instant::now() + Duration::from_secs(cfg.osint_deadline_secs);
    let max_q = cfg.osint_max_external_queries.max(1) as usize;
    let id2 = id.clone();
    std::thread::spawn(move || worker(id2, inputs, cancel, deadline, max_q));
    Ok(StartOk::Started(id))
}

struct QueryCtx<'a> {
    address: &'a str,
    cancel: &'a AtomicBool,
    deadline: Instant,
}
impl QueryCtx<'_> {
    fn stop(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

struct Outcome {
    source: SourceStatus,
    findings: Vec<Finding>,
}

fn run_provider(id: &str, q: &QueryCtx) -> Outcome {
    match id {
        "fixture" => fixture(q),
        other => Outcome {
            source: SourceStatus {
                id: other.to_string(),
                state: SourceState::Failed,
                retry_after: None,
                detail: "no such provider".into(),
            },
            findings: Vec::new(),
        },
    }
}

fn fixture(q: &QueryCtx) -> Outcome {
    let local = q.address.split('@').next().unwrap_or("").to_ascii_lowercase();
    let status = |state, detail: &str| SourceStatus {
        id: "fixture".into(),
        state,
        retry_after: None,
        detail: detail.into(),
    };
    if local.contains("slow") {
        for _ in 0..40 {
            if q.stop() {
                return Outcome { source: status(SourceState::Inconclusive, "stopped before finishing"), findings: vec![] };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if local.contains("fail") {
        return Outcome { source: status(SourceState::Failed, "synthetic failure"), findings: vec![] };
    }
    if local.contains("breach") {
        let f = Finding {
            group: Group::Exposure,
            confidence: Confidence::Medium,
            confidence_reason: "synthetic fixture".into(),
            severity: Severity::Info,
            observed_at: now_secs(),
            event_at: Some(1_500_000_000),
            source_id: "fixture".into(),
            source_url: Some("https://example.org/fixture".into()),
            title: "Appears in a synthetic incident".into(),
            evidence: "Incident-wide data classes: Email addresses, Passwords. This does not show that a password for this address was exposed.".into(),
            limitations: vec!["Historical incident; synthetic data.".into()],
        };
        return Outcome { source: status(SourceState::Matched, "1 incident"), findings: vec![f] };
    }
    Outcome { source: status(SourceState::NoMatch, "nothing found in this source"), findings: vec![] }
}

fn worker(id: String, inputs: Inputs, cancel: Arc<AtomicBool>, deadline: Instant, max_q: usize) {
    let mut sources = Vec::new();
    let mut findings = Vec::new();
    let mut ran = 0usize;
    for p in &inputs.providers {
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
            break;
        }
        if ran >= max_q {
            sources.push(SourceStatus {
                id: p.clone(),
                state: SourceState::NotRequested,
                retry_after: None,
                detail: "skipped: external query limit for this run reached".into(),
            });
            continue;
        }
        ran += 1;
        let q = QueryCtx { address: &inputs.address, cancel: &cancel, deadline };
        let o = run_provider(p, &q);
        sources.push(o.source);
        findings.extend(o.findings);
        with_runs(|runs| {
            if let Some(s) = runs.get_mut(&id) {
                s.report.sources = sources.clone();
                s.report.findings = findings.clone();
            }
        });
    }
    let cancelled = cancel.load(Ordering::Relaxed);
    // Sources never started are recorded as such, so the report stays honest.
    for p in &inputs.providers {
        if !sources.iter().any(|s| &s.id == p) {
            sources.push(SourceStatus {
                id: p.clone(),
                state: SourceState::NotRequested,
                retry_after: None,
                detail: if cancelled { "run cancelled before this source".into() } else { "run time limit reached before this source".into() },
            });
        }
    }
    let all_terminal_ok = sources
        .iter()
        .all(|s| matches!(s.state, SourceState::Matched | SourceState::NoMatch));
    let state = if cancelled {
        RunState::Cancelled
    } else if all_terminal_ok {
        RunState::Complete
    } else {
        RunState::Partial
    };
    let report = with_runs(|runs| {
        let s = runs.get_mut(&id)?;
        s.report.sources = sources;
        s.report.findings = findings;
        s.report.state = state;
        s.report.finished = Some(now_secs());
        s.finished_at = Some(Instant::now());
        Some(s.report.clone())
    });
    if let Some(r) = report {
        if !tombstoned(&id) {
            let _ = persist(&r);
        }
    }
}

// ---- persistence -------------------------------------------------------------

fn persist(r: &OsintReport) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    if !valid_id(&r.run_id) {
        return Err(std::io::Error::other("bad run id"));
    }
    let dir = report_dir();
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let tmp = dir.join(format!("{}.tmp", r.run_id));
    let fin = dir.join(format!("{}.json", r.run_id));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(r.to_json().to_string().as_bytes())?;
    }
    std::fs::rename(&tmp, &fin)
}

fn load(id: &str) -> Option<OsintReport> {
    if !valid_id(id) {
        return None;
    }
    let p = report_dir().join(format!("{id}.json"));
    let md = std::fs::symlink_metadata(&p).ok()?;
    if !md.is_file() {
        return None; // symlinks and anything unusual are refused
    }
    let text = std::fs::read_to_string(&p).ok()?;
    OsintReport::from_json(&crate::json::Json::parse(&text).ok()?).ok()
}

pub fn snapshot(id: &str) -> Option<OsintReport> {
    if !valid_id(id) {
        return None;
    }
    if tombstoned(id) {
        return None;
    }
    with_runs(|runs| runs.get(id).map(|s| s.report.clone())).or_else(|| load(id))
}

pub fn cancel(id: &str) -> bool {
    with_runs(|runs| match runs.get(id) {
        Some(s) if s.report.state == RunState::Running => {
            s.cancel.store(true, Ordering::Relaxed);
            true
        }
        _ => false,
    })
}

pub fn recent(n: usize) -> Vec<OsintReport> {
    let mut v: Vec<OsintReport> = with_runs(|runs| runs.values().map(|s| s.report.clone()).collect());
    if let Ok(rd) = std::fs::read_dir(report_dir()) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                if !v.iter().any(|r| r.run_id == id) {
                    if let Some(r) = load(id) {
                        v.push(r);
                    }
                }
            }
        }
    }
    v.sort_by(|a, b| b.started.cmp(&a.started));
    v.truncate(n);
    v
}

/// Delete a run and its file, cancelling pending work so it cannot come back.
pub fn remove(id: &str) -> bool {
    if !valid_id(id) {
        return false;
    }
    TOMBS.lock().unwrap_or_else(|e| e.into_inner()).push(id.to_string());
    let had_mem = with_runs(|runs| match runs.remove(id) {
        Some(s) => {
            s.cancel.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    });
    let p = report_dir().join(format!("{id}.json"));
    let had_file = std::fs::remove_file(&p).is_ok();
    // A worker that finished between the removal above and its persist call is
    // covered by the tombstone check in `worker`.
    let _ = std::fs::remove_file(report_dir().join(format!("{id}.tmp")));
    had_mem || had_file
}

fn sweep_memory() {
    with_runs(|runs| {
        runs.retain(|_, s| s.finished_at.map(|t| t.elapsed() < EVICT_AFTER).unwrap_or(true));
    });
}

/// Delete `<16hex>.json` files older than `max_age_secs`. Other files in the
/// directory are never touched.
pub fn sweep(max_age_secs: u64) {
    let Ok(rd) = std::fs::read_dir(report_dir()) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_suffix(".json") else { continue };
        if !valid_id(id) {
            continue;
        }
        let age = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if age >= max_age_secs {
            let _ = std::fs::remove_file(e.path());
        }
    }
}
```

Add `pub mod osintrun;` to `lib.rs`. If `deliveryrun::snapshot` has a different signature than `fn(&str) -> Option<Report>`, adapt the one call in `parse_inputs` only. Rename the private struct `RunState_` to `Slot` if clippy objects to the underscore name.

The `rate_limit_applies` test depends on the process-global start window shared by other tests; if it proves flaky, replace it with a unit test of an extracted `fn admit(window: &mut Vec<Instant>, per_min: usize, now: Instant) -> Result<(), u64>` (extract it in this step and have `start()` call it).

- [ ] **Step 5: Run tests**

Run: `cargo test -p msfe-core osint 2>&1 | tail -20`
Expected: all pass. Run twice to check for flakiness: `cargo test -p msfe-core osintrun:: -- --test-threads=8`.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all && cargo clippy -p msfe-core --all-targets -- -D warnings
git add crates/msfe-core/src/osintrun.rs crates/msfe-core/src/lib.rs crates/msfe-core/src/config.rs
git commit -m "OSINT: run controller with fixture provider and osint_* settings (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: HTML export (`osinthtml.rs`)

**Files:**
- Create: `crates/msfe-core/src/osinthtml.rs`
- Modify: `crates/msfe-core/src/lib.rs` (`pub mod osinthtml;`)

**Interfaces:**
- Consumes: `OsintReport`, `deliveryhtml::escape(&str) -> String` (already `pub`).
- Produces: `pub fn render(r: &OsintReport) -> String`; `pub fn safe_url(u: &str) -> bool` (true only for `http://` and `https://`).

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::*;

    fn rep(evidence: &str, url: Option<&str>) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "a<b>@example.org".into(),
            started: 1,
            finished: Some(2),
            state: RunState::Complete,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![SourceStatus { id: "fixture".into(), state: SourceState::NoMatch, retry_after: None, detail: "d".into() }],
            findings: vec![Finding {
                group: Group::Exposure, confidence: Confidence::Low, confidence_reason: "r".into(),
                severity: Severity::Info, observed_at: 1, event_at: None, source_id: "fixture".into(),
                source_url: url.map(String::from), title: "T".into(), evidence: evidence.into(), limitations: vec![],
            }],
            delivery_run_id: None,
            limitations: vec!["l".into()],
        }
    }

    #[test]
    fn evidence_and_address_are_escaped() {
        let h = render(&rep("<script>alert(1)</script>\"'", None));
        assert!(!h.contains("<script>alert"));
        assert!(h.contains("&lt;script&gt;"));
        assert!(h.contains("a&lt;b&gt;@example.org"));
    }

    #[test]
    fn only_http_urls_become_links() {
        assert!(safe_url("https://example.org/x"));
        assert!(safe_url("http://example.org"));
        for bad in ["javascript:alert(1)", "data:text/html,x", "//evil", "", "ftp://x", " https://x"] {
            assert!(!safe_url(bad), "{bad}");
        }
        let h = render(&rep("e", Some("javascript:alert(1)")));
        assert!(!h.contains("href=\"javascript:"));
    }

    #[test]
    fn non_matching_sources_stay_visible() {
        let h = render(&rep("e", None));
        assert!(h.contains("no_match"));
        assert!(h.contains("does not"), "limitations are printed");
    }
}
```

- [ ] **Step 2: Run to verify failure:** `cargo test -p msfe-core osinthtml:: 2>&1 | tail -3` → compile error.

- [ ] **Step 3: Implement**

```rust
//! Self-contained HTML export of an OSINT report. Every value is escaped; only
//! http(s) URLs become links.

use crate::deliveryhtml::escape;
use crate::osint::OsintReport;

pub fn safe_url(u: &str) -> bool {
    u.starts_with("https://") || u.starts_with("http://")
}

pub fn render(r: &OsintReport) -> String {
    let mut h = String::new();
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>OSINT report — ");
    h.push_str(&escape(&r.address));
    h.push_str("</title><style>body{font:14px system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}.muted{color:#666}</style></head><body>");
    h.push_str(&format!(
        "<h1>OSINT report — {}</h1><p class=\"muted\">run {} · state {} · started {} (unix)</p>",
        escape(&r.address),
        escape(&r.run_id),
        escape(r.state.as_str()),
        r.started
    ));
    h.push_str("<h2>Source coverage</h2><table><tr><th>Source</th><th>State</th><th>Detail</th></tr>");
    for s in &r.sources {
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&s.id),
            escape(s.state.as_str()),
            escape(&s.detail)
        ));
    }
    h.push_str("</table><h2>Findings</h2>");
    if r.findings.is_empty() {
        h.push_str("<p class=\"muted\">No findings. This does not mean the address is unexposed.</p>");
    }
    for f in &r.findings {
        h.push_str(&format!(
            "<h3>{}</h3><p class=\"muted\">{} · confidence {} ({}) · observed {} (unix)</p><p>{}</p>",
            escape(&f.title),
            escape(f.group.as_str()),
            escape(f.confidence.as_str()),
            escape(&f.confidence_reason),
            f.observed_at,
            escape(&f.evidence)
        ));
        if let Some(u) = &f.source_url {
            if safe_url(u) {
                h.push_str(&format!("<p><a href=\"{0}\" rel=\"noreferrer noopener\">{0}</a></p>", escape(u)));
            } else {
                h.push_str(&format!("<p class=\"muted\">{}</p>", escape(u)));
            }
        }
        for l in &f.limitations {
            h.push_str(&format!("<p class=\"muted\">Limit: {}</p>", escape(l)));
        }
    }
    h.push_str("<h2>Limitations</h2><ul>");
    for l in &r.limitations {
        h.push_str(&format!("<li>{}</li>", escape(l)));
    }
    h.push_str("</ul></body></html>");
    h
}
```

Verify `deliveryhtml::escape` also escapes `'` and `"` (it must, since `href="{0}"` relies on it); if it does not, escape `"` in the link case with `.replace('"', "&quot;")`.

- [ ] **Step 4: Run tests:** `cargo test -p msfe-core osinthtml:: 2>&1 | tail -5` → 3 passed. The limitations text from Task 2 contains "does not", satisfying the third test only because the test report has `limitations: ["l"]`; the "does not" assertion comes from the empty-findings sentence, so the fixture `rep` must keep `findings` non-empty. If the assertion fails, change the test to build a report with no findings.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy -p msfe-core --all-targets -- -D warnings
git add crates/msfe-core/src/osinthtml.rs crates/msfe-core/src/lib.rs
git commit -m "OSINT: escaped HTML export (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Daemon routes (`osint_api.rs`)

**Files:**
- Create: `crates/msfe-ngd/src/osint_api.rs`
- Modify: `crates/msfe-ngd/src/main.rs` (add `mod osint_api;` after `mod http;`), `crates/msfe-ngd/src/api.rs` (arm before the `/api/delivery/` arm at ~l.1232), `crates/msfe-ngd/src/main.rs` startup near `deliveryrun::sweep()` (~l.75): add `msfe_core::osintrun::sweep(cfg.osint_retention_hours * 3600);` using the loaded config variable in scope there.

**Interfaces:**
- Consumes: `osintrun::{start, snapshot, cancel, recent, remove, providers, parse_inputs, StartOk, StartError}`, `osinthtml::render`.
- Produces: `pub fn handle(method: &str, path: &str, req: &Request, cfg: &Config) -> Response`.

- [ ] **Step 1: Failing tests.** Follow the existing test style in `api.rs` (see tests near l.3506) for building a `Request`; place these in `osint_api.rs`. If a request builder helper exists in `api.rs` tests, copy its construction; otherwise construct `Request` the way those tests do.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Config {
        std::env::set_var("MSFE_NG_OSINT_FIXTURE", "1");
        std::env::set_var(
            "MSFE_NG_OSINT_DIR",
            std::env::temp_dir().join(format!("msfe-osint-api-{}", std::process::id())),
        );
        let mut c = Config::default();
        c.osint_enabled = true;
        c.osint_runs_per_min = 30;
        c
    }

    #[test]
    fn providers_answers_even_when_disabled() {
        let mut c = setup();
        c.osint_enabled = false;
        let r = handle("GET", "/api/delivery/osint/providers", &crate::http::Request::test("GET", "/api/delivery/osint/providers", ""), &c);
        assert_eq!(r.status, 200);
        assert!(r.body.contains("\"enabled\":false"));
        assert!(r.body.contains("fixture"));
    }

    #[test]
    fn run_is_forbidden_when_disabled() {
        let mut c = setup();
        c.osint_enabled = false;
        let body = r#"{"address":"a@example.org","providers":["fixture"]}"#;
        let r = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", body), &c);
        assert_eq!(r.status, 403);
    }

    #[test]
    fn invalid_input_is_400_and_unknown_route_is_404() {
        let c = setup();
        let bad = r#"{"address":"nope","providers":["fixture"]}"#;
        let r = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", bad), &c);
        assert_eq!(r.status, 400);
        let r = handle("GET", "/api/delivery/osint/nothing", &crate::http::Request::test("GET", "/api/delivery/osint/nothing", ""), &c);
        assert_eq!(r.status, 404);
    }

    #[test]
    fn run_poll_report_and_remove() {
        let c = setup();
        let body = r#"{"address":"breach.api@example.org","providers":["fixture"],"force":true}"#;
        let r = handle("POST", "/api/delivery/osint/run", &crate::http::Request::test("POST", "/api/delivery/osint/run", body), &c);
        assert_eq!(r.status, 201);
        let id = Json::parse(&r.body).unwrap().str_field("run_id");
        let mut done = false;
        for _ in 0..200 {
            let p = handle("GET", "/api/delivery/osint/run", &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={id}"), ""), &c);
            assert_eq!(p.status, 200);
            if Json::parse(&p.body).unwrap().str_field("state") == "complete" { done = true; break; }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(done);
        let h = handle("GET", "/api/delivery/osint/report", &crate::http::Request::test("GET", &format!("/api/delivery/osint/report?id={id}&format=html"), ""), &c);
        assert_eq!(h.status, 200);
        let rm = handle("POST", "/api/delivery/osint/remove", &crate::http::Request::test("POST", "/api/delivery/osint/remove", &format!(r#"{{"id":"{id}"}}"#)), &c);
        assert_eq!(rm.status, 200);
        let gone = handle("GET", "/api/delivery/osint/run", &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={id}"), ""), &c);
        assert_eq!(gone.status, 404);
    }

    #[test]
    fn poll_with_a_traversal_id_is_404() {
        let c = setup();
        let r = handle("GET", "/api/delivery/osint/run", &crate::http::Request::test("GET", "/api/delivery/osint/run?id=..%2Fetc%2Fpasswd", ""), &c);
        assert_eq!(r.status, 404);
    }
}
```

`Request::test(method, path_and_query, body)` may not exist. Check `http.rs` for how `Request` is built and how other daemon tests build requests; if there is no helper, add a `#[cfg(test)] impl Request { pub fn test(...) }` to `http.rs` that sets method, path, query (split at `?`), body, and defaults for remaining fields, mirroring an existing test constructor. Check also that `Response` exposes `status` and `body` to tests.

- [ ] **Step 2: Run to verify failure:** `cargo test -p msfe-ngd osint_api 2>&1 | tail -5`.

- [ ] **Step 3: Implement**

```rust
//! `/api/delivery/osint/*` (admin only, via the existing peer check): start an
//! OSINT run, poll it, cancel it, export, list, remove. Starting returns at
//! once; the run continues on its own thread and polling is a lock-free GET.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::osintrun::{self, StartError, StartOk};
use msfe_core::Config;

pub fn handle(method: &str, path: &str, req: &Request, cfg: &Config) -> Response {
    match (method, path) {
        ("GET", "/api/delivery/osint/providers") => providers(cfg),
        ("POST", "/api/delivery/osint/run") => start(req, cfg),
        ("GET", "/api/delivery/osint/run") => poll(req),
        ("POST", "/api/delivery/osint/run/cancel") => cancel(req),
        ("GET", "/api/delivery/osint/report") => report(req),
        ("GET", "/api/delivery/osint/recent") => recent(),
        ("POST", "/api/delivery/osint/remove") => remove(req),
        _ => err(404, "not found"),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn providers(cfg: &Config) -> Response {
    let list: Vec<Json> = osintrun::providers()
        .iter()
        .map(|p| {
            Json::Object(vec![
                ("id".into(), Json::str(p.id)),
                ("name".into(), Json::str(p.name)),
                ("disclosure".into(), Json::str(p.disclosure)),
                ("configured".into(), Json::Bool(true)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("enabled".into(), Json::Bool(cfg.osint_enabled)),
            ("providers".into(), Json::Array(list)),
            (
                "limits".into(),
                Json::Object(vec![
                    ("runs_per_min".into(), Json::Int(cfg.osint_runs_per_min as i64)),
                    ("max_concurrent".into(), Json::Int(cfg.osint_max_concurrent as i64)),
                    ("deadline_secs".into(), Json::Int(cfg.osint_deadline_secs as i64)),
                    ("max_external_queries".into(), Json::Int(cfg.osint_max_external_queries as i64)),
                ]),
            ),
        ])
        .to_string(),
    )
}

fn start(req: &Request, cfg: &Config) -> Response {
    if !cfg.osint_enabled {
        return err(403, "OSINT is switched off — enable it in Config first");
    }
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    let provs: Vec<String> = v
        .get("providers")
        .and_then(Json::as_array)
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let ctx = v.get("context");
    let delivery_id = ctx.and_then(|c| c.get("delivery_run_id")).and_then(Json::as_str);
    let inputs = match osintrun::parse_inputs(
        &v.str_field("address"),
        &provs,
        matches!(v.get("force"), Some(Json::Bool(true))),
        delivery_id,
    ) {
        Ok(i) => i,
        Err(e) => return err(400, &e),
    };
    match osintrun::start(cfg, inputs) {
        Ok(StartOk::Started(id)) => Response::json(
            201,
            &Json::Object(vec![("run_id".into(), Json::str(id)), ("cached".into(), Json::Bool(false))]).to_string(),
        ),
        Ok(StartOk::Cached(id)) => Response::json(
            200,
            &Json::Object(vec![("run_id".into(), Json::str(id)), ("cached".into(), Json::Bool(true))]).to_string(),
        ),
        Err(StartError::Disabled) => err(403, "OSINT is switched off"),
        Err(StartError::Invalid(e)) => err(400, &e),
        Err(StartError::Busy(id)) => Response::json(
            409,
            &Json::Object(vec![
                ("error".into(), Json::str("a lookup of this address is already running")),
                ("run_id".into(), Json::str(id)),
            ])
            .to_string(),
        ),
        Err(StartError::RateLimited(secs)) => Response::json(
            429,
            &Json::Object(vec![
                ("error".into(), Json::str(format!("too many lookups started — try again in {secs} s"))),
                ("retry_secs".into(), Json::Int(secs as i64)),
            ])
            .to_string(),
        ),
        Err(StartError::TooManyRuns) => err(429, "too many lookups are running — wait for one to finish"),
    }
}

fn poll(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    match osintrun::snapshot(&id) {
        Some(r) => Response::json(200, &r.to_json().to_string()),
        None => err(404, "no such run (the daemon may have restarted — start the lookup again)"),
    }
}

fn cancel(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    if osintrun::cancel(&v.str_field("id")) {
        Response::json(200, r#"{"ok":true}"#)
    } else {
        err(404, "no such running lookup")
    }
}

fn report(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    let Some(r) = osintrun::snapshot(&id) else {
        return err(404, "no such run");
    };
    match req.query_param("format").as_deref() {
        Some("html") => Response::html(200, &msfe_core::osinthtml::render(&r)),
        _ => Response::json(200, &r.to_json().to_string()),
    }
}

fn recent() -> Response {
    let items: Vec<Json> = osintrun::recent(20)
        .iter()
        .map(|r| {
            Json::Object(vec![
                ("run_id".into(), Json::str(&r.run_id)),
                ("address".into(), Json::str(&r.address)),
                ("state".into(), Json::str(r.state.as_str())),
                ("started".into(), Json::Int(r.started as i64)),
                ("findings".into(), Json::Int(r.findings.len() as i64)),
            ])
        })
        .collect();
    Response::json(200, &Json::Object(vec![("runs".into(), Json::Array(items))]).to_string())
}

fn remove(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    if osintrun::remove(&v.str_field("id")) {
        Response::json(200, r#"{"ok":true}"#)
    } else {
        err(404, "no such run")
    }
}
```

In `api.rs`, add before the `/api/delivery/` arm:

```rust
        (m, p) if p.starts_with("/api/delivery/osint/") => {
            crate::osint_api::handle(m, p, req, cfg)
        }
```

- [ ] **Step 4: Add an authorization test** in `api.rs` or `http.rs` test modules, following how existing tests check `peer_scope`: a non-root peer requesting `/api/delivery/osint/providers` gets 403 (the existing `peer_scope` already denies every non-`/api/user` path; this test pins that OSINT is not reachable by account users). Run it and the module tests:

Run: `cargo test -p msfe-ngd 2>&1 | tail -10`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/msfe-ngd
git commit -m "OSINT: admin-only daemon routes (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: CLI (`delivery osint`)

**Files:**
- Modify: `crates/msfe-cli/src/main.rs`: `rejected_flag` table (~l.40-110), `usage_of("delivery")` (~l.140), `cmd_delivery` (~l.2580).

**Interfaces:**
- Consumes: `osintrun::{parse_inputs, start, snapshot, providers, sweep, StartOk, StartError}`, `osinthtml::render`.
- Produces: `delivery osint <address> [--providers a,b] [--json|--html] [--force]`, `delivery osint providers [--json]`, `delivery osint sweep`. Exit codes 0/2/3/4.

Look at how `cmd_delivery_inbox` (~l.2996) parses its flags (`flag_value`-style helpers) and reuse the same helpers; the code below uses placeholder helper names `flag_val(rest, "--providers") -> Option<String>` and `has_flag(rest, "--json") -> bool`: replace them with the file's actual helpers.

- [ ] **Step 1: Failing tests.** In the CLI test module, following the existing tests for `rejected_flag`:

```rust
    #[test]
    fn delivery_osint_flags_are_accepted() {
        assert!(rejected_flag("delivery", Some("osint"), &["--providers".into(), "fixture".into()]).is_none());
        assert!(rejected_flag("delivery", Some("osint"), &["--json".into()]).is_none());
        assert!(rejected_flag("delivery", Some("osint"), &["--nonsense".into()]).is_some());
    }
```

(Adapt the call to the real `rejected_flag` signature.) Add a pure-function test for the exit-code mapping:

```rust
    #[test]
    fn osint_exit_codes() {
        use msfe_core::osint::RunState::*;
        assert_eq!(osint_exit(Complete), 0);
        assert_eq!(osint_exit(Partial), 4);
        assert_eq!(osint_exit(Cancelled), 4);
        assert_eq!(osint_exit(Failed), 3);
    }
```

- [ ] **Step 2: Run to verify failure:** `cargo test -p msfe-cli osint 2>&1 | tail -5`.

- [ ] **Step 3: Implement.** In the flag table add, before the generic `delivery` entry if one exists:

```rust
        ("delivery", Some("osint")) => Some(&["--providers", "--json", "--html", "--force"]),
```

In `cmd_delivery`, directly after the `monitor` dispatch:

```rust
    if sub == Some("osint") {
        return cmd_delivery_osint(rest);
    }
```

Add the function and the exit mapping:

```rust
fn osint_exit(s: msfe_core::osint::RunState) -> u8 {
    use msfe_core::osint::RunState::*;
    match s {
        Complete => 0,
        Partial | Cancelled => 4,
        Failed | Running => 3,
    }
}

fn cmd_delivery_osint(rest: &[String]) -> ExitCode {
    use msfe_core::osint::RunState;
    use msfe_core::osintrun::{self, StartError, StartOk};
    let cfg = Config::load(&config_path());
    if rest.first().map(String::as_str) == Some("providers") {
        for p in osintrun::providers() {
            println!("{}\t{}\t{}", p.id, p.name, p.disclosure);
        }
        return ExitCode::SUCCESS;
    }
    if rest.first().map(String::as_str) == Some("sweep") {
        osintrun::sweep(cfg.osint_retention_hours * 3600);
        return ExitCode::SUCCESS;
    }
    let Some(addr) = rest.iter().find(|a| !a.starts_with("--") && a.contains('@')) else {
        eprintln!("usage: {}", usage_of("delivery"));
        return ExitCode::from(2);
    };
    let provs: Vec<String> = flag_val(rest, "--providers")
        .map(|s| s.split(',').map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect())
        .unwrap_or_else(|| osintrun::providers().iter().map(|p| p.id.to_string()).collect());
    let inputs = match osintrun::parse_inputs(addr, &provs, has_flag(rest, "--force"), None) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("msfe-ng: {e}");
            return ExitCode::from(3);
        }
    };
    let id = match osintrun::start(&cfg, inputs) {
        Ok(StartOk::Started(id) | StartOk::Cached(id)) => id,
        Err(StartError::Disabled) => {
            eprintln!("msfe-ng: OSINT is switched off (set osint_enabled = true in config.toml)");
            return ExitCode::from(3);
        }
        Err(e) => {
            eprintln!("msfe-ng: cannot start: {e:?}");
            return ExitCode::from(3);
        }
    };
    let report = loop {
        match osintrun::snapshot(&id) {
            Some(r) if r.state != RunState::Running => break r,
            Some(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
            None => {
                eprintln!("msfe-ng: the run disappeared");
                return ExitCode::from(3);
            }
        }
    };
    if has_flag(rest, "--html") {
        println!("{}", msfe_core::osinthtml::render(&report));
    } else if has_flag(rest, "--json") {
        println!("{}", report.to_json());
    } else {
        println!("{} — {}", report.address, report.state.as_str());
        for s in &report.sources {
            println!("  source {:<10} {:<14} {}", s.id, s.state.as_str(), s.detail);
        }
        for f in &report.findings {
            println!("  [{}] {} — {}", f.group.as_str(), f.title, f.evidence);
        }
        for l in &report.limitations {
            println!("  note: {l}");
        }
    }
    ExitCode::from(osint_exit(report.state))
}
```

Update `usage_of("delivery")` text to append: `| osint <address> [--providers a,b] [--json|--html] [--force] | osint providers | osint sweep`.

Note: the CLI runs the controller in-process (like `delivery test` using `run_blocking`), so its registry is separate from the daemon's; it persists to the same report dir.

- [ ] **Step 4: Run tests:** `cargo test -p msfe-cli 2>&1 | tail -8` → pass. Then a manual smoke test:

```bash
d=$(mktemp -d) && printf 'osint_enabled = true\n' > $d/config.toml
MSFE_NG_OSINT_DIR=$d MSFE_NG_OSINT_FIXTURE=1 MSFE_NG_CONFIG=$d/config.toml cargo run -q -p msfe-cli -- delivery osint breach.x@example.org --providers fixture; echo "exit=$?"
```

Expected: a `matched` source line, one `[exposure]` finding, `exit=0`. (Use whatever env var `config_path()` honors; check it.)

- [ ] **Step 5: Commit**

```bash
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings
git add crates/msfe-cli/src/main.rs
git commit -m "OSINT: delivery osint CLI with 0/2/3/4 exit codes (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 6: WHM UI (OSINT pill, run, poll, results)

**Files:**
- Modify: `web/whm/index.html`: timers (~l.629-637), `DLV_VIEW` comment (~l.638), tab handler timer list (~l.650), `DLV_VIEWS` (~l.2897), `renderDelivery` dispatch and its timer-clear list (~l.2898-2913); add `renderOsint` and `osintFor` near `renderDmarcReports` (~l.2677).
- Build: `web/whm/app.css` only if new CSS classes are added (prefer none).

**Interfaces:**
- Consumes: `api(path,{method,body})`, `el`, `esc`, `toast`; routes from Task 4.
- Produces: `let dlvOsintTimer=null;`, `OSINT_PREFILL`, `osintFor(address, context)`, `renderOsint(v)`.

- [ ] **Step 1: Wire the view.**
  1. Add `dlvOsintTimer` to the `let` declaration list of timers (l.629-637).
  2. Update the `DLV_VIEW` comment to `test|accounts|dmarc|osint`.
  3. Add `clearInterval(dlvOsintTimer);` to the tab-click timer clearing (l.~650) and to the view-switch clearing list (l.~2904-2906).
  4. Change `DLV_VIEWS` to `[['test','Address test'],['accounts','Account DNS'],['dmarc','DMARC reports'],['osint','OSINT']]`.
  5. Change the dispatch to `({accounts:renderAcctDns,dmarc:renderDmarcReports,osint:renderOsint}[DLV_VIEW]||renderDeliveryTest)(body)`.
  6. Next to `deliveryTestFor`, add:

```js
let OSINT_PREFILL=null;
// "Investigate address": open Delivery → OSINT with the address filled in. It
// never starts a lookup; the operator picks sources and presses Run.
function osintFor(address,context){
  const a=String(address||'').trim();
  if(!a.includes('@')){toast('no address to investigate');return;}
  OSINT_PREFILL={address:a,context:context||null};
  DLV_VIEW='osint';
  document.querySelector('#tabs button[data-tab="delivery"]').click();
}
```

- [ ] **Step 2: Add `renderOsint`.** Place near `renderDmarcReports`:

```js
const OSINT_STATE_LABEL={matched:'found',no_match:'no match',inconclusive:'inconclusive',restricted:'restricted',not_configured:'not configured',not_requested:'not requested',rate_limited:'rate limited',failed:'failed'};
const OSINT_GROUPS=[['exposure','Exposure'],['profile','Public identity and avatar'],['reference','Public references'],['domain','Domain context'],['validation','Validation'],['context','Delivery context']];
async function renderOsint(v){
  clearInterval(dlvOsintTimer);dlvOsintTimer=null;
  const card=el('div',{class:'card'},el('h2',{},'OSINT — what is publicly known about an address'));
  card.append(el('div',{class:'muted',style:'font-size:.8rem;margin-bottom:.6rem'},
    'Looks up public sources for one address you choose. Nothing runs until you press Run. A source finding nothing does not mean the address is safe or unexposed, and an old breach is history, not proof of a current problem. Nothing here changes how mail is filtered or delivered.'));
  v.append(card);
  const prov=await api('/api/delivery/osint/providers');
  if(!prov||prov.error){card.append(el('div',{class:'note warn'},(prov&&prov.error)||'no response'));return;}
  if(!prov.enabled){card.append(el('div',{class:'note warn'},'OSINT is switched off. Set osint_enabled = true in config.toml (Config tab) to use it.'));}
  const pre=OSINT_PREFILL;OSINT_PREFILL=null;
  const addr=el('input',{type:'text',placeholder:'user@example.org',style:'min-width:18rem',value:pre?pre.address:''});
  const force=el('input',{type:'checkbox'});
  const runBtn=el('button',{class:'act'},'Run OSINT');
  const cancelBtn=el('button',{class:'act',style:'display:none'},'Cancel');
  runBtn.disabled=!prov.enabled;
  card.append(el('div',{class:'ctl'},addr,runBtn,cancelBtn,el('label',{class:'muted',style:'font-size:.8rem;display:flex;gap:.3rem;align-items:center'},force,' fresh lookup')));
  const boxes=[];
  const srcRow=el('div',{style:'margin:.4rem 0'});
  if(!prov.providers.length)srcRow.append(el('div',{class:'muted'},'No sources are available.'));
  prov.providers.forEach(p=>{
    const cb=el('input',{type:'checkbox',checked:'checked'});cb.dataset.id=p.id;boxes.push(cb);
    srcRow.append(el('label',{style:'display:block;font-size:.85rem'},cb,' ',el('b',{},p.name),el('span',{class:'muted'},' — '+p.disclosure)));
  });
  card.append(srcRow);
  const out=el('div',{});v.append(out);
  let curId=null;

  function paint(r){
    out.innerHTML='';
    const head=el('div',{class:'card'});
    head.append(el('h2',{},r.address+' — '+r.state));
    if(r.cached)head.append(el('div',{class:'muted'},'Showing a recent result; tick “fresh lookup” to query again.'));
    if(r.state==='cancelled')head.append(el('div',{class:'note warn'},'Cancelled — this result is incomplete.'));
    if(r.state==='partial')head.append(el('div',{class:'note warn'},'Some sources did not give an answer; see Source coverage.'));
    const acts=el('div',{class:'ctl'});
    const t=el('button',{class:'act'},'Open Address test');t.onclick=()=>deliveryTestFor(r.address);
    const j=el('a',{class:'act',href:'#'},'JSON');
    j.onclick=async e=>{e.preventDefault();const x=await api('/api/delivery/osint/report?id='+r.run_id+'&format=json',{raw:true});const b=new Blob([x],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='osint-'+r.run_id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);};
    const h=el('a',{class:'act',href:'#'},'HTML');
    h.onclick=async e=>{e.preventDefault();const x=await api('/api/delivery/osint/report?id='+r.run_id+'&format=html',{raw:true});const b=new Blob([x],{type:'text/html'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='osint-'+r.run_id+'.html';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);};
    acts.append(t,j,h);head.append(acts);
    out.append(head);
    OSINT_GROUPS.forEach(([g,title])=>{
      const fs=(r.findings||[]).filter(f=>f.group===g);
      if(!fs.length)return;
      const c=el('div',{class:'card'},el('h2',{},title));
      fs.forEach(f=>{
        const row=el('div',{style:'margin:.5rem 0'});
        row.append(el('div',{},el('b',{},f.title)));
        row.append(el('div',{},f.evidence));
        const when=f.event_at?('event '+new Date(f.event_at*1000).toLocaleDateString()+' · '):'';
        row.append(el('div',{class:'muted',style:'font-size:.78rem'},when+'source '+f.source_id+' · confidence '+f.confidence+(f.confidence_reason?' ('+f.confidence_reason+')':'')+' · retrieved '+new Date(f.observed_at*1000).toLocaleString()));
        if(f.source_url&&/^https?:\/\//.test(f.source_url)){const a=el('a',{href:f.source_url,target:'_blank',rel:'noopener noreferrer'},f.source_url);row.append(a);}
        (f.limitations||[]).forEach(l=>row.append(el('div',{class:'muted',style:'font-size:.78rem'},'Limit: '+l)));
        c.append(row);
      });
      out.append(c);
    });
    if(!(r.findings||[]).length&&r.state!=='running')out.append(el('div',{class:'card'},el('div',{class:'empty'},'No findings. That does not mean the address is unexposed.')));
    const cov=el('div',{class:'card'},el('h2',{},'Source coverage'));
    (r.sources||[]).forEach(s=>cov.append(el('div',{style:'font-size:.85rem'},el('b',{},s.id),' — '+(OSINT_STATE_LABEL[s.state]||s.state)+(s.detail?': '+s.detail:'')+(s.retry_after?' (retry after '+s.retry_after+' s)':''))));
    (r.limitations||[]).forEach(l=>cov.append(el('div',{class:'muted',style:'font-size:.78rem'},l)));
    out.append(cov);
  }
  async function poll(){
    const r=await api('/api/delivery/osint/run?id='+curId);
    if(!r||r.error){clearInterval(dlvOsintTimer);dlvOsintTimer=null;runBtn.disabled=false;cancelBtn.style.display='none';out.innerHTML='';out.append(el('div',{class:'note warn'},(r&&r.error)||'no response'));return;}
    paint(r);
    if(r.state!=='running'){clearInterval(dlvOsintTimer);dlvOsintTimer=null;runBtn.disabled=!prov.enabled;cancelBtn.style.display='none';}
  }
  runBtn.onclick=async()=>{
    const providers=boxes.filter(b=>b.checked).map(b=>b.dataset.id);
    const body={address:addr.value.trim(),providers,force:force.checked};
    if(pre&&pre.context&&pre.context.delivery_run_id&&pre.address===body.address)body.context={delivery_run_id:pre.context.delivery_run_id};
    const r=await api('/api/delivery/osint/run',{method:'POST',body});
    if(!r||(r.error&&!r.run_id)){toast((r&&r.error)||'cannot start');return;}
    curId=r.run_id;runBtn.disabled=true;cancelBtn.style.display='';
    clearInterval(dlvOsintTimer);dlvOsintTimer=setInterval(poll,1500);poll();
  };
  cancelBtn.onclick=async()=>{if(curId)await api('/api/delivery/osint/run/cancel',{method:'POST',body:{id:curId}});};
}
```

All evidence is placed with `el(...)` text children (never `html:`), so it renders as text.

- [ ] **Step 3: Syntax check.** From the repo root:

```bash
cd web && npm ci >/dev/null && cd .. 
python3 - <<'EOF'
import re,subprocess,sys
t=open('web/whm/index.html').read()
s=re.findall(r'<script>(.*?)</script>',t,re.S)[-1]
open('/tmp/claude-1000/-home-alain-maiscanner-msfe-ng/dcd9b6ae-f75a-465f-89d6-9a3610f110a7/scratchpad/whm.js','w').write(s)
EOF
node --check /tmp/claude-1000/-home-alain-maiscanner-msfe-ng/dcd9b6ae-f75a-465f-89d6-9a3610f110a7/scratchpad/whm.js && echo ok
```

Expected: `ok`. (CI extracts the `<script>` block the same way; if the page has more than one, mirror CI's extraction from `.github/workflows/ci.yml`.) If no CSS class was added, `cd web && npm run build && git diff --exit-code whm/app.css user/app.css` must be clean.

- [ ] **Step 4: Manual browser check** (syntax checks do not prove rendering). Start the daemon in dev mode the way the repo documents for the SPA (see `docs/architecture.md` or the existing dev instructions), with a config containing `osint_enabled = true` and `MSFE_NG_OSINT_FIXTURE=1`. Verify: four pills; OSINT view shows the fixture source with its disclosure; running `breach.test@example.org` shows an Exposure card with source, confidence, retrieval time and limits; `quiet@example.org` shows "No findings. That does not mean…"; `slow@example.org` then Cancel shows the cancelled notice; switching tab mid-run leaves no polling (watch the network tab); `<script>` typed as a local part is rejected or rendered as text. Record the result in the PR description.

- [ ] **Step 5: Commit**

```bash
git add web/whm/index.html
git commit -m "OSINT: Delivery → OSINT view with run, poll, cancel and export (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Entry-point links, wiki page and final gates

**Files:**
- Modify: `web/whm/index.html`: add an "Investigate address" action next to `deliveryTestLink(addr)` (~l.320) and in Address-test results.
- Create: `docs/wiki/OSINT.md`; link from `docs/wiki/Delivery-test.md` and the wiki Home/sidebar files (find them with `ls docs/wiki`).

**Interfaces:**
- Consumes: `osintFor(address, context)` from Task 6.

- [ ] **Step 1: Investigate action.** Next to `deliveryTestLink` add:

```js
function osintLink(addr){
  const a=el('a',{href:'#',class:'dlv-link',title:'Investigate this address (OSINT)'},'🔎');
  a.onclick=e=>{e.preventDefault();e.stopPropagation();osintFor(addr);};
  return a;
}
```

Use it everywhere `deliveryTestLink(addr)` is appended in message details and sender/recipient menus (`grep -n "deliveryTestLink(" web/whm/index.html`), and in the Address-test result header pass the run id: `osintFor(addr,{delivery_run_id:<current run id>})`. Match the surrounding markup of each call site; do not change the paper-plane action.

- [ ] **Step 2: Wiki page.** Write `docs/wiki/OSINT.md` covering: what the view does and does not prove (no match is not "safe"; breach is history; nothing changes mail handling), how to enable (`osint_enabled`), limits and defaults, what each source receives (phase 1: fixture only, nothing leaves the server), the CLI commands and exit codes 0/2/3/4, where reports are stored (`/var/cache/msfe-ng/osint`, `0700`, 24 h), and that real providers arrive in later phases. No server names. Link it from the pages that mention the Delivery tab, following how `Delivery-test.md` is linked (check `publish-wiki.sh` for the sidebar source).

- [ ] **Step 3: Full gates.**

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
(cd web && npm run build && git diff --exit-code whm/app.css user/app.css)
node --check <extracted whm script, as in Task 6>
grep -rniE "ncc|gauss|erdos" docs/wiki/OSINT.md crates/msfe-core/src/osint*.rs crates/msfe-ngd/src/osint_api.rs && echo LEAK || echo clean
```

Expected: everything passes and the last line prints `clean`. Also confirm regressions are absent: `cargo test --workspace 2>&1 | grep -E "test result|FAILED"`.

- [ ] **Step 4: Commit and stop.**

```bash
git add -A docs/wiki web/whm
git commit -m "OSINT: Investigate-address links and wiki page (phase 1)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

Do not tag or release. Report completion to the user and wait for "go".

---

## Self-Review

**Spec coverage (phase 1 only):** models/JSON (T1), settings and limits, controller, cache scope, busy/rate/concurrency, cancel, persistence, tombstones, sweep (T2), HTML export (T3), routes, 403-when-disabled, admin-only (T4), CLI and exit codes (T5), pill, poller clearing, `osintFor`/`OSINT_PREFILL`, result cards, partial and empty states (T6), entry-point links, wiki (T7). Deliberately out of scope here: `providerhttp`, secrets, HIBP, Gravatar, avatars, asset route, `osint_*_key` settings (phase 2); search/RDAP (phase 3); validation (4); DB history and `osintmon` (5); advanced sources (6). The `GET .../asset` route and the `osint_hibp_*`, search and validation settings are therefore not added in this phase. The "Delivery context" card is limited to the `delivery_run_id` link plus the Open Address test action; the richer summary lands with phase 3.

**Placeholder scan:** the only deliberate adaptation points are marked where the repo's real helper names must be confirmed (`Request::test`, CLI flag helpers, `config_path()` env var, `deliveryrun::snapshot` signature, `Config::load` argument). Each says what to check and what to do.

**Type consistency:** `StartOk`/`StartError`, `Inputs`, `parse_inputs`, `snapshot`, `cancel`, `remove`, `recent`, `sweep`, `report_dir`, `valid_id`, `providers()` are named identically in T2, T4 and T5. `RunState`, `SourceState`, `Group` names match across T1–T5. JSON field names used by the UI in T6 (`run_id`, `state`, `findings`, `sources`, `limitations`, `cached`, `retry_after`, `event_at`, `observed_at`, `source_url`, `confidence_reason`) match `OsintReport::to_json` in T1.
