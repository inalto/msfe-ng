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
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
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

struct Slot {
    report: OsintReport,
    key: String,
    finished_at: Option<Instant>,
    cancel: Arc<AtomicBool>,
}

static RUNS: Mutex<Option<HashMap<String, Slot>>> = Mutex::new(None);
static STARTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());
/// Ids removed while a worker may still be running: a late worker must not
/// recreate the run or its file.
static TOMBS: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
/// Held by `remove()` and by the tombstone-check-plus-persist section of the
/// worker, so a late persist can never land after a remove.
static PERSIST: Mutex<()> = Mutex::new(());
const TOMB_TTL: Duration = Duration::from_secs(3600);

fn with_runs<T>(f: impl FnOnce(&mut HashMap<String, Slot>) -> T) -> T {
    let mut g = RUNS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

fn tombstoned(id: &str) -> bool {
    TOMBS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .any(|(t, at)| t == id && at.elapsed() < TOMB_TTL)
}

/// Window admission. Pushes `now` on success; on refusal returns the seconds
/// until the oldest entry leaves the window.
fn admit(window: &mut Vec<Instant>, per_min: usize, now: Instant) -> Result<(), u64> {
    if let Some(cutoff) = now.checked_sub(Duration::from_secs(60)) {
        window.retain(|t| *t > cutoff);
    }
    if window.len() >= per_min {
        let oldest = window.iter().min().copied().unwrap_or(now);
        let waited = now.saturating_duration_since(oldest).as_secs();
        return Err(60u64.saturating_sub(waited).max(1));
    }
    window.push(now);
    Ok(())
}

/// Take back an admission whose start was then rejected.
fn unadmit(at: Instant) {
    let mut g = STARTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(i) = g.iter().position(|t| *t == at) {
        g.remove(i);
    }
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
    sweep_memory(Duration::from_secs(cfg.osint_cache_secs).max(EVICT_AFTER));
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
    let id = crate::deliveryrun::new_id();
    let cancel = Arc::new(AtomicBool::new(false));
    let max_conc = cfg.osint_max_concurrent.max(1) as usize;
    // Rate window first; a start rejected below hands its entry back so
    // rejections never burn the window.
    let admitted_at = Instant::now();
    {
        let per_min = cfg.osint_runs_per_min.max(1) as usize;
        let mut g = STARTS.lock().unwrap_or_else(|e| e.into_inner());
        admit(&mut g, per_min, admitted_at).map_err(StartError::RateLimited)?;
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
    // Busy, the concurrency ceiling and the insert happen under one lock, so
    // two simultaneous starts cannot both pass.
    let rejected = with_runs(|runs| {
        if let Some(s) = runs
            .values()
            .find(|s| s.report.state == RunState::Running && s.report.address == inputs.address)
        {
            return Some(StartError::Busy(s.report.run_id.clone()));
        }
        if runs
            .values()
            .filter(|s| s.report.state == RunState::Running)
            .count()
            >= max_conc
        {
            return Some(StartError::TooManyRuns);
        }
        runs.insert(
            id.clone(),
            Slot {
                report,
                key,
                finished_at: None,
                cancel: cancel.clone(),
            },
        );
        None
    });
    if let Some(e) = rejected {
        unadmit(admitted_at);
        return Err(e);
    }
    let deadline = Instant::now() + Duration::from_secs(cfg.osint_deadline_secs);
    let max_q = cfg.osint_max_external_queries.max(1) as usize;
    let id2 = id.clone();
    let spawned = std::thread::Builder::new()
        .name("osint-run".into())
        .spawn(move || worker(id2, inputs, cancel, deadline, max_q));
    if spawned.is_err() {
        with_runs(|runs| runs.remove(&id));
        unadmit(admitted_at);
        return Err(StartError::Invalid("could not start the lookup".into()));
    }
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
    let local = q
        .address
        .split('@')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let status = |state, detail: &str| SourceStatus {
        id: "fixture".into(),
        state,
        retry_after: None,
        detail: detail.into(),
    };
    if local.contains("panic") {
        panic!("synthetic provider panic");
    }
    if local.contains("slow") {
        for _ in 0..40 {
            if q.stop() {
                return Outcome {
                    source: status(SourceState::Inconclusive, "stopped before finishing"),
                    findings: vec![],
                };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if local.contains("fail") {
        return Outcome {
            source: status(SourceState::Failed, "synthetic failure"),
            findings: vec![],
        };
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
        return Outcome {
            source: status(SourceState::Matched, "1 incident"),
            findings: vec![f],
        };
    }
    Outcome {
        source: status(SourceState::NoMatch, "nothing found in this source"),
        findings: vec![],
    }
}

fn worker(id: String, inputs: Inputs, cancel: Arc<AtomicBool>, deadline: Instant, max_q: usize) {
    let mut sources = Vec::new();
    let mut findings = Vec::new();
    let mut ran = 0usize;
    let mut panicked = false;
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
        let q = QueryCtx {
            address: &inputs.address,
            cancel: &cancel,
            deadline,
        };
        let o = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run_provider(p, &q)))
        {
            Ok(o) => o,
            Err(_) => {
                panicked = true;
                Outcome {
                    source: SourceStatus {
                        id: p.clone(),
                        state: SourceState::Failed,
                        retry_after: None,
                        detail: "the source lookup failed unexpectedly".into(),
                    },
                    findings: Vec::new(),
                }
            }
        };
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
                detail: if cancelled {
                    "run cancelled before this source".into()
                } else {
                    "run time limit reached before this source".into()
                },
            });
        }
    }
    let all_terminal_ok = sources
        .iter()
        .all(|s| matches!(s.state, SourceState::Matched | SourceState::NoMatch));
    // The cancel flag is read under the registry lock that sets the final
    // state, and cancel() sets it under the same lock: a cancel() that returned
    // true always yields Cancelled.
    let report = with_runs(|runs| {
        let s = runs.get_mut(&id)?;
        let state = if cancel.load(Ordering::Relaxed) {
            RunState::Cancelled
        } else if panicked {
            RunState::Failed
        } else if all_terminal_ok {
            RunState::Complete
        } else {
            RunState::Partial
        };
        s.report.sources = sources;
        s.report.findings = findings;
        s.report.state = state;
        s.report.finished = Some(now_secs());
        s.finished_at = Some(Instant::now());
        Some(s.report.clone())
    });
    if let Some(r) = report {
        let _g = PERSIST.lock().unwrap_or_else(|e| e.into_inner());
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
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
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
    if tombstoned(id) {
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
    let mut v: Vec<OsintReport> =
        with_runs(|runs| runs.values().map(|s| s.report.clone()).collect());
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
    v.sort_by_key(|r| std::cmp::Reverse(r.started));
    v.truncate(n);
    v
}

/// Delete a run and its file, cancelling pending work so it cannot come back.
pub fn remove(id: &str) -> bool {
    if !valid_id(id) {
        return false;
    }
    let _g = PERSIST.lock().unwrap_or_else(|e| e.into_inner());
    let p = report_dir().join(format!("{id}.json"));
    let on_disk = p.exists();
    let had_mem = with_runs(|runs| match runs.remove(id) {
        Some(s) => {
            s.cancel.store(true, Ordering::Relaxed);
            true
        }
        None => false,
    });
    if had_mem || on_disk {
        let mut t = TOMBS.lock().unwrap_or_else(|e| e.into_inner());
        t.retain(|(_, at)| at.elapsed() < TOMB_TTL);
        t.push((id.to_string(), Instant::now()));
    }
    let had_file = std::fs::remove_file(&p).is_ok();
    // A worker that finished between the removal above and its persist call is
    // covered by the tombstone check in `worker`.
    let _ = std::fs::remove_file(report_dir().join(format!("{id}.tmp")));
    had_mem || had_file
}

fn sweep_memory(keep_finished: Duration) {
    with_runs(|runs| {
        runs.retain(|_, s| {
            s.finished_at
                .map(|t| t.elapsed() < keep_finished)
                .unwrap_or(true)
        });
    });
}

/// Delete `<16hex>.json` files older than `max_age_secs`. Other files in the
/// directory are never touched.
pub fn sweep(max_age_secs: u64) {
    let Ok(rd) = std::fs::read_dir(report_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, Once};
    use std::time::{Duration, Instant};

    static INIT: Once = Once::new();
    static TEST_LOCK: Mutex<()> = Mutex::new(());
    fn setup() -> (Config, MutexGuard<'static, ()>) {
        let g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        INIT.call_once(|| {
            let d = std::env::temp_dir().join(format!("msfe-osint-test-{}", std::process::id()));
            std::env::set_var("MSFE_NG_OSINT_DIR", &d);
            std::env::set_var("MSFE_NG_OSINT_FIXTURE", "1");
        });
        let c = Config {
            osint_enabled: true,
            osint_runs_per_min: 1000,
            osint_max_concurrent: 8,
            ..Config::default()
        };
        (c, g)
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
        let (_c, _g) = setup();
        let p = vec!["fixture".to_string()];
        assert!(parse_inputs("no-at-sign", &p, false, None).is_err());
        assert!(parse_inputs("a b@example.org", &p, false, None).is_err());
        assert!(parse_inputs("a@example.org", &["nope".to_string()], false, None).is_err());
        assert!(parse_inputs("a@example.org", &[], false, None).is_err());
    }

    #[test]
    fn disabled_refuses_to_start() {
        let (mut c, _g) = setup();
        c.osint_enabled = false;
        assert_eq!(
            start(&c, inp("off@example.org", false)).unwrap_err(),
            StartError::Disabled
        );
    }

    #[test]
    fn breach_fixture_produces_a_finding_and_completes() {
        let (c, _g) = setup();
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
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.one@example.org", true)).unwrap() else {
            panic!()
        };
        let r = wait_done(&id);
        assert_eq!(r.sources[0].state, SourceState::NoMatch);
        assert!(r.findings.is_empty());
        assert!(!r.limitations.is_empty(), "every report states its limits");
    }

    #[test]
    fn failed_source_makes_the_run_partial() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("fail.one@example.org", true)).unwrap() else {
            panic!()
        };
        assert_eq!(wait_done(&id).state, RunState::Partial);
    }

    #[test]
    fn second_run_for_a_running_address_is_busy() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("slow.busy@example.org", true)).unwrap() else {
            panic!()
        };
        match start(&c, inp("slow.busy@example.org", true)) {
            Err(StartError::Busy(b)) => assert_eq!(b, id),
            other => panic!("expected Busy, got {other:?}"),
        }
        cancel(&id);
        wait_done(&id);
    }

    #[test]
    fn cancelled_run_is_never_complete() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("slow.cancel@example.org", true)).unwrap() else {
            panic!()
        };
        assert!(cancel(&id));
        let r = wait_done(&id);
        assert_eq!(r.state, RunState::Cancelled);
    }

    #[test]
    fn finished_run_is_served_from_cache_unless_forced() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.cache@example.org", true)).unwrap() else {
            panic!()
        };
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
        let (c, _g) = setup();
        let StartOk::Started(a) = start(&c, inp("Quiet.Case@example.org", true)).unwrap() else {
            panic!()
        };
        wait_done(&a);
        // Different local-part case is a different subject: not a cache hit.
        assert!(matches!(
            start(&c, inp("quiet.case@example.org", false)).unwrap(),
            StartOk::Started(_)
        ));
    }

    #[test]
    fn concurrency_ceiling_returns_too_many_runs() {
        let (mut c, _g) = setup();
        c.osint_max_concurrent = 1;
        let StartOk::Started(id) = start(&c, inp("slow.limit1@example.org", true)).unwrap() else {
            panic!()
        };
        let r = start(&c, inp("slow.limit2@example.org", true));
        assert_eq!(r.unwrap_err(), StartError::TooManyRuns);
        cancel(&id);
        wait_done(&id);
    }

    #[test]
    fn rate_limit_applies() {
        let (mut c, _g) = setup();
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
        let (_c, _g) = setup();
        assert!(valid_id("0123456789abcdef"));
        for bad in [
            "",
            "../etc/passwd",
            "0123456789ABCDEF",
            "0123456789abcde",
            "0123456789abcdef0",
        ] {
            assert!(!valid_id(bad), "{bad}");
            assert!(snapshot(bad).is_none());
            assert!(!remove(bad));
        }
    }

    #[test]
    fn finished_report_is_persisted_0600_and_removal_deletes_it() {
        use std::os::unix::fs::PermissionsExt;
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("quiet.persist@example.org", true)).unwrap()
        else {
            panic!()
        };
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
        let (_c, _g) = setup();
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

    #[test]
    fn admit_window_and_release() {
        let now = Instant::now();
        let mut w = Vec::new();
        assert!(admit(&mut w, 1, now).is_ok());
        assert!(matches!(admit(&mut w, 1, now), Err(s) if s >= 1));
        assert!(admit(&mut w, 1, now + Duration::from_secs(61)).is_ok());
    }

    #[test]
    fn rejected_starts_do_not_burn_the_rate_window() {
        let (mut c, _g) = setup();
        c.osint_max_concurrent = 1;
        c.osint_runs_per_min = 1000;
        let StartOk::Started(id) = start(&c, inp("slow.burn1@example.org", true)).unwrap() else {
            panic!()
        };
        let before = STARTS.lock().unwrap().len();
        assert_eq!(
            start(&c, inp("slow.burn2@example.org", true)).unwrap_err(),
            StartError::TooManyRuns
        );
        assert!(matches!(
            start(&c, inp("slow.burn1@example.org", true)),
            Err(StartError::Busy(_))
        ));
        assert_eq!(STARTS.lock().unwrap().len(), before);
        cancel(&id);
        wait_done(&id);
    }

    #[test]
    fn a_cancel_that_succeeded_always_yields_cancelled() {
        let (mut c, _g) = setup();
        c.osint_runs_per_min = 1000;
        for i in 0..30 {
            let a = format!("quiet.race{i}@example.org");
            let StartOk::Started(id) = start(&c, inp(&a, true)).unwrap() else {
                panic!()
            };
            if cancel(&id) {
                assert_eq!(wait_done(&id).state, RunState::Cancelled, "run {i}");
            } else {
                wait_done(&id);
            }
        }
    }

    #[test]
    fn removed_run_does_not_come_back() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("slow.gone@example.org", true)).unwrap() else {
            panic!()
        };
        assert!(remove(&id));
        std::thread::sleep(Duration::from_millis(400));
        assert!(snapshot(&id).is_none());
        assert!(!report_dir().join(format!("{id}.json")).exists());
        assert!(recent(100).iter().all(|r| r.run_id != id));
    }

    #[test]
    fn unknown_ids_are_not_tombstoned() {
        let (_c, _g) = setup();
        let before = TOMBS.lock().unwrap().len();
        assert!(!remove("0123456789abcdef"));
        assert_eq!(TOMBS.lock().unwrap().len(), before);
    }

    #[test]
    fn a_panicking_provider_finalises_the_run_as_failed() {
        let (c, _g) = setup();
        let StartOk::Started(id) = start(&c, inp("panic.one@example.org", true)).unwrap() else {
            panic!()
        };
        let r = wait_done(&id);
        assert_eq!(r.state, RunState::Failed);
        assert!(r.finished.is_some());
        assert!(matches!(
            start(&c, inp("panic.one@example.org", true)),
            Ok(StartOk::Started(_))
        ));
    }
}
