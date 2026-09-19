//! Running a delivery test: the task scheduler (a small worker pool over a
//! dependency-ordered task list with a run deadline), the in-memory registry
//! that serves progressive results, the finished-report cache, the rate
//! limit and the on-disk copy of every report.
//!
//! A run is started from a request handler and continues on its own thread;
//! polling reads the registry without any lock the handlers contend on.

use crate::delivery::{now_secs, Category, Check, Inputs, Report, Scope, Severity, Verdict};
use crate::dns::Client;
use crate::json::Json;
use crate::{netguard, Config};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

pub const WORKERS: usize = 6;
pub const DEADLINE: Duration = Duration::from_secs(90);
/// How long a finished run stays in memory.
const EVICT_AFTER: Duration = Duration::from_secs(30 * 60);
/// How long a report file is kept.
const KEEP_FILES_SECS: u64 = 24 * 3600;

/// Everything a task may need; cloned into workers.
pub struct Ctx {
    pub cfg: Config,
    pub inputs: Inputs,
    pub dns: Arc<Client>,
    pub deadline: Instant,
    pub cancel: Arc<AtomicBool>,
    /// The name this server introduces itself with.
    pub helo: String,
}

impl Ctx {
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
    pub fn time_left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Shared facts between tasks (what earlier tasks learned), plus the checks.
#[derive(Default)]
pub struct Results {
    checks: Mutex<Vec<Check>>,
    facts: Mutex<HashMap<String, Json>>,
}

impl Results {
    pub fn push(&self, c: Check) {
        self.checks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(c);
    }
    pub fn checks(&self) -> Vec<Check> {
        self.checks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn set_fact(&self, k: &str, v: Json) {
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(k.to_string(), v);
    }
    /// Add `(key, value)` to the object fact `k` (created when absent),
    /// replacing an earlier entry with the same key — atomically, since
    /// tasks that run side by side all write the same object.
    pub fn insert_fact_entry(&self, k: &str, key: &str, value: Json) {
        let mut g = self.facts.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries = match g.remove(k) {
            Some(Json::Object(f)) => f,
            _ => Vec::new(),
        };
        entries.retain(|(h, _)| h != key);
        entries.push((key.to_string(), value));
        g.insert(k.to_string(), Json::Object(entries));
    }
    pub fn fact(&self, k: &str) -> Option<Json> {
        self.facts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(k)
            .cloned()
    }
    pub fn fact_bool(&self, k: &str) -> Option<bool> {
        match self.fact(k) {
            Some(Json::Bool(b)) => Some(b),
            _ => None,
        }
    }
    pub fn fact_str(&self, k: &str) -> Option<String> {
        self.fact(k).and_then(|v| v.as_str().map(str::to_string))
    }
    pub fn fact_strs(&self, k: &str) -> Vec<String> {
        self.fact(k)
            .and_then(|v| {
                v.as_array().map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default()
    }
}

pub type TaskFn = Box<dyn FnOnce(&Ctx, &Results) -> (Vec<Check>, Vec<Task>) + Send>;

/// One unit of work; runs after its `deps` finished, may spawn more tasks.
pub struct Task {
    pub id: String,
    pub deps: Vec<String>,
    pub run: TaskFn,
}

impl Task {
    pub fn new(
        id: &str,
        deps: &[&str],
        run: impl FnOnce(&Ctx, &Results) -> (Vec<Check>, Vec<Task>) + Send + 'static,
    ) -> Task {
        Task {
            id: id.to_string(),
            deps: deps.iter().map(|s| s.to_string()).collect(),
            run: Box::new(run),
        }
    }
}

/// Run every task to completion (or the deadline) on a pool of `WORKERS`
/// threads, handing each finished check to `on_check` as it arrives.
pub fn execute(
    ctx: Arc<Ctx>,
    tasks: Vec<Task>,
    on_check: &mut dyn FnMut(&Check),
    on_planned: &mut dyn FnMut(&str),
) -> (Vec<Check>, Vec<String>) {
    let results = Arc::new(Results::default());
    let mut pending: VecDeque<Task> = VecDeque::new();
    let mut done: Vec<String> = Vec::new();
    let mut running = 0usize;
    let (tx, rx) = mpsc::channel::<(String, Vec<Check>, Vec<Task>)>();
    let mut unfinished: Vec<String> = Vec::new();
    for t in tasks {
        on_planned(&t.id);
        pending.push_back(t);
    }
    loop {
        // launch every runnable task while workers are free
        let mut i = 0;
        while i < pending.len() && running < WORKERS {
            if pending[i].deps.iter().all(|d| done.contains(d)) {
                let t = pending.remove(i).unwrap();
                if ctx.cancelled() {
                    unfinished.push(t.id);
                    continue;
                }
                running += 1;
                let (ctx2, res2, tx2) = (ctx.clone(), results.clone(), tx.clone());
                let id = t.id.clone();
                let run = t.run;
                std::thread::spawn(move || {
                    let t0 = Instant::now();
                    let (mut checks, more) = run(&ctx2, &res2);
                    let ms = t0.elapsed().as_millis() as u64;
                    for c in &mut checks {
                        if c.duration_ms == 0 {
                            c.duration_ms = ms;
                        }
                    }
                    let _ = tx2.send((id, checks, more));
                });
            } else {
                i += 1;
            }
        }
        if running == 0 {
            // nothing runs: either all done, or the rest can never run
            // (deps missing / cancelled)
            for t in pending.drain(..) {
                unfinished.push(t.id);
            }
            break;
        }
        let wait = ctx.time_left().max(Duration::from_millis(50));
        match rx.recv_timeout(wait) {
            Ok((id, checks, more)) => {
                running -= 1;
                for c in checks {
                    on_check(&c);
                    results.push(c);
                }
                for t in more {
                    on_planned(&t.id);
                    pending.push_back(t);
                }
                done.push(id);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if ctx.cancelled() {
                    // late workers are abandoned; their results are dropped
                    for t in pending.drain(..) {
                        unfinished.push(t.id);
                    }
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    (results.checks(), unfinished)
}

// ---- the registry ------------------------------------------------------------

struct RunState {
    report: Report,
    finished_at: Option<Instant>,
    cancel: Arc<AtomicBool>,
}

static RUNS: Mutex<Option<HashMap<String, RunState>>> = Mutex::new(None);
static STARTS: Mutex<Vec<Instant>> = Mutex::new(Vec::new());

fn with_runs<T>(f: impl FnOnce(&mut HashMap<String, RunState>) -> T) -> T {
    let mut g = RUNS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

#[derive(Debug, Clone, PartialEq)]
pub enum StartError {
    Invalid(String),
    /// A run for this address is in progress (its id).
    Busy(String),
    RateLimited(u64),
}

pub fn report_dir() -> PathBuf {
    std::env::var("MSFE_NG_DELIVERY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/cache/msfe-ng/delivery"))
}

/// 16 hex characters from /dev/urandom (time-seeded fallback).
pub fn new_id() -> String {
    let mut b = [0u8; 8];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        b = (t as u64 ^ (std::process::id() as u64) << 32).to_be_bytes();
    }
    crate::dns::hex(&b)
}

/// Validate raw inputs into `Inputs`.
pub fn parse_inputs(
    address: &str,
    ip: Option<&str>,
    selector: Option<&str>,
    days: Option<i64>,
    audit: bool,
    force: bool,
    user_scope: Option<String>,
) -> Result<Inputs, String> {
    let (local_part, domain) = netguard::parse_address(address)?;
    let ip = match ip.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            let parsed: std::net::IpAddr = s
                .parse()
                .map_err(|_| format!("'{s}' is not an IP address"))?;
            if !netguard::is_public(parsed) {
                return Err(format!("{parsed} is not a public address"));
            }
            Some(parsed)
        }
        None => None,
    };
    let selector = match selector.map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            if s.len() > 63
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            {
                return Err(
                    "the DKIM selector may only contain letters, digits, '-', '_' and '.'".into(),
                );
            }
            Some(s.to_ascii_lowercase())
        }
        None => None,
    };
    let days = days.unwrap_or(2).clamp(1, 7) as u32;
    Ok(Inputs {
        address: format!("{local_part}@{domain}"),
        domain,
        local_part,
        ip,
        selector,
        days,
        audit,
        force,
        user_scope,
    })
}

/// The task list of a public delivery test (phase A).
pub fn plan(_inputs: &Inputs) -> Vec<Task> {
    let mut tasks = crate::dnschecks::tasks();
    tasks.extend(crate::authchecks::tasks());
    tasks.extend(crate::mxchecks::tasks());
    tasks.extend(crate::tschecks::tasks());
    tasks.push(crate::dnschecks::meta_task());
    tasks
}

/// A finished report for the same inputs from the last `cache_secs`.
pub fn cached_report(inputs: &Inputs, cache_secs: u64) -> Option<Report> {
    let key = inputs.cache_key();
    let now = now_secs();
    with_runs(|runs| {
        runs.values()
            .filter(|s| s.report.done && s.report.inputs.cache_key() == key)
            .filter(|s| {
                s.report
                    .finished
                    .is_some_and(|f| now.saturating_sub(f) <= cache_secs)
            })
            .max_by_key(|s| s.report.finished)
            .map(|s| {
                let mut r = s.report.clone();
                r.cached = true;
                r
            })
    })
}

/// Register and start a run. The coordinator thread owns the run until done.
pub fn start(
    cfg: &Config,
    inputs: Inputs,
    plan: impl FnOnce(&Inputs) -> Vec<Task> + Send + 'static,
) -> Result<String, StartError> {
    let per_min = cfg.delivery_runs_per_min.max(1) as usize;
    {
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
    sweep_memory();
    let addr = inputs.address.to_ascii_lowercase();
    let id = new_id();
    let cancel = Arc::new(AtomicBool::new(false));
    let busy = with_runs(|runs| {
        if let Some((rid, _)) = runs
            .iter()
            .find(|(_, s)| !s.report.done && s.report.inputs.address.eq_ignore_ascii_case(&addr))
        {
            return Some(rid.clone());
        }
        runs.insert(
            id.clone(),
            RunState {
                report: Report {
                    id: id.clone(),
                    inputs: inputs.clone(),
                    started: now_secs(),
                    finished: None,
                    done: false,
                    planned: Vec::new(),
                    checks: Vec::new(),
                    tool_notes: Vec::new(),
                    cached: false,
                },
                finished_at: None,
                cancel: cancel.clone(),
            },
        );
        None
    });
    if let Some(rid) = busy {
        return Err(StartError::Busy(rid));
    }
    let cfg = cfg.clone();
    let id2 = id.clone();
    std::thread::spawn(move || {
        let ctx = Arc::new(Ctx {
            helo: helo_name(&cfg),
            dns: Arc::new(Client::system()),
            deadline: Instant::now() + DEADLINE,
            cancel,
            inputs: inputs.clone(),
            cfg,
        });
        let notes = tool_notes(&ctx);
        with_runs(|runs| {
            if let Some(s) = runs.get_mut(&id2) {
                s.report.tool_notes = notes;
            }
        });
        let tasks = plan(&inputs);
        let id3 = id2.clone();
        let id4 = id2.clone();
        let (_, unfinished) = execute(
            ctx.clone(),
            tasks,
            &mut |c| {
                with_runs(|runs| {
                    if let Some(s) = runs.get_mut(&id3) {
                        s.report.checks.push(c.clone());
                    }
                })
            },
            &mut |t| {
                with_runs(|runs| {
                    if let Some(s) = runs.get_mut(&id4) {
                        s.report.planned.push(t.to_string());
                    }
                })
            },
        );
        let cancelled = ctx.cancel.load(Ordering::Relaxed);
        with_runs(|runs| {
            if let Some(s) = runs.get_mut(&id2) {
                for t in unfinished {
                    s.report.checks.push(
                        Check::new(
                            &t,
                            Scope::Sending,
                            Category::Meta,
                            Verdict::Unknown,
                            Severity::Info,
                            format!("{t}: not run"),
                            if cancelled {
                                "the run was cancelled before this check ran"
                            } else {
                                "the run's time limit was reached before this check ran — try again, or fewer checks"
                            },
                        ),
                    );
                }
                s.report.done = true;
                s.report.finished = Some(now_secs());
                s.finished_at = Some(Instant::now());
                persist(&s.report);
            }
        });
    });
    Ok(id)
}

/// Run to completion on the calling thread (CLI, monitors).
pub fn run_blocking(
    cfg: &Config,
    inputs: Inputs,
    plan: impl FnOnce(&Inputs) -> Vec<Task>,
    on_check: &mut dyn FnMut(&Check),
) -> Report {
    let ctx = Arc::new(Ctx {
        helo: helo_name(cfg),
        dns: Arc::new(Client::system()),
        deadline: Instant::now() + DEADLINE,
        cancel: Arc::new(AtomicBool::new(false)),
        inputs: inputs.clone(),
        cfg: cfg.clone(),
    });
    let mut report = Report {
        id: new_id(),
        inputs: inputs.clone(),
        started: now_secs(),
        finished: None,
        done: false,
        planned: Vec::new(),
        checks: Vec::new(),
        tool_notes: tool_notes(&ctx),
        cached: false,
    };
    let tasks = plan(&inputs);
    let mut planned = Vec::new();
    let (checks, unfinished) = execute(ctx, tasks, on_check, &mut |t| planned.push(t.to_string()));
    report.planned = planned;
    report.checks = checks;
    for t in unfinished {
        report.checks.push(Check::new(
            &t,
            Scope::Sending,
            Category::Meta,
            Verdict::Unknown,
            Severity::Info,
            format!("{t}: not run"),
            "the run's time limit was reached before this check ran",
        ));
    }
    report.done = true;
    report.finished = Some(now_secs());
    persist(&report);
    report
}

pub fn snapshot(id: &str) -> Option<Report> {
    with_runs(|runs| runs.get(id).map(|s| s.report.clone())).or_else(|| load(id))
}

pub fn cancel(id: &str) -> bool {
    with_runs(|runs| {
        runs.get(id).map(|s| {
            s.cancel.store(true, Ordering::Relaxed);
            true
        })
    })
    .unwrap_or(false)
}

/// Finished reports, newest first (memory + disk).
pub fn recent(limit: usize) -> Vec<Report> {
    let mut v: Vec<Report> = with_runs(|runs| runs.values().map(|s| s.report.clone()).collect());
    if let Ok(rd) = std::fs::read_dir(report_dir()) {
        for e in rd.filter_map(Result::ok) {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".json") {
                if !v.iter().any(|r| r.id == id) {
                    if let Some(r) = load(id) {
                        v.push(r);
                    }
                }
            }
        }
    }
    v.sort_by_key(|r| std::cmp::Reverse(r.started));
    v.truncate(limit);
    v
}

fn persist(r: &Report) {
    let dir = report_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    let path = dir.join(format!("{}.json", r.id));
    if std::fs::write(&path, r.to_json().to_string()).is_ok() {
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

fn load(id: &str) -> Option<Report> {
    if !crate::service::safe_name(id) {
        return None;
    }
    let t = std::fs::read_to_string(report_dir().join(format!("{id}.json"))).ok()?;
    Json::parse(&t).ok().and_then(|v| Report::from_json(&v))
}

fn sweep_memory() {
    with_runs(|runs| {
        runs.retain(|_, s| !s.finished_at.is_some_and(|t| t.elapsed() > EVICT_AFTER));
    });
}

/// Drop stale memory entries and report files older than a day.
pub fn sweep() {
    sweep_memory();
    let now = now_secs();
    if let Ok(rd) = std::fs::read_dir(report_dir()) {
        for e in rd.filter_map(Result::ok) {
            use std::os::unix::fs::MetadataExt;
            if e.metadata()
                .is_ok_and(|m| now.saturating_sub(m.mtime().max(0) as u64) > KEEP_FILES_SECS)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

fn helo_name(cfg: &Config) -> String {
    if !cfg.delivery_helo.trim().is_empty() {
        return cfg.delivery_helo.trim().to_string();
    }
    std::process::Command::new("hostname")
        .arg("-f")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

fn tool_notes(ctx: &Ctx) -> Vec<String> {
    let mut notes = vec![format!(
        "resolver: {}",
        ctx.dns
            .servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )];
    notes.push(format!("EHLO name: {}", ctx.helo));
    match crate::tlsprobe::openssl_version() {
        Some(v) => notes.push(format!("TLS probes: {v}")),
        None => notes.push("openssl not found: TLS checks are reported as unknown".into()),
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// The tests that set process-wide env vars must not overlap.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn ctx(deadline: Duration) -> Arc<Ctx> {
        Arc::new(Ctx {
            cfg: Config::default(),
            inputs: parse_inputs("a@example.com", None, None, None, false, false, None).unwrap(),
            dns: Arc::new(Client::at("127.0.0.1:1".parse().unwrap())),
            deadline: Instant::now() + deadline,
            cancel: Arc::new(AtomicBool::new(false)),
            helo: "test.local".into(),
        })
    }

    fn check(id: &str) -> Check {
        Check::new(
            id,
            Scope::Sending,
            Category::Dns,
            Verdict::Pass,
            Severity::Info,
            id,
            "",
        )
    }

    #[test]
    fn scheduler_honours_deps_bounds_concurrency_and_spawns() {
        let high = Arc::new(AtomicUsize::new(0));
        let cur = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for i in 0..12 {
            let (h, c) = (high.clone(), cur.clone());
            tasks.push(Task::new(&format!("t{i}"), &[], move |_, _| {
                let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                h.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(40));
                c.fetch_sub(1, Ordering::SeqCst);
                (vec![check(&format!("c{i}"))], Vec::new())
            }));
        }
        tasks.push(Task::new("after", &["t0", "t1"], |_, res| {
            assert!(
                res.checks().iter().any(|c| c.id == "c0"),
                "dep finished before us"
            );
            res.set_fact("k", Json::str("v"));
            (
                vec![check("after")],
                vec![Task::new("spawned", &["after"], |_, res| {
                    assert_eq!(res.fact_str("k").as_deref(), Some("v"));
                    (vec![check("spawned")], Vec::new())
                })],
            )
        }));
        let mut seen = Vec::new();
        let mut planned = Vec::new();
        let (checks, unfinished) = execute(
            ctx(Duration::from_secs(10)),
            tasks,
            &mut |c| seen.push(c.id.clone()),
            &mut |t| planned.push(t.to_string()),
        );
        assert!(unfinished.is_empty());
        assert_eq!(checks.len(), 14);
        assert!(seen.contains(&"spawned".to_string()));
        assert!(planned.contains(&"spawned".to_string()));
        assert!(
            high.load(Ordering::SeqCst) <= WORKERS,
            "high-water {}",
            high.load(Ordering::SeqCst)
        );
        assert!(high.load(Ordering::SeqCst) >= 2);
        assert!(checks
            .iter()
            .all(|c| c.duration_ms > 0 || c.id.starts_with("after") || c.id == "spawned"));
    }

    #[test]
    fn deadline_and_cancel_leave_pending_tasks_unfinished() {
        let mut tasks = vec![Task::new("slow", &[], |_, _| {
            std::thread::sleep(Duration::from_millis(600));
            (vec![check("slow")], Vec::new())
        })];
        tasks.push(Task::new("waits", &["slow"], |_, _| {
            (vec![check("waits")], Vec::new())
        }));
        let t0 = Instant::now();
        let (checks, unfinished) = execute(
            ctx(Duration::from_millis(200)),
            tasks,
            &mut |_| {},
            &mut |_| {},
        );
        assert!(
            t0.elapsed() < Duration::from_millis(550),
            "deadline cut the wait"
        );
        assert!(checks.is_empty());
        assert_eq!(unfinished, vec!["waits"]);
        // a dep that never exists
        let tasks = vec![Task::new("orphan", &["nope"], |_, _| (vec![], vec![]))];
        let (_, unfinished) = execute(ctx(Duration::from_secs(1)), tasks, &mut |_| {}, &mut |_| {});
        assert_eq!(unfinished, vec!["orphan"]);
    }

    #[test]
    fn a_full_dns_run_over_a_fake_zone() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        use crate::dns::testsupport::start as fake;
        use crate::dns::{RData, Rr};
        let rr = |name: &str, rtype: u16, data: RData| Rr {
            name: name.into(),
            rtype,
            ttl: 3600,
            data,
        };
        let srv = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("good.example", 15) => Some((
                    0,
                    vec![
                        rr(
                            "good.example",
                            15,
                            RData::Mx {
                                pref: 10,
                                host: "mx1.good.example".into(),
                            },
                        ),
                        rr(
                            "good.example",
                            15,
                            RData::Mx {
                                pref: 20,
                                host: "mx2.good.example".into(),
                            },
                        ),
                    ],
                    false,
                )),
                ("good.example", 2) => Some((
                    0,
                    vec![
                        rr("good.example", 2, RData::Ns("ns1.good.example".into())),
                        rr("good.example", 2, RData::Ns("ns2.good.example".into())),
                    ],
                    false,
                )),
                ("good.example", 6) => Some((
                    0,
                    vec![rr(
                        "good.example",
                        6,
                        RData::Soa {
                            mname: "ns1.good.example".into(),
                            rname: "hostmaster.good.example".into(),
                            serial: 1,
                            refresh: 3600,
                            retry: 900,
                            expire: 1209600,
                            minimum: 3600,
                        },
                    )],
                    false,
                )),
                ("good.example", 1) | ("good.example", 28) | ("good.example", 16) => {
                    Some((0, vec![], false))
                }
                ("ns1.good.example", 1) | ("ns2.good.example", 1) => Some((
                    0,
                    vec![rr(name, 1, RData::A("192.0.2.53".parse().unwrap()))],
                    false,
                )),
                ("mx1.good.example", 1) => Some((
                    0,
                    vec![rr(
                        "mx1.good.example",
                        1,
                        RData::A("185.199.108.25".parse().unwrap()),
                    )],
                    false,
                )),
                ("mx1.good.example", 28) => Some((
                    0,
                    vec![rr(
                        "mx1.good.example",
                        28,
                        RData::Aaaa("2001:db8:1::25".parse().unwrap()),
                    )],
                    false,
                )),
                ("mx2.good.example", 1) => Some((
                    0,
                    vec![
                        rr(
                            "mx2.good.example",
                            5,
                            RData::Cname("mx1.good.example".into()),
                        ),
                        rr(
                            "mx1.good.example",
                            1,
                            RData::A("185.199.108.25".parse().unwrap()),
                        ),
                    ],
                    false,
                )),
                ("25.108.199.185.in-addr.arpa", 12) => Some((
                    0,
                    vec![rr(name, 12, RData::Ptr("mx1.good.example".into()))],
                    false,
                )),
                ("nomx.example", 15) => Some((0, vec![], false)),
                ("nomx.example", 1) => Some((
                    0,
                    vec![rr(
                        "nomx.example",
                        1,
                        RData::A("198.51.100.80".parse().unwrap()),
                    )],
                    false,
                )),
                ("nomx.example", _) => Some((0, vec![], false)),
                ("gone.example", _) => Some((3, vec![], false)),
                (n, 28) if n.ends_with("good.example") => Some((0, vec![], false)),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        std::env::set_var("MSFE_NG_RESOLVER", srv.addr.to_string());
        std::env::set_var("MSFE_NG_DELIVERY_NO_NET", "1");
        let dir = std::env::temp_dir().join(format!("msfe-dlvrun-{}", std::process::id()));
        std::env::set_var("MSFE_NG_DELIVERY_DIR", &dir);
        let cfg = Config {
            delivery_helo: "t.local".into(),
            ..Config::default()
        };
        let by = |r: &Report, id: &str, target: Option<&str>| -> Verdict {
            r.checks
                .iter()
                .find(|c| {
                    c.id == id
                        && target
                            .is_none_or(|t| c.target.as_deref().is_some_and(|x| x.starts_with(t)))
                })
                .map(|c| c.verdict)
                .unwrap_or_else(|| {
                    panic!(
                        "{id} {target:?} missing in {:?}",
                        r.checks
                            .iter()
                            .map(|c| (c.id.clone(), c.target.clone()))
                            .collect::<Vec<_>>()
                    )
                })
        };
        let r = run_blocking(
            &cfg,
            parse_inputs("a@good.example", None, None, None, false, false, None).unwrap(),
            plan,
            &mut |_| {},
        );
        assert!(r.done);
        assert_eq!(by(&r, "dns.domain", None), Verdict::Pass);
        assert_eq!(by(&r, "dns.ns", None), Verdict::Pass);
        assert_eq!(by(&r, "dns.soa", None), Verdict::Pass);
        assert_eq!(by(&r, "dns.mx", None), Verdict::Pass);
        assert_eq!(by(&r, "dns.mx.priorities", None), Verdict::Pass);
        assert_eq!(
            by(&r, "dns.mx.target", Some("mx1.good.example")),
            Verdict::Pass
        );
        assert_eq!(
            by(&r, "dns.mx.target", Some("mx2.good.example")),
            Verdict::Warn,
            "CNAME"
        );
        assert_eq!(by(&r, "dns.mx.ptr", Some("185.199.108.25")), Verdict::Pass);
        assert_eq!(
            by(&r, "dns.mx.addr_public", Some("mx1.good.example")),
            Verdict::Fail,
            "2001:db8::/32 is documentation space, not public"
        );
        assert!(
            !r.checks.iter().any(|c| c.id == "dns.mx.ptr"
                && c.target
                    .as_deref()
                    .is_some_and(|t| t.starts_with("2001:db8"))),
            "non-public addresses get no PTR check"
        );
        assert_eq!(by(&r, "dns.ipv6", None), Verdict::Pass);
        assert_eq!(by(&r, "dns.apex_cname", None), Verdict::Pass);
        assert_eq!(by(&r, "meta.mailbox", None), Verdict::Unknown);
        assert_eq!(by(&r, "meta.provider", None), Verdict::Pass);
        assert_eq!(
            by(&r, "mx.connect", Some("mx1.good.example (185.199.108.25)")),
            Verdict::Unknown,
            "probes are off in tests"
        );
        assert!(r
            .planned
            .contains(&"dns.mx.host.mx1.good.example".to_string()));
        assert!(r.planned.contains(&"mx.host.mx1.good.example".to_string()));

        let r = run_blocking(
            &cfg,
            parse_inputs("a@nomx.example", None, None, None, false, false, None).unwrap(),
            plan,
            &mut |_| {},
        );
        assert_eq!(by(&r, "dns.mx", None), Verdict::Warn);
        assert!(r.checks.iter().any(|c| c.id == "dns.mx"
            && c.fix.as_ref().unwrap().dns_record.as_deref()
                == Some("nomx.example. 3600 IN MX 10 mail.nomx.example.")));

        let r = run_blocking(
            &cfg,
            parse_inputs("a@gone.example", None, None, None, false, false, None).unwrap(),
            plan,
            &mut |_| {},
        );
        assert_eq!(by(&r, "dns.domain", None), Verdict::Fail);
        assert!(
            !r.checks.iter().any(|c| c.id == "dns.mx"),
            "no further DNS checks on a missing domain"
        );
        std::env::remove_var("MSFE_NG_RESOLVER");
        std::env::remove_var("MSFE_NG_DELIVERY_DIR");
        std::env::remove_var("MSFE_NG_DELIVERY_NO_NET");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inputs_are_validated() {
        let i = parse_inputs(
            " Bob@Example.COM ",
            Some("203.0.113.9"),
            None,
            Some(30),
            true,
            false,
            None,
        );
        assert!(i.is_err(), "documentation range is not public");
        let i = parse_inputs(
            "Bob@Example.COM",
            Some("8.8.8.8"),
            Some("Default"),
            Some(30),
            true,
            false,
            None,
        )
        .unwrap();
        assert_eq!(i.address, "Bob@example.com");
        assert_eq!(i.days, 7);
        assert_eq!(i.selector.as_deref(), Some("default"));
        assert!(i.audit);
        assert!(parse_inputs(
            "x@example.com",
            Some("not an ip"),
            None,
            None,
            false,
            false,
            None
        )
        .is_err());
        assert!(parse_inputs(
            "x@example.com",
            None,
            Some("bad sel!"),
            None,
            false,
            false,
            None
        )
        .is_err());
        assert!(parse_inputs("nope", None, None, None, false, false, None).is_err());
        assert_eq!(
            parse_inputs("x@example.com", None, None, Some(0), false, false, None)
                .unwrap()
                .days,
            1
        );
    }

    #[test]
    fn registry_start_busy_ratelimit_cache_and_persist() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("msfe-dlv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::env::set_var("MSFE_NG_DELIVERY_DIR", &dir);
        std::env::set_var("MSFE_NG_RESOLVER", "127.0.0.1:1");
        let cfg = Config {
            delivery_runs_per_min: 3,
            delivery_helo: "test.local".into(),
            ..Config::default()
        };
        let inputs = parse_inputs("reg@example.com", None, None, None, false, false, None).unwrap();
        let plan = |_: &Inputs| {
            vec![Task::new("slow", &[], |_, _| {
                std::thread::sleep(Duration::from_millis(300));
                (vec![check("slow")], Vec::new())
            })]
        };
        let id = start(&cfg, inputs.clone(), plan).unwrap();
        assert_eq!(id.len(), 16);
        // busy while running
        assert_eq!(
            start(&cfg, inputs.clone(), plan),
            Err(StartError::Busy(id.clone()))
        );
        let r = snapshot(&id).unwrap();
        assert!(!r.done);
        // wait for completion
        let mut r = snapshot(&id).unwrap();
        for _ in 0..40 {
            if r.done {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            r = snapshot(&id).unwrap();
        }
        assert!(r.done);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.planned, vec!["slow"]);
        assert!(r.tool_notes.iter().any(|n| n.starts_with("resolver: ")));
        assert!(dir.join(format!("{id}.json")).exists());
        // cache
        let c = cached_report(&inputs, 600).unwrap();
        assert!(c.cached);
        assert_eq!(c.id, id);
        assert!(cached_report(&inputs, 0).is_none() || now_secs() == c.finished.unwrap());
        // rate limit: 3 per minute, two used (the busy one did not count? it did — it is counted before the busy check)
        let other =
            parse_inputs("other@example.com", None, None, None, false, false, None).unwrap();
        let _ = start(&cfg, other.clone(), |_| vec![]);
        let third =
            parse_inputs("third@example.com", None, None, None, false, false, None).unwrap();
        assert!(matches!(
            start(&cfg, third, |_| vec![]),
            Err(StartError::RateLimited(_))
        ));
        // recent lists it, including from disk after eviction
        assert!(recent(10).iter().any(|r| r.id == id));
        with_runs(|runs| runs.clear());
        assert!(recent(10).iter().any(|r| r.id == id), "loaded from disk");
        assert!(snapshot("../etc/passwd").is_none());
        // cancel of a running run
        STARTS.lock().unwrap().clear();
        let cinputs =
            parse_inputs("cancel@example.com", None, None, None, false, false, None).unwrap();
        let cid = start(&cfg, cinputs, |_| {
            vec![
                Task::new("first", &[], |ctx, _| {
                    std::thread::sleep(Duration::from_millis(200));
                    assert!(ctx.cancelled());
                    (vec![check("first")], Vec::new())
                }),
                Task::new("second", &["first"], |_, _| {
                    (vec![check("second")], Vec::new())
                }),
            ]
        })
        .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(cancel(&cid));
        let mut r = snapshot(&cid).unwrap();
        for _ in 0..40 {
            if r.done {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
            r = snapshot(&cid).unwrap();
        }
        assert!(r.done);
        assert!(r.checks.iter().any(|c| c.id == "second"
            && c.verdict == Verdict::Unknown
            && c.explanation.contains("cancelled")));
        std::env::remove_var("MSFE_NG_DELIVERY_DIR");
        std::env::remove_var("MSFE_NG_RESOLVER");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
