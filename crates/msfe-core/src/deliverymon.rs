//! Scheduled delivery tests: a monitor is an address with its test options
//! and an interval; `msfe-ng monitor` (the 5-minute cron) runs the due ones
//! one after another, stores each report in MySQL, compares it with the
//! previous run and sends a Telegram message when a check got worse (or
//! recovered), under the usual alert cooldown.

use crate::config::Config;
use crate::db;
use crate::delivery::{Inputs, Report, Verdict};
use crate::json::Json;

pub const MIN_INTERVAL_MINS: u32 = 60;
pub const MAX_INTERVAL_MINS: u32 = 24 * 60;
pub const DEFAULT_INTERVAL_MINS: u32 = 6 * 60;
/// Runs kept per monitor.
pub const KEEP_RUNS: u32 = 200;

#[derive(Debug, Clone)]
pub struct Monitor {
    pub id: u32,
    pub address: String,
    pub owner: String,
    pub options: Json,
    pub interval_mins: u32,
    pub enabled: bool,
    pub created_at: u64,
    pub last_run_at: u64,
    pub last_summary: String,
}

impl Monitor {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::Int(self.id as i64)),
            ("address".into(), Json::str(&self.address)),
            ("owner".into(), Json::str(&self.owner)),
            ("options".into(), self.options.clone()),
            ("interval_mins".into(), Json::Int(self.interval_mins as i64)),
            ("enabled".into(), Json::Bool(self.enabled)),
            ("created_at".into(), Json::Int(self.created_at as i64)),
            ("last_run_at".into(), Json::Int(self.last_run_at as i64)),
            ("last_summary".into(), Json::str(&self.last_summary)),
            (
                "due".into(),
                Json::Bool(self.due(crate::delivery::now_secs())),
            ),
        ])
    }
    pub fn due(&self, now: u64) -> bool {
        self.enabled && now.saturating_sub(self.last_run_at) >= self.interval_mins as u64 * 60
    }
    /// The test inputs this monitor runs with.
    pub fn inputs(&self) -> Result<Inputs, String> {
        let o = &self.options;
        crate::deliveryrun::parse_inputs(
            &self.address,
            o.get("ip").and_then(Json::as_str),
            o.get("selector").and_then(Json::as_str),
            o.get("days").and_then(Json::as_i64),
            matches!(o.get("audit"), Some(Json::Bool(true))),
            true,
            if self.owner.is_empty() {
                None
            } else {
                Some(self.owner.clone())
            },
        )
    }
}

fn row_to_monitor(r: &[String]) -> Option<Monitor> {
    Some(Monitor {
        id: r.first()?.parse().ok()?,
        address: r.get(1)?.clone(),
        owner: r.get(2)?.clone(),
        options: Json::parse(r.get(3)?).unwrap_or(Json::Object(vec![])),
        interval_mins: r.get(4)?.parse().unwrap_or(DEFAULT_INTERVAL_MINS),
        enabled: r.get(5).map(|v| v == "1").unwrap_or(true),
        created_at: r.get(6)?.parse().unwrap_or(0),
        last_run_at: r.get(7)?.parse().unwrap_or(0),
        last_summary: r.get(8).cloned().unwrap_or_default(),
    })
}

const COLS: &str =
    "id, address, owner, options, interval_mins, enabled, created_at, last_run_at, last_summary";

/// Monitors, optionally those of one owner (the end-user variant).
pub fn list(cfg: &Config, owner: Option<&str>) -> std::io::Result<Vec<Monitor>> {
    let filter = owner
        .map(|o| format!(" WHERE owner = {}", db::quote(o)))
        .unwrap_or_default();
    let rows = db::query(
        cfg,
        &format!("SELECT {COLS} FROM delivery_monitors{filter} ORDER BY address"),
    )?;
    Ok(rows.iter().filter_map(|r| row_to_monitor(r)).collect())
}

pub fn get(cfg: &Config, id: u32) -> std::io::Result<Option<Monitor>> {
    let rows = db::query(
        cfg,
        &format!("SELECT {COLS} FROM delivery_monitors WHERE id = {id}"),
    )?;
    Ok(rows.first().and_then(|r| row_to_monitor(r)))
}

/// Add a monitor (or update the interval/options of the existing one for
/// the address). Enforces the interval bounds and the monitor cap.
pub fn add(
    cfg: &Config,
    inputs: &Inputs,
    interval_mins: u32,
    owner: &str,
) -> Result<Monitor, String> {
    let interval = interval_mins.clamp(MIN_INTERVAL_MINS, MAX_INTERVAL_MINS);
    let existing = list(cfg, None).map_err(|e| e.to_string())?;
    let addr = inputs.address.to_ascii_lowercase();
    let already = existing
        .iter()
        .find(|m| m.address == addr && m.owner == owner);
    if already.is_none() && existing.len() >= cfg.delivery_max_monitors as usize {
        return Err(format!(
            "the limit of {} monitors is reached (delivery_max_monitors)",
            cfg.delivery_max_monitors
        ));
    }
    let options = Json::Object(vec![
        (
            "ip".into(),
            inputs
                .ip
                .map(|i| Json::str(i.to_string()))
                .unwrap_or(Json::Null),
        ),
        (
            "selector".into(),
            inputs.selector.clone().map(Json::Str).unwrap_or(Json::Null),
        ),
        ("days".into(), Json::Int(inputs.days as i64)),
        ("audit".into(), Json::Bool(inputs.audit)),
    ]);
    let now = crate::delivery::now_secs();
    let sql = format!(
        "INSERT INTO delivery_monitors (address, owner, options, interval_mins, enabled, created_at) VALUES ({}, {}, {}, {interval}, 1, {now}) \
         ON DUPLICATE KEY UPDATE options = VALUES(options), interval_mins = VALUES(interval_mins), enabled = 1;\n",
        db::quote(&addr),
        db::quote(owner),
        db::quote(&options.to_string())
    );
    db::exec_stdin(cfg, &sql).map_err(|e| e.to_string())?;
    list(cfg, None)
        .map_err(|e| e.to_string())?
        .into_iter()
        .find(|m| m.address == addr && m.owner == owner)
        .ok_or_else(|| "the monitor was not stored".into())
}

pub fn remove(cfg: &Config, id: u32, owner: Option<&str>) -> std::io::Result<bool> {
    let filter = owner
        .map(|o| format!(" AND owner = {}", db::quote(o)))
        .unwrap_or_default();
    let before = get(cfg, id)?;
    db::exec_stdin(cfg, &format!("DELETE FROM delivery_runs WHERE monitor_id = {id};\nDELETE FROM delivery_monitors WHERE id = {id}{filter};\n"))?;
    Ok(before.is_some())
}

pub fn set_enabled(cfg: &Config, id: u32, enabled: bool) -> std::io::Result<()> {
    db::exec_stdin(
        cfg,
        &format!(
            "UPDATE delivery_monitors SET enabled = {} WHERE id = {id};\n",
            if enabled { 1 } else { 0 }
        ),
    )
}

/// One stored run.
#[derive(Debug, Clone, PartialEq)]
pub struct RunRow {
    pub id: u32,
    pub monitor_id: u32,
    pub started_at: u64,
    pub duration_ms: u64,
    pub n_pass: u32,
    pub n_warn: u32,
    pub n_fail: u32,
    pub n_unknown: u32,
}

impl RunRow {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::Int(self.id as i64)),
            ("monitor_id".into(), Json::Int(self.monitor_id as i64)),
            ("started_at".into(), Json::Int(self.started_at as i64)),
            ("duration_ms".into(), Json::Int(self.duration_ms as i64)),
            ("fail".into(), Json::Int(self.n_fail as i64)),
            ("warn".into(), Json::Int(self.n_warn as i64)),
            ("unknown".into(), Json::Int(self.n_unknown as i64)),
            ("pass".into(), Json::Int(self.n_pass as i64)),
        ])
    }
}

fn totals(r: &Report) -> (u32, u32, u32, u32) {
    let mut t = (0, 0, 0, 0);
    for c in &r.checks {
        match c.verdict {
            Verdict::Pass => t.0 += 1,
            Verdict::Warn => t.1 += 1,
            Verdict::Fail => t.2 += 1,
            Verdict::Unknown => t.3 += 1,
            Verdict::NotApplicable => {}
        }
    }
    t
}

pub fn summary_line(r: &Report) -> String {
    let (p, w, f, u) = totals(r);
    format!("{f} fail, {w} warn, {u} unknown, {p} pass")
}

/// Store a run and trim the history.
pub fn store_run(cfg: &Config, monitor_id: u32, r: &Report) -> std::io::Result<u32> {
    let (p, w, f, u) = totals(r);
    let dur = r.finished.unwrap_or(r.started).saturating_sub(r.started) * 1000;
    let sql = format!(
        "INSERT INTO delivery_runs (monitor_id, started_at, duration_ms, n_pass, n_warn, n_fail, n_unknown, report) VALUES ({monitor_id}, {}, {dur}, {p}, {w}, {f}, {u}, {});\n\
         UPDATE delivery_monitors SET last_run_at = {}, last_summary = {} WHERE id = {monitor_id};\n\
         DELETE FROM delivery_runs WHERE monitor_id = {monitor_id} AND id NOT IN (SELECT id FROM (SELECT id FROM delivery_runs WHERE monitor_id = {monitor_id} ORDER BY started_at DESC LIMIT {KEEP_RUNS}) AS keep);\n",
        r.started,
        db::quote(&r.to_json().to_string()),
        r.finished.unwrap_or(r.started),
        db::quote(&summary_line(r))
    );
    db::exec_stdin(cfg, &sql)?;
    let rows = db::query(
        cfg,
        &format!(
            "SELECT id FROM delivery_runs WHERE monitor_id = {monitor_id} ORDER BY id DESC LIMIT 1"
        ),
    )?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

pub fn runs(cfg: &Config, monitor_id: u32, limit: u32) -> std::io::Result<Vec<RunRow>> {
    let rows = db::query(cfg, &format!("SELECT id, monitor_id, started_at, duration_ms, n_pass, n_warn, n_fail, n_unknown FROM delivery_runs WHERE monitor_id = {monitor_id} ORDER BY started_at DESC LIMIT {}", limit.clamp(1, 1000)))?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            Some(RunRow {
                id: r.first()?.parse().ok()?,
                monitor_id: r.get(1)?.parse().ok()?,
                started_at: r.get(2)?.parse().ok()?,
                duration_ms: r.get(3)?.parse().unwrap_or(0),
                n_pass: r.get(4)?.parse().unwrap_or(0),
                n_warn: r.get(5)?.parse().unwrap_or(0),
                n_fail: r.get(6)?.parse().unwrap_or(0),
                n_unknown: r.get(7)?.parse().unwrap_or(0),
            })
        })
        .collect())
}

/// The full report of a stored run.
pub fn run_report(cfg: &Config, run_id: u32) -> std::io::Result<Option<Report>> {
    let rows = db::query(
        cfg,
        &format!("SELECT report FROM delivery_runs WHERE id = {run_id}"),
    )?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .and_then(|t| Json::parse(t).ok())
        .and_then(|j| Report::from_json(&j)))
}

/// The previous run's report (before `before_run_id`), for comparison.
fn previous_report(cfg: &Config, monitor_id: u32, before_run_id: u32) -> Option<Report> {
    let rows = db::query(cfg, &format!("SELECT report FROM delivery_runs WHERE monitor_id = {monitor_id} AND id < {before_run_id} ORDER BY id DESC LIMIT 1")).ok()?;
    rows.first()
        .and_then(|r| r.first())
        .and_then(|t| Json::parse(t).ok())
        .and_then(|j| Report::from_json(&j))
}

/// A check that changed between two runs.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub id: String,
    pub target: Option<String>,
    pub from: Verdict,
    pub to: Verdict,
    pub title: String,
}

/// Checks that got worse (pass→warn/fail, warn→fail) or unknown twice in a
/// row, and the ones that recovered.
pub fn regressions(prev: &Report, cur: &Report) -> (Vec<Change>, Vec<Change>) {
    let rank = |v: Verdict| match v {
        Verdict::Pass | Verdict::NotApplicable => 0,
        Verdict::Unknown => 1,
        Verdict::Warn => 2,
        Verdict::Fail => 3,
    };
    let key =
        |c: &crate::delivery::Check| format!("{}|{}", c.id, c.target.clone().unwrap_or_default());
    let prev_map: std::collections::HashMap<String, &crate::delivery::Check> =
        prev.checks.iter().map(|c| (key(c), c)).collect();
    let mut worse = Vec::new();
    let mut better = Vec::new();
    for c in &cur.checks {
        let Some(p) = prev_map.get(&key(c)) else {
            continue;
        };
        if p.verdict == c.verdict {
            continue;
        }
        let ch = Change {
            id: c.id.clone(),
            target: c.target.clone(),
            from: p.verdict,
            to: c.verdict,
            title: c.title.clone(),
        };
        // unknown is not a regression by itself (a lookup failed); a drop
        // from unknown to pass is not a recovery worth a message either
        match (p.verdict, c.verdict) {
            (_, Verdict::Unknown) | (Verdict::Unknown, _) => {}
            _ if rank(c.verdict) > rank(p.verdict) => worse.push(ch),
            _ if rank(c.verdict) < rank(p.verdict) => better.push(ch),
            _ => {}
        }
    }
    (worse, better)
}

/// Run every due monitor. Returns the notes for the cron's output.
pub fn run_due(cfg: &Config, dry: bool) -> Vec<String> {
    let mut notes = Vec::new();
    // no table yet (migration pending), DB down or not configured: monitors
    // are opt-in, so the cron stays quiet rather than mailing root every
    // five minutes — the tab shows the error when someone looks
    let Ok(monitors) = list(cfg, None) else {
        return notes;
    };
    let now = crate::delivery::now_secs();
    for m in monitors.iter().filter(|m| m.due(now)) {
        if dry {
            notes.push(format!(
                "delivery monitor {}: due (every {} min) — dry run, not started",
                m.address, m.interval_mins
            ));
            continue;
        }
        let inputs = match m.inputs() {
            Ok(i) => i,
            Err(e) => {
                notes.push(format!("delivery monitor {}: bad options: {e}", m.address));
                continue;
            }
        };
        let report =
            crate::deliveryrun::run_blocking(cfg, inputs, crate::deliveryrun::plan, &mut |_| {});
        let run_id = match store_run(cfg, m.id, &report) {
            Ok(id) => id,
            Err(e) => {
                notes.push(format!(
                    "delivery monitor {}: cannot store the run: {e}",
                    m.address
                ));
                continue;
            }
        };
        notes.push(format!(
            "delivery monitor {}: {}",
            m.address,
            summary_line(&report)
        ));
        if let Some(prev) = previous_report(cfg, m.id, run_id) {
            let (worse, better) = regressions(&prev, &report);
            if worse.is_empty() && better.is_empty() {
                continue;
            }
            let key = format!("alert_delivery_{}", m.id);
            let cooled = db::kv_get(cfg, &key)
                .and_then(|v| v.parse::<u64>().ok())
                .map(|last| now.saturating_sub(last) >= cfg.alert_cooldown_mins.max(1) as u64 * 60)
                .unwrap_or(true);
            if !cooled {
                notes.push(format!("delivery monitor {}: {} regression(s), {} recovery(ies) — alert suppressed by the cooldown", m.address, worse.len(), better.len()));
                continue;
            }
            let mut text = format!(
                "Delivery test of {} on {}:\n",
                m.address,
                crate::diaginbox::hostname(cfg)
            );
            for w in &worse {
                text.push_str(&format!(
                    "⚠ {} → {}: {}{}\n",
                    w.from.as_str(),
                    w.to.as_str(),
                    w.title,
                    w.target
                        .as_ref()
                        .map(|t| format!(" [{t}]"))
                        .unwrap_or_default()
                ));
            }
            for b in &better {
                text.push_str(&format!(
                    "✓ {} → {}: {}{}\n",
                    b.from.as_str(),
                    b.to.as_str(),
                    b.title,
                    b.target
                        .as_ref()
                        .map(|t| format!(" [{t}]"))
                        .unwrap_or_default()
                ));
            }
            text.push_str(&format!("now {}", summary_line(&report)));
            if crate::telegram::configured(cfg) {
                match crate::telegram::send(cfg, &text) {
                    Ok(()) => {
                        let _ = db::kv_set(cfg, &key, &now.to_string());
                        notes.push(format!(
                            "delivery monitor {}: Telegram alert sent ({} worse, {} better)",
                            m.address,
                            worse.len(),
                            better.len()
                        ));
                    }
                    Err(e) => notes.push(format!(
                        "delivery monitor {}: Telegram failed: {e}",
                        m.address
                    )),
                }
            } else {
                notes.push(format!(
                    "delivery monitor {}: changes ({} worse, {} better) — Telegram not configured",
                    m.address,
                    worse.len(),
                    better.len()
                ));
            }
        }
    }
    notes
}

/// Runs older than `days` go (the per-monitor cap already bounds the table).
pub fn prune(cfg: &Config, days: u32) -> std::io::Result<()> {
    let cutoff = crate::delivery::now_secs().saturating_sub(days.max(1) as u64 * 86_400);
    db::exec_stdin(
        cfg,
        &format!("DELETE FROM delivery_runs WHERE started_at < {cutoff};\n"),
    )
}

/// CSV of a monitor's history (one line per run).
pub fn history_csv(rows: &[RunRow]) -> String {
    let mut s = String::from("run_id,started_at,duration_ms,fail,warn,unknown,pass\n");
    for r in rows {
        s.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            r.id, r.started_at, r.duration_ms, r.n_fail, r.n_warn, r.n_unknown, r.n_pass
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{Category, Check, Scope, Severity};

    fn report(checks: Vec<(&str, Option<&str>, Verdict)>) -> Report {
        Report {
            id: "r".into(),
            inputs: crate::deliveryrun::parse_inputs(
                "a@x.test", None, None, None, false, false, None,
            )
            .unwrap(),
            started: 1,
            finished: Some(2),
            done: true,
            planned: vec![],
            checks: checks
                .into_iter()
                .map(|(id, t, v)| {
                    let c =
                        Check::new(id, Scope::Sending, Category::Dns, v, Severity::Info, id, "");
                    match t {
                        Some(t) => c.target(t),
                        None => c,
                    }
                })
                .collect(),
            tool_notes: vec![],
            cached: false,
        }
    }

    #[test]
    fn regressions_and_recoveries() {
        let prev = report(vec![
            ("a", None, Verdict::Pass),
            ("b", None, Verdict::Warn),
            ("c", Some("x"), Verdict::Pass),
            ("d", None, Verdict::Unknown),
            ("e", None, Verdict::Fail),
        ]);
        let cur = report(vec![
            ("a", None, Verdict::Fail),
            ("b", None, Verdict::Pass),
            ("c", Some("x"), Verdict::Unknown),
            ("d", None, Verdict::Fail),
            ("e", None, Verdict::Fail),
            ("new", None, Verdict::Fail),
        ]);
        let (worse, better) = regressions(&prev, &cur);
        assert_eq!(
            worse.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["a"],
            "pass→fail; unknown transitions and new checks are not regressions"
        );
        assert_eq!(
            better.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(),
            vec!["b"]
        );
        assert_eq!(summary_line(&cur), "4 fail, 0 warn, 1 unknown, 1 pass");
        let m = Monitor {
            id: 1,
            address: "a@x.test".into(),
            owner: String::new(),
            options: Json::parse(
                r#"{"ip":"185.199.108.25","selector":null,"days":3,"audit":true}"#,
            )
            .unwrap(),
            interval_mins: 60,
            enabled: true,
            created_at: 0,
            last_run_at: 1000,
            last_summary: String::new(),
        };
        assert!(!m.due(1000 + 3599));
        assert!(m.due(1000 + 3600));
        let i = m.inputs().unwrap();
        assert_eq!(
            (i.ip.map(|x| x.to_string()), i.days, i.audit),
            (Some("185.199.108.25".into()), 3, true)
        );
        assert!(history_csv(&[RunRow {
            id: 1,
            monitor_id: 1,
            started_at: 5,
            duration_ms: 10,
            n_pass: 3,
            n_warn: 1,
            n_fail: 0,
            n_unknown: 2
        }])
        .ends_with("1,5,10,0,1,2,3\n"));
    }
}
