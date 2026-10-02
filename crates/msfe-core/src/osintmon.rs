//! OSINT monitors: an address checked on a schedule with the source set
//! approved when it was added. This is the data layer: the `Store` the
//! scheduler and the API code against, its MySQL implementation (every
//! statement is built by a pure function and every dynamic value goes
//! through `db::quote` or is an integer formatted here) and an in-memory
//! store for tests.

use crate::config::Config;
use crate::db;
use crate::json::Json;
use crate::osint::{Finding, Group, OsintReport, RunState, Severity, SourceState};
use crate::osintproviders::clean_text;

pub const MIN_INTERVAL_MINS: u32 = 1440;
pub const MAX_INTERVAL_MINS: u32 = 10080;
pub const DEFAULT_INTERVAL_MINS: u32 = 1440;
/// Runs kept per monitor.
pub const KEEP_RUNS: usize = 100;
/// Monitors run per `msfe-ng monitor` pass.
pub const MAX_PER_PASS: usize = 2;

#[derive(Debug, Clone, PartialEq)]
pub struct Monitor {
    pub id: u32,
    pub address: String,
    pub owner: String,
    pub sources: Vec<String>,
    pub interval_mins: u32,
    pub enabled: bool,
    pub created_at: u64,
    pub last_run_at: u64,
    pub last_summary: String,
}

impl Monitor {
    pub fn due(&self, now: u64) -> bool {
        self.enabled && now.saturating_sub(self.last_run_at) >= self.interval_mins as u64 * 60
    }
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::Int(self.id as i64)),
            ("address".into(), Json::str(&self.address)),
            ("owner".into(), Json::str(&self.owner)),
            (
                "sources".into(),
                Json::Array(self.sources.iter().map(Json::str).collect()),
            ),
            ("interval_mins".into(), Json::Int(self.interval_mins as i64)),
            ("enabled".into(), Json::Bool(self.enabled)),
            ("created_at".into(), Json::Int(self.created_at as i64)),
            ("last_run_at".into(), Json::Int(self.last_run_at as i64)),
            ("last_summary".into(), Json::str(&self.last_summary)),
            ("due".into(), Json::Bool(self.due(crate::osint::now_secs()))),
        ])
    }
}

/// One stored run (the report itself is fetched separately).
#[derive(Debug, Clone, PartialEq)]
pub struct RunRow {
    pub id: u32,
    pub monitor_id: u32,
    pub started_at: u64,
    pub duration_ms: u32,
    pub state: String,
    pub n_findings: u32,
    pub n_sources_ok: u32,
    pub n_sources_bad: u32,
}

impl RunRow {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::Int(self.id as i64)),
            ("monitor_id".into(), Json::Int(self.monitor_id as i64)),
            ("started_at".into(), Json::Int(self.started_at as i64)),
            ("duration_ms".into(), Json::Int(self.duration_ms as i64)),
            ("state".into(), Json::str(&self.state)),
            ("findings".into(), Json::Int(self.n_findings as i64)),
            ("sources_ok".into(), Json::Int(self.n_sources_ok as i64)),
            ("sources_bad".into(), Json::Int(self.n_sources_bad as i64)),
        ])
    }
}

// ---- pure helpers -----------------------------------------------------------

pub fn clamp_interval(mins: u32) -> u32 {
    if mins < MIN_INTERVAL_MINS {
        MIN_INTERVAL_MINS
    } else {
        mins.min(MAX_INTERVAL_MINS)
    }
}

/// The approved source set of a new monitor: known ids only, never
/// `delivery`, de-duplicated in input order, at least one. `hunter` is kept
/// only because the caller named it (nothing is added here).
pub fn validate_sources(input: &[String], _cfg: &Config) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for s in input {
        let id = s.trim();
        if id == crate::osintproviders::DELIVERY_ID {
            return Err("the delivery test cannot be monitored here".into());
        }
        if !valid_id(id) || !crate::osintproviders::is_known(id) {
            return Err(format!(
                "unknown source \"{}\"",
                id.chars().take(40).collect::<String>()
            ));
        }
        if !out.iter().any(|o| o == id) {
            out.push(id.to_string());
        }
    }
    if out.is_empty() {
        return Err("choose at least one source".into());
    }
    Ok(out)
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The sources column, read defensively: only well-formed ids survive.
pub fn parse_sources(col: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in col.split(',') {
        let p = p.trim();
        if valid_id(p) && !out.iter().any(|o| o == p) {
            out.push(p.to_string());
        }
    }
    out
}

/// `YYYYMM` of a Unix timestamp (UTC): the metering period.
pub fn period_for(unix_secs: u64) -> String {
    let d = crate::civil::Date::from_unix(unix_secs);
    format!("{:04}{:02}", d.y, d.m)
}

/// Stored reports carry no avatar references (the assets expire).
pub fn strip_assets(r: &mut OsintReport) {
    for f in &mut r.findings {
        f.asset_id = None;
        f.asset_mime = None;
    }
}

/// The `mysql` client connects with a 3-byte UTF-8 charset, which rejects
/// characters beyond the BMP (emoji in a profile name, say). In JSON text
/// they are written as `\\uD83D\\uDE00` escapes instead, which parse back
/// to the same character.
pub fn bmp_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c as u32) > 0xFFFF {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Plain text for a column: characters beyond the BMP become U+FFFD.
pub fn bmp_only(s: &str) -> String {
    s.chars()
        .map(|c| if (c as u32) > 0xFFFF { '\u{fffd}' } else { c })
        .collect()
}

/// A summary as stored: no characters beyond the BMP, at most 255 characters
/// (the column is VARCHAR(255); a longer value would fail the UPDATE).
pub fn summary_for_column(s: &str) -> String {
    bmp_only(s).chars().take(255).collect()
}

/// The mysql client's duplicate-key error for `usage_reserve` becomes the
/// same message the in-memory store gives.
pub fn map_usage_error(e: &str) -> String {
    if e.contains("Duplicate entry") || e.contains("ERROR 1062") {
        "duplicate run id".to_string()
    } else {
        e.to_string()
    }
}

fn valid_period(p: &str) -> bool {
    p.len() == 6 && p.bytes().all(|b| b.is_ascii_digit())
}

fn valid_run_key(r: &str) -> bool {
    !r.is_empty()
        && r.len() <= 32
        && r.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn source_counts(r: &OsintReport) -> (u32, u32) {
    let mut ok = 0;
    let mut bad = 0;
    for s in &r.sources {
        match s.state {
            SourceState::Matched | SourceState::NoMatch | SourceState::Inconclusive => ok += 1,
            SourceState::Failed | SourceState::Restricted | SourceState::RateLimited => bad += 1,
            _ => {}
        }
    }
    (ok, bad)
}

// ---- SQL builders -------------------------------------------------------------

const COLS: &str =
    "id, address, owner, sources, interval_mins, enabled, created_at, last_run_at, last_summary";

pub fn sql_select_monitors(owner: Option<&str>) -> String {
    let filter = owner
        .map(|o| format!(" WHERE owner = {}", db::quote(o)))
        .unwrap_or_default();
    format!("SELECT {COLS} FROM osint_monitors{filter} ORDER BY address, owner")
}

pub fn sql_select_monitor(id: u32) -> String {
    format!("SELECT {COLS} FROM osint_monitors WHERE id = {id}")
}

pub fn sql_insert_monitor(
    address: &str,
    owner: &str,
    sources: &[String],
    interval_mins: u32,
    now: u64,
) -> String {
    format!(
        "INSERT INTO osint_monitors (address, owner, sources, interval_mins, enabled, created_at) VALUES ({}, {}, {}, {interval_mins}, 1, {now}) \
         ON DUPLICATE KEY UPDATE sources = VALUES(sources), interval_mins = VALUES(interval_mins), enabled = 1;\n",
        db::quote(address),
        db::quote(owner),
        db::quote(&sources.join(","))
    )
}

pub fn sql_set_enabled(id: u32, enabled: bool) -> String {
    format!(
        "UPDATE osint_monitors SET enabled = {} WHERE id = {id};\n",
        enabled as u8
    )
}

pub fn sql_touch_last_run(id: u32, when: u64) -> String {
    format!("UPDATE osint_monitors SET last_run_at = {when} WHERE id = {id};\n")
}

/// Removing a monitor removes its runs, its usage rows and its kv keys
/// (`osint_base_<id>`, `alert_osint_<id>_*`; the `_` are escaped for LIKE).
pub fn sql_remove(id: u32) -> String {
    format!(
        "DELETE FROM osint_runs WHERE monitor_id = {id};\n\
         DELETE FROM osint_usage WHERE monitor_id = {id};\n\
         DELETE FROM msfe_config WHERE scope = 'global' AND scope_id = '' AND (ckey = 'osint_base_{id}' OR ckey LIKE 'alert\\\\_osint\\\\_{id}\\\\_%');\n\
         DELETE FROM osint_monitors WHERE id = {id};\n"
    )
}

pub fn sql_trim_runs(monitor_id: u32) -> String {
    format!(
        "DELETE FROM osint_runs WHERE monitor_id = {monitor_id} AND id NOT IN (SELECT id FROM (SELECT id FROM osint_runs WHERE monitor_id = {monitor_id} ORDER BY id DESC LIMIT {KEEP_RUNS}) AS keep);\n"
    )
}

#[allow(clippy::too_many_arguments)]
pub fn sql_store_run(
    monitor_id: u32,
    report_json: &str,
    started_at: u64,
    duration_ms: u32,
    state: &str,
    n_findings: u32,
    n_ok: u32,
    n_bad: u32,
    last_run_at: u64,
    summary: &str,
) -> String {
    format!(
        "START TRANSACTION;\nINSERT INTO osint_runs (monitor_id, started_at, duration_ms, state, n_findings, n_sources_ok, n_sources_bad, report) VALUES ({monitor_id}, {started_at}, {duration_ms}, {}, {n_findings}, {n_ok}, {n_bad}, {});\n\
         UPDATE osint_monitors SET last_run_at = {last_run_at}, last_summary = {} WHERE id = {monitor_id};\n{}COMMIT;\n",
        db::quote(state),
        db::quote(report_json),
        db::quote(summary),
        sql_trim_runs(monitor_id)
    )
}

pub fn sql_runs(monitor_id: u32, limit: usize) -> String {
    format!(
        "SELECT id, monitor_id, started_at, duration_ms, state, n_findings, n_sources_ok, n_sources_bad FROM osint_runs WHERE monitor_id = {monitor_id} ORDER BY id DESC LIMIT {}",
        limit.clamp(1, 1000)
    )
}

pub fn sql_latest_run_id(monitor_id: u32) -> String {
    format!("SELECT id FROM osint_runs WHERE monitor_id = {monitor_id} ORDER BY id DESC LIMIT 1")
}

pub fn sql_run_report(run_id: u32) -> String {
    format!("SELECT report FROM osint_runs WHERE id = {run_id}")
}

pub fn sql_run_by_id(run_id: u32) -> String {
    format!("SELECT monitor_id, report FROM osint_runs WHERE id = {run_id}")
}

pub fn sql_previous_run(monitor_id: u32, before_run_id: u32) -> String {
    format!("SELECT id, report FROM osint_runs WHERE monitor_id = {monitor_id} AND id < {before_run_id} ORDER BY id DESC LIMIT 1")
}

pub fn sql_usage_month(period: &str) -> String {
    format!(
        "SELECT COALESCE(SUM(COALESCE(final_units, reserved)), 0) FROM osint_usage WHERE period = {}",
        db::quote(period)
    )
}

pub fn sql_usage_reserve(
    monitor_id: u32,
    period: &str,
    units: u32,
    run_id: &str,
    now: u64,
) -> String {
    format!(
        "INSERT INTO osint_usage (monitor_id, period, reserved, run_id, created_at) VALUES ({monitor_id}, {}, {units}, {}, {now});\n",
        db::quote(period),
        db::quote(run_id)
    )
}

pub fn sql_usage_settle(run_id: &str, final_units: u32) -> String {
    format!(
        "UPDATE osint_usage SET final_units = {final_units} WHERE run_id = {};\n",
        db::quote(run_id)
    )
}

pub fn sql_usage_release(run_id: &str) -> String {
    format!(
        "DELETE FROM osint_usage WHERE run_id = {};\n",
        db::quote(run_id)
    )
}

/// Retention: runs older than `days` go, except each monitor's latest run
/// (the comparison baseline); usage rows are kept for 400 days.
pub fn sql_prune(now: u64, days: u32) -> String {
    let cutoff = now.saturating_sub(days as u64 * 86_400);
    let usage_cutoff = now.saturating_sub(400 * 86_400);
    format!(
        "DELETE FROM osint_runs WHERE started_at < {cutoff} AND id NOT IN (SELECT mx FROM (SELECT MAX(id) AS mx FROM osint_runs GROUP BY monitor_id) AS latest);\n\
         DELETE FROM osint_usage WHERE created_at < {usage_cutoff};\n"
    )
}

// ---- the store ---------------------------------------------------------------------

pub trait Store {
    fn list(&self, owner: Option<&str>) -> Result<Vec<Monitor>, String>;
    fn get(&self, id: u32) -> Result<Option<Monitor>, String>;
    /// Add a monitor; an existing one for the same address (case-sensitive)
    /// and owner is updated (sources, interval, enabled) instead. The cap
    /// `max` applies to new monitors only.
    fn add(
        &self,
        address: &str,
        owner: &str,
        sources: &[String],
        interval_mins: u32,
        max: u32,
    ) -> Result<Monitor, String>;
    fn remove(&self, id: u32) -> Result<bool, String>;
    fn set_enabled(&self, id: u32, enabled: bool) -> Result<(), String>;
    fn store_run(
        &self,
        monitor_id: u32,
        report: &OsintReport,
        duration_ms: u32,
        summary: &str,
    ) -> Result<u32, String>;
    fn runs(&self, monitor_id: u32, limit: usize) -> Result<Vec<RunRow>, String>;
    fn run_report(&self, run_id: u32) -> Result<Option<OsintReport>, String>;
    /// The run with the next-lower id of the same monitor: `(run id, report)`.
    fn previous_run(
        &self,
        monitor_id: u32,
        before_run_id: u32,
    ) -> Result<Option<(u32, OsintReport)>, String>;
    /// A run by id: `(monitor id, report)`.
    fn run_by_id(&self, id: u32) -> Result<Option<(u32, OsintReport)>, String>;
    fn usage_month(&self, period: &str) -> Result<u32, String>;
    /// Reserve units for a run; a second reservation for the same `run_id` is an error.
    fn usage_reserve(
        &self,
        monitor_id: u32,
        period: &str,
        units: u32,
        run_id: &str,
    ) -> Result<(), String>;
    fn usage_settle(&self, run_id: &str, final_units: u32) -> Result<(), String>;
    fn usage_release(&self, run_id: &str) -> Result<(), String>;
    fn kv_get(&self, key: &str) -> Option<String>;
    fn kv_set(&self, key: &str, value: &str) -> Result<(), String>;
    fn touch_last_run(&self, id: u32, when: u64) -> Result<(), String>;
    fn prune(&self, days: u32) -> Result<(), String>;
}

fn parse_report(text: &str) -> Option<OsintReport> {
    Json::parse(text)
        .ok()
        .and_then(|j| OsintReport::from_json(&j).ok())
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

fn row_to_monitor(r: &[String]) -> Option<Monitor> {
    Some(Monitor {
        id: r.first()?.parse().ok()?,
        address: r.get(1)?.clone(),
        owner: r.get(2)?.clone(),
        sources: parse_sources(r.get(3)?),
        interval_mins: r
            .get(4)?
            .parse()
            .map(clamp_interval)
            .unwrap_or(DEFAULT_INTERVAL_MINS),
        enabled: r.get(5).map(|v| v == "1").unwrap_or(true),
        created_at: r.get(6)?.parse().unwrap_or(0),
        last_run_at: r.get(7)?.parse().unwrap_or(0),
        last_summary: r.get(8).cloned().unwrap_or_default(),
    })
}

fn limit_error(max: u32) -> String {
    format!("the limit of {max} monitors is reached (osint_max_monitors)")
}

pub struct MysqlStore<'a> {
    pub cfg: &'a Config,
}

impl<'a> MysqlStore<'a> {
    pub fn new(cfg: &'a Config) -> Self {
        MysqlStore { cfg }
    }
}

impl Store for MysqlStore<'_> {
    fn list(&self, owner: Option<&str>) -> Result<Vec<Monitor>, String> {
        let rows = db::query(self.cfg, &sql_select_monitors(owner)).map_err(io)?;
        Ok(rows.iter().filter_map(|r| row_to_monitor(r)).collect())
    }

    fn get(&self, id: u32) -> Result<Option<Monitor>, String> {
        let rows = db::query(self.cfg, &sql_select_monitor(id)).map_err(io)?;
        Ok(rows.first().and_then(|r| row_to_monitor(r)))
    }

    fn add(
        &self,
        address: &str,
        owner: &str,
        sources: &[String],
        interval_mins: u32,
        max: u32,
    ) -> Result<Monitor, String> {
        let interval = clamp_interval(interval_mins);
        let existing = self.list(None)?;
        let found = |m: &&Monitor| m.address == address && m.owner == owner;
        if existing.iter().find(found).is_none() && existing.len() >= max as usize {
            return Err(limit_error(max));
        }
        let sql = sql_insert_monitor(address, owner, sources, interval, crate::osint::now_secs());
        db::exec_stdin(self.cfg, &sql).map_err(io)?;
        self.list(None)?
            .into_iter()
            .find(|m| m.address == address && m.owner == owner)
            .ok_or_else(|| "the monitor was not stored".to_string())
    }

    fn remove(&self, id: u32) -> Result<bool, String> {
        let before = self.get(id)?;
        db::exec_stdin(self.cfg, &sql_remove(id)).map_err(io)?;
        Ok(before.is_some())
    }

    fn set_enabled(&self, id: u32, enabled: bool) -> Result<(), String> {
        db::exec_stdin(self.cfg, &sql_set_enabled(id, enabled)).map_err(io)
    }

    fn store_run(
        &self,
        monitor_id: u32,
        report: &OsintReport,
        duration_ms: u32,
        summary: &str,
    ) -> Result<u32, String> {
        let mut r = report.clone();
        strip_assets(&mut r);
        let (ok, bad) = source_counts(&r);
        let sql = sql_store_run(
            monitor_id,
            &bmp_escape(&r.to_json().to_string()),
            r.started,
            duration_ms,
            r.state.as_str(),
            r.findings.len() as u32,
            ok,
            bad,
            r.finished.unwrap_or(r.started),
            &summary_for_column(summary),
        );
        db::exec_stdin_captured(self.cfg, &sql).map_err(io)?;
        let rows = db::query(self.cfg, &sql_latest_run_id(monitor_id)).map_err(io)?;
        rows.first()
            .and_then(|r| r.first())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "the run was not stored".to_string())
    }

    fn runs(&self, monitor_id: u32, limit: usize) -> Result<Vec<RunRow>, String> {
        let rows = db::query(self.cfg, &sql_runs(monitor_id, limit)).map_err(io)?;
        Ok(rows
            .iter()
            .filter_map(|r| {
                Some(RunRow {
                    id: r.first()?.parse().ok()?,
                    monitor_id: r.get(1)?.parse().ok()?,
                    started_at: r.get(2)?.parse().ok()?,
                    duration_ms: r.get(3)?.parse().unwrap_or(0),
                    state: r.get(4)?.clone(),
                    n_findings: r.get(5)?.parse().unwrap_or(0),
                    n_sources_ok: r.get(6)?.parse().unwrap_or(0),
                    n_sources_bad: r.get(7)?.parse().unwrap_or(0),
                })
            })
            .collect())
    }

    fn run_report(&self, run_id: u32) -> Result<Option<OsintReport>, String> {
        let rows = db::query(self.cfg, &sql_run_report(run_id)).map_err(io)?;
        Ok(rows
            .first()
            .and_then(|r| r.first())
            .and_then(|t| parse_report(t)))
    }

    fn previous_run(
        &self,
        monitor_id: u32,
        before_run_id: u32,
    ) -> Result<Option<(u32, OsintReport)>, String> {
        let rows = db::query(self.cfg, &sql_previous_run(monitor_id, before_run_id)).map_err(io)?;
        Ok(rows
            .first()
            .and_then(|r| Some((r.first()?.parse().ok()?, parse_report(r.get(1)?)?))))
    }

    fn run_by_id(&self, id: u32) -> Result<Option<(u32, OsintReport)>, String> {
        let rows = db::query(self.cfg, &sql_run_by_id(id)).map_err(io)?;
        Ok(rows
            .first()
            .and_then(|r| Some((r.first()?.parse().ok()?, parse_report(r.get(1)?)?))))
    }

    fn usage_month(&self, period: &str) -> Result<u32, String> {
        if !valid_period(period) {
            return Err("invalid period".into());
        }
        let rows = db::query(self.cfg, &sql_usage_month(period)).map_err(io)?;
        Ok(rows
            .first()
            .and_then(|r| r.first())
            .and_then(|s| s.parse::<u64>().ok())
            .map(|n| n.min(u32::MAX as u64) as u32)
            .unwrap_or(0))
    }

    fn usage_reserve(
        &self,
        monitor_id: u32,
        period: &str,
        units: u32,
        run_id: &str,
    ) -> Result<(), String> {
        if !valid_period(period) || !valid_run_key(run_id) {
            return Err("invalid usage key".into());
        }
        let sql = sql_usage_reserve(monitor_id, period, units, run_id, crate::osint::now_secs());
        db::exec_stdin_captured(self.cfg, &sql).map_err(|e| map_usage_error(&e.to_string()))
    }

    fn usage_settle(&self, run_id: &str, final_units: u32) -> Result<(), String> {
        db::exec_stdin(self.cfg, &sql_usage_settle(run_id, final_units)).map_err(io)
    }

    fn usage_release(&self, run_id: &str) -> Result<(), String> {
        db::exec_stdin(self.cfg, &sql_usage_release(run_id)).map_err(io)
    }

    fn kv_get(&self, key: &str) -> Option<String> {
        db::kv_get(self.cfg, key)
    }

    fn kv_set(&self, key: &str, value: &str) -> Result<(), String> {
        db::kv_set(self.cfg, key, value).map_err(io)
    }

    fn touch_last_run(&self, id: u32, when: u64) -> Result<(), String> {
        db::exec_stdin(self.cfg, &sql_touch_last_run(id, when)).map_err(io)
    }

    fn prune(&self, days: u32) -> Result<(), String> {
        db::exec_stdin(self.cfg, &sql_prune(crate::osint::now_secs(), days)).map_err(io)
    }
}

// ---- in-memory store for tests -----------------------------------------------------------

#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct FakeState {
    pub monitors: Vec<Monitor>,
    /// (run id, monitor id, row, report json)
    pub runs: Vec<(RunRow, String)>,
    /// (monitor id, period, reserved, final, run key, created_at)
    pub usage: Vec<(u32, String, u32, Option<u32>, String, u64)>,
    pub kv: std::collections::BTreeMap<String, String>,
    pub fail_store_run: bool,
    next_monitor: u32,
    next_run: u32,
}

#[cfg(any(test, feature = "testing"))]
#[derive(Default)]
pub struct FakeStore {
    pub st: std::cell::RefCell<FakeState>,
}

#[cfg(any(test, feature = "testing"))]
impl FakeStore {
    /// The kv keys that belong to monitor `id` (exact: id 5 is not 55).
    pub fn remove_keys(&self, id: u32) {
        let base = format!("osint_base_{id}");
        let alert = format!("alert_osint_{id}_");
        self.st
            .borrow_mut()
            .kv
            .retain(|k, _| *k != base && !k.starts_with(&alert));
    }
}

#[cfg(any(test, feature = "testing"))]
impl Store for FakeStore {
    fn list(&self, owner: Option<&str>) -> Result<Vec<Monitor>, String> {
        let mut v: Vec<Monitor> = self
            .st
            .borrow()
            .monitors
            .iter()
            .filter(|m| owner.map(|o| m.owner == o).unwrap_or(true))
            .cloned()
            .collect();
        v.sort_by(|a, b| (&a.address, &a.owner).cmp(&(&b.address, &b.owner)));
        Ok(v)
    }
    fn get(&self, id: u32) -> Result<Option<Monitor>, String> {
        Ok(self
            .st
            .borrow()
            .monitors
            .iter()
            .find(|m| m.id == id)
            .cloned())
    }
    fn add(
        &self,
        address: &str,
        owner: &str,
        sources: &[String],
        interval_mins: u32,
        max: u32,
    ) -> Result<Monitor, String> {
        let mut s = self.st.borrow_mut();
        let interval = clamp_interval(interval_mins);
        if let Some(m) = s
            .monitors
            .iter_mut()
            .find(|m| m.address == address && m.owner == owner)
        {
            m.sources = sources.to_vec();
            m.interval_mins = interval;
            m.enabled = true;
            return Ok(m.clone());
        }
        if s.monitors.len() >= max as usize {
            return Err(limit_error(max));
        }
        s.next_monitor += 1;
        let m = Monitor {
            id: s.next_monitor,
            address: address.into(),
            owner: owner.into(),
            sources: sources.to_vec(),
            interval_mins: interval,
            enabled: true,
            created_at: crate::osint::now_secs(),
            last_run_at: 0,
            last_summary: String::new(),
        };
        s.monitors.push(m.clone());
        Ok(m)
    }
    fn remove(&self, id: u32) -> Result<bool, String> {
        let existed = self.get(id)?.is_some();
        {
            let mut s = self.st.borrow_mut();
            s.runs.retain(|(r, _)| r.monitor_id != id);
            s.usage.retain(|u| u.0 != id);
            s.monitors.retain(|m| m.id != id);
        }
        self.remove_keys(id);
        Ok(existed)
    }
    fn set_enabled(&self, id: u32, enabled: bool) -> Result<(), String> {
        if let Some(m) = self
            .st
            .borrow_mut()
            .monitors
            .iter_mut()
            .find(|m| m.id == id)
        {
            m.enabled = enabled;
        }
        Ok(())
    }
    fn store_run(
        &self,
        monitor_id: u32,
        report: &OsintReport,
        duration_ms: u32,
        summary: &str,
    ) -> Result<u32, String> {
        let mut r = report.clone();
        strip_assets(&mut r);
        let (ok, bad) = source_counts(&r);
        let mut s = self.st.borrow_mut();
        if s.fail_store_run {
            return Err("disk full".into());
        }
        s.next_run += 1;
        let id = s.next_run;
        s.runs.push((
            RunRow {
                id,
                monitor_id,
                started_at: r.started,
                duration_ms,
                state: r.state.as_str().to_string(),
                n_findings: r.findings.len() as u32,
                n_sources_ok: ok,
                n_sources_bad: bad,
            },
            r.to_json().to_string(),
        ));
        if let Some(m) = s.monitors.iter_mut().find(|m| m.id == monitor_id) {
            m.last_run_at = r.finished.unwrap_or(r.started);
            m.last_summary = summary.to_string();
        }
        let mine: Vec<u32> = s
            .runs
            .iter()
            .filter(|(r, _)| r.monitor_id == monitor_id)
            .map(|(r, _)| r.id)
            .collect();
        if mine.len() > KEEP_RUNS {
            let cut = mine[mine.len() - KEEP_RUNS];
            s.runs
                .retain(|(r, _)| r.monitor_id != monitor_id || r.id >= cut);
        }
        Ok(id)
    }
    fn runs(&self, monitor_id: u32, limit: usize) -> Result<Vec<RunRow>, String> {
        let mut v: Vec<RunRow> = self
            .st
            .borrow()
            .runs
            .iter()
            .filter(|(r, _)| r.monitor_id == monitor_id)
            .map(|(r, _)| r.clone())
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.id));
        v.truncate(limit.clamp(1, 1000));
        Ok(v)
    }
    fn run_report(&self, run_id: u32) -> Result<Option<OsintReport>, String> {
        Ok(self
            .st
            .borrow()
            .runs
            .iter()
            .find(|(r, _)| r.id == run_id)
            .and_then(|(_, j)| parse_report(j)))
    }
    fn previous_run(
        &self,
        monitor_id: u32,
        before_run_id: u32,
    ) -> Result<Option<(u32, OsintReport)>, String> {
        let s = self.st.borrow();
        Ok(s.runs
            .iter()
            .filter(|(r, _)| r.monitor_id == monitor_id && r.id < before_run_id)
            .max_by_key(|(r, _)| r.id)
            .and_then(|(r, j)| Some((r.id, parse_report(j)?))))
    }
    fn run_by_id(&self, id: u32) -> Result<Option<(u32, OsintReport)>, String> {
        let s = self.st.borrow();
        Ok(s.runs
            .iter()
            .find(|(r, _)| r.id == id)
            .and_then(|(r, j)| Some((r.monitor_id, parse_report(j)?))))
    }
    fn usage_month(&self, period: &str) -> Result<u32, String> {
        if !valid_period(period) {
            return Err("invalid period".into());
        }
        Ok(self
            .st
            .borrow()
            .usage
            .iter()
            .filter(|u| u.1 == period)
            .map(|u| u.3.unwrap_or(u.2))
            .sum())
    }
    fn usage_reserve(
        &self,
        monitor_id: u32,
        period: &str,
        units: u32,
        run_id: &str,
    ) -> Result<(), String> {
        if !valid_period(period) || !valid_run_key(run_id) {
            return Err("invalid usage key".into());
        }
        let mut s = self.st.borrow_mut();
        if s.usage.iter().any(|u| u.4 == run_id) {
            return Err("duplicate run id".into());
        }
        s.usage.push((
            monitor_id,
            period.into(),
            units,
            None,
            run_id.into(),
            crate::osint::now_secs(),
        ));
        Ok(())
    }
    fn usage_settle(&self, run_id: &str, final_units: u32) -> Result<(), String> {
        for u in self.st.borrow_mut().usage.iter_mut() {
            if u.4 == run_id {
                u.3 = Some(final_units);
            }
        }
        Ok(())
    }
    fn usage_release(&self, run_id: &str) -> Result<(), String> {
        self.st.borrow_mut().usage.retain(|u| u.4 != run_id);
        Ok(())
    }
    fn kv_get(&self, key: &str) -> Option<String> {
        self.st.borrow().kv.get(key).cloned()
    }
    fn kv_set(&self, key: &str, value: &str) -> Result<(), String> {
        self.st.borrow_mut().kv.insert(key.into(), value.into());
        Ok(())
    }
    fn touch_last_run(&self, id: u32, when: u64) -> Result<(), String> {
        if let Some(m) = self
            .st
            .borrow_mut()
            .monitors
            .iter_mut()
            .find(|m| m.id == id)
        {
            m.last_run_at = when;
        }
        Ok(())
    }
    fn prune(&self, days: u32) -> Result<(), String> {
        self.prune_at(crate::osint::now_secs(), days);
        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
impl FakeStore {
    /// Same semantics as `sql_prune`: runs older than `days` go except the
    /// latest run of every monitor id present in the runs; usage rows older
    /// than 400 days go.
    pub fn prune_at(&self, now: u64, days: u32) {
        let cutoff = now.saturating_sub(days as u64 * 86_400);
        let usage_cutoff = now.saturating_sub(400 * 86_400);
        let mut s = self.st.borrow_mut();
        let mut latest: std::collections::BTreeMap<u32, u32> = Default::default();
        for (r, _) in &s.runs {
            let e = latest.entry(r.monitor_id).or_insert(r.id);
            *e = (*e).max(r.id);
        }
        let keep: Vec<u32> = latest.values().copied().collect();
        s.runs
            .retain(|(r, _)| r.started_at >= cutoff || keep.contains(&r.id));
        s.usage.retain(|u| u.5 >= usage_cutoff);
    }
}

// ---- change detection (pure) ----

/// A finding as the monitor remembers it: only what an alert may show.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingRef {
    pub source_id: String,
    pub group: Group,
    pub title: String,
    pub source_url: Option<String>,
    pub severity: Severity,
}

/// A source whose usability changed between two runs.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceRef {
    pub id: String,
    pub from: SourceState,
    pub to: SourceState,
    pub detail: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Delta {
    pub new_findings: Vec<FindingRef>,
    pub gone_findings: Vec<FindingRef>,
    pub went_bad: Vec<SourceRef>,
    pub recovered: Vec<SourceRef>,
}

/// A URL as the key sees it: scheme and host in lower case, no fragment, no
/// trailing slash on the path; path and query keep their case. Text that is
/// not a `scheme://` URL is returned unchanged.
fn normalise_url(u: &str) -> String {
    let Some((scheme, rest)) = u.split_once("://") else {
        return u.to_string();
    };
    let rest = rest.split('#').next().unwrap_or("");
    let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (auth, tail) = rest.split_at(auth_end);
    let (path, query) = match tail.find('?') {
        Some(i) => tail.split_at(i),
        None => (tail, ""),
    };
    let auth = match auth.rsplit_once('@') {
        Some((user, host)) => format!("{user}@{}", host.to_ascii_lowercase()),
        None => auth.to_ascii_lowercase(),
    };
    format!(
        "{}://{}{}{}",
        scheme.to_ascii_lowercase(),
        auth,
        path.trim_end_matches('/'),
        query
    )
}

/// Stable identity of a finding: never the observation time, evidence,
/// confidence or severity.
pub fn finding_key(f: &Finding) -> String {
    format!(
        "{}|{}|{}",
        f.source_id,
        f.group.as_str(),
        f.source_url
            .as_deref()
            .map(normalise_url)
            .unwrap_or_else(|| f.title.clone())
    )
}

fn finding_ref(f: &Finding) -> FindingRef {
    FindingRef {
        source_id: f.source_id.clone(),
        group: f.group.clone(),
        title: f.title.clone(),
        source_url: f.source_url.clone(),
        severity: f.severity.clone(),
    }
}

fn answered(s: &SourceState) -> bool {
    matches!(s, SourceState::Matched | SourceState::NoMatch)
}
fn broken(s: &SourceState) -> bool {
    matches!(s, SourceState::Failed | SourceState::Restricted)
}

/// Compare two runs of the same monitor. Transitions to states that say
/// nothing about the source (rate limited, inconclusive, not configured, not
/// requested, unknown) are ignored, and a source that did not answer now
/// never makes its earlier findings "gone".
pub fn diff_reports(prev: &OsintReport, cur: &OsintReport) -> Delta {
    let mut d = Delta::default();
    let mut prev_keys: Vec<String> = Vec::new();
    for f in &prev.findings {
        let k = finding_key(f);
        if !prev_keys.contains(&k) {
            prev_keys.push(k);
        }
    }
    let mut cur_keys: Vec<String> = Vec::new();
    for f in &cur.findings {
        let k = finding_key(f);
        if cur_keys.contains(&k) {
            continue;
        }
        if !prev_keys.contains(&k) {
            d.new_findings.push(finding_ref(f));
        }
        cur_keys.push(k);
    }
    let mut seen: Vec<String> = Vec::new();
    for f in &prev.findings {
        let k = finding_key(f);
        if seen.contains(&k) {
            continue;
        }
        seen.push(k.clone());
        if cur_keys.contains(&k) {
            continue;
        }
        let src_answered = cur
            .sources
            .iter()
            .find(|s| s.id == f.source_id)
            .map(|s| answered(&s.state))
            .unwrap_or(false);
        if src_answered {
            d.gone_findings.push(finding_ref(f));
        }
    }
    for c in &cur.sources {
        let Some(p) = prev.sources.iter().find(|s| s.id == c.id) else {
            continue;
        };
        let r = SourceRef {
            id: c.id.clone(),
            from: p.state.clone(),
            to: c.state.clone(),
            detail: c.detail.clone(),
        };
        if answered(&p.state) && broken(&c.state) {
            d.went_bad.push(r);
        } else if broken(&p.state) && answered(&c.state) {
            d.recovered.push(r);
        }
    }
    d
}

/// `None` when there is no previous report: the first run (or a pruned
/// baseline) is a baseline run and never alerts.
pub fn diff_or_baseline(prev: Option<&OsintReport>, cur: &OsintReport) -> Option<Delta> {
    prev.map(|p| diff_reports(p, cur))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    Findings,
    Providers,
    Budget,
}

impl AlertKind {
    pub fn key_part(&self) -> &'static str {
        match self {
            AlertKind::Findings => "findings",
            AlertKind::Providers => "providers",
            AlertKind::Budget => "budget",
        }
    }
}

const MAX_ALERT_LINES: usize = 5;

fn alertable(g: &Group) -> bool {
    matches!(
        g,
        Group::Exposure | Group::Profile | Group::Reference | Group::Domain
    )
}

/// One message per kind that has something to say. Recoveries and findings
/// that are no longer listed are history only. Texts carry no evidence and
/// no URLs.
pub fn alert_texts(host: &str, address: &str, delta: &Delta) -> Vec<(AlertKind, String)> {
    let mut out = Vec::new();
    let new: Vec<&FindingRef> = delta
        .new_findings
        .iter()
        .filter(|f| alertable(&f.group))
        .collect();
    if !new.is_empty() {
        let mut s = format!(
            "OSINT watch of {address} on {host}: {} new public item(s)\n",
            new.len()
        );
        for f in new.iter().take(MAX_ALERT_LINES) {
            s.push_str(&format!(
                "• [{}] {}\n",
                f.group.as_str(),
                clean_text(&f.title, 100)
            ));
        }
        if new.len() > MAX_ALERT_LINES {
            s.push_str(&format!("…and {} more\n", new.len() - MAX_ALERT_LINES));
        }
        out.push((AlertKind::Findings, s.trim_end().to_string()));
    }
    if !delta.went_bad.is_empty() {
        let mut s = format!("OSINT watch of {address} on {host}: source problem\n");
        for r in delta.went_bad.iter().take(MAX_ALERT_LINES) {
            s.push_str(&format!(
                "• {}: answered before, now {} ({})\n",
                clean_text(&r.id, 40),
                r.to.as_str(),
                clean_text(&r.detail, 80)
            ));
        }
        if delta.went_bad.len() > MAX_ALERT_LINES {
            s.push_str(&format!(
                "…and {} more\n",
                delta.went_bad.len() - MAX_ALERT_LINES
            ));
        }
        out.push((AlertKind::Providers, s.trim_end().to_string()));
    }
    out
}

pub fn budget_text(host: &str, used: u32, cap: u32, period: &str) -> String {
    format!(
        "OSINT watch on {host}: monthly provider budget reached ({used} of {cap} units, period {period}). Scheduled checks are paused until next month or a higher osint_monitor_budget."
    )
}

/// True when the monitor's baseline may advance to the current run: nothing
/// needed an alert, or every needed alert was sent (or Telegram is not
/// configured). A failed send or a cooldown suppression keeps the old
/// baseline so the change is raised again.
pub fn baseline_decision(delta_has_alerts: bool, all_sent_or_unconfigured: bool) -> bool {
    !delta_has_alerts || all_sent_or_unconfigured
}

pub fn cooldown_ok(now: u64, last: Option<u64>, cooldown_mins: u32) -> bool {
    match last {
        None => true,
        Some(l) => now.saturating_sub(l) >= cooldown_mins as u64 * 60,
    }
}

// ---- the scheduler ------------------------------------------------------------------

/// Why a scheduled run did not produce a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunSkip {
    Disabled,
    Busy,
    RateLimited,
    TooManyRuns,
    Invalid(String),
    Failed(String),
}

pub trait Runner {
    fn run(&self, cfg: &Config, address: &str, sources: &[String]) -> Result<OsintReport, RunSkip>;
}

pub trait Notifier {
    fn configured(&self) -> bool;
    fn send(&self, text: &str) -> Result<(), String>;
    fn now(&self) -> u64;
    fn host(&self) -> String;
}

/// Runs the monitor's sources through the OSINT run controller, never from
/// the interactive cache.
pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&self, cfg: &Config, address: &str, sources: &[String]) -> Result<OsintReport, RunSkip> {
        use crate::osintrun::{self, StartError, StartOk};
        let inputs =
            osintrun::parse_inputs(address, sources, true, None).map_err(RunSkip::Invalid)?;
        let id = match osintrun::start(cfg, inputs) {
            Ok(StartOk::Started(id) | StartOk::Cached(id)) => id,
            Err(StartError::Disabled) => return Err(RunSkip::Disabled),
            Err(StartError::Busy(_)) => return Err(RunSkip::Busy),
            Err(StartError::RateLimited(_)) => return Err(RunSkip::RateLimited),
            Err(StartError::TooManyRuns) => return Err(RunSkip::TooManyRuns),
            Err(StartError::Invalid(e)) => return Err(RunSkip::Invalid(e)),
        };
        let limit = std::time::Duration::from_secs(cfg.osint_deadline_secs + 15);
        let t0 = std::time::Instant::now();
        loop {
            match osintrun::snapshot(&id) {
                Some(r) if r.state != RunState::Running => return Ok(r),
                Some(_) => {}
                None => return Err(RunSkip::Failed("the run vanished".into())),
            }
            if t0.elapsed() >= limit {
                osintrun::cancel(&id);
                return Err(RunSkip::Failed("timed out".into()));
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }
}

pub struct TelegramNotifier<'a>(pub &'a Config);

impl Notifier for TelegramNotifier<'_> {
    fn configured(&self) -> bool {
        crate::telegram::configured(self.0)
    }
    fn send(&self, text: &str) -> Result<(), String> {
        crate::telegram::send(self.0, text)
    }
    fn now(&self) -> u64 {
        crate::osint::now_secs()
    }
    fn host(&self) -> String {
        crate::diaginbox::hostname(self.0)
    }
}

/// Clears the "pass running" marker however the pass ends.
struct PassGuard<'a>(&'a dyn Store);
impl Drop for PassGuard<'_> {
    fn drop(&mut self) {
        let _ = self.0.kv_set("osintmon_running", "0");
    }
}

const GUARD_STALE_SECS: u64 = 600;

/// Run every due monitor (public entry: the real runner and Telegram).
pub fn run_due(cfg: &Config, dry: bool) -> Vec<String> {
    run_due_with(
        cfg,
        &MysqlStore::new(cfg),
        &RealRunner,
        &TelegramNotifier(cfg),
        dry,
    )
}

fn runner_skip_note(addr: &str, s: &RunSkip) -> String {
    let what = match s {
        RunSkip::Busy => "a run for this address is in progress, will retry".to_string(),
        RunSkip::RateLimited => "rate limited, will retry".to_string(),
        RunSkip::TooManyRuns => "too many OSINT runs in progress, will retry".to_string(),
        RunSkip::Disabled => "OSINT is switched off".to_string(),
        RunSkip::Invalid(e) => format!("invalid: {}", clean_text(e, 120)),
        RunSkip::Failed(e) => format!("run failed: {}", clean_text(e, 120)),
    };
    format!("osint monitor {addr}: {what}")
}

/// The run to compare against: the baseline pointer when it names a run of
/// this monitor, else the run before this one; `None` makes this run the
/// new baseline.
fn baseline_report(store: &dyn Store, m: &Monitor, run_id: u32) -> Option<OsintReport> {
    let by_pointer = store
        .kv_get(&format!("osint_base_{}", m.id))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|id| *id != run_id)
        .and_then(|id| store.run_by_id(id).ok().flatten())
        .filter(|(mon, _)| *mon == m.id)
        .map(|(_, r)| r);
    by_pointer.or_else(|| {
        store
            .previous_run(m.id, run_id)
            .ok()
            .flatten()
            .map(|(_, r)| r)
    })
}

pub fn run_due_with(
    cfg: &Config,
    store: &dyn Store,
    runner: &dyn Runner,
    notifier: &dyn Notifier,
    dry: bool,
) -> Vec<String> {
    let mut notes = Vec::new();
    if !cfg.osint_enabled {
        return notes;
    }
    // no table yet, DB down or not configured: quiet, like Delivery monitors
    let Ok(monitors) = store.list(None) else {
        return notes;
    };
    let now = notifier.now();
    let mut due: Vec<Monitor> = monitors.into_iter().filter(|m| m.due(now)).collect();
    due.sort_by_key(|m| (m.last_run_at, m.id));
    if due.is_empty() {
        return notes;
    }
    if dry {
        for m in &due {
            notes.push(format!(
                "osint monitor {}: due (every {} min) — dry run, not started",
                clean_text(&m.address, 254),
                m.interval_mins
            ));
        }
        return notes;
    }
    let fresh = store
        .kv_get("osintmon_running")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|t| now.saturating_sub(t) < GUARD_STALE_SECS && t <= now)
        .unwrap_or(false);
    if fresh {
        notes.push("osint monitors: previous pass still running".into());
        return notes;
    }
    let _ = store.kv_set("osintmon_running", &now.to_string());
    let _guard = PassGuard(store);
    let host = clean_text(&notifier.host(), 100);
    let infos = crate::osintproviders::infos(cfg);
    let mut started = 0;
    for m in due {
        if started >= MAX_PER_PASS {
            break;
        }
        let addr = clean_text(&m.address, 254);
        let period = period_for(now);
        let units = m
            .sources
            .iter()
            .filter(|s| infos.iter().any(|i| i.id == s.as_str() && i.configured))
            .count() as u32;
        if cfg.osint_monitor_budget > 0 {
            let used = store.usage_month(&period).unwrap_or(0);
            if used + units > cfg.osint_monitor_budget {
                let key = format!("alert_osint_budget_{period}");
                if store.kv_get(&key).is_none() {
                    notes.push(format!(
                        "osint monitor {addr}: skipped, monthly budget reached ({used} of {} units)",
                        cfg.osint_monitor_budget
                    ));
                    if notifier.configured() {
                        let text = budget_text(&host, used, cfg.osint_monitor_budget, &period);
                        match notifier.send(&text) {
                            Ok(()) => {
                                let _ = store.kv_set(&key, &now.to_string());
                                notes.push("osint monitors: Telegram alert sent (budget)".into());
                            }
                            Err(e) => notes.push(format!(
                                "osint monitors: Telegram failed: {}",
                                clean_text(&e, 120)
                            )),
                        }
                    } else {
                        let _ = store.kv_set(&key, &now.to_string());
                        notes
                            .push("osint monitors: budget reached, Telegram not configured".into());
                    }
                }
                continue;
            }
        }
        started += 1;
        let run_key = crate::deliveryrun::new_id();
        if let Err(e) = store.usage_reserve(m.id, &period, units, &run_key) {
            notes.push(format!(
                "osint monitor {addr}: cannot reserve usage: {}",
                clean_text(&e, 120)
            ));
            continue;
        }
        let began = std::time::Instant::now();
        let mut report = match runner.run(cfg, &m.address, &m.sources) {
            Ok(r) => r,
            Err(skip) => {
                match skip {
                    // nothing was started: try again on the next pass
                    RunSkip::Busy | RunSkip::RateLimited | RunSkip::TooManyRuns => {
                        let _ = store.usage_release(&run_key);
                    }
                    // OSINT is off: touch nothing, take no slot
                    RunSkip::Disabled => {
                        let _ = store.usage_release(&run_key);
                        started -= 1;
                    }
                    RunSkip::Invalid(_) => {
                        let _ = store.usage_release(&run_key);
                        let _ = store.touch_last_run(m.id, now);
                    }
                    // providers may have been queried: charge the reservation
                    RunSkip::Failed(_) => {
                        let _ = store.usage_settle(&run_key, units);
                        let _ = store.touch_last_run(m.id, now);
                    }
                }
                notes.push(runner_skip_note(&addr, &skip));
                continue;
            }
        };
        if report.state == RunState::Failed || report.state == RunState::Cancelled {
            let _ = store.usage_settle(&run_key, units);
            let _ = store.touch_last_run(m.id, now);
            notes.push(format!(
                "osint monitor {addr}: run {}, nothing stored",
                report.state.as_str()
            ));
            continue;
        }
        match store.get(m.id) {
            Ok(Some(cur)) if cur.enabled => {}
            _ => {
                let _ = store.usage_release(&run_key);
                notes.push(format!(
                    "osint monitor {addr}: removed or disabled during the run, result dropped"
                ));
                continue;
            }
        }
        let final_units = report
            .sources
            .iter()
            .filter(|s| {
                !matches!(
                    s.state,
                    SourceState::NotConfigured | SourceState::NotRequested
                )
            })
            .count() as u32;
        let _ = store.usage_settle(&run_key, final_units);
        strip_assets(&mut report);
        let (ok, bad) = source_counts(&report);
        let summary = format!(
            "{} finding(s), {ok} source(s) ok, {bad} not",
            report.findings.len()
        );
        let duration_ms = began.elapsed().as_millis().min(u32::MAX as u128) as u32;
        let run_id = match store.store_run(m.id, &report, duration_ms, &summary) {
            Ok(id) => id,
            Err(e) => {
                // the units were really used: no retry storm
                let _ = store.touch_last_run(m.id, now);
                notes.push(format!(
                    "osint monitor {addr}: cannot store the run: {}",
                    clean_text(&e, 160)
                ));
                continue;
            }
        };
        let pointer = format!("osint_base_{}", m.id);
        let Some(prev) = baseline_report(store, &m, run_id) else {
            let _ = store.kv_set(&pointer, &run_id.to_string());
            notes.push(format!("osint monitor {addr}: {summary} — baseline stored"));
            continue;
        };
        notes.push(format!("osint monitor {addr}: {summary}"));
        let delta = diff_reports(&prev, &report);
        let texts = alert_texts(&host, &addr, &delta);
        // false when a needed alert was held back or failed to send: the
        // baseline then stays and the change is raised again
        let mut all_done = true;
        for (kind, text) in &texts {
            let key = format!("alert_osint_{}_{}", m.id, kind.key_part());
            let last = store
                .kv_get(&key)
                .and_then(|v| v.trim().parse::<u64>().ok());
            if !cooldown_ok(now, last, cfg.alert_cooldown_mins) {
                all_done = false;
                notes.push(format!(
                    "osint monitor {addr}: {} alert suppressed by the cooldown",
                    kind.key_part()
                ));
                continue;
            }
            if !notifier.configured() {
                notes.push(format!(
                    "osint monitor {addr}: {} changes — Telegram not configured",
                    kind.key_part()
                ));
                continue;
            }
            match notifier.send(text) {
                Ok(()) => {
                    let _ = store.kv_set(&key, &now.to_string());
                    notes.push(format!(
                        "osint monitor {addr}: Telegram alert sent ({})",
                        kind.key_part()
                    ));
                }
                Err(e) => {
                    all_done = false;
                    notes.push(format!(
                        "osint monitor {addr}: Telegram failed: {}",
                        clean_text(&e, 120)
                    ));
                }
            }
        }
        if baseline_decision(!texts.is_empty(), all_done) {
            let _ = store.kv_set(&pointer, &run_id.to_string());
        }
    }
    notes
}

/// Drop runs past the retention window (the latest run of each monitor stays).
pub fn prune(cfg: &Config, days: u32) -> Result<(), String> {
    MysqlStore::new(cfg).prune(days)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::{
        Confidence, Finding, Group, OsintReport, RunState, Severity, SourceState, SourceStatus,
    };

    fn finding(url: &str) -> Finding {
        Finding {
            group: Group::Exposure,
            confidence: Confidence::Medium,
            confidence_reason: "r".into(),
            severity: Severity::Info,
            observed_at: 105,
            event_at: None,
            source_id: "fixture".into(),
            source_url: Some(url.into()),
            title: "t \"q\" 'x' \\ \n é".into(),
            evidence: "e".into(),
            limitations: vec![],
            asset_id: Some("0123456789abcdef".into()),
            asset_mime: Some("image/png".into()),
        }
    }

    fn report(started: u64) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "user@example.org".into(),
            started,
            finished: Some(started + 3),
            state: RunState::Partial,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![
                SourceStatus {
                    id: "a".into(),
                    state: SourceState::Matched,
                    retry_after: None,
                    detail: String::new(),
                },
                SourceStatus {
                    id: "b".into(),
                    state: SourceState::Failed,
                    retry_after: None,
                    detail: String::new(),
                },
                SourceStatus {
                    id: "c".into(),
                    state: SourceState::NotConfigured,
                    retry_after: None,
                    detail: String::new(),
                },
            ],
            findings: vec![finding("https://example.org/x")],
            delivery_run_id: None,
            limitations: vec![],
        }
    }

    fn srcs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn interval_clamps() {
        assert_eq!(clamp_interval(0), 1440);
        assert_eq!(clamp_interval(100), 1440);
        assert_eq!(clamp_interval(2880), 2880);
        assert_eq!(clamp_interval(20000), 10080);
    }

    #[test]
    fn due_needs_enabled_and_the_interval() {
        let mut m = Monitor {
            id: 1,
            address: "a@x.org".into(),
            owner: String::new(),
            sources: srcs(&["rdap"]),
            interval_mins: 1440,
            enabled: true,
            created_at: 0,
            last_run_at: 1000,
            last_summary: String::new(),
        };
        assert!(!m.due(1000 + 86_400 - 1));
        assert!(m.due(1000 + 86_400));
        assert!(!m.due(0)); // a clock before the last run never underflows
        m.enabled = false;
        assert!(!m.due(1_000_000));
        assert!(m.to_json().to_string().contains("\"due\":false"));
    }

    #[test]
    fn sources_are_validated() {
        let cfg = Config::default();
        assert_eq!(
            validate_sources(&srcs(&["rdap", "gravatar", "rdap"]), &cfg).unwrap(),
            srcs(&["rdap", "gravatar"])
        );
        assert!(validate_sources(&[], &cfg).is_err());
        assert!(validate_sources(&srcs(&["rdap", "nope"]), &cfg).is_err());
        assert!(validate_sources(&srcs(&["rdap", "delivery"]), &cfg).is_err());
        assert!(validate_sources(&srcs(&["rdap,x"]), &cfg).is_err());
        let with = validate_sources(&srcs(&["rdap", "hunter"]), &cfg).unwrap();
        assert!(with.contains(&"hunter".to_string()));
        let without = validate_sources(&srcs(&["rdap"]), &cfg).unwrap();
        assert!(!without.contains(&"hunter".to_string()));
    }

    #[test]
    fn sources_column_is_parsed_defensively() {
        assert_eq!(parse_sources("rdap,gravatar"), srcs(&["rdap", "gravatar"]));
        assert_eq!(
            parse_sources(" rdap,,Bad Id,gravatar;x,pgp_1 "),
            srcs(&["rdap", "pgp_1"])
        );
        assert!(parse_sources("").is_empty());
    }

    #[test]
    fn period_is_year_and_month() {
        assert_eq!(period_for(0), "197001");
        assert_eq!(period_for(1_798_761_600 - 1), "202612"); // 2026-12-31 23:59:59
        assert_eq!(period_for(1_798_761_600), "202701"); // 2027-01-01
    }

    #[test]
    fn astral_characters_are_escaped_for_a_utf8mb3_connection() {
        assert_eq!(
            bmp_escape("a\u{e9}\u{65e5}\u{1F600}"),
            "a\u{e9}\u{65e5}\\ud83d\\ude00"
        );
        assert_eq!(bmp_only("a\u{1F600}b"), "a\u{fffd}b");
        // an escaped report parses back to the same text
        let mut r = report(1);
        r.findings[0].title = "x \u{1F600} y".into();
        let esc = bmp_escape(&r.to_json().to_string());
        assert!(esc.is_ascii() || !esc.chars().any(|c| c as u32 > 0xFFFF));
        let back = parse_report(&esc).unwrap();
        assert_eq!(back.findings[0].title, "x \u{1F600} y");
    }

    #[test]
    fn strip_assets_clears_both_fields() {
        let mut r = report(1);
        strip_assets(&mut r);
        assert!(r.findings[0].asset_id.is_none() && r.findings[0].asset_mime.is_none());
    }

    #[test]
    fn sql_insert_is_exact_and_escapes() {
        assert_eq!(
            sql_insert_monitor("a@x.org", "", &srcs(&["rdap", "gravatar"]), 1440, 1000),
            "INSERT INTO osint_monitors (address, owner, sources, interval_mins, enabled, created_at) VALUES ('a@x.org', '', 'rdap,gravatar', 1440, 1, 1000) \
             ON DUPLICATE KEY UPDATE sources = VALUES(sources), interval_mins = VALUES(interval_mins), enabled = 1;\n"
        );
        let s = sql_insert_monitor("o'b\\c\nd@x.org", "ow'n", &srcs(&["rdap"]), 1440, 1);
        assert!(s.contains("VALUES ('o''b\\\\c\nd@x.org', 'ow''n', 'rdap'"));
        assert!(!s.contains("o'b"));
    }

    #[test]
    fn sql_select_filters_by_owner() {
        let all = sql_select_monitors(None);
        assert!(all.starts_with("SELECT id, address, owner, sources,"));
        assert!(all.ends_with("FROM osint_monitors ORDER BY address, owner"));
        assert!(sql_select_monitors(Some("o'x")).contains("WHERE owner = 'o''x'"));
    }

    #[test]
    fn sql_trim_keeps_the_newest_hundred() {
        assert_eq!(
            sql_trim_runs(7),
            "DELETE FROM osint_runs WHERE monitor_id = 7 AND id NOT IN (SELECT id FROM (SELECT id FROM osint_runs WHERE monitor_id = 7 ORDER BY id DESC LIMIT 100) AS keep);\n"
        );
    }

    #[test]
    fn sql_remove_cascades_to_runs_usage_and_keys() {
        assert_eq!(
            sql_remove(7),
            "DELETE FROM osint_runs WHERE monitor_id = 7;\n\
             DELETE FROM osint_usage WHERE monitor_id = 7;\n\
             DELETE FROM msfe_config WHERE scope = 'global' AND scope_id = '' AND (ckey = 'osint_base_7' OR ckey LIKE 'alert\\\\_osint\\\\_7\\\\_%');\n\
             DELETE FROM osint_monitors WHERE id = 7;\n"
        );
    }

    #[test]
    fn sql_store_run_inserts_updates_and_trims() {
        let s = sql_store_run(
            7,
            "{\"a\":\"it's\"}",
            100,
            3000,
            "partial",
            2,
            1,
            1,
            103,
            "2 findings 'x'",
        );
        assert!(s.starts_with("START TRANSACTION;\nINSERT INTO osint_runs (monitor_id, started_at, duration_ms, state, n_findings, n_sources_ok, n_sources_bad, report) VALUES (7, 100, 3000, 'partial', 2, 1, 1, '{\"a\":\"it''s\"}');\n"));
        assert!(s.contains("UPDATE osint_monitors SET last_run_at = 103, last_summary = '2 findings ''x''' WHERE id = 7;\n"));
        assert!(s.ends_with(&format!("{}COMMIT;\n", sql_trim_runs(7))));
    }

    #[test]
    fn sql_usage_statements() {
        assert_eq!(
            sql_usage_reserve(3, "202610", 8, "abc'd", 55),
            "INSERT INTO osint_usage (monitor_id, period, reserved, run_id, created_at) VALUES (3, '202610', 8, 'abc''d', 55);\n"
        );
        assert_eq!(
            sql_usage_settle("abc", 5),
            "UPDATE osint_usage SET final_units = 5 WHERE run_id = 'abc';\n"
        );
        assert_eq!(
            sql_usage_release("abc"),
            "DELETE FROM osint_usage WHERE run_id = 'abc';\n"
        );
        assert_eq!(
            sql_usage_month("202610"),
            "SELECT COALESCE(SUM(COALESCE(final_units, reserved)), 0) FROM osint_usage WHERE period = '202610'"
        );
    }

    #[test]
    fn sql_prune_spares_each_monitors_latest_run() {
        let s = sql_prune(10_000_000, 90);
        assert!(s.contains("started_at < 2224000"));
        assert!(s.contains("SELECT MAX(id) AS mx FROM osint_runs GROUP BY monitor_id"));
        assert!(s.contains("DELETE FROM osint_usage WHERE created_at <"));
    }

    #[test]
    fn usage_ids_are_validated() {
        let st = FakeStore::default();
        assert!(st.usage_reserve(1, "2026", 1, "r").is_err());
        assert!(st.usage_reserve(1, "202610", 1, "").is_err());
        assert!(st.usage_reserve(1, "202610", 1, "a'b").is_err());
        assert!(st.usage_month("x").is_err());
    }

    fn add(st: &FakeStore, a: &str, max: u32) -> Result<Monitor, String> {
        st.add(a, "", &srcs(&["rdap"]), 1440, max)
    }

    #[test]
    fn fake_addresses_are_case_sensitive_and_capped() {
        let st = FakeStore::default();
        let a = add(&st, "A@x.org", 2).unwrap();
        let b = add(&st, "a@x.org", 2).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(st.list(None).unwrap().len(), 2);
        let e = add(&st, "c@x.org", 2).unwrap_err();
        assert_eq!(e, "the limit of 2 monitors is reached (osint_max_monitors)");
        // re-adding an existing address is an update, not a new row, and is not capped
        let again = st
            .add("A@x.org", "", &srcs(&["gravatar"]), 2880, 2)
            .unwrap();
        assert_eq!(again.id, a.id);
        assert_eq!(again.sources, srcs(&["gravatar"]));
        assert_eq!(again.interval_mins, 2880);
        assert_eq!(st.list(None).unwrap().len(), 2);
        // owners are separate identities; list filters by owner
        st.add("A@x.org", "bob", &srcs(&["rdap"]), 1440, 9).unwrap();
        assert_eq!(st.list(Some("bob")).unwrap().len(), 1);
    }

    #[test]
    fn fake_store_run_strips_assets_and_trims() {
        let st = FakeStore::default();
        let m = add(&st, "a@x.org", 5).unwrap();
        let mut last = 0;
        for i in 0..(KEEP_RUNS as u64 + 5) {
            last = st
                .store_run(m.id, &report(1000 + i), 10, &format!("s{i}"))
                .unwrap();
        }
        let runs = st.runs(m.id, 1000).unwrap();
        assert_eq!(runs.len(), KEEP_RUNS);
        assert_eq!(runs[0].id, last); // newest first
        assert_eq!(runs[0].n_findings, 1);
        assert_eq!((runs[0].n_sources_ok, runs[0].n_sources_bad), (1, 1));
        assert_eq!(runs[0].state, "partial");
        assert_eq!(st.runs(m.id, 3).unwrap().len(), 3);
        let r = st.run_report(last).unwrap().unwrap();
        assert!(r.findings[0].asset_id.is_none() && r.findings[0].asset_mime.is_none());
        assert_eq!(st.get(m.id).unwrap().unwrap().last_summary, "s104");
        assert!(st.run_report(999_999).unwrap().is_none());
    }

    #[test]
    fn fake_previous_run_is_the_next_lower_id_of_the_same_monitor() {
        let st = FakeStore::default();
        let a = add(&st, "a@x.org", 5).unwrap();
        let b = add(&st, "b@x.org", 5).unwrap();
        let a1 = st.store_run(a.id, &report(10), 1, "").unwrap();
        let _b1 = st.store_run(b.id, &report(11), 1, "").unwrap();
        let a2 = st.store_run(a.id, &report(12), 1, "").unwrap();
        assert_eq!(st.previous_run(a.id, a2).unwrap().unwrap().0, a1);
        assert!(st.previous_run(a.id, a1).unwrap().is_none());
        assert!(st.previous_run(b.id, a2).unwrap().unwrap().0 != a1);
        let (mid, rep) = st.run_by_id(a2).unwrap().unwrap();
        assert_eq!((mid, rep.started), (a.id, 12));
        assert!(st.run_by_id(424242).unwrap().is_none());
    }

    #[test]
    fn fake_remove_cascades() {
        let st = FakeStore::default();
        let a = add(&st, "a@x.org", 5).unwrap();
        let b = add(&st, "b@x.org", 5).unwrap();
        st.store_run(a.id, &report(10), 1, "").unwrap();
        st.store_run(b.id, &report(10), 1, "").unwrap();
        st.usage_reserve(a.id, "202610", 8, "ra").unwrap();
        st.usage_reserve(b.id, "202610", 4, "rb").unwrap();
        st.kv_set(&format!("osint_base_{}", a.id), "1").unwrap();
        st.kv_set(&format!("alert_osint_{}_new", a.id), "1")
            .unwrap();
        st.kv_set(&format!("osint_base_{}", b.id), "1").unwrap();
        st.kv_set("other", "1").unwrap();
        assert!(st.remove(a.id).unwrap());
        assert!(!st.remove(a.id).unwrap());
        assert!(st.get(a.id).unwrap().is_none());
        assert!(st.runs(a.id, 10).unwrap().is_empty());
        assert_eq!(st.usage_month("202610").unwrap(), 4);
        assert!(st.kv_get(&format!("osint_base_{}", a.id)).is_none());
        assert!(st.kv_get(&format!("alert_osint_{}_new", a.id)).is_none());
        assert!(st.kv_get(&format!("osint_base_{}", b.id)).is_some());
        assert!(st.kv_get("other").is_some());
        assert_eq!(st.runs(b.id, 10).unwrap().len(), 1);
    }

    #[test]
    fn fake_remove_does_not_touch_ids_sharing_a_prefix() {
        let st = FakeStore::default();
        st.kv_set("osint_base_5", "1").unwrap();
        st.kv_set("osint_base_55", "1").unwrap();
        st.kv_set("alert_osint_55_new", "1").unwrap();
        st.remove_keys(5);
        assert!(st.kv_get("osint_base_5").is_none());
        assert!(st.kv_get("osint_base_55").is_some());
        assert!(st.kv_get("alert_osint_55_new").is_some());
    }

    #[test]
    fn fake_usage_counts_reserved_until_settled() {
        let st = FakeStore::default();
        st.usage_reserve(1, "202610", 8, "r1").unwrap();
        st.usage_reserve(1, "202610", 8, "r2").unwrap();
        st.usage_reserve(1, "202609", 100, "r3").unwrap();
        assert_eq!(st.usage_month("202610").unwrap(), 16);
        assert!(st.usage_reserve(1, "202610", 8, "r1").is_err()); // idempotent key = error
        st.usage_settle("r1", 3).unwrap();
        assert_eq!(st.usage_month("202610").unwrap(), 11);
        st.usage_release("r2").unwrap();
        assert_eq!(st.usage_month("202610").unwrap(), 3);
        st.usage_settle("r1", 0).unwrap();
        assert_eq!(st.usage_month("202610").unwrap(), 0);
        assert_eq!(st.usage_month("202611").unwrap(), 0);
    }

    #[test]
    fn fake_enable_touch_and_kv() {
        let st = FakeStore::default();
        let m = add(&st, "a@x.org", 5).unwrap();
        st.set_enabled(m.id, false).unwrap();
        assert!(!st.get(m.id).unwrap().unwrap().enabled);
        st.touch_last_run(m.id, 777).unwrap();
        assert_eq!(st.get(m.id).unwrap().unwrap().last_run_at, 777);
        assert_eq!(st.kv_get("k"), None);
        st.kv_set("k", "v").unwrap();
        assert_eq!(st.kv_get("k").as_deref(), Some("v"));
    }

    #[test]
    fn long_multibyte_summaries_are_cut_to_255_characters() {
        let long = "é日😀".repeat(400);
        let cut = summary_for_column(&long);
        assert_eq!(cut.chars().count(), 255);
        assert!(!cut.chars().any(|c| c as u32 > 0xFFFF));
        assert_eq!(summary_for_column("short"), "short");
    }

    #[test]
    fn store_run_sql_is_one_transaction() {
        let s = sql_store_run(7, "{}", 1, 1, "complete", 0, 0, 0, 1, "s");
        assert!(s.starts_with("START TRANSACTION;\nINSERT INTO osint_runs"));
        assert!(s.ends_with("COMMIT;\n"));
        assert_eq!(s.matches("COMMIT;").count(), 1);
    }

    #[test]
    fn duplicate_usage_error_is_mapped() {
        let e = "mysql exited non-zero: ERROR 1062 (23000) at line 1: Duplicate entry 'r1' for key 'osint_usage_run'";
        assert_eq!(map_usage_error(e), "duplicate run id");
        assert_eq!(
            map_usage_error("mysql exited non-zero: ERROR 2002"),
            "mysql exited non-zero: ERROR 2002"
        );
    }

    #[test]
    fn fake_prune_spares_the_latest_run_per_monitor_and_drops_old_usage() {
        let st = FakeStore::default();
        let now = 500 * 86_400;
        // monitor 1: two old runs and a recent one; monitor 2: only old runs;
        // monitor 9 has runs but no monitor row (still spared once)
        let o1 = st.store_run(1, &report(now - 200 * 86_400), 1, "").unwrap();
        let o2 = st.store_run(1, &report(now - 100 * 86_400), 1, "").unwrap();
        let r3 = st.store_run(1, &report(now - 86_400), 1, "").unwrap();
        let p1 = st.store_run(2, &report(now - 300 * 86_400), 1, "").unwrap();
        let p2 = st.store_run(2, &report(now - 250 * 86_400), 1, "").unwrap();
        let q1 = st.store_run(9, &report(now - 400 * 86_400), 1, "").unwrap();
        st.usage_reserve(1, "202601", 1, "old").unwrap();
        st.usage_reserve(1, "202602", 1, "new").unwrap();
        for u in st.st.borrow_mut().usage.iter_mut() {
            u.5 = if u.4 == "old" {
                now - 401 * 86_400
            } else {
                now - 399 * 86_400
            };
        }
        st.prune_at(now, 90);
        let ids = |m| {
            st.runs(m, 100)
                .unwrap()
                .iter()
                .map(|r| r.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(1), vec![r3]);
        assert_eq!(ids(2), vec![p2]);
        assert_eq!(ids(9), vec![q1]);
        let _ = (o1, o2, p1);
        let usage: Vec<String> = st.st.borrow().usage.iter().map(|u| u.4.clone()).collect();
        assert_eq!(usage, vec!["new".to_string()]);
        // a run inside the window is kept even when it is not the latest
        let st = FakeStore::default();
        let a = st.store_run(1, &report(now - 50 * 86_400), 1, "").unwrap();
        let b = st.store_run(1, &report(now - 10 * 86_400), 1, "").unwrap();
        st.prune_at(now, 90);
        assert_eq!(ids_of(&st, 1), vec![b, a]);
    }

    fn ids_of(st: &FakeStore, m: u32) -> Vec<u32> {
        st.runs(m, 100).unwrap().iter().map(|r| r.id).collect()
    }

    #[test]
    fn sql_prune_statement_is_exact() {
        assert_eq!(
            sql_prune(10_000_000, 90),
            "DELETE FROM osint_runs WHERE started_at < 2224000 AND id NOT IN (SELECT mx FROM (SELECT MAX(id) AS mx FROM osint_runs GROUP BY monitor_id) AS latest);\n\
             DELETE FROM osint_usage WHERE created_at < 0;\n"
        );
        assert!(sql_prune(40_000_000, 90)
            .contains("DELETE FROM osint_usage WHERE created_at < 5440000;"));
    }
}

#[cfg(test)]
mod change_tests {
    use super::*;
    use crate::osint::{
        Confidence, Finding, Group, OsintReport, RunState, Severity, SourceState, SourceStatus,
    };

    fn f(src: &str, group: Group, url: Option<&str>, title: &str) -> Finding {
        Finding {
            group,
            confidence: Confidence::Medium,
            confidence_reason: "r".into(),
            severity: Severity::Info,
            observed_at: 1,
            event_at: None,
            source_id: src.into(),
            source_url: url.map(|u| u.to_string()),
            title: title.into(),
            evidence: "SECRET-EVIDENCE".into(),
            limitations: vec![],
            asset_id: None,
            asset_mime: None,
        }
    }
    fn rep(sources: &[(&str, SourceState)], findings: Vec<Finding>) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "a@x.org".into(),
            started: 1,
            finished: Some(2),
            state: RunState::Complete,
            cached: false,
            planned: vec![],
            sources: sources
                .iter()
                .map(|(i, s)| SourceStatus {
                    id: i.to_string(),
                    state: s.clone(),
                    retry_after: None,
                    detail: "why".into(),
                })
                .collect(),
            findings,
            delivery_run_id: None,
            limitations: vec![],
        }
    }
    fn ok() -> Vec<(&'static str, SourceState)> {
        vec![("hibp", SourceState::Matched)]
    }

    #[test]
    fn identical_reports_have_empty_delta() {
        let a = rep(&ok(), vec![f("hibp", Group::Exposure, Some("u1"), "t")]);
        let d = diff_reports(&a, &a.clone());
        assert!(d.new_findings.is_empty() && d.gone_findings.is_empty());
        assert!(d.went_bad.is_empty() && d.recovered.is_empty());
    }

    #[test]
    fn new_finding_detected_and_key_is_stable() {
        let a = rep(&ok(), vec![f("hibp", Group::Exposure, Some("u1"), "t")]);
        let mut changed = f("hibp", Group::Exposure, Some("u1"), "other title");
        changed.observed_at = 999;
        changed.evidence = "different".into();
        changed.severity = Severity::High;
        changed.confidence = Confidence::Low;
        let b = rep(
            &ok(),
            vec![changed, f("hibp", Group::Exposure, Some("u2"), "new")],
        );
        let d = diff_reports(&a, &b);
        assert_eq!(d.new_findings.len(), 1);
        assert_eq!(d.new_findings[0].source_url.as_deref(), Some("u2"));
        assert!(d.gone_findings.is_empty());
    }

    #[test]
    fn urls_are_normalised_in_the_key() {
        let k = |u: &str| finding_key(&f("hibp", Group::Exposure, Some(u), "t"));
        let base = k("https://example.org/Path/x");
        assert_eq!(k("HTTPS://Example.ORG/Path/x/"), base);
        assert_eq!(k("https://example.org/Path/x#frag"), base);
        assert_eq!(k("https://example.org/Path/x/#frag"), base);
        assert_ne!(k("https://example.org/path/x"), base);
        assert_ne!(k("https://example.org/Path/y"), base);
        assert_ne!(k("https://example.org/Path/x?q=1"), base);
        assert_eq!(
            k("https://example.org/a?Q=1/"),
            k("https://example.org/a?Q=1/")
        );
        // a root path stays a root path; non-URLs are left alone
        assert_eq!(k("https://Example.org/"), k("https://example.org"));
        assert_eq!(k("u1"), "hibp|exposure|u1");
        let a = rep(
            &ok(),
            vec![f("hibp", Group::Exposure, Some("https://e.org/x/"), "t")],
        );
        let b = rep(
            &ok(),
            vec![f("hibp", Group::Exposure, Some("https://E.org/x#top"), "t")],
        );
        assert!(diff_reports(&a, &b).new_findings.is_empty());
    }

    #[test]
    fn no_url_keyed_by_title_and_duplicates_collapse() {
        let a = rep(&ok(), vec![f("hibp", Group::Profile, None, "one")]);
        let b = rep(
            &ok(),
            vec![
                f("hibp", Group::Profile, None, "one"),
                f("hibp", Group::Profile, None, "two"),
                f("hibp", Group::Profile, None, "two"),
            ],
        );
        let d = diff_reports(&a, &b);
        assert_eq!(d.new_findings.len(), 1);
        assert_eq!(d.new_findings[0].title, "two");
        assert_eq!(
            finding_key(&f("hibp", Group::Profile, None, "one")),
            "hibp|profile|one"
        );
        assert_eq!(
            finding_key(&f("hibp", Group::Exposure, Some("U"), "one")),
            "hibp|exposure|U"
        );
    }

    #[test]
    fn gone_only_when_source_answered() {
        let a = rep(&ok(), vec![f("hibp", Group::Exposure, Some("u1"), "t")]);
        let d = diff_reports(&a, &rep(&[("hibp", SourceState::NoMatch)], vec![]));
        assert_eq!(d.gone_findings.len(), 1);
        let d = diff_reports(&a, &rep(&[("hibp", SourceState::Matched)], vec![]));
        assert_eq!(d.gone_findings.len(), 1);
        for s in [
            SourceState::Failed,
            SourceState::Restricted,
            SourceState::RateLimited,
            SourceState::Inconclusive,
            SourceState::NotConfigured,
            SourceState::NotRequested,
            SourceState::Unknown("x".into()),
        ] {
            let d = diff_reports(&a, &rep(&[("hibp", s.clone())], vec![]));
            assert!(d.gone_findings.is_empty(), "{:?}", s);
        }
        // source absent from cur
        let d = diff_reports(&a, &rep(&[], vec![]));
        assert!(d.gone_findings.is_empty() && d.went_bad.is_empty());
    }

    #[test]
    fn went_bad_and_recovered() {
        for from in [SourceState::Matched, SourceState::NoMatch] {
            for to in [SourceState::Failed, SourceState::Restricted] {
                let a = rep(&[("hibp", from.clone())], vec![]);
                let b = rep(&[("hibp", to.clone())], vec![]);
                let d = diff_reports(&a, &b);
                assert_eq!(d.went_bad.len(), 1);
                assert_eq!(d.went_bad[0].id, "hibp");
                assert_eq!(d.went_bad[0].from, from);
                assert_eq!(d.went_bad[0].to, to);
                assert_eq!(d.went_bad[0].detail, "why");
                assert!(d.recovered.is_empty());
                let r = diff_reports(&b, &a);
                assert_eq!(r.recovered.len(), 1);
                assert!(r.went_bad.is_empty());
            }
        }
        for to in [
            SourceState::RateLimited,
            SourceState::NotConfigured,
            SourceState::Inconclusive,
            SourceState::NotRequested,
            SourceState::Unknown("x".into()),
        ] {
            let a = rep(&[("hibp", SourceState::Matched)], vec![]);
            let b = rep(&[("hibp", to)], vec![]);
            let d = diff_reports(&a, &b);
            assert!(d.went_bad.is_empty() && d.recovered.is_empty());
            let d = diff_reports(&b, &a);
            assert!(d.went_bad.is_empty() && d.recovered.is_empty());
        }
        let a = rep(&[("hibp", SourceState::Failed)], vec![]);
        let d = diff_reports(&a, &a.clone());
        assert!(d.went_bad.is_empty() && d.recovered.is_empty());
        // flapping matched -> rate_limited -> matched never alerts
        let m = rep(&ok(), vec![]);
        let rl = rep(&[("hibp", SourceState::RateLimited)], vec![]);
        assert!(diff_reports(&m, &rl).went_bad.is_empty());
        assert!(diff_reports(&rl, &m).recovered.is_empty());
    }

    #[test]
    fn baseline_missing_is_none() {
        let a = rep(&ok(), vec![]);
        assert!(diff_or_baseline(None, &a).is_none());
        assert!(diff_or_baseline(Some(&a), &a).is_some());
    }

    fn delta_new(n: usize, group: Group) -> Delta {
        Delta {
            new_findings: (0..n)
                .map(|i| FindingRef {
                    source_id: "hibp".into(),
                    group: group.clone(),
                    title: format!("title {i}"),
                    source_url: Some(format!("https://secret.example/{i}")),
                    severity: Severity::Info,
                })
                .collect(),
            ..Delta::default()
        }
    }

    #[test]
    fn findings_text_limits_and_privacy() {
        let t = alert_texts("h1", "a@x.org", &delta_new(7, Group::Exposure));
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, AlertKind::Findings);
        let s = &t[0].1;
        assert!(s.starts_with("OSINT watch of a@x.org on h1: 7 new public item(s)\n"));
        assert_eq!(s.matches("• [exposure] ").count(), 5);
        assert!(s.contains("…and 2 more"));
        assert_eq!(s.matches("a@x.org").count(), 1);
        assert!(!s.contains("http") && !s.contains("SECRET"));
    }

    #[test]
    fn findings_text_cleans_and_caps_titles_and_skips_context() {
        let mut d = delta_new(1, Group::Profile);
        d.new_findings[0].title = format!("<b>bold</b> {}", "x".repeat(300));
        let s = &alert_texts("h", "a@x.org", &d)[0].1;
        assert!(!s.contains("<b>"));
        let line = s.lines().nth(1).unwrap();
        assert!(line.chars().count() <= "• [profile] ".chars().count() + 100);
        // context and unknown groups never alert
        assert!(alert_texts("h", "a@x.org", &delta_new(2, Group::Context)).is_empty());
        assert!(alert_texts("h", "a@x.org", &delta_new(2, Group::Unknown("z".into()))).is_empty());
        // a validation verdict is history only
        assert!(alert_texts("h", "a@x.org", &delta_new(2, Group::Validation)).is_empty());
        for g in [Group::Reference, Group::Domain] {
            assert_eq!(alert_texts("h", "a@x.org", &delta_new(1, g)).len(), 1);
        }
    }

    #[test]
    fn provider_text_and_no_text_for_gone_or_recovered() {
        let sr = |i: usize| SourceRef {
            id: format!("src{i}"),
            from: SourceState::Matched,
            to: SourceState::Failed,
            detail: format!("<i>boom</i> {}", "y".repeat(200)),
        };
        let d = Delta {
            went_bad: (0..7).map(sr).collect(),
            ..Delta::default()
        };
        let t = alert_texts("h", "a@x.org", &d);
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].0, AlertKind::Providers);
        let s = &t[0].1;
        assert!(s.starts_with("OSINT watch of a@x.org on h: source problem\n"));
        assert_eq!(s.matches("• src").count(), 5);
        assert!(s.contains("• src0: answered before, now failed (boom"));
        assert!(!s.contains("<i>"));
        assert_eq!(s.matches("a@x.org").count(), 1);
        let only = Delta {
            gone_findings: delta_new(2, Group::Exposure).new_findings,
            recovered: vec![sr(1)],
            ..Delta::default()
        };
        assert!(alert_texts("h", "a@x.org", &only).is_empty());
        // both kinds
        let both = Delta {
            new_findings: delta_new(1, Group::Exposure).new_findings,
            went_bad: vec![sr(1)],
            ..Delta::default()
        };
        let t = alert_texts("h", "a@x.org", &both);
        assert_eq!(
            t.iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![AlertKind::Findings, AlertKind::Providers]
        );
    }

    #[test]
    fn kinds_and_budget_text() {
        assert_eq!(AlertKind::Findings.key_part(), "findings");
        assert_eq!(AlertKind::Providers.key_part(), "providers");
        assert_eq!(AlertKind::Budget.key_part(), "budget");
        let b = budget_text("h1", 300, 300, "202610");
        assert!(b.contains("h1") && b.contains("300") && b.contains("202610"));
    }

    #[test]
    fn baseline_truth_table() {
        assert!(baseline_decision(false, false));
        assert!(baseline_decision(false, true));
        assert!(baseline_decision(true, true));
        assert!(!baseline_decision(true, false));
    }

    #[test]
    fn cooldown_boundary() {
        assert!(cooldown_ok(100, None, 60));
        assert!(!cooldown_ok(100 + 3599, Some(100), 60));
        assert!(cooldown_ok(100 + 3600, Some(100), 60));
        assert!(cooldown_ok(50, Some(100), 0));
        assert!(!cooldown_ok(50, Some(100), 60));
    }
}

#[cfg(test)]
mod sched_tests {
    use super::*;
    use crate::osint::{
        Confidence, Finding, Group, OsintReport, RunState, Severity, SourceState, SourceStatus,
    };
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    const T0: u64 = 1_000_000;

    struct FakeRunner<'a> {
        queue: RefCell<VecDeque<Result<OsintReport, RunSkip>>>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
        hook: RefCell<Option<Box<dyn Fn() + 'a>>>,
    }
    impl<'a> FakeRunner<'a> {
        fn new() -> Self {
            FakeRunner {
                queue: RefCell::new(VecDeque::new()),
                calls: RefCell::new(vec![]),
                hook: RefCell::new(None),
            }
        }
        fn push(&self, r: Result<OsintReport, RunSkip>) {
            self.queue.borrow_mut().push_back(r);
        }
    }
    impl Runner for FakeRunner<'_> {
        fn run(
            &self,
            _cfg: &Config,
            address: &str,
            sources: &[String],
        ) -> Result<OsintReport, RunSkip> {
            self.calls
                .borrow_mut()
                .push((address.to_string(), sources.to_vec()));
            if let Some(h) = self.hook.borrow().as_ref() {
                h();
            }
            self.queue
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(RunSkip::Failed("nothing canned".into())))
        }
    }

    struct FakeNotifier {
        configured: Cell<bool>,
        fail: Cell<bool>,
        sent: RefCell<Vec<String>>,
        now: Cell<u64>,
    }
    impl FakeNotifier {
        fn new() -> Self {
            FakeNotifier {
                configured: Cell::new(true),
                fail: Cell::new(false),
                sent: RefCell::new(vec![]),
                now: Cell::new(T0),
            }
        }
        fn sent(&self) -> usize {
            self.sent.borrow().len()
        }
    }
    impl Notifier for FakeNotifier {
        fn configured(&self) -> bool {
            self.configured.get()
        }
        fn send(&self, text: &str) -> Result<(), String> {
            if self.fail.get() {
                return Err("boom".into());
            }
            self.sent.borrow_mut().push(text.to_string());
            Ok(())
        }
        fn now(&self) -> u64 {
            self.now.get()
        }
        fn host(&self) -> String {
            "host.test".into()
        }
    }

    fn cfg() -> Config {
        Config {
            osint_enabled: true,
            osint_monitor_budget: 0,
            alert_cooldown_mins: 60,
            ..Config::default()
        }
    }

    fn fnd(url: &str) -> Finding {
        Finding {
            group: Group::Exposure,
            confidence: Confidence::Medium,
            confidence_reason: "r".into(),
            severity: Severity::Info,
            observed_at: 1,
            event_at: None,
            source_id: "gravatar".into(),
            source_url: Some(url.into()),
            title: format!("item {}", url.len()),
            evidence: "EVID".into(),
            limitations: vec![],
            asset_id: Some("aaaaaaaaaaaaaaaa".into()),
            asset_mime: Some("image/png".into()),
        }
    }
    fn st(s: SourceState) -> Vec<(&'static str, SourceState)> {
        vec![("gravatar", s)]
    }
    fn rpt(sources: Vec<(&str, SourceState)>, urls: &[&str]) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "A@x.org".into(),
            started: T0,
            finished: Some(T0 + 1),
            state: RunState::Complete,
            cached: false,
            planned: vec![],
            sources: sources
                .into_iter()
                .map(|(i, s)| SourceStatus {
                    id: i.into(),
                    state: s,
                    retry_after: None,
                    detail: "d".into(),
                })
                .collect(),
            findings: urls.iter().map(|u| fnd(u)).collect(),
            delivery_run_id: None,
            limitations: vec![],
        }
    }
    fn mon(store: &FakeStore, addr: &str, sources: &[&str]) -> Monitor {
        let v: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
        store.add(addr, "root", &v, 1440, 50).unwrap()
    }
    /// Make every monitor due, then run a pass.
    fn pass(store: &FakeStore, r: &FakeRunner, n: &FakeNotifier) -> Vec<String> {
        for m in store.list(None).unwrap() {
            store.touch_last_run(m.id, 0).unwrap();
        }
        run_due_with(&cfg(), store, r, n, false)
    }
    fn ptr(store: &FakeStore, id: u32) -> Option<String> {
        store.kv_get(&format!("osint_base_{id}"))
    }
    fn has(notes: &[String], what: &str) -> bool {
        notes.iter().any(|n| n.contains(what))
    }

    #[test]
    fn disabled_or_nothing_due_does_nothing() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        let off = Config {
            osint_enabled: false,
            ..cfg()
        };
        assert!(run_due_with(&off, &s, &r, &n, false).is_empty());
        assert!(r.calls.borrow().is_empty());
        // enabled but nothing due: the monitor ran just now
        s.touch_last_run(1, T0).unwrap();
        assert!(run_due_with(&cfg(), &s, &r, &n, false).is_empty());
        let empty = FakeStore::default();
        assert!(run_due_with(&cfg(), &empty, &r, &n, false).is_empty());
        assert!(empty.kv_get("osintmon_running").is_none());
    }

    #[test]
    fn first_run_is_a_baseline_without_alert() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "A@x.org", &["gravatar", "rdap"]);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/1"])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "baseline stored"), "{notes:?}");
        assert!(!has(&notes, "alert sent"));
        assert_eq!(n.sent(), 0);
        assert_eq!(ptr(&s, 1).as_deref(), Some("1"));
        assert_eq!(s.runs(1, 10).unwrap().len(), 1);
        // the stored address and the approved set reach the runner exactly
        let c = r.calls.borrow();
        assert_eq!(c[0].0, "A@x.org");
        assert_eq!(c[0].1, vec!["gravatar".to_string(), "rdap".to_string()]);
        assert_eq!(
            s.st.borrow().monitors[0].last_summary,
            "1 finding(s), 1 source(s) ok, 0 not"
        );
    }

    #[test]
    fn a_new_finding_alerts_once() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "A@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/1"])));
        pass(&s, &r, &n);
        r.push(Ok(rpt(
            st(SourceState::Matched),
            &["https://e.org/1", "https://e.org/2"],
        )));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram alert sent"), "{notes:?}");
        assert_eq!(n.sent(), 1);
        let text = n.sent.borrow()[0].clone();
        assert!(text.contains("A@x.org") && text.contains("host.test"));
        assert!(!text.contains("EVID") && !text.contains("http"));
        assert_eq!(ptr(&s, 1).as_deref(), Some("2"));
        // an identical third run is quiet
        r.push(Ok(rpt(
            st(SourceState::Matched),
            &["https://e.org/1", "https://e.org/2"],
        )));
        let notes = pass(&s, &r, &n);
        assert!(!has(&notes, "alert sent"));
        assert_eq!(n.sent(), 1);
        assert_eq!(ptr(&s, 1).as_deref(), Some("3"));
    }

    #[test]
    fn a_failed_send_keeps_the_baseline_and_is_retried() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        n.fail.set(true);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/2"])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram failed: boom"), "{notes:?}");
        assert!(!has(&notes, "alert sent"));
        assert_eq!(ptr(&s, 1).as_deref(), Some("1"));
        // no cooldown was set by the failure, so the retry is not held back
        n.fail.set(false);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/2"])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram alert sent"));
        assert_eq!(n.sent(), 1);
        assert_eq!(ptr(&s, 1).as_deref(), Some("3"));
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/2"])));
        pass(&s, &r, &n);
        assert_eq!(n.sent(), 1);
    }

    #[test]
    fn unconfigured_telegram_advances_the_baseline_without_spam() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        n.configured.set(false);
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/2"])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram not configured"), "{notes:?}");
        assert!(!has(&notes, "alert sent"));
        assert_eq!(ptr(&s, 1).as_deref(), Some("2"));
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/2"])));
        let notes = pass(&s, &r, &n);
        assert!(!has(&notes, "not configured"));
        assert_eq!(n.sent(), 0);
    }

    #[test]
    fn the_cooldown_holds_an_alert_back_without_losing_the_change() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/a"])));
        pass(&s, &r, &n);
        assert_eq!(n.sent(), 1);
        assert_eq!(ptr(&s, 1).as_deref(), Some("2"));
        // ten minutes later another finding: held back, baseline stays
        n.now.set(T0 + 600);
        r.push(Ok(rpt(
            st(SourceState::Matched),
            &["https://e.org/a", "https://e.org/b"],
        )));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "cooldown"), "{notes:?}");
        assert!(!has(&notes, "alert sent"));
        assert_eq!(n.sent(), 1);
        assert_eq!(ptr(&s, 1).as_deref(), Some("2"));
        // after the window the same change is alerted
        n.now.set(T0 + 3601);
        r.push(Ok(rpt(
            st(SourceState::Matched),
            &["https://e.org/a", "https://e.org/b"],
        )));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram alert sent"), "{notes:?}");
        assert_eq!(n.sent(), 2);
        assert_eq!(ptr(&s, 1).as_deref(), Some("4"));
    }

    #[test]
    fn a_source_going_bad_alerts_once_and_a_flapping_one_never() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        r.push(Ok(rpt(st(SourceState::Failed), &[])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "Telegram alert sent"), "{notes:?}");
        assert_eq!(n.sent(), 1);
        assert!(n.sent.borrow()[0].contains("source problem"));
        r.push(Ok(rpt(st(SourceState::Failed), &[])));
        pass(&s, &r, &n);
        assert_eq!(n.sent(), 1);
        // matched -> rate_limited -> matched: nothing at all
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        for state in [
            SourceState::Matched,
            SourceState::RateLimited,
            SourceState::Matched,
        ] {
            r.push(Ok(rpt(st(state), &[])));
            pass(&s, &r, &n);
        }
        assert_eq!(n.sent(), 0);
    }

    #[test]
    fn a_monitor_removed_or_disabled_while_running_leaves_nothing() {
        for remove in [true, false] {
            let (s, n) = (FakeStore::default(), FakeNotifier::new());
            mon(&s, "a@x.org", &["gravatar"]);
            let r = FakeRunner::new();
            r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/1"])));
            {
                let sref = &s;
                *r.hook.borrow_mut() = Some(Box::new(move || {
                    if remove {
                        sref.remove(1).unwrap();
                    } else {
                        sref.set_enabled(1, false).unwrap();
                    }
                }));
                let notes = pass(&s, &r, &n);
                assert!(has(&notes, "removed or disabled"), "{notes:?}");
            }
            assert!(s.st.borrow().runs.is_empty());
            assert!(s.st.borrow().usage.is_empty());
            assert_eq!(n.sent(), 0);
            assert!(ptr(&s, 1).is_none());
        }
    }

    #[test]
    fn budget_cap_skips_and_alerts_once_per_month() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar", "rdap", "openpgp"]);
        let period = period_for(T0);
        s.usage_reserve(1, &period, 2, "other1").unwrap();
        let c = Config {
            osint_monitor_budget: 3,
            ..cfg()
        };
        s.touch_last_run(1, 0).unwrap();
        let notes = run_due_with(&c, &s, &r, &n, false);
        assert!(has(&notes, "budget"), "{notes:?}");
        assert!(r.calls.borrow().is_empty());
        assert_eq!(n.sent(), 1);
        assert!(n.sent.borrow()[0].contains("budget"));
        assert_eq!(s.usage_month(&period).unwrap(), 2, "nothing reserved");
        assert!(s.kv_get(&format!("alert_osint_budget_{period}")).is_some());
        // later in the month: still skipped, no second alert
        n.now.set(T0 + 7200);
        let notes = run_due_with(&c, &s, &r, &n, false);
        assert!(!has(&notes, "alert sent"));
        assert_eq!(n.sent(), 1);
        assert!(r.calls.borrow().is_empty());
        // a cap of 0 is unlimited
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        let c0 = Config {
            osint_monitor_budget: 0,
            ..cfg()
        };
        run_due_with(&c0, &s, &r, &n, false);
        assert_eq!(r.calls.borrow().len(), 1);
    }

    #[test]
    fn usage_is_reserved_then_settled_to_the_real_units() {
        let seen = RefCell::new(0u32);
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar", "rdap", "openpgp"]);
        {
            let sref = &s;
            let seen = &seen;
            *r.hook.borrow_mut() = Some(Box::new(move || {
                *seen.borrow_mut() = sref.usage_month(&period_for(T0)).unwrap();
            }));
            r.push(Ok(rpt(
                vec![
                    ("gravatar", SourceState::Matched),
                    ("rdap", SourceState::NoMatch),
                    ("openpgp", SourceState::NotConfigured),
                ],
                &[],
            )));
            pass(&s, &r, &n);
        }
        assert_eq!(*seen.borrow(), 3, "reserved while running");
        assert_eq!(s.usage_month(&period_for(T0)).unwrap(), 2, "settled");
    }

    #[test]
    fn a_run_that_did_not_start_is_released_and_retried_next_pass() {
        for skip in [RunSkip::Busy, RunSkip::RateLimited, RunSkip::TooManyRuns] {
            let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
            mon(&s, "a@x.org", &["gravatar"]);
            r.push(Err(skip.clone()));
            let notes = run_due_with(&cfg(), &s, &r, &n, false);
            assert_eq!(notes.len(), 1, "{skip:?} {notes:?}");
            assert!(has(&notes, "retry"), "{notes:?}");
            assert!(s.st.borrow().usage.is_empty(), "{skip:?}");
            assert!(s.st.borrow().runs.is_empty(), "{skip:?}");
            assert_eq!(s.st.borrow().monitors[0].last_run_at, 0, "{skip:?}");
            assert_eq!(n.sent(), 0);
            // the next pass tries again
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
            run_due_with(&cfg(), &s, &r, &n, false);
            assert_eq!(s.runs(1, 5).unwrap().len(), 1, "{skip:?}");
        }
    }

    #[test]
    fn disabled_runner_touches_nothing_and_takes_no_slot() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        for i in 0..3 {
            mon(&s, &format!("u{i}@x.org"), &["gravatar"]);
        }
        r.push(Err(RunSkip::Disabled));
        r.push(Err(RunSkip::Disabled));
        r.push(Err(RunSkip::Disabled));
        run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(r.calls.borrow().len(), 3, "no slot was used up");
        assert!(s.st.borrow().usage.is_empty());
        assert!(s.st.borrow().monitors.iter().all(|m| m.last_run_at == 0));
    }

    #[test]
    fn a_stuck_monitor_waits_its_interval_and_does_not_starve_others() {
        for skip in [
            RunSkip::Invalid("source gone".into()),
            RunSkip::Failed("timed out".into()),
        ] {
            let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
            mon(&s, "stuck@x.org", &["gravatar", "rdap"]);
            for i in 0..2 {
                mon(&s, &format!("ok{i}@x.org"), &["gravatar"]);
            }
            // the stuck one is the oldest, so it goes first and takes a slot
            s.touch_last_run(1, 10).unwrap();
            s.touch_last_run(2, 20).unwrap();
            s.touch_last_run(3, 30).unwrap();
            r.push(Err(skip.clone()));
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
            run_due_with(&cfg(), &s, &r, &n, false);
            assert_eq!(r.calls.borrow().len(), 2, "{skip:?}");
            assert_eq!(s.st.borrow().monitors[0].last_run_at, T0, "{skip:?}");
            // next pass: the stuck monitor is not due, the third monitor runs
            n.now.set(T0 + 300);
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
            run_due_with(&cfg(), &s, &r, &n, false);
            let c = r.calls.borrow();
            assert_eq!(c.len(), 3, "{skip:?}");
            assert_eq!(c[2].0, "ok1@x.org", "{skip:?}");
            assert!(c.iter().skip(1).all(|x| x.0 != "stuck@x.org"));
        }
    }

    #[test]
    fn a_timed_out_run_is_charged_and_a_failing_monitor_cannot_burn_the_budget() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar", "rdap"]);
        let period = period_for(T0);
        r.push(Err(RunSkip::Failed("timed out".into())));
        s.touch_last_run(1, 0).unwrap();
        run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(s.usage_month(&period).unwrap(), 2, "reserved units settled");
        assert!(s.st.borrow().runs.is_empty());
        // many passes within the interval: no further attempts, same usage
        for k in 1..=12 {
            n.now.set(T0 + k * 300);
            r.push(Err(RunSkip::Failed("timed out".into())));
            run_due_with(&cfg(), &s, &r, &n, false);
        }
        assert_eq!(r.calls.borrow().len(), 1);
        assert_eq!(s.usage_month(&period).unwrap(), 2);
        // an Invalid skip never charges anything
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Err(RunSkip::Invalid("x".into())));
        run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(s.usage_month(&period).unwrap(), 0);
        assert_eq!(s.st.borrow().monitors[0].last_run_at, T0);
    }

    #[test]
    fn a_failed_or_cancelled_report_is_charged_and_not_retried_at_once() {
        for state in [RunState::Failed, RunState::Cancelled] {
            let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
            mon(&s, "a@x.org", &["gravatar", "rdap"]);
            let mut rep = rpt(st(SourceState::Failed), &[]);
            rep.state = state;
            r.push(Ok(rep));
            run_due_with(&cfg(), &s, &r, &n, false);
            assert_eq!(s.usage_month(&period_for(T0)).unwrap(), 2);
            assert_eq!(s.st.borrow().monitors[0].last_run_at, T0);
            assert!(s.st.borrow().runs.is_empty());
        }
    }

    #[test]
    fn a_store_error_settles_usage_and_advances_the_schedule() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        s.st.borrow_mut().fail_store_run = true;
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        let notes = run_due_with(&cfg(), &s, &r, &n, false);
        assert!(has(&notes, "cannot store the run"), "{notes:?}");
        assert_eq!(s.usage_month(&period_for(T0)).unwrap(), 1);
        assert_eq!(s.st.borrow().monitors[0].last_run_at, T0);
        n.now.set(T0 + 300);
        run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(r.calls.borrow().len(), 1, "no retry storm");
        assert_eq!(s.usage_month(&period_for(T0)).unwrap(), 1);
    }

    #[test]
    fn at_most_max_per_pass_run_oldest_first() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        for i in 0..5 {
            mon(&s, &format!("u{i}@x.org"), &["gravatar"]);
            s.touch_last_run(i + 1, 100 + (5 - i) as u64).unwrap();
        }
        for _ in 0..5 {
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
        }
        run_due_with(&cfg(), &s, &r, &n, false);
        let c = r.calls.borrow();
        assert_eq!(c.len(), MAX_PER_PASS);
        // u4 has the oldest last_run_at, then u3
        assert_eq!(c[0].0, "u4@x.org");
        assert_eq!(c[1].0, "u3@x.org");
    }

    #[test]
    fn the_running_guard_blocks_a_fresh_pass_and_ignores_a_stale_one() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        s.touch_last_run(1, 0).unwrap();
        s.kv_set("osintmon_running", &(T0 - 100).to_string())
            .unwrap();
        let notes = run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(
            notes,
            vec!["osint monitors: previous pass still running".to_string()]
        );
        assert!(r.calls.borrow().is_empty());
        s.kv_set("osintmon_running", &(T0 - 601).to_string())
            .unwrap();
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        let notes = run_due_with(&cfg(), &s, &r, &n, false);
        assert!(has(&notes, "baseline stored"));
        // the guard is cleared at the end
        let v: u64 = s.kv_get("osintmon_running").unwrap().parse().unwrap();
        assert_eq!(v, 0);
        // also when the pass ends early (a skipped run)
        s.touch_last_run(1, 0).unwrap();
        r.push(Err(RunSkip::Busy));
        run_due_with(&cfg(), &s, &r, &n, false);
        assert_eq!(s.kv_get("osintmon_running").as_deref(), Some("0"));
    }

    #[test]
    fn a_dry_run_starts_nothing() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        s.touch_last_run(1, 0).unwrap();
        let notes = run_due_with(&cfg(), &s, &r, &n, true);
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("dry run, not started"), "{notes:?}");
        assert!(r.calls.borrow().is_empty());
        assert!(s.st.borrow().usage.is_empty());
        assert!(s.kv_get("osintmon_running").is_none());
    }

    #[test]
    fn avatar_ids_never_reach_the_store() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/1"])));
        pass(&s, &r, &n);
        let json = s.st.borrow().runs[0].1.clone();
        assert!(!json.contains("aaaaaaaaaaaaaaaa"), "{json}");
        assert!(!json.contains("image/png"));
    }

    #[test]
    fn a_failed_runner_leaves_history_untouched() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        r.push(Err(RunSkip::Failed("timed out".into())));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "timed out"));
        assert_eq!(s.runs(1, 10).unwrap().len(), 1);
        assert_eq!(ptr(&s, 1).as_deref(), Some("1"));
    }

    #[test]
    fn a_missing_baseline_falls_back_to_the_previous_run() {
        for bad in ["999", "junk", ""] {
            let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
            mon(&s, "a@x.org", &["gravatar"]);
            r.push(Ok(rpt(st(SourceState::Matched), &[])));
            pass(&s, &r, &n);
            s.kv_set("osint_base_1", bad).unwrap();
            r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/x"])));
            pass(&s, &r, &n);
            // diffed against run 1 (the previous run): one alert, pointer advanced
            assert_eq!(n.sent(), 1, "pointer {bad:?}");
            assert_eq!(ptr(&s, 1).as_deref(), Some("2"), "pointer {bad:?}");
        }
        // a baseline that points at another monitor's run is invalid too
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        mon(&s, "b@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        s.kv_set("osint_base_1", "2").unwrap();
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/y"])));
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/y"])));
        pass(&s, &r, &n);
        assert_eq!(n.sent(), 2);
    }

    #[test]
    fn a_pointer_to_a_pruned_run_with_no_history_is_a_new_baseline() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        s.kv_set("osint_base_1", "77").unwrap();
        r.push(Ok(rpt(st(SourceState::Matched), &["https://e.org/1"])));
        let notes = pass(&s, &r, &n);
        assert!(has(&notes, "baseline stored"));
        assert_eq!(n.sent(), 0);
        assert_eq!(ptr(&s, 1).as_deref(), Some("1"));
    }

    #[test]
    fn validation_findings_are_history_only() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        r.push(Ok(rpt(st(SourceState::Matched), &[])));
        pass(&s, &r, &n);
        let mut rep = rpt(st(SourceState::Matched), &["https://e.org/v"]);
        rep.findings[0].group = Group::Validation;
        r.push(Ok(rep));
        pass(&s, &r, &n);
        assert_eq!(n.sent(), 0);
        assert_eq!(ptr(&s, 1).as_deref(), Some("2"));
    }

    #[test]
    fn disabled_monitors_do_not_run() {
        let (s, r, n) = (FakeStore::default(), FakeRunner::new(), FakeNotifier::new());
        mon(&s, "a@x.org", &["gravatar"]);
        s.set_enabled(1, false).unwrap();
        assert!(pass(&s, &r, &n).is_empty());
        assert!(r.calls.borrow().is_empty());
    }
}
