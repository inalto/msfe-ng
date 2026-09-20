//! Auto-ban of spam sources in csf, and admin match rules.
//!
//! Bans come from the log, not from the scan: `msfe-ng autoban run` (a
//! minute cron) reads the `maillog` rows written since its last run, counts
//! high spam / spam per client IP inside each rule's window, and bans the
//! sources that cross a threshold with a temporary csf deny (`csf -td`).
//! Match rules — a subject, a sender, a header, a body pattern — become
//! SpamAssassin rules named `MSFE_MATCH_<id>` (rendered by `sync` into the
//! site rules dir): score 100 when the rule blocks delivery (the domain's
//! high-spam action takes it), 0.01 when it only tags the message so the
//! source can be banned. Every ban is a row in the `autoban` table.
//!
//! Safeguards are fixed: never own, loopback or private addresses, never an
//! address csf already allows or denies, never an address that also
//! delivered clean mail inside the window (a shared provider IP with one
//! false positive), never the same address twice within a window.

use crate::json::Json;
use crate::{csf, db, telegram, Config};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// ---- durations ----------------------------------------------------------------

/// `"90"`, `"30s"`, `"10m"`, `"2h"`, `"1d"` → seconds; `None` when unparsable.
pub fn parse_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3_600),
        'd' => (&s[..s.len() - 1], 86_400),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// Seconds as the largest unit that divides them: `86400` → `1d`, `3660` →
/// `61m`, `59` → `59s`.
pub fn format_secs(secs: u64) -> String {
    for (unit, size) in [('d', 86_400), ('h', 3_600), ('m', 60)] {
        if secs > 0 && secs % size == 0 {
            return format!("{}{unit}", secs / size);
        }
    }
    format!("{secs}s")
}

// ---- thresholds -----------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub enabled: bool,
    /// Messages within the window that trigger the ban (1 = the first one).
    pub count: u32,
    pub window_secs: u64,
    pub ban_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    pub high: Threshold,
    pub spam: Threshold,
}

impl Rules {
    pub fn from_config(cfg: &Config) -> Rules {
        Rules {
            high: Threshold {
                enabled: cfg.autoban_high_enabled,
                count: cfg.autoban_high_count.max(1),
                window_secs: cfg.autoban_high_window_secs.max(1),
                ban_secs: cfg.autoban_high_ban_secs.max(1),
            },
            spam: Threshold {
                enabled: cfg.autoban_spam_enabled,
                count: cfg.autoban_spam_count.max(1),
                window_secs: cfg.autoban_spam_window_secs.max(1),
                ban_secs: cfg.autoban_spam_ban_secs.max(1),
            },
        }
    }

    pub fn any_enabled(&self) -> bool {
        self.high.enabled || self.spam.enabled
    }

    /// The widest window any enabled rule needs.
    pub fn widest_window(&self, matches: &[MatchRule]) -> u64 {
        let mut w = 0;
        if self.high.enabled {
            w = w.max(self.high.window_secs);
        }
        if self.spam.enabled {
            w = w.max(self.spam.window_secs);
        }
        if matches.iter().any(|m| m.enabled && m.ban_secs > 0) {
            w = w.max(MATCH_WINDOW_SECS);
        }
        w
    }
}

/// A match rule bans on the first message; this is the dedup / clean-mail
/// window it is judged in.
pub const MATCH_WINDOW_SECS: u64 = 3_600;

// ---- match rules -----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchRule {
    pub id: u32,
    pub enabled: bool,
    /// `subject` | `from` | `to` | `header:<Name>` | `body`
    pub field: String,
    /// `contains` | `regex`
    pub matcher: String,
    pub pattern: String,
    /// Score 100 → the domain's high-spam action; never delivered.
    pub block: bool,
    /// Ban the source for this long (0 = no ban).
    pub ban_secs: u64,
    pub comment: String,
    pub created: String,
}

pub const FIELDS: &[&str] = &["subject", "from", "to", "body"];

pub fn match_rules_path(policy_dir: &Path) -> PathBuf {
    policy_dir.join("match.rules.json")
}

pub fn rule_name(id: u32) -> String {
    format!("MSFE_MATCH_{id}")
}

/// Is the field one SpamAssassin can test? (`header:<Name>` needs a name of
/// header characters only.)
pub fn valid_field(field: &str) -> bool {
    if FIELDS.contains(&field) {
        return true;
    }
    field
        .strip_prefix("header:")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

/// The regex SpamAssassin gets: `contains` escapes everything that is not
/// alphanumeric (a literal, case-insensitive); `regex` is taken as given,
/// wrapped in `/…/i` when it has no delimiters.
pub fn pattern_to_regex(matcher: &str, pattern: &str) -> Result<String, String> {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return Err("the pattern is empty".into());
    }
    if pattern.contains('\n') {
        return Err("the pattern must be one line".into());
    }
    match matcher {
        "contains" => {
            let mut out = String::from("/");
            for c in pattern.chars() {
                if c.is_ascii_alphanumeric() || c == ' ' {
                    if c == ' ' {
                        out.push_str("\\ ");
                    } else {
                        out.push(c);
                    }
                } else if c == '/' {
                    out.push_str("\\/");
                } else if c.is_ascii() {
                    out.push('\\');
                    out.push(c);
                } else {
                    out.push(c);
                }
            }
            out.push_str("/i");
            Ok(out)
        }
        "regex" => {
            if pattern.starts_with('/') {
                Ok(pattern.to_string())
            } else {
                Ok(format!("/{}/i", pattern.replace('/', "\\/")))
            }
        }
        other => Err(format!("unknown matcher '{other}' (contains or regex)")),
    }
}

/// The `.cf` SpamAssassin reads. Disabled rules are left out; an empty set
/// still yields the banner, so the file is always ours to overwrite.
pub fn sa_rules_text(rules: &[MatchRule]) -> String {
    let mut out = String::from(
        "# Managed by MSFE-NG (Settings → Auto-ban → Match rules); edits are overwritten on sync.\n",
    );
    for r in rules.iter().filter(|r| r.enabled) {
        let Ok(re) = pattern_to_regex(&r.matcher, &r.pattern) else {
            continue;
        };
        let name = rule_name(r.id);
        let line = match r.field.as_str() {
            "subject" => format!("header {name} Subject =~ {re}"),
            "from" => format!("header {name} From =~ {re}"),
            "to" => format!("header {name} ToCc =~ {re}"),
            "body" => format!("body {name} {re}"),
            f => match f.strip_prefix("header:") {
                Some(h) => format!("header {name} {h} =~ {re}"),
                None => continue,
            },
        };
        let describe = if r.comment.trim().is_empty() {
            format!("{} {} {}", r.field, r.matcher, r.pattern)
        } else {
            r.comment.trim().to_string()
        };
        out.push_str(&format!(
            "\n{line}\ndescribe {name} {}\nscore {name} {}\n",
            describe.replace('\n', " "),
            if r.block { "100" } else { "0.01" }
        ));
    }
    out
}

fn json_u64(j: Option<&Json>) -> u64 {
    match j {
        Some(Json::Int(n)) => (*n).max(0) as u64,
        Some(Json::Num(s)) => s.parse::<f64>().map(|f| f.max(0.0) as u64).unwrap_or(0),
        Some(Json::Str(s)) => parse_secs(s).unwrap_or(0),
        _ => 0,
    }
}

fn json_bool(j: Option<&Json>) -> bool {
    matches!(j, Some(Json::Bool(true)))
}

fn json_str(j: Option<&Json>) -> String {
    match j {
        Some(Json::Str(s)) => s.clone(),
        _ => String::new(),
    }
}

/// A rule from its JSON object (`id` 0 = new, assigned at save).
pub fn match_rule_from_json(j: &Json) -> MatchRule {
    MatchRule {
        id: json_u64(j.get("id")) as u32,
        enabled: json_bool(j.get("enabled")),
        field: json_str(j.get("field")),
        matcher: json_str(j.get("matcher")),
        pattern: json_str(j.get("pattern")),
        block: json_bool(j.get("block")),
        ban_secs: json_u64(j.get("ban_secs")),
        comment: json_str(j.get("comment")),
        created: json_str(j.get("created")),
    }
}

pub fn match_rule_json(r: &MatchRule) -> Json {
    Json::Object(vec![
        ("id".into(), Json::Int(r.id as i64)),
        ("enabled".into(), Json::Bool(r.enabled)),
        ("field".into(), Json::str(&r.field)),
        ("matcher".into(), Json::str(&r.matcher)),
        ("pattern".into(), Json::str(&r.pattern)),
        ("block".into(), Json::Bool(r.block)),
        ("ban_secs".into(), Json::Int(r.ban_secs as i64)),
        ("comment".into(), Json::str(&r.comment)),
        ("created".into(), Json::str(&r.created)),
    ])
}

/// The stored envelope: `{"next_id": N, "rules": [...]}` — ids are never
/// reused, so a rule name in an old spam report still means one thing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchStore {
    pub next_id: u32,
    pub rules: Vec<MatchRule>,
}

pub fn load_match_store(policy_dir: &Path) -> MatchStore {
    let text = std::fs::read_to_string(match_rules_path(policy_dir)).unwrap_or_default();
    let Ok(j) = Json::parse(&text) else {
        return MatchStore {
            next_id: 1,
            rules: Vec::new(),
        };
    };
    let rules: Vec<MatchRule> = match j.get("rules") {
        Some(Json::Array(a)) => a.iter().map(match_rule_from_json).collect(),
        _ => Vec::new(),
    };
    let next_id = (json_u64(j.get("next_id")) as u32)
        .max(rules.iter().map(|r| r.id).max().unwrap_or(0) + 1)
        .max(1);
    MatchStore { next_id, rules }
}

pub fn load_match_rules(policy_dir: &Path) -> Vec<MatchRule> {
    load_match_store(policy_dir).rules
}

/// Save the rules; new ones (`id == 0`) get the next id. Returns the rules
/// as stored.
pub fn save_match_rules(policy_dir: &Path, rules: &[MatchRule]) -> io::Result<Vec<MatchRule>> {
    let mut store = load_match_store(policy_dir);
    let mut next = store.next_id;
    let mut out = Vec::new();
    for r in rules {
        let mut r = r.clone();
        if r.id == 0 {
            r.id = next;
            next += 1;
        } else {
            next = next.max(r.id + 1);
        }
        if r.created.is_empty() {
            r.created = crate::dbtools::stamp(crate::dbtools::now_secs());
        }
        out.push(r);
    }
    store.next_id = next;
    store.rules = out.clone();
    std::fs::create_dir_all(policy_dir)?;
    let j = Json::Object(vec![
        ("next_id".into(), Json::Int(store.next_id as i64)),
        (
            "rules".into(),
            Json::Array(store.rules.iter().map(match_rule_json).collect()),
        ),
    ]);
    crate::sync::atomic_write(&match_rules_path(policy_dir), j.to_string().as_bytes())?;
    Ok(out)
}

/// Do the rules ban anything? (Blocking alone is SpamAssassin's business.)
pub fn any_ban_rule(rules: &[MatchRule]) -> bool {
    rules.iter().any(|r| r.enabled && r.ban_secs > 0)
}

// ---- the decision engine -----------------------------------------------------------

/// One `maillog` row as the engine sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub id: u64,
    /// Unix time the message arrived.
    pub ts: u64,
    pub ip: String,
    pub isspam: bool,
    pub ishighspam: bool,
    /// Match rule ids named in the spam report.
    pub matched: Vec<u32>,
}

/// `MSFE_MATCH_<n>` names in a SpamAssassin report.
pub fn matched_rules(spamreport: &str) -> Vec<u32> {
    let mut out: Vec<u32> = spamreport
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter_map(|w| w.strip_prefix("MSFE_MATCH_"))
        .filter_map(|n| n.parse().ok())
        .collect();
    out.sort();
    out.dedup();
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub ip: String,
    /// `high` | `spam` | `match`
    pub reason: String,
    pub rule_id: Option<u32>,
    pub count: u32,
    pub seconds: u64,
    /// A maillog id that triggered it (the newest).
    pub sample_id: u64,
    /// The comment csf gets.
    pub detail: String,
}

/// Which addresses the rows call for banning, at `now`. Pure.
pub fn evaluate(rows: &[Row], rules: &Rules, matches: &[MatchRule], now: u64) -> Vec<Candidate> {
    let mut by_ip: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
    for r in rows {
        if !r.ip.is_empty() {
            by_ip.entry(r.ip.as_str()).or_default().push(r);
        }
    }
    let in_window = |r: &Row, window: u64| r.ts + window >= now;
    let mut out = Vec::new();
    for (ip, rows) in by_ip {
        let mut best: Option<Candidate> = None;
        let mut consider = |c: Candidate| {
            if best.as_ref().map_or(true, |b| c.seconds > b.seconds) {
                best = Some(c);
            }
        };
        let clean_in = |window: u64| {
            rows.iter()
                .any(|r| in_window(r, window) && !r.isspam && !r.ishighspam && r.matched.is_empty())
        };
        // thresholds
        for (reason, t, pick) in [
            (
                "high",
                rules.high,
                (|r: &Row| r.ishighspam) as fn(&Row) -> bool,
            ),
            ("spam", rules.spam, |r: &Row| r.isspam && !r.ishighspam),
        ] {
            if !t.enabled {
                continue;
            }
            let hits: Vec<&&Row> = rows
                .iter()
                .filter(|r| in_window(r, t.window_secs) && pick(r))
                .collect();
            if hits.len() as u32 >= t.count && !clean_in(t.window_secs) {
                consider(Candidate {
                    ip: ip.to_string(),
                    reason: reason.into(),
                    rule_id: None,
                    count: hits.len() as u32,
                    seconds: t.ban_secs,
                    sample_id: hits.iter().map(|r| r.id).max().unwrap_or(0),
                    detail: format!(
                        "MSFE-NG auto-ban: {} {} message{} in {}",
                        hits.len(),
                        if reason == "high" {
                            "high-spam"
                        } else {
                            "spam"
                        },
                        if hits.len() == 1 { "" } else { "s" },
                        format_secs(t.window_secs)
                    ),
                });
            }
        }
        // match rules: the first hit is enough
        for m in matches.iter().filter(|m| m.enabled && m.ban_secs > 0) {
            let hits: Vec<&&Row> = rows
                .iter()
                .filter(|r| in_window(r, MATCH_WINDOW_SECS) && r.matched.contains(&m.id))
                .collect();
            if !hits.is_empty() && !clean_in(MATCH_WINDOW_SECS) {
                consider(Candidate {
                    ip: ip.to_string(),
                    reason: "match".into(),
                    rule_id: Some(m.id),
                    count: hits.len() as u32,
                    seconds: m.ban_secs,
                    sample_id: hits.iter().map(|r| r.id).max().unwrap_or(0),
                    detail: format!(
                        "MSFE-NG auto-ban: matched rule #{}{}",
                        m.id,
                        if m.comment.trim().is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", m.comment.trim())
                        }
                    ),
                });
            }
        }
        if let Some(c) = best {
            out.push(c);
        }
    }
    out
}

// ---- the run -----------------------------------------------------------------------

/// `maillog` rows since `since_id`, never older than `window_secs`, bounded.
pub fn rows_sql(since_id: u64, window_secs: u64) -> String {
    format!(
        "SELECT row_id, UNIX_TIMESTAMP(msg_ts), clientip, isspam, ishighspam, spamreport FROM maillog \
         WHERE row_id > {since_id} AND msg_ts >= (NOW() - INTERVAL {window_secs} SECOND) AND clientip <> '' \
         ORDER BY row_id LIMIT 20000"
    )
}

/// Addresses this engine banned within `window_secs`.
pub fn recent_bans_sql(window_secs: u64) -> String {
    format!(
        "SELECT DISTINCT ip FROM autoban WHERE banned_at >= (NOW() - INTERVAL {window_secs} SECOND)"
    )
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub dry_run: bool,
    pub enabled: bool,
    pub examined: usize,
    pub candidates: Vec<Candidate>,
    pub banned: Vec<Candidate>,
    /// `(ip, why)` for candidates left alone.
    pub skipped: Vec<(String, String)>,
    pub transcript: Vec<String>,
}

fn parse_row(r: &[String]) -> Option<Row> {
    let get = |i: usize| r.get(i).map(String::as_str).unwrap_or("");
    Some(Row {
        id: get(0).parse().ok()?,
        ts: get(1).parse::<f64>().ok()? as u64,
        ip: csf::normalize_ip(get(2)),
        isspam: get(3) == "1",
        ishighspam: get(4) == "1",
        matched: matched_rules(get(5)),
    })
}

/// Bans per run, so the minute cron stays bounded on a first run over a
/// wide window; the rest re-trigger on their next message.
pub const MAX_BANS_PER_RUN: usize = 100;

/// A pid file so overlapping minute crons never process the same rows.
struct RunGuard(PathBuf);

impl RunGuard {
    fn acquire() -> Result<RunGuard, String> {
        let dir = crate::jobs::jobs_dir();
        let _ = std::fs::create_dir_all(&dir);
        let pid = dir.join("autoban.pid");
        if crate::jobs::pid_alive(&pid) {
            return Err("another auto-ban run is still going".into());
        }
        std::fs::write(&pid, format!("{}\n", std::process::id())).map_err(|e| e.to_string())?;
        Ok(RunGuard(pid))
    }
}

impl Drop for RunGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// One pass: read, decide, ban, record. Never advances the cursor on a dry
/// run.
pub fn run(cfg: &Config, config_file: &Path, dry_run: bool) -> Report {
    let rules = Rules::from_config(cfg);
    let matches = load_match_rules(&crate::sync::policy_dir(config_file));
    let mut rep = Report {
        dry_run,
        enabled: rules.any_enabled() || any_ban_rule(&matches),
        ..Default::default()
    };
    if !rep.enabled {
        rep.transcript.push("auto-ban: nothing enabled".into());
        return rep;
    }
    let _guard = if dry_run {
        None
    } else {
        match RunGuard::acquire() {
            Ok(g) => Some(g),
            Err(e) => {
                rep.transcript.push(format!("auto-ban: {e}"));
                return rep;
            }
        }
    };
    if !cfg.db_configured() {
        rep.transcript
            .push("auto-ban: database not configured — nothing to read".into());
        return rep;
    }
    let window = rules.widest_window(&matches).max(60);
    let since = db::kv_get(cfg, "autoban_last_id")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let raw = match db::query(cfg, &rows_sql(since, window)) {
        Ok(r) => r,
        Err(e) => {
            rep.transcript.push(format!("auto-ban: query failed: {e}"));
            return rep;
        }
    };
    let rows: Vec<Row> = raw.iter().filter_map(|r| parse_row(r)).collect();
    rep.examined = rows.len();
    let max_id = rows.iter().map(|r| r.id).max().unwrap_or(since);
    let now = crate::dbtools::now_secs();
    rep.candidates = evaluate(&rows, &rules, &matches, now);
    rep.transcript.push(format!(
        "auto-ban{}: {} new message(s) since id {since}, {} candidate(s)",
        if dry_run { " (dry run)" } else { "" },
        rows.len(),
        rep.candidates.len()
    ));
    let recent: Vec<String> = db::query(cfg, &recent_bans_sql(window))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| r.first().cloned())
        .collect();
    let csf_ok = csf::available();
    for c in rep.candidates.clone() {
        if let Err(e) = csf::validate_target(&c.ip, false) {
            rep.skipped.push((c.ip.clone(), e));
            continue;
        }
        if recent.iter().any(|r| r == &c.ip) {
            rep.skipped
                .push((c.ip.clone(), "already auto-banned in this window".into()));
            continue;
        }
        if !csf_ok {
            rep.skipped
                .push((c.ip.clone(), "csf is not installed".into()));
            continue;
        }
        match csf::list_state(&c.ip) {
            csf::ListState::Allowed => {
                rep.skipped
                    .push((c.ip.clone(), "listed in csf.allow / csf.ignore".into()));
                continue;
            }
            csf::ListState::Denied => {
                rep.skipped
                    .push((c.ip.clone(), "already denied by csf".into()));
                continue;
            }
            csf::ListState::Unlisted => {}
        }
        if rep.banned.len() >= MAX_BANS_PER_RUN {
            rep.skipped.push((
                c.ip.clone(),
                format!("over {MAX_BANS_PER_RUN} bans in one run — next run"),
            ));
            continue;
        }
        if dry_run {
            rep.transcript.push(format!(
                "would ban {} for {} — {}",
                c.ip,
                format_secs(c.seconds),
                c.detail
            ));
            rep.banned.push(c);
            continue;
        }
        let o = csf::ban_secs(&c.ip, &c.detail, c.seconds);
        rep.transcript.extend(o.transcript.iter().cloned());
        if !o.ok {
            rep.skipped
                .push((c.ip.clone(), "csf refused the ban".into()));
            continue;
        }
        let sql = format!(
            "INSERT INTO autoban (banned_at, expires_at, ip, reason, rule_id, count, seconds, detail, sample_id) \
             VALUES (NOW(), NOW() + INTERVAL {} SECOND, {}, {}, {}, {}, {}, {}, {})",
            c.seconds,
            db::quote(&c.ip),
            db::quote(&c.reason),
            c.rule_id.map(|r| r.to_string()).unwrap_or_else(|| "NULL".into()),
            c.count,
            c.seconds,
            db::quote(&c.detail),
            c.sample_id
        );
        if let Err(e) = db::exec_stdin(cfg, &sql) {
            rep.transcript.push(format!("autoban table: {e}"));
        }
        if cfg.autoban_telegram && telegram::configured(cfg) {
            let text = format!(
                "MSFE-NG auto-ban: {} banned for {} — {}",
                c.ip,
                format_secs(c.seconds),
                c.detail.trim_start_matches("MSFE-NG auto-ban: ")
            );
            let _ = telegram::send(cfg, &text);
        }
        rep.banned.push(c);
    }
    for (ip, why) in &rep.skipped {
        rep.transcript.push(format!("skipped {ip}: {why}"));
    }
    if !dry_run {
        let _ = db::kv_set(cfg, "autoban_last_id", &max_id.to_string());
        let _ = db::kv_set(cfg, "autoban_last_run", &now.to_string());
    }
    rep.transcript.push(format!(
        "→ {} banned, {} skipped",
        rep.banned.len(),
        rep.skipped.len()
    ));
    rep
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRow {
    pub id: u64,
    pub banned_at: String,
    pub expires_at: String,
    pub ip: String,
    pub reason: String,
    pub rule_id: Option<u32>,
    pub count: u32,
    pub seconds: u64,
    pub detail: String,
    pub sample_id: u64,
}

/// The newest bans first.
pub fn history(cfg: &Config, limit: usize) -> Vec<BanRow> {
    if !cfg.db_configured() {
        return Vec::new();
    }
    let sql = format!(
        "SELECT id, banned_at, IFNULL(expires_at,''), ip, reason, IFNULL(rule_id,''), count, seconds, detail, IFNULL(sample_id,0) \
         FROM autoban ORDER BY id DESC LIMIT {}",
        limit.clamp(1, 1000)
    );
    db::query(cfg, &sql)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|r| {
            let get = |i: usize| r.get(i).cloned().unwrap_or_default();
            Some(BanRow {
                id: get(0).parse().ok()?,
                banned_at: get(1),
                expires_at: get(2),
                ip: get(3),
                reason: get(4),
                rule_id: get(5).parse().ok(),
                count: get(6).parse().unwrap_or(0),
                seconds: get(7).parse().unwrap_or(0),
                detail: get(8),
                sample_id: get(9).parse().unwrap_or(0),
            })
        })
        .collect()
}

pub fn ban_row_json(b: &BanRow) -> Json {
    Json::Object(vec![
        ("id".into(), Json::Int(b.id as i64)),
        ("banned_at".into(), Json::str(&b.banned_at)),
        ("expires_at".into(), Json::str(&b.expires_at)),
        ("ip".into(), Json::str(&b.ip)),
        ("reason".into(), Json::str(&b.reason)),
        (
            "rule_id".into(),
            b.rule_id.map(|r| Json::Int(r as i64)).unwrap_or(Json::Null),
        ),
        ("count".into(), Json::Int(b.count as i64)),
        ("seconds".into(), Json::Int(b.seconds as i64)),
        ("detail".into(), Json::str(&b.detail)),
        ("sample_id".into(), Json::Int(b.sample_id as i64)),
    ])
}

// ---- pattern validation and testing (perl: SpamAssassin's own regex engine) -----------

/// Split `/pattern/flags` into its parts.
fn split_regex(re: &str) -> Option<(&str, &str)> {
    let rest = re.strip_prefix('/')?;
    let end = rest.rfind('/')?;
    Some((&rest[..end], &rest[end + 1..]))
}

/// Does the regex compile under `perl` (the engine's), exactly as
/// SpamAssassin will compile it? `Err` carries perl's message.
pub fn check_regex(perl: &[String], re: &str) -> Result<(), String> {
    let Some((pat, flags)) = split_regex(re) else {
        return Err("a regex must look like /pattern/flags".into());
    };
    if !flags.chars().all(|c| matches!(c, 'i' | 'm' | 's' | 'x')) {
        return Err(format!("unsupported regex flags '{flags}'"));
    }
    let (interp, args) = perl
        .split_first()
        .map(|(i, a)| (i.as_str(), a))
        .unwrap_or(("perl", &[][..]));
    let script = "my ($p, $f) = @ARGV; my $r = eval { qr/(?$f)$p/ }; if (!$r) { my $e = $@; $e =~ s/ at -e line.*//s; print STDERR $e; exit 2 } exit 0";
    let out = Command::new(interp)
        .args(args)
        .args(["-e", script, "--", pat, flags])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run perl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let e = String::from_utf8_lossy(&out.stderr).trim().to_string();
        Err(if e.is_empty() {
            "the regex does not compile".into()
        } else {
            e
        })
    }
}

/// Which of the last `limit` messages the pattern matches, for the fields
/// the log holds (`subject`, `from`, `to`); `(maillog id, value)`. Other
/// fields are only validated (empty list).
pub fn test_pattern(
    cfg: &Config,
    perl: &[String],
    field: &str,
    matcher: &str,
    pattern: &str,
    limit: usize,
) -> Result<(String, Vec<(String, String)>), String> {
    let re = pattern_to_regex(matcher, pattern)?;
    check_regex(perl, &re)?;
    let column = match field {
        "subject" => "subject",
        "from" => "from_address",
        "to" => "to_address",
        _ => return Ok((re, Vec::new())),
    };
    if !cfg.db_configured() {
        return Ok((re, Vec::new()));
    }
    let rows = db::query(
        cfg,
        &format!(
            "SELECT row_id, {column} FROM maillog ORDER BY row_id DESC LIMIT {}",
            limit.clamp(1, 2000)
        ),
    )
    .map_err(|e| e.to_string())?;
    let (pat, flags) = split_regex(&re).unwrap_or((&re, ""));
    let (interp, args) = perl
        .split_first()
        .map(|(i, a)| (i.as_str(), a))
        .unwrap_or(("perl", &[][..]));
    let script = "my ($p, $f) = @ARGV; my $r = qr/(?$f)$p/; while (my $l = <STDIN>) { chomp $l; my ($id, $v) = split /\\t/, $l, 2; print \"$id\\n\" if defined $v && $v =~ $r }";
    let mut child = Command::new(interp)
        .args(args)
        .args(["-e", script, "--", pat, flags])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run perl: {e}"))?;
    if let Some(mut si) = child.stdin.take() {
        use std::io::Write;
        for r in &rows {
            let id = r.first().cloned().unwrap_or_default();
            let v = r
                .get(1)
                .cloned()
                .unwrap_or_default()
                .replace(['\t', '\n'], " ");
            let _ = writeln!(si, "{id}\t{v}");
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("perl failed: {e}"))?;
    let hits: std::collections::HashSet<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect();
    Ok((
        re,
        rows.into_iter()
            .filter(|r| r.first().is_some_and(|id| hits.contains(id)))
            .map(|r| {
                (
                    r.first().cloned().unwrap_or_default(),
                    r.get(1).cloned().unwrap_or_default(),
                )
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_round_trip() {
        assert_eq!(parse_secs("1d"), Some(86_400));
        assert_eq!(parse_secs("2h"), Some(7_200));
        assert_eq!(parse_secs("10m"), Some(600));
        assert_eq!(parse_secs("30s"), Some(30));
        assert_eq!(parse_secs("90"), Some(90));
        assert_eq!(parse_secs("0"), Some(0));
        assert_eq!(parse_secs("x"), None);
        assert_eq!(parse_secs(""), None);
        assert_eq!(format_secs(86_400), "1d");
        assert_eq!(format_secs(3_600), "1h");
        assert_eq!(format_secs(3_660), "61m");
        assert_eq!(format_secs(59), "59s");
        assert_eq!(format_secs(0), "0s");
    }

    #[test]
    fn rules_from_config_defaults_are_off() {
        let r = Rules::from_config(&Config::default());
        assert!(!r.any_enabled());
        assert_eq!(r.high.count, 1);
        assert_eq!(r.high.ban_secs, 86_400);
        assert_eq!(r.spam.count, 3);
        let cfg = Config {
            autoban_high_enabled: true,
            ..Config::default()
        };
        assert!(Rules::from_config(&cfg).any_enabled());
        assert_eq!(Rules::from_config(&cfg).widest_window(&[]), 600);
    }

    #[test]
    fn contains_pattern_is_escaped() {
        assert_eq!(
            pattern_to_regex("contains", "a.b/c (x)").unwrap(),
            r"/a\.b\/c\ \(x\)/i"
        );
        assert_eq!(pattern_to_regex("contains", "Hello").unwrap(), "/Hello/i");
        assert!(pattern_to_regex("contains", "  ").is_err());
        assert!(pattern_to_regex("glob", "x").is_err());
    }

    #[test]
    fn regex_pattern_is_wrapped_when_bare() {
        assert_eq!(pattern_to_regex("regex", "foo|bar").unwrap(), "/foo|bar/i");
        assert_eq!(pattern_to_regex("regex", "/foo/").unwrap(), "/foo/");
        assert_eq!(pattern_to_regex("regex", "a/b").unwrap(), r"/a\/b/i");
    }

    fn rule(
        id: u32,
        field: &str,
        matcher: &str,
        pattern: &str,
        block: bool,
        ban: u64,
    ) -> MatchRule {
        MatchRule {
            id,
            enabled: true,
            field: field.into(),
            matcher: matcher.into(),
            pattern: pattern.into(),
            block,
            ban_secs: ban,
            comment: String::new(),
            created: String::new(),
        }
    }

    #[test]
    fn sa_rules_text_renders_each_field() {
        let mut a = rule(3, "subject", "contains", "account suspended", true, 86_400);
        a.comment = "suspension wave".into();
        let b = rule(4, "from", "regex", "@spammy\\.example$", false, 3_600);
        let mut off = rule(5, "body", "contains", "x", true, 0);
        off.enabled = false;
        let h = rule(6, "header:X-Mailer", "contains", "MassMail", true, 0);
        let text = sa_rules_text(&[a, b, off, h]);
        assert_eq!(
            text,
            "# Managed by MSFE-NG (Settings → Auto-ban → Match rules); edits are overwritten on sync.\n\
             \nheader MSFE_MATCH_3 Subject =~ /account\\ suspended/i\ndescribe MSFE_MATCH_3 suspension wave\nscore MSFE_MATCH_3 100\n\
             \nheader MSFE_MATCH_4 From =~ /@spammy\\.example$/i\ndescribe MSFE_MATCH_4 from regex @spammy\\.example$\nscore MSFE_MATCH_4 0.01\n\
             \nheader MSFE_MATCH_6 X-Mailer =~ /MassMail/i\ndescribe MSFE_MATCH_6 header:X-Mailer contains MassMail\nscore MSFE_MATCH_6 100\n"
        );
        assert!(sa_rules_text(&[]).starts_with("# Managed by MSFE-NG"));
        assert!(
            valid_field("header:X-Mailer")
                && valid_field("body")
                && !valid_field("header:")
                && !valid_field("cc")
        );
    }

    #[test]
    fn match_rules_json_round_trip_never_reuses_ids() {
        let dir = std::env::temp_dir().join(format!("msfe-autoban-json-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(load_match_rules(&dir).is_empty());
        let saved = save_match_rules(
            &dir,
            &[
                rule(0, "subject", "contains", "a", true, 0),
                rule(0, "from", "contains", "b", false, 60),
                rule(0, "body", "contains", "c", true, 0),
            ],
        )
        .unwrap();
        assert_eq!(
            saved.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert!(!saved[0].created.is_empty());
        let loaded = load_match_rules(&dir);
        assert_eq!(loaded, saved);
        // delete #3, add one: id 4, never 3 again
        let saved = save_match_rules(
            &dir,
            &[
                loaded[0].clone(),
                loaded[1].clone(),
                rule(0, "to", "contains", "d", true, 0),
            ],
        )
        .unwrap();
        assert_eq!(
            saved.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2, 4]
        );
        assert_eq!(load_match_store(&dir).next_id, 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn matched_rules_parses_the_report() {
        assert_eq!(
            matched_rules("spam, SpamAssassin (score=100.5, required 6, MSFE_MATCH_3 100.00, BAYES_50 0.80, MSFE_MATCH_12 0.01)"),
            vec![3, 12]
        );
        assert!(matched_rules("not spam, SpamAssassin (score=0.1)").is_empty());
    }

    fn row(id: u64, ts: u64, ip: &str, spam: bool, high: bool, matched: &[u32]) -> Row {
        Row {
            id,
            ts,
            ip: ip.into(),
            isspam: spam || high,
            ishighspam: high,
            matched: matched.to_vec(),
        }
    }

    fn rules(high: (bool, u32, u64, u64), spam: (bool, u32, u64, u64)) -> Rules {
        Rules {
            high: Threshold {
                enabled: high.0,
                count: high.1,
                window_secs: high.2,
                ban_secs: high.3,
            },
            spam: Threshold {
                enabled: spam.0,
                count: spam.1,
                window_secs: spam.2,
                ban_secs: spam.3,
            },
        }
    }

    #[test]
    fn threshold_reached_only_inside_the_window() {
        let r = rules((false, 1, 600, 86_400), (true, 3, 3_600, 7_200));
        let now = 100_000;
        let rows = vec![
            row(1, now - 100, "1.2.3.4", true, false, &[]),
            row(2, now - 200, "1.2.3.4", true, false, &[]),
            row(3, now - 5_000, "1.2.3.4", true, false, &[]), // outside 1h
        ];
        assert!(evaluate(&rows, &r, &[], now).is_empty(), "2 in window < 3");
        let mut rows = rows;
        rows.push(row(4, now - 300, "1.2.3.4", true, false, &[]));
        let c = evaluate(&rows, &r, &[], now);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].ip, "1.2.3.4");
        assert_eq!(c[0].reason, "spam");
        assert_eq!(c[0].count, 3);
        assert_eq!(c[0].seconds, 7_200);
        assert_eq!(c[0].sample_id, 4);
        assert_eq!(c[0].detail, "MSFE-NG auto-ban: 3 spam messages in 1h");
    }

    #[test]
    fn high_count_one_bans_on_first_message() {
        let r = rules((true, 1, 600, 86_400), (false, 3, 3_600, 7_200));
        let now = 100_000;
        let rows = vec![row(9, now - 10, "5.6.7.8", false, true, &[])];
        let c = evaluate(&rows, &r, &[], now);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].reason, "high");
        assert_eq!(c[0].detail, "MSFE-NG auto-ban: 1 high-spam message in 10m");
        // a high-spam message does not count as plain spam
        let r = rules((false, 1, 600, 86_400), (true, 1, 3_600, 7_200));
        assert!(evaluate(&rows, &r, &[], now).is_empty());
    }

    #[test]
    fn clean_mail_in_the_window_exempts_the_ip() {
        let r = rules((true, 1, 600, 86_400), (false, 3, 3_600, 7_200));
        let now = 100_000;
        let rows = vec![
            row(1, now - 10, "5.6.7.8", false, true, &[]),
            row(2, now - 20, "5.6.7.8", false, false, &[]), // clean from the same IP
        ];
        assert!(evaluate(&rows, &r, &[], now).is_empty());
        // clean mail outside the window does not protect
        let rows = vec![
            row(1, now - 10, "5.6.7.8", false, true, &[]),
            row(2, now - 700, "5.6.7.8", false, false, &[]),
        ];
        assert_eq!(evaluate(&rows, &r, &[], now).len(), 1);
    }

    #[test]
    fn match_rule_bans_immediately_with_its_duration() {
        let r = rules((false, 1, 600, 86_400), (false, 3, 3_600, 7_200));
        let mut m = rule(3, "subject", "contains", "x", true, 172_800);
        m.comment = "wave".into();
        let now = 100_000;
        let rows = vec![row(1, now - 10, "9.9.9.9", false, true, &[3])];
        let c = evaluate(&rows, &r, &[m.clone()], now);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].reason, "match");
        assert_eq!(c[0].rule_id, Some(3));
        assert_eq!(c[0].seconds, 172_800);
        assert_eq!(c[0].detail, "MSFE-NG auto-ban: matched rule #3 (wave)");
        // a blocking rule without a ban never bans
        m.ban_secs = 0;
        assert!(evaluate(&rows, &r, &[m.clone()], now).is_empty());
        // disabled: nothing
        m.ban_secs = 60;
        m.enabled = false;
        assert!(evaluate(&rows, &r, &[m], now).is_empty());
    }

    #[test]
    fn longest_ban_wins_per_ip() {
        let r = rules((true, 1, 600, 3_600), (true, 1, 3_600, 7_200));
        let m = rule(2, "subject", "contains", "x", false, 86_400);
        let now = 100_000;
        let rows = vec![
            row(1, now - 10, "1.1.1.1", false, true, &[2]),
            row(2, now - 20, "1.1.1.1", true, false, &[]),
        ];
        let c = evaluate(&rows, &r, &[m], now);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].reason, "match");
        assert_eq!(c[0].seconds, 86_400);
    }

    #[test]
    fn disabled_rules_never_fire() {
        let r = rules((false, 1, 600, 86_400), (false, 1, 3_600, 7_200));
        let now = 100_000;
        let rows = vec![row(1, now - 10, "1.1.1.1", false, true, &[])];
        assert!(evaluate(&rows, &r, &[], now).is_empty());
        assert_eq!(
            rows_sql(42, 3_600),
            "SELECT row_id, UNIX_TIMESTAMP(msg_ts), clientip, isspam, ishighspam, spamreport FROM maillog \
             WHERE row_id > 42 AND msg_ts >= (NOW() - INTERVAL 3600 SECOND) AND clientip <> '' \
             ORDER BY row_id LIMIT 20000"
        );
    }

    #[test]
    fn check_regex_accepts_and_rejects() {
        if Command::new("perl").arg("-e1").status().is_err() {
            return;
        }
        let perl = vec!["perl".to_string()];
        assert_eq!(check_regex(&perl, "/a+b/i"), Ok(()));
        let e = check_regex(&perl, "/a(/").unwrap_err();
        assert!(e.contains("Unmatched") || e.contains("regex"), "{e}");
        assert!(check_regex(&perl, "a+").is_err(), "needs delimiters");
        assert!(check_regex(&perl, "/a/q").is_err(), "unknown flag");
    }
}
