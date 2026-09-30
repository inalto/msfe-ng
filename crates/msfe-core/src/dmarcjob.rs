//! `msfe-ng dmarc fetch`: read the rua= mailbox, store the reports, clean up.
//!
//! Each mail is fetched (without marking it read), its report attachments
//! parsed and stored in one transaction per report. Only then is the mail
//! deleted — a duplicate report (already stored) is deleted too. A mail that
//! carries no report, or one that does not parse, is flagged \Seen and
//! remembered so later runs skip it; it stays for the admin to look at.
//! After the mailbox: new unknown sources failing DMARC are announced on
//! Telegram, missing reverse DNS is filled in, and old rows are pruned.

use crate::config::Config;
use crate::db;
use crate::dmarcrep::{self, Report};
use crate::json::Json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::Path;

pub const LOCK: &str = "/run/msfe-ng-dmarc.lock";

/// The lock file; `MSFE_NG_DMARC_LOCK` moves it (tests, unprivileged runs).
pub fn lock_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_DMARC_LOCK")
        .unwrap_or_else(|_| LOCK.to_string())
        .into()
}
const LAST_RUN_KEY: &str = "dmarc_last_run";
const SKIP_KEY: &str = "dmarc_skip";
const MAX_SKIP: usize = 5000;
const RDNS_PER_RUN: usize = 50;

#[derive(Debug, Clone, Default)]
pub struct Options {
    /// fetch and parse, but write nothing and leave the mailbox alone
    pub dry: bool,
    /// store, but never delete mails
    pub keep: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub at: u64,
    pub ok: bool,
    pub dry: bool,
    pub mails: usize,
    pub reports: usize,
    pub stored: usize,
    pub duplicates: usize,
    pub skipped: usize,
    pub failed: usize,
    pub deleted: usize,
    pub alerts: usize,
    pub pruned: bool,
    pub errors: Vec<String>,
    pub log: Vec<String>,
}

impl Summary {
    fn err(&mut self, e: String) {
        if self.errors.len() < 10 {
            self.errors.push(e.clone());
        }
        self.log.push(format!("✗ {e}"));
    }
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("at".into(), Json::Int(self.at as i64)),
            ("ok".into(), Json::Bool(self.ok)),
            ("dry".into(), Json::Bool(self.dry)),
            ("mails".into(), Json::Int(self.mails as i64)),
            ("reports".into(), Json::Int(self.reports as i64)),
            ("stored".into(), Json::Int(self.stored as i64)),
            ("duplicates".into(), Json::Int(self.duplicates as i64)),
            ("skipped".into(), Json::Int(self.skipped as i64)),
            ("failed".into(), Json::Int(self.failed as i64)),
            ("deleted".into(), Json::Int(self.deleted as i64)),
            ("alerts".into(), Json::Int(self.alerts as i64)),
            (
                "errors".into(),
                Json::Array(self.errors.iter().map(Json::str).collect()),
            ),
        ])
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A pid lock file: one fetch at a time (cron and the UI's "Fetch now").
pub struct Lock(std::path::PathBuf);

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// True when a fetch holds the lock (its pid still alive).
pub fn running(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|p| p.trim().parse::<u32>().ok())
        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

pub fn lock(path: &Path) -> Result<Lock, String> {
    use std::io::Write;
    for _ in 0..2 {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut f) => {
                let _ = write!(f, "{}", std::process::id());
                return Ok(Lock(path.to_path_buf()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if running(path) {
                    return Err("another DMARC fetch is running".into());
                }
                let _ = std::fs::remove_file(path); // stale: its process is gone
            }
            Err(e) => return Err(format!("cannot create {}: {e}", path.display())),
        }
    }
    Err("cannot take the DMARC fetch lock".into())
}

/// This server's addresses: the interfaces' global ones, cPanel's main IP,
/// its extra IPs and the per-domain outgoing IPs. `root` prefixes the files
/// (tests); interfaces are read only when it is "/".
pub fn own_ips(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut add = |s: &str| {
        if let Ok(ip) = s.trim().parse::<IpAddr>() {
            if !ip.is_loopback() && !ip.is_unspecified() {
                out.insert(ip.to_string());
            }
        }
    };
    let read =
        |p: &str| std::fs::read_to_string(root.join(p.trim_start_matches('/'))).unwrap_or_default();
    add(&read("/var/cpanel/mainip"));
    for l in read("/etc/ips").lines() {
        add(l.split(':').next().unwrap_or(""));
    }
    for l in read("/etc/mailips").lines() {
        if let Some((_, ip)) = l.split_once(':') {
            add(ip);
        }
    }
    if root == Path::new("/") {
        if let Ok(o) = std::process::Command::new("ip")
            .args(["-o", "addr", "show", "scope", "global"])
            .output()
        {
            for l in String::from_utf8_lossy(&o.stdout).lines() {
                let mut w = l.split_whitespace();
                while let Some(t) = w.next() {
                    if t == "inet" || t == "inet6" {
                        if let Some(a) = w.next() {
                            add(a.split('/').next().unwrap_or(""));
                        }
                    }
                }
            }
        }
    }
    out
}

pub enum Stored {
    New,
    Duplicate,
}

/// Store one report unless (org_name, report_id) is already there.
pub fn store(cfg: &Config, r: &Report, origin: &str) -> Result<Stored, String> {
    let dup = db::query(
        cfg,
        &format!(
            "SELECT id FROM dmarc_reports WHERE org_name={} AND report_id={} LIMIT 1",
            db::quote(&r.org_name),
            db::quote(&r.report_id)
        ),
    )
    .map_err(|e| e.to_string())?;
    if !dup.is_empty() {
        return Ok(Stored::Duplicate);
    }
    db::exec_stdin(cfg, &dmarcrep::insert_sql(r, origin))
        .map_err(|e| format!("storing the report failed: {e}"))?;
    Ok(Stored::New)
}

/// Failing messages per (ip, header_from) in a report that could be spoofing:
/// not passed, not forwarded, not from this server.
pub fn suspects(r: &Report, own: &BTreeSet<String>) -> BTreeMap<(String, String), u64> {
    let mut m = BTreeMap::new();
    for x in &r.records {
        if x.passed() || x.forwarded() || own.contains(&x.source_ip) {
            continue;
        }
        let hf = if x.header_from.is_empty() {
            r.domain.clone()
        } else {
            x.header_from.clone()
        };
        *m.entry((x.source_ip.clone(), hf)).or_insert(0) += x.count;
    }
    m
}

/// Telegram once per new unknown source failing on at least the threshold.
fn alert(cfg: &Config, r: &Report, own: &BTreeSet<String>, s: &mut Summary) {
    if !cfg.dmarc_alerts || !crate::telegram::configured(cfg) {
        return;
    }
    for ((ip, dom), n) in suspects(r, own) {
        if n < cfg.dmarc_alert_min_messages.max(1) as u64 {
            continue;
        }
        let row = db::query(
            cfg,
            &format!(
                "SELECT status, alerted_at IS NOT NULL, IFNULL(rdns,'') FROM dmarc_sources WHERE ip={} AND domain={}",
                db::quote(&ip),
                db::quote(&dom)
            ),
        )
        .unwrap_or_default();
        let Some(row) = row.first() else { continue };
        if row.first().map(String::as_str) != Some("unknown")
            || row.get(1).map(String::as_str) == Some("1")
        {
            continue;
        }
        let rdns = match row.get(2).map(String::as_str) {
            Some(x) if !x.is_empty() => x.to_string(),
            _ => crate::csf::reverse_dns(&ip),
        };
        let text = format!(
            "⚠️ DMARC: unknown source failing for {dom}\n{ip}{} sent {n} message(s) as {dom} that failed SPF and DKIM ({} report, {}).\nTriage it in Delivery → DMARC reports.",
            if rdns.is_empty() { String::new() } else { format!(" ({rdns})") },
            r.org_name,
            crate::civil::Date::from_unix(r.begin.max(0) as u64)
        );
        match crate::telegram::send(cfg, &text) {
            Ok(()) => {
                s.alerts += 1;
                let _ = db::exec_stdin(
                    cfg,
                    &format!(
                        "UPDATE dmarc_sources SET alerted_at=UTC_TIMESTAMP() WHERE ip={} AND domain={};\n",
                        db::quote(&ip),
                        db::quote(&dom)
                    ),
                );
            }
            Err(e) => s.err(format!("Telegram alert: {e}")),
        }
    }
}

/// Reverse DNS for sources that have none yet, a bounded number per run.
fn fill_rdns(cfg: &Config) {
    let rows = db::query(
        cfg,
        &format!("SELECT DISTINCT ip FROM dmarc_sources WHERE rdns IS NULL ORDER BY last_seen DESC LIMIT {RDNS_PER_RUN}"),
    )
    .unwrap_or_default();
    let mut sql = String::new();
    for r in rows {
        let Some(ip) = r.first() else { continue };
        let name = crate::csf::reverse_dns(ip);
        sql.push_str(&format!(
            "UPDATE dmarc_sources SET rdns={} WHERE ip={};\n",
            db::quote(&name.chars().take(253).collect::<String>()),
            db::quote(ip)
        ));
    }
    if !sql.is_empty() {
        let _ = db::exec_stdin(cfg, &sql);
    }
}

/// Drop rows older than the retention.
pub fn prune(cfg: &Config) -> Result<(), String> {
    let d = cfg.dmarc_retention_days.max(7);
    let sql = format!(
        "DELETE FROM dmarc_records WHERE day < UTC_DATE() - INTERVAL {d} DAY;\n\
         DELETE FROM dmarc_reports WHERE day < UTC_DATE() - INTERVAL {d} DAY;\n\
         DELETE FROM dmarc_sources WHERE last_seen < UTC_DATE() - INTERVAL {d} DAY AND status='unknown';\n"
    );
    db::exec_stdin(cfg, &sql).map_err(|e| e.to_string())
}

fn load_skip(cfg: &Config, uidvalidity: u64) -> BTreeSet<u32> {
    let v = db::kv_get(cfg, SKIP_KEY).unwrap_or_default();
    match v.split_once(':') {
        Some((uv, list)) if uv.parse() == Ok(uidvalidity) => {
            list.split(',').filter_map(|u| u.parse().ok()).collect()
        }
        _ => BTreeSet::new(),
    }
}

fn save_skip(cfg: &Config, uidvalidity: u64, skip: &BTreeSet<u32>) {
    let list: Vec<String> = skip
        .iter()
        .rev()
        .take(MAX_SKIP)
        .map(|u| u.to_string())
        .collect();
    let _ = db::kv_set(cfg, SKIP_KEY, &format!("{uidvalidity}:{}", list.join(",")));
}

/// The outcome of one mail's reports: store them all, or say why not.
enum MailOutcome {
    /// every report stored or already known: the mail can go
    Done { stored: usize, duplicates: usize },
    /// nothing report-like (`failed` false), or a report that failed to
    /// parse or store: keep the mail and skip it from now on
    Keep { why: String, failed: bool },
}

fn handle_mail(
    cfg: &Config,
    uid: u32,
    raw: &[u8],
    opt: &Options,
    own: &BTreeSet<String>,
    s: &mut Summary,
) -> MailOutcome {
    let found = dmarcrep::extract(raw);
    if found.is_empty() {
        return MailOutcome::Keep {
            why: format!("UID {uid}: no report attachment"),
            failed: false,
        };
    }
    let (mut stored, mut duplicates) = (0, 0);
    for (name, r) in found {
        s.reports += 1;
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                s.failed += 1;
                return MailOutcome::Keep {
                    why: format!("UID {uid} {name}: {e}"),
                    failed: true,
                };
            }
        };
        let what = format!(
            "{} {} {} ({} records)",
            r.org_name,
            r.domain,
            crate::civil::Date::from_unix(r.begin.max(0) as u64),
            r.records.len()
        );
        if opt.dry {
            s.log.push(format!("· would store {what}"));
            stored += 1;
            continue;
        }
        match store(cfg, &r, "imap") {
            Ok(Stored::New) => {
                s.log.push(format!("✓ stored {what}"));
                stored += 1;
                alert(cfg, &r, own, s);
            }
            Ok(Stored::Duplicate) => {
                s.log.push(format!("= already stored: {what}"));
                duplicates += 1;
            }
            Err(e) => {
                s.failed += 1;
                return MailOutcome::Keep {
                    why: format!("UID {uid} {what}: {e}"),
                    failed: true,
                };
            }
        }
    }
    MailOutcome::Done { stored, duplicates }
}

/// One fetch run. Always returns a summary; `ok` false when the mailbox
/// could not be read at all.
pub fn run(cfg: &Config, opt: &Options) -> Summary {
    let mut s = Summary {
        at: now(),
        dry: opt.dry,
        ..Default::default()
    };
    if !cfg.dmarc_configured() {
        s.err("no DMARC report mailbox is configured".into());
        return s;
    }
    let _lock = match lock(&lock_path()) {
        Ok(l) => l,
        Err(e) => {
            s.err(e);
            return s;
        }
    };
    run_locked(cfg, opt, &mut s);
    if !opt.dry {
        let _ = db::kv_set(cfg, LAST_RUN_KEY, &s.to_json().to_string());
    }
    s
}

fn run_locked(cfg: &Config, opt: &Options, s: &mut Summary) {
    let st = match crate::imap::status(cfg) {
        Ok(st) => st,
        Err(e) => return s.err(e),
    };
    let uids = match crate::imap::uids(cfg) {
        Ok(u) => u,
        Err(e) => return s.err(e),
    };
    s.ok = true;
    let mut skip = load_skip(cfg, st.uidvalidity);
    let own = own_ips(Path::new("/"));
    let (mut done, mut seen) = (Vec::new(), Vec::new());
    let mut uids = uids;
    uids.sort_unstable(); // UIDs ascend with sequence numbers
    for (i, uid) in uids.iter().copied().enumerate() {
        if skip.contains(&uid) {
            continue;
        }
        s.mails += 1;
        let raw = match crate::imap::fetch(cfg, uid, i as u32 + 1) {
            Ok(r) => r,
            Err(e) => {
                s.err(format!("UID {uid}: {e}"));
                continue;
            }
        };
        match handle_mail(cfg, uid, &raw, opt, &own, s) {
            MailOutcome::Done { stored, duplicates } => {
                s.stored += stored;
                s.duplicates += duplicates;
                done.push(uid);
            }
            MailOutcome::Keep { why, failed } => {
                s.skipped += 1;
                if failed {
                    s.err(why);
                } else {
                    s.log.push(format!("· kept {why}"));
                }
                seen.push(uid);
            }
        }
    }
    if opt.dry {
        return;
    }
    if !seen.is_empty() {
        if let Err(e) = crate::imap::mark_seen(cfg, &seen) {
            s.err(format!("flagging kept mails \\Seen: {e}"));
        }
        skip.extend(&seen);
        save_skip(cfg, st.uidvalidity, &skip);
    }
    if cfg.dmarc_delete_imported && !opt.keep && !done.is_empty() {
        match crate::imap::delete(cfg, &done) {
            Ok(()) => s.deleted = done.len(),
            Err(e) => s.err(format!("deleting imported mails: {e}")),
        }
    }
    fill_rdns(cfg);
    match prune(cfg) {
        Ok(()) => s.pruned = true,
        Err(e) => s.err(format!("pruning: {e}")),
    }
}

/// `msfe-ng dmarc import FILE`: a report file (xml, gz, zip) or a saved mail.
pub fn import_file(cfg: &Config, path: &Path) -> Summary {
    let mut s = Summary {
        at: now(),
        ..Default::default()
    };
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            s.err(format!("{}: {e}", path.display()));
            return s;
        }
    };
    s.ok = true;
    let own = own_ips(Path::new("/"));
    for (_, r) in dmarcrep::from_file(&bytes) {
        s.reports += 1;
        match r {
            Err(e) => {
                s.failed += 1;
                s.err(e);
            }
            Ok(r) => match store(cfg, &r, "file") {
                Ok(Stored::New) => {
                    s.stored += 1;
                    s.log.push(format!(
                        "✓ stored {} {} ({} records)",
                        r.org_name,
                        r.domain,
                        r.records.len()
                    ));
                    alert(cfg, &r, &own, &mut s);
                }
                Ok(Stored::Duplicate) => {
                    s.duplicates += 1;
                    s.log
                        .push(format!("= already stored: {} {}", r.org_name, r.report_id));
                }
                Err(e) => {
                    s.failed += 1;
                    s.err(e);
                }
            },
        }
    }
    if s.reports == 0 {
        s.err("no DMARC report found in the file".into());
    }
    s
}

/// The last run's summary (JSON), if any.
pub fn last_run(cfg: &Config) -> Option<Json> {
    db::kv_get(cfg, LAST_RUN_KEY).and_then(|t| Json::parse(&t).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_ips_from_cpanel_files() {
        let root = std::env::temp_dir().join(format!("msfe-dmarc-ips-{}", std::process::id()));
        std::fs::create_dir_all(root.join("var/cpanel")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("var/cpanel/mainip"), "198.51.100.1").unwrap();
        std::fs::write(
            root.join("etc/ips"),
            "198.51.100.2:255.255.255.0:198.51.100.255\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/mailips"),
            "*: 198.51.100.3\nexample.com: 2001:db8::5\nbad: x\n",
        )
        .unwrap();
        let ips = own_ips(&root);
        let _ = std::fs::remove_dir_all(&root);
        let want: BTreeSet<String> = [
            "198.51.100.1",
            "198.51.100.2",
            "198.51.100.3",
            "2001:db8::5",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(ips, want);
    }

    #[test]
    fn suspects_skip_pass_forwarded_and_own() {
        let xml = include_str!("../tests/fixtures/dmarc/outlook-example.org.xml");
        let mut r = dmarcrep::parse(xml).unwrap();
        let mut bad = r.records[0].clone();
        bad.source_ip = "203.0.113.9".into();
        bad.dkim = "fail".into();
        bad.spf = "fail".into();
        bad.count = 7;
        let mut fwd = bad.clone();
        fwd.reasons = vec![("forwarded".into(), String::new())];
        let mut own_fail = bad.clone();
        own_fail.source_ip = "198.51.100.1".into();
        r.records.extend([bad.clone(), bad, fwd, own_fail]);
        let own: BTreeSet<String> = ["198.51.100.1".to_string()].into();
        let s = suspects(&r, &own);
        assert_eq!(s.len(), 1);
        assert_eq!(
            s[&("203.0.113.9".to_string(), "example.org".to_string())],
            14
        );
    }

    #[test]
    fn lock_is_exclusive_and_stale_locks_are_taken() {
        let p = std::env::temp_dir().join(format!("msfe-dmarc-lock-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let l = lock(&p).unwrap();
        assert!(running(&p));
        assert!(lock(&p).is_err());
        drop(l);
        assert!(!p.exists());
        std::fs::write(&p, "999999999").unwrap(); // no such pid
        let l = lock(&p).unwrap();
        drop(l);
    }
}
