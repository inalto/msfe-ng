//! Report an abusive address to AbuseIPDB — manual only.
//!
//! The admin blocks an address in the client-IP view (csf) and may also
//! report it: typically a bot that posts unsolicited web forms. Nothing here
//! runs on its own: no cron, no auto-ban involvement.
//!
//! - The API key is a secret (`abuseipdb_key`): it goes into a private 0600
//!   curl config file passed via `--config`, never onto argv (the pattern of
//!   telegram.rs).
//! - The comment is public on AbuseIPDB: [`default_comment`] never puts
//!   recipients, subjects, senders or the admin's domains in it.
//! - Refused before any request: an empty key, a network (only a single
//!   address is reported), private / loopback / reserved and own addresses,
//!   addresses csf allows, no category, a comment over 1024 characters.
//! - AbuseIPDB refuses the same address within 15 minutes (HTTP 422): that is
//!   "already reported", not a failure.
//! - Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
//!   2001:db8::/32) are reserved and refused like private addresses; the
//!   tests let them through with `MSFE_NG_REPORT_DOC_NETS=1` so fixtures
//!   never name a real address.
//!
//! Every report that reached the API is appended to `<backup_dir>/reports.jsonl`
//! (0600; `MSFE_NG_REPORT_LOG` overrides), read back by [`history`].

use crate::config::Config;
use crate::json::Json;
use std::io::{self, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const REPORT_URL: &str = "https://api.abuseipdb.com/api/v2/report";
const CHECK_URL: &str = "https://api.abuseipdb.com/api/v2/check";
/// AbuseIPDB's limit on the comment of a report.
pub const MAX_COMMENT: usize = 1024;

/// An AbuseIPDB report category.
#[derive(Debug)]
pub struct Category {
    pub id: u8,
    pub name: &'static str,
    pub hint: &'static str,
}

/// The categories offered, in display order (10 and 19 are the default).
pub const CATEGORIES: &[Category] = &[
    Category {
        id: 10,
        name: "Web Spam",
        hint: "Comment/forum spam, HTTP referer spam, or other CMS spam (unsolicited web forms).",
    },
    Category {
        id: 19,
        name: "Bad Web Bot",
        hint: "Webpage scraping and crawlers that do not honor robots.txt; excessive requests and user agent spoofing.",
    },
    Category {
        id: 11,
        name: "Email Spam",
        hint: "Spam email content, infected attachments, and phishing emails.",
    },
    Category {
        id: 18,
        name: "Brute-Force",
        hint: "Credential brute-force attacks on webpage logins and services like SSH, FTP, SMTP, IMAP.",
    },
    Category {
        id: 21,
        name: "Web App Attack",
        hint: "Attempts to probe for or exploit installed web applications (CMS, forums, phpMyAdmin, plugins).",
    },
    Category {
        id: 14,
        name: "Port Scan",
        hint: "Scanning for open ports and vulnerable services.",
    },
];

/// The categories preselected in the UI and used by the CLI by default.
pub const DEFAULT_CATEGORIES: &[u8] = &[10, 19];

pub fn category(id: u8) -> Option<&'static Category> {
    CATEGORIES.iter().find(|c| c.id == id)
}

/// A category from its id (`19`) or name (`bad-web-bot`, `Bad Web Bot`,
/// `badwebbot`), case-insensitive.
pub fn parse_category(s: &str) -> Option<u8> {
    let s = s.trim();
    if let Ok(id) = s.parse::<u8>() {
        return category(id).map(|c| c.id);
    }
    let norm = |t: &str| -> String {
        t.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let want = norm(s);
    CATEGORIES
        .iter()
        .find(|c| norm(c.name) == want)
        .map(|c| c.id)
}

/// What is sent: one address, at least one category, a public comment.
#[derive(Debug, Clone)]
pub struct Report {
    pub ip: String,
    pub categories: Vec<u8>,
    pub comment: String,
}

/// The prefilled public comment. Only category names and, when known and
/// non-zero, the number of messages this server saw from the address in the
/// last 30 days — never recipients, subjects, senders or local domains.
pub fn default_comment(categories: &[u8], messages_30d: Option<u64>) -> String {
    let names: Vec<&str> = categories
        .iter()
        .filter_map(|id| category(*id))
        .map(|c| c.name)
        .collect();
    let mut s = String::from("automated abuse from this address");
    if !names.is_empty() {
        s.push_str(&format!(" ({})", names.join(", ")));
    }
    if let Some(n) = messages_30d.filter(|n| *n > 0) {
        s.push_str(&format!(
            "; {n} message(s) seen by this mail server in the last 30 days"
        ));
    }
    truncate_chars(&s, MAX_COMMENT)
}

fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

fn is_documentation(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_documentation(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            s[0] == 0x2001 && s[1] == 0x0db8
        }
    }
}

/// Worth reporting: routable on the public internet (documentation ranges
/// too when `doc_ok`, for tests).
fn reportable(ip: IpAddr, doc_ok: bool) -> bool {
    crate::netguard::is_public(ip) || (doc_ok && is_documentation(ip))
}

fn doc_nets_allowed() -> bool {
    std::env::var("MSFE_NG_REPORT_DOC_NETS").is_ok_and(|v| v == "1")
}

/// Parse a single address (no network, no port).
fn parse_single(ip: &str) -> Result<IpAddr, String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err("no address given".into());
    }
    if ip.contains('/') {
        return Err(format!(
            "'{ip}' is a network: only a single address is reported (the one that was seen)"
        ));
    }
    ip.parse::<IpAddr>()
        .map_err(|_| format!("'{ip}' is not an IP address"))
}

/// The address, category and comment checks, with the csf allow test and
/// the documentation-range switch injected (tests use a fixture csf root).
fn check_request(r: &Report, allowed: &dyn Fn(&str) -> bool, doc_ok: bool) -> Result<(), String> {
    let ip = parse_single(&r.ip)?;
    if !reportable(ip, doc_ok) {
        return Err(format!(
            "{ip} is a private, loopback or reserved address — not reported"
        ));
    }
    if crate::netguard::own_addresses().contains(&ip) {
        return Err(format!(
            "{ip} is one of this server's own addresses — not reported"
        ));
    }
    if allowed(&ip.to_string()) {
        return Err(format!(
            "{ip} is allowed in csf (csf.allow / csf.ignore) — not reported"
        ));
    }
    if r.categories.is_empty() {
        return Err("choose at least one category".into());
    }
    if let Some(bad) = r.categories.iter().find(|id| category(**id).is_none()) {
        return Err(format!("unknown category {bad}"));
    }
    let n = r.comment.chars().count();
    if n > MAX_COMMENT {
        return Err(format!(
            "the comment is {n} characters; AbuseIPDB takes at most {MAX_COMMENT}"
        ));
    }
    Ok(())
}

/// Everything [`validate`] checks except the key: what `--dry-run` runs on
/// a host where the key is not set yet.
pub fn validate_request(r: &Report) -> Result<(), String> {
    check_request(
        r,
        &|ip| crate::csf::list_state(ip) == crate::csf::ListState::Allowed,
        doc_nets_allowed(),
    )
}

/// All the refusals made before a request: key, address, categories, comment.
pub fn validate(cfg: &Config, r: &Report) -> Result<(), String> {
    if cfg.abuseipdb_key.trim().is_empty() {
        return Err("AbuseIPDB is not configured: set abuseipdb_key (Settings)".into());
    }
    validate_request(r)
}

/// How a report ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Accepted; AbuseIPDB's confidence score for the address afterwards.
    Reported { score: Option<u32> },
    /// Refused by AbuseIPDB because the address was reported within 15 minutes.
    AlreadyReported,
    /// Refused here, before any request.
    Refused(String),
    /// The request failed or AbuseIPDB answered with an error.
    Failed(String),
}

impl Outcome {
    /// The short name used in the log and the API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Reported { .. } => "reported",
            Outcome::AlreadyReported => "already_reported",
            Outcome::Refused(_) => "refused",
            Outcome::Failed(_) => "failed",
        }
    }

    /// The detail kept in the log: the score or the error.
    pub fn detail(&self) -> String {
        match self {
            Outcome::Reported { score: Some(s) } => format!("confidence score {s}"),
            Outcome::Reported { score: None } => String::new(),
            Outcome::AlreadyReported => "already reported within the last 15 minutes".into(),
            Outcome::Refused(e) | Outcome::Failed(e) => e.clone(),
        }
    }
}

/// The first `errors[].detail` of an AbuseIPDB error body.
fn error_detail(v: &Json) -> Option<String> {
    v.get("errors")?
        .as_array()?
        .iter()
        .map(|e| e.str_field("detail"))
        .find(|d| !d.is_empty())
}

/// Interpret AbuseIPDB's answer to a report.
pub fn parse_report_reply(status: u16, body: &str) -> Outcome {
    let v = Json::parse(body.trim()).unwrap_or(Json::Null);
    let detail = error_detail(&v);
    if (200..300).contains(&status) {
        let score = v
            .get("data")
            .and_then(|d| d.get("abuseConfidenceScore"))
            .and_then(Json::as_i64)
            .map(|n| n.clamp(0, 100) as u32);
        return Outcome::Reported { score };
    }
    if status == 422 {
        if let Some(d) = &detail {
            if d.contains("15 minutes") {
                return Outcome::AlreadyReported;
            }
        }
    }
    let msg = detail.unwrap_or_else(|| {
        let b = body.trim();
        if b.is_empty() {
            "no answer".to_string()
        } else {
            truncate_chars(b, 300)
        }
    });
    Outcome::Failed(format!("AbuseIPDB answered HTTP {status}: {msg}"))
}

static SEQ: AtomicU64 = AtomicU64::new(0);

struct CurlConfig(PathBuf);
impl Drop for CurlConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A quoted curl config value: `\`, `"` and control whitespace escaped.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Run curl on a private config file (`lines`, after the key and Accept
/// headers) and return (HTTP status, body). The key never reaches argv.
fn curl(cfg: &Config, lines: &[String]) -> Result<(u16, String), String> {
    let name = format!(
        "msfe-ng-abuseipdb-{}-{}.cfg",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(name);
    let write = || -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(f, "header = \"Key: {}\"", esc(cfg.abuseipdb_key.trim()))?;
        writeln!(f, "header = \"Accept: application/json\"")?;
        for l in lines {
            writeln!(f, "{l}")?;
        }
        Ok(())
    };
    if let Err(e) = write() {
        return Err(format!("cannot write curl config: {e}"));
    }
    let guard = CurlConfig(path);
    let out = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "15",
            "-A",
            "msfe-ng",
            "-w",
            "\\n%{http_code}",
            "--config",
        ])
        .arg(&guard.0)
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = stdout.rsplit_once('\n').unwrap_or(("", stdout.as_str()));
    let status: u16 = code.trim().parse().unwrap_or(0);
    if status == 0 {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "AbuseIPDB did not answer: {}",
            if err.trim().is_empty() {
                "no response"
            } else {
                err.trim()
            }
        ));
    }
    Ok((status, body.to_string()))
}

/// Send the report (validated first; refusals never reach the network).
pub fn send(cfg: &Config, r: &Report) -> Outcome {
    if let Err(e) = validate(cfg, r) {
        return Outcome::Refused(e);
    }
    let cats: Vec<String> = r.categories.iter().map(u8::to_string).collect();
    let lines = vec![
        format!("url = \"{REPORT_URL}\""),
        format!("data-urlencode = \"ip={}\"", esc(r.ip.trim())),
        format!("data-urlencode = \"categories={}\"", cats.join(",")),
        format!("data-urlencode = \"comment={}\"", esc(&r.comment)),
    ];
    match curl(cfg, &lines) {
        Ok((status, body)) => parse_report_reply(status, &body),
        Err(e) => Outcome::Failed(e),
    }
}

/// What AbuseIPDB knows about an address (last 90 days).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckInfo {
    pub score: u32,
    pub total_reports: u32,
    pub last_reported: Option<String>,
    pub whitelisted: bool,
    pub usage_type: String,
    pub isp: String,
    pub domain: String,
}

impl CheckInfo {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("score".into(), Json::Int(self.score as i64)),
            ("total_reports".into(), Json::Int(self.total_reports as i64)),
            (
                "last_reported".into(),
                self.last_reported
                    .clone()
                    .map(Json::Str)
                    .unwrap_or(Json::Null),
            ),
            ("whitelisted".into(), Json::Bool(self.whitelisted)),
            ("usage_type".into(), Json::str(&self.usage_type)),
            ("isp".into(), Json::str(&self.isp)),
            ("domain".into(), Json::str(&self.domain)),
        ])
    }
}

/// Interpret AbuseIPDB's answer to a check.
pub fn parse_check_reply(body: &str) -> Result<CheckInfo, String> {
    let v = Json::parse(body.trim()).map_err(|e| format!("unreadable AbuseIPDB answer: {e}"))?;
    if let Some(d) = error_detail(&v) {
        return Err(format!("AbuseIPDB: {d}"));
    }
    let d = v
        .get("data")
        .ok_or_else(|| "AbuseIPDB answer without data".to_string())?;
    let num = |k: &str| {
        d.get(k)
            .and_then(Json::as_i64)
            .unwrap_or(0)
            .clamp(0, u32::MAX as i64) as u32
    };
    let last = d.str_field("lastReportedAt");
    Ok(CheckInfo {
        score: num("abuseConfidenceScore"),
        total_reports: num("totalReports"),
        last_reported: (!last.is_empty()).then_some(last),
        whitelisted: matches!(d.get("isWhitelisted"), Some(Json::Bool(true))),
        usage_type: d.str_field("usageType"),
        isp: d.str_field("isp"),
        domain: d.str_field("domain"),
    })
}

/// Look an address up on AbuseIPDB (GET, same curl discipline as [`send`]).
pub fn check(cfg: &Config, ip: &str) -> Result<CheckInfo, String> {
    if cfg.abuseipdb_key.trim().is_empty() {
        return Err("AbuseIPDB is not configured: set abuseipdb_key (Settings)".into());
    }
    let addr = parse_single(ip)?;
    if !reportable(addr, doc_nets_allowed()) {
        return Err(format!("{addr} is a private, loopback or reserved address"));
    }
    let lines = vec![
        format!("url = \"{CHECK_URL}\""),
        "get".to_string(),
        format!("data-urlencode = \"ipAddress={addr}\""),
        "data-urlencode = \"maxAgeInDays=90\"".to_string(),
    ];
    let (status, body) = curl(cfg, &lines)?;
    if !(200..300).contains(&status) {
        let v = Json::parse(body.trim()).unwrap_or(Json::Null);
        return Err(format!(
            "AbuseIPDB answered HTTP {status}: {}",
            error_detail(&v).unwrap_or_else(|| truncate_chars(body.trim(), 300))
        ));
    }
    parse_check_reply(&body)
}

// ---- history -----------------------------------------------------------------

/// One line of `reports.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub at: u64,
    pub ip: String,
    pub categories: Vec<u8>,
    pub comment: String,
    pub outcome: String,
    pub detail: String,
}

impl LogEntry {
    /// The entry for a report and its outcome, stamped now.
    pub fn new(r: &Report, o: &Outcome) -> LogEntry {
        LogEntry {
            at: crate::delivery::now_secs(),
            ip: r.ip.trim().to_string(),
            categories: r.categories.clone(),
            comment: r.comment.clone(),
            outcome: o.as_str().to_string(),
            detail: o.detail(),
        }
    }

    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("at".into(), Json::Int(self.at as i64)),
            ("ip".into(), Json::str(&self.ip)),
            (
                "categories".into(),
                Json::Array(
                    self.categories
                        .iter()
                        .map(|c| Json::Int(*c as i64))
                        .collect(),
                ),
            ),
            ("comment".into(), Json::str(&self.comment)),
            ("outcome".into(), Json::str(&self.outcome)),
            ("detail".into(), Json::str(&self.detail)),
        ])
    }

    fn from_json(v: &Json) -> Option<LogEntry> {
        let at = v.get("at")?.as_i64()?;
        let ip = v.str_field("ip");
        if ip.is_empty() {
            return None;
        }
        Some(LogEntry {
            at: at.max(0) as u64,
            ip,
            categories: v
                .get("categories")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Json::as_i64)
                .filter_map(|n| u8::try_from(n).ok())
                .collect(),
            comment: v.str_field("comment"),
            outcome: v.str_field("outcome"),
            detail: v.str_field("detail"),
        })
    }
}

/// `<backup_dir>/reports.jsonl`; `MSFE_NG_REPORT_LOG` overrides (tests).
pub fn log_file(cfg: &Config) -> PathBuf {
    if let Ok(p) = std::env::var("MSFE_NG_REPORT_LOG") {
        if !p.is_empty() {
            return p.into();
        }
    }
    Path::new(&cfg.backup_dir).join("reports.jsonl")
}

/// Append one entry (the file is created 0600).
pub fn log_append(cfg: &Config, e: &LogEntry) -> io::Result<()> {
    let path = log_file(cfg);
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)?;
    writeln!(f, "{}", e.to_json())
}

/// Logged reports, newest first, optionally for one address only.
pub fn history(cfg: &Config, ip: Option<&str>, limit: usize) -> Vec<LogEntry> {
    let text = std::fs::read_to_string(log_file(cfg)).unwrap_or_default();
    let want = ip.map(str::trim).filter(|s| !s.is_empty());
    let mut out: Vec<LogEntry> = text
        .lines()
        .filter_map(|l| Json::parse(l.trim()).ok())
        .filter_map(|v| LogEntry::from_json(&v))
        .filter(|e| want.map_or(true, |w| e.ip == w))
        .collect();
    out.reverse();
    out.truncate(limit);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rep(ip: &str, cats: &[u8], comment: &str) -> Report {
        Report {
            ip: ip.into(),
            categories: cats.to_vec(),
            comment: comment.into(),
        }
    }

    fn never(_: &str) -> bool {
        false
    }

    #[test]
    fn categories_lookup_by_id_and_name() {
        assert_eq!(CATEGORIES.len(), 6);
        let ids: Vec<u8> = CATEGORIES.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![10, 19, 11, 18, 21, 14]);
        assert_eq!(category(19).unwrap().name, "Bad Web Bot");
        assert!(category(3).is_none());
        assert_eq!(parse_category("10"), Some(10));
        assert_eq!(parse_category("bad-web-bot"), Some(19));
        assert_eq!(parse_category("Web App Attack"), Some(21));
        assert_eq!(parse_category("brute-force"), Some(18));
        assert_eq!(parse_category("3"), None);
        assert_eq!(parse_category("nonsense"), None);
    }

    #[test]
    fn default_comment_names_categories_and_the_count() {
        assert_eq!(
            default_comment(&[10, 19], Some(12)),
            "automated abuse from this address (Web Spam, Bad Web Bot); 12 message(s) seen by this mail server in the last 30 days"
        );
        assert_eq!(
            default_comment(&[10, 19], None),
            "automated abuse from this address (Web Spam, Bad Web Bot)"
        );
        assert_eq!(
            default_comment(&[11], Some(0)),
            "automated abuse from this address (Email Spam)"
        );
        let long = vec![21u8; 200];
        assert_eq!(
            default_comment(&long, Some(u64::MAX)).chars().count(),
            MAX_COMMENT
        );
    }

    #[test]
    fn validate_refuses_before_any_request() {
        let ok = |r: &Report| check_request(r, &never, true);
        assert!(ok(&rep("203.0.113.9", &[10, 19], "bot")).is_ok());
        let e = ok(&rep("10.0.0.1", &[10], "")).unwrap_err();
        assert!(e.contains("private"), "{e}");
        let e = ok(&rep("127.0.0.1", &[10], "")).unwrap_err();
        assert!(e.contains("loopback"), "{e}");
        let e = ok(&rep("::1", &[10], "")).unwrap_err();
        assert!(e.contains("private"), "{e}");
        let e = ok(&rep("203.0.113.0/24", &[10], "")).unwrap_err();
        assert!(e.contains("single address"), "{e}");
        let e = ok(&rep("not-an-ip", &[10], "")).unwrap_err();
        assert!(e.contains("not an IP address"), "{e}");
        let e = ok(&rep("203.0.113.9", &[], "")).unwrap_err();
        assert!(e.contains("at least one category"), "{e}");
        let e = ok(&rep("203.0.113.9", &[99], "")).unwrap_err();
        assert!(e.contains("unknown category"), "{e}");
        let e = ok(&rep("203.0.113.9", &[10], &"x".repeat(1100))).unwrap_err();
        assert!(e.contains("1100") && e.contains("1024"), "{e}");
        // documentation ranges are reserved outside tests
        let e = check_request(&rep("203.0.113.9", &[10], ""), &never, false).unwrap_err();
        assert!(e.contains("reserved"), "{e}");

        // an address csf allows (fixture root, as in csf.rs)
        let root = std::env::temp_dir().join(format!("msfe-report-csf-{}", std::process::id()));
        std::fs::create_dir_all(root.join("etc/csf")).unwrap();
        std::fs::write(
            root.join("etc/csf/csf.allow"),
            "198.51.100.0/24 # partner\n",
        )
        .unwrap();
        let allowed =
            |ip: &str| crate::csf::list_state_at(&root, ip) == crate::csf::ListState::Allowed;
        let e = check_request(&rep("198.51.100.7", &[10], ""), &allowed, true).unwrap_err();
        assert!(e.contains("allowed in csf"), "{e}");
        assert!(check_request(&rep("203.0.113.9", &[10], ""), &allowed, true).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_needs_the_key() {
        let cfg = Config::default();
        let e = validate(&cfg, &rep("203.0.113.9", &[10], "")).unwrap_err();
        assert!(e.contains("abuseipdb_key"), "{e}");
    }

    #[test]
    fn send_without_key_is_refused_without_curl() {
        let cfg = Config::default();
        match send(&cfg, &rep("203.0.113.9", &[10, 19], "bot")) {
            Outcome::Refused(e) => assert!(e.contains("abuseipdb_key"), "{e}"),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn report_replies_are_interpreted() {
        assert_eq!(
            parse_report_reply(
                200,
                r#"{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":47}}"#
            ),
            Outcome::Reported { score: Some(47) }
        );
        assert_eq!(
            parse_report_reply(
                422,
                r#"{"errors":[{"detail":"You can only report the same IP address (`203.0.113.9`) once in 15 minutes.","status":422}]}"#
            ),
            Outcome::AlreadyReported
        );
        match parse_report_reply(
            401,
            r#"{"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked.","status":401}]}"#,
        ) {
            Outcome::Failed(e) => {
                assert!(
                    e.contains("401") && e.contains("Authentication failed"),
                    "{e}"
                )
            }
            o => panic!("{o:?}"),
        }
        match parse_report_reply(502, "") {
            Outcome::Failed(e) => assert!(e.contains("502") && e.contains("no answer"), "{e}"),
            o => panic!("{o:?}"),
        }
        assert_eq!(
            Outcome::Reported { score: Some(47) }.detail(),
            "confidence score 47"
        );
    }

    #[test]
    fn check_replies_are_interpreted() {
        let c = parse_check_reply(
            r#"{"data":{"ipAddress":"203.0.113.9","isPublic":true,"ipVersion":4,"isWhitelisted":false,"abuseConfidenceScore":47,"countryCode":"ZZ","usageType":"Data Center/Web Hosting/Transit","isp":"Example Hosting","domain":"example.com","hostnames":[],"isTor":false,"totalReports":12,"numDistinctUsers":5,"lastReportedAt":"2026-09-20T10:00:00+00:00"}}"#,
        )
        .unwrap();
        assert_eq!(c.score, 47);
        assert_eq!(c.total_reports, 12);
        assert_eq!(
            c.last_reported.as_deref(),
            Some("2026-09-20T10:00:00+00:00")
        );
        assert!(!c.whitelisted);
        assert_eq!(c.usage_type, "Data Center/Web Hosting/Transit");
        assert_eq!(c.isp, "Example Hosting");
        assert_eq!(c.domain, "example.com");
        let c = parse_check_reply(
            r#"{"data":{"ipAddress":"198.51.100.7","isWhitelisted":null,"abuseConfidenceScore":0,"usageType":null,"isp":"Example","domain":null,"totalReports":0,"lastReportedAt":null}}"#,
        )
        .unwrap();
        assert_eq!(c.total_reports, 0);
        assert!(c.last_reported.is_none() && !c.whitelisted && c.usage_type.is_empty());
        let e =
            parse_check_reply(r#"{"errors":[{"detail":"Authentication failed.","status":401}]}"#)
                .unwrap_err();
        assert!(e.contains("Authentication failed"), "{e}");
        assert!(parse_check_reply("<html>").is_err());
    }

    #[test]
    fn log_round_trip_newest_first() {
        let d = std::env::temp_dir().join(format!("msfe-report-log-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let cfg = Config {
            backup_dir: d.display().to_string(),
            ..Default::default()
        };
        assert!(history(&cfg, None, 10).is_empty());
        let mk = |at: u64, ip: &str, outcome: &str| LogEntry {
            at,
            ip: ip.into(),
            categories: vec![10, 19],
            comment: "bot \"quoted\"\nline".into(),
            outcome: outcome.into(),
            detail: String::new(),
        };
        log_append(&cfg, &mk(1, "203.0.113.9", "reported")).unwrap();
        log_append(&cfg, &mk(2, "198.51.100.7", "failed")).unwrap();
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(log_file(&cfg))
                .unwrap();
            writeln!(f, "not json\n{{\"at\":\"x\"}}\n").unwrap();
        }
        log_append(&cfg, &mk(3, "203.0.113.9", "already_reported")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(log_file(&cfg))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        let all = history(&cfg, None, 10);
        assert_eq!(all.iter().map(|e| e.at).collect::<Vec<_>>(), vec![3, 2, 1]);
        assert_eq!(all[2], mk(1, "203.0.113.9", "reported"));
        let one = history(&cfg, Some("203.0.113.9"), 10);
        assert_eq!(one.iter().map(|e| e.at).collect::<Vec<_>>(), vec![3, 1]);
        assert_eq!(history(&cfg, None, 1).len(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }
}
