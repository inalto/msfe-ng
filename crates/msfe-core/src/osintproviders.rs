//! Source adapters for the OSINT controller. Each adapter turns one external
//! (or synthetic) lookup into an [`Outcome`]: a source status plus findings.
//! Adapters never copy provider free text that may contain markup, never
//! log credentials, and report every failure as a failed source, never as
//! "no match".

use crate::config::Config;
use crate::json::Json;
use crate::osint::*;
use crate::providerhttp::{self, HttpError, Request};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub struct QueryCtx<'a> {
    pub address: &'a str,
    pub cancel: &'a AtomicBool,
    pub deadline: Instant,
    pub cfg: &'a Config,
}

impl QueryCtx<'_> {
    pub fn stop(&self) -> bool {
        self.cancel.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
}

pub struct Outcome {
    pub source: SourceStatus,
    pub findings: Vec<Finding>,
}

pub struct Info {
    pub id: &'static str,
    pub name: &'static str,
    /// What the source receives, shown to the operator before a run.
    pub disclosure: String,
    pub configured: bool,
}

fn fixture_enabled() -> bool {
    std::env::var_os("MSFE_NG_OSINT_FIXTURE").is_some()
}

pub fn infos(cfg: &Config) -> Vec<Info> {
    let mut v = vec![hibp_info(cfg)];
    if fixture_enabled() {
        v.push(Info {
            id: "fixture",
            name: "Fixture (synthetic, no network)",
            disclosure: "Nothing leaves this server.".into(),
            configured: true,
        });
    }
    v
}

pub fn is_known(id: &str) -> bool {
    id == "hibp" || (id == "fixture" && fixture_enabled())
}

pub fn run(id: &str, q: &QueryCtx) -> Outcome {
    match id {
        "fixture" => fixture(q),
        "hibp" => hibp(q),
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

fn status(id: &str, state: SourceState, detail: &str) -> SourceStatus {
    SourceStatus {
        id: id.into(),
        state,
        retry_after: None,
        detail: detail.into(),
    }
}

fn outcome(id: &str, state: SourceState, detail: &str) -> Outcome {
    Outcome {
        source: status(id, state, detail),
        findings: Vec::new(),
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

// ---- Have I Been Pwned ------------------------------------------------

const HIBP_ID: &str = "hibp";
const HIBP_HOST: &str = "haveibeenpwned.com";
const MAX_FINDINGS: usize = 100;

fn hibp_range_mode(cfg: &Config) -> bool {
    cfg.osint_hibp_mode == "range"
}

fn hibp_info(cfg: &Config) -> Info {
    Info {
        id: HIBP_ID,
        name: "Have I Been Pwned",
        disclosure: if hibp_range_mode(cfg) {
            "only a 6-character SHA-1 prefix of the address is sent to haveibeenpwned.com"
        } else {
            "the full address is sent to haveibeenpwned.com"
        }
        .into(),
        configured: !cfg.osint_hibp_key.trim().is_empty(),
    }
}

/// Plain text only: control characters dropped, length bounded.
fn clean_text(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn str_of<'a>(j: &'a Json, key: &str) -> Option<&'a str> {
    j.get(key).and_then(|v| v.as_str())
}

fn flag(j: &Json, key: &str) -> bool {
    matches!(j.get(key), Some(Json::Bool(true)))
}

fn parse_array(body: &[u8]) -> Result<Vec<Json>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "unexpected answer".to_string())?;
    match Json::parse(text) {
        Ok(Json::Array(a)) => Ok(a),
        _ => Err("unexpected answer".into()),
    }
}

fn hibp_source_url(name: &str) -> String {
    let n: String = name.chars().filter(char::is_ascii_alphanumeric).collect();
    format!("https://haveibeenpwned.com/PwnedWebsites#{n}")
}

fn breach_date(s: Option<&str>) -> Option<(String, u64)> {
    let d = crate::civil::Date::parse(s?)?;
    let days = d.to_days();
    if days < 0 {
        return None;
    }
    Some((s?.to_string(), days as u64 * 86_400))
}

fn breach_finding(b: &Json, now: u64) -> Result<Finding, String> {
    if !matches!(b, Json::Object(_)) {
        return Err("unexpected answer".into());
    }
    let name = str_of(b, "Name").filter(|n| !n.is_empty());
    let Some(name) = name else {
        return Err("unexpected answer".into());
    };
    let title = str_of(b, "Title")
        .filter(|t| !t.trim().is_empty())
        .unwrap_or(name);
    let classes: Vec<String> = match b.get("DataClasses") {
        Some(Json::Array(a)) => a
            .iter()
            .filter_map(|c| c.as_str())
            .map(|c| clean_text(c, 80))
            .filter(|c| !c.is_empty())
            .take(40)
            .collect(),
        _ => Vec::new(),
    };
    let verified = flag(b, "IsVerified");
    let fabricated = flag(b, "IsFabricated");
    let (confidence, reason) = if fabricated {
        (Confidence::Low, "fabricated data reported by the source")
    } else if verified {
        (Confidence::High, "verified incident")
    } else {
        (Confidence::Low, "unverified incident")
    };
    let severity = if classes.iter().any(|c| c == "Passwords") {
        Severity::Medium
    } else if flag(b, "IsSpamList") {
        Severity::Info
    } else {
        Severity::Low
    };
    let mut evidence = if classes.is_empty() {
        "The source lists no data classes.".to_string()
    } else {
        format!(
            "Incident-wide data classes: {}. This describes what the incident exposed in general; it does not show that a password for this address was exposed.",
            classes.join(", ")
        )
    };
    if flag(b, "IsSpamList") {
        evidence.push_str(" Flags: spam list.");
    }
    if flag(b, "IsMalware") {
        evidence.push_str(" Flags: malware.");
    }
    let sensitive = flag(b, "IsSensitive");
    if sensitive {
        evidence.push_str(" Flags: sensitive.");
    }
    let date = breach_date(str_of(b, "BreachDate"));
    let mut limitations = Vec::new();
    limitations.push(match &date {
        Some((d, _)) => format!(
            "Historical incident dated {d}; it does not describe the address's current exposure."
        ),
        None => {
            "Historical incident; it does not describe the address's current exposure.".to_string()
        }
    });
    if sensitive || flag(b, "IsRetired") {
        limitations.push("Public searches omit some sensitive or retired incidents.".into());
    }
    Ok(Finding {
        group: Group::Exposure,
        confidence,
        confidence_reason: reason.into(),
        severity,
        observed_at: now,
        event_at: date.map(|(_, t)| t),
        source_id: HIBP_ID.into(),
        source_url: Some(hibp_source_url(name)),
        title: format!("Appears in breach: {}", clean_text(title, 200)),
        evidence,
        limitations,
    })
}

fn hibp_findings_direct(body: &[u8], now: u64) -> Result<Vec<Finding>, String> {
    let arr = parse_array(body)?;
    let mut out = Vec::new();
    for b in arr.iter() {
        let f = breach_finding(b, now)?;
        if out.len() < MAX_FINDINGS {
            out.push(f);
        }
    }
    Ok(out)
}

/// `suffix_upper` is the 34 characters of the address hash after the prefix.
/// Every row but the matching one is discarded as it is read.
fn hibp_findings_range(body: &[u8], suffix_upper: &str, now: u64) -> Result<Vec<Finding>, String> {
    let arr = parse_array(body)?;
    let mut out = Vec::new();
    for row in arr.iter() {
        let suffix = str_of(row, "hashSuffix").ok_or("unexpected answer")?;
        let Some(Json::Array(sites)) = row.get("websites") else {
            return Err("unexpected answer".into());
        };
        if !suffix.eq_ignore_ascii_case(suffix_upper) {
            continue;
        }
        for s in sites.iter() {
            let name = s
                .as_str()
                .filter(|n| !n.is_empty())
                .ok_or("unexpected answer")?;
            if out.len() >= MAX_FINDINGS {
                break;
            }
            out.push(Finding {
                group: Group::Exposure,
                confidence: Confidence::Medium,
                confidence_reason: "matched by hash prefix; the source returned no details".into(),
                severity: Severity::Low,
                observed_at: now,
                event_at: None,
                source_id: HIBP_ID.into(),
                source_url: Some(hibp_source_url(name)),
                title: format!("Appears in breach: {}", clean_text(name, 200)),
                evidence:
                    "Listed by incident name only (a hash-range lookup returns no further detail)."
                        .into(),
                limitations: vec![
                    "Historical incident; it does not describe the address's current exposure."
                        .into(),
                ],
            });
        }
    }
    Ok(out)
}

fn hibp(q: &QueryCtx) -> Outcome {
    let key = q.cfg.osint_hibp_key.trim().to_string();
    if key.is_empty() {
        return outcome(
            HIBP_ID,
            SourceState::NotConfigured,
            "no HIBP API key is set (Config \u{2192} OSINT providers)",
        );
    }
    let remaining = q.deadline.saturating_duration_since(Instant::now());
    if q.stop() || remaining.is_zero() {
        return outcome(
            HIBP_ID,
            SourceState::Inconclusive,
            "stopped before this source ran",
        );
    }
    let range = hibp_range_mode(q.cfg);
    let addr = q.address.trim();
    let (path, query, suffix, max_body) = if range {
        let h = match providerhttp::sha1_hex_upper(addr.to_ascii_lowercase().as_bytes()) {
            Ok(h) if h.len() == 40 => h,
            _ => {
                return outcome(
                    HIBP_ID,
                    SourceState::Failed,
                    "could not compute the address hash",
                )
            }
        };
        (
            format!("/api/v3/breachedaccount/range/{}", &h[..6]),
            Vec::new(),
            Some(h[6..].to_string()),
            1 << 20,
        )
    } else {
        (
            format!("/api/v3/breachedaccount/{}", providerhttp::pct_encode(addr)),
            vec![("truncateResponse", "false".to_string())],
            None,
            2 << 20,
        )
    };
    let req = Request {
        provider: "hibp",
        host: HIBP_HOST,
        path,
        query,
        headers: vec![("hibp-api-key", key.clone())],
        timeout: remaining.min(Duration::from_secs(10)),
        max_body,
    };
    let resp = match providerhttp::fetch(&req) {
        Ok(r) => r,
        Err(HttpError::Timeout) => return outcome(HIBP_ID, SourceState::Failed, "timed out"),
        Err(e) => {
            let t = providerhttp::redact(&e.to_string(), &[&key, addr]);
            return outcome(HIBP_ID, SourceState::Failed, &t);
        }
    };
    let unexpected = || outcome(HIBP_ID, SourceState::Failed, "unexpected answer from HIBP");
    match resp.status {
        200 => {
            let now = now_secs();
            let parsed = match &suffix {
                Some(s) => hibp_findings_range(&resp.body, s, now),
                None => hibp_findings_direct(&resp.body, now),
            };
            match parsed {
                Err(_) => unexpected(),
                Ok(f) if f.is_empty() => outcome(
                    HIBP_ID,
                    SourceState::NoMatch,
                    "nothing found in this source",
                ),
                Ok(f) => Outcome {
                    source: status(
                        HIBP_ID,
                        SourceState::Matched,
                        &format!("{} incident(s)", f.len()),
                    ),
                    findings: f,
                },
            }
        }
        404 => outcome(
            HIBP_ID,
            SourceState::NoMatch,
            "nothing found in this source",
        ),
        401 | 403 => outcome(
            HIBP_ID,
            SourceState::Restricted,
            "the API key was rejected or the plan does not include this lookup",
        ),
        429 => Outcome {
            source: SourceStatus {
                id: HIBP_ID.into(),
                state: SourceState::RateLimited,
                retry_after: resp.retry_after,
                detail: "HIBP rate limit reached".into(),
            },
            findings: Vec::new(),
        },
        400 => outcome(
            HIBP_ID,
            SourceState::Failed,
            "the provider rejected the address",
        ),
        n => outcome(
            HIBP_ID,
            SourceState::Failed,
            &format!("HIBP answered HTTP {n}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::Mutex;

    static HIBP_LOCK: Mutex<()> = Mutex::new(());

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
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(&reply);
            String::from_utf8_lossy(&head).into_owned()
        });
        (port, h)
    }

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
        assert!(f
            .evidence
            .contains("does not show that a password for this address was exposed"));
        assert!(!f.evidence.contains("<script>"));
        assert_eq!(
            f.source_url.as_deref(),
            Some("https://haveibeenpwned.com/PwnedWebsites#Adobe")
        );
        assert_eq!(f.event_at, Some(1380844800)); // 2013-10-04 UTC
        assert!(f.limitations.iter().any(|l| l.contains("2013-10-04")));
    }

    #[test]
    fn source_url_keeps_only_alphanumerics_of_the_name() {
        let body = r#"[{"Name":"A\"><b>x y/..","Title":"T","BreachDate":"bad"}]"#;
        let fs = hibp_findings_direct(body.as_bytes(), 1).unwrap();
        assert_eq!(
            fs[0].source_url.as_deref(),
            Some("https://haveibeenpwned.com/PwnedWebsites#Abxy")
        );
        assert_eq!(fs[0].event_at, None);
        assert_eq!(fs[0].confidence, Confidence::Low);
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
        let fs =
            hibp_findings_range(body.as_bytes(), "C6C0AADE0C085843D66E4944E108C4A4CD", 1).unwrap();
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|f| f.evidence.contains("name only")));
        let none =
            hibp_findings_range(body.as_bytes(), "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 1).unwrap();
        assert!(none.is_empty());
        assert!(hibp_findings_range(b"{}", "A", 1).is_err());
    }

    #[test]
    fn missing_key_is_not_configured_and_sends_nothing() {
        let cfg = Config::default(); // no key
        let cancel = AtomicBool::new(false);
        let q = QueryCtx {
            address: "a@example.org",
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(5),
            cfg: &cfg,
        };
        let o = run("hibp", &q);
        assert_eq!(o.source.state, SourceState::NotConfigured);
        assert!(o.findings.is_empty());
    }

    #[test]
    fn status_mapping_end_to_end() {
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
            let body = if status.starts_with("200") {
                DIRECT_BODY
            } else {
                ""
            };
            let reply = format!("HTTP/1.1 {status}\r\nRetry-After: 7\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            let (port, h) = serve(reply.into_bytes());
            std::env::set_var(
                "MSFE_NG_OSINT_BASE_HIBP",
                format!("http://127.0.0.1:{port}"),
            );
            let cfg = Config {
                osint_hibp_key: "SECRETKEY123".into(),
                ..Config::default()
            };
            let cancel = AtomicBool::new(false);
            let q = QueryCtx {
                address: "a+b@example.org",
                cancel: &cancel,
                deadline: Instant::now() + Duration::from_secs(10),
                cfg: &cfg,
            };
            let o = run("hibp", &q);
            let head = h.join().unwrap();
            assert_eq!(o.source.state, want, "{status}");
            assert!(
                head.starts_with(
                    "GET /api/v3/breachedaccount/a%2Bb%40example.org?truncateResponse=false"
                ),
                "{head}"
            );
            if status.starts_with("429") {
                assert_eq!(o.source.retry_after, Some(7));
            }
            assert!(!o.source.detail.contains("SECRETKEY123"));
        }
        std::env::remove_var("MSFE_NG_OSINT_BASE_HIBP");
    }

    #[test]
    fn range_mode_sends_only_the_prefix() {
        let _g = HIBP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha1sum").arg("--version").output().is_err() {
            return;
        }
        let body = "[]";
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let (port, h) = serve(reply.into_bytes());
        std::env::set_var(
            "MSFE_NG_OSINT_BASE_HIBP",
            format!("http://127.0.0.1:{port}"),
        );
        let cfg = Config {
            osint_hibp_key: "SECRETKEY123".into(),
            osint_hibp_mode: "range".into(),
            ..Config::default()
        };
        let cancel = AtomicBool::new(false);
        let q = QueryCtx {
            address: " Multiple-Breaches@HIBP-integration-tests.com ",
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(10),
            cfg: &cfg,
        };
        let o = run("hibp", &q);
        let head = h.join().unwrap();
        assert!(
            head.starts_with("GET /api/v3/breachedaccount/range/6B5917 "),
            "{head}"
        );
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
}
