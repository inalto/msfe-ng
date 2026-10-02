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

/// An image a finding refers to, stored by the controller (never inlined into
/// the report).
#[derive(Debug, Clone)]
pub struct Asset {
    pub id: String,
    pub mime: &'static str,
    pub bytes: Vec<u8>,
}

pub struct Outcome {
    pub source: SourceStatus,
    pub findings: Vec<Finding>,
    pub assets: Vec<Asset>,
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
    let mut v = vec![hibp_info(cfg), gravatar_info()];
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
    id == "hibp" || id == "gravatar" || (id == "fixture" && fixture_enabled())
}

pub fn run(id: &str, q: &QueryCtx) -> Outcome {
    match id {
        "fixture" => fixture(q),
        "hibp" => hibp(q),
        "gravatar" => gravatar(q),
        other => Outcome {
            source: SourceStatus {
                id: other.to_string(),
                state: SourceState::Failed,
                retry_after: None,
                detail: "no such provider".into(),
            },
            findings: Vec::new(),
            assets: Vec::new(),
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
        assets: Vec::new(),
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
                    assets: vec![],
                };
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if local.contains("fail") {
        return Outcome {
            source: status(SourceState::Failed, "synthetic failure"),
            findings: vec![],
            assets: vec![],
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
            asset_id: None,
            asset_mime: None,
        };
        return Outcome {
            source: status(SourceState::Matched, "1 incident"),
            findings: vec![f],
            assets: vec![],
        };
    }
    if local.contains("avatar") {
        if local.contains(".rm") {
            // Test hook: busy and deaf to cancel, so a run can be removed
            // while it still holds an image it is about to hand over.
            #[cfg(test)]
            FIXTURE_SLEEPING.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(400));
        }
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        bytes.resize(70, 0);
        let asset = Asset {
            id: crate::deliveryrun::new_id(),
            mime: "image/png",
            bytes,
        };
        #[cfg(test)]
        {
            *LAST_FIXTURE_ASSET.lock().unwrap_or_else(|e| e.into_inner()) = Some(asset.id.clone());
        }
        let f = Finding {
            group: Group::Profile,
            confidence: Confidence::Medium,
            confidence_reason: "synthetic fixture".into(),
            severity: Severity::Info,
            observed_at: now_secs(),
            event_at: None,
            source_id: "fixture".into(),
            source_url: None,
            title: "Synthetic avatar".into(),
            evidence: "A synthetic image is published for this address.".into(),
            limitations: vec![],
            asset_id: Some(asset.id.clone()),
            asset_mime: Some(asset.mime.into()),
        };
        return Outcome {
            source: status(SourceState::Matched, "1 avatar"),
            findings: vec![f],
            assets: vec![asset],
        };
    }
    Outcome {
        source: status(SourceState::NoMatch, "nothing found in this source"),
        findings: vec![],
        assets: vec![],
    }
}

#[cfg(test)]
pub(crate) static FIXTURE_SLEEPING: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(crate) fn reset_fixture_probe() {
    FIXTURE_SLEEPING.store(false, Ordering::SeqCst);
    *LAST_FIXTURE_ASSET.lock().unwrap_or_else(|e| e.into_inner()) = None;
}
#[cfg(test)]
static LAST_FIXTURE_ASSET: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
#[cfg(test)]
pub(crate) fn last_fixture_asset() -> Option<String> {
    LAST_FIXTURE_ASSET
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
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
        asset_id: None,
        asset_mime: None,
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
                asset_id: None,
                asset_mime: None,
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
                    assets: Vec::new(),
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
            assets: Vec::new(),
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

// ---- Gravatar -----------------------------------------------------------

const GRAVATAR_ID: &str = "gravatar";
const GRAVATAR_HOST: &str = "gravatar.com";
pub const MAX_AVATAR: usize = 256 * 1024;

fn gravatar_info() -> Info {
    Info {
        id: GRAVATAR_ID,
        name: "Gravatar",
        disclosure: "A SHA-256 hash of the lower-cased address is sent to gravatar.com".into(),
        configured: true,
    }
}

/// The image type, if the body's magic bytes and the declared content type
/// name the same one of PNG, JPEG or WebP. Nothing is decoded.
pub fn sniff_image(bytes: &[u8], content_type: Option<&str>) -> Option<&'static str> {
    let declared = content_type?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let magic = if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        "image/png"
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        "image/webp"
    } else {
        return None;
    };
    (declared == magic).then_some(magic)
}

fn gravatar(q: &QueryCtx) -> Outcome {
    let remaining = q.deadline.saturating_duration_since(Instant::now());
    if q.stop() || remaining.is_zero() {
        return outcome(
            GRAVATAR_ID,
            SourceState::Inconclusive,
            "stopped before this source ran",
        );
    }
    let addr = q.address.trim();
    let hash = match providerhttp::sha256_hex(addr.to_ascii_lowercase().as_bytes()) {
        Ok(h) if h.len() == 64 => h,
        _ => {
            return outcome(
                GRAVATAR_ID,
                SourceState::Failed,
                "could not compute the address hash",
            )
        }
    };
    let req = Request {
        provider: "gravatar",
        host: GRAVATAR_HOST,
        path: format!("/avatar/{hash}"),
        query: vec![("d", "404".into()), ("s", "256".into()), ("r", "g".into())],
        headers: Vec::new(),
        timeout: remaining.min(Duration::from_secs(10)),
        max_body: MAX_AVATAR,
    };
    let resp = match providerhttp::fetch(&req) {
        Ok(r) => r,
        Err(HttpError::Timeout) => return outcome(GRAVATAR_ID, SourceState::Failed, "timed out"),
        Err(HttpError::TooLarge) => {
            return outcome(
                GRAVATAR_ID,
                SourceState::Failed,
                "avatar larger than the 256 KiB limit",
            )
        }
        Err(e) => {
            let t = providerhttp::redact(&e.to_string(), &[addr, &hash]);
            return outcome(GRAVATAR_ID, SourceState::Failed, &t);
        }
    };
    match resp.status {
        200 => {
            let Some(mime) = sniff_image(&resp.body, resp.content_type.as_deref()) else {
                return outcome(
                    GRAVATAR_ID,
                    SourceState::Failed,
                    "the answer was not a supported image",
                );
            };
            let asset = Asset {
                id: crate::deliveryrun::new_id(),
                mime,
                bytes: resp.body,
            };
            let f = Finding {
                group: Group::Profile,
                confidence: Confidence::Medium,
                confidence_reason: "hash of the normalized address matches; this does not prove who controls the mailbox or that the image is used elsewhere".into(),
                severity: Severity::Info,
                observed_at: now_secs(),
                event_at: None,
                source_id: GRAVATAR_ID.into(),
                source_url: Some(format!("https://gravatar.com/{hash}")),
                title: "Public avatar found through Gravatar".into(),
                evidence: "A Gravatar image is published for this address (rating G, 256 px).".into(),
                limitations: vec![
                    "Absence of an avatar is not evidence of anything.".into(),
                    "Gravatar's profile data is not queried in this release.".into(),
                ],
                asset_id: Some(asset.id.clone()),
                asset_mime: Some(mime.into()),
            };
            Outcome {
                source: status(GRAVATAR_ID, SourceState::Matched, "1 avatar"),
                findings: vec![f],
                assets: vec![asset],
            }
        }
        404 => outcome(
            GRAVATAR_ID,
            SourceState::NoMatch,
            "no public avatar at rating G (a Gravatar may exist at a stricter rating)",
        ),
        401 | 403 => outcome(
            GRAVATAR_ID,
            SourceState::Restricted,
            "Gravatar refused the request",
        ),
        429 => Outcome {
            source: SourceStatus {
                id: GRAVATAR_ID.into(),
                state: SourceState::RateLimited,
                retry_after: resp.retry_after,
                detail: "Gravatar rate limit reached".into(),
            },
            findings: Vec::new(),
            assets: Vec::new(),
        },
        n => outcome(
            GRAVATAR_ID,
            SourceState::Failed,
            &format!("Gravatar answered HTTP {n}"),
        ),
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// One-shot HTTP stand-in: serves `reply` (raw bytes) to the first
    /// connection and returns the request head it received.
    pub fn serve(reply: Vec<u8>) -> (u16, std::thread::JoinHandle<String>) {
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
}

#[cfg(test)]
mod tests {
    use super::testutil::serve;
    use super::*;
    use std::process::Command;
    use std::sync::Mutex;

    static HIBP_LOCK: Mutex<()> = Mutex::new(());
    static GRAV_LOCK: Mutex<()> = Mutex::new(());

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

    fn png() -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        v.extend_from_slice(&[0u8; 64]);
        v
    }

    #[test]
    fn image_validation_requires_matching_type_and_magic() {
        assert_eq!(sniff_image(&png(), Some("image/png")), Some("image/png"));
        assert_eq!(
            sniff_image(
                &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0],
                Some("image/jpeg; charset=x")
            ),
            Some("image/jpeg")
        );
        let mut webp = b"RIFF".to_vec();
        webp.extend_from_slice(&[0, 0, 0, 0]);
        webp.extend_from_slice(b"WEBPVP8 ");
        assert_eq!(sniff_image(&webp, Some("image/webp")), Some("image/webp"));
        assert_eq!(
            sniff_image(&png(), Some("image/jpeg")),
            None,
            "type and magic must agree"
        );
        assert_eq!(
            sniff_image(
                b"<svg xmlns='http://www.w3.org/2000/svg'/>",
                Some("image/svg+xml")
            ),
            None
        );
        assert_eq!(sniff_image(b"<html>", Some("image/png")), None);
        assert_eq!(sniff_image(b"GIF89a....", Some("image/gif")), None);
        assert_eq!(
            sniff_image(&png()[..4], Some("image/png")),
            None,
            "truncated"
        );
        assert_eq!(sniff_image(&png(), None), None);
    }

    #[test]
    fn gravatar_end_to_end_stores_an_asset_for_a_real_image_only() {
        let _g = GRAV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha256sum").arg("--version").output().is_err() {
            return;
        }
        let img = png();
        let mut reply = format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", img.len()).into_bytes();
        reply.extend_from_slice(&img);
        let (port, h) = serve(reply);
        std::env::set_var(
            "MSFE_NG_OSINT_BASE_GRAVATAR",
            format!("http://127.0.0.1:{port}"),
        );
        let cfg = Config::default();
        let cancel = AtomicBool::new(false);
        let q = QueryCtx {
            address: "User@Example.org",
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(10),
            cfg: &cfg,
        };
        let o = run("gravatar", &q);
        let head = h.join().unwrap();
        assert!(head.starts_with("GET /avatar/"), "{head}");
        assert!(head.contains("d=404") && head.contains("s=256") && head.contains("r=g"));
        assert!(
            !head.to_ascii_lowercase().contains("example.org"),
            "the address itself must not be sent"
        );
        assert_eq!(o.source.state, SourceState::Matched);
        assert_eq!(o.assets.len(), 1);
        assert_eq!(
            o.findings[0].asset_id.as_deref(),
            Some(o.assets[0].id.as_str())
        );
        assert_eq!(o.findings[0].asset_mime.as_deref(), Some("image/png"));
        assert!(!o.findings[0]
            .source_url
            .as_deref()
            .unwrap()
            .contains("example.org"));
        std::env::remove_var("MSFE_NG_OSINT_BASE_GRAVATAR");
    }

    #[test]
    fn gravatar_non_image_404_and_oversize_store_nothing() {
        let _g = GRAV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if Command::new("sha256sum").arg("--version").output().is_err() {
            return;
        }
        let big = vec![0x89u8; 300 * 1024];
        let cases: Vec<(Vec<u8>, SourceState)> = vec![
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>".to_vec(), SourceState::Failed),
            (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::NoMatch),
            ([format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", big.len()).into_bytes(), big].concat(), SourceState::Failed),
            (b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::RateLimited),
            (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::Restricted),
        ];
        for (reply, want) in cases {
            let (port, _h) = serve(reply);
            std::env::set_var(
                "MSFE_NG_OSINT_BASE_GRAVATAR",
                format!("http://127.0.0.1:{port}"),
            );
            let cfg = Config::default();
            let cancel = AtomicBool::new(false);
            let q = QueryCtx {
                address: "u@example.org",
                cancel: &cancel,
                deadline: Instant::now() + Duration::from_secs(10),
                cfg: &cfg,
            };
            let o = run("gravatar", &q);
            assert_eq!(o.source.state, want, "{}", o.source.detail);
            assert!(o.assets.is_empty() && o.findings.is_empty());
        }
        std::env::remove_var("MSFE_NG_OSINT_BASE_GRAVATAR");
    }

    #[test]
    fn gravatar_is_always_configured_and_discloses_the_hash() {
        let i = infos(&Config::default())
            .into_iter()
            .find(|p| p.id == "gravatar")
            .unwrap();
        assert!(i.configured);
        assert!(i.disclosure.contains("SHA-256 hash"));
        assert!(is_known("gravatar"));
    }
}
