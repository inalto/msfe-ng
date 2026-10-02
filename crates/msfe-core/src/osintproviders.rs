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
    let mut v = vec![hibp_info(cfg), gravatar_info(), rdap_info()];
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
    id == "hibp" || id == "gravatar" || id == "rdap" || (id == "fixture" && fixture_enabled())
}

pub fn run(id: &str, q: &QueryCtx) -> Outcome {
    match id {
        "fixture" => fixture(q),
        "hibp" => hibp(q),
        "gravatar" => gravatar(q),
        "rdap" => rdap(q),
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

/// A valid 1x1 PNG (one RGB pixel), so a real browser can decode the fixture avatar.
const FIXTURE_PNG: [u8; 69] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x30, 0x68, 0xb8, 0x00,
    0x00, 0x02, 0x64, 0x01, 0x81, 0xd9, 0xf1, 0x9e, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

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
        let bytes = FIXTURE_PNG.to_vec();
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

/// Plain text only: markup removed (everything between `<` and `>`, and an
/// unclosed `<` to the end), the five basic entities decoded once, control
/// characters dropped, whitespace collapsed, and the result at most `max`
/// characters long (cut on a character boundary, ending in `\u{2026}`).
pub(crate) fn clean_text(s: &str, max: usize) -> String {
    let mut stripped = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if in_tag => {}
            _ => stripped.push(c),
        }
    }
    let mut decoded = String::with_capacity(stripped.len());
    let mut rest = stripped.as_str();
    while let Some(i) = rest.find('&') {
        decoded.push_str(&rest[..i]);
        rest = &rest[i..];
        let mut hit = false;
        for (ent, ch) in [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&#39;", '\''),
        ] {
            if let Some(r) = rest.strip_prefix(ent) {
                decoded.push(ch);
                rest = r;
                hit = true;
                break;
            }
        }
        if !hit {
            decoded.push('&');
            rest = &rest[1..];
        }
    }
    decoded.push_str(rest);
    let spaced: String = decoded
        .chars()
        .filter_map(|c| {
            if c.is_whitespace() {
                Some(' ')
            } else if c.is_control() {
                None
            } else {
                Some(c)
            }
        })
        .collect();
    let collapsed = spaced.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        return collapsed;
    }
    if max == 0 {
        return String::new();
    }
    let mut cut: String = collapsed.chars().take(max - 1).collect();
    cut.truncate(cut.trim_end().len());
    cut.push('\u{2026}');
    cut
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
        if out.len() <= MAX_FINDINGS {
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
            if out.len() > MAX_FINDINGS {
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
        host: HIBP_HOST.to_string(),
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
                Ok(mut f) if f.len() > MAX_FINDINGS => {
                    // The helpers keep one extra row so a cut-off is detectable.
                    f.truncate(MAX_FINDINGS);
                    let note = format!(
                        "Showing the first {MAX_FINDINGS} incidents; the source returned more."
                    );
                    for x in f.iter_mut() {
                        x.limitations.push(note.clone());
                    }
                    Outcome {
                        source: status(
                            HIBP_ID,
                            SourceState::Matched,
                            &format!("{MAX_FINDINGS} incident(s) shown; the source returned more"),
                        ),
                        findings: f,
                        assets: Vec::new(),
                    }
                }
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
            &format!(
                "HTTP {}: the API key was rejected or the plan does not include this lookup (a proxy or firewall page can also cause this)",
                resp.status
            ),
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
        host: GRAVATAR_HOST.to_string(),
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
            "no public avatar at rating G (a Gravatar may exist at a higher, more mature rating)",
        ),
        401 | 403 => outcome(
            GRAVATAR_ID,
            SourceState::Restricted,
            &format!("HTTP {}: Gravatar refused the request", resp.status),
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

// ---- RDAP domain context ------------------------------------------------

const RDAP_ID: &str = "rdap";
const BOOTSTRAP_HOST: &str = "data.iana.org";
const BOOTSTRAP_PATH: &str = "/rdap/dns.json";
const RDAP_MAX_BODY: usize = 512 * 1024;
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 3600);
const REDACTION_LIMIT: &str =
    "Registrant details are redacted by the registry; no owner identity is shown.";

type Services = Vec<(Vec<String>, Vec<String>)>;

static BOOTSTRAP_CACHE: std::sync::Mutex<Option<(Instant, Services)>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn clear_bootstrap_cache() {
    *BOOTSTRAP_CACHE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
fn age_bootstrap_cache(by: Duration) {
    if let Some((t, _)) = BOOTSTRAP_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        *t = t.checked_sub(by).unwrap_or(*t);
    }
}

fn rdap_info() -> Info {
    Info {
        id: RDAP_ID,
        name: "RDAP domain registration",
        disclosure: "the domain of the address (not the full address) is sent to the registry's RDAP server (found through the IANA bootstrap file)".into(),
        configured: true,
    }
}

/// RDAP needs no credentials: the only header ever sent is `Accept`. Nothing
/// secret is passed to this function, so no registry host taken from the
/// bootstrap can ever be paired with one.
fn rdap_request(
    provider: &'static str,
    host: &str,
    path: String,
    accept: &str,
    timeout: Duration,
) -> Request {
    Request {
        provider,
        host: host.to_string(),
        path,
        query: Vec::new(),
        headers: vec![("accept", accept.to_string())],
        timeout,
        max_body: RDAP_MAX_BODY,
    }
}

/// `{"services":[[["com","net"],["https://…/"]],…]}`; any other shape is an error.
fn parse_bootstrap(body: &[u8]) -> Result<Services, String> {
    let bad = || "unexpected bootstrap answer".to_string();
    let text = std::str::from_utf8(body).map_err(|_| bad())?;
    let doc = Json::parse(text).map_err(|_| bad())?;
    let Some(Json::Array(services)) = doc.get("services") else {
        return Err(bad());
    };
    let strings = |j: &Json| -> Result<Vec<String>, String> {
        match j {
            Json::Array(a) => a
                .iter()
                .map(|x| x.as_str().map(str::to_string).ok_or_else(bad))
                .collect(),
            _ => Err(bad()),
        }
    };
    let mut out = Vec::new();
    for s in services {
        let Json::Array(pair) = s else {
            return Err(bad());
        };
        if pair.len() != 2 {
            return Err(bad());
        }
        out.push((strings(&pair[0])?, strings(&pair[1])?));
    }
    Ok(out)
}

/// `https://<host>[/<path>]` with a lower-case public host and nothing else:
/// no port, userinfo, query or fragment, and a plain path. Returns the host
/// and the path prefix (starting and ending with `/`).
fn validate_rdap_base(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if !providerhttp::valid_public_hostname(host) {
        return None;
    }
    if !path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        || path.split('/').any(|seg| seg == "..")
    {
        return None;
    }
    let mut prefix = path.to_string();
    if !prefix.ends_with('/') {
        prefix.push('/');
    }
    Some((host.to_string(), prefix))
}

/// The registry server for a domain: the service listing the last label of
/// the domain, its first URL.
fn rdap_base_for(services: &Services, domain: &str) -> Option<(String, String)> {
    let tld = domain.rsplit('.').next()?.to_ascii_lowercase();
    let (_, urls) = services
        .iter()
        .find(|(tlds, _)| tlds.iter().any(|t| t.eq_ignore_ascii_case(&tld)))?;
    validate_rdap_base(urls.first()?)
}

fn rdap_date(s: &str) -> Option<(String, u64)> {
    let d = s.get(..10)?;
    breach_date(Some(d))
}

fn vcard_fn(entity: &Json) -> Option<String> {
    let Some(Json::Array(card)) = entity.get("vcardArray") else {
        return None;
    };
    let Some(Json::Array(props)) = card.get(1) else {
        return None;
    };
    for p in props {
        let Json::Array(p) = p else { continue };
        if p.first().and_then(|n| n.as_str()) == Some("fn") {
            let v = clean_text(p.get(3)?.as_str()?, 200);
            return (!v.is_empty()).then_some(v);
        }
    }
    None
}

fn has_role(entity: &Json, role: &str) -> bool {
    matches!(entity.get("roles"), Some(Json::Array(r)) if r.iter().any(|x| x.as_str().is_some_and(|x| x.eq_ignore_ascii_case(role))))
}

fn mentions_redaction(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("redacted") || l.contains("privacy")
}

/// Builds the one summary finding. Returns it with whether the registry
/// redacted the registrant. Registrant personal data is never read into the
/// output: only the registrar and technical facts are shown.
fn rdap_finding(
    body: &[u8],
    domain: &str,
    base: &str,
    now: u64,
) -> Result<(Finding, bool), String> {
    let text = std::str::from_utf8(body).map_err(|_| "unexpected answer".to_string())?;
    let doc = match Json::parse(text) {
        Ok(d @ Json::Object(_)) => d,
        _ => return Err("unexpected answer".into()),
    };
    let name = str_of(&doc, "ldhName")
        .map(|n| clean_text(n, 200))
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| domain.to_string());
    let mut parts: Vec<String> = Vec::new();
    let entities: &[Json] = doc
        .get("entities")
        .and_then(|e| e.as_array())
        .unwrap_or(&[]);
    if let Some(r) = entities
        .iter()
        .filter(|e| has_role(e, "registrar"))
        .find_map(vcard_fn)
    {
        parts.push(format!("Registrar: {r}."));
    }
    let mut event_at = None;
    let events: &[Json] = doc.get("events").and_then(|e| e.as_array()).unwrap_or(&[]);
    for (action, label) in [
        ("registration", "Registered"),
        ("last changed", "Last changed"),
        ("expiration", "Expires"),
    ] {
        let found = events.iter().find_map(|e| {
            if !str_of(e, "eventAction").is_some_and(|a| a.eq_ignore_ascii_case(action)) {
                return None;
            }
            rdap_date(str_of(e, "eventDate")?)
        });
        if let Some((d, t)) = found {
            parts.push(format!("{label}: {d}."));
            if action == "registration" {
                event_at = Some(t);
            }
        }
    }
    let mut redacted = false;
    let statuses: Vec<String> = doc
        .get("status")
        .and_then(|s| s.as_array())
        .unwrap_or(&[])
        .iter()
        .filter_map(|s| s.as_str())
        .map(|s| clean_text(s, 200))
        .filter(|s| !s.is_empty())
        .collect();
    if statuses.iter().any(|s| mentions_redaction(s)) {
        redacted = true;
    }
    if !statuses.is_empty() {
        parts.push(format!(
            "Status: {}.",
            statuses
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let ns: Vec<String> = doc
        .get("nameservers")
        .and_then(|s| s.as_array())
        .unwrap_or(&[])
        .iter()
        .filter_map(|n| str_of(n, "ldhName"))
        .map(|n| clean_text(n, 200))
        .filter(|n| !n.is_empty())
        .take(8)
        .collect();
    if !ns.is_empty() {
        parts.push(format!("Nameservers: {}.", ns.join(", ")));
    }
    if let Some(sd) = doc.get("secureDNS") {
        if let Some(Json::Bool(b)) = sd.get("delegationSigned") {
            parts.push(format!(
                "DNSSEC: {}.",
                if *b { "signed" } else { "not signed" }
            ));
        }
    }
    // Registrant: only whether details exist is used, never their content.
    let registrant_details = entities
        .iter()
        .filter(|e| has_role(e, "registrant"))
        .any(|e| vcard_fn(e).is_some_and(|n| !mentions_redaction(&n)));
    if let Some(Json::Array(rem)) = doc.get("remarks") {
        for r in rem {
            let mut texts: Vec<&str> = str_of(r, "title").into_iter().collect();
            if let Some(Json::Array(d)) = r.get("description") {
                texts.extend(d.iter().filter_map(|x| x.as_str()));
            }
            if texts.iter().any(|t| mentions_redaction(t)) {
                redacted = true;
            }
        }
    }
    if doc.get("redacted").is_some() {
        redacted = true;
    }
    let mut limitations = vec![
        "Registry data describes the domain; it does not show who controls a mailbox at it."
            .to_string(),
    ];
    let redact_note = redacted || !registrant_details;
    if redact_note {
        limitations.push(REDACTION_LIMIT.into());
    }
    let url = format!("{base}domain/{domain}");
    Ok((
        Finding {
            group: Group::Domain,
            confidence: Confidence::High,
            confidence_reason: "published by the domain's registry".into(),
            severity: Severity::Info,
            observed_at: now,
            event_at,
            source_id: RDAP_ID.into(),
            source_url: crate::osinthtml::safe_url(&url).then_some(url),
            title: format!("Registration: {name}"),
            evidence: if parts.is_empty() {
                "The registry published no registrar or technical details.".into()
            } else {
                parts.join(" ")
            },
            limitations,
            asset_id: None,
            asset_mime: None,
        },
        redact_note,
    ))
}

/// The cached bootstrap, or a fresh one. A stale entry is refetched; a
/// malformed answer is never cached.
fn rdap_services(timeout: Duration, addr: &str) -> Result<Services, String> {
    {
        let c = BOOTSTRAP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((t, s)) = c.as_ref() {
            if t.elapsed() < BOOTSTRAP_TTL {
                return Ok(s.clone());
            }
        }
    }
    let req = rdap_request(
        "rdap_bootstrap",
        BOOTSTRAP_HOST,
        BOOTSTRAP_PATH.into(),
        "application/json",
        timeout,
    );
    let resp = providerhttp::fetch(&req).map_err(|e| match e {
        HttpError::Timeout => "bootstrap request timed out".to_string(),
        e => providerhttp::redact(&e.to_string(), &[addr]),
    })?;
    if resp.status != 200 {
        return Err(format!("bootstrap answered HTTP {}", resp.status));
    }
    let services = parse_bootstrap(&resp.body)?;
    *BOOTSTRAP_CACHE.lock().unwrap_or_else(|e| e.into_inner()) =
        Some((Instant::now(), services.clone()));
    Ok(services)
}

/// The registry request. It takes the validated host and path prefix of a
/// bootstrap-selected base; the only way to reach anything else is the
/// loopback test override for provider `rdap_registry`, applied by
/// `providerhttp::fetch` (loopback http only), which replaces the origin.
fn rdap_registry_fetch(
    host: &str,
    prefix: &str,
    domain: &str,
    timeout: Duration,
) -> Result<providerhttp::Response, HttpError> {
    let path = format!("{prefix}domain/{}", providerhttp::pct_encode(domain));
    let req = rdap_request(
        "rdap_registry",
        host,
        path,
        "application/rdap+json",
        timeout,
    );
    providerhttp::fetch(&req)
}

fn rdap(q: &QueryCtx) -> Outcome {
    let remaining = q.deadline.saturating_duration_since(Instant::now());
    if q.stop() || remaining.is_zero() {
        return outcome(
            RDAP_ID,
            SourceState::Inconclusive,
            "stopped before this source ran",
        );
    }
    let addr = q.address.trim();
    let domain = addr
        .rsplit_once('@')
        .map(|(_, d)| d.trim_end_matches('.').to_ascii_lowercase())
        .unwrap_or_default();
    if !providerhttp::valid_public_hostname(&domain) {
        return outcome(
            RDAP_ID,
            SourceState::Inconclusive,
            "the address has no domain this source can look up",
        );
    }
    let timeout = remaining.min(Duration::from_secs(10));
    let services = match rdap_services(timeout, addr) {
        Ok(s) => s,
        Err(e) => return outcome(RDAP_ID, SourceState::Failed, &e),
    };
    let tld = domain.rsplit('.').next().unwrap_or("");
    let Some((host, prefix)) = rdap_base_for(&services, &domain) else {
        return outcome(
            RDAP_ID,
            SourceState::Failed,
            &format!("no usable RDAP server for .{tld}"),
        );
    };
    let remaining = q.deadline.saturating_duration_since(Instant::now());
    if q.stop() || remaining.is_zero() {
        return outcome(
            RDAP_ID,
            SourceState::Inconclusive,
            "stopped before this source ran",
        );
    }
    let resp = match rdap_registry_fetch(
        &host,
        &prefix,
        &domain,
        remaining.min(Duration::from_secs(10)),
    ) {
        Ok(r) => r,
        Err(HttpError::Timeout) => return outcome(RDAP_ID, SourceState::Failed, "timed out"),
        Err(e) => {
            let t = providerhttp::redact(&e.to_string(), &[addr]);
            return outcome(RDAP_ID, SourceState::Failed, &t);
        }
    };
    match resp.status {
        200 => match rdap_finding(
            &resp.body,
            &domain,
            &format!("https://{host}{prefix}"),
            now_secs(),
        ) {
            Ok((f, _)) => Outcome {
                source: status(RDAP_ID, SourceState::Matched, "registration record found"),
                findings: vec![f],
                assets: Vec::new(),
            },
            Err(_) => outcome(
                RDAP_ID,
                SourceState::Failed,
                "unexpected answer from the registry",
            ),
        },
        404 => outcome(
            RDAP_ID,
            SourceState::NoMatch,
            "no registration found; RDAP answers for registered domains; the address's domain may be a subdomain",
        ),
        429 => Outcome {
            source: SourceStatus {
                id: RDAP_ID.into(),
                state: SourceState::RateLimited,
                retry_after: resp.retry_after,
                detail: "the registry's rate limit was reached".into(),
            },
            findings: Vec::new(),
            assets: Vec::new(),
        },
        400 | 501 => outcome(
            RDAP_ID,
            SourceState::Inconclusive,
            "the registry does not answer this query",
        ),
        n => outcome(
            RDAP_ID,
            SourceState::Failed,
            &format!("the registry answered HTTP {n}"),
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
    fn findings_over_the_cap_are_cut_with_a_limitation_line() {
        let one = r#"{"Name":"N","Title":"T","BreachDate":"2013-10-04"}"#;
        let body = format!("[{}]", vec![one; MAX_FINDINGS + 5].join(","));
        let fs = hibp_findings_direct(body.as_bytes(), 1).unwrap();
        assert_eq!(
            fs.len(),
            MAX_FINDINGS + 1,
            "one extra row marks the cut-off"
        );
        let _g = HIBP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let (port, _h) = serve(reply.into_bytes());
        std::env::set_var(
            "MSFE_NG_OSINT_BASE_HIBP",
            format!("http://127.0.0.1:{port}"),
        );
        let cfg = Config {
            osint_hibp_key: "K".into(),
            ..Config::default()
        };
        let cancel = AtomicBool::new(false);
        let q = QueryCtx {
            address: "a@example.org",
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(10),
            cfg: &cfg,
        };
        let o = run("hibp", &q);
        std::env::remove_var("MSFE_NG_OSINT_BASE_HIBP");
        assert_eq!(o.findings.len(), MAX_FINDINGS);
        assert!(
            o.source.detail.contains("returned more"),
            "{}",
            o.source.detail
        );
        assert!(o.findings[0]
            .limitations
            .iter()
            .any(|l| l.contains("first 100 incidents")));
    }

    #[test]
    fn fixture_png_is_a_well_formed_1x1_image() {
        let p = &FIXTURE_PNG;
        assert_eq!(&p[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(&p[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(p[16..20].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(p[20..24].try_into().unwrap()), 1);
        assert_eq!(&p[p.len() - 8..p.len() - 4], b"IEND");
        assert_eq!(&p[p.len() - 4..], &[0xAE, 0x42, 0x60, 0x82]);
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
            if status.starts_with("401") || status.starts_with("403") {
                assert!(
                    o.source
                        .detail
                        .starts_with(&format!("HTTP {}", &status[..3])),
                    "{}",
                    o.source.detail
                );
            }
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
        let mut big = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        big.resize(300 * 1024, 0);
        let cases: Vec<(Vec<u8>, SourceState)> = vec![
            (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\nConnection: close\r\n\r\n<html>".to_vec(), SourceState::Failed),
            (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::NoMatch),
            ([format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", big.len()).into_bytes(), big].concat(), SourceState::Failed),
            (b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::RateLimited),
            (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(), SourceState::Restricted),
        ];
        for (reply, want) in cases {
            let reply_len = reply.len();
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
            if reply_len > 100 * 1024 {
                assert!(o.source.detail.contains("256 KiB"), "{}", o.source.detail);
            }
            if want == SourceState::Restricted {
                assert!(o.source.detail.contains("HTTP 403"), "{}", o.source.detail);
                assert!(!o.source.detail.contains("API key"), "{}", o.source.detail);
            }
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

    // ---- RDAP -----------------------------------------------------------

    static RDAP_LOCK: Mutex<()> = Mutex::new(());

    const BOOTSTRAP: &str = r#"{"version":"1.0","services":[[["com","net"],["https://rdap.verisign.com/com/v1/","http://other.example.net/"]],[["org"],["https://rdap.example.net/org/v1/"]],[["uk"],["https://rdap.nominet.example.uk/uk/"]],[["bad"],[]]]}"#;

    const DOMAIN_JSON: &str = r#"{"objectClassName":"domain","ldhName":"EXAMPLE.ORG","status":["client transfer prohibited","active"],"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"last changed","eventDate":"2024-08-14T07:01:38Z"},{"eventAction":"expiration","eventDate":"2025-08-13T04:00:00Z"}],"nameservers":[{"ldhName":"A.IANA-SERVERS.NET"},{"ldhName":"B.IANA-SERVERS.NET"}],"secureDNS":{"delegationSigned":true},"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Reg <script>alert(1)</script>Ltd\u0007"]]]},{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Jane Q. Registrant"],["email",{},"text","jane@registrant.example"]]]}],"remarks":[{"title":"REDACTED FOR PRIVACY","description":["Some data redacted"]}]}"#;

    #[test]
    fn clean_text_strips_tags_decodes_few_entities_and_controls() {
        assert_eq!(
            clean_text("a <b>bold</b> <script>x()</script>y", 100),
            "a bold x()y"
        );
        assert_eq!(
            clean_text(
                "Tom &amp; Jerry &lt;3 &quot;q&quot; it&#39;s &nbsp;&copy;",
                100
            ),
            "Tom & Jerry <3 \"q\" it's &nbsp;&copy;"
        );
        assert_eq!(clean_text("&amp;lt;", 100), "&lt;", "decoded once only");
        assert_eq!(clean_text("a\u{7}b\u{0}c\u{1b}[0m", 100), "abc[0m");
        assert_eq!(clean_text("  a \n\t b\r\n  c  ", 100), "a b c");
        assert_eq!(clean_text("unclosed <tag", 100), "unclosed");
        assert_eq!(clean_text("", 10), "");
        assert_eq!(clean_text("abc", 0), "");
    }

    #[test]
    fn clean_text_truncates_on_char_boundaries() {
        let big = "x".repeat(5 * 1024);
        let t = clean_text(&big, 200);
        assert_eq!(t.chars().count(), 200);
        assert!(t.ends_with('\u{2026}'));
        let multi = "\u{e9}\u{4e2d}\u{1f600}".repeat(100);
        for max in [1, 2, 3, 4, 5, 7, 50] {
            let t = clean_text(&multi, max);
            assert!(t.chars().count() <= max, "{max}");
            assert!(t.ends_with('\u{2026}'));
        }
        assert_eq!(clean_text("short", 5), "short");
    }

    #[test]
    fn bootstrap_parses_and_rejects_malformed_documents() {
        let s = parse_bootstrap(BOOTSTRAP.as_bytes()).unwrap();
        assert_eq!(s.len(), 4);
        assert_eq!(s[0].0, vec!["com".to_string(), "net".to_string()]);
        assert_eq!(s[0].1.len(), 2);
        for bad in [
            "",
            "null",
            "{}",
            "[1]",
            "{\"services\":3}",
            "{\"services\":[[1,2]]}",
            "{\"services\":[[[\"a\"]]]}",
            "<html>",
            "{\"services\":[[[\"a\"],[1]]]}",
        ] {
            assert!(parse_bootstrap(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(parse_bootstrap(b"{\"services\":[]}").unwrap().is_empty());
    }

    #[test]
    fn base_is_chosen_by_the_last_label_and_first_url() {
        let s = parse_bootstrap(BOOTSTRAP.as_bytes()).unwrap();
        let b = rdap_base_for(&s, "Example.NET").unwrap();
        assert_eq!(b, ("rdap.verisign.com".to_string(), "/com/v1/".to_string()));
        let b = rdap_base_for(&s, "foo.bar.co.uk").unwrap();
        assert_eq!(b.0, "rdap.nominet.example.uk");
        assert_eq!(b.1, "/uk/");
        assert!(rdap_base_for(&s, "example.zz").is_none());
        assert!(rdap_base_for(&s, "example.bad").is_none(), "empty url list");
    }

    #[test]
    fn base_urls_are_accepted_only_when_plain_https_public_hosts() {
        assert_eq!(
            validate_rdap_base("https://rdap.example.com/x/v1/"),
            Some(("rdap.example.com".into(), "/x/v1/".into()))
        );
        assert_eq!(
            validate_rdap_base("https://rdap.example.com"),
            Some(("rdap.example.com".into(), "/".into()))
        );
        assert_eq!(
            validate_rdap_base("https://rdap.example.com/x"),
            Some(("rdap.example.com".into(), "/x/".into()))
        );
        for bad in [
            "http://rdap.example.com/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://rdap.example.com:8080/",
            "https://user@rdap.example.com/",
            "https://user:pw@rdap.example.com/",
            "https://Rdap.Example.COM/",
            "https://rdap.example.com/?q=1",
            "https://rdap.example.com/#f",
            "https://rdap.example.com/a b/",
            "https://rdap.example.com/%2e%2e/",
            "https://rdap.example.com/../x/",
            "https://rdap.example.com/a\\b/",
            "https://10.0.0.1/",
            "ftp://rdap.example.com/",
            "",
            "https://",
            "https:///x",
        ] {
            assert!(validate_rdap_base(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn domain_object_becomes_one_registrar_and_technical_finding() {
        let (f, redacted) = rdap_finding(
            DOMAIN_JSON.as_bytes(),
            "example.org",
            "https://rdap.example.net/org/v1/",
            5,
        )
        .unwrap();
        assert_eq!(f.group, Group::Domain);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.confidence_reason, "published by the domain's registry");
        assert_eq!(f.title, "Registration: EXAMPLE.ORG");
        assert_eq!(f.event_at, Some(808_358_400));
        assert!(
            f.evidence.contains("Registrar: Reg alert(1)Ltd"),
            "{}",
            f.evidence
        );
        assert!(f.evidence.contains("1995-08-14"));
        assert!(f.evidence.contains("2024-08-14"));
        assert!(f.evidence.contains("2025-08-13"));
        assert!(f.evidence.contains("client transfer prohibited"));
        assert!(f.evidence.contains("A.IANA-SERVERS.NET"));
        assert!(f.evidence.contains("DNSSEC: signed"));
        assert!(!f.evidence.contains("Jane") && !f.evidence.contains("registrant.example"));
        assert!(!f.evidence.contains('<') && !f.evidence.contains('\u{7}'));
        assert!(redacted);
        assert!(f
            .limitations
            .iter()
            .any(|l| l
                == "Registrant details are redacted by the registry; no owner identity is shown."));
        assert_eq!(
            f.source_url.as_deref(),
            Some("https://rdap.example.net/org/v1/domain/example.org")
        );
    }

    #[test]
    fn a_domain_without_registrant_details_gets_the_redaction_limitation_and_unsigned_dnssec() {
        let body = r#"{"ldhName":"x.example.org","secureDNS":{"delegationSigned":false},"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","R"]]]}]}"#;
        let (f, _) = rdap_finding(
            body.as_bytes(),
            "x.example.org",
            "https://r.example.net/",
            5,
        )
        .unwrap();
        assert!(f.evidence.contains("DNSSEC: not signed"));
        assert!(f
            .limitations
            .iter()
            .any(|l| l.contains("redacted by the registry")));
        assert_eq!(f.event_at, None);
        let (empty, _) = rdap_finding(b"{}", "q.example.org", "https://r.example.net/", 5).unwrap();
        assert_eq!(empty.title, "Registration: q.example.org");
        for bad in ["", "[]", "null", "<html>", "\"x\""] {
            assert!(rdap_finding(bad.as_bytes(), "a.org", "https://r.example.net/", 1).is_err());
        }
    }

    #[test]
    fn lists_are_capped_and_strings_are_bounded() {
        let ns: Vec<String> = (0..20)
            .map(|i| format!("{{\"ldhName\":\"ns{i}.example.org\"}}"))
            .collect();
        let st: Vec<String> = (0..20).map(|i| format!("\"status{i}\"")).collect();
        let body = format!(
            "{{\"ldhName\":\"{}\",\"nameservers\":[{}],\"status\":[{}]}}",
            "a".repeat(5000),
            ns.join(","),
            st.join(",")
        );
        let (f, _) = rdap_finding(body.as_bytes(), "a.org", "https://r.example.net/", 1).unwrap();
        assert!(f.evidence.contains("ns7.example.org") && !f.evidence.contains("ns8.example.org"));
        assert!(f.evidence.contains("status7") && !f.evidence.contains("status8"));
        assert!(f.title.chars().count() <= "Registration: ".len() + 200);
    }

    #[test]
    fn rdap_requests_carry_only_an_accept_header() {
        let r = rdap_request(
            "rdap_registry",
            "rdap.example.net",
            "/org/v1/domain/a.org".into(),
            "application/rdap+json",
            Duration::from_secs(5),
        );
        let names: Vec<&str> = r.headers.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, vec!["accept"]);
        let r = rdap_request(
            "rdap_bootstrap",
            BOOTSTRAP_HOST,
            BOOTSTRAP_PATH.into(),
            "application/json",
            Duration::from_secs(5),
        );
        let names: Vec<&str> = r.headers.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, vec!["accept"]);
        assert_eq!(r.host, "data.iana.org");
        assert_eq!(r.max_body, 512 * 1024);
    }

    fn http(status: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status}\r\nRetry-After: 7\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).into_bytes()
    }

    fn run_rdap(address: &str) -> Outcome {
        let cfg = Config::default();
        let cancel = AtomicBool::new(false);
        let q = QueryCtx {
            address,
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(10),
            cfg: &cfg,
        };
        run("rdap", &q)
    }

    fn set_rdap_env(boot: u16, reg: Option<u16>) {
        clear_bootstrap_cache();
        std::env::set_var(
            "MSFE_NG_OSINT_BASE_RDAP_BOOTSTRAP",
            format!("http://127.0.0.1:{boot}"),
        );
        if let Some(r) = reg {
            std::env::set_var(
                "MSFE_NG_OSINT_BASE_RDAP_REGISTRY",
                format!("http://127.0.0.1:{r}"),
            );
        }
    }

    fn clear_rdap_env() {
        std::env::remove_var("MSFE_NG_OSINT_BASE_RDAP_BOOTSTRAP");
        std::env::remove_var("MSFE_NG_OSINT_BASE_RDAP_REGISTRY");
        clear_bootstrap_cache();
    }

    #[test]
    fn rdap_status_mapping_end_to_end_with_two_stand_ins() {
        let _g = RDAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cases: Vec<(&str, SourceState)> = vec![
            ("200 OK", SourceState::Matched),
            ("404 Not Found", SourceState::NoMatch),
            ("429 Too Many Requests", SourceState::RateLimited),
            ("400 Bad Request", SourceState::Inconclusive),
            ("501 Not Implemented", SourceState::Inconclusive),
            ("503 Service Unavailable", SourceState::Failed),
        ];
        for (status, want) in cases {
            let (bport, bh) = serve(http("200 OK", BOOTSTRAP));
            let body = if status.starts_with("200") {
                DOMAIN_JSON
            } else {
                ""
            };
            let (rport, rh) = serve(http(status, body));
            set_rdap_env(bport, Some(rport));
            let o = run_rdap("nobody@Example.ORG");
            clear_rdap_env();
            let bhead = bh.join().unwrap();
            let rhead = rh.join().unwrap();
            assert_eq!(o.source.state, want, "{status}: {}", o.source.detail);
            assert!(bhead.starts_with("GET /rdap/dns.json "), "{bhead}");
            assert!(
                rhead.starts_with("GET /org/v1/domain/example.org "),
                "{rhead}"
            );
            assert!(!rhead.to_ascii_lowercase().contains("nobody"));
            let low = rhead.to_ascii_lowercase();
            assert!(low.contains("accept: application/rdap+json"), "{rhead}");
            for secret in ["authorization", "api-key", "cookie", "token", "key"] {
                assert!(!low.contains(secret), "{secret}: {rhead}");
            }
            if status.starts_with("429") {
                assert_eq!(o.source.retry_after, Some(7));
            }
            if status.starts_with("200") {
                assert_eq!(o.findings.len(), 1);
            } else {
                assert!(o.findings.is_empty());
            }
            if status.starts_with("404") {
                assert!(
                    o.source.detail.contains("may be a subdomain"),
                    "{}",
                    o.source.detail
                );
            }
            if status.starts_with("400") || status.starts_with("501") {
                assert!(o.source.detail.contains("does not answer this query"));
            }
        }
    }

    #[test]
    fn rdap_bootstrap_failures_and_unusable_servers_are_failed_not_no_match() {
        let _g = RDAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cases: Vec<(&str, &str, &str, &str)> = vec![
            (
                "200 OK",
                "<html>blocked</html>",
                "nobody@example.org",
                "unexpected bootstrap answer",
            ),
            (
                "503 Service Unavailable",
                "",
                "nobody@example.org",
                "HTTP 503",
            ),
            (
                "200 OK",
                BOOTSTRAP,
                "nobody@example.zz",
                "no usable RDAP server for .zz",
            ),
            (
                "200 OK",
                r#"{"services":[[["org"],["http://rdap.example.net/"]]]}"#,
                "nobody@example.org",
                "no usable RDAP server for .org",
            ),
        ];
        for (status, body, addr, want) in cases {
            let (bport, _bh) = serve(http(status, body));
            set_rdap_env(bport, None);
            let o = run_rdap(addr);
            clear_rdap_env();
            assert_eq!(o.source.state, SourceState::Failed, "{}", o.source.detail);
            assert!(o.source.detail.contains(want), "{}", o.source.detail);
            assert!(!o.source.detail.contains("nobody"));
        }
    }

    #[test]
    fn rdap_unusable_addresses_make_no_request() {
        let _g = RDAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_rdap_env();
        for a in ["nodomain", "a@", "a@localhost", "a@127.0.0.1", "a@[::1]"] {
            let o = run_rdap(a);
            assert_eq!(
                o.source.state,
                SourceState::Inconclusive,
                "{a}: {}",
                o.source.detail
            );
        }
    }

    #[test]
    fn rdap_bootstrap_is_cached_and_a_stale_or_cleared_cache_is_refetched() {
        let _g = RDAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (bport, bh) = serve(http("200 OK", BOOTSTRAP));
        let (r1, _h1) = serve(http("404 Not Found", ""));
        set_rdap_env(bport, Some(r1));
        let o = run_rdap("a@example.org");
        assert_eq!(o.source.state, SourceState::NoMatch);
        bh.join().unwrap();
        // the bootstrap stand-in is gone: a second run must come from the cache
        let (r2, _h2) = serve(http("404 Not Found", ""));
        std::env::set_var(
            "MSFE_NG_OSINT_BASE_RDAP_REGISTRY",
            format!("http://127.0.0.1:{r2}"),
        );
        let o = run_rdap("a@example.org");
        assert_eq!(o.source.state, SourceState::NoMatch, "{}", o.source.detail);
        // a stale entry is refetched (the dead stand-in then fails the run)
        age_bootstrap_cache(Duration::from_secs(25 * 3600));
        let o = run_rdap("a@example.org");
        assert_eq!(o.source.state, SourceState::Failed, "{}", o.source.detail);
        clear_rdap_env();
    }

    #[test]
    fn rdap_is_known_keyless_and_discloses_only_the_domain() {
        let i = infos(&Config::default())
            .into_iter()
            .find(|p| p.id == "rdap")
            .unwrap();
        assert!(i.configured);
        assert!(i
            .disclosure
            .contains("domain of the address (not the full address)"));
        assert!(i.disclosure.contains("IANA bootstrap"));
        assert!(is_known("rdap"));
    }
}
