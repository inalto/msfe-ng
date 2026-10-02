//! OSINT report model: what an address-footprint investigation found, where it
//! came from, and what that evidence does not prove. Pure data and JSON; no
//! I/O. Kept apart from `delivery::Report` so exposure never reads as mail
//! health.

use crate::json::Json;

pub const SCHEMA_VERSION: i64 = 1;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

macro_rules! simple_enum {
    ($name:ident { $($var:ident => $s:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name { $($var),+ }
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self { $($name::$var => $s),+ }
            }
            pub fn parse(s: &str) -> Option<$name> {
                match s { $($s => Some($name::$var),)+ _ => None }
            }
        }
    };
}

/// Finding group. Unknown strings are kept verbatim so a newer writer's
/// findings are not dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group {
    Exposure,
    Profile,
    Reference,
    Domain,
    Validation,
    Context,
    Unknown(String),
}
impl Group {
    pub fn as_str(&self) -> &str {
        match self {
            Group::Exposure => "exposure",
            Group::Profile => "profile",
            Group::Reference => "reference",
            Group::Domain => "domain",
            Group::Validation => "validation",
            Group::Context => "context",
            Group::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> Group {
        match s {
            "exposure" => Group::Exposure,
            "profile" => Group::Profile,
            "reference" => Group::Reference,
            "domain" => Group::Domain,
            "validation" => Group::Validation,
            "context" => Group::Context,
            other => Group::Unknown(other.to_string()),
        }
    }
}
simple_enum!(Confidence { High => "high", Medium => "medium", Low => "low", Unknown => "unknown" });
/// Finding severity. Unknown strings are kept verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Unknown(String),
}
impl Severity {
    pub fn as_str(&self) -> &str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            other => Severity::Unknown(other.to_string()),
        }
    }
}
simple_enum!(RunState {
    Running => "running", Complete => "complete", Partial => "partial",
    Cancelled => "cancelled", Failed => "failed",
});

/// Outcome of one source. Unknown strings are kept verbatim and never count as
/// success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceState {
    Matched,
    NoMatch,
    Inconclusive,
    Restricted,
    NotConfigured,
    NotRequested,
    RateLimited,
    Failed,
    Unknown(String),
}

impl SourceState {
    pub fn as_str(&self) -> &str {
        match self {
            SourceState::Matched => "matched",
            SourceState::NoMatch => "no_match",
            SourceState::Inconclusive => "inconclusive",
            SourceState::Restricted => "restricted",
            SourceState::NotConfigured => "not_configured",
            SourceState::NotRequested => "not_requested",
            SourceState::RateLimited => "rate_limited",
            SourceState::Failed => "failed",
            SourceState::Unknown(s) => s,
        }
    }
    pub fn parse(s: &str) -> SourceState {
        match s {
            "matched" => SourceState::Matched,
            "no_match" => SourceState::NoMatch,
            "inconclusive" => SourceState::Inconclusive,
            "restricted" => SourceState::Restricted,
            "not_configured" => SourceState::NotConfigured,
            "not_requested" => SourceState::NotRequested,
            "rate_limited" => SourceState::RateLimited,
            "failed" => SourceState::Failed,
            other => SourceState::Unknown(other.to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub group: Group,
    pub confidence: Confidence,
    pub confidence_reason: String,
    pub severity: Severity,
    /// When MSFE-NG retrieved the evidence.
    pub observed_at: u64,
    /// When the source says the event happened, if known.
    pub event_at: Option<u64>,
    pub source_id: String,
    pub source_url: Option<String>,
    pub title: String,
    pub evidence: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SourceStatus {
    pub id: String,
    pub state: SourceState,
    pub retry_after: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct OsintReport {
    pub run_id: String,
    pub address: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub state: RunState,
    pub cached: bool,
    pub planned: Vec<String>,
    pub sources: Vec<SourceStatus>,
    pub findings: Vec<Finding>,
    pub delivery_run_id: Option<String>,
    pub limitations: Vec<String>,
}

fn opt_u64(v: Option<u64>) -> Json {
    v.map(|n| Json::Int(n as i64)).unwrap_or(Json::Null)
}
fn opt_str(v: &Option<String>) -> Json {
    v.as_ref().map(Json::str).unwrap_or(Json::Null)
}
fn strs(v: &[String]) -> Json {
    Json::Array(v.iter().map(Json::str).collect())
}
fn str_list(j: Option<&Json>) -> Vec<String> {
    j.and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

impl Finding {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("group".into(), Json::str(self.group.as_str())),
            ("confidence".into(), Json::str(self.confidence.as_str())),
            (
                "confidence_reason".into(),
                Json::str(&self.confidence_reason),
            ),
            ("severity".into(), Json::str(self.severity.as_str())),
            ("observed_at".into(), Json::Int(self.observed_at as i64)),
            ("event_at".into(), opt_u64(self.event_at)),
            ("source_id".into(), Json::str(&self.source_id)),
            ("source_url".into(), opt_str(&self.source_url)),
            ("title".into(), Json::str(&self.title)),
            ("evidence".into(), Json::str(&self.evidence)),
            ("limitations".into(), strs(&self.limitations)),
        ])
    }
    fn from_json(j: &Json) -> Option<Finding> {
        Some(Finding {
            group: Group::parse(&j.str_field("group")),
            confidence: Confidence::parse(&j.str_field("confidence"))
                .unwrap_or(Confidence::Unknown),
            confidence_reason: j.str_field("confidence_reason"),
            severity: Severity::parse(&j.str_field("severity")),
            observed_at: j.get("observed_at").and_then(Json::as_i64).unwrap_or(0) as u64,
            event_at: j.get("event_at").and_then(Json::as_i64).map(|n| n as u64),
            source_id: j.str_field("source_id"),
            source_url: j.get("source_url").and_then(Json::as_str).map(String::from),
            title: j.str_field("title"),
            evidence: j.str_field("evidence"),
            limitations: str_list(j.get("limitations")),
        })
    }
}

impl SourceStatus {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::str(&self.id)),
            ("state".into(), Json::str(self.state.as_str())),
            ("retry_after".into(), opt_u64(self.retry_after)),
            ("detail".into(), Json::str(&self.detail)),
        ])
    }
    fn from_json(j: &Json) -> SourceStatus {
        SourceStatus {
            id: j.str_field("id"),
            state: SourceState::parse(&j.str_field("state")),
            retry_after: j
                .get("retry_after")
                .and_then(Json::as_i64)
                .map(|n| n as u64),
            detail: j.str_field("detail"),
        }
    }
}

impl OsintReport {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("schema_version".into(), Json::Int(SCHEMA_VERSION)),
            ("kind".into(), Json::str("osint")),
            ("run_id".into(), Json::str(&self.run_id)),
            ("address".into(), Json::str(&self.address)),
            ("started".into(), Json::Int(self.started as i64)),
            ("finished".into(), opt_u64(self.finished)),
            ("state".into(), Json::str(self.state.as_str())),
            ("cached".into(), Json::Bool(self.cached)),
            ("planned".into(), strs(&self.planned)),
            (
                "sources".into(),
                Json::Array(self.sources.iter().map(SourceStatus::to_json).collect()),
            ),
            (
                "findings".into(),
                Json::Array(self.findings.iter().map(Finding::to_json).collect()),
            ),
            ("delivery_run_id".into(), opt_str(&self.delivery_run_id)),
            ("limitations".into(), strs(&self.limitations)),
        ])
    }

    pub fn from_json(j: &Json) -> Result<OsintReport, String> {
        if j.str_field("kind") != "osint" {
            return Err("not an OSINT report".into());
        }
        if let Some(v) = j.get("schema_version").and_then(Json::as_i64) {
            if v > SCHEMA_VERSION {
                return Err(format!("report written by a newer version (schema {v})"));
            }
        }
        Ok(OsintReport {
            run_id: j.str_field("run_id"),
            address: j.str_field("address"),
            started: j.get("started").and_then(Json::as_i64).unwrap_or(0) as u64,
            finished: j.get("finished").and_then(Json::as_i64).map(|n| n as u64),
            state: RunState::parse(&j.str_field("state")).unwrap_or(RunState::Failed),
            cached: matches!(j.get("cached"), Some(Json::Bool(true))),
            planned: str_list(j.get("planned")),
            sources: j
                .get("sources")
                .and_then(Json::as_array)
                .map(|a| a.iter().map(SourceStatus::from_json).collect())
                .unwrap_or_default(),
            findings: j
                .get("findings")
                .and_then(Json::as_array)
                .map(|a| a.iter().filter_map(Finding::from_json).collect())
                .unwrap_or_default(),
            delivery_run_id: j
                .get("delivery_run_id")
                .and_then(Json::as_str)
                .map(String::from),
            limitations: str_list(j.get("limitations")),
        })
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn unknown_group_and_severity_survive_a_round_trip() {
        let j = Json::parse(
            r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete","findings":[{"group":"brand_new","severity":"catastrophic","confidence":"high","title":"t","evidence":"e","source_id":"s","observed_at":5}]}"#,
        ).unwrap();
        let r = OsintReport::from_json(&j).unwrap();
        assert_eq!(
            r.findings.len(),
            1,
            "an unknown group must not drop the finding"
        );
        assert_eq!(r.findings[0].group, Group::Unknown("brand_new".into()));
        assert_eq!(
            r.findings[0].severity,
            Severity::Unknown("catastrophic".into())
        );
        let again =
            OsintReport::from_json(&Json::parse(&r.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(again.findings[0].group.as_str(), "brand_new");
        assert_eq!(again.findings[0].severity.as_str(), "catastrophic");
    }

    #[test]
    fn a_newer_schema_version_is_refused() {
        let j = Json::parse(r#"{"schema_version":2,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete"}"#).unwrap();
        assert!(OsintReport::from_json(&j).is_err());
        let ok = Json::parse(r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"complete"}"#).unwrap();
        assert!(OsintReport::from_json(&ok).is_ok());
    }

    use super::*;

    fn sample() -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "user@example.org".into(),
            started: 100,
            finished: Some(110),
            state: RunState::Partial,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![SourceStatus {
                id: "fixture".into(),
                state: SourceState::Matched,
                retry_after: Some(30),
                detail: "ok".into(),
            }],
            findings: vec![Finding {
                group: Group::Exposure,
                confidence: Confidence::Medium,
                confidence_reason: "fixture".into(),
                severity: Severity::Info,
                observed_at: 105,
                event_at: Some(50),
                source_id: "fixture".into(),
                source_url: Some("https://example.org/x".into()),
                title: "t".into(),
                evidence: "<b>\"q\"</b>".into(),
                limitations: vec!["l".into()],
            }],
            delivery_run_id: None,
            limitations: vec!["public sources are incomplete".into()],
        }
    }

    #[test]
    fn round_trips_through_json() {
        let r = sample();
        let text = r.to_json().to_string();
        let back = OsintReport::from_json(&Json::parse(&text).unwrap()).unwrap();
        assert_eq!(back.to_json().to_string(), text);
        assert_eq!(back.findings[0].evidence, "<b>\"q\"</b>");
    }

    #[test]
    fn json_carries_schema_version_and_kind() {
        let j = sample().to_json();
        assert_eq!(j.get("schema_version").and_then(Json::as_i64), Some(1));
        assert_eq!(j.str_field("kind"), "osint");
    }

    #[test]
    fn unknown_source_state_is_preserved_not_success() {
        let s = SourceState::parse("brand_new");
        assert_eq!(s, SourceState::Unknown("brand_new".into()));
        assert_eq!(s.as_str(), "brand_new");
        assert_ne!(s, SourceState::NoMatch);
    }

    #[test]
    fn unknown_fields_and_missing_optionals_are_tolerated() {
        let j = Json::parse(
            r#"{"schema_version":1,"kind":"osint","run_id":"0123456789abcdef","address":"a@b.co","started":1,"state":"running","extra":{"x":1}}"#,
        )
        .unwrap();
        let r = OsintReport::from_json(&j).unwrap();
        assert!(r.finished.is_none() && r.findings.is_empty() && r.sources.is_empty());
    }

    #[test]
    fn rejects_a_non_osint_document() {
        let j = Json::parse(r#"{"kind":"delivery"}"#).unwrap();
        assert!(OsintReport::from_json(&j).is_err());
    }
}
