//! The result model of the delivery test: every check is one `Check` with a
//! five-state verdict, the side of the conversation it concerns (sending,
//! receiving, or this server), evidence, and a fix. A `Report` is the set of
//! checks of one run plus what was planned, so a client can show progress.
//!
//! The rule the whole tab rests on: a lookup that could not be performed is
//! `Unknown` with the reason — never a finding. A check only says `Fail`
//! when the evidence says so.

use crate::json::Json;
use std::collections::BTreeMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Verdict {
    Fail,
    Warn,
    Unknown,
    Pass,
    NotApplicable,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Pass => "pass",
            Verdict::Warn => "warn",
            Verdict::Fail => "fail",
            Verdict::Unknown => "unknown",
            Verdict::NotApplicable => "na",
        }
    }
    pub fn parse(s: &str) -> Verdict {
        match s {
            "pass" => Verdict::Pass,
            "warn" => Verdict::Warn,
            "fail" => Verdict::Fail,
            "na" => Verdict::NotApplicable,
            _ => Verdict::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Sending,
    Receiving,
    Server,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Sending => "sending",
            Scope::Receiving => "receiving",
            Scope::Server => "server",
        }
    }
    pub fn parse(s: &str) -> Scope {
        match s {
            "receiving" => Scope::Receiving,
            "server" => Scope::Server,
            _ => Scope::Sending,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
    pub fn parse(s: &str) -> Severity {
        match s {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Dns,
    Spf,
    Dkim,
    Dmarc,
    MailServers,
    TransportSecurity,
    Reputation,
    Account,
    Routing,
    OutboundIdentity,
    Services,
    Limits,
    Logs,
    Abuse,
    Message,
    Bounce,
    Inbox,
    Meta,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Dns => "dns",
            Category::Spf => "spf",
            Category::Dkim => "dkim",
            Category::Dmarc => "dmarc",
            Category::MailServers => "mailservers",
            Category::TransportSecurity => "transport",
            Category::Reputation => "reputation",
            Category::Account => "account",
            Category::Routing => "routing",
            Category::OutboundIdentity => "outbound",
            Category::Services => "services",
            Category::Limits => "limits",
            Category::Logs => "logs",
            Category::Abuse => "abuse",
            Category::Message => "message",
            Category::Bounce => "bounce",
            Category::Inbox => "inbox",
            Category::Meta => "meta",
        }
    }
    /// Human title for the report sections.
    pub fn title(&self) -> &'static str {
        match self {
            Category::Dns => "DNS",
            Category::Spf => "SPF",
            Category::Dkim => "DKIM",
            Category::Dmarc => "DMARC",
            Category::MailServers => "Mail servers",
            Category::TransportSecurity => "Transport security",
            Category::Reputation => "Reputation",
            Category::Account => "Account",
            Category::Routing => "Routing",
            Category::OutboundIdentity => "Outbound identity",
            Category::Services => "Services and network",
            Category::Limits => "Limits and filtering",
            Category::Logs => "Logs and queues",
            Category::Abuse => "Abuse and reputation",
            Category::Message => "Message",
            Category::Bounce => "Bounce",
            Category::Inbox => "Diagnostic inbox",
            Category::Meta => "About this test",
        }
    }
    pub fn parse(s: &str) -> Category {
        match s {
            "dns" => Category::Dns,
            "spf" => Category::Spf,
            "dkim" => Category::Dkim,
            "dmarc" => Category::Dmarc,
            "mailservers" => Category::MailServers,
            "transport" => Category::TransportSecurity,
            "reputation" => Category::Reputation,
            "account" => Category::Account,
            "routing" => Category::Routing,
            "outbound" => Category::OutboundIdentity,
            "services" => Category::Services,
            "limits" => Category::Limits,
            "logs" => Category::Logs,
            "abuse" => Category::Abuse,
            "message" => Category::Message,
            "bounce" => Category::Bounce,
            "inbox" => Category::Inbox,
            _ => Category::Meta,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    pub label: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Fix {
    pub summary: String,
    /// A DNS record to publish, in zone-file form.
    pub dns_record: Option<String>,
    /// Where in WHM/cPanel to click.
    pub location: Option<String>,
    pub command: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    /// Stable id, e.g. `spf.record`, `mx.starttls`.
    pub id: String,
    /// The host / IP / selector the check is about, when per-target.
    pub target: Option<String>,
    pub scope: Scope,
    pub category: Category,
    pub verdict: Verdict,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<Evidence>,
    pub fix: Option<Fix>,
    /// Epoch seconds when the check finished.
    pub at: u64,
    pub duration_ms: u64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Check {
    pub fn new(
        id: impl Into<String>,
        scope: Scope,
        category: Category,
        verdict: Verdict,
        severity: Severity,
        title: impl Into<String>,
        explanation: impl Into<String>,
    ) -> Check {
        Check {
            id: id.into(),
            target: None,
            scope,
            category,
            verdict,
            severity,
            title: title.into(),
            explanation: explanation.into(),
            evidence: Vec::new(),
            fix: None,
            at: now_secs(),
            duration_ms: 0,
        }
    }
    pub fn target(mut self, t: impl Into<String>) -> Check {
        self.target = Some(t.into());
        self
    }
    pub fn evidence(mut self, label: impl Into<String>, text: impl Into<String>) -> Check {
        self.evidence.push(Evidence {
            label: label.into(),
            text: text.into(),
        });
        self
    }
    pub fn fix(mut self, fix: Fix) -> Check {
        self.fix = Some(fix);
        self
    }
    pub fn fix_summary(self, summary: impl Into<String>) -> Check {
        self.fix(Fix {
            summary: summary.into(),
            ..Default::default()
        })
    }
    pub fn took(mut self, ms: u64) -> Check {
        self.duration_ms = ms;
        self
    }

    pub fn to_json(&self) -> Json {
        let opt = |o: &Option<String>| o.clone().map(Json::Str).unwrap_or(Json::Null);
        Json::Object(vec![
            ("id".into(), Json::str(&self.id)),
            ("target".into(), opt(&self.target)),
            ("scope".into(), Json::str(self.scope.as_str())),
            ("category".into(), Json::str(self.category.as_str())),
            ("verdict".into(), Json::str(self.verdict.as_str())),
            ("severity".into(), Json::str(self.severity.as_str())),
            ("title".into(), Json::str(&self.title)),
            ("explanation".into(), Json::str(&self.explanation)),
            (
                "evidence".into(),
                Json::Array(
                    self.evidence
                        .iter()
                        .map(|e| {
                            Json::Object(vec![
                                ("label".into(), Json::str(&e.label)),
                                ("text".into(), Json::str(&e.text)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "fix".into(),
                match &self.fix {
                    Some(f) => Json::Object(vec![
                        ("summary".into(), Json::str(&f.summary)),
                        ("dns_record".into(), opt(&f.dns_record)),
                        ("location".into(), opt(&f.location)),
                        ("command".into(), opt(&f.command)),
                        ("url".into(), opt(&f.url)),
                    ]),
                    None => Json::Null,
                },
            ),
            ("at".into(), Json::Int(self.at as i64)),
            ("duration_ms".into(), Json::Int(self.duration_ms as i64)),
        ])
    }

    pub fn from_json(v: &Json) -> Option<Check> {
        let s = |k: &str| v.get(k).and_then(Json::as_str).map(str::to_string);
        Some(Check {
            id: s("id")?,
            target: s("target"),
            scope: Scope::parse(&v.str_field("scope")),
            category: Category::parse(&v.str_field("category")),
            verdict: Verdict::parse(&v.str_field("verdict")),
            severity: Severity::parse(&v.str_field("severity")),
            title: v.str_field("title"),
            explanation: v.str_field("explanation"),
            evidence: v
                .get("evidence")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|e| Evidence {
                    label: e.str_field("label"),
                    text: e.str_field("text"),
                })
                .collect(),
            fix: v.get("fix").and_then(|f| match f {
                Json::Object(_) => Some(Fix {
                    summary: f.str_field("summary"),
                    dns_record: f
                        .get("dns_record")
                        .and_then(Json::as_str)
                        .map(str::to_string),
                    location: f.get("location").and_then(Json::as_str).map(str::to_string),
                    command: f.get("command").and_then(Json::as_str).map(str::to_string),
                    url: f.get("url").and_then(Json::as_str).map(str::to_string),
                }),
                _ => None,
            }),
            at: v.get("at").and_then(Json::as_i64).unwrap_or(0) as u64,
            duration_ms: v.get("duration_ms").and_then(Json::as_i64).unwrap_or(0) as u64,
        })
    }
}

/// What a run was asked to test.
#[derive(Debug, Clone, PartialEq)]
pub struct Inputs {
    pub address: String,
    pub domain: String,
    pub local_part: String,
    /// A sending IP to evaluate SPF and reputation for.
    pub ip: Option<IpAddr>,
    pub selector: Option<String>,
    /// Log days for the server audit.
    pub days: u32,
    pub audit: bool,
    pub force: bool,
    /// The end-user variant: the account the caller is limited to.
    pub user_scope: Option<String>,
}

impl Inputs {
    /// The key a cached report is looked up by (everything but `force`).
    pub fn cache_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.address.to_ascii_lowercase(),
            self.ip.map(|i| i.to_string()).unwrap_or_default(),
            self.selector.clone().unwrap_or_default(),
            self.days,
            self.audit,
            self.user_scope.clone().unwrap_or_default()
        )
    }
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("address".into(), Json::str(&self.address)),
            ("domain".into(), Json::str(&self.domain)),
            ("local_part".into(), Json::str(&self.local_part)),
            (
                "ip".into(),
                self.ip
                    .map(|i| Json::str(i.to_string()))
                    .unwrap_or(Json::Null),
            ),
            (
                "selector".into(),
                self.selector.clone().map(Json::Str).unwrap_or(Json::Null),
            ),
            ("days".into(), Json::Int(self.days as i64)),
            ("audit".into(), Json::Bool(self.audit)),
            (
                "user_scope".into(),
                self.user_scope.clone().map(Json::Str).unwrap_or(Json::Null),
            ),
        ])
    }
    pub fn from_json(v: &Json) -> Option<Inputs> {
        let address = v.get("address").and_then(Json::as_str)?.to_string();
        let (local_part, domain) = address.rsplit_once('@')?;
        Some(Inputs {
            address: address.clone(),
            domain: v
                .get("domain")
                .and_then(Json::as_str)
                .unwrap_or(domain)
                .to_string(),
            local_part: v
                .get("local_part")
                .and_then(Json::as_str)
                .unwrap_or(local_part)
                .to_string(),
            ip: v
                .get("ip")
                .and_then(Json::as_str)
                .and_then(|s| s.parse().ok()),
            selector: v.get("selector").and_then(Json::as_str).map(str::to_string),
            days: v.get("days").and_then(Json::as_i64).unwrap_or(2) as u32,
            audit: matches!(v.get("audit"), Some(Json::Bool(true))),
            force: false,
            user_scope: v
                .get("user_scope")
                .and_then(Json::as_str)
                .map(str::to_string),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub id: String,
    pub inputs: Inputs,
    pub started: u64,
    pub finished: Option<u64>,
    pub done: bool,
    /// Task ids the run intends to complete, for progress.
    pub planned: Vec<String>,
    pub checks: Vec<Check>,
    /// Which tools were missing, which resolver was used, etc.
    pub tool_notes: Vec<String>,
    pub cached: bool,
}

pub type Summary = BTreeMap<Scope, [usize; 5]>;

/// Index of a verdict in a summary row: fail, warn, unknown, pass, na.
pub fn summary_index(v: Verdict) -> usize {
    match v {
        Verdict::Fail => 0,
        Verdict::Warn => 1,
        Verdict::Unknown => 2,
        Verdict::Pass => 3,
        Verdict::NotApplicable => 4,
    }
}

impl Report {
    pub fn summary(&self) -> Summary {
        let mut m: Summary = BTreeMap::new();
        for c in &self.checks {
            m.entry(c.scope).or_insert([0; 5])[summary_index(c.verdict)] += 1;
        }
        m
    }
    /// Checks by attention order: fail, warn, unknown, pass, n/a — then by
    /// severity, then by id.
    pub fn sorted(&self) -> Vec<&Check> {
        let mut v: Vec<&Check> = self.checks.iter().collect();
        v.sort_by(|a, b| {
            a.verdict
                .cmp(&b.verdict)
                .then(a.severity.cmp(&b.severity))
                .then(a.id.cmp(&b.id))
        });
        v
    }
    pub fn has_failures(&self) -> bool {
        self.checks.iter().any(|c| c.verdict == Verdict::Fail)
    }

    pub fn to_json(&self) -> Json {
        let summary = Json::Object(
            self.summary()
                .into_iter()
                .map(|(scope, n)| {
                    (
                        scope.as_str().to_string(),
                        Json::Object(vec![
                            ("fail".into(), Json::Int(n[0] as i64)),
                            ("warn".into(), Json::Int(n[1] as i64)),
                            ("unknown".into(), Json::Int(n[2] as i64)),
                            ("pass".into(), Json::Int(n[3] as i64)),
                            ("na".into(), Json::Int(n[4] as i64)),
                        ]),
                    )
                })
                .collect(),
        );
        Json::Object(vec![
            ("id".into(), Json::str(&self.id)),
            ("inputs".into(), self.inputs.to_json()),
            ("started".into(), Json::Int(self.started as i64)),
            (
                "finished".into(),
                self.finished
                    .map(|f| Json::Int(f as i64))
                    .unwrap_or(Json::Null),
            ),
            ("done".into(), Json::Bool(self.done)),
            ("cached".into(), Json::Bool(self.cached)),
            (
                "planned".into(),
                Json::Array(self.planned.iter().map(Json::str).collect()),
            ),
            (
                "checks".into(),
                Json::Array(self.checks.iter().map(Check::to_json).collect()),
            ),
            ("summary".into(), summary),
            (
                "tool_notes".into(),
                Json::Array(self.tool_notes.iter().map(Json::str).collect()),
            ),
        ])
    }

    pub fn from_json(v: &Json) -> Option<Report> {
        Some(Report {
            id: v.get("id").and_then(Json::as_str)?.to_string(),
            inputs: Inputs::from_json(v.get("inputs")?)?,
            started: v.get("started").and_then(Json::as_i64).unwrap_or(0) as u64,
            finished: v.get("finished").and_then(Json::as_i64).map(|n| n as u64),
            done: matches!(v.get("done"), Some(Json::Bool(true))),
            planned: v
                .get("planned")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect(),
            checks: v
                .get("checks")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Check::from_json)
                .collect(),
            tool_notes: v
                .get("tool_notes")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect(),
            cached: matches!(v.get("cached"), Some(Json::Bool(true))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Report {
        Report {
            id: "abc".into(),
            inputs: Inputs {
                address: "User@Example.com".into(),
                domain: "example.com".into(),
                local_part: "User".into(),
                ip: Some("192.0.2.1".parse().unwrap()),
                selector: None,
                days: 2,
                audit: false,
                force: true,
                user_scope: None,
            },
            started: 10,
            finished: Some(20),
            done: true,
            planned: vec!["dns.mx".into(), "spf.record".into()],
            checks: vec![
                Check::new(
                    "spf.record",
                    Scope::Sending,
                    Category::Spf,
                    Verdict::Pass,
                    Severity::Info,
                    "SPF",
                    "one record",
                )
                .evidence("TXT", "v=spf1 -all"),
                Check::new(
                    "dns.mx",
                    Scope::Receiving,
                    Category::Dns,
                    Verdict::Fail,
                    Severity::Critical,
                    "MX",
                    "none",
                )
                .target("example.com")
                .fix(Fix {
                    summary: "add MX".into(),
                    dns_record: Some("example.com. IN MX 10 mail.example.com.".into()),
                    ..Default::default()
                }),
                Check::new(
                    "dns.ipv6",
                    Scope::Receiving,
                    Category::Dns,
                    Verdict::Warn,
                    Severity::Low,
                    "v6",
                    "no AAAA",
                ),
                Check::new(
                    "meta.mailbox",
                    Scope::Sending,
                    Category::Meta,
                    Verdict::Unknown,
                    Severity::Info,
                    "mailbox",
                    "cannot know",
                ),
                Check::new(
                    "dane.tlsa",
                    Scope::Receiving,
                    Category::TransportSecurity,
                    Verdict::NotApplicable,
                    Severity::Info,
                    "DANE",
                    "none",
                ),
            ],
            tool_notes: vec!["openssl 1.1.1k".into()],
            cached: false,
        }
    }

    #[test]
    fn round_trips_through_json_and_summarises() {
        let r = sample();
        let back = Report::from_json(&Json::parse(&r.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(back.checks, r.checks);
        assert_eq!(back.inputs.ip, r.inputs.ip);
        assert_eq!(back.planned, r.planned);
        assert!(back.done);
        let s = back.summary();
        assert_eq!(s[&Scope::Receiving], [1, 1, 0, 0, 1]);
        assert_eq!(s[&Scope::Sending], [0, 0, 1, 1, 0]);
        assert!(back.has_failures());
        let ids: Vec<&str> = back.sorted().iter().map(|c| c.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "dns.mx",
                "dns.ipv6",
                "meta.mailbox",
                "spf.record",
                "dane.tlsa"
            ]
        );
        assert!(r
            .inputs
            .cache_key()
            .starts_with("user@example.com|192.0.2.1|"));
    }

    #[test]
    fn json_has_the_documented_shape() {
        let j = sample().to_json().to_string();
        assert!(j.contains("\"verdict\":\"fail\""));
        assert!(j.contains("\"na\":1"));
        assert!(j.contains("\"dns_record\":\"example.com. IN MX 10 mail.example.com.\""));
        assert!(j.contains("\"fix\":null"));
        assert_eq!(Verdict::parse("bogus"), Verdict::Unknown);
        assert_eq!(Category::parse("transport").title(), "Transport security");
    }
}
