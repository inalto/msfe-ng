//! Account DNS: SPF, DKIM and DMARC for every domain hosted on this server.
//!
//! One scan asks cPanel's own validators (`validate_current_spfs`,
//! `validate_current_dkims`, `has_local_authority`) about every account
//! domain, then adds what they do not check — DMARC, the SPF lookup count and
//! `all` qualifier, DKIM key strength — through this crate's own resolvers and
//! parsers. Repairs run cPanel's installers (`install_spf_records`,
//! `ensure_dkim_keys_exist` + `enable_dkim`, `addzonerecord`), never a hand
//! edit of a zone file; when the zone is not hosted here the row carries the
//! record to publish elsewhere instead of a fix. Everything except `fix` is
//! read-only, and under `MSFE_NG_CPANEL_ROOT` every command comes from the
//! fixture tree (`_cmd/<name>.txt`), so the whole path is testable.
//!
//! Deviations from `docs/superpowers/specs/2026-09-22-account-dns-design.md`,
//! all of them additive and none visible in the JSON contract:
//!
//! * `whmapi1` runs through a local helper, not `Cp::whmapi1`, because that one
//!   hard-codes a 15 s timeout and the validators need 120 s. Fixture mode is
//!   unchanged (`Cp::read` of `_cmd/<name>.txt`).
//! * The validator parsers return `Result<_, String>` so a failed call's
//!   `metadata.reason` reaches `Scan::errors`; `validate` likewise returns its
//!   errors next to the rows.
//! * `spf_notes` / `dkim_notes` return `Vec<Note>` (level + text) because a
//!   Warn-level note has to raise the row's level; `Check::notes` stays a list
//!   of strings.
//! * `classify_spf` / `classify_dkim` / `dmarc_check` also take the domain and
//!   its `Zone`: `fixable`, `fix_note` and the zone-file form of `suggested`
//!   cannot be derived without them. `classify_dkim` takes the suggested
//!   record instead of a `key_exists` flag (`None` *is* "no key here").
//! * `Check` carries `suggested_value` beside `suggested`: the bare TXT value
//!   is what `fix` accepts as `record`, the zone-file line is what the UI
//!   copies. `fix` also accepts either form.
//! * `dkim_suggested` takes the `Cp` (it may have to read the key file) and
//!   returns `Option<String>`, as the design's own prose says.
//! * `fix` fails with a `FixError` rather than a bare string, so a refusal can
//!   hand back the record to publish elsewhere in `actions`.
//! * `StartError::Invalid` exists so the API can answer 400 on a bad filter.

use crate::config::Config;
use crate::cpaudit::{self, Cp, DomainKind};
use crate::delivery::now_secs;
use crate::dns::Client;
use crate::json::Json;
use crate::service::run_with_timeout;
use crate::{dkim, dmarc, spf};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

/// Domains per `whmapi1` validator call. The validators resolve every domain,
/// so a chunk is slow; smaller chunks keep the progressive table moving.
const CHUNK: usize = 25;
/// A validator chunk resolves 25 domains three times over.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(120);
/// One installer call.
const FIX_TIMEOUT: Duration = Duration::from_secs(60);
/// The TTL cPanel writes for the records this module suggests.
const TTL: u32 = 14400;
/// Cap on a record the admin hands us.
const MAX_RECORD: usize = 450;

// ---- the model ----------------------------------------------------------------

/// What cPanel calls the domain in the account's userdata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Main,
    Addon,
    Parked,
    Sub,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Main => "main",
            Kind::Addon => "addon",
            Kind::Parked => "parked",
            Kind::Sub => "sub",
        }
    }
    pub fn parse(s: &str) -> Kind {
        match s {
            "addon" => Kind::Addon,
            "parked" => Kind::Parked,
            "sub" => Kind::Sub,
            _ => Kind::Main,
        }
    }
}

/// The verdict on one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Ok,
    Missing,
    Mismatch,
    /// No DKIM key for the domain on this server.
    NoKey,
    /// Published and matching, but the key is under 2048 bits.
    Weak,
    /// Published but broken (two records, a syntax error).
    Error,
    Unknown,
    NotApplicable,
}

impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Ok => "ok",
            State::Missing => "missing",
            State::Mismatch => "mismatch",
            State::NoKey => "no_key",
            State::Weak => "weak",
            State::Error => "error",
            State::Unknown => "unknown",
            State::NotApplicable => "na",
        }
    }
    pub fn parse(s: &str) -> State {
        match s {
            "ok" => State::Ok,
            "missing" => State::Missing,
            "mismatch" => State::Mismatch,
            "no_key" => State::NoKey,
            "weak" => State::Weak,
            "error" => State::Error,
            "na" => State::NotApplicable,
            _ => State::Unknown,
        }
    }
}

/// The colour of a cell or a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Fail,
    Warn,
    Ok,
    Unknown,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Fail => "fail",
            Level::Warn => "warn",
            Level::Ok => "ok",
            Level::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> Level {
        match s {
            "fail" => Level::Fail,
            "warn" => Level::Warn,
            "ok" => Level::Ok,
            _ => Level::Unknown,
        }
    }
    /// Fail > Warn > Unknown > Ok, for "the worst of these".
    fn rank(&self) -> u8 {
        match self {
            Level::Fail => 3,
            Level::Warn => 2,
            Level::Unknown => 1,
            Level::Ok => 0,
        }
    }
    fn worst(self, other: Level) -> Level {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// An extra finding about a record, with the level it deserves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub level: Level,
    pub text: String,
}

impl Note {
    fn new(level: Level, text: impl Into<String>) -> Note {
        Note {
            level,
            text: text.into(),
        }
    }
}

/// One domain of one cPanel account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    pub domain: String,
    pub user: String,
    pub kind: Kind,
    /// Which of cPanel's routing files lists it.
    pub mail: DomainKind,
}

/// Where the domain's zone lives, as `has_local_authority` sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Zone {
    /// The local zone holding the name (the parent zone for a subdomain);
    /// `None` when this server has no zone for it.
    pub name: Option<String>,
    pub local_authority: bool,
    pub nameservers: Vec<String>,
}

impl Zone {
    /// The DNS column: `here`, `copy here, NS elsewhere` or `elsewhere`.
    pub fn summary(&self) -> &'static str {
        match (self.name.is_some(), self.local_authority) {
            (true, true) => "here",
            (true, false) => "copy here, NS elsewhere",
            _ => "elsewhere",
        }
    }
}

/// The verdict on one record of one domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub state: State,
    pub level: Level,
    /// cPanel's own word (`VALID`, `NOPUB`, …); empty for our own checks.
    pub raw_state: String,
    /// The table cell, short enough to read at a glance.
    pub summary: String,
    /// One paragraph for the expanded row.
    pub detail: String,
    /// The records seen in DNS.
    pub current: Vec<String>,
    /// What cPanel expects to find (an SPF mechanism, a DKIM record).
    pub expected: Option<String>,
    /// The record to publish, zone-file form: `name. 14400 IN TXT "…"`.
    pub suggested: Option<String>,
    /// The same record's TXT value alone — what `fix` takes as `record`.
    pub suggested_value: Option<String>,
    /// An Apply button makes sense.
    pub fixable: bool,
    /// Why a fix is limited or impossible.
    pub fix_note: Option<String>,
    pub notes: Vec<String>,
}

impl Default for Check {
    fn default() -> Check {
        Check {
            state: State::Unknown,
            level: Level::Unknown,
            raw_state: String::new(),
            summary: String::new(),
            detail: String::new(),
            current: Vec::new(),
            expected: None,
            suggested: None,
            suggested_value: None,
            fixable: false,
            fix_note: None,
            notes: Vec::new(),
        }
    }
}

impl Check {
    /// An unknown verdict with the reason in both texts.
    pub fn unknown(why: impl Into<String>) -> Check {
        let why = why.into();
        Check {
            state: State::Unknown,
            level: Level::Unknown,
            summary: "unknown".into(),
            detail: why,
            ..Check::default()
        }
    }
    fn with_notes(mut self, notes: &[Note]) -> Check {
        for n in notes {
            self.level = self.level.worst(n.level);
            self.notes.push(n.text.clone());
        }
        self
    }
    pub fn to_json(&self) -> Json {
        let opt = |o: &Option<String>| o.clone().map(Json::Str).unwrap_or(Json::Null);
        Json::Object(vec![
            ("state".into(), Json::str(self.state.as_str())),
            ("level".into(), Json::str(self.level.as_str())),
            ("raw_state".into(), Json::str(&self.raw_state)),
            ("summary".into(), Json::str(&self.summary)),
            ("detail".into(), Json::str(&self.detail)),
            (
                "current".into(),
                Json::Array(self.current.iter().map(Json::str).collect()),
            ),
            ("expected".into(), opt(&self.expected)),
            ("suggested".into(), opt(&self.suggested)),
            ("suggested_value".into(), opt(&self.suggested_value)),
            ("fixable".into(), Json::Bool(self.fixable)),
            ("fix_note".into(), opt(&self.fix_note)),
            (
                "notes".into(),
                Json::Array(self.notes.iter().map(Json::str).collect()),
            ),
        ])
    }
    pub fn from_json(v: &Json) -> Check {
        let strs = |key: &str| {
            v.get(key)
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect::<Vec<String>>()
        };
        let opt = |key: &str| v.get(key).and_then(Json::as_str).map(str::to_string);
        Check {
            state: State::parse(&v.str_field("state")),
            level: Level::parse(&v.str_field("level")),
            raw_state: v.str_field("raw_state"),
            summary: v.str_field("summary"),
            detail: v.str_field("detail"),
            current: strs("current"),
            expected: opt("expected"),
            suggested: opt("suggested"),
            suggested_value: opt("suggested_value"),
            fixable: matches!(v.get("fixable"), Some(Json::Bool(true))),
            fix_note: opt("fix_note"),
            notes: strs("notes"),
        }
    }
}

/// One line of the table: a domain, where its zone lives, its three records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub domain: Domain,
    pub zone: Zone,
    pub spf: Check,
    pub dkim: Check,
    pub dmarc: Check,
    pub level: Level,
    pub checked_at: u64,
}

impl Row {
    /// The row's fields are flat (`domain`, `user`, `kind`, `mail`) so the UI
    /// reads `row.domain` as a name.
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("domain".into(), Json::str(&self.domain.domain)),
            ("user".into(), Json::str(&self.domain.user)),
            ("kind".into(), Json::str(self.domain.kind.as_str())),
            ("mail".into(), Json::str(self.domain.mail.as_str())),
            (
                "zone".into(),
                Json::Object(vec![
                    (
                        "name".into(),
                        self.zone.name.clone().map(Json::Str).unwrap_or(Json::Null),
                    ),
                    (
                        "local_authority".into(),
                        Json::Bool(self.zone.local_authority),
                    ),
                    (
                        "nameservers".into(),
                        Json::Array(self.zone.nameservers.iter().map(Json::str).collect()),
                    ),
                    ("summary".into(), Json::str(self.zone.summary())),
                ]),
            ),
            ("spf".into(), self.spf.to_json()),
            ("dkim".into(), self.dkim.to_json()),
            ("dmarc".into(), self.dmarc.to_json()),
            ("level".into(), Json::str(self.level.as_str())),
            ("checked_at".into(), Json::Int(self.checked_at as i64)),
        ])
    }
    pub fn from_json(v: &Json) -> Row {
        let z = v.get("zone");
        let zone = Zone {
            name: z
                .and_then(|z| z.get("name"))
                .and_then(Json::as_str)
                .map(str::to_string),
            local_authority: matches!(
                z.and_then(|z| z.get("local_authority")),
                Some(Json::Bool(true))
            ),
            nameservers: z
                .and_then(|z| z.get("nameservers"))
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect(),
        };
        let check = |key: &str| v.get(key).map(Check::from_json).unwrap_or_default();
        Row {
            domain: Domain {
                domain: v.str_field("domain"),
                user: v.str_field("user"),
                kind: Kind::parse(&v.str_field("kind")),
                mail: mail_kind(&v.str_field("mail")),
            },
            zone,
            spf: check("spf"),
            dkim: check("dkim"),
            dmarc: check("dmarc"),
            level: Level::parse(&v.str_field("level")),
            checked_at: v.get("checked_at").and_then(Json::as_i64).unwrap_or(0) as u64,
        }
    }
}

/// `DomainKind` from the string `DomainKind::as_str` writes.
fn mail_kind(s: &str) -> DomainKind {
    match s {
        "local" => DomainKind::Local,
        "remote" => DomainKind::Remote,
        "secondary MX" => DomainKind::SecondaryMx,
        _ => DomainKind::Unlisted,
    }
}

/// One run over the server's domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub id: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub done: bool,
    /// Domains the scan intends to check (rows arrive progressively).
    pub total: usize,
    pub rows: Vec<Row>,
    pub errors: Vec<String>,
    /// The control panel's display name.
    pub panel: String,
    pub supported: bool,
}

impl Scan {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".into(), Json::str(&self.id)),
            ("started".into(), Json::Int(self.started as i64)),
            (
                "finished".into(),
                self.finished
                    .map(|t| Json::Int(t as i64))
                    .unwrap_or(Json::Null),
            ),
            ("done".into(), Json::Bool(self.done)),
            ("total".into(), Json::Int(self.total as i64)),
            (
                "rows".into(),
                Json::Array(self.rows.iter().map(Row::to_json).collect()),
            ),
            (
                "errors".into(),
                Json::Array(self.errors.iter().map(Json::str).collect()),
            ),
            ("panel".into(), Json::str(&self.panel)),
            ("supported".into(), Json::Bool(self.supported)),
        ])
    }
    pub fn from_json(v: &Json) -> Scan {
        Scan {
            id: v.str_field("id"),
            started: v.get("started").and_then(Json::as_i64).unwrap_or(0) as u64,
            finished: v.get("finished").and_then(Json::as_i64).map(|t| t as u64),
            done: matches!(v.get("done"), Some(Json::Bool(true))),
            total: v.get("total").and_then(Json::as_i64).unwrap_or(0) as usize,
            rows: v
                .get("rows")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(Row::from_json)
                .collect(),
            errors: v
                .get("errors")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect(),
            panel: v.str_field("panel"),
            supported: matches!(v.get("supported"), Some(Json::Bool(true))),
        }
    }
}

// ---- the host -----------------------------------------------------------------

/// Whether this feature can run here: cPanel, or a fixture tree that looks
/// like one.
pub fn supported(cp: &Cp) -> bool {
    if cp.live() {
        cp.exists("/usr/local/cpanel/version")
    } else {
        cp.exists("/etc/userdomains")
    }
}

/// The control panel's name, for the "needs cPanel (this host: …)" message.
pub fn panel_name(cp: &Cp) -> String {
    if supported(cp) {
        "cPanel / WHM".to_string()
    } else {
        crate::panel::detect_panel().display_name().to_string()
    }
}

/// `whmapi1 --output=json <func> <args…>` with our own timeout (`Cp::whmapi1`
/// hard-codes 15 s, too short for a validator chunk). In fixture mode the
/// output comes from `_cmd/<name>.txt`.
fn whmapi1(
    cp: &Cp,
    name: &str,
    func: &str,
    args: &[String],
    timeout: Duration,
) -> Result<Json, String> {
    let text = if cp.live() {
        let mut c = Command::new("whmapi1");
        c.arg("--output=json").arg(func).args(args);
        let out = run_with_timeout(&mut c, timeout).map_err(|e| format!("whmapi1: {e}"))?;
        if out.timed_out {
            return Err(format!("whmapi1 {func} timed out"));
        }
        format!("{}{}", out.stdout, out.stderr)
    } else {
        cp.read(&format!("_cmd/{name}.txt"))
            .ok_or_else(|| format!("no fixture _cmd/{name}.txt"))?
    };
    Json::parse(&text).map_err(|e| format!("whmapi1 {func}: unreadable output ({e})"))
}

/// `metadata.result == 1` → cPanel's `reason`, else the reason as the error.
fn meta_ok(v: &Json) -> Result<String, String> {
    let m = v.get("metadata");
    let reason = m
        .map(|m| m.str_field("reason"))
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| "no reason given".to_string());
    let result = m.and_then(|m| m.get("result")).map(|r| match r {
        Json::Str(s) => s == "1",
        other => other.as_i64() == Some(1),
    });
    match result {
        Some(true) => Ok(reason),
        Some(false) => Err(reason),
        None => Err("no metadata in the reply".into()),
    }
}

// ---- the account's domains ----------------------------------------------------

/// What `/var/cpanel/userdata/<user>/main` says about an account's domains.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserdataMain {
    pub main: Option<String>,
    /// (addon domain, the service subdomain it is served from).
    pub addon: Vec<(String, String)>,
    pub parked: Vec<String>,
    pub subs: Vec<String>,
}

/// Parse the YAML-ish `main` file: top-level `key:` lines open a section,
/// indented `- name` or `name: value` lines fill it. No YAML library.
pub fn parse_userdata_main(text: &str) -> UserdataMain {
    let mut u = UserdataMain::default();
    let mut section = String::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        let body = line.trim();
        if !indented {
            let Some((key, value)) = body.split_once(':') else {
                continue;
            };
            let (key, value) = (key.trim(), value.trim());
            section = key.to_string();
            if key == "main_domain" && !value.is_empty() {
                u.main = Some(value.to_ascii_lowercase());
            }
            continue;
        }
        let value = match body.strip_prefix('-') {
            Some(v) => v.trim().to_ascii_lowercase(),
            None => {
                // `addon.example.net: addon.example.com`
                let (k, v) = body.split_once(':').unwrap_or((body, ""));
                let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
                if section == "addon_domains" {
                    u.addon.push((k, v));
                    continue;
                }
                k
            }
        };
        if value.is_empty() {
            continue;
        }
        match section.as_str() {
            "parked_domains" => u.parked.push(value),
            "sub_domains" => u.subs.push(value),
            "addon_domains" => u.addon.push((value, String::new())),
            _ => {}
        }
    }
    u
}

/// Every account domain of the server, sorted by account then main → addon →
/// parked → sub then name. The server's own host name (owned by `nobody`) and
/// the `*` catch-all are left out.
pub fn list_domains(cp: &Cp) -> Vec<Domain> {
    let text = cp.read("/etc/userdomains").unwrap_or_default();
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let Some((domain, user)) = line.split_once(':') else {
            continue;
        };
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let user = user.trim().to_string();
        if domain.starts_with('*')
            || user.is_empty()
            || user == "nobody"
            || !crate::users::valid_username(&user)
            || !crate::netguard::valid_hostname(&domain)
        {
            continue;
        }
        if !pairs.iter().any(|(d, _)| *d == domain) {
            pairs.push((domain, user));
        }
    }
    let mut userdata: HashMap<String, UserdataMain> = HashMap::new();
    let mut out: Vec<Domain> = Vec::new();
    for (domain, user) in &pairs {
        let u = userdata.entry(user.clone()).or_insert_with(|| {
            parse_userdata_main(
                &cp.read(&format!("/var/cpanel/userdata/{user}/main"))
                    .unwrap_or_default(),
            )
        });
        let kind = if u.main.as_deref() == Some(domain.as_str()) {
            Kind::Main
        } else if u.addon.iter().any(|(a, _)| a == domain) {
            Kind::Addon
        } else if u.parked.iter().any(|p| p == domain) {
            Kind::Parked
        } else if u.subs.iter().any(|s| s == domain)
            || pairs
                .iter()
                // not in userdata at all: a proper subdomain of a domain of
                // the same account is a subdomain, anything else a main domain
                .any(|(d, o)| o == user && d != domain && domain.ends_with(&format!(".{d}")))
        {
            Kind::Sub
        } else {
            Kind::Main
        };
        out.push(Domain {
            domain: domain.clone(),
            user: user.clone(),
            kind,
            mail: cpaudit::domain_kind(cp, domain),
        });
    }
    out.sort_by(|a, b| {
        a.user
            .cmp(&b.user)
            .then(a.kind.cmp(&b.kind))
            .then(a.domain.cmp(&b.domain))
    });
    out
}

// ---- the validators -----------------------------------------------------------

/// One entry of `validate_current_spfs`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpfResult {
    /// cPanel's word: `VALID`, `MISSING`, `MISMATCH`, … (empty when absent).
    pub state: String,
    /// The mechanism cPanel wants to see, e.g. `ip4:192.0.2.10`.
    pub expected: String,
    pub ip: Option<IpAddr>,
    pub records: Vec<String>,
    /// cPanel's explanation for a record that does not pass (`INVALID`).
    pub reason: Option<String>,
    pub error: Option<String>,
}

/// One entry of `validate_current_dkims`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DkimResult {
    /// `VALID`, `MISSING`, `MISMATCH`, `NOPUB`, … (empty when absent).
    pub state: String,
    /// The record this server's key would publish.
    pub expected: String,
    pub records: Vec<String>,
    pub error: Option<String>,
}

/// `payload[].records[].current`, skipping empty strings.
fn current_records(entry: &Json) -> Vec<String> {
    entry
        .get("records")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .map(|r| r.str_field("current"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn error_field(entry: &Json) -> Option<String> {
    entry
        .get("error")
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The `data.payload[]` of a validator reply, or cPanel's reason.
fn payload<'a>(v: &'a Json, func: &str) -> Result<&'a [Json], String> {
    meta_ok(v).map_err(|r| format!("{func}: {r}"))?;
    v.get("data")
        .and_then(|d| d.get("payload"))
        .and_then(Json::as_array)
        .ok_or_else(|| format!("{func}: no payload in the reply"))
}

/// `validate_current_spfs` → (domain, result) pairs.
pub fn parse_validate_spfs(v: &Json) -> Result<Vec<(String, SpfResult)>, String> {
    let mut out = Vec::new();
    for e in payload(v, "validate_current_spfs")? {
        let domain = e.str_field("domain").trim().to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        out.push((
            domain,
            SpfResult {
                state: e.str_field("state").trim().to_ascii_uppercase(),
                expected: e.str_field("expected").trim().to_string(),
                ip: e
                    .get("ip_address")
                    .and_then(Json::as_str)
                    .and_then(|s| s.trim().parse().ok()),
                records: current_records(e),
                reason: record_reason(e),
                error: error_field(e),
            },
        ));
    }
    Ok(out)
}

/// The first `records[].reason` of a validator entry, if any.
fn record_reason(e: &Json) -> Option<String> {
    e.get("records")
        .and_then(Json::as_array)?
        .iter()
        .filter_map(|r| r.get("reason").and_then(Json::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

/// `validate_current_dkims` → (domain, result) pairs; the reply's `domain` is
/// prefixed `default._domainkey.` and the prefix is stripped here.
pub fn parse_validate_dkims(v: &Json) -> Result<Vec<(String, DkimResult)>, String> {
    let mut out = Vec::new();
    for e in payload(v, "validate_current_dkims")? {
        let raw = e.str_field("domain").trim().to_ascii_lowercase();
        let domain = raw
            .strip_prefix("default._domainkey.")
            .unwrap_or(&raw)
            .to_string();
        if domain.is_empty() {
            continue;
        }
        out.push((
            domain,
            DkimResult {
                state: e.str_field("state").trim().to_ascii_uppercase(),
                expected: e.str_field("expected").trim().to_string(),
                records: current_records(e),
                error: error_field(e),
            },
        ));
    }
    Ok(out)
}

/// `has_local_authority` → (domain, zone) pairs from `data.records[]`.
pub fn parse_local_authority(v: &Json) -> Result<Vec<(String, Zone)>, String> {
    meta_ok(v).map_err(|r| format!("has_local_authority: {r}"))?;
    let recs = v
        .get("data")
        .and_then(|d| d.get("records"))
        .and_then(Json::as_array)
        .ok_or("has_local_authority: no records in the reply")?;
    let mut out = Vec::new();
    for e in recs {
        let domain = e.str_field("domain").trim().to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        let name = e
            .get("zone")
            .and_then(Json::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('.').to_ascii_lowercase());
        let local_authority = match e.get("local_authority") {
            Some(Json::Bool(b)) => *b,
            Some(other) => other.as_i64().unwrap_or(0) == 1,
            None => false,
        };
        out.push((
            domain,
            Zone {
                name,
                local_authority,
                nameservers: e
                    .get("nameservers")
                    .and_then(Json::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(Json::as_str)
                    .map(|s| s.trim().trim_end_matches('.').to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
            },
        ));
    }
    Ok(out)
}

// ---- suggested records --------------------------------------------------------

/// A zone-file line for a TXT record.
fn txt_line(name: &str, value: &str) -> String {
    format!("{}. {TTL} IN TXT \"{value}\"", name.trim_end_matches('.'))
}

/// The `"…"` value of a zone-file TXT line, or the text itself when it is
/// already a bare record. Lets `fix` accept either form.
pub fn txt_value(record: &str) -> String {
    let r = record.trim();
    match (r.find('"'), r.rfind('"')) {
        (Some(a), Some(b)) if b > a => r[a + 1..b].trim().to_string(),
        _ => r.to_string(),
    }
}

/// Is the token an `all` mechanism, with or without a qualifier?
fn is_all_term(tok: &str) -> bool {
    tok.strip_prefix(['+', '-', '~', '?'])
        .unwrap_or(tok)
        .eq_ignore_ascii_case("all")
}

/// The mechanism that must appear in the record: cPanel's `expected`, else one
/// built from the server's outgoing address.
fn spf_mechanism(expected: &str, out_ip: Option<IpAddr>) -> String {
    let e = expected.trim();
    if !e.is_empty() {
        return e.to_string();
    }
    match out_ip {
        Some(IpAddr::V4(ip)) => format!("ip4:{ip}"),
        Some(IpAddr::V6(ip)) => format!("ip6:{ip}"),
        None => String::new(),
    }
}

/// The SPF record to publish: cPanel's default shape when there is none, else
/// the existing record(s) with the missing mechanism added before `all`.
/// Never produces two `v=spf1` or two `all` terms.
pub fn suggest_spf(current: &[String], expected: &str, out_ip: Option<IpAddr>) -> String {
    let mech = spf_mechanism(expected, out_ip);
    let records: Vec<&String> = current.iter().filter(|r| !r.trim().is_empty()).collect();
    if records.is_empty() {
        return match mech.is_empty() {
            true => "v=spf1 +mx +a ~all".to_string(),
            false => format!("v=spf1 +mx +a {mech} ~all"),
        };
    }
    let mut terms: Vec<String> = Vec::new();
    let mut modifiers: Vec<String> = Vec::new();
    let mut all: Option<String> = None;
    let push = |list: &mut Vec<String>, tok: &str| {
        if !list.iter().any(|t| t.eq_ignore_ascii_case(tok)) {
            list.push(tok.to_string());
        }
    };
    for rec in &records {
        for (i, tok) in rec.split_whitespace().enumerate() {
            if i == 0 && tok.eq_ignore_ascii_case("v=spf1") {
                continue;
            }
            if is_all_term(tok) {
                if all.is_none() {
                    all = Some(tok.to_ascii_lowercase());
                }
            } else if tok.contains('=') {
                push(&mut modifiers, tok);
            } else {
                push(&mut terms, tok);
            }
        }
    }
    if !mech.is_empty() && !terms.iter().any(|t| t.eq_ignore_ascii_case(&mech)) {
        terms.push(mech);
    }
    let redirects = modifiers
        .iter()
        .any(|m| m.to_ascii_lowercase().starts_with("redirect="));
    let mut out = vec!["v=spf1".to_string()];
    out.extend(terms);
    out.extend(modifiers);
    match all {
        Some(a) => out.push(a),
        // a redirect= is only consulted when no mechanism matched and the
        // record has no `all`: adding one would disable it.
        None if !redirects => out.push("~all".into()),
        None => {}
    }
    out.join(" ")
}

/// The DKIM record this server's key would publish, zone-file form: from
/// cPanel's `expected`, else from `/var/cpanel/domain_keys/public/<domain>`.
/// `None` when there is no key here.
pub fn dkim_suggested(cp: &Cp, domain: &str, expected: &str) -> Option<String> {
    let value = dkim_value(cp, domain, expected)?;
    Some(txt_line(&format!("default._domainkey.{domain}"), &value))
}

/// The bare `v=DKIM1; …` value behind [`dkim_suggested`].
pub fn dkim_value(cp: &Cp, domain: &str, expected: &str) -> Option<String> {
    let e = txt_value(expected);
    if e.to_ascii_lowercase().contains("v=dkim1") {
        return Some(e);
    }
    let pem = cp.read(&format!("/var/cpanel/domain_keys/public/{domain}"))?;
    let der = cpaudit::pem_to_der_b64(&pem);
    if der.is_empty() {
        return None;
    }
    Some(format!("v=DKIM1; k=rsa; p={der}"))
}

/// The first DMARC record to publish: monitor-only, reports to postmaster.
/// The repair modal lets the admin edit it before it is installed.
pub fn suggest_dmarc(domain: &str) -> String {
    txt_line(&format!("_dmarc.{domain}"), &suggest_dmarc_value(domain))
}

/// The bare value behind [`suggest_dmarc`].
pub fn suggest_dmarc_value(domain: &str) -> String {
    format!("v=DMARC1; p=none; rua=mailto:postmaster@{domain}")
}

// ---- our own findings ---------------------------------------------------------

/// What cPanel's SPF validator does not look at: syntax, the `all` qualifier,
/// the ten-lookup limit, `ptr`.
pub fn spf_notes(client: &Client, domain: &str, record: &str) -> Vec<Note> {
    let mut notes = Vec::new();
    let rec = match spf::parse(record) {
        Ok(r) => r,
        Err(e) => {
            notes.push(Note::new(Level::Fail, format!("syntax: {e}")));
            return notes;
        }
    };
    match rec.all_qualifier() {
        Some(spf::Qualifier::Pass) => notes.push(Note::new(
            Level::Fail,
            "+all authorizes every host on the internet to send as this domain",
        )),
        Some(spf::Qualifier::Neutral) => notes.push(Note::new(
            Level::Warn,
            "?all is neutral: receivers learn nothing from the record",
        )),
        None if rec.redirect.is_none() => notes.push(Note::new(
            Level::Warn,
            "no all term: unlisted senders are treated as neutral",
        )),
        _ => {}
    }
    let walk = spf::walk(client, domain);
    if walk.lookups > 10 {
        notes.push(Note::new(
            Level::Fail,
            format!(
                "SPF needs {} DNS lookups (limit 10): receivers return permerror",
                walk.lookups
            ),
        ));
    } else if walk.lookups >= 9 {
        notes.push(Note::new(
            Level::Warn,
            format!("SPF uses {} of the 10 permitted DNS lookups", walk.lookups),
        ));
    }
    if walk.uses_ptr || rec.terms.iter().any(|t| matches!(t.m, spf::Mech::Ptr(_))) {
        notes.push(Note::new(
            Level::Warn,
            "ptr is deprecated (RFC 7208) and ignored by several receivers",
        ));
    }
    notes
}

/// What cPanel's DKIM validator does not look at: key strength, test mode, a
/// revoked key.
pub fn dkim_notes(record: &str) -> Vec<Note> {
    let mut notes = Vec::new();
    if record.trim().is_empty() {
        return notes;
    }
    let key = dkim::parse_record("default", record);
    if key.revoked {
        notes.push(Note::new(
            Level::Fail,
            "the key is revoked (p= is empty): every signature fails",
        ));
    } else if let Some(bits) = key.bits {
        if bits < 1024 {
            notes.push(Note::new(
                Level::Fail,
                format!("{bits}-bit key: too weak, regenerate with 2048 bits"),
            ));
        } else if bits < 2048 {
            notes.push(Note::new(
                Level::Warn,
                format!("{bits}-bit key — regenerate with 2048 bits"),
            ));
        }
    }
    if key.t_testing {
        notes.push(Note::new(
            Level::Warn,
            "t=y marks the key as a test: receivers ignore the signature's result",
        ));
    }
    for p in &key.problems {
        notes.push(Note::new(Level::Warn, p.clone()));
    }
    notes
}

/// The DKIM key size of a published record, when it parses.
fn record_bits(records: &[String]) -> Option<u32> {
    dkim::parse_record("default", records.first()?).bits
}

// ---- classification -----------------------------------------------------------

/// Why a fix is limited or impossible, given where the zone lives.
/// `generates_key` is set for the DKIM case, where cPanel still does half the
/// work without a local zone.
fn fix_note(zone: &Zone, generates_key: bool) -> Option<String> {
    let ns = if zone.nameservers.is_empty() {
        "not this server".to_string()
    } else {
        zone.nameservers.join(", ")
    };
    match (zone.name.is_some(), zone.local_authority) {
        (true, true) => None,
        (true, false) => Some(format!(
            "this server holds a copy of the zone but the domain's name servers are {ns}: \
             cPanel updates the local copy; publish the record at those servers too unless \
             they replicate from here"
        )),
        _ if generates_key => Some(format!(
            "the key is generated on this server, but DNS for this domain is hosted \
             elsewhere ({ns}) — publish the record there"
        )),
        _ => Some(format!(
            "DNS for this domain is hosted elsewhere ({ns}) — publish the record there"
        )),
    }
}

/// Fill `fixable` and `fix_note`: an installer needs a local zone, except DKIM
/// key generation, which is useful on its own.
fn set_fixability(c: &mut Check, zone: &Zone, key_generation: bool) {
    let needs_fix = matches!(c.state, State::Missing | State::Mismatch | State::NoKey);
    if !needs_fix {
        c.fixable = false;
        c.fix_note = None;
        if matches!(c.state, State::Weak) {
            c.fix_note = Some(
                "a weak key is replaced by regenerating it in WHM → Email Deliverability".into(),
            );
        }
        return;
    }
    c.fixable = zone.name.is_some() || (key_generation && c.state == State::NoKey);
    c.fix_note = fix_note(zone, key_generation && c.state == State::NoKey);
}

/// cPanel's SPF verdict plus our own notes as one cell.
pub fn classify_spf(domain: &str, zone: &Zone, res: &SpfResult, notes: &[Note]) -> Check {
    let expected = (!res.expected.is_empty()).then(|| res.expected.clone());
    let mut c = match res.state.as_str() {
        "VALID" => Check {
            state: State::Ok,
            level: Level::Ok,
            summary: "ok".into(),
            detail: format!(
                "cPanel's validator finds this server's sending address authorized by the \
                 SPF record of {domain}."
            ),
            ..Check::default()
        },
        "MISSING" => Check {
            state: State::Missing,
            level: Level::Fail,
            summary: "not published".into(),
            detail: format!(
                "No SPF record was found for {domain}: receivers cannot tell that this \
                 server is allowed to send for it, and strict receivers reject the mail."
            ),
            ..Check::default()
        },
        // MISMATCH: the expected mechanism is absent; INVALID: cPanel evaluated
        // the record for this server's address and it did not pass.
        "MISMATCH" | "INVALID" => Check {
            state: State::Mismatch,
            level: Level::Fail,
            summary: "server IP not authorized".into(),
            detail: format!(
                "{domain} publishes an SPF record, but it does not authorize this server \
                 ({}): mail sent from here fails SPF.{}",
                if res.expected.is_empty() {
                    "the mechanism cPanel expects is missing"
                } else {
                    res.expected.as_str()
                },
                res.reason
                    .as_deref()
                    .map(|r| format!(" cPanel: {r}"))
                    .unwrap_or_default()
            ),
            ..Check::default()
        },
        other => {
            let why = match (&res.error, other.is_empty()) {
                (Some(e), _) => format!("cPanel could not check the SPF record: {e}"),
                (None, true) => "cPanel returned no SPF state for this domain".to_string(),
                (None, false) => format!("cPanel returned the SPF state {other}"),
            };
            Check::unknown(why)
        }
    };
    c.raw_state = res.state.clone();
    c.current = res.records.clone();
    c.expected = expected;
    if matches!(c.state, State::Missing | State::Mismatch) {
        let value = suggest_spf(&res.records, &res.expected, res.ip);
        c.suggested = Some(txt_line(domain, &value));
        c.suggested_value = Some(value);
    }
    set_fixability(&mut c, zone, false);
    c.with_notes(notes)
}

/// cPanel's DKIM verdict plus our own notes as one cell. `suggested` is the
/// zone-file record this server's key would publish — `None` means there is no
/// key here yet.
pub fn classify_dkim(
    domain: &str,
    zone: &Zone,
    res: &DkimResult,
    notes: &[Note],
    suggested: Option<String>,
) -> Check {
    let mut c = match res.state.as_str() {
        "VALID" => match record_bits(&res.records) {
            Some(bits) if bits < 2048 => Check {
                state: State::Weak,
                level: Level::Warn,
                summary: format!("{bits}-bit key"),
                detail: format!(
                    "The published key matches this server's, but {bits} bits is below the \
                     2048 bits receivers now expect."
                ),
                ..Check::default()
            },
            _ => Check {
                state: State::Ok,
                level: Level::Ok,
                summary: "ok".into(),
                detail: format!(
                    "The DKIM record at default._domainkey.{domain} matches the key this \
                     server signs with."
                ),
                ..Check::default()
            },
        },
        "MISSING" => Check {
            state: State::Missing,
            level: Level::Fail,
            summary: "not published".into(),
            detail: format!(
                "This server holds a DKIM key for {domain} but no record is published at \
                 default._domainkey.{domain}, so every signature fails validation."
            ),
            ..Check::default()
        },
        "MISMATCH" => Check {
            state: State::Mismatch,
            level: Level::Fail,
            summary: "key differs from this server's".into(),
            detail: format!(
                "The record at default._domainkey.{domain} publishes a different key than \
                 the one this server signs with: signatures added here fail."
            ),
            ..Check::default()
        },
        "NOPUB" => Check {
            state: State::NoKey,
            level: Level::Fail,
            summary: "no key on this server".into(),
            detail: format!(
                "No DKIM key exists for {domain} on this server, so outgoing mail is not \
                 signed at all. Generating one also publishes the record when the zone is \
                 hosted here."
            ),
            ..Check::default()
        },
        other => {
            let why = match (&res.error, other.is_empty()) {
                (Some(e), _) => format!("cPanel could not check the DKIM record: {e}"),
                (None, true) => "cPanel returned no DKIM state for this domain".to_string(),
                (None, false) => format!("cPanel returned the DKIM state {other}"),
            };
            Check::unknown(why)
        }
    };
    c.raw_state = res.state.clone();
    c.current = res.records.clone();
    c.expected = (!res.expected.is_empty()).then(|| res.expected.clone());
    if matches!(c.state, State::Missing | State::Mismatch | State::NoKey) {
        if let Some(line) = suggested {
            c.suggested_value = Some(txt_value(&line));
            c.suggested = Some(line);
        }
    }
    set_fixability(&mut c, zone, true);
    c.with_notes(notes)
}

/// Our own DMARC verdict: the domain's own record, or the one it inherits from
/// its organizational domain.
pub fn dmarc_check(client: &Client, domain: &str, zone: &Zone) -> Check {
    let lookup = match dmarc::lookup(client, domain) {
        Ok(l) => l,
        Err(e) => return Check::unknown(format!("could not look up _dmarc.{domain}: {e}")),
    };
    let mut c = if lookup.records.len() > 1 {
        Check {
            state: State::Error,
            level: Level::Fail,
            summary: "two DMARC records".into(),
            detail: format!(
                "{} publishes {} DMARC records; receivers ignore the policy entirely when \
                 more than one exists. Keep exactly one.",
                lookup.at,
                lookup.records.len()
            ),
            ..Check::default()
        }
    } else if let Some(e) = &lookup.parse_error {
        Check {
            state: State::Error,
            level: Level::Fail,
            summary: "record does not parse".into(),
            detail: format!("The DMARC record at _dmarc.{}: {e}", lookup.at),
            ..Check::default()
        }
    } else {
        match (&lookup.record, lookup.inherited) {
            (Some(r), true) => {
                let p = r.sp.clone().or(r.p.clone()).unwrap_or_default();
                Check {
                    state: State::NotApplicable,
                    level: Level::Ok,
                    summary: format!("inherited from {}: p={p}", lookup.at),
                    detail: format!(
                        "{domain} has no DMARC record of its own; receivers apply the policy \
                         of {} (p={p}). A subdomain needs its own record only to differ from \
                         it.",
                        lookup.at
                    ),
                    ..Check::default()
                }
            }
            (Some(r), false) => {
                let p = r.p.clone().unwrap_or_default();
                match p.as_str() {
                    "reject" | "quarantine" => Check {
                        state: State::Ok,
                        level: Level::Ok,
                        summary: format!("p={p}"),
                        detail: format!("{domain} publishes an enforcing DMARC policy (p={p})."),
                        ..Check::default()
                    },
                    "none" => Check {
                        state: State::Ok,
                        level: Level::Warn,
                        summary: "p=none".into(),
                        detail: format!(
                            "{domain} publishes a DMARC record, but p=none only asks for \
                             reports: nothing is enforced. Move to p=quarantine once the \
                             reports look clean."
                        ),
                        notes: vec!["monitor-only policy".into()],
                        ..Check::default()
                    },
                    _ => Check {
                        state: State::Error,
                        level: Level::Fail,
                        summary: "no usable p= tag".into(),
                        detail: format!(
                            "The DMARC record of {domain} has no valid policy tag, so \
                             receivers ignore it."
                        ),
                        ..Check::default()
                    },
                }
            }
            (None, _) => Check {
                state: State::Missing,
                level: Level::Fail,
                summary: "not published".into(),
                detail: format!(
                    "Neither {domain} nor its organizational domain publishes a DMARC \
                     record. Bulk receivers (Gmail, Yahoo) now require one."
                ),
                ..Check::default()
            },
        }
    };
    c.current = lookup.records.clone();
    if matches!(c.state, State::Missing) {
        c.suggested = Some(suggest_dmarc(domain));
        c.suggested_value = Some(suggest_dmarc_value(domain));
    }
    set_fixability(&mut c, zone, false);
    c
}

/// The row's colour: the worst of its three cells.
pub fn row_level(spf: &Check, dkim: &Check, dmarc: &Check) -> Level {
    spf.level.worst(dkim.level).worst(dmarc.level)
}

// ---- the live scan ------------------------------------------------------------

/// The `domain=` arguments of one validator call.
fn domain_args(chunk: &[Domain]) -> Vec<String> {
    chunk
        .iter()
        .map(|d| format!("domain={}", d.domain))
        .collect()
}

/// A result for `domain` out of a chunk reply, or why there is none.
fn pick<T: Clone>(res: &Result<Vec<(String, T)>, String>, domain: &str) -> Result<T, String> {
    match res {
        Err(e) => Err(e.clone()),
        Ok(list) => list
            .iter()
            .find(|(d, _)| d == domain)
            .map(|(_, r)| r.clone())
            .ok_or_else(|| format!("cPanel returned no result for {domain}")),
    }
}

/// cPanel names no name servers for a subdomain; take those of the zone that
/// holds it when that zone was answered in the same call.
fn inherit_nameservers(mut z: Zone, auth: &Result<Vec<(String, Zone)>, String>) -> Zone {
    if z.nameservers.is_empty() {
        if let (Some(name), Ok(list)) = (&z.name, auth) {
            if let Some((_, parent)) = list.iter().find(|(d, _)| d == name) {
                z.nameservers = parent.nameservers.clone();
                z.local_authority = z.local_authority || parent.local_authority;
            }
        }
    }
    z
}

/// Check every domain: cPanel's three validators in chunks of 25, then our own
/// DMARC lookup and notes per domain. Returns the rows and the errors of the
/// calls that failed (one per chunk, for `Scan::errors`).
pub fn validate(cp: &Cp, client: &Client, domains: &[Domain]) -> (Vec<Row>, Vec<String>) {
    let mut rows = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    for chunk in domains.chunks(CHUNK) {
        let args = domain_args(chunk);
        let spfs = whmapi1(
            cp,
            "acctdns_spfs",
            "validate_current_spfs",
            &args,
            VALIDATE_TIMEOUT,
        )
        .and_then(|v| parse_validate_spfs(&v));
        let dkims = whmapi1(
            cp,
            "acctdns_dkims",
            "validate_current_dkims",
            &args,
            VALIDATE_TIMEOUT,
        )
        .and_then(|v| parse_validate_dkims(&v));
        let auth = whmapi1(
            cp,
            "acctdns_authority",
            "has_local_authority",
            &args,
            VALIDATE_TIMEOUT,
        )
        .and_then(|v| parse_local_authority(&v));
        let mut note_error = |e: Option<&String>| {
            if let Some(e) = e {
                if !errors.contains(e) {
                    errors.push(e.clone());
                }
            }
        };
        note_error(spfs.as_ref().err());
        note_error(dkims.as_ref().err());
        note_error(auth.as_ref().err());
        for d in chunk {
            let zone = pick(&auth, &d.domain).map(|z| inherit_nameservers(z, &auth));
            let z = zone.clone().unwrap_or_default();
            let mut spf = match pick(&spfs, &d.domain) {
                Err(why) => Check::unknown(why),
                Ok(mut res) => {
                    if res.records.is_empty() {
                        if let Ok(found) = spf::records_at(client, &d.domain) {
                            res.records = found;
                        }
                    }
                    let notes = match res.records.first() {
                        Some(r) => spf_notes(client, &d.domain, r),
                        None => Vec::new(),
                    };
                    classify_spf(&d.domain, &z, &res, &notes)
                }
            };
            let mut dkim = match pick(&dkims, &d.domain) {
                Err(why) => Check::unknown(why),
                Ok(res) => {
                    let notes = match res.records.first() {
                        Some(r) => dkim_notes(r),
                        None => Vec::new(),
                    };
                    let suggested = dkim_suggested(cp, &d.domain, &res.expected);
                    classify_dkim(&d.domain, &z, &res, &notes, suggested)
                }
            };
            let mut dmarc = dmarc_check(client, &d.domain, &z);
            if let Err(why) = &zone {
                // Without the zone answer a fix would be a guess.
                for c in [&mut spf, &mut dkim, &mut dmarc] {
                    if matches!(c.state, State::Missing | State::Mismatch | State::NoKey) {
                        c.fixable = false;
                        c.fix_note =
                            Some(format!("cPanel did not say where the zone lives: {why}"));
                    }
                }
            }
            rows.push(Row {
                level: row_level(&spf, &dkim, &dmarc),
                domain: d.clone(),
                zone: z,
                spf,
                dkim,
                dmarc,
                checked_at: now_secs(),
            });
        }
    }
    (rows, errors)
}

/// One domain, checked inline (after a fix, or for the CLI). `None` when the
/// domain is not hosted here.
pub fn check_one(cp: &Cp, client: &Client, domain: &str) -> Option<Row> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let found = list_domains(cp).into_iter().find(|x| x.domain == d)?;
    let (mut rows, _) = validate(cp, client, &[found]);
    rows.pop()
}

// ---- repairs ------------------------------------------------------------------

/// Which record a repair installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    Spf,
    Dkim,
    Dmarc,
}

impl What {
    pub fn as_str(&self) -> &'static str {
        match self {
            What::Spf => "spf",
            What::Dkim => "dkim",
            What::Dmarc => "dmarc",
        }
    }
    pub fn parse(s: &str) -> Option<What> {
        match s.trim().to_ascii_lowercase().as_str() {
            "spf" => Some(What::Spf),
            "dkim" => Some(What::Dkim),
            "dmarc" => Some(What::Dmarc),
            _ => None,
        }
    }
}

/// What a repair did, and the re-checked row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixReport {
    /// The transcript: the commands run and cPanel's answers.
    pub actions: Vec<String>,
    pub row: Option<Row>,
}

impl FixReport {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("ok".into(), Json::Bool(true)),
            (
                "actions".into(),
                Json::Array(self.actions.iter().map(Json::str).collect()),
            ),
            (
                "row".into(),
                self.row.as_ref().map(Row::to_json).unwrap_or(Json::Null),
            ),
        ])
    }
}

/// A refused or failed repair: the reason, plus whatever the attempt found out
/// (the record to publish elsewhere, the calls already made).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixError {
    pub error: String,
    pub actions: Vec<String>,
}

impl FixError {
    fn new(error: impl Into<String>) -> FixError {
        FixError {
            error: error.into(),
            actions: Vec::new(),
        }
    }
    fn with(error: impl Into<String>, actions: Vec<String>) -> FixError {
        FixError {
            error: error.into(),
            actions,
        }
    }
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("error".into(), Json::str(&self.error)),
            (
                "actions".into(),
                Json::Array(self.actions.iter().map(Json::str).collect()),
            ),
        ])
    }
}

impl std::fmt::Display for FixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.error)
    }
}

/// A record handed to us by the admin: one TXT value, parseable, no quotes.
fn check_record(what: What, record: &str) -> Result<String, String> {
    let v = txt_value(record).trim().to_string();
    if v.is_empty() {
        return Err("the record is empty".into());
    }
    if v.len() > MAX_RECORD {
        return Err(format!(
            "the record is {} characters long (limit {MAX_RECORD})",
            v.len()
        ));
    }
    if v.contains('"') || v.chars().any(|c| c.is_control()) {
        return Err("the record may not contain quotes or control characters".into());
    }
    let lower = v.to_ascii_lowercase();
    match what {
        What::Spf => {
            if !lower.starts_with("v=spf1") {
                return Err("an SPF record must start with v=spf1".into());
            }
            spf::parse(&v).map_err(|e| format!("the SPF record does not parse: {e}"))?;
        }
        What::Dmarc => {
            if !lower.starts_with("v=dmarc1") {
                return Err("a DMARC record must start with v=DMARC1".into());
            }
            dmarc::parse(&v).map_err(|e| format!("the DMARC record does not parse: {e}"))?;
        }
        What::Dkim => {}
    }
    Ok(v)
}

/// Run one installer, quoting its arguments in the transcript.
fn installer(
    cp: &Cp,
    fixture: &str,
    func: &str,
    args: &[String],
    actions: &mut Vec<String>,
) -> Result<(), FixError> {
    let shown = args
        .iter()
        .map(|a| match a.split_once('=') {
            Some((k, v)) if v.contains(' ') => format!("{k}='{v}'"),
            _ => a.clone(),
        })
        .collect::<Vec<_>>()
        .join(" ");
    actions.push(format!("whmapi1 {func} {shown}"));
    let out = whmapi1(cp, fixture, func, args, FIX_TIMEOUT)
        .and_then(|v| meta_ok(&v))
        .map_err(|e| {
            FixError::with(e.clone(), {
                let mut a = actions.clone();
                a.push(format!("failed: {e}"));
                a
            })
        })?;
    actions.push(out);
    Ok(())
}

/// Install the missing record with cPanel's own API, then re-check the domain.
/// `record` may be a bare TXT value or a zone-file line; `None` uses the
/// record the scan suggested.
pub fn fix(cp: &Cp, domain: &str, what: What, record: Option<&str>) -> Result<FixReport, FixError> {
    if !supported(cp) {
        return Err(FixError::new(format!(
            "Account DNS needs cPanel (this host: {})",
            panel_name(cp)
        )));
    }
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if !crate::netguard::valid_hostname(&d) {
        return Err(FixError::new(format!("'{domain}' is not a domain name")));
    }
    if !list_domains(cp).iter().any(|x| x.domain == d) {
        return Err(FixError::new(format!(
            "{d} is not a domain of an account on this server"
        )));
    }
    let given = match record.map(str::trim).filter(|r| !r.is_empty()) {
        Some(r) => Some(check_record(what, r).map_err(FixError::new)?),
        None => None,
    };
    let client = Client::system();
    let mut actions: Vec<String> = Vec::new();
    // The zone (for DMARC) and the suggested record (when none was given)
    // both come from a fresh check.
    let pre = match (what, &given) {
        (What::Dmarc, _) | (_, None) => check_one(cp, &client, &d),
        _ => None,
    };
    match what {
        What::Spf => {
            let value = given
                .or_else(|| pre.as_ref().and_then(|r| r.spf.suggested_value.clone()))
                .ok_or_else(|| {
                    FixError::new("no SPF record to install — scan the domain again first")
                })?;
            installer(
                cp,
                "acctdns_fix_spf",
                "install_spf_records",
                &[format!("domain={d}"), format!("record={value}")],
                &mut actions,
            )?;
        }
        What::Dkim => {
            installer(
                cp,
                "acctdns_fix_dkim",
                "ensure_dkim_keys_exist",
                &[format!("domain={d}")],
                &mut actions,
            )?;
            installer(
                cp,
                "acctdns_fix_dkim",
                "enable_dkim",
                &[format!("domain={d}")],
                &mut actions,
            )?;
        }
        What::Dmarc => {
            let value = given
                .or_else(|| pre.as_ref().and_then(|r| r.dmarc.suggested_value.clone()))
                .unwrap_or_else(|| suggest_dmarc_value(&d));
            let zone = pre.as_ref().and_then(|r| r.zone.name.clone());
            let Some(zone) = zone else {
                return Err(FixError::with(
                    "this server holds no zone for the domain, so cPanel cannot add the \
                     record — publish it at the domain's own name servers",
                    vec![txt_line(&format!("_dmarc.{d}"), &value)],
                ));
            };
            installer(
                cp,
                "acctdns_fix_dmarc",
                "addzonerecord",
                &[
                    format!("domain={zone}"),
                    format!("name=_dmarc.{d}."),
                    "type=TXT".to_string(),
                    format!("ttl={TTL}"),
                    format!("txtdata={value}"),
                ],
                &mut actions,
            )?;
        }
    }
    let row = check_one(cp, &client, &d);
    let still_broken = row.as_ref().is_some_and(|r| {
        let c = match what {
            What::Spf => &r.spf,
            What::Dkim => &r.dkim,
            What::Dmarc => &r.dmarc,
        };
        !matches!(c.state, State::Ok | State::NotApplicable)
    });
    if still_broken {
        actions.push(
            "installed — resolvers keep the old answer until the record's TTL expires; \
             rescan later"
                .into(),
        );
    }
    Ok(FixReport { actions, row })
}

// ---- the scan registry --------------------------------------------------------

/// Limit a scan to one account or one domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub user: Option<String>,
    pub domain: Option<String>,
}

/// Why a scan did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// A scan is already running (its id).
    Busy(String),
    /// Not a cPanel server.
    Unsupported,
    Invalid(String),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::Busy(id) => write!(f, "a scan is already running ({id})"),
            StartError::Unsupported => f.write_str("Account DNS needs cPanel"),
            StartError::Invalid(why) => f.write_str(why),
        }
    }
}

struct Live {
    scan: Scan,
    /// When the scan started, to spot a thread that died mid-way.
    at: std::time::Instant,
}

static SCAN: Mutex<Option<Live>> = Mutex::new(None);
/// A running scan older than this is assumed dead and may be replaced.
const STALE_AFTER: Duration = Duration::from_secs(1800);

fn with_scan<T>(f: impl FnOnce(&mut Option<Live>) -> T) -> T {
    let mut g = SCAN.lock().unwrap_or_else(|e| e.into_inner());
    f(&mut g)
}

/// Where a finished full scan is kept between daemon restarts.
pub fn scan_file() -> PathBuf {
    std::env::var("MSFE_NG_ACCTDNS_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/cache/msfe-ng/acctdns.json"))
}

fn persist(scan: &Scan) {
    let path = scan_file();
    if let Some(dir) = path.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    if crate::sync::atomic_write(&path, scan.to_json().to_string().as_bytes()).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
}

fn load() -> Option<Scan> {
    let text = std::fs::read_to_string(scan_file()).ok()?;
    Json::parse(&text).ok().map(|v| Scan::from_json(&v))
}

/// The scan in memory: the running one, or the last one this process ran.
pub fn snapshot() -> Option<Scan> {
    with_scan(|s| s.as_ref().map(|l| l.scan.clone()))
}

/// The answer for a host this feature cannot run on: no rows, no scan, just
/// the panel it found.
pub fn unsupported_scan(cp: &Cp) -> Scan {
    Scan {
        id: String::new(),
        started: now_secs(),
        finished: None,
        done: true,
        total: 0,
        rows: Vec::new(),
        errors: Vec::new(),
        panel: panel_name(cp),
        supported: false,
    }
}

/// The scan to show when the tab opens: the one in memory, else the last
/// finished full scan from disk.
pub fn last() -> Option<Scan> {
    snapshot().or_else(load)
}

/// Start a scan in the background, one chunk of domains at a time so the table
/// fills progressively. `only` limits it to an account or a single domain.
pub fn start(cfg: &Config, only: Option<Filter>) -> Result<String, StartError> {
    let _ = cfg; // no config knobs yet; kept for symmetry with delivery runs
    let cp = Cp::detect();
    if !supported(&cp) {
        return Err(StartError::Unsupported);
    }
    let filter = only.unwrap_or_default();
    if let Some(u) = filter.user.as_deref() {
        if !crate::users::valid_username(u) {
            return Err(StartError::Invalid(format!("'{u}' is not an account name")));
        }
    }
    let wanted = match filter.domain.as_deref() {
        Some(d) => {
            let d = d.trim().trim_end_matches('.').to_ascii_lowercase();
            if !crate::netguard::valid_hostname(&d) {
                return Err(StartError::Invalid(format!("'{d}' is not a domain name")));
            }
            Some(d)
        }
        None => None,
    };
    let domains: Vec<Domain> = list_domains(&cp)
        .into_iter()
        .filter(|d| match filter.user.as_deref() {
            Some(u) => d.user == u,
            None => true,
        })
        .filter(|d| match wanted.as_deref() {
            Some(w) => d.domain == w,
            None => true,
        })
        .collect();
    let id = crate::deliveryrun::new_id();
    let full = filter.user.is_none() && wanted.is_none();
    let scan = Scan {
        id: id.clone(),
        started: now_secs(),
        finished: None,
        done: false,
        total: domains.len(),
        rows: Vec::new(),
        errors: Vec::new(),
        panel: panel_name(&cp),
        supported: true,
    };
    let busy = with_scan(|slot| {
        if let Some(l) = slot.as_ref() {
            if !l.scan.done && l.at.elapsed() < STALE_AFTER {
                return Some(l.scan.id.clone());
            }
        }
        *slot = Some(Live {
            scan,
            at: std::time::Instant::now(),
        });
        None
    });
    if let Some(running) = busy {
        return Err(StartError::Busy(running));
    }
    let id2 = id.clone();
    // The fixture root and the resolvers are read here, once, so a scan is not
    // affected by the environment changing under it.
    let client = Client::system();
    std::thread::spawn(move || {
        for chunk in domains.chunks(CHUNK) {
            let (rows, errors) = validate(&cp, &client, chunk);
            let alive = with_scan(|slot| match slot.as_mut().filter(|l| l.scan.id == id2) {
                Some(l) => {
                    l.scan.rows.extend(rows);
                    for e in errors {
                        if !l.scan.errors.contains(&e) {
                            l.scan.errors.push(e);
                        }
                    }
                    true
                }
                // another scan replaced this one: stop.
                None => false,
            });
            if !alive {
                return;
            }
        }
        let finished = with_scan(|slot| {
            let l = slot.as_mut().filter(|l| l.scan.id == id2)?;
            l.scan.done = true;
            l.scan.finished = Some(now_secs());
            Some(l.scan.clone())
        });
        if let (Some(scan), true) = (finished, full) {
            persist(&scan);
        }
    });
    Ok(id)
}

/// Forget the scan in memory (tests, and a daemon reload).
pub fn reset() {
    with_scan(|slot| *slot = None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deliveryrun::tests::ENV_LOCK;
    use crate::dns::{testsupport, RData, Rr};
    use std::path::Path;

    /// A 1024-bit public key (generated for the tests, never a real key).
    const PUB_1024: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkWDIOLt8aiQuBeW2YfEpBLeNni8mR+hVY9IWQkifY4VNg4qj9zrw249G0CYRaXtFJtC5G+1E6c1SHenL6MCd1nL//egX/OXc9lleranRf7DTwl+EJLuR1zSI10czPdj70MGr62GnRYB3xwOL5oL5wqYX9yCrzFfbGuRhA/1SjwwIDAQAB";

    fn pem_1024() -> String {
        format!("-----BEGIN PUBLIC KEY-----\n{PUB_1024}\n-----END PUBLIC KEY-----\n")
    }

    /// A 2048-bit public key (generated for the tests, never a real key).
    const PUB_2048: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAps9eA53TbtR8CvI/7MfupkSR9YhG+D5oJgZqFaos8vW8w3vfxIZ0cSB6MQFjsfDQZDapZg4ogKYHKAq6ImrwPFQm/Uae0LcSxOXAzLVwJra5T/R7HzJ4pePVjNHq4M/CJn1SwjHfZSs0+c67toPfLQfbL7TcBwGvgc+6+HGGS/WGX6aql2s7A9+IHpvrnhiiI0f3oJcTyQV1QJr+U8uN0fx6ZZuzXPLKZu3JKvMKU3oxXXCWIS78K/h/n13x2Qi+QTM1CNim4KKthvdNuYM3pUK0zNo7wGlWZp1Do7e9UFXuuiLJjLF1b40hvvJtIH/f9hRNUR0R0YNYq9o7Mow/lwIDAQAB";

    fn dkim_1024() -> String {
        format!("v=DKIM1; k=rsa; p={PUB_1024}")
    }

    fn dkim_2048() -> String {
        format!("v=DKIM1; k=rsa; p={PUB_2048}")
    }

    // The captured shapes of cPanel 138's replies, rewritten to documentation
    // domains and addresses.
    const SPFS: &str = r#"{"metadata":{"command":"validate_current_spfs","reason":"OK","result":1,"version":1},"data":{"payload":[
      {"domain":"example.com","state":"VALID","expected":"ip4:192.0.2.10","ip_address":"192.0.2.10","ip_version":4,"records":[{"current":"v=spf1 +mx +a +ip4:192.0.2.10 ~all","state":"VALID"}],"error":null},
      {"domain":"shop.example.com","state":"MISSING","expected":"ip4:192.0.2.10","ip_address":"192.0.2.10","ip_version":4,"records":[],"error":null},
      {"domain":"example.net","state":"MISMATCH","expected":"ip4:192.0.2.10","ip_address":"192.0.2.10","ip_version":4,"records":[{"current":"v=spf1 include:_spf.example.org -all","state":"MISMATCH"}],"error":null}
    ]}}"#;

    const DKIMS: &str = r#"{"metadata":{"command":"validate_current_dkims","reason":"OK","result":1,"version":1},"data":{"payload":[
      {"domain":"default._domainkey.example.com","state":"MISMATCH","expected":"v=DKIM1; k=rsa; p=AAAAmine","records":[{"current":"v=DKIM1; k=rsa; p=AAAAtheirs","state":"MISMATCH"}],"error":null},
      {"domain":"default._domainkey.shop.example.com","state":"MISSING","expected":"v=DKIM1; k=rsa; p=AAAAmine","records":[],"error":null},
      {"domain":"default._domainkey.example.net","state":"NOPUB","expected":"","records":[],"error":"No DKIM key exists for 'example.net'."}
    ]}}"#;

    const AUTH: &str = r#"{"metadata":{"command":"has_local_authority","reason":"OK","result":1,"version":1},"data":{"records":[
      {"domain":"example.com","zone":"example.com","local_authority":0,"nameservers":["ns1.example.net.","ns2.example.net."],"error":null},
      {"domain":"shop.example.com","zone":"example.com","local_authority":1,"nameservers":["ns1.example.com"],"error":null},
      {"domain":"example.org","zone":null,"local_authority":0,"nameservers":[],"error":null}
    ]}}"#;

    const OK_REPLY: &str =
        r#"{"metadata":{"command":"install_spf_records","reason":"OK","result":1,"version":1}}"#;
    const DENIED_REPLY: &str =
        r#"{"metadata":{"command":"install_spf_records","reason":"Access denied","result":0}}"#;

    fn map<T>(v: Vec<(String, T)>) -> HashMap<String, T> {
        v.into_iter().collect()
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-acctdns-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // ---- parsers --------------------------------------------------------------

    #[test]
    fn parses_validator_replies() {
        let spfs = map(parse_validate_spfs(&Json::parse(SPFS).unwrap()).unwrap());
        assert_eq!(spfs.len(), 3);
        assert_eq!(spfs["example.com"].state, "VALID");
        assert_eq!(spfs["example.com"].ip, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(
            spfs["example.com"].records,
            vec!["v=spf1 +mx +a +ip4:192.0.2.10 ~all"]
        );
        assert!(spfs["shop.example.com"].records.is_empty());
        assert_eq!(spfs["example.net"].state, "MISMATCH");
        assert_eq!(spfs["example.net"].expected, "ip4:192.0.2.10");

        let dkims = map(parse_validate_dkims(&Json::parse(DKIMS).unwrap()).unwrap());
        assert_eq!(dkims.len(), 3, "the default._domainkey. prefix is stripped");
        assert_eq!(dkims["example.com"].state, "MISMATCH");
        assert_eq!(dkims["shop.example.com"].state, "MISSING");
        assert_eq!(dkims["example.net"].state, "NOPUB");
        assert!(dkims["example.net"].expected.is_empty());
        assert!(dkims["example.net"]
            .error
            .as_deref()
            .unwrap()
            .contains("No DKIM key"));

        let auth = map(parse_local_authority(&Json::parse(AUTH).unwrap()).unwrap());
        assert_eq!(auth["example.com"].name.as_deref(), Some("example.com"));
        assert!(!auth["example.com"].local_authority);
        assert_eq!(auth["example.com"].summary(), "copy here, NS elsewhere");
        assert_eq!(
            auth["example.com"].nameservers,
            vec!["ns1.example.net", "ns2.example.net"]
        );
        assert_eq!(
            auth["shop.example.com"].name.as_deref(),
            Some("example.com"),
            "a subdomain reports its parent zone"
        );
        assert!(auth["shop.example.com"].local_authority);
        assert_eq!(auth["shop.example.com"].summary(), "here");
        assert_eq!(auth["example.org"].name, None);
        assert_eq!(auth["example.org"].summary(), "elsewhere");

        let denied = Json::parse(DENIED_REPLY).unwrap();
        assert!(parse_validate_spfs(&denied)
            .unwrap_err()
            .contains("Access denied"));
        let empty = Json::parse(r#"{"metadata":{"reason":"OK","result":1},"data":{}}"#).unwrap();
        assert!(parse_validate_dkims(&empty).is_err(), "no payload");
        assert!(parse_local_authority(&empty).is_err(), "no records");
        assert!(
            parse_validate_spfs(&Json::parse("{}").unwrap()).is_err(),
            "no metadata"
        );
    }

    #[test]
    fn parses_userdata_main() {
        let u = parse_userdata_main(
            "main_domain: example.com\naddon_domains:\n  addon.example.net: addon.example.com\nparked_domains:\n  - parked.example.org\nsub_domains:\n  - shop.example.com\n  - addon.example.com\n",
        );
        assert_eq!(u.main.as_deref(), Some("example.com"));
        assert_eq!(
            u.addon,
            vec![(
                "addon.example.net".to_string(),
                "addon.example.com".to_string()
            )]
        );
        assert_eq!(u.parked, vec!["parked.example.org"]);
        assert_eq!(u.subs, vec!["shop.example.com", "addon.example.com"]);
        // the empty shapes cPanel writes, and an unknown section
        let u = parse_userdata_main(
            "addon_domains: []\nmain_domain: example.org\nparked_domains: []\nsub_domains:\n  - mail.example.org\nip: 192.0.2.10\n",
        );
        assert_eq!(u.main.as_deref(), Some("example.org"));
        assert!(u.addon.is_empty() && u.parked.is_empty());
        assert_eq!(u.subs, vec!["mail.example.org"]);
        assert_eq!(parse_userdata_main(""), UserdataMain::default());
    }

    // ---- suggestions ----------------------------------------------------------

    #[test]
    fn suggests_spf_records() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            suggest_spf(&[], "ip4:192.0.2.10", None),
            "v=spf1 +mx +a ip4:192.0.2.10 ~all"
        );
        assert_eq!(
            suggest_spf(&[], "", Some(ip)),
            "v=spf1 +mx +a ip4:192.0.2.10 ~all",
            "the mechanism is built from the outgoing address when cPanel gives none"
        );
        assert_eq!(suggest_spf(&[], "", None), "v=spf1 +mx +a ~all");
        assert_eq!(
            suggest_spf(
                &["v=spf1 include:_spf.example.net".into()],
                "ip4:192.0.2.10",
                None
            ),
            "v=spf1 include:_spf.example.net ip4:192.0.2.10 ~all"
        );
        assert_eq!(
            suggest_spf(
                &["v=spf1 include:_spf.example.net -all".into()],
                "ip4:192.0.2.10",
                None
            ),
            "v=spf1 include:_spf.example.net ip4:192.0.2.10 -all",
            "the existing all qualifier is kept"
        );
        let already = "v=spf1 +a ip4:192.0.2.10 ~all".to_string();
        assert_eq!(
            suggest_spf(std::slice::from_ref(&already), "ip4:192.0.2.10", None),
            already
        );
        let merged = suggest_spf(
            &[
                "v=spf1 a ~all".into(),
                "v=spf1 include:_spf.example.org -all".into(),
            ],
            "ip4:192.0.2.10",
            None,
        );
        assert_eq!(
            merged,
            "v=spf1 a include:_spf.example.org ip4:192.0.2.10 ~all"
        );
        assert_eq!(merged.matches("v=spf1").count(), 1);
        assert_eq!(merged.matches("all").count(), 1);
        assert_eq!(
            suggest_spf(
                &["v=spf1 redirect=_spf.example.net".into()],
                "ip4:192.0.2.10",
                None
            ),
            "v=spf1 ip4:192.0.2.10 redirect=_spf.example.net",
            "no all term is added next to a redirect"
        );
    }

    #[test]
    fn suggests_dkim_and_dmarc_records() {
        let root = tmpdir("keys");
        write(&root, "/etc/userdomains", "example.com: alice\n");
        write(
            &root,
            "/var/cpanel/domain_keys/public/example.com",
            &pem_1024(),
        );
        let cp = Cp { root: root.clone() };
        assert_eq!(
            dkim_suggested(&cp, "example.com", "v=DKIM1; k=rsa; p=AAAA").unwrap(),
            "default._domainkey.example.com. 14400 IN TXT \"v=DKIM1; k=rsa; p=AAAA\""
        );
        let from_pem = dkim_suggested(&cp, "example.com", "").unwrap();
        assert!(from_pem.contains(PUB_1024) && from_pem.contains("v=DKIM1; k=rsa;"));
        assert!(
            dkim_suggested(&cp, "other.example.com", "").is_none(),
            "no key file, no suggestion"
        );
        assert_eq!(
            suggest_dmarc("example.com"),
            "_dmarc.example.com. 14400 IN TXT \"v=DMARC1; p=none; rua=mailto:postmaster@example.com\""
        );
        assert_eq!(
            txt_value(&suggest_dmarc("example.com")),
            suggest_dmarc_value("example.com")
        );
        assert_eq!(txt_value("v=spf1 ~all"), "v=spf1 ~all");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- our own findings -----------------------------------------------------

    /// A server that answers the given TXT names and nothing else.
    fn dns_server(txts: &'static [(&'static str, &'static str)]) -> testsupport::FakeServer {
        testsupport::start(
            Box::new(move |name, rtype| {
                let n = name.trim_end_matches('.').to_ascii_lowercase();
                if rtype == 16 {
                    let recs: Vec<Rr> = txts
                        .iter()
                        .filter(|(k, _)| *k == n)
                        .map(|(_, v)| Rr {
                            name: n.clone(),
                            rtype: 16,
                            ttl: 300,
                            data: RData::Txt(vec![v.to_string()]),
                        })
                        .collect();
                    return Some((0, recs, false));
                }
                Some((0, vec![], false))
            }),
            false,
        )
    }

    fn dns(txts: &'static [(&'static str, &'static str)]) -> Client {
        Client::at(dns_server(txts).addr)
    }

    #[test]
    fn notes_what_cpanel_does_not_check() {
        let c = dns(&[]);
        let notes = spf_notes(&c, "example.com", "v=spf1 +all");
        assert_eq!(notes[0].level, Level::Fail);
        assert!(notes[0].text.contains("+all"));
        let notes = spf_notes(&c, "example.com", "v=spf1 ip4:192.0.2.10");
        assert_eq!(notes[0].level, Level::Warn);
        assert!(notes[0].text.contains("no all term"));
        let notes = spf_notes(&c, "example.com", "v=spf1 ?all");
        assert_eq!(notes[0].level, Level::Warn);
        let notes = spf_notes(&c, "example.com", "not a record");
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].level, Level::Fail);
        assert!(notes[0].text.starts_with("syntax:"));
        let notes = spf_notes(&c, "example.com", "v=spf1 ptr -all");
        assert!(notes.iter().any(|n| n.text.contains("ptr is deprecated")));
        assert!(spf_notes(&c, "example.com", "v=spf1 +mx +a ~all").is_empty());

        let notes = dkim_notes(&dkim_1024());
        assert_eq!(notes[0].level, Level::Warn);
        assert!(notes[0].text.contains("1024-bit key"));
        let notes = dkim_notes("v=DKIM1; k=rsa; p=");
        assert_eq!(notes[0].level, Level::Fail);
        assert!(notes[0].text.contains("revoked"));
        let notes = dkim_notes(&format!("v=DKIM1; k=rsa; t=y; p={PUB_1024}"));
        assert!(notes.iter().any(|n| n.text.contains("t=y")));
        assert!(dkim_notes("").is_empty());
    }

    #[test]
    fn checks_dmarc_against_dns() {
        let here = Zone {
            name: Some("example.com".into()),
            local_authority: true,
            nameservers: vec!["ns1.example.com".into()],
        };
        let c = dns(&[
            (
                "_dmarc.example.com",
                "v=DMARC1; p=reject; rua=mailto:postmaster@example.com",
            ),
            ("_dmarc.example.net", "v=DMARC1; p=none"),
            ("_dmarc.two.example.com", "v=DMARC1; p=reject"),
            ("_dmarc.broken.example.com", "v=DMARC1 p=reject"),
        ]);
        let own = dmarc_check(&c, "example.com", &here);
        assert_eq!(own.state, State::Ok);
        assert_eq!(own.level, Level::Ok);
        assert_eq!(own.summary, "p=reject");
        assert!(!own.fixable && own.suggested.is_none());

        let monitor = dmarc_check(&c, "example.net", &here);
        assert_eq!(monitor.state, State::Ok);
        assert_eq!(
            monitor.level,
            Level::Warn,
            "p=none is a warning, not a failure"
        );
        assert_eq!(monitor.summary, "p=none");
        assert_eq!(monitor.notes, vec!["monitor-only policy"]);

        let sub = dmarc_check(&c, "shop.example.com", &here);
        assert_eq!(sub.state, State::NotApplicable);
        assert_eq!(sub.level, Level::Ok);
        assert!(sub
            .summary
            .starts_with("inherited from example.com: p=reject"));
        assert!(!sub.fixable);

        let none = dmarc_check(&c, "example.org", &here);
        assert_eq!(none.state, State::Missing);
        assert_eq!(none.level, Level::Fail);
        assert_eq!(none.summary, "not published");
        assert!(none.fixable, "the zone is here");
        assert_eq!(
            none.suggested_value.as_deref(),
            Some("v=DMARC1; p=none; rua=mailto:postmaster@example.org")
        );

        let broken = dmarc_check(&c, "broken.example.com", &here);
        assert_eq!(broken.state, State::Error);
        assert_eq!(broken.level, Level::Fail);

        // a silent server: the lookup cannot say anything
        let quiet = testsupport::start(Box::new(|_, _| None), false);
        let mut slow = Client::at(quiet.addr);
        slow.timeout = Duration::from_millis(40);
        slow.tries = 1;
        let unknown = dmarc_check(&slow, "example.com", &here);
        assert_eq!(unknown.state, State::Unknown);
        assert_eq!(unknown.level, Level::Unknown);
        assert!(unknown.detail.contains("could not look up"));
    }

    #[test]
    fn two_dmarc_records_are_an_error() {
        let srv = testsupport::start(
            Box::new(|name, rtype| {
                if rtype != 16 {
                    return Some((0, vec![], false));
                }
                let rr = |v: &str| Rr {
                    name: name.to_string(),
                    rtype: 16,
                    ttl: 300,
                    data: RData::Txt(vec![v.to_string()]),
                };
                Some((
                    0,
                    vec![rr("v=DMARC1; p=none"), rr("v=DMARC1; p=reject")],
                    false,
                ))
            }),
            false,
        );
        let c = dmarc_check(&Client::at(srv.addr), "example.com", &Zone::default());
        assert_eq!(c.state, State::Error);
        assert_eq!(c.summary, "two DMARC records");
        assert!(c.detail.contains("2 DMARC records"));
    }

    // ---- classification -------------------------------------------------------

    fn zone_here() -> Zone {
        Zone {
            name: Some("example.com".into()),
            local_authority: true,
            nameservers: vec!["ns1.example.com".into()],
        }
    }

    #[test]
    fn classifies_cpanel_states() {
        let res = |state: &str| SpfResult {
            state: state.into(),
            expected: "ip4:192.0.2.10".into(),
            ip: Some("192.0.2.10".parse().unwrap()),
            records: Vec::new(),
            reason: None,
            error: None,
        };
        let ok = classify_spf("example.com", &zone_here(), &res("VALID"), &[]);
        let invalid = SpfResult {
            reason: Some("mechanism '~all' matched".into()),
            records: vec!["v=spf1 +a ~all".into()],
            ..res("INVALID")
        };
        let inv = classify_spf("example.com", &zone_here(), &invalid, &[]);
        assert_eq!((inv.state, inv.level), (State::Mismatch, Level::Fail));
        assert!(
            inv.detail.contains("cPanel: mechanism '~all' matched"),
            "{}",
            inv.detail
        );
        assert_eq!(
            inv.suggested_value.as_deref(),
            Some("v=spf1 +a ip4:192.0.2.10 ~all")
        );
        assert_eq!((ok.state, ok.level), (State::Ok, Level::Ok));
        assert_eq!(ok.raw_state, "VALID");
        assert!(!ok.fixable && ok.suggested.is_none());

        let warned = classify_spf(
            "example.com",
            &zone_here(),
            &res("VALID"),
            &[Note::new(Level::Warn, "1 of 10 lookups")],
        );
        assert_eq!(
            (warned.state, warned.level),
            (State::Ok, Level::Warn),
            "a warning note raises the level but not the state"
        );
        assert_eq!(warned.notes, vec!["1 of 10 lookups"]);

        let missing = classify_spf("example.com", &zone_here(), &res("MISSING"), &[]);
        assert_eq!(
            (missing.state, missing.level),
            (State::Missing, Level::Fail)
        );
        assert_eq!(missing.summary, "not published");
        assert!(missing.fixable && missing.fix_note.is_none());
        assert_eq!(
            missing.suggested.as_deref(),
            Some("example.com. 14400 IN TXT \"v=spf1 +mx +a ip4:192.0.2.10 ~all\"")
        );
        assert_eq!(
            missing.suggested_value.as_deref(),
            Some("v=spf1 +mx +a ip4:192.0.2.10 ~all")
        );

        // no local zone: nothing to install, the record is to be published there
        let elsewhere = classify_spf("example.com", &Zone::default(), &res("MISSING"), &[]);
        assert!(!elsewhere.fixable);
        assert!(elsewhere
            .fix_note
            .as_deref()
            .unwrap()
            .contains("hosted elsewhere"));

        // a local copy of the zone whose name servers are elsewhere
        let copy = Zone {
            name: Some("example.com".into()),
            local_authority: false,
            nameservers: vec!["ns1.example.net".into()],
        };
        let mismatch = classify_spf("example.com", &copy, &res("MISMATCH"), &[]);
        assert_eq!(mismatch.state, State::Mismatch);
        assert_eq!(mismatch.summary, "server IP not authorized");
        assert!(mismatch.fixable);
        let note = mismatch.fix_note.unwrap();
        assert!(note.contains("holds a copy of the zone") && note.contains("ns1.example.net"));

        let unknown = classify_spf("example.com", &zone_here(), &res("WHAT"), &[]);
        assert_eq!(
            (unknown.state, unknown.level),
            (State::Unknown, Level::Unknown)
        );
        assert_eq!(unknown.raw_state, "WHAT");
        assert!(unknown.detail.contains("WHAT") && !unknown.fixable);

        let mut errored = res("");
        errored.error = Some("resolver failure".into());
        let c = classify_spf("example.com", &zone_here(), &errored, &[]);
        assert_eq!(c.state, State::Unknown);
        assert!(c.detail.contains("resolver failure"));
    }

    #[test]
    fn classifies_dkim_states() {
        let res = |state: &str, current: Vec<String>| DkimResult {
            state: state.into(),
            expected: "v=DKIM1; k=rsa; p=AAAAmine".into(),
            records: current,
            error: None,
        };
        let suggested = Some(
            "default._domainkey.example.com. 14400 IN TXT \"v=DKIM1; k=rsa; p=AAAAmine\""
                .to_string(),
        );
        let weak = classify_dkim(
            "example.com",
            &zone_here(),
            &res("VALID", vec![dkim_1024()]),
            &dkim_notes(&dkim_1024()),
            suggested.clone(),
        );
        assert_eq!((weak.state, weak.level), (State::Weak, Level::Warn));
        assert_eq!(weak.summary, "1024-bit key");
        assert!(!weak.fixable, "a weak key is regenerated by hand");
        assert!(weak.fix_note.as_deref().unwrap().contains("regenerating"));

        let ok = classify_dkim(
            "example.com",
            &zone_here(),
            &res("VALID", vec!["v=DKIM1; k=rsa; p=AAAAmine".into()]),
            &[],
            suggested.clone(),
        );
        assert_eq!((ok.state, ok.level), (State::Ok, Level::Ok));

        let missing = classify_dkim(
            "example.com",
            &zone_here(),
            &res("MISSING", vec![]),
            &[],
            suggested.clone(),
        );
        assert_eq!(missing.state, State::Missing);
        assert!(missing.fixable);
        assert_eq!(
            missing.suggested_value.as_deref(),
            Some("v=DKIM1; k=rsa; p=AAAAmine")
        );

        let mism = classify_dkim(
            "example.com",
            &zone_here(),
            &res("MISMATCH", vec!["v=DKIM1; k=rsa; p=AAAAtheirs".into()]),
            &[],
            suggested.clone(),
        );
        assert_eq!(mism.state, State::Mismatch);
        assert_eq!(mism.summary, "key differs from this server's");

        // no key here and no local zone: cPanel can still generate the key
        let nopub = classify_dkim(
            "example.net",
            &Zone::default(),
            &res("NOPUB", vec![]),
            &[],
            None,
        );
        assert_eq!((nopub.state, nopub.level), (State::NoKey, Level::Fail));
        assert_eq!(nopub.summary, "no key on this server");
        assert!(nopub.fixable);
        assert!(nopub.suggested.is_none());
        assert!(nopub
            .fix_note
            .as_deref()
            .unwrap()
            .contains("generated on this server"));

        let unknown = classify_dkim("example.com", &zone_here(), &res("HUH", vec![]), &[], None);
        assert_eq!(unknown.state, State::Unknown);
        assert_eq!(unknown.raw_state, "HUH");
    }

    #[test]
    fn row_level_is_the_worst_cell() {
        let lvl = |level: Level| Check {
            level,
            ..Check::default()
        };
        assert_eq!(
            row_level(&lvl(Level::Ok), &lvl(Level::Warn), &lvl(Level::Fail)),
            Level::Fail
        );
        assert_eq!(
            row_level(&lvl(Level::Ok), &lvl(Level::Warn), &lvl(Level::Unknown)),
            Level::Warn
        );
        assert_eq!(
            row_level(&lvl(Level::Ok), &lvl(Level::Unknown), &lvl(Level::Ok)),
            Level::Unknown
        );
        assert_eq!(
            row_level(&lvl(Level::Ok), &lvl(Level::Ok), &lvl(Level::Ok)),
            Level::Ok
        );
    }

    // ---- a whole fixture server ----------------------------------------------

    /// Six domains over two accounts: the cases the table must make readable.
    fn server_tree(tag: &str) -> PathBuf {
        let root = tmpdir(tag);
        write(
            &root,
            "/etc/userdomains",
            "example.com: alice\nshop.example.com: alice\naddon.example.net: alice\naddon.example.com: alice\nparked.example.org: alice\nexample.org: bob\nhost.example.com: nobody\n*: nobody\n",
        );
        write(
            &root,
            "/var/cpanel/userdata/alice/main",
            "main_domain: example.com\naddon_domains:\n  addon.example.net: addon.example.com\nparked_domains:\n  - parked.example.org\nsub_domains:\n  - shop.example.com\n  - addon.example.com\n",
        );
        write(
            &root,
            "/var/cpanel/userdata/bob/main",
            "main_domain: example.org\naddon_domains: []\nparked_domains: []\nsub_domains: []\n",
        );
        write(
            &root,
            "/etc/localdomains",
            "example.com\nshop.example.com\naddon.example.net\naddon.example.com\nexample.org\n",
        );
        write(&root, "/etc/remotedomains", "parked.example.org\n");
        write(
            &root,
            "/var/cpanel/domain_keys/public/example.com",
            &pem_1024(),
        );
        let spf = |d: &str, state: &str, current: &str| {
            let records = if current.is_empty() {
                "[]".to_string()
            } else {
                format!("[{{\"current\":\"{current}\",\"state\":\"{state}\"}}]")
            };
            format!("{{\"domain\":\"{d}\",\"state\":\"{state}\",\"expected\":\"ip4:192.0.2.10\",\"ip_address\":\"192.0.2.10\",\"ip_version\":4,\"records\":{records},\"error\":null}}")
        };
        let good = "v=spf1 +mx +a +ip4:192.0.2.10 ~all";
        write(
            &root,
            "/_cmd/acctdns_spfs.txt",
            &format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{}]}}}}",
                [
                    spf("example.com", "VALID", good),
                    spf("addon.example.net", "VALID", good),
                    spf("addon.example.com", "VALID", good),
                    spf("parked.example.org", "VALID", good),
                    spf("shop.example.com", "MISSING", ""),
                    spf(
                        "example.org",
                        "MISMATCH",
                        "v=spf1 include:_spf.example.net -all"
                    ),
                ]
                .join(",")
            ),
        );
        let dkim = |d: &str, state: &str, current: &str, expected: &str| {
            let records = if current.is_empty() {
                "[]".to_string()
            } else {
                format!("[{{\"current\":\"{current}\",\"state\":\"{state}\"}}]")
            };
            format!("{{\"domain\":\"default._domainkey.{d}\",\"state\":\"{state}\",\"expected\":\"{expected}\",\"records\":{records},\"error\":null}}")
        };
        let mine = dkim_2048();
        let mine = mine.as_str();
        let theirs = dkim_1024();
        write(
            &root,
            "/_cmd/acctdns_dkims.txt",
            &format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{}]}}}}",
                [
                    dkim("example.com", "MISMATCH", &theirs, mine),
                    dkim("addon.example.net", "NOPUB", "", ""),
                    dkim("addon.example.com", "VALID", &dkim_1024(), &dkim_1024()),
                    dkim("parked.example.org", "VALID", mine, mine),
                    dkim("shop.example.com", "MISSING", "", mine),
                    dkim("example.org", "VALID", mine, mine),
                ]
                .join(",")
            ),
        );
        let zone = |d: &str, z: &str, la: u8, ns: &str| {
            format!("{{\"domain\":\"{d}\",\"zone\":{z},\"local_authority\":{la},\"nameservers\":[{ns}],\"error\":null}}")
        };
        write(
            &root,
            "/_cmd/acctdns_authority.txt",
            &format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"records\":[{}]}}}}",
                [
                    zone(
                        "example.com",
                        "\"example.com\"",
                        0,
                        "\"ns1.example.net\",\"ns2.example.net\""
                    ),
                    zone(
                        "shop.example.com",
                        "\"example.com\"",
                        1,
                        "\"ns1.example.com\""
                    ),
                    zone(
                        "addon.example.com",
                        "\"example.com\"",
                        1,
                        "\"ns1.example.com\""
                    ),
                    zone("addon.example.net", "null", 0, ""),
                    zone("parked.example.org", "null", 0, "\"ns1.example.org\""),
                    zone("example.org", "\"example.org\"", 1, "\"ns1.example.com\""),
                ]
                .join(",")
            ),
        );
        for what in ["spf", "dkim", "dmarc"] {
            write(&root, &format!("/_cmd/acctdns_fix_{what}.txt"), OK_REPLY);
        }
        root
    }

    /// The DNS the fixture server's domains resolve to.
    const SERVER_TXTS: &[(&str, &str)] = &[
        ("example.com", "v=spf1 +mx +a +ip4:192.0.2.10 ~all"),
        (
            "_dmarc.example.com",
            "v=DMARC1; p=reject; rua=mailto:postmaster@example.com",
        ),
        ("_dmarc.addon.example.com", "v=DMARC1; p=none"),
        ("_dmarc.example.org", "v=DMARC1; p=quarantine"),
    ];

    fn server_dns() -> Client {
        dns(SERVER_TXTS)
    }

    #[test]
    fn lists_the_domains_of_every_account() {
        let root = server_tree("list");
        let cp = Cp { root: root.clone() };
        assert!(supported(&cp));
        let domains = list_domains(&cp);
        let names: Vec<&str> = domains.iter().map(|d| d.domain.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "example.com",
                "addon.example.net",
                "parked.example.org",
                "addon.example.com",
                "shop.example.com",
                "example.org",
            ],
            "account, then main -> addon -> parked -> sub, then name"
        );
        let kinds: Vec<Kind> = domains.iter().map(|d| d.kind).collect();
        assert_eq!(
            kinds,
            vec![
                Kind::Main,
                Kind::Addon,
                Kind::Parked,
                Kind::Sub,
                Kind::Sub,
                Kind::Main
            ]
        );
        assert_eq!(domains[5].user, "bob");
        assert_eq!(domains[0].mail, DomainKind::Local);
        assert_eq!(
            domains[2].mail,
            DomainKind::Remote,
            "parked domain routed away"
        );
        assert!(
            !domains.iter().any(|d| d.domain == "host.example.com"),
            "the server's own host name belongs to nobody and is left out"
        );
        // a domain cPanel's userdata does not mention falls back to its shape
        let cp2 = Cp {
            root: tmpdir("list-bare"),
        };
        write(
            &cp2.root,
            "/etc/userdomains",
            "example.com: alice\nmail.example.com: alice\n",
        );
        let bare = list_domains(&cp2);
        assert_eq!(bare[0].kind, Kind::Main);
        assert_eq!(
            bare[1].kind,
            Kind::Sub,
            "a subdomain of another domain of the account"
        );
        assert!(!supported(&Cp {
            root: tmpdir("empty")
        }));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validates_every_domain_over_the_fixture_tree() {
        let root = server_tree("validate");
        let cp = Cp { root: root.clone() };
        let client = server_dns();
        let domains = list_domains(&cp);
        let (rows, errors) = validate(&cp, &client, &domains);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(rows.len(), 6);
        let by = |name: &str| {
            rows.iter()
                .find(|r| r.domain.domain == name)
                .unwrap_or_else(|| panic!("no row for {name}"))
        };

        // the main domain: zone here, name servers elsewhere, DKIM mismatch
        let main = by("example.com");
        assert_eq!(main.spf.state, State::Ok);
        assert_eq!(main.dkim.state, State::Mismatch);
        assert_eq!(main.dmarc.state, State::Ok);
        assert_eq!(main.level, Level::Fail);
        assert_eq!(main.zone.summary(), "copy here, NS elsewhere");
        assert!(main.dkim.fixable);
        assert!(main
            .dkim
            .fix_note
            .as_deref()
            .unwrap()
            .contains("holds a copy of the zone"));
        assert_eq!(
            main.dkim.suggested,
            Some(format!(
                "default._domainkey.example.com. 14400 IN TXT \"{}\"",
                dkim_2048()
            ))
        );

        // the addon domain: no key here, DNS elsewhere
        let addon = by("addon.example.net");
        assert_eq!(addon.dkim.state, State::NoKey);
        assert!(addon.dkim.fixable, "cPanel can still generate the key");
        assert_eq!(addon.zone.summary(), "elsewhere");
        assert_eq!(addon.dmarc.state, State::Missing);
        assert!(!addon.dmarc.fixable, "no zone here to add the record to");
        assert!(addon
            .dmarc
            .suggested
            .as_deref()
            .unwrap()
            .contains("_dmarc.addon.example.net."));
        assert_eq!(addon.level, Level::Fail);

        // the service subdomain: a 1024-bit key and a monitor-only policy
        let sub = by("addon.example.com");
        assert_eq!(sub.dkim.state, State::Weak);
        assert_eq!(sub.dkim.summary, "1024-bit key");
        assert_eq!(sub.dmarc.summary, "p=none");
        assert_eq!(sub.level, Level::Warn);

        // the subdomain with nothing published inherits its parent's DMARC
        let shop = by("shop.example.com");
        assert_eq!(shop.spf.state, State::Missing);
        assert_eq!(
            shop.spf.suggested.as_deref(),
            Some("shop.example.com. 14400 IN TXT \"v=spf1 +mx +a ip4:192.0.2.10 ~all\"")
        );
        assert!(shop.spf.fixable);
        assert_eq!(shop.dkim.state, State::Missing);
        assert_eq!(shop.dmarc.state, State::NotApplicable);
        assert!(shop.dmarc.summary.contains("inherited from example.com"));

        // the parked domain: routed elsewhere, everything in order
        let parked = by("parked.example.org");
        assert_eq!(parked.level, Level::Ok);
        assert_eq!(parked.dmarc.state, State::NotApplicable);
        assert_eq!(parked.domain.mail, DomainKind::Remote);

        // the other account: SPF mismatch, the suggestion keeps the include
        let other = by("example.org");
        assert_eq!(other.spf.state, State::Mismatch);
        let suggested = other.spf.suggested_value.clone().unwrap();
        assert_eq!(
            suggested,
            "v=spf1 include:_spf.example.net ip4:192.0.2.10 -all"
        );
        assert_eq!(other.dmarc.summary, "p=quarantine");
        assert_eq!(other.level, Level::Fail);
        assert!(rows.iter().all(|r| r.checked_at > 0));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validates_more_domains_than_one_chunk_holds() {
        let root = tmpdir("chunks");
        let n = CHUNK + 5;
        let mut userdomains = String::from("example.net: carol\n");
        let mut subs = String::new();
        let mut spfs = Vec::new();
        let mut dkims = Vec::new();
        let mut zones = Vec::new();
        for i in 0..n {
            let d = if i == 0 {
                "example.net".to_string()
            } else {
                format!("s{i}.example.net")
            };
            if i > 0 {
                userdomains.push_str(&format!("{d}: carol\n"));
                subs.push_str(&format!("  - {d}\n"));
            }
            spfs.push(format!("{{\"domain\":\"{d}\",\"state\":\"VALID\",\"expected\":\"ip4:192.0.2.10\",\"ip_address\":\"192.0.2.10\",\"records\":[],\"error\":null}}"));
            dkims.push(format!("{{\"domain\":\"default._domainkey.{d}\",\"state\":\"VALID\",\"expected\":\"\",\"records\":[],\"error\":null}}"));
            zones.push(format!("{{\"domain\":\"{d}\",\"zone\":\"example.net\",\"local_authority\":1,\"nameservers\":[],\"error\":null}}"));
        }
        write(&root, "/etc/userdomains", &userdomains);
        write(
            &root,
            "/var/cpanel/userdata/carol/main",
            &format!("main_domain: example.net\nsub_domains:\n{subs}"),
        );
        let wrap = |field: &str, items: &[String]| {
            format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"{field}\":[{}]}}}}",
                items.join(",")
            )
        };
        write(&root, "/_cmd/acctdns_spfs.txt", &wrap("payload", &spfs));
        write(&root, "/_cmd/acctdns_dkims.txt", &wrap("payload", &dkims));
        write(
            &root,
            "/_cmd/acctdns_authority.txt",
            &wrap("records", &zones),
        );
        let cp = Cp { root: root.clone() };
        let domains = list_domains(&cp);
        assert_eq!(domains.len(), n);
        let (rows, errors) = validate(&cp, &server_dns(), &domains);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(rows.len(), n, "every chunk's domains are matched by name");
        assert!(
            rows.iter()
                .all(|r| r.spf.state == State::Ok && r.dkim.state == State::Ok),
            "a fixture holding every domain answers each chunk"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_validator_call_leaves_unknown_cells() {
        let root = server_tree("failed");
        write(&root, "/_cmd/acctdns_spfs.txt", DENIED_REPLY);
        let _ = std::fs::remove_file(root.join("_cmd/acctdns_authority.txt"));
        let cp = Cp { root: root.clone() };
        let (rows, errors) = validate(&cp, &server_dns(), &list_domains(&cp));
        assert_eq!(rows.len(), 6);
        assert!(errors.iter().any(|e| e.contains("Access denied")));
        assert!(errors.iter().any(|e| e.contains("acctdns_authority")));
        let r = &rows[0];
        assert_eq!(r.spf.state, State::Unknown);
        assert_eq!(r.spf.level, Level::Unknown);
        assert!(!r.dkim.fixable, "without the zone answer a fix is a guess");
        assert!(r
            .dkim
            .fix_note
            .as_deref()
            .unwrap()
            .contains("did not say where the zone lives"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn json_survives_a_round_trip() {
        let root = server_tree("json");
        let cp = Cp { root: root.clone() };
        let (rows, _) = validate(&cp, &server_dns(), &list_domains(&cp));
        let scan = Scan {
            id: "abcd1234".into(),
            started: 1_700_000_000,
            finished: Some(1_700_000_030),
            done: true,
            total: rows.len(),
            rows,
            errors: vec!["validate_current_spfs: Access denied".into()],
            panel: "cPanel / WHM".into(),
            supported: true,
        };
        let text = scan.to_json().to_string();
        let back = Scan::from_json(&Json::parse(&text).unwrap());
        assert_eq!(back, scan);
        // the field names the daemon and the UI read
        let v = Json::parse(&text).unwrap();
        for key in [
            "id",
            "started",
            "finished",
            "done",
            "total",
            "rows",
            "errors",
            "panel",
            "supported",
        ] {
            assert!(v.get(key).is_some(), "{key} missing from the scan JSON");
        }
        let row = &v.get("rows").unwrap().as_array().unwrap()[0];
        for key in [
            "domain",
            "user",
            "kind",
            "mail",
            "zone",
            "spf",
            "dkim",
            "dmarc",
            "level",
            "checked_at",
        ] {
            assert!(row.get(key).is_some(), "{key} missing from a row");
        }
        let check = row.get("spf").unwrap();
        for key in [
            "state",
            "level",
            "raw_state",
            "summary",
            "detail",
            "current",
            "expected",
            "suggested",
            "suggested_value",
            "fixable",
            "fix_note",
            "notes",
        ] {
            assert!(check.get(key).is_some(), "{key} missing from a check");
        }
        let unfinished = Scan {
            finished: None,
            done: false,
            ..scan
        };
        assert_eq!(
            Scan::from_json(&Json::parse(&unfinished.to_json().to_string()).unwrap()),
            unfinished
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- repairs --------------------------------------------------------------

    #[test]
    fn fix_validates_its_arguments_and_runs_the_installers() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = server_tree("fix");
        let srv = testsupport::start(Box::new(|_, _| Some((0, vec![], false))), false);
        std::env::set_var("MSFE_NG_RESOLVER", srv.addr.to_string());
        let cp = Cp { root: root.clone() };

        let err = fix(&cp, "not a domain", What::Spf, None).unwrap_err();
        assert!(err.error.contains("is not a domain name"));
        let err = fix(&cp, "other.example.net", What::Spf, None).unwrap_err();
        assert!(err.error.contains("not a domain of an account"));
        let err = fix(&cp, "example.com", What::Spf, Some("junk")).unwrap_err();
        assert!(err.error.contains("must start with v=spf1"));
        let err = fix(
            &cp,
            "example.com",
            What::Spf,
            Some("v=spf1 ip4:192.0.2.10 \" ~all"),
        )
        .unwrap_err();
        assert!(err.error.contains("quotes"));
        let long = format!("v=spf1 {}~all", "include:a.example.net ".repeat(30));
        let err = fix(&cp, "example.com", What::Spf, Some(&long)).unwrap_err();
        assert!(err.error.contains("limit 450"), "{}", err.error);
        let err = fix(&cp, "example.com", What::Dmarc, Some("p=none")).unwrap_err();
        assert!(err.error.contains("must start with v=DMARC1"));

        // DMARC with no local zone: refused, with the record to publish there
        let err = fix(&cp, "addon.example.net", What::Dmarc, None).unwrap_err();
        assert!(err
            .error
            .contains("publish it at the domain's own name servers"));
        assert_eq!(err.actions.len(), 1);
        assert!(err.actions[0].starts_with("_dmarc.addon.example.net. 14400 IN TXT \"v=DMARC1;"));

        // SPF: the suggested record is installed and quoted in the transcript
        let rep = fix(&cp, "shop.example.com", What::Spf, None).unwrap();
        assert_eq!(
            rep.actions[0],
            "whmapi1 install_spf_records domain=shop.example.com record='v=spf1 +mx +a ip4:192.0.2.10 ~all'"
        );
        assert_eq!(rep.actions[1], "OK");
        assert!(rep
            .actions
            .last()
            .unwrap()
            .contains("resolvers keep the old answer"));
        assert_eq!(rep.row.unwrap().domain.domain, "shop.example.com");

        // DKIM: both calls, in order
        let rep = fix(&cp, "example.com", What::Dkim, None).unwrap();
        assert_eq!(
            rep.actions[0],
            "whmapi1 ensure_dkim_keys_exist domain=example.com"
        );
        assert_eq!(rep.actions[2], "whmapi1 enable_dkim domain=example.com");
        assert_eq!(rep.row.as_ref().unwrap().dkim.state, State::Mismatch);

        // DMARC into a local zone, with the admin's own record
        let rep = fix(
            &cp,
            "example.org",
            What::Dmarc,
            Some("v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org"),
        )
        .unwrap();
        assert_eq!(
            rep.actions[0],
            "whmapi1 addzonerecord domain=example.org name=_dmarc.example.org. type=TXT ttl=14400 txtdata='v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org'"
        );

        // cPanel refusing the call is an error carrying the transcript
        write(&root, "/_cmd/acctdns_fix_spf.txt", DENIED_REPLY);
        let err = fix(&cp, "shop.example.com", What::Spf, Some("v=spf1 +mx ~all")).unwrap_err();
        assert_eq!(err.error, "Access denied");
        assert!(err.actions[0].starts_with("whmapi1 install_spf_records"));
        assert!(err.actions[1].contains("failed: Access denied"));

        // an unsupported host refuses before anything runs
        let bare = Cp {
            root: tmpdir("fix-bare"),
        };
        assert!(fix(&bare, "example.com", What::Spf, None)
            .unwrap_err()
            .error
            .contains("needs cPanel"));

        std::env::remove_var("MSFE_NG_RESOLVER");
        let _ = std::fs::remove_dir_all(&root);
    }

    // ---- the registry ---------------------------------------------------------

    #[test]
    fn the_registry_runs_one_scan_and_keeps_the_last() {
        let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = server_tree("scan");
        let store = root.join("acctdns.json");
        let srv = dns_server(SERVER_TXTS);
        std::env::set_var("MSFE_NG_RESOLVER", srv.addr.to_string());
        std::env::set_var("MSFE_NG_CPANEL_ROOT", &root);
        std::env::set_var("MSFE_NG_ACCTDNS_FILE", &store);
        let cfg = Config::default();
        reset();

        // a scan already running is not started twice
        with_scan(|slot| {
            *slot = Some(Live {
                scan: Scan {
                    id: "running1".into(),
                    started: now_secs(),
                    finished: None,
                    done: false,
                    total: 1,
                    rows: Vec::new(),
                    errors: Vec::new(),
                    panel: "cPanel / WHM".into(),
                    supported: true,
                },
                at: std::time::Instant::now(),
            });
        });
        assert_eq!(start(&cfg, None), Err(StartError::Busy("running1".into())));
        reset();

        assert_eq!(
            start(
                &cfg,
                Some(Filter {
                    user: Some("no user!".into()),
                    domain: None
                })
            ),
            Err(StartError::Invalid(
                "'no user!' is not an account name".into()
            ))
        );
        assert!(matches!(
            start(
                &cfg,
                Some(Filter {
                    user: None,
                    domain: Some("nope".into())
                })
            ),
            Err(StartError::Invalid(_))
        ));

        let id = start(&cfg, None).unwrap();
        let snap = snapshot().unwrap();
        assert_eq!(snap.id, id);
        assert_eq!(snap.total, 6);
        assert!(snap.supported && snap.panel.contains("cPanel"));
        let done = loop_until_done();
        assert!(done.done && done.finished.is_some());
        assert_eq!(done.rows.len(), 6);
        assert!(done.errors.is_empty(), "{:?}", done.errors);
        assert_eq!(
            done.rows.iter().filter(|r| r.level == Level::Fail).count(),
            4,
            "the main domain, the addon, the subdomain and the other account"
        );

        // the finished scan is on disk and comes back when memory is empty
        assert!(store.exists());
        let mode = std::fs::metadata(&store).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(mode.permissions().mode() & 0o777, 0o600);
        reset();
        assert!(snapshot().is_none());
        let from_disk = last().unwrap();
        assert_eq!(from_disk.id, id);
        assert_eq!(from_disk.rows.len(), 6);

        // one account only
        reset();
        let id2 = start(
            &cfg,
            Some(Filter {
                user: Some("bob".into()),
                domain: None,
            }),
        )
        .unwrap();
        assert_ne!(id2, id);
        let one = loop_until_done();
        assert_eq!(one.total, 1);
        assert_eq!(one.rows[0].domain.domain, "example.org");
        assert_eq!(
            Scan::from_json(&Json::parse(&std::fs::read_to_string(&store).unwrap()).unwrap()).id,
            id,
            "a filtered scan does not replace the last full one"
        );

        // and check_one, the inline path a fix uses
        let cp = Cp { root: root.clone() };
        let client = Client::system();
        assert!(
            check_one(&cp, &client, "EXAMPLE.ORG.").is_some(),
            "name folded"
        );
        assert!(check_one(&cp, &client, "other.example.net").is_none());

        // an unsupported host
        reset();
        std::env::set_var("MSFE_NG_CPANEL_ROOT", tmpdir("scan-bare"));
        assert_eq!(start(&cfg, None), Err(StartError::Unsupported));

        reset();
        std::env::remove_var("MSFE_NG_ACCTDNS_FILE");
        std::env::remove_var("MSFE_NG_CPANEL_ROOT");
        std::env::remove_var("MSFE_NG_RESOLVER");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Wait for the running scan to finish (a fixture scan takes milliseconds).
    fn loop_until_done() -> Scan {
        for _ in 0..500 {
            if let Some(s) = snapshot() {
                if s.done {
                    return s;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the scan did not finish");
    }
}
