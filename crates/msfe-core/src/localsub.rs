//! Local submission privacy (issue #15).
//!
//! Webmail submits to Exim over authenticated SMTP on loopback, and Exim's
//! stock `received_header_text` then prints the sending host: every webmail
//! message leaves with `Received: from localhost (server.name) [127.0.0.1]`.
//! Rewriting `Received:` after reception would break tracing, so the fix is
//! Exim's own template, with one condition — an authenticated submission from
//! 127.0.0.0/8 or ::1 gets no `from` clause (RFC 5321 allows that; `with
//! esmtpsa` still says it was authenticated). Every other hop prints exactly
//! as before.
//!
//! The template goes into the `@CONFIG@` section of `/etc/exim.conf.local`,
//! cPanel's supported override that `/scripts/buildeximconf` merges into
//! `/etc/exim.conf`, so it survives every rebuild. The state lives on disk
//! only (our marker block); each change keeps a byte-for-byte backup of
//! `exim.conf.local`, is validated by Exim itself and rolled back when Exim
//! does not accept it.

use crate::config::Config;
use crate::json::Json;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const START_MARKER: &str = "# --- MSFE-NG local submission privacy start ---";
pub const END_MARKER: &str = "# --- MSFE-NG local submission privacy end ---";
/// cPanel's section for main-configuration settings in `exim.conf.local`.
pub const SECTION: &str = "@CONFIG@";
pub const OPTION: &str = "received_header_text";

/// What our block sets: Exim's stock text with the loopback guard. Each
/// continued line ends with a backslash (Exim joins them and drops the
/// next line's leading whitespace).
pub const TEMPLATE: &str = r"received_header_text = Received: ${if and{{def:authenticated_id}{match_ip{$sender_host_address}{<; 127.0.0.0/8 ; ::1}}}\
  {}\
  {${if def:sender_rcvhost {from $sender_rcvhost\n\t}{${if def:sender_ident {from ${quote_local_part:$sender_ident} }}${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}}}\
  by $primary_hostname ${if def:received_protocol {with $received_protocol }}${if def:tls_in_ver { ($tls_in_ver)}}${if def:tls_in_cipher_std { tls $tls_in_cipher_std\n\t}}(Exim $version_number)\n\t${if def:sender_address {(envelope-from <$sender_address>)\n\t}}id $message_exim_id${if def:received_for {\n\tfor $received_for}}";

/// Exim's built-in `received_header_text` (what applies when nothing sets
/// it, as on a stock cPanel host).
pub const STOCK: &str = r"Received: ${if def:sender_rcvhost {from $sender_rcvhost\n\t}{${if def:sender_ident {from ${quote_local_part:$sender_ident} }}${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}by $primary_hostname ${if def:received_protocol {with $received_protocol }}${if def:tls_in_ver { ($tls_in_ver)}}${if def:tls_in_cipher_std { tls $tls_in_cipher_std\n\t}}(Exim $version_number)\n\t${if def:sender_address {(envelope-from <$sender_address>)\n\t}}id $message_exim_id${if def:received_for {\n\tfor $received_for}}";

const EXIM: &str = "/usr/sbin/exim";
const BUILDEXIMCONF: &str = "/scripts/buildeximconf";
const RESTARTSRV_EXIM: &str = "/scripts/restartsrv_exim";
const KEEP_BACKUPS: usize = 10;

/// cPanel's Roundcube configuration, in the order Roundcube reads it (the
/// last value wins).
pub const ROUNDCUBE_CONFIGS: [&str; 3] = [
    "/usr/local/cpanel/base/3rdparty/roundcube/config/defaults.inc.php",
    "/usr/local/cpanel/base/3rdparty/roundcube/config/config.inc.php",
    "/var/cpanel/roundcube/config.inc.php",
];

pub fn exim_conf_local() -> PathBuf {
    crate::diaginbox::exim_conf_local()
}

pub fn backup_root(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .join("localsub")
}

fn skip_cmds() -> bool {
    std::env::var_os("MSFE_NG_SKIP_EXIM_CMDS").is_some()
}

/// cPanel only: `exim.conf.local` is cPanel's mechanism. The test override
/// of that file counts as cPanel, like the diagnostic inbox.
pub fn applicable(cfg: &Config) -> bool {
    cfg.panel == "cpanel" || std::env::var_os("MSFE_NG_EXIM_CONF_LOCAL").is_some()
}

// ---- the Exim configuration as text --------------------------------------------

/// Logical lines (continuations joined, the next line's leading whitespace
/// dropped as Exim does), each with the 1-based number of its first line.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out: Vec<(usize, String)> = Vec::new();
    let mut cur: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let piece = match &cur {
            Some(_) => raw.trim_start(),
            None => raw,
        };
        let (body, cont) = match piece.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (piece, false),
        };
        match &mut cur {
            Some((_, s)) => s.push_str(body),
            None => cur = Some((i + 1, body.to_string())),
        }
        if !cont {
            out.extend(cur.take());
        }
    }
    out.extend(cur.take());
    out
}

/// The value a main-section line gives `received_header_text`, if any:
/// `(line number, value)`. Only the main section counts (before the first
/// `begin`); comments are skipped.
pub fn setting_in(text: &str) -> Option<(usize, String)> {
    for (n, l) in logical_lines(text) {
        let t = l.trim_start();
        if t.starts_with('#') {
            continue;
        }
        if t.split_whitespace().next() == Some("begin") {
            break;
        }
        if let Some(rest) = t.strip_prefix(OPTION) {
            if let Some(v) = rest.trim_start().strip_prefix('=') {
                return Some((n, v.trim().to_string()));
            }
        }
    }
    None
}

/// `text` without our block anywhere.
fn strip_block(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut skipping = false;
    for l in text.lines() {
        if l.trim() == START_MARKER {
            skipping = true;
            continue;
        }
        if l.trim() == END_MARKER {
            skipping = false;
            continue;
        }
        if !skipping {
            lines.push(l.to_string());
        }
    }
    lines
}

/// The lines of `exim.conf.local`'s `@CONFIG@` section, our block excluded.
fn config_section(text: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for l in strip_block(text) {
        let t = l.trim();
        if t.starts_with('@') && t.ends_with('@') && t.len() > 2 {
            inside = t == SECTION;
            continue;
        }
        if inside {
            out.push(l);
        }
    }
    out.join("\n")
}

/// Our block is in `exim.conf.local`.
pub fn block_present(text: &str) -> bool {
    text.lines().any(|l| l.trim() == START_MARKER)
}

fn block_lines() -> Vec<String> {
    let mut b = vec![
        START_MARKER.to_string(),
        "# Authenticated submissions from loopback (webmail) get no `from` clause;".to_string(),
        "# every other hop prints as before. `msfe-ng localsub off` removes this.".to_string(),
    ];
    b.extend(TEMPLATE.lines().map(str::to_string));
    b.push(END_MARKER.to_string());
    b
}

/// `exim.conf.local` with our block right under `@CONFIG@` (the marker is
/// added at the end when missing), or without it. Any earlier block of ours,
/// wherever it is, goes first. Returns the new text and whether it changed.
pub fn splice(text: &str, install: bool) -> (String, bool) {
    let mut lines = strip_block(text);
    if install {
        let block = block_lines();
        match lines.iter().position(|l| l.trim() == SECTION) {
            Some(i) => {
                for (k, b) in block.into_iter().enumerate() {
                    lines.insert(i + 1 + k, b);
                }
            }
            None => {
                if lines.last().is_some_and(|l| !l.trim().is_empty()) {
                    lines.push(String::new());
                }
                lines.push(SECTION.to_string());
                lines.extend(block);
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    let changed = out != text && !(text.is_empty() && !install);
    (out, changed)
}

// ---- verdicts ------------------------------------------------------------------

/// What Exim's effective `received_header_text` does with webmail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effective {
    /// Our template, exactly.
    Ours,
    /// Another text that hides the loopback hop: a hand-written guard, or a
    /// template that never prints the sending host.
    Hand,
    /// Prints the sending host for every hop (the stock text).
    Exposes,
    /// Exim did not answer and its configuration cannot be read.
    Unknown,
}

impl Effective {
    pub fn as_str(&self) -> &'static str {
        match self {
            Effective::Ours => "ours",
            Effective::Hand => "hand",
            Effective::Exposes => "exposes",
            Effective::Unknown => "unknown",
        }
    }
    /// The loopback hop is hidden.
    pub fn hides(&self) -> bool {
        matches!(self, Effective::Ours | Effective::Hand)
    }
}

fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// The value our template gives the option, continuations joined.
pub fn template_value() -> String {
    setting_in(TEMPLATE).map(|(_, v)| v).unwrap_or_default()
}

fn has_guard(squashed: &str) -> bool {
    squashed.contains("def:authenticated_id")
        && (squashed.contains("match_ip{$sender_host_address}")
            || squashed.contains("match_ip{${sender_host_address}}"))
}

/// Classify a `received_header_text` value, as `exim -bP` prints it (with or
/// without the `received_header_text =` prefix) or as a configuration file
/// sets it. The exact text is not required for "hides": an equivalent guard
/// written by hand counts.
pub fn verdict(value: &str) -> Effective {
    let mut v = value.trim();
    if let Some(r) = v.strip_prefix(OPTION) {
        v = r.trim_start().strip_prefix('=').unwrap_or(r).trim();
    }
    if v.is_empty() {
        return Effective::Unknown;
    }
    let s = squash(v);
    if s == squash(&template_value()) {
        return Effective::Ours;
    }
    if has_guard(&s) {
        return Effective::Hand;
    }
    let host = [
        "$sender_rcvhost",
        "${sender_rcvhost}",
        "$sender_host_address",
        "${sender_host_address}",
        "$sender_fullhost",
        "${sender_fullhost}",
        "$sender_host_name",
        "${sender_host_name}",
    ];
    if host.iter().any(|h| s.contains(h)) {
        Effective::Exposes
    } else {
        Effective::Hand
    }
}

/// Where `received_header_text` is already set outside our block, which
/// would make Exim refuse the configuration once ours is added (an option
/// set twice): `exim.conf.local`'s `@CONFIG@` section first, then
/// `exim.conf` itself (unless what it holds is our own text from an earlier
/// build). `None` when installing is safe.
pub fn find_conflict(
    conf_local: &str,
    local_name: &str,
    exim_conf: &str,
    exim_name: &str,
) -> Option<String> {
    if let Some((_, v)) = setting_in(&config_section(conf_local)) {
        return Some(format!(
            "{local_name} already sets {OPTION} in its {SECTION} section ({OPTION} = {})",
            clip(&v, 80)
        ));
    }
    let (n, v) = setting_in(exim_conf)?;
    if verdict(&v) == Effective::Ours {
        return None;
    }
    Some(format!(
        "{exim_name} line {n} already sets {OPTION} ({OPTION} = {})",
        clip(&v, 80)
    ))
}

fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// What the doctor says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorVerdict {
    Ok(String),
    /// Exposed, our block not installed.
    Exposed(String),
    /// Our block is in `exim.conf.local` but Exim does not use it.
    NotInEffect(String),
    /// Nothing to say (Exim's setting cannot be read).
    Silent,
}

pub fn doctor_verdict(
    installed: bool,
    effective: Effective,
    conflict: Option<&str>,
) -> DoctorVerdict {
    match (effective, installed) {
        (e, true) if e.hides() => DoctorVerdict::Ok(
            "Exim prints no host for authenticated loopback submissions (installed by MSFE-NG)"
                .into(),
        ),
        (e, false) if e.hides() => DoctorVerdict::Ok(
            "Exim prints no host for authenticated loopback submissions (by the administrator)"
                .into(),
        ),
        (_, true) => DoctorVerdict::NotInEffect(format!(
            "the MSFE-NG block is in {} but Exim does not use it (cPanel rebuilt exim.conf without it, or the file was edited) — webmail messages still say `from localhost (…) [127.0.0.1]`",
            exim_conf_local().display()
        )),
        (Effective::Exposes, false) => DoctorVerdict::Exposed(match conflict {
            Some(c) => format!(
                "every webmail message carries `Received: from localhost (…) [127.0.0.1]`; {c}, so MSFE-NG cannot add its template — edit that setting by hand"
            ),
            None => "every webmail message carries `Received: from localhost (…) [127.0.0.1]` — Exim's stock header names the loopback hop of an authenticated submission".into(),
        }),
        _ => DoctorVerdict::Silent,
    }
}

// ---- running Exim and cPanel's scripts ----------------------------------------

fn run(argv: &[&str], secs: u64) -> Result<String, String> {
    let (bin, args) = argv.split_first().ok_or("empty command")?;
    let mut c = std::process::Command::new(bin);
    c.args(args);
    match crate::service::run_with_timeout(&mut c, Duration::from_secs(secs)) {
        Ok(o) => {
            let text = format!("{}{}", o.stdout, o.stderr).trim_end().to_string();
            if o.ok {
                Ok(text)
            } else if o.timed_out {
                Err(format!("{bin} did not finish in {secs} s"))
            } else {
                Err(if text.is_empty() {
                    format!("{bin} failed (exit {})", o.code.unwrap_or(-1))
                } else {
                    text
                })
            }
        }
        Err(e) => Err(format!("cannot run {bin}: {e}")),
    }
}

/// The value Exim uses: `exim -bP received_header_text`, falling back to
/// `exim.conf` (where no setting means Exim's stock text). `None` when
/// neither answers.
fn effective_value_at(exim_conf: &Path) -> Option<String> {
    if !skip_cmds() {
        if let Ok(out) = run(&[EXIM, "-bP", OPTION], 10) {
            let line = out.lines().find(|l| l.trim_start().starts_with(OPTION));
            if let Some(v) = line.and_then(|l| l.split_once('=')).map(|(_, v)| v.trim()) {
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    let text = std::fs::read_to_string(exim_conf).ok()?;
    Some(
        setting_in(&text)
            .map(|(_, v)| v)
            .unwrap_or_else(|| STOCK.to_string()),
    )
}

/// The effective template and its verdict.
pub fn effective() -> (Effective, Option<String>) {
    let v = effective_value_at(&crate::engine::exim_conf_path());
    (v.as_deref().map(verdict).unwrap_or(Effective::Unknown), v)
}

/// Our block is in `exim.conf.local`.
pub fn installed() -> bool {
    std::fs::read_to_string(exim_conf_local()).is_ok_and(|t| block_present(&t))
}

/// The conflict on this host, if any.
pub fn conflict() -> Option<String> {
    let local = exim_conf_local();
    let exim = crate::engine::exim_conf_path();
    find_conflict(
        &std::fs::read_to_string(&local).unwrap_or_default(),
        &local.display().to_string(),
        &std::fs::read_to_string(&exim).unwrap_or_default(),
        &exim.display().to_string(),
    )
}

// ---- preview -------------------------------------------------------------------

/// One simulated hop, expanded with Exim's stock text and with ours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewRow {
    pub ip: String,
    pub label: String,
    /// Our template leaves the host out for this hop.
    pub hidden: bool,
    pub before: String,
    pub after: String,
}

fn expand(template: &str, ip: &str, host: &str) -> Option<String> {
    run(
        &[
            EXIM,
            "-be",
            "-oMa",
            ip,
            "-oMai",
            "user@example.com",
            "-oMr",
            "esmtpsa",
            "-oMs",
            host,
            template,
        ],
        10,
    )
    .ok()
    .filter(|s| !s.trim().is_empty())
}

/// The `Received:` lines Exim would write before and after, for webmail on
/// this server (127.0.0.1 and ::1) and an external authenticated client.
/// Best effort: absent when exim is missing or `-be` fails.
pub fn preview() -> Option<Vec<PreviewRow>> {
    if skip_cmds() || !Path::new(EXIM).exists() {
        return None;
    }
    let ours = template_value();
    [
        ("127.0.0.1", "localhost", "webmail on this server", true),
        ("::1", "localhost", "webmail on this server (IPv6)", true),
        (
            "203.0.113.5",
            "client.example.net",
            "external authenticated client",
            false,
        ),
    ]
    .iter()
    .map(|(ip, host, label, hidden)| {
        Some(PreviewRow {
            ip: ip.to_string(),
            label: label.to_string(),
            hidden: *hidden,
            before: expand(STOCK, ip, host)?,
            after: expand(&ours, ip, host)?,
        })
    })
    .collect()
}

// ---- Roundcube -----------------------------------------------------------------

/// Roundcube's own origin header: with `http_received_header` on, Roundcube
/// adds a `Received:` line naming the browser's address (encrypted with
/// `http_received_header_encrypt`). Read only: cPanel regenerates the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roundcube {
    pub received_header: Option<bool>,
    pub encrypt: Option<bool>,
    /// The files that were read.
    pub files: Vec<String>,
}

/// `$config['<key>'] = <bool>;` in a Roundcube PHP config; `None` when not set
/// (or set to something that is not a plain boolean).
pub fn roundcube_value(php: &str, key: &str) -> Option<bool> {
    let mut found = None;
    for l in php.lines() {
        let t = l.trim();
        if t.starts_with("//") || t.starts_with('#') || t.starts_with('*') || t.starts_with("/*") {
            continue;
        }
        let Some((lhs, rhs)) = t.split_once('=') else {
            continue;
        };
        let lhs = squash(lhs);
        let wanted = [
            format!("$config['{key}']"),
            format!("$config[\"{key}\"]"),
            format!("$rcmail_config['{key}']"),
        ];
        if !wanted.contains(&lhs) {
            continue;
        }
        let v = rhs
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(|c| c == '\'' || c == '"')
            .to_ascii_lowercase();
        found = match v.as_str() {
            "true" | "1" => Some(true),
            "false" | "0" | "" | "null" => Some(false),
            _ => found,
        };
    }
    found
}

pub fn roundcube_state() -> Roundcube {
    let mut r = Roundcube::default();
    for f in ROUNDCUBE_CONFIGS {
        let Ok(t) = std::fs::read_to_string(f) else {
            continue;
        };
        r.files.push(f.to_string());
        if let Some(v) = roundcube_value(&t, "http_received_header") {
            r.received_header = Some(v);
        }
        if let Some(v) = roundcube_value(&t, "http_received_header_encrypt") {
            r.encrypt = Some(v);
        }
    }
    r
}

// ---- backups -------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupInfo {
    pub stamp: String,
    pub at: i64,
    /// "on", "off" or "restore <stamp>": the change this backup preceded.
    pub action: String,
    /// The effective template before the change, when it could be read.
    pub effective_before: Option<String>,
    /// `exim.conf.local` existed (a missing file is restored by removing it).
    pub existed: bool,
    /// The change went through.
    pub applied: bool,
}

impl BackupInfo {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("stamp".into(), Json::str(&self.stamp)),
            ("at".into(), Json::Int(self.at)),
            ("action".into(), Json::str(&self.action)),
            (
                "effective_before".into(),
                self.effective_before
                    .as_deref()
                    .map(Json::str)
                    .unwrap_or(Json::Null),
            ),
            ("existed".into(), Json::Bool(self.existed)),
            ("applied".into(), Json::Bool(self.applied)),
        ])
    }

    pub fn from_json(j: &Json) -> Option<BackupInfo> {
        Some(BackupInfo {
            stamp: j.get("stamp").and_then(Json::as_str)?.to_string(),
            at: j.get("at").and_then(Json::as_i64).unwrap_or(0),
            action: j.str_field("action"),
            effective_before: j
                .get("effective_before")
                .and_then(Json::as_str)
                .map(str::to_string),
            existed: !matches!(j.get("existed"), Some(Json::Bool(false))),
            applied: matches!(j.get("applied"), Some(Json::Bool(true))),
        })
    }
}

fn valid_stamp(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

fn backups_in(root: &Path) -> Vec<BackupInfo> {
    let mut out: Vec<BackupInfo> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|d| {
            let name = d.file_name().to_string_lossy().to_string();
            if !valid_stamp(&name) {
                return None;
            }
            let t = std::fs::read_to_string(d.path().join("state.json")).ok()?;
            BackupInfo::from_json(&Json::parse(&t).ok()?)
        })
        .collect();
    out.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    out
}

/// The backups, newest first.
pub fn backups(config_file: &Path) -> Vec<BackupInfo> {
    backups_in(&backup_root(config_file))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn write_state(root: &Path, info: &BackupInfo) -> std::io::Result<()> {
    std::fs::write(
        root.join(&info.stamp).join("state.json"),
        info.to_json().to_string(),
    )
}

/// Copy `exim.conf.local` (byte for byte) into a new backup directory.
fn take_backup(
    root: &Path,
    current: Option<&[u8]>,
    action: &str,
    effective_before: Option<String>,
) -> std::io::Result<BackupInfo> {
    let at = now();
    let stamp = crate::footers::unique_stamp(root, at);
    let dir = root.join(&stamp);
    std::fs::create_dir_all(&dir)?;
    if let Some(bytes) = current {
        std::fs::write(dir.join("exim.conf.local"), bytes)?;
    }
    let info = BackupInfo {
        stamp,
        at,
        action: action.to_string(),
        effective_before,
        existed: current.is_some(),
        applied: false,
    };
    write_state(root, &info)?;
    Ok(info)
}

fn prune(root: &Path) {
    for b in backups_in(root).into_iter().skip(KEEP_BACKUPS) {
        let _ = std::fs::remove_dir_all(root.join(&b.stamp));
    }
}

// ---- apply / restore -----------------------------------------------------------

/// What an apply or restore did.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub ok: bool,
    pub actions: Vec<String>,
    /// The backup taken before the change.
    pub backup: Option<String>,
    pub dry_run: bool,
}

/// The files one run works on (the live paths, or a fixture's).
#[derive(Debug, Clone)]
pub struct Paths {
    pub conf_local: PathBuf,
    pub exim_conf: PathBuf,
    pub backup_root: PathBuf,
}

impl Paths {
    pub fn live(config_file: &Path) -> Paths {
        Paths {
            conf_local: exim_conf_local(),
            exim_conf: crate::engine::exim_conf_path(),
            backup_root: backup_root(config_file),
        }
    }
}

/// What the validation expects to see in `exim -bP` after the rebuild.
#[derive(Clone, Copy)]
enum Expect {
    Guard,
    NoGuard,
    Valid,
}

/// buildeximconf, then Exim must accept the result and show what was
/// asked for. The transcript lines go to `actions` either way.
fn rebuild_and_validate(actions: &mut Vec<String>, expect: Expect) -> Result<(), String> {
    run(&[BUILDEXIMCONF], 300)
        .map(|_| actions.push(format!("ran {BUILDEXIMCONF}: ok")))
        .map_err(|e| format!("{BUILDEXIMCONF} failed: {e}"))?;
    run(&[EXIM, "-bV"], 10)
        .map(|_| actions.push("exim -bV: the configuration is valid".into()))
        .map_err(|e| format!("exim -bV refuses the configuration: {e}"))?;
    if matches!(expect, Expect::Valid) {
        return Ok(());
    }
    let shown =
        run(&[EXIM, "-bP", OPTION], 10).map_err(|e| format!("exim -bP {OPTION} failed: {e}"))?;
    let hides = verdict(shown.split_once('=').map(|(_, v)| v).unwrap_or(&shown)).hides();
    match (expect, hides) {
        (Expect::Guard, true) => {
            actions.push(format!(
                "exim -bP {OPTION}: the loopback guard is in effect"
            ));
            Ok(())
        }
        (Expect::NoGuard, false) => {
            actions.push(format!(
                "exim -bP {OPTION}: back to a template without the guard"
            ));
            Ok(())
        }
        (Expect::Guard, false) => Err(format!(
            "after the rebuild Exim does not use the template ({})",
            clip(shown.trim(), 160)
        )),
        _ => Err(format!(
            "after the rebuild Exim still uses a guarded template ({})",
            clip(shown.trim(), 160)
        )),
    }
}

fn put_bytes(path: &Path, bytes: Option<&[u8]>) -> std::io::Result<()> {
    match bytes {
        Some(b) => crate::sync::atomic_write(path, b),
        None => match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        },
    }
}

/// What `commit` left behind: `applied` when the new file is in place and
/// Exim accepted it (so the backup is a real undo point), `ok` when Exim
/// was also restarted.
#[derive(Clone, Copy)]
struct Committed {
    applied: bool,
    ok: bool,
}

const FAILED: Committed = Committed {
    applied: false,
    ok: false,
};

/// Write `new`, rebuild and validate; on failure put `previous` back and
/// rebuild again so nothing stays half-applied. Then restart Exim.
fn commit(
    rep: &mut Report,
    path: &Path,
    previous: Option<&[u8]>,
    new: Option<&[u8]>,
    expect: Expect,
) -> Committed {
    if let Err(e) = put_bytes(path, new) {
        rep.actions
            .push(format!("✗ cannot write {}: {e}", path.display()));
        return FAILED;
    }
    rep.actions.push(format!("wrote {}", path.display()));
    if skip_cmds() {
        rep.actions.push(format!("would run: {BUILDEXIMCONF}"));
        rep.actions
            .push("validation skipped (MSFE_NG_SKIP_EXIM_CMDS)".into());
        rep.actions.push(format!("would run: {RESTARTSRV_EXIM}"));
        return Committed {
            applied: true,
            ok: true,
        };
    }
    if let Err(why) = rebuild_and_validate(&mut rep.actions, expect) {
        rep.actions.push(format!("✗ {why}"));
        match put_bytes(path, previous) {
            Ok(()) => rep
                .actions
                .push(format!("put {} back as it was", path.display())),
            Err(e) => rep.actions.push(format!(
                "✗ cannot put {} back: {e} — restore it from the backup",
                path.display()
            )),
        }
        match run(&[BUILDEXIMCONF], 300) {
            Ok(_) => rep
                .actions
                .push(format!("ran {BUILDEXIMCONF} again: ok — nothing changed")),
            Err(e) => rep
                .actions
                .push(format!("✗ {BUILDEXIMCONF} failed after the rollback: {e}")),
        }
        return FAILED;
    }
    match run(&[RESTARTSRV_EXIM], 120) {
        Ok(_) => {
            rep.actions.push(format!("ran {RESTARTSRV_EXIM}: ok"));
            Committed {
                applied: true,
                ok: true,
            }
        }
        Err(e) => {
            rep.actions.push(format!(
                "✗ {RESTARTSRV_EXIM} failed: {e} — the configuration is valid; restart Exim by hand"
            ));
            Committed {
                applied: true,
                ok: false,
            }
        }
    }
}

/// Install (`install = true`) or remove our template. Refuses outside cPanel
/// and when Exim's configuration already sets the option.
pub fn apply(cfg: &Config, config_file: &Path, install: bool, dry: bool) -> Report {
    if !applicable(cfg) {
        return Report {
            actions: vec![
                "✗ local submission privacy is implemented for cPanel's Exim (exim.conf.local) only"
                    .into(),
            ],
            dry_run: dry,
            ..Default::default()
        };
    }
    apply_at(&Paths::live(config_file), install, dry)
}

pub fn apply_at(p: &Paths, install: bool, dry: bool) -> Report {
    let mut rep = Report {
        dry_run: dry,
        ..Default::default()
    };
    let current = std::fs::read(&p.conf_local).ok();
    let text = current
        .as_deref()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default();
    if install {
        let exim = std::fs::read_to_string(&p.exim_conf).unwrap_or_default();
        if let Some(c) = find_conflict(
            &text,
            &p.conf_local.display().to_string(),
            &exim,
            &p.exim_conf.display().to_string(),
        ) {
            rep.actions.push(format!(
                "✗ {c} — Exim refuses an option set twice; remove that setting (or make it hide the loopback hop yourself) and try again"
            ));
            return rep;
        }
    }
    let (new, changed) = splice(&text, install);
    if !changed {
        rep.ok = true;
        rep.actions.push(if install {
            format!(
                "{} already has the template (if Exim does not use it: {BUILDEXIMCONF} && {RESTARTSRV_EXIM})",
                p.conf_local.display()
            )
        } else {
            format!("{} has no MSFE-NG template: nothing to remove", p.conf_local.display())
        });
        return rep;
    }
    let what = if install {
        format!(
            "add the template under {SECTION} in {}",
            p.conf_local.display()
        )
    } else {
        format!("remove the template from {}", p.conf_local.display())
    };
    if dry {
        rep.ok = true;
        rep.actions.push(format!(
            "would back up {} to {}/<stamp>/",
            p.conf_local.display(),
            p.backup_root.display()
        ));
        rep.actions.push(format!("would {what}"));
        rep.actions.push(format!(
            "would run: {BUILDEXIMCONF}, exim -bV, exim -bP {OPTION}, {RESTARTSRV_EXIM}"
        ));
        return rep;
    }
    let before = effective_value_at(&p.exim_conf);
    let mut info = match take_backup(
        &p.backup_root,
        current.as_deref(),
        if install { "on" } else { "off" },
        before,
    ) {
        Ok(i) => i,
        Err(e) => {
            rep.actions.push(format!(
                "✗ cannot write the backup under {}: {e} — nothing changed",
                p.backup_root.display()
            ));
            return rep;
        }
    };
    rep.actions.push(format!(
        "backed up {} to {}",
        p.conf_local.display(),
        p.backup_root.join(&info.stamp).display()
    ));
    rep.backup = Some(info.stamp.clone());
    rep.actions
        .push(format!("{}{}", what[..1].to_uppercase(), &what[1..]));
    let c = commit(
        &mut rep,
        &p.conf_local,
        current.as_deref(),
        Some(new.as_bytes()),
        if install {
            Expect::Guard
        } else {
            Expect::NoGuard
        },
    );
    rep.ok = c.ok;
    if c.applied {
        info.applied = true;
        let _ = write_state(&p.backup_root, &info);
        prune(&p.backup_root);
    } else {
        rep.actions
            .push(format!("backup {} kept, unused", info.stamp));
    }
    rep
}

/// Put `exim.conf.local` back as it was in backup `stamp` (the current file
/// is backed up first, so a restore can itself be undone).
pub fn restore(cfg: &Config, config_file: &Path, stamp: &str, dry: bool) -> Report {
    if !applicable(cfg) {
        return Report {
            actions: vec![
                "✗ local submission privacy is implemented for cPanel's Exim (exim.conf.local) only"
                    .into(),
            ],
            dry_run: dry,
            ..Default::default()
        };
    }
    restore_at(&Paths::live(config_file), stamp, dry)
}

pub fn restore_at(p: &Paths, stamp: &str, dry: bool) -> Report {
    let mut rep = Report {
        dry_run: dry,
        ..Default::default()
    };
    if !valid_stamp(stamp) {
        rep.actions.push("✗ bad backup name".into());
        return rep;
    }
    let dir = p.backup_root.join(stamp);
    let Some(info) = std::fs::read_to_string(dir.join("state.json"))
        .ok()
        .and_then(|t| Json::parse(&t).ok())
        .and_then(|j| BackupInfo::from_json(&j))
    else {
        rep.actions.push(format!("✗ backup {stamp} not found"));
        return rep;
    };
    let saved = if info.existed {
        match std::fs::read(dir.join("exim.conf.local")) {
            Ok(b) => Some(b),
            Err(e) => {
                rep.actions.push(format!(
                    "✗ backup {stamp} has no copy of exim.conf.local: {e}"
                ));
                return rep;
            }
        }
    } else {
        None
    };
    let current = std::fs::read(&p.conf_local).ok();
    if current == saved {
        rep.ok = true;
        rep.actions.push(format!(
            "nothing to restore — {} is already as in backup {stamp}",
            p.conf_local.display()
        ));
        return rep;
    }
    if dry {
        rep.ok = true;
        rep.actions.push(format!(
            "would back up {} and put back the copy from {stamp}",
            p.conf_local.display()
        ));
        rep.actions.push(format!(
            "would run: {BUILDEXIMCONF}, exim -bV, {RESTARTSRV_EXIM}"
        ));
        return rep;
    }
    let before = effective_value_at(&p.exim_conf);
    let mut mine = match take_backup(
        &p.backup_root,
        current.as_deref(),
        &format!("restore {stamp}"),
        before,
    ) {
        Ok(i) => i,
        Err(e) => {
            rep.actions.push(format!(
                "✗ cannot write the backup under {}: {e} — nothing changed",
                p.backup_root.display()
            ));
            return rep;
        }
    };
    rep.backup = Some(mine.stamp.clone());
    rep.actions.push(format!(
        "backed up the current {} to {}",
        p.conf_local.display(),
        p.backup_root.join(&mine.stamp).display()
    ));
    rep.actions.push(format!("putting back backup {stamp}"));
    let c = commit(
        &mut rep,
        &p.conf_local,
        current.as_deref(),
        saved.as_deref(),
        Expect::Valid,
    );
    rep.ok = c.ok;
    if c.applied {
        mine.applied = true;
        let _ = write_state(&p.backup_root, &mine);
        prune(&p.backup_root);
    }
    rep
}

// ---- state ---------------------------------------------------------------------

/// Everything the Settings card and `msfe-ng localsub status` show.
#[derive(Debug, Clone)]
pub struct State {
    pub applicable: bool,
    pub installed: bool,
    pub effective: Effective,
    /// The effective template text, when it could be read.
    pub template: Option<String>,
    pub conflict: Option<String>,
    pub backups: Vec<BackupInfo>,
    pub preview: Option<Vec<PreviewRow>>,
    pub roundcube: Roundcube,
    pub conf_local: PathBuf,
}

pub fn state(cfg: &Config, config_file: &Path) -> State {
    let applicable = applicable(cfg);
    let (effective, template) = if applicable {
        effective()
    } else {
        (Effective::Unknown, None)
    };
    State {
        applicable,
        installed: installed(),
        effective,
        template,
        conflict: if applicable { conflict() } else { None },
        backups: backups(config_file),
        preview: if applicable { preview() } else { None },
        roundcube: if applicable {
            roundcube_state()
        } else {
            Roundcube::default()
        },
        conf_local: exim_conf_local(),
    }
}

pub fn state_json(st: &State) -> Json {
    let opt_s = |v: &Option<String>| v.as_deref().map(Json::str).unwrap_or(Json::Null);
    let opt_b = |v: Option<bool>| v.map(Json::Bool).unwrap_or(Json::Null);
    Json::Object(vec![
        ("applicable".into(), Json::Bool(st.applicable)),
        ("installed".into(), Json::Bool(st.installed)),
        ("effective".into(), Json::str(st.effective.as_str())),
        ("hidden".into(), Json::Bool(st.effective.hides())),
        ("template".into(), opt_s(&st.template)),
        ("conflict".into(), opt_s(&st.conflict)),
        (
            "conf_local".into(),
            Json::str(st.conf_local.display().to_string()),
        ),
        (
            "preview".into(),
            match &st.preview {
                None => Json::Null,
                Some(rows) => Json::Array(
                    rows.iter()
                        .map(|r| {
                            Json::Object(vec![
                                ("ip".into(), Json::str(&r.ip)),
                                ("label".into(), Json::str(&r.label)),
                                ("hidden".into(), Json::Bool(r.hidden)),
                                ("before".into(), Json::str(&r.before)),
                                ("after".into(), Json::str(&r.after)),
                            ])
                        })
                        .collect(),
                ),
            },
        ),
        (
            "roundcube".into(),
            Json::Object(vec![
                (
                    "received_header".into(),
                    opt_b(st.roundcube.received_header),
                ),
                ("encrypt".into(), opt_b(st.roundcube.encrypt)),
                (
                    "files".into(),
                    Json::Array(st.roundcube.files.iter().map(Json::str).collect()),
                ),
            ]),
        ),
        (
            "backups".into(),
            Json::Array(st.backups.iter().map(BackupInfo::to_json).collect()),
        ),
    ])
}

pub fn report_json(r: &Report) -> Json {
    let b = r.backup.clone().map(Json::Str).unwrap_or(Json::Null);
    Json::Object(vec![
        ("ok".into(), Json::Bool(r.ok)),
        ("dry_run".into(), Json::Bool(r.dry_run)),
        ("backup".into(), b.clone()),
        ("stamp".into(), b),
        (
            "transcript".into(),
            Json::Array(r.actions.iter().map(Json::str).collect()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL: &str =
        "@AUTH@\n\n@BEGINACL@\n\n@CONFIG@\nsmtp_banner = hello\n\n@DIRECTOREND@\n\n@ROUTERSTART@\n";

    fn guarded(text: &str) -> bool {
        text.contains(r"match_ip{$sender_host_address}{<; 127.0.0.0/8 ; ::1}}}\")
    }

    #[test]
    fn template_is_the_stock_text_with_one_guard() {
        let v = template_value();
        assert!(v.starts_with("Received: ${if and{{def:authenticated_id}"));
        assert!(!v.contains('\n'), "continuations are joined");
        // braces balance
        let mut depth = 0i32;
        for c in v.chars() {
            match c {
                '{' => depth += 1,
                '}' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0);
        }
        assert_eq!(depth, 0);
        // stripping the guard gives Exim's stock text back
        let body = STOCK.strip_prefix("Received: ").unwrap();
        let (from, rest) = body.split_at(body.find("by $primary_hostname").unwrap());
        let expect = format!(
            "Received: ${{if and{{{{def:authenticated_id}}{{match_ip{{$sender_host_address}}{{<; 127.0.0.0/8 ; ::1}}}}}}{{}}{{{from}}}}}{rest}"
        );
        assert_eq!(v, expect);
        // every continued line ends with a backslash
        let lines: Vec<&str> = TEMPLATE.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[..3].iter().all(|l| l.ends_with('\\')));
        assert!(!lines[3].ends_with('\\'));
    }

    #[test]
    fn splice_round_trip() {
        let (once, changed) = splice(LOCAL, true);
        assert!(changed);
        assert!(once.contains(&format!("@CONFIG@\n{START_MARKER}\n")));
        assert!(once.contains(&format!("{END_MARKER}\nsmtp_banner = hello\n")));
        assert!(guarded(&once));
        assert!(block_present(&once));
        // idempotent
        let (twice, changed2) = splice(&once, true);
        assert!(!changed2);
        assert_eq!(twice, once);
        // and back
        let (back, changed3) = splice(&once, false);
        assert!(changed3);
        assert_eq!(back, LOCAL);
        let (same, changed4) = splice(LOCAL, false);
        assert!(!changed4);
        assert_eq!(same, LOCAL);
        // the section marker is added when missing
        let (added, _) = splice("@AUTH@\nsomething\n", true);
        assert!(added.starts_with("@AUTH@\nsomething\n\n@CONFIG@\n# --- MSFE-NG"));
        let (empty, changed5) = splice("", false);
        assert!(!changed5 && empty == "\n");
        // an older block elsewhere goes; other sections stay as they were
        let stray =
            format!("@ROUTERSTART@\n{START_MARKER}\nold\n{END_MARKER}\nr: x\n@CONFIG@\nk = v\n");
        let (fixed, _) = splice(&stray, true);
        assert_eq!(fixed.matches(START_MARKER).count(), 1);
        assert!(fixed.starts_with("@ROUTERSTART@\nr: x\n@CONFIG@\n# --- MSFE-NG"));
        assert!(fixed.ends_with(&format!("{END_MARKER}\nk = v\n")));
        assert!(!fixed.contains("old"));
    }

    #[test]
    fn verdicts_on_exim_samples() {
        assert_eq!(
            verdict(&format!("received_header_text = {STOCK}")),
            Effective::Exposes
        );
        assert_eq!(verdict(STOCK), Effective::Exposes);
        assert_eq!(
            verdict(&format!("received_header_text = {}", template_value())),
            Effective::Ours
        );
        // how a block in a file reads back, continuations included
        assert_eq!(
            setting_in(TEMPLATE).map(|(_, v)| verdict(&v)),
            Some(Effective::Ours)
        );
        let hand = "Received: ${if and {{def:authenticated_id} {match_ip {$sender_host_address}{127.0.0.1}}}{}{from $sender_rcvhost\\n\\t}}by $primary_hostname id $message_exim_id";
        assert_eq!(verdict(hand), Effective::Hand);
        assert_eq!(
            verdict("received_header_text = Received: by $primary_hostname id $message_exim_id"),
            Effective::Hand
        );
        assert_eq!(verdict(""), Effective::Unknown);
        assert_eq!(verdict("received_header_text ="), Effective::Unknown);
        assert!(Effective::Ours.hides() && Effective::Hand.hides());
        assert!(!Effective::Exposes.hides() && !Effective::Unknown.hides());
    }

    #[test]
    fn conflict_names_the_line() {
        let exim = "primary_hostname = h\nreceived_header_text = Received: from $sender_rcvhost by $primary_hostname\nbegin acl\n";
        let c = find_conflict(LOCAL, "/etc/exim.conf.local", exim, "/etc/exim.conf").unwrap();
        assert!(
            c.starts_with("/etc/exim.conf line 2 already sets received_header_text"),
            "{c}"
        );
        // stock cPanel: not set anywhere
        assert!(find_conflict(LOCAL, "l", "primary_hostname = h\n", "e").is_none());
        // in a later section (an ACL's own text) it does not count
        assert!(find_conflict(LOCAL, "l", "begin acl\nreceived_header_text = x\n", "e").is_none());
        // our own text from an earlier build is not a conflict
        assert!(find_conflict(LOCAL, "l", &format!("{TEMPLATE}\nbegin acl\n"), "e").is_none());
        // set by hand in exim.conf.local's @CONFIG@ section
        let local =
            "@CONFIG@\nreceived_header_text = Received: by $primary_hostname\n@ROUTERSTART@\n";
        let c = find_conflict(local, "/etc/exim.conf.local", "", "e").unwrap();
        assert!(c.contains("/etc/exim.conf.local already sets"), "{c}");
        // our block itself is not a conflict
        let (ours, _) = splice(LOCAL, true);
        assert!(find_conflict(&ours, "l", "", "e").is_none());
    }

    #[test]
    fn doctor_verdicts() {
        assert!(matches!(
            doctor_verdict(true, Effective::Ours, None),
            DoctorVerdict::Ok(d) if d.ends_with("(installed by MSFE-NG)")
        ));
        assert!(matches!(
            doctor_verdict(false, Effective::Hand, None),
            DoctorVerdict::Ok(d) if d.ends_with("(by the administrator)")
        ));
        assert!(matches!(
            doctor_verdict(false, Effective::Exposes, None),
            DoctorVerdict::Exposed(_)
        ));
        assert!(matches!(
            doctor_verdict(false, Effective::Exposes, Some("x sets it")),
            DoctorVerdict::Exposed(d) if d.contains("x sets it")
        ));
        assert!(matches!(
            doctor_verdict(true, Effective::Exposes, None),
            DoctorVerdict::NotInEffect(_)
        ));
        assert!(matches!(
            doctor_verdict(true, Effective::Unknown, None),
            DoctorVerdict::NotInEffect(_)
        ));
        assert_eq!(
            doctor_verdict(false, Effective::Unknown, None),
            DoctorVerdict::Silent
        );
    }

    #[test]
    fn roundcube_values() {
        let php = "<?php\n// $config['http_received_header'] = true;\n$config['http_received_header'] = false;\n$config[ 'http_received_header_encrypt' ] = true ;\n";
        assert_eq!(roundcube_value(php, "http_received_header"), Some(false));
        assert_eq!(
            roundcube_value(php, "http_received_header_encrypt"),
            Some(true)
        );
        assert_eq!(roundcube_value(php, "des_key"), None);
        assert_eq!(
            roundcube_value(
                "$config['http_received_header'] = true;\n$config['http_received_header'] = 0;",
                "http_received_header"
            ),
            Some(false)
        );
    }

    #[test]
    fn apply_and_restore_under_the_env_overrides() {
        let _g1 = crate::engine::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _g2 = crate::diaginbox::tests::ENV
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("msfe-localsub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let local = root.join("exim.conf.local");
        let original = format!("{LOCAL}# trailing bytes kept as they are  \r\n");
        std::fs::write(&local, &original).unwrap();
        std::fs::write(root.join("exim.conf"), "primary_hostname = h\nbegin acl\n").unwrap();
        std::env::set_var("MSFE_NG_EXIM_CONF_LOCAL", &local);
        std::env::set_var("MSFE_NG_EXIM_CONF", root.join("exim.conf"));
        std::env::set_var("MSFE_NG_SKIP_EXIM_CMDS", "1");
        let cfg = Config::default(); // panel "none": the override makes it applicable
        let config_file = root.join("config.toml");

        let st = state(&cfg, &config_file);
        assert!(st.applicable && !st.installed);
        assert_eq!(st.effective, Effective::Exposes); // nothing set: Exim's stock text
        assert!(st.preview.is_none() && st.conflict.is_none());

        // dry run touches nothing
        let r = apply(&cfg, &config_file, true, true);
        assert!(r.ok && r.dry_run && r.backup.is_none(), "{r:?}");
        assert_eq!(std::fs::read_to_string(&local).unwrap(), original);
        assert!(!root.join("localsub").exists());

        let r = apply(&cfg, &config_file, true, false);
        assert!(r.ok, "{r:?}");
        let stamp = r.backup.clone().unwrap();
        assert_eq!(
            std::fs::read(root.join("localsub").join(&stamp).join("exim.conf.local")).unwrap(),
            original.as_bytes()
        );
        assert!(guarded(&std::fs::read_to_string(&local).unwrap()));
        assert!(installed());
        let b = backups(&config_file);
        assert_eq!(b.len(), 1);
        assert!(b[0].applied && b[0].action == "on" && b[0].existed);
        assert_eq!(b[0].effective_before.as_deref(), Some(STOCK));
        // a second "on" changes nothing
        let r = apply(&cfg, &config_file, true, false);
        assert!(r.ok && r.backup.is_none(), "{r:?}");
        assert!(state_json(&state(&cfg, &config_file))
            .to_string()
            .contains("\"installed\":true"));

        // restore is byte-identical (and backs up what it replaces)
        let r = restore(&cfg, &config_file, &stamp, false);
        assert!(r.ok, "{r:?}");
        assert_eq!(std::fs::read_to_string(&local).unwrap(), original);
        assert!(!installed());
        assert_eq!(backups(&config_file).len(), 2);
        let r = restore(&cfg, &config_file, &stamp, false);
        assert!(
            r.ok && r.actions[0].starts_with("nothing to restore"),
            "{r:?}"
        );
        assert!(!restore(&cfg, &config_file, "../x", false).ok);
        assert!(!restore(&cfg, &config_file, "20000101-000000", false).ok);

        // on, then off: the block goes, the rest stays
        assert!(apply(&cfg, &config_file, true, false).ok);
        let r = apply(&cfg, &config_file, false, false);
        assert!(r.ok, "{r:?}");
        assert_eq!(
            std::fs::read_to_string(&local).unwrap(),
            splice(&original, false).0
        );
        let r = apply(&cfg, &config_file, false, false);
        assert!(r.ok && r.actions[0].contains("nothing to remove"), "{r:?}");

        // a conflicting exim.conf: refused before anything is written
        std::fs::write(
            root.join("exim.conf"),
            "received_header_text = Received: from $sender_rcvhost\n",
        )
        .unwrap();
        let before = std::fs::read(&local).unwrap();
        let n = backups(&config_file).len();
        let r = apply(&cfg, &config_file, true, false);
        assert!(
            !r.ok && r.actions[0].contains("line 1 already sets"),
            "{r:?}"
        );
        assert_eq!(std::fs::read(&local).unwrap(), before);
        assert_eq!(backups(&config_file).len(), n);

        // a missing exim.conf.local is created, and restoring removes it again
        std::fs::write(root.join("exim.conf"), "").unwrap();
        std::fs::remove_file(&local).unwrap();
        let r = apply(&cfg, &config_file, true, false);
        assert!(r.ok, "{r:?}");
        assert!(std::fs::read_to_string(&local)
            .unwrap()
            .starts_with("@CONFIG@\n"));
        let r = restore(&cfg, &config_file, r.backup.as_deref().unwrap(), false);
        assert!(r.ok, "{r:?}");
        assert!(!local.exists());

        for v in [
            "MSFE_NG_EXIM_CONF_LOCAL",
            "MSFE_NG_EXIM_CONF",
            "MSFE_NG_SKIP_EXIM_CMDS",
        ] {
            std::env::remove_var(v);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn backups_are_pruned_to_ten() {
        let root = std::env::temp_dir().join(format!("msfe-localsub-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for i in 0..13 {
            let info = BackupInfo {
                stamp: format!("20261015-1000{i:02}"),
                at: i,
                action: "on".into(),
                effective_before: None,
                existed: false,
                applied: true,
            };
            std::fs::create_dir_all(root.join(&info.stamp)).unwrap();
            write_state(&root, &info).unwrap();
        }
        prune(&root);
        let left = backups_in(&root);
        assert_eq!(left.len(), 10);
        assert_eq!(left[0].stamp, "20261015-100012");
        assert_eq!(BackupInfo::from_json(&left[0].to_json()).unwrap(), left[0]);
        let _ = std::fs::remove_dir_all(&root);
    }
}
