//! The configuration tester: one run that turns `MailScanner --lint`,
//! `spamassassin --lint` and MSFE-NG's own cross-file checks into a list of
//! findings, each naming the file (and key or line) it is about.
//!
//! With pending edits the run uses the same staged copy a save does
//! (`confstage`) and never touches the live tree — "test my unsaved changes"
//! and "save" are one code path minus the promotion. The lint transcripts are
//! parsed line by line; whatever a parser does not recognise stays in the
//! transcript, which the report carries in full.

use crate::confcatalog;
use crate::confstage::Stage;
use crate::json::Json;
use crate::{confcheck, doctor, layout, msdefs, sa, service, Config};
pub use doctor::Level;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    MailScanner,
    SpamAssassin,
    Msfe,
}

impl Source {
    pub fn as_str(&self) -> &'static str {
        match self {
            Source::MailScanner => "mailscanner",
            Source::SpamAssassin => "spamassassin",
            Source::Msfe => "msfe",
        }
    }
    fn parse(s: &str) -> Source {
        match s {
            "mailscanner" => Source::MailScanner,
            "spamassassin" => Source::SpamAssassin,
            _ => Source::Msfe,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub level: Level,
    pub source: Source,
    /// Catalog id (`ms:rules/bounce.rules`).
    pub file: Option<String>,
    /// Directive (`Virus Scanners`) or SpamAssassin option.
    pub key: Option<String>,
    pub line: Option<u32>,
    pub message: String,
}

impl Finding {
    pub fn new(level: Level, source: Source, message: impl Into<String>) -> Finding {
        Finding {
            level,
            source,
            file: None,
            key: None,
            line: None,
            message: message.into(),
        }
    }
    pub fn file(mut self, id: impl Into<String>) -> Finding {
        self.file = Some(id.into());
        self
    }
    pub fn key(mut self, k: impl Into<String>) -> Finding {
        self.key = Some(k.into());
        self
    }
    pub fn line(mut self, n: u32) -> Finding {
        self.line = Some(n);
        self
    }
    pub fn to_json(&self) -> Json {
        let opt = |o: &Option<String>| o.clone().map(Json::Str).unwrap_or(Json::Null);
        Json::Object(vec![
            ("level".into(), Json::str(self.level.as_str())),
            ("source".into(), Json::str(self.source.as_str())),
            ("file".into(), opt(&self.file)),
            ("key".into(), opt(&self.key)),
            (
                "line".into(),
                self.line.map(|n| Json::Int(n as i64)).unwrap_or(Json::Null),
            ),
            ("message".into(), Json::str(&self.message)),
        ])
    }
    fn from_json(v: &Json) -> Finding {
        Finding {
            level: match v.str_field("level").as_str() {
                "fail" => Level::Fail,
                "warn" => Level::Warn,
                _ => Level::Ok,
            },
            source: Source::parse(&v.str_field("source")),
            file: v.get("file").and_then(Json::as_str).map(str::to_string),
            key: v.get("key").and_then(Json::as_str).map(str::to_string),
            line: v.get("line").and_then(Json::as_i64).map(|n| n as u32),
            message: v.str_field("message"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestReport {
    /// `live` or `staged`.
    pub scope: String,
    pub started: u64,
    pub duration_ms: u64,
    pub findings: Vec<Finding>,
    pub transcripts: Vec<(Source, String)>,
}

impl TestReport {
    /// `(fail, warn, ok)` counts.
    pub fn summary(&self) -> (usize, usize, usize) {
        let n = |l: Level| self.findings.iter().filter(|f| f.level == l).count();
        (n(Level::Fail), n(Level::Warn), n(Level::Ok))
    }
    pub fn to_json(&self) -> Json {
        let (fail, warn, ok) = self.summary();
        Json::Object(vec![
            ("ok".into(), Json::Bool(fail == 0)),
            ("scope".into(), Json::str(&self.scope)),
            ("started".into(), Json::Int(self.started as i64)),
            ("duration_ms".into(), Json::Int(self.duration_ms as i64)),
            (
                "summary".into(),
                Json::Object(vec![
                    ("fail".into(), Json::Int(fail as i64)),
                    ("warn".into(), Json::Int(warn as i64)),
                    ("ok".into(), Json::Int(ok as i64)),
                ]),
            ),
            (
                "findings".into(),
                Json::Array(self.findings.iter().map(Finding::to_json).collect()),
            ),
            (
                "transcripts".into(),
                Json::Object(
                    self.transcripts
                        .iter()
                        .map(|(s, t)| (s.as_str().to_string(), Json::str(t)))
                        .collect(),
                ),
            ),
        ])
    }
    pub fn from_json(v: &Json) -> TestReport {
        TestReport {
            scope: v.str_field("scope"),
            started: v.get("started").and_then(Json::as_i64).unwrap_or(0) as u64,
            duration_ms: v.get("duration_ms").and_then(Json::as_i64).unwrap_or(0) as u64,
            findings: v
                .get("findings")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(Finding::from_json)
                .collect(),
            transcripts: match v.get("transcripts") {
                Some(Json::Object(f)) => f
                    .iter()
                    .map(|(k, t)| (Source::parse(k), t.as_str().unwrap_or("").to_string()))
                    .collect(),
                _ => Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Parts {
    pub ms_lint: bool,
    pub sa_lint: bool,
    pub checks: bool,
}

impl Default for Parts {
    fn default() -> Parts {
        Parts {
            ms_lint: true,
            sa_lint: true,
            checks: true,
        }
    }
}

/// An unsaved edit: the catalog id and the full candidate text.
#[derive(Debug, Clone)]
pub struct PendingEdit {
    pub id: String,
    pub new_text: String,
}

fn level_rank(l: Level) -> u8 {
    match l {
        Level::Fail => 0,
        Level::Warn => 1,
        Level::Ok => 2,
    }
}

/// Perl's `at /path/Module.pm line N.` suffix carries the engine's location,
/// not the conf's — drop it.
pub fn strip_perl_at(l: &str) -> String {
    match l.find(" at /") {
        Some(i) if l[i..].contains(".pm line ") => l[..i].trim_end_matches('.').to_string(),
        _ => l.to_string(),
    }
}

/// `Error in line 12 of /x/rules/bounce.rules` → `(12, "/x/rules/bounce.rules")`.
fn line_of(l: &str) -> Option<(u32, String)> {
    let i = l.find(" line ")?;
    let rest = &l[i + 6..];
    let mut it = rest.split_whitespace();
    let n: u32 = it.next()?.trim_end_matches(':').parse().ok()?;
    let of = it.next()?;
    if of != "of" && of != "in" {
        return None;
    }
    let path = it.next()?.trim_end_matches(['.', ',', ':']);
    Some((n, path.to_string()))
}

/// Findings from a `MailScanner --lint` transcript. `map` turns a path the
/// engine printed into a catalog id (stage or live).
pub fn parse_ms_lint(
    out: &str,
    exit_ok: bool,
    timed_out: bool,
    map: &dyn Fn(&str) -> Option<String>,
) -> Vec<Finding> {
    use Source::MailScanner as MS;
    let mut f = Vec::new();
    if timed_out {
        f.push(Finding::new(
            Level::Fail,
            MS,
            "MailScanner --lint did not finish within 180 s — a virus/spam scanner is probably unreachable (check clamd and its socket)",
        ));
        return f;
    }
    let mut says_scanners: Option<Vec<String>> = None;
    let mut in_sa = false;
    let mut sa_lines: Vec<String> = Vec::new();
    let mut sa_closed = false;
    let mut viruses_found = false;
    for raw in out.lines() {
        let l = raw.trim();
        if l.is_empty() {
            continue;
        }
        let low = l.to_ascii_lowercase();
        if in_sa {
            if low.starts_with("spamassassin reported no errors") {
                in_sa = false;
                sa_closed = true;
                f.push(Finding::new(
                    Level::Ok,
                    Source::SpamAssassin,
                    "SpamAssassin loaded its configuration without errors",
                ));
                continue;
            }
            if low.starts_with("using ")
                || low.starts_with("connected ")
                || low.starts_with("created ")
                || low.starts_with("there are ")
                || low.starts_with("checking ")
                || low.starts_with("mailscanner setting ")
            {
                continue;
            }
            // anything else SpamAssassin printed while loading is a complaint
            sa_lines.push(strip_perl_at(l));
            continue;
        }
        if low.starts_with("checking for spamassassin errors") {
            in_sa = true;
            continue;
        }
        if let Some((n, path)) = line_of(l) {
            if low.contains("error") || low.starts_with("cannot") || low.starts_with("syntax") {
                let mut x = Finding::new(Level::Fail, MS, strip_perl_at(l)).line(n);
                if let Some(id) = map(&path) {
                    x = x.file(id);
                }
                f.push(x);
                continue;
            }
        }
        if let Some(rest) = l.strip_prefix("MailScanner.conf says \"Virus Scanners = ") {
            let list = rest.trim_end_matches('"');
            says_scanners = Some(list.split_whitespace().map(str::to_string).collect());
            continue;
        }
        if let Some(rest) = l.strip_prefix("Found these virus scanners installed:") {
            let found: Vec<&str> = rest.split_whitespace().collect();
            if let Some(want) = says_scanners.take() {
                let missing: Vec<&String> = want
                    .iter()
                    .filter(|w| {
                        !["none", "auto"].contains(&w.as_str()) && !found.contains(&w.as_str())
                    })
                    .collect();
                if missing.is_empty() {
                    f.push(
                        Finding::new(
                            Level::Ok,
                            MS,
                            format!("virus scanners installed: {}", found.join(" ")),
                        )
                        .key("Virus Scanners"),
                    );
                } else {
                    f.push(
                        Finding::new(
                            Level::Fail,
                            MS,
                            format!(
                                "Virus Scanners names {} but the engine found only: {}",
                                missing
                                    .iter()
                                    .map(|s| s.as_str())
                                    .collect::<Vec<_>>()
                                    .join(" "),
                                if found.is_empty() {
                                    "(none)".to_string()
                                } else {
                                    found.join(" ")
                                }
                            ),
                        )
                        .key("Virus Scanners")
                        .file("ms:virus.scanners.conf"),
                    );
                }
            }
            continue;
        }
        if let Some(rest) = l.strip_prefix("Read ") {
            if let Some(i) = rest.find(" hostnames from the phishing ") {
                let n: u64 = rest[..i].trim().parse().unwrap_or(0);
                let which = &rest[i + " hostnames from the phishing ".len()..];
                let (id, key) = if which.starts_with("white") {
                    ("ms:phishing.safe.sites.conf", "Phishing Safe Sites File")
                } else {
                    ("ms:phishing.bad.sites.conf", "Phishing Bad Sites File")
                };
                f.push(
                    Finding::new(
                        if n == 0 { Level::Warn } else { Level::Ok },
                        MS,
                        format!(
                            "{n} hostnames in the phishing {}",
                            which.trim_end_matches('s')
                        ),
                    )
                    .file(id)
                    .key(key),
                );
                continue;
            }
        }
        if low.starts_with("version number in mailscanner.conf") {
            f.push(
                Finding::new(
                    if low.ends_with("is correct.") {
                        Level::Ok
                    } else {
                        Level::Warn
                    },
                    MS,
                    l,
                )
                .key("MailScanner Version Number")
                .file("ms:MailScanner.conf"),
            );
            continue;
        }
        if low.contains("envelope_sender_header") {
            f.push(
                Finding::new(
                    if low.contains("is correct") {
                        Level::Ok
                    } else {
                        Level::Fail
                    },
                    MS,
                    l,
                )
                .file("ms:spamassassin.conf")
                .key("envelope_sender_header"),
            );
            continue;
        }
        if low.starts_with("virus scanning: found ")
            || low.contains(" found ") && low.contains(" infections")
        {
            if !low.contains("found 0 ") {
                viruses_found = true;
            }
            continue;
        }
        if low.starts_with("config: calling custom ") {
            continue;
        }
        if low.starts_with("warning") {
            f.push(Finding::new(Level::Warn, MS, strip_perl_at(l)));
            continue;
        }
        if low.starts_with("cannot ")
            || low.starts_with("can't ")
            || low.starts_with("could not ")
            || low.starts_with("error")
            || low.starts_with("fatal")
            || low.starts_with("syntax error")
            || low.starts_with("died")
            || low.contains(" cannot be a ruleset")
            || (low.contains("value of ") && low.contains(" must be "))
        {
            let mut x = Finding::new(Level::Fail, MS, strip_perl_at(l));
            // `Value of children cannot be a ruleset` → the internal name
            if let Some(rest) = low.strip_prefix("value of ") {
                if let Some(tok) = rest.split_whitespace().next() {
                    x = x.key(tok.trim_matches('"'));
                }
            }
            f.push(x);
            continue;
        }
    }
    if in_sa && !sa_closed {
        f.push(Finding::new(
            Level::Fail,
            Source::SpamAssassin,
            "SpamAssassin did not report a clean load — see the transcript",
        ));
    }
    for s in sa_lines {
        f.push(Finding::new(Level::Warn, Source::SpamAssassin, s));
    }
    if out.contains("Virus Scanner test reports:") {
        f.push(Finding::new(
            if viruses_found {
                Level::Ok
            } else {
                Level::Warn
            },
            MS,
            if viruses_found {
                "the lint test batch caught the EICAR sample — virus scanning works end to end"
            } else {
                "the lint test batch did not flag the EICAR sample — check the virus scanner"
            },
        ));
    }
    if !exit_ok && !f.iter().any(|x| x.level == Level::Fail) {
        f.push(Finding::new(
            Level::Fail,
            MS,
            "MailScanner --lint exited with an error — see the transcript",
        ));
    }
    if f.is_empty() && exit_ok {
        f.push(Finding::new(
            Level::Ok,
            MS,
            "MailScanner --lint reported no problems",
        ));
    }
    f
}

/// Findings from a `spamassassin --lint` transcript.
pub fn parse_sa_lint(
    out: &str,
    exit_ok: bool,
    map: &dyn Fn(&str) -> Option<String>,
) -> Vec<Finding> {
    use Source::SpamAssassin as SA;
    let mut f = Vec::new();
    for l in crate::confsave::sa_lint_problems(out) {
        let low = l.to_ascii_lowercase();
        let path = l
            .find(" in \"")
            .map(|i| &l[i + 5..])
            .and_then(|r| r.split('"').next())
            .map(str::to_string);
        let level = if low.starts_with("config: failed")
            || low.starts_with("lint:")
            || low.contains("error")
        {
            Level::Fail
        } else {
            Level::Warn
        };
        let mut x = Finding::new(level, SA, l.clone());
        if let Some(id) = path.as_deref().and_then(map) {
            x = x.file(id);
        }
        // `config: … option "foo"` / `unknown option`
        if let Some(i) = low.find("option ") {
            let opt = l[i + 7..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(['"', '\'', ',']);
            if !opt.is_empty() {
                x = x.key(opt);
            }
        }
        f.push(x);
    }
    if !exit_ok && !f.iter().any(|x| x.level == Level::Fail) {
        f.push(Finding::new(
            Level::Fail,
            SA,
            "spamassassin --lint exited with an error — see the transcript",
        ));
    }
    if f.is_empty() && exit_ok {
        f.push(
            Finding::new(Level::Ok, SA, "spamassassin --lint found no problems")
                .file("ms:spamassassin.conf"),
        );
    }
    f
}

/// Doctor checks that judge the same chain the tester does; they run once
/// and are mapped into findings, never duplicated.
pub const DOCTOR_CHECKS: &[(&str, Option<&str>, Option<&str>)] = &[
    ("MailScanner.conf found", Some("ms:MailScanner.conf"), None),
    (
        "engine configured for Exim",
        Some("ms:MailScanner.conf"),
        Some("MTA"),
    ),
    (
        "MailScanner reads the Exim message-id format",
        Some("ms:MailScanner.conf"),
        Some("Exim Command"),
    ),
    (
        "rules dir is the engine's %rules-dir%",
        Some("ms:MailScanner.conf"),
        Some("%rules-dir%"),
    ),
    ("SpamAssassin available to MailScanner", None, None),
    (
        "virus scanning (clamd)",
        Some("ms:MailScanner.conf"),
        Some("Clamd Socket"),
    ),
    (
        "SpamAssassin envelope-sender header",
        Some("ms:spamassassin.conf"),
        Some("envelope_sender_header"),
    ),
    (
        "large messages get spam-checked",
        Some("ms:MailScanner.conf"),
        Some("Max Spam Check Size"),
    ),
    (
        "Bayes DB shared with MailScanner",
        Some("ms:MailScanner.conf"),
        Some("SpamAssassin User State Dir"),
    ),
    (
        "DNS blocklists answering",
        Some("ms:MailScanner.conf"),
        Some("Spam List"),
    ),
    (
        "phishing site lists updating",
        Some("ms:phishing.bad.sites.conf"),
        None,
    ),
    (
        "quarantine writable by scan user",
        Some("ms:MailScanner.conf"),
        Some("Quarantine Dir"),
    ),
];

fn doctor_findings(cfg: &Config, config_file: &Path) -> Vec<Finding> {
    doctor::run(cfg, config_file)
        .into_iter()
        .filter_map(|c| {
            let (_, file, key) = DOCTOR_CHECKS.iter().find(|(n, _, _)| *n == c.name)?;
            let mut msg = format!("{}: {}", c.name, c.detail);
            if let (Some(fix), false) = (&c.fix, c.level == Level::Ok) {
                msg.push_str(&format!(" — fix: {fix}"));
            }
            let mut x = Finding::new(c.level, Source::Msfe, msg);
            if let Some(f) = file {
                x = x.file(*f);
            }
            if let Some(k) = key {
                x = x.key(*k);
            }
            Some(x)
        })
        .collect()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn last_path(cfg: &Config) -> std::path::PathBuf {
    Path::new(&cfg.backup_dir).join("tests").join("last.json")
}

/// The most recent report, if one was kept.
pub fn last(cfg: &Config) -> Option<TestReport> {
    let t = std::fs::read_to_string(last_path(cfg)).ok()?;
    Json::parse(&t).ok().map(|v| TestReport::from_json(&v))
}

/// Run the tester over the live tree, or over a staged copy carrying `edits`.
pub fn run(
    cfg: &Config,
    config_file: &Path,
    edits: &[PendingEdit],
    parts: Parts,
) -> io::Result<TestReport> {
    let lay = layout::resolve(cfg);
    run_with(cfg, config_file, edits, parts, &lay.bin, &lay.perl, true)
}

/// `run` with an explicit engine binary and perl (tests), optionally without
/// the doctor pass.
pub fn run_with(
    cfg: &Config,
    config_file: &Path,
    edits: &[PendingEdit],
    parts: Parts,
    bin: &Path,
    perl: &[String],
    with_doctor: bool,
) -> io::Result<TestReport> {
    let t0 = std::time::Instant::now();
    let started = now_secs();
    let live_etc = Path::new(&cfg.mailscanner_conf)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into());
    let mut findings = Vec::new();
    let mut transcripts = Vec::new();

    let ms_edits: Vec<&PendingEdit> = edits.iter().filter(|e| e.id.starts_with("ms:")).collect();
    let stage = if ms_edits.is_empty() {
        None
    } else {
        let mut st = Stage::new(cfg)?;
        for e in &ms_edits {
            let rel = &e.id[3..];
            if let Err(err) = st.apply(rel, &e.new_text) {
                findings.push(
                    Finding::new(
                        Level::Warn,
                        Source::Msfe,
                        format!("{rel}: not staged ({err}); tested as on disk"),
                    )
                    .file(e.id.clone()),
                );
            }
        }
        Some(st)
    };
    let etc = stage
        .as_ref()
        .map(|s| s.etc.clone())
        .unwrap_or(live_etc.clone());
    let map = |p: &str| -> Option<String> {
        match &stage {
            Some(st) => st.to_live_id(p),
            None => {
                let r = live_etc.display().to_string();
                p.strip_prefix(&r)
                    .and_then(|rest| rest.strip_prefix('/'))
                    .map(|rel| format!("ms:{rel}"))
            }
        }
    };
    let conf_text = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap_or_default();

    // syntax of every staged edit, by its kind
    for e in &ms_edits {
        let kind = confcatalog::classify(confcatalog::Root::Ms, &e.id[3..]).0;
        if let Err(m) = crate::confsave::syntax_check(kind, &e.new_text) {
            findings.push(Finding::new(Level::Fail, Source::Msfe, m).file(e.id.clone()));
        }
    }

    if parts.ms_lint {
        let conf = stage.as_ref().map(|s| s.conf());
        let r = service::lint_conf(bin, conf.as_deref());
        if let Some(c) = &conf {
            if !r.timed_out && !r.output.contains(&c.display().to_string()) {
                findings.push(Finding::new(
                    Level::Warn,
                    Source::MailScanner,
                    "the engine read the live configuration instead of the staged copy — the lint below judges the files on disk",
                ));
            }
        }
        findings.extend(parse_ms_lint(&r.output, r.ok, r.timed_out, &map));
        transcripts.push((Source::MailScanner, r.output));
    }
    if parts.sa_lint {
        let prefs = etc.join("spamassassin.conf");
        if prefs.is_file() {
            let (ok, out) = sa::lint_prefs(Some(&prefs));
            findings.extend(parse_sa_lint(&out, ok, &map));
            transcripts.push((Source::SpamAssassin, out));
        }
    }
    if parts.checks {
        let schema = msdefs::load(&layout::resolve(cfg));
        findings.extend(confcheck::run(
            cfg,
            &confcheck::Tree {
                etc: &etc,
                conf: &conf_text,
            },
            schema.as_ref(),
            perl,
        ));
        if with_doctor {
            findings.extend(doctor_findings(cfg, config_file));
        }
    }
    drop(stage);

    findings.sort_by_key(|f| level_rank(f.level));
    let report = TestReport {
        scope: if ms_edits.is_empty() {
            "live".into()
        } else {
            "staged".into()
        },
        started,
        duration_ms: t0.elapsed().as_millis() as u64,
        findings,
        transcripts,
    };
    if let Some(dir) = last_path(cfg).parent() {
        if std::fs::create_dir_all(dir).is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::write(last_path(cfg), report.to_json().to_string());
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINT_OK: &str = "Trying to setlogsock(unix)\n\nReading configuration file /etc/MailScanner/MailScanner.conf\nReading configuration file /etc/MailScanner/conf.d/README\nRead 1492 hostnames from the phishing whitelist\nRead 41239 hostnames from the phishing blacklists\nConfig: calling custom init function MSFENGLogging\n\nChecking version numbers...\nVersion number in MailScanner.conf (5.5.3) is correct.\n\nYour envelope_sender_header in spamassassin.conf is correct.\nMailScanner setting GID to  (12)\nMailScanner setting UID to  (47)\n\nChecking for SpamAssassin errors (if you use it)...\nUsing SpamAssassin results cache\nConnected to SpamAssassin cache database\nSpamAssassin reported no errors.\nConnected to Processing Attempts Database\nCreated Processing Attempts Database successfully\nThere are 87 messages in the Processing Attempts Database\nUsing locktype = posix\nMailScanner.conf says \"Virus Scanners = clamd\"\nFound these virus scanners installed: clamd\n===========================================================================\nFilename Checks: Windows/DOS Executable (1 eicar.com)\nOther Checks: Found 1 problems\nVirus and Content Scanning: Starting\nClamd::INFECTED::Eicar-Test-Signature :: ./1/\nVirus Scanning: Clamd found 2 infections\nInfected message 1 came from 10.1.1.1\nVirus Scanning: Found 2 viruses\n===========================================================================\nVirus Scanner test reports:\nClamd said \"eicar.com was infected: Eicar-Test-Signature\"\n\nIf any of your virus scanners (clamd)\nare not listed there, you should check that they are installed correctly\nConfig: calling custom end function MSFENGLogging\n";

    fn live_map(p: &str) -> Option<String> {
        p.strip_prefix("/etc/MailScanner/")
            .map(|r| format!("ms:{r}"))
    }

    #[test]
    fn clean_lint_transcript_is_all_ok() {
        let f = parse_ms_lint(LINT_OK, true, false, &live_map);
        assert!(f.iter().all(|x| x.level == Level::Ok), "{f:#?}");
        let msgs: Vec<&str> = f.iter().map(|x| x.message.as_str()).collect();
        assert!(msgs
            .iter()
            .any(|m| m.contains("virus scanners installed: clamd")));
        assert!(msgs.iter().any(|m| m.contains("caught the EICAR")));
        assert!(msgs.iter().any(|m| m.contains("SpamAssassin loaded")));
        let ph = f
            .iter()
            .find(|x| x.file.as_deref() == Some("ms:phishing.safe.sites.conf"))
            .unwrap();
        assert_eq!(ph.message, "1492 hostnames in the phishing whitelist");
        let env = f
            .iter()
            .find(|x| x.key.as_deref() == Some("envelope_sender_header"))
            .unwrap();
        assert_eq!(env.file.as_deref(), Some("ms:spamassassin.conf"));
    }

    #[test]
    fn broken_lint_transcript_yields_failures_with_files_and_keys() {
        let bad = "Reading configuration file /opt/b/.stage/1-0/etc/MailScanner.conf\n\
                   Value of children cannot be a ruleset, only a simple value at /usr/share/MailScanner/perl/MailScanner/Config.pm line 3298.\n\
                   Cannot open ruleset file notanumber, No such file or directory at /usr/share/MailScanner/perl/MailScanner/Config.pm line 2633.\n\
                   Error in line 12 of /opt/b/.stage/1-0/etc/rules/bounce.rules\n\
                   Warning: something odd\n\
                   MailScanner.conf says \"Virus Scanners = clamd sophos\"\nFound these virus scanners installed: clamd\n\
                   Checking for SpamAssassin errors (if you use it)...\nconfig: failed to parse line in spamassassin.conf\n";
        let stage_map = |p: &str| {
            p.strip_prefix("/opt/b/.stage/1-0/etc/")
                .map(|r| format!("ms:{r}"))
        };
        let f = parse_ms_lint(bad, false, false, &stage_map);
        let fails: Vec<&Finding> = f.iter().filter(|x| x.level == Level::Fail).collect();
        assert!(fails.iter().any(|x| x.key.as_deref() == Some("children")
            && x.message.starts_with("Value of children cannot")));
        assert!(
            fails
                .iter()
                .any(|x| x.message
                    == "Cannot open ruleset file notanumber, No such file or directory")
        );
        let e = fails.iter().find(|x| x.line == Some(12)).unwrap();
        assert_eq!(e.file.as_deref(), Some("ms:rules/bounce.rules"));
        let vs = fails
            .iter()
            .find(|x| x.key.as_deref() == Some("Virus Scanners"))
            .unwrap();
        assert!(vs.message.contains("sophos"));
        assert!(f
            .iter()
            .any(|x| x.level == Level::Warn && x.message == "Warning: something odd"));
        // SA block never closed → fail, its odd line → warn
        assert!(f
            .iter()
            .any(|x| x.source == Source::SpamAssassin && x.level == Level::Fail));
        assert!(f.iter().any(|x| x.source == Source::SpamAssassin
            && x.level == Level::Warn
            && x.message.contains("failed to parse")));
        assert!(parse_ms_lint("", true, true, &live_map)[0]
            .message
            .contains("180 s"));
        assert_eq!(
            parse_ms_lint("nothing useful\n", true, false, &live_map)[0].level,
            Level::Ok
        );
        assert_eq!(
            parse_ms_lint("nothing useful\n", false, false, &live_map)[0].level,
            Level::Fail
        );
    }

    #[test]
    fn sa_lint_transcripts() {
        let out = "Sep 19 10:00:00 [123] warn: config: failed to parse line, skipping, in \"/etc/MailScanner/spamassassin.conf\": bogus line\n\
                   Sep 19 10:00:00 [123] warn: config: unknown option \"frobnicate\" in \"/etc/MailScanner/spamassassin.conf\"\n\
                   Sep 19 10:00:00 [123] warn: lint: 2 issues detected, please rerun with debug enabled for more information\n";
        let f = parse_sa_lint(out, false, &live_map);
        assert_eq!(f[0].level, Level::Fail);
        assert_eq!(f[0].file.as_deref(), Some("ms:spamassassin.conf"));
        assert_eq!(f[1].level, Level::Warn);
        assert_eq!(f[1].key.as_deref(), Some("frobnicate"));
        assert_eq!(f[2].level, Level::Fail);
        let ok = parse_sa_lint("", true, &live_map);
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].level, Level::Ok);
    }

    #[test]
    fn report_round_trips_through_json() {
        let r = TestReport {
            scope: "staged".into(),
            started: 5,
            duration_ms: 7,
            findings: vec![Finding::new(Level::Fail, Source::Msfe, "x")
                .file("ms:a")
                .key("K")
                .line(3)],
            transcripts: vec![(Source::MailScanner, "t".into())],
        };
        let back = TestReport::from_json(&Json::parse(&r.to_json().to_string()).unwrap());
        assert_eq!(back.scope, "staged");
        assert_eq!(back.findings, r.findings);
        assert_eq!(back.transcripts[0].1, "t");
        assert_eq!(back.summary(), (1, 0, 0));
    }

    #[test]
    fn staged_run_lints_the_copy_and_keeps_the_last_report() {
        let base = std::env::temp_dir().join(format!("msfe-conftest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("rules")).unwrap();
        std::fs::write(
            etc.join("MailScanner.conf"),
            format!(
                "%etc-dir% = {}\nMax Children = 5\nVirus Scanners = none\n",
                etc.display()
            ),
        )
        .unwrap();
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
        let msfe = base.join("etc/msfe-ng");
        std::fs::create_dir_all(&msfe).unwrap();
        let conf = msfe.join("config.toml");
        std::fs::write(&conf, "panel = \"x\"\n").unwrap();
        let bin = base.join("fake");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nc=\"${{2:-{live}}}\"\necho \"Reading configuration file $c\"\nd=$(dirname \"$c\")\nif grep -rq BREAKME \"$d\"; then echo \"Error in line 1 of $d/rules/bounce.rules\"; exit 1; fi\necho ok\n",
                live = etc.join("MailScanner.conf").display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        let parts = Parts {
            ms_lint: true,
            sa_lint: false,
            checks: false,
        };
        let edits = vec![PendingEdit {
            id: "ms:rules/bounce.rules".into(),
            new_text: "FromOrTo: default BREAKME\n".into(),
        }];
        let r = run_with(&cfg, &conf, &edits, parts, &bin, &[], false).unwrap();
        assert_eq!(r.scope, "staged");
        assert_eq!(r.summary().0, 1, "{:#?}", r.findings);
        let f = &r.findings[0];
        assert_eq!(f.file.as_deref(), Some("ms:rules/bounce.rules"));
        assert_eq!(f.line, Some(1));
        assert!(r.transcripts[0].1.contains("/.stage/"));
        // live untouched, stage gone, last report kept
        assert_eq!(
            std::fs::read_to_string(etc.join("rules/bounce.rules")).unwrap(),
            "FromOrTo: default no\n"
        );
        assert_eq!(
            std::fs::read_dir(base.join("backups/.stage"))
                .map(|d| d.count())
                .unwrap_or(0),
            0
        );
        assert_eq!(last(&cfg).unwrap().summary(), (1, 0, 0));
        let r = run_with(&cfg, &conf, &[], parts, &bin, &[], false).unwrap();
        assert_eq!(r.scope, "live");
        assert_eq!(r.summary().0, 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}
