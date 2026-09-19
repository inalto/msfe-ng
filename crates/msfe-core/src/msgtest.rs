//! Test-message simulation: what the configured chain would do with a
//! message, without delivering it.
//!
//! Driving `MailScanner --debug` against a hand-built Exim spool is not done
//! here — spool files are Exim-version specific, `--debug` still delivers
//! through the real MTA, and its verdict lines are prose. Instead each stage
//! is asked directly with the same inputs MailScanner gives it: SpamAssassin
//! with MailScanner's `spamassassin.conf` as the run-as user, clamd through
//! `clamdscan`, the attachments against the filename/filetype rules, and the
//! actions resolved through the rulesets with first-match semantics. The
//! result is clearly a *prediction*; `msfe-ng selftest` remains the real
//! end-to-end run.

use crate::json::Json;
use crate::{engine, jobs, mailscanner, mime, msgrammar, rulefile, service, Config};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const JOB: &str = "conf-test-message";
pub const SELFTEST_JOB: &str = "selftest";
pub const GTUBE: &str = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
pub const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".into())
}

/// A ready-made sample: `clean`, `gtube` (SpamAssassin's test string) or
/// `eicar` (the AV test file as an attachment named `eicar.com`, so the
/// filename rules see it too).
pub fn sample_eml(kind: &str) -> Option<String> {
    let host = hostname();
    let head = format!(
        "From: MSFE-NG test <msfe-ng-test@{host}>\r\nTo: root@localhost\r\nDate: Thu, 1 Jan 2026 00:00:00 +0000\r\nMessage-ID: <msfe-ng-test-{kind}@{host}>\r\n"
    );
    Some(match kind {
        "clean" => format!("{head}Subject: MSFE-NG test: clean message\r\n\r\nNothing to see here — a plain test message.\r\n"),
        "gtube" => format!("{head}Subject: MSFE-NG test: GTUBE spam\r\n\r\nThis message carries the GTUBE test string.\r\n\r\n{GTUBE}\r\n"),
        "eicar" => format!(
            "{head}Subject: MSFE-NG test: EICAR attachment\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"msfe-ng-eicar\"\r\n\r\n\
             --msfe-ng-eicar\r\nContent-Type: text/plain\r\n\r\nThe EICAR test file is attached.\r\n\
             --msfe-ng-eicar\r\nContent-Type: application/octet-stream; name=\"eicar.com\"\r\nContent-Disposition: attachment; filename=\"eicar.com\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--msfe-ng-eicar--\r\n",
            crate::b64::encode(EICAR.as_bytes())
        ),
        _ => return None,
    })
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SaVerdict {
    pub ran: bool,
    pub spam: Option<bool>,
    pub score: Option<f64>,
    pub required: Option<f64>,
    pub tests: Vec<String>,
    pub note: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct AvVerdict {
    pub ran: bool,
    pub infected: Option<bool>,
    pub signature: String,
    pub tool: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContentMatch {
    pub filename: String,
    /// `filename.rules.conf` or `filetype.rules.conf` (catalog id).
    pub rule_file: String,
    pub pattern: String,
    pub action: String,
    pub log_text: String,
    /// What was matched: the name, or `file(1)`'s description.
    pub subject: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Predicted {
    pub from: String,
    pub to: String,
    pub outcome: String,
    /// `(directive, value resolved for this sender/recipient)`.
    pub resolved: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct MessageReport {
    pub sample: String,
    pub spamassassin: SaVerdict,
    pub virus: AvVerdict,
    pub content: Vec<ContentMatch>,
    pub predicted: Predicted,
    pub transcript: Vec<String>,
}

impl MessageReport {
    pub fn to_json(&self) -> Json {
        let num = |o: Option<f64>| o.map(|n| Json::Num(format!("{n}"))).unwrap_or(Json::Null);
        let b = |o: Option<bool>| o.map(Json::Bool).unwrap_or(Json::Null);
        Json::Object(vec![
            ("sample".into(), Json::str(&self.sample)),
            (
                "spamassassin".into(),
                Json::Object(vec![
                    ("ran".into(), Json::Bool(self.spamassassin.ran)),
                    ("spam".into(), b(self.spamassassin.spam)),
                    ("score".into(), num(self.spamassassin.score)),
                    ("required".into(), num(self.spamassassin.required)),
                    (
                        "tests".into(),
                        Json::Array(self.spamassassin.tests.iter().map(Json::str).collect()),
                    ),
                    ("note".into(), Json::str(&self.spamassassin.note)),
                ]),
            ),
            (
                "virus".into(),
                Json::Object(vec![
                    ("ran".into(), Json::Bool(self.virus.ran)),
                    ("infected".into(), b(self.virus.infected)),
                    ("signature".into(), Json::str(&self.virus.signature)),
                    ("tool".into(), Json::str(&self.virus.tool)),
                    ("note".into(), Json::str(&self.virus.note)),
                ]),
            ),
            (
                "content".into(),
                Json::Array(
                    self.content
                        .iter()
                        .map(|c| {
                            Json::Object(vec![
                                ("filename".into(), Json::str(&c.filename)),
                                ("rule_file".into(), Json::str(&c.rule_file)),
                                ("pattern".into(), Json::str(&c.pattern)),
                                ("action".into(), Json::str(&c.action)),
                                ("log_text".into(), Json::str(&c.log_text)),
                                ("subject".into(), Json::str(&c.subject)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "predicted".into(),
                Json::Object(vec![
                    ("from".into(), Json::str(&self.predicted.from)),
                    ("to".into(), Json::str(&self.predicted.to)),
                    ("outcome".into(), Json::str(&self.predicted.outcome)),
                    (
                        "resolved".into(),
                        Json::Object(
                            self.predicted
                                .resolved
                                .iter()
                                .map(|(k, v)| (k.clone(), Json::str(v)))
                                .collect(),
                        ),
                    ),
                ]),
            ),
            (
                "transcript".into(),
                Json::Array(self.transcript.iter().map(Json::str).collect()),
            ),
        ])
    }
}

// ---- parsing ---------------------------------------------------------------------

/// The address inside a `From:`/`To:` header value.
pub fn address_of(header_value: &str) -> String {
    let v = header_value.trim();
    if let (Some(a), Some(b)) = (v.find('<'), v.rfind('>')) {
        if a < b {
            return v[a + 1..b].trim().to_ascii_lowercase();
        }
    }
    v.split([',', ' ', ';'])
        .find(|t| t.contains('@'))
        .unwrap_or(v)
        .trim_matches(['"', '<', '>'])
        .to_ascii_lowercase()
}

fn header(raw: &str, name: &str) -> Option<String> {
    let head = raw.split("\n\r\n").next().unwrap_or(raw);
    let head = head.split("\n\n").next().unwrap_or(head);
    let mut out: Option<String> = None;
    for line in head.lines() {
        if let Some(cur) = out.as_mut() {
            if line.starts_with([' ', '\t']) {
                cur.push(' ');
                cur.push_str(line.trim());
                continue;
            }
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.eq_ignore_ascii_case(name) {
                out = Some(v.trim().to_string());
            }
        }
    }
    out
}

/// `X-Spam-Status: Yes, score=1000.0 required=5.0 tests=GTUBE,… autolearn=no`
/// from `spamassassin -t` output (the header may be folded).
pub fn parse_spam_status(out: &str) -> SaVerdict {
    let mut v = SaVerdict {
        ran: true,
        ..Default::default()
    };
    let Some(status) = header(out, "X-Spam-Status") else {
        v.note = "no X-Spam-Status header in SpamAssassin's output".into();
        return v;
    };
    let mut toks = status.split_whitespace();
    if let Some(first) = toks.next() {
        v.spam = Some(first.trim_end_matches(',').eq_ignore_ascii_case("yes"));
    }
    for t in status.split_whitespace() {
        if let Some(s) = t.strip_prefix("score=") {
            v.score = s.parse().ok();
        } else if let Some(r) = t.strip_prefix("required=") {
            v.required = r.parse().ok();
        }
    }
    // `tests=A,B,` may continue on a folded line: take everything up to the
    // next `key=` token
    if let Some(i) = status.find("tests=") {
        v.tests = status[i + 6..]
            .split_whitespace()
            .take_while(|t| !t.contains('='))
            .flat_map(|t| t.split(','))
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
    }
    v
}

/// `path: OK` / `path: Eicar-Test-Signature FOUND` from clamdscan/clamscan.
pub fn parse_clam(out: &str, ok: bool) -> (Option<bool>, String) {
    for l in out.lines() {
        let l = l.trim();
        if let Some(rest) = l.strip_suffix(" FOUND") {
            let sig = rest.rsplit(": ").next().unwrap_or(rest).to_string();
            return (Some(true), sig);
        }
        if l.ends_with(": OK") {
            return (Some(false), String::new());
        }
    }
    if ok {
        (Some(false), String::new())
    } else {
        (None, String::new())
    }
}

// ---- rules ---------------------------------------------------------------------------

/// MailScanner's address glob: `*` matches anything, the rest is literal,
/// case-insensitive; `default` matches everything.
pub fn glob_matches(pattern: &str, addr: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let a = addr.to_ascii_lowercase();
    if p == "default" || p == "*" {
        return true;
    }
    if p.starts_with('/') && p.ends_with('/') {
        return false; // perl regex rule: not evaluated here
    }
    let parts: Vec<&str> = p.split('*').collect();
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        match a[pos..].find(part) {
            Some(at) => {
                if i == 0 && at != 0 {
                    return false;
                }
                pos += at + part.len();
            }
            None => return false,
        }
    }
    parts.last().is_some_and(|l| l.is_empty()) || pos == a.len()
}

pub fn rule_matches(r: &rulefile::Rule, from: &str, to: &str) -> bool {
    let one = |d: rulefile::Direction, p: &str| match d {
        rulefile::Direction::To => glob_matches(p, to),
        rulefile::Direction::From => glob_matches(p, from),
        rulefile::Direction::FromOrTo => glob_matches(p, from) || glob_matches(p, to),
        rulefile::Direction::FromAndTo => glob_matches(p, from) && glob_matches(p, to),
    };
    one(r.direction, &r.pattern)
        && match (&r.and_direction, &r.and_pattern) {
            (Some(d), Some(p)) => one(*d, p),
            _ => true,
        }
}

/// The value a directive resolves to for this sender/recipient: a ruleset's
/// first matching rule, or the plain value. `None` when the directive is
/// absent or the ruleset has no matching rule.
pub fn resolve_directive(conf: &str, key: &str, from: &str, to: &str) -> Option<String> {
    let raw = mailscanner::get_directive(conf, key)?;
    let exp = mailscanner::expand_variables(conf, raw);
    if exp.is_empty() {
        return Some(String::new());
    }
    if exp.ends_with(".rules") || Path::new(&exp).is_file() && exp.contains("/rules/") {
        let text = std::fs::read_to_string(&exp).ok()?;
        return rulefile::rules_of(&rulefile::parse(&text))
            .into_iter()
            .find(|r| rule_matches(r, from, to))
            .map(|r| r.value);
    }
    Some(exp)
}

fn num(v: &str) -> Option<f64> {
    v.trim().parse().ok()
}

pub fn predict(
    conf: &str,
    from: &str,
    to: &str,
    sa: &SaVerdict,
    av: &AvVerdict,
    content: &[ContentMatch],
) -> Predicted {
    let mut p = Predicted {
        from: from.into(),
        to: to.into(),
        ..Default::default()
    };
    let mut res = |k: &str| -> Option<String> {
        let v = resolve_directive(conf, k, from, to);
        if let Some(v) = &v {
            p.resolved.push((k.to_string(), v.clone()));
        }
        v
    };
    let spam_checks = res("Spam Checks").map(|v| {
        !matches!(
            v.to_ascii_lowercase().as_str(),
            "no" | "0" | "off" | "false"
        )
    });
    let required = res("Required SpamAssassin Score")
        .and_then(|v| num(&v))
        .or(sa.required);
    let high = res("High SpamAssassin Score").and_then(|v| num(&v));
    let spam_actions = res("Spam Actions");
    let high_actions = res("High Scoring Spam Actions");
    let non_spam = res("Non Spam Actions");
    let virus_scanning = res("Virus Scanning");
    let deliver_disinfected = res("Deliver Disinfected Files");
    let silent = res("Silent Viruses");
    let notify = res("Notify Senders");
    let mut steps: Vec<String> = Vec::new();

    if av.infected == Some(true) {
        if virus_scanning
            .as_deref()
            .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "no" | "0" | "off"))
        {
            steps.push("virus found by the scanner, but Virus Scanning resolves to 'no' for this sender/recipient — the message passes unscanned".into());
        } else {
            steps.push(format!(
                "virus '{}': the infected part is removed and the message quarantined; a warning replaces it{}{}",
                av.signature,
                deliver_disinfected.as_deref().map(|v| format!("; Deliver Disinfected Files = {v}")).unwrap_or_default(),
                match (&silent, &notify) {
                    (Some(s), Some(n)) => format!("; Silent Viruses = {s}, Notify Senders = {n}"),
                    _ => String::new(),
                }
            ));
        }
    }
    for c in content {
        let a = c.action.to_ascii_lowercase();
        if a.starts_with("deny") || a.starts_with("rename") {
            steps.push(format!(
                "attachment '{}' {} by {} ({}: {})",
                c.filename,
                if a.starts_with("deny+delete") {
                    "deleted"
                } else if a.starts_with("deny") {
                    "blocked"
                } else {
                    "renamed"
                },
                c.rule_file.trim_start_matches("ms:"),
                c.pattern,
                c.log_text
            ));
        }
    }
    match (spam_checks, sa.score) {
        (Some(false), _) => steps.push(format!(
            "Spam Checks = no for this sender/recipient: not checked for spam; delivered per Non Spam Actions = {}",
            non_spam.clone().unwrap_or_else(|| "deliver".into())
        )),
        (_, Some(score)) => {
            let req = required.unwrap_or(5.0);
            if let Some(h) = high.filter(|h| score >= *h) {
                steps.push(format!(
                    "score {score} ≥ High SpamAssassin Score {h}: high-scoring spam → High Scoring Spam Actions = {}",
                    high_actions.clone().unwrap_or_else(|| "(engine default)".into())
                ));
            } else if score >= req {
                steps.push(format!(
                    "score {score} ≥ Required SpamAssassin Score {req}: spam → Spam Actions = {}",
                    spam_actions.clone().unwrap_or_else(|| "(engine default)".into())
                ));
            } else {
                steps.push(format!(
                    "score {score} < Required SpamAssassin Score {req}: not spam → Non Spam Actions = {}",
                    non_spam.clone().unwrap_or_else(|| "deliver".into())
                ));
            }
        }
        _ => steps.push("SpamAssassin verdict unavailable — spam handling not predicted".into()),
    }
    p.outcome = steps.join(" · ");
    p
}

// ---- running the stages ----------------------------------------------------------------

fn find_bin(candidates: &[&str]) -> Option<PathBuf> {
    for c in candidates {
        let p = Path::new(c);
        if p.is_absolute() {
            if p.is_file() {
                return Some(p.to_path_buf());
            }
        } else if let Some(paths) = std::env::var_os("PATH") {
            for d in std::env::split_paths(&paths) {
                let f = d.join(c);
                if f.is_file() {
                    return Some(f);
                }
            }
        }
    }
    None
}

/// A copy of the message the run-as user can read (SpamAssassin runs as it,
/// so the Bayes/AWL state it touches is MailScanner's own).
fn user_readable_copy(eml: &Path, user: &str) -> io::Result<PathBuf> {
    let p = std::env::temp_dir().join(format!("msfe-ng-test-{}.eml", std::process::id()));
    std::fs::copy(eml, &p)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    if let Some((uid, gid)) = crate::confcheck::uid_gid_of(user) {
        let _ = std::os::unix::fs::chown(&p, Some(uid), Some(gid));
    }
    Ok(p)
}

fn run_sa(cfg: &Config, eml: &Path, online: bool, transcript: &mut Vec<String>) -> SaVerdict {
    let Some(sa) = find_bin(&[
        "spamassassin",
        "/usr/local/bin/spamassassin",
        "/usr/bin/spamassassin",
    ]) else {
        transcript.push("spamassassin: not installed".into());
        return SaVerdict {
            note: "spamassassin is not installed".into(),
            ..Default::default()
        };
    };
    let etc = Path::new(&cfg.mailscanner_conf)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into());
    let prefs = etc.join("spamassassin.conf");
    let user = engine::run_user_for(cfg);
    let copy = match user_readable_copy(eml, user) {
        Ok(p) => p,
        Err(e) => {
            transcript.push(format!("cannot stage the message: {e}"));
            return SaVerdict {
                note: format!("cannot stage the message: {e}"),
                ..Default::default()
            };
        }
    };
    let mut cmd;
    let as_user = crate::confcheck::uid_gid_of(user).is_some()
        && find_bin(&["runuser", "/sbin/runuser", "/usr/sbin/runuser"]).is_some();
    if as_user {
        cmd = Command::new("runuser");
        cmd.arg("-u").arg(user).arg("--").arg(&sa);
    } else {
        cmd = Command::new(&sa);
    }
    cmd.arg("-t");
    if prefs.is_file() {
        cmd.arg("-p").arg(&prefs);
    }
    if !online {
        cmd.arg("-L");
    }
    cmd.arg(&copy);
    transcript.push(format!(
        "$ {}spamassassin -t{}{} <message>",
        if as_user {
            format!("runuser -u {user} -- ")
        } else {
            String::new()
        },
        if prefs.is_file() {
            format!(" -p {}", prefs.display())
        } else {
            String::new()
        },
        if online { "" } else { " -L" }
    ));
    let r = service::run_with_timeout(&mut cmd, std::time::Duration::from_secs(180));
    let _ = std::fs::remove_file(&copy);
    match r {
        Ok(o) if o.timed_out => {
            transcript.push("spamassassin did not finish within 180 s".into());
            SaVerdict {
                ran: true,
                note: "timed out after 180 s (network tests? try offline)".into(),
                ..Default::default()
            }
        }
        Ok(o) => {
            let mut v = parse_spam_status(&o.stdout);
            if !o.ok && v.spam.is_none() {
                v.note = format!(
                    "spamassassin exited with an error: {}",
                    o.stderr.lines().last().unwrap_or("").trim()
                );
            }
            for l in o.stderr.lines().filter(|l| !l.trim().is_empty()).take(20) {
                transcript.push(format!("spamassassin: {l}"));
            }
            if let Some(s) = header(&o.stdout, "X-Spam-Status") {
                transcript.push(format!("X-Spam-Status: {s}"));
            }
            v
        }
        Err(e) => {
            transcript.push(format!("cannot run spamassassin: {e}"));
            SaVerdict {
                note: format!("cannot run spamassassin: {e}"),
                ..Default::default()
            }
        }
    }
}

fn run_av(eml: &Path, transcript: &mut Vec<String>) -> AvVerdict {
    let clamd = find_bin(&[
        "clamdscan",
        "/usr/local/cpanel/3rdparty/bin/clamdscan",
        "/usr/bin/clamdscan",
    ]);
    let (tool, mut cmd) = match clamd {
        Some(p) => {
            let mut c = Command::new(&p);
            c.args(["--fdpass", "--no-summary", "--stdout"]).arg(eml);
            (p.display().to_string(), c)
        }
        None => match find_bin(&[
            "clamscan",
            "/usr/local/cpanel/3rdparty/bin/clamscan",
            "/usr/bin/clamscan",
        ]) {
            Some(p) => {
                let mut c = Command::new(&p);
                c.args(["--no-summary", "--stdout"]).arg(eml);
                (p.display().to_string(), c)
            }
            None => {
                transcript.push("clamdscan/clamscan: not installed".into());
                return AvVerdict {
                    note: "no clamdscan or clamscan found — the virus verdict is not simulated"
                        .into(),
                    ..Default::default()
                };
            }
        },
    };
    transcript.push(format!("$ {tool} <message>"));
    match service::run_with_timeout(&mut cmd, std::time::Duration::from_secs(120)) {
        Ok(o) if o.timed_out => AvVerdict {
            ran: true,
            tool,
            note: "the scanner did not answer within 120 s".into(),
            ..Default::default()
        },
        Ok(o) => {
            let out = format!("{}{}", o.stdout, o.stderr);
            for l in out.lines().filter(|l| !l.trim().is_empty()).take(10) {
                transcript.push(format!("clam: {l}"));
            }
            let (infected, signature) = parse_clam(&o.stdout, o.ok || o.code == Some(1));
            AvVerdict {
                ran: true,
                infected,
                signature,
                tool,
                note: if infected.is_none() {
                    format!("scanner error: {}", out.lines().last().unwrap_or("").trim())
                } else {
                    String::new()
                },
            }
        }
        Err(e) => AvVerdict {
            tool,
            note: format!("cannot run the scanner: {e}"),
            ..Default::default()
        },
    }
}

/// Which of `rows` matches `subject` first, by one run of the engine's perl
/// (`/i`, as MailScanner does). `None` when perl is unavailable.
fn first_match_perl(perl: &[String], patterns: &[String], subject: &str) -> Option<Option<usize>> {
    use std::io::Write;
    use std::process::Stdio;
    let exe = perl.first()?;
    let mut child = Command::new(exe)
        .args(perl.iter().skip(1))
        .arg("-e")
        .arg(r#"my $s = <STDIN>; chomp $s; my $i = 0; while (<STDIN>) { chomp; my $ok = eval { $s =~ /$_/i }; if ($ok) { print "$i\n"; exit 0 } $i++ } print "-\n";"#)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        let _ = writeln!(stdin, "{}", subject.replace(['\n', '\r'], " "));
        for p in patterns {
            let _ = writeln!(stdin, "{}", p.replace(['\n', '\r'], " "));
        }
    }
    let out = child.wait_with_output().ok()?;
    let t = String::from_utf8_lossy(&out.stdout);
    Some(t.trim().parse::<usize>().ok())
}

fn content_matches(
    cfg: &Config,
    perl: &[String],
    raw: &[u8],
    transcript: &mut Vec<String>,
) -> Vec<ContentMatch> {
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let etc = Path::new(&cfg.mailscanner_conf)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into());
    let atts = mime::attachments(raw);
    if atts.is_empty() {
        transcript.push("no attachments".into());
        return Vec::new();
    }
    let mut out = Vec::new();
    for (name, bytes) in &atts {
        for (key, by_type) in [("Filename Rules", false), ("Filetype Rules", true)] {
            let Some(v) = mailscanner::get_directive(&conf, key) else {
                continue;
            };
            let file = mailscanner::expand_variables(&conf, v);
            let Ok(text) = std::fs::read_to_string(&file) else {
                continue;
            };
            let table = msgrammar::parse_filename_rules(&text);
            let rows = table.rows();
            let patterns: Vec<String> = rows.iter().map(|r| r.pattern.clone()).collect();
            let subject = if by_type {
                let mut c = Command::new("file");
                c.args(["-b", "-"]);
                use std::io::Write;
                use std::process::Stdio;
                let desc = c
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .ok()
                    .and_then(|mut ch| {
                        ch.stdin.take()?.write_all(bytes).ok()?;
                        ch.wait_with_output().ok()
                    })
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
                match desc {
                    Some(d) if !d.is_empty() => d,
                    _ => continue,
                }
            } else {
                name.clone()
            };
            let id = Path::new(&file)
                .strip_prefix(&etc)
                .map(|r| format!("ms:{}", r.display()))
                .unwrap_or_else(|_| file.clone());
            match first_match_perl(perl, &patterns, &subject) {
                Some(Some(i)) => {
                    let r = rows[i];
                    transcript.push(format!(
                        "{key}: '{subject}' matches {} → {}",
                        r.pattern,
                        r.action.as_string()
                    ));
                    out.push(ContentMatch {
                        filename: name.clone(),
                        rule_file: id,
                        pattern: r.pattern.clone(),
                        action: r.action.as_string(),
                        log_text: r.log_text.clone(),
                        subject,
                    });
                }
                Some(None) => transcript.push(format!("{key}: '{subject}' matches no rule")),
                None => transcript.push(format!("{key}: not checked (no perl)")),
            }
        }
    }
    out
}

/// Simulate the chain over one message file.
pub fn run_message(cfg: &Config, eml: &Path, online: bool) -> io::Result<MessageReport> {
    let raw = std::fs::read(eml)?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let from = header(&text, "From")
        .map(|v| address_of(&v))
        .unwrap_or_default();
    let to = header(&text, "To")
        .map(|v| address_of(&v))
        .unwrap_or_default();
    let mut transcript = Vec::new();
    let lay = crate::layout::resolve(cfg);
    let spamassassin = run_sa(cfg, eml, online, &mut transcript);
    let virus = run_av(eml, &mut transcript);
    let content = content_matches(cfg, &lay.perl, &raw, &mut transcript);
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let predicted = predict(&conf, &from, &to, &spamassassin, &virus, &content);
    Ok(MessageReport {
        sample: eml
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        spamassassin,
        virus,
        content,
        predicted,
        transcript,
    })
}

// ---- job plumbing --------------------------------------------------------------------

pub fn result_path() -> PathBuf {
    jobs::dir().join(format!("{JOB}.result.json"))
}

/// The `msfe-ng` binary the job runs: the one beside the running daemon when
/// there is one (they ship together), else whatever the job's PATH finds.
fn msfe_ng_bin() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("msfe-ng")))
        .filter(|p| p.is_file())
        .map(|p| jobs::sh_quote(&p))
        .unwrap_or_else(|| "msfe-ng".into())
}

/// Start the simulation as a background job over `eml` (a file the daemon
/// wrote); the result lands in `result_path()`.
pub fn start_job(eml: &Path, online: bool) -> io::Result<()> {
    let script = format!(
        "{} conf test-message {} {}--json > {}",
        msfe_ng_bin(),
        jobs::sh_quote(eml),
        if online { "" } else { "--offline " },
        jobs::sh_quote(&result_path())
    );
    jobs::start(JOB, &script, &[])
}

pub fn start_selftest() -> io::Result<()> {
    jobs::start(SELFTEST_JOB, &format!("{} selftest", msfe_ng_bin()), &[])
}

/// The last simulation's result, as the job wrote it.
pub fn last() -> Option<Json> {
    let t = std::fs::read_to_string(result_path()).ok()?;
    Json::parse(&t).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_well_formed_and_eicar_is_an_attachment() {
        for k in ["clean", "gtube", "eicar"] {
            let e = sample_eml(k).unwrap();
            assert!(e.contains("\r\nSubject: MSFE-NG test"));
            assert_eq!(address_of(&header(&e, "To").unwrap()), "root@localhost");
        }
        assert!(sample_eml("gtube").unwrap().contains(GTUBE));
        let atts = mime::attachments(sample_eml("eicar").unwrap().as_bytes());
        assert_eq!(atts.len(), 1);
        assert_eq!(atts[0].0, "eicar.com");
        assert_eq!(atts[0].1, EICAR.as_bytes());
        assert!(sample_eml("bogus").is_none());
    }

    #[test]
    fn spam_status_and_clam_output_parse() {
        let out = "Received: from x\nX-Spam-Checker-Version: SpamAssassin 4.0.0\nX-Spam-Flag: YES\nX-Spam-Status: Yes, score=1000.0 required=5.0 tests=GTUBE,NO_RECEIVED,\n\tNO_RELAYS autolearn=no autolearn_force=no version=4.0.0\nSubject: x\n\nbody\n";
        let v = parse_spam_status(out);
        assert_eq!(v.spam, Some(true));
        assert_eq!(v.score, Some(1000.0));
        assert_eq!(v.required, Some(5.0));
        assert_eq!(v.tests, vec!["GTUBE", "NO_RECEIVED", "NO_RELAYS"]);
        let v = parse_spam_status(
            "X-Spam-Status: No, score=-0.1 required=5.0 tests=none autolearn=ham\n\nx",
        );
        assert_eq!(v.spam, Some(false));
        assert_eq!(v.tests, vec!["none"]);
        assert!(!parse_spam_status("no headers at all").note.is_empty());
        assert_eq!(
            parse_clam("/tmp/x.eml: Eicar-Test-Signature FOUND\n", false),
            (Some(true), "Eicar-Test-Signature".into())
        );
        assert_eq!(
            parse_clam("/tmp/x.eml: OK\n", true),
            (Some(false), String::new())
        );
        assert_eq!(
            parse_clam("ERROR: Can't connect to clamd\n", false),
            (None, String::new())
        );
        assert_eq!(address_of("MSFE <a@b.example>"), "a@b.example");
        assert_eq!(address_of("a@b.example"), "a@b.example");
        assert_eq!(address_of("\"Q\" <A@B.EXAMPLE>, c@d"), "a@b.example");
    }

    #[test]
    fn globs_rules_and_resolution() {
        assert!(glob_matches("default", "x@y"));
        assert!(glob_matches("*@example.com", "bob@example.com"));
        assert!(!glob_matches("*@example.com", "bob@example.org"));
        assert!(glob_matches("bob@*", "bob@anywhere"));
        assert!(glob_matches("*@*.example.com", "a@mail.example.com"));
        assert!(!glob_matches("*@*.example.com", "a@example.com"));
        assert!(glob_matches("Bob@Example.com", "bob@example.com"));
        assert!(
            !glob_matches("/^bob/", "bob@x"),
            "regex rules are not evaluated"
        );
        let r = rulefile::Rule {
            direction: rulefile::Direction::FromAndTo,
            pattern: "*@a.example".into(),
            and_direction: None,
            and_pattern: None,
            value: "yes".into(),
        };
        assert!(rule_matches(&r, "x@a.example", "y@a.example"));
        assert!(!rule_matches(&r, "x@a.example", "y@b.example"));
        let r = rulefile::Rule {
            direction: rulefile::Direction::From,
            pattern: "*@a.example".into(),
            and_direction: Some(rulefile::Direction::To),
            and_pattern: Some("boss@b.example".into()),
            value: "no".into(),
        };
        assert!(rule_matches(&r, "x@a.example", "boss@b.example"));
        assert!(!rule_matches(&r, "x@a.example", "other@b.example"));

        let base = std::env::temp_dir().join(format!("msfe-msgtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let rules = base.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("score.rules"),
            "To: *@vip.example\t3.0\nFromOrTo: default\t6\n",
        )
        .unwrap();
        std::fs::write(rules.join("checks.rules"), "From: *@trusted.example\tno\n").unwrap();
        let conf = format!(
            "%rules-dir% = {r}\nSpam Checks = %rules-dir%/checks.rules\nRequired SpamAssassin Score = %rules-dir%/score.rules\nHigh SpamAssassin Score = 10\nSpam Actions = store\nHigh Scoring Spam Actions = delete\nNon Spam Actions = deliver\n",
            r = rules.display()
        );
        assert_eq!(
            resolve_directive(&conf, "Required SpamAssassin Score", "a@x", "b@vip.example")
                .as_deref(),
            Some("3.0")
        );
        assert_eq!(
            resolve_directive(&conf, "Required SpamAssassin Score", "a@x", "b@y").as_deref(),
            Some("6")
        );
        assert_eq!(
            resolve_directive(&conf, "Spam Checks", "a@trusted.example", "b@y").as_deref(),
            Some("no")
        );
        assert_eq!(
            resolve_directive(&conf, "Spam Checks", "a@x", "b@y"),
            None,
            "no matching rule → engine default"
        );
        assert_eq!(
            resolve_directive(&conf, "Spam Actions", "a@x", "b@y").as_deref(),
            Some("store")
        );
        assert_eq!(resolve_directive(&conf, "Nope", "a", "b"), None);

        let sa = SaVerdict {
            ran: true,
            spam: Some(true),
            score: Some(4.0),
            required: Some(5.0),
            ..Default::default()
        };
        let av = AvVerdict::default();
        let p = predict(&conf, "a@x", "b@vip.example", &sa, &av, &[]);
        assert!(
            p.outcome
                .contains("score 4 ≥ Required SpamAssassin Score 3: spam → Spam Actions = store"),
            "{}",
            p.outcome
        );
        let p = predict(&conf, "a@x", "b@y", &sa, &av, &[]);
        assert!(
            p.outcome.contains("not spam → Non Spam Actions = deliver"),
            "{}",
            p.outcome
        );
        let sa = SaVerdict {
            ran: true,
            spam: Some(true),
            score: Some(1000.0),
            required: Some(5.0),
            ..Default::default()
        };
        let p = predict(&conf, "a@x", "b@y", &sa, &av, &[]);
        assert!(p
            .outcome
            .contains("high-scoring spam → High Scoring Spam Actions = delete"));
        let p = predict(&conf, "a@trusted.example", "b@y", &sa, &av, &[]);
        assert!(p.outcome.contains("Spam Checks = no"));
        let av = AvVerdict {
            ran: true,
            infected: Some(true),
            signature: "Eicar-Test-Signature".into(),
            ..Default::default()
        };
        let c = vec![ContentMatch {
            filename: "eicar.com".into(),
            rule_file: "ms:filename.rules.conf".into(),
            pattern: "\\.com$".into(),
            action: "deny".into(),
            log_text: "DOS executable".into(),
            subject: "eicar.com".into(),
        }];
        let p = predict(&conf, "a@x", "b@y", &sa, &av, &c);
        assert!(p.outcome.contains("virus 'Eicar-Test-Signature'"));
        assert!(p
            .outcome
            .contains("attachment 'eicar.com' blocked by filename.rules.conf"));
        assert!(p
            .resolved
            .iter()
            .any(|(k, v)| k == "Spam Actions" && v == "store"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn report_json_shape() {
        let r = MessageReport {
            sample: "s".into(),
            spamassassin: SaVerdict {
                ran: true,
                spam: Some(false),
                score: Some(0.5),
                required: Some(5.0),
                tests: vec!["A".into()],
                note: String::new(),
            },
            virus: AvVerdict::default(),
            content: vec![],
            predicted: Predicted::default(),
            transcript: vec!["t".into()],
        };
        let j = Json::parse(&r.to_json().to_string()).unwrap();
        assert_eq!(
            j.get("spamassassin")
                .unwrap()
                .get("score")
                .and_then(|s| match s {
                    Json::Num(n) => n.parse::<f64>().ok(),
                    _ => None,
                }),
            Some(0.5)
        );
        assert!(matches!(
            j.get("virus").unwrap().get("infected"),
            Some(Json::Null)
        ));
    }
}
