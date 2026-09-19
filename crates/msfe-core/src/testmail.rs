//! A real outbound test message: submitted to this server's own Exim from
//! a hosted address to an external one, then followed through the main log
//! until the remote accepted, refused or kept deferring it. Runs as a
//! background job (`delivery-testmail`) because a delivery can take minutes
//! of retries; the result is a JSON file the API and the tab read.

use crate::config::Config;
use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliverylog::{classify_rejection, parse_mainlog_line, Kind};
use crate::jobs;
use crate::json::Json;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const JOB: &str = "delivery-testmail";
const CAT: Category = Category::TestMail;
const SC: Scope = Scope::Sending;
/// How long the job follows the message before giving up.
pub const FOLLOW_SECS: u64 = 150;

pub fn result_path() -> PathBuf {
    jobs::dir().join(format!("{JOB}.result.json"))
}

fn msfe_ng_bin() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("msfe-ng")))
        .filter(|p| p.is_file())
        .map(|p| jobs::sh_quote(&p))
        .unwrap_or_else(|| "msfe-ng".into())
}

/// `from` must be an address hosted here, `to` a well-formed external one.
pub fn validate(from: &str, to: &str) -> Result<(String, String), String> {
    let (fl, fd) = crate::netguard::parse_address(from)?;
    let (tl, td) = crate::netguard::parse_address(to)?;
    if std::env::var("MSFE_NG_USERDOMAINS_FILE").is_err()
        && crate::users::owner_of_domain(&fd).is_none()
    {
        return Err(format!(
            "{fd} is not hosted on this server — the test message must come from a local address"
        ));
    }
    if std::env::var("MSFE_NG_USERDOMAINS_FILE").is_ok()
        && crate::users::owner_of_domain(&fd).is_none()
    {
        return Err(format!("{fd} is not hosted on this server"));
    }
    Ok((format!("{fl}@{fd}"), format!("{tl}@{td}")))
}

pub fn new_tag() -> String {
    format!(
        "{:x}{:04x}",
        crate::delivery::now_secs(),
        std::process::id() % 0xffff
    )
}

/// Start the job. The result lands in `result_path()`.
pub fn start(from: &str, to: &str, tag: &str) -> std::io::Result<()> {
    let script = format!(
        "{} delivery testmail --from {} --to {} --tag {} --json > {}",
        msfe_ng_bin(),
        jobs::sh_quote(std::path::Path::new(from)),
        jobs::sh_quote(std::path::Path::new(to)),
        jobs::sh_quote(std::path::Path::new(tag)),
        jobs::sh_quote(&result_path())
    );
    jobs::start(JOB, &script, &[])
}

pub fn last() -> Option<Json> {
    let t = std::fs::read_to_string(result_path()).ok()?;
    Json::parse(&t).ok()
}

/// The message as submitted.
pub fn build_message(
    from: &str,
    to: &str,
    tag: &str,
    hostname: &str,
) -> (Vec<(String, String)>, String) {
    let date = rfc5322_date(crate::delivery::now_secs());
    let headers = vec![
        ("From".to_string(), from.to_string()),
        ("To".to_string(), to.to_string()),
        (
            "Subject".to_string(),
            format!("MSFE-NG delivery test {tag}"),
        ),
        ("Date".to_string(), date),
        (
            "Message-ID".to_string(),
            format!("<msfe-ng-{tag}@{hostname}>"),
        ),
        ("MIME-Version".to_string(), "1.0".to_string()),
        (
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        ),
        ("X-MSFE-NG-Test".to_string(), tag.to_string()),
        ("Auto-Submitted".to_string(), "auto-generated".to_string()),
    ];
    let body = format!(
        "This is a delivery test sent by MSFE-NG from {from} on {hostname}.\n\nTag: {tag}\n\nIf you received it, the path from this server to your mailbox works.\nLook at where it landed (inbox or spam) and at the message's authentication results\n(Gmail: \"Show original\"); the sending server's report has the rest.\n"
    );
    (headers, body)
}

/// `Sat, 19 Sep 2026 20:00:00 +0000`
pub fn rfc5322_date(secs: u64) -> String {
    let d = crate::civil::Date::from_unix(secs);
    let dow = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][((secs / 86_400) % 7) as usize];
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(d.m - 1) as usize];
    let t = secs % 86_400;
    format!(
        "{dow}, {} {mon} {} {:02}:{:02}:{:02} +0000",
        d.d,
        d.y,
        t / 3600,
        (t / 60) % 60,
        t % 60
    )
}

/// Submit and follow. `smtp` is the local MTA (`127.0.0.1:25`), `log` the
/// Exim main log; `follow` bounds the wait.
pub fn run(
    cfg: &Config,
    from: &str,
    to: &str,
    tag: &str,
    smtp: &str,
    follow: Duration,
    on_progress: &mut dyn FnMut(&str),
) -> Json {
    let hostname = crate::diaginbox::hostname(cfg);
    let (headers, body) = build_message(from, to, tag, &hostname);
    let hrefs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let mut checks = Vec::new();
    let started = crate::delivery::now_secs();
    let reply = match crate::smtpprobe::submit_local(smtp, from, to, &hrefs, &body) {
        Ok(r) => r,
        Err(e) => {
            checks.push(
                Check::new("testmail.submitted", SC, CAT, Verdict::Fail, Severity::Critical, "the local MTA refused the message", format!("{e} — Exim on {smtp} did not accept the submission; nothing left the server"))
                    .fix_summary("Check that exim runs and listens on 127.0.0.1:25 (Services rows), and the reason in the reply: a suspended account, a sender-verify failure, the hourly limit"),
            );
            return result_json(from, to, tag, None, started, checks, Vec::new());
        }
    };
    let id = reply
        .split_whitespace()
        .find_map(|t| t.strip_prefix("id="))
        .map(str::to_string);
    on_progress(&format!("submitted: {reply}"));
    checks.push(
        Check::new(
            "testmail.submitted",
            SC,
            CAT,
            Verdict::Pass,
            Severity::Info,
            "Exim accepted the message",
            reply.clone(),
        )
        .evidence("reply", reply.clone()),
    );
    let Some(id) = id else {
        checks.push(Check::new(
            "testmail.followed",
            SC,
            CAT,
            Verdict::Unknown,
            Severity::Info,
            "cannot follow the message",
            "the reply carried no id= — the log cannot be matched",
        ));
        return result_json(from, to, tag, None, started, checks, Vec::new());
    };
    // follow the id through the main log
    let log = PathBuf::from(&cfg.exim_mainlog_path);
    let t0 = Instant::now();
    let mut lines: Vec<String> = Vec::new();
    let mut outcome: Option<Check> = None;
    let mut scanned = false;
    while t0.elapsed() < follow {
        std::thread::sleep(Duration::from_secs(3));
        let Some(text) = crate::cpaudit::tail_bytes(&log, 4 * 1024 * 1024) else {
            continue;
        };
        lines = text
            .lines()
            .filter(|l| l.contains(&id))
            .map(str::to_string)
            .collect();
        let mut delivered = None;
        let mut failed = None;
        let mut deferred = None;
        let mut completed = false;
        for l in &lines {
            if l.contains("Q=mailscanner") || l.contains("T=mailscanner") {
                scanned = true;
            }
            let Some(p) = parse_mainlog_line(l) else {
                continue;
            };
            match p.kind {
                Some(Kind::Delivered) | Some(Kind::Forwarded) => delivered = Some(p),
                Some(Kind::Failed) => failed = Some(p),
                Some(Kind::Deferred) => deferred = Some(p),
                Some(Kind::Completed) => completed = true,
                _ => {}
            }
        }
        if let Some(d) = delivered {
            let tls = d
                .raw
                .split_whitespace()
                .find_map(|t| t.strip_prefix("X="))
                .map(str::to_string);
            let resp = d.response.clone().unwrap_or_default();
            outcome = Some(
                Check::new(
                    "testmail.delivered",
                    SC,
                    CAT,
                    Verdict::Pass,
                    Severity::Info,
                    format!(
                        "delivered to {} in {} s",
                        d.host.clone().unwrap_or_else(|| "the remote MX".into()),
                        t0.elapsed().as_secs()
                    ),
                    format!(
                        "remote said: {}",
                        if resp.is_empty() {
                            "(no response recorded)".to_string()
                        } else {
                            resp.chars().take(200).collect()
                        }
                    ),
                )
                .evidence("exim", d.raw.clone()),
            );
            checks.push(match tls {
                Some(x) => Check::new("testmail.tls_out", SC, CAT, Verdict::Pass, Severity::Info, "sent over TLS", x),
                None => Check::new("testmail.tls_out", SC, CAT, Verdict::Warn, Severity::Medium, "sent in clear text", "the remote MX did not negotiate STARTTLS (or Exim is configured not to try); the message could be read on the way").fix_summary("Check the recipient's MX for STARTTLS (a delivery test of the recipient address) and Exim's tls_advertise/tls_verify settings"),
            });
            on_progress("delivered");
            break;
        }
        if let Some(f) = failed {
            let reason = f.response.clone().unwrap_or_default();
            let cls = classify_rejection(&reason);
            let mut c = Check::new(
                "testmail.failed",
                SC,
                CAT,
                Verdict::Fail,
                Severity::High,
                format!(
                    "the remote refused the message{}",
                    cls.as_ref()
                        .map(|c| format!(" — {}", c.provider))
                        .unwrap_or_default()
                ),
                format!(
                    "{}{}",
                    reason.chars().take(300).collect::<String>(),
                    cls.as_ref()
                        .map(|c| format!(". {}", c.meaning))
                        .unwrap_or_default()
                ),
            )
            .evidence("exim", f.raw.clone());
            if let Some(cl) = cls {
                c = c.fix(Fix {
                    summary: cl.fix.into(),
                    url: cl.url.map(str::to_string),
                    ..Default::default()
                });
            }
            outcome = Some(c);
            on_progress("failed");
            break;
        }
        if completed {
            break;
        }
        if let Some(d) = &deferred {
            on_progress(&format!(
                "deferred: {}",
                d.response.clone().unwrap_or_default()
            ));
        }
        if scanned {
            on_progress("in the MailScanner queue");
        }
    }
    if scanned {
        checks.push(Check::new(
            "testmail.scanned",
            SC,
            CAT,
            Verdict::Pass,
            Severity::Info,
            "went through MailScanner",
            "the message was queued for scanning before delivery (Q=mailscanner)",
        ));
    }
    match outcome {
        Some(c) => checks.push(c),
        None => {
            let last_defer = lines
                .iter()
                .rev()
                .find_map(|l| parse_mainlog_line(l).filter(|p| p.kind == Some(Kind::Deferred)));
            checks.push(match last_defer {
                Some(d) => {
                    let reason = d.response.clone().unwrap_or_default();
                    let cls = classify_rejection(&reason);
                    let mut c = Check::new("testmail.deferred", SC, CAT, Verdict::Warn, Severity::Medium, format!("still deferred after {} s", follow.as_secs()), format!("{}{}. Exim keeps retrying; the Queues tab shows the message", reason.chars().take(300).collect::<String>(), cls.as_ref().map(|c| format!(". {}: {}", c.provider, c.meaning)).unwrap_or_default())).evidence("exim", d.raw.clone());
                    if let Some(cl) = cls {
                        c = c.fix(Fix {
                            summary: cl.fix.into(),
                            url: cl.url.map(str::to_string),
                            ..Default::default()
                        });
                    }
                    c
                }
                None => Check::new("testmail.pending", SC, CAT, Verdict::Unknown, Severity::Info, format!("not delivered within {} s", follow.as_secs()), "no delivery, failure or deferral logged yet — the message may still be in the MailScanner queue or waiting for a queue run; the Queues tab shows it").evidence("exim", lines.join("\n")),
            });
        }
    }
    result_json(from, to, tag, Some(id), started, checks, lines)
}

fn result_json(
    from: &str,
    to: &str,
    tag: &str,
    id: Option<String>,
    started: u64,
    checks: Vec<Check>,
    lines: Vec<String>,
) -> Json {
    Json::Object(vec![
        ("from".into(), Json::str(from)),
        ("to".into(), Json::str(to)),
        ("tag".into(), Json::str(tag)),
        ("id".into(), id.map(Json::Str).unwrap_or(Json::Null)),
        ("started".into(), Json::Int(started as i64)),
        (
            "finished".into(),
            Json::Int(crate::delivery::now_secs() as i64),
        ),
        (
            "ok".into(),
            Json::Bool(!checks.iter().any(|c| c.verdict == Verdict::Fail)),
        ),
        (
            "checks".into(),
            Json::Array(checks.iter().map(|c| c.to_json()).collect()),
        ),
        (
            "log".into(),
            Json::Array(lines.iter().map(Json::str).collect()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_messages() {
        assert_eq!(rfc5322_date(0), "Thu, 1 Jan 1970 00:00:00 +0000");
        assert_eq!(
            rfc5322_date(1_700_000_000),
            "Tue, 14 Nov 2023 22:13:20 +0000"
        );
        let (h, b) = build_message("a@x.test", "b@y.test", "t1", "host.test");
        assert!(h
            .iter()
            .any(|(k, v)| k == "Message-ID" && v == "<msfe-ng-t1@host.test>"));
        assert!(b.contains("Tag: t1"));
        assert!(new_tag().len() >= 10);
    }

    #[test]
    fn validates_addresses() {
        let f = std::env::temp_dir().join(format!("msfe-tm-ud-{}", std::process::id()));
        std::fs::write(&f, "x.test: bob\n").unwrap();
        std::env::set_var("MSFE_NG_USERDOMAINS_FILE", &f);
        assert_eq!(
            validate("a@x.test", "b@gmail.com").unwrap(),
            ("a@x.test".to_string(), "b@gmail.com".to_string())
        );
        assert!(validate("a@other.test", "b@gmail.com")
            .unwrap_err()
            .contains("not hosted"));
        assert!(validate("a@x.test", "nonsense").is_err());
        std::env::remove_var("MSFE_NG_USERDOMAINS_FILE");
        let _ = std::fs::remove_file(f);
    }
}
