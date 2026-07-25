//! SpamAssassin Bayes training and spam-report parsing.
//!
//! Training operates on the raw message (piped to `sa-learn` on stdin), so it
//! works for any message whose body we can read — i.e. quarantined copies.
//! Report parsing turns MailScanner's stored `spamreport` string into the
//! rule/score component rows the full-email view shows.

use crate::service::ControlOutcome;
use std::io::Write;
use std::process::{Command, Stdio};

/// A parsed spam-report component: rule name, score, optional description.
pub struct Component {
    pub rule: String,
    pub score: f64,
    pub desc: Option<&'static str>,
}

/// Parse a MailScanner spamreport, e.g.
/// `spam, SpamAssassin (not cached, score=10.5, required 5, BAYES_99 5.00, ...)`
/// into rule/score rows. Recognizes `RULE_NAME <score>` tokens.
pub fn parse_report(report: &str) -> Vec<Component> {
    let mut out = Vec::new();
    // rule names are UPPER_SNAKE (optionally digits); score is a signed decimal
    let toks: Vec<&str> = report
        .split([',', ' ', '(', ')'])
        .filter(|t| !t.is_empty())
        .collect();
    let mut i = 0;
    while i + 1 < toks.len() {
        let name = toks[i];
        let is_rule = name.len() >= 3
            && name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && name.contains('_');
        if is_rule {
            if let Ok(score) = toks[i + 1].parse::<f64>() {
                out.push(Component {
                    rule: name.to_string(),
                    score,
                    desc: describe(name),
                });
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Descriptions for the most common SpamAssassin rules (best-effort; unknown
/// rules simply have none — the raw report is always shown too).
fn describe(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "ALL_TRUSTED" => "Passed through trusted hosts only via SMTP",
        "BAYES_00" => "Bayes spam probability is 0 to 1%",
        "BAYES_99" => "Bayes spam probability is 99 to 100%",
        "BAYES_999" => "Bayes spam probability is 99.9 to 100%",
        "HTML_MESSAGE" => "HTML included in message",
        "MIME_HTML_ONLY" => "Message only has text/html MIME parts",
        "DKIM_SIGNED" => "Message has a DKIM signature",
        "DKIM_VALID" => "Message has a valid DKIM signature",
        "SPF_PASS" => "SPF: sender matches SPF record",
        "SPF_FAIL" => "SPF: sender does not match SPF record",
        "FREEMAIL_FROM" => "Sender uses a free webmail provider",
        "HK_RANDOM_REPLYTO" => "Reply-To username looks random",
        "KAM_DMARC_STATUS" => "DMARC check status",
        "KAM_DMARC_REJECT" => "Domain DMARC policy is reject",
        "KAM_DMARC_QUARANTINE" => "Domain DMARC policy is quarantine",
        "RCVD_IN_DNSWL_BLOCKED" => "DNSWL lookup was blocked (too many queries)",
        "URIBL_BLOCKED" => "URIBL lookup was blocked (too many queries)",
        _ => return None,
    })
}

/// Received-header hops (IP + optional helo/host), newest first. No external
/// geolocation — the note in the UI explains only the last external IP is
/// trustworthy.
pub struct HeaderIp {
    pub ip: String,
    pub host: String,
}

pub fn header_ips(headers: &str) -> Vec<HeaderIp> {
    let mut out = Vec::new();
    for line in headers.lines() {
        let l = line.trim_start();
        if !l.starts_with("Received:") && !line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(ip) = extract_bracketed_ip(line) {
            if out.iter().all(|h: &HeaderIp| h.ip != ip) {
                let host = extract_helo(line).unwrap_or_default();
                out.push(HeaderIp { ip, host });
            }
        }
    }
    out
}

fn extract_bracketed_ip(s: &str) -> Option<String> {
    let start = s.find('[')?;
    let end = s[start..].find(']')? + start;
    let cand = &s[start + 1..end];
    let ok = cand.contains('.')
        && cand.split('.').count() == 4
        && cand.split('.').all(|o| o.parse::<u8>().is_ok());
    let ok6 = cand.contains(':') && cand.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    (ok || ok6).then(|| cand.to_string())
}

fn extract_helo(s: &str) -> Option<String> {
    let h = s.find("helo=")?;
    let rest = &s[h + 5..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ')' || c == ']')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Bayes training / reporting on a raw message. Actions:
/// `ham` | `spam` | `forget` (sa-learn) and `report` (network report + learn).
pub fn learn(message: &[u8], action: &str) -> ControlOutcome {
    let mut transcript = Vec::new();
    let steps: &[(&str, &[&str])] = match action {
        "ham" => &[("sa-learn", &["--ham", "--no-sync"])],
        "spam" => &[("sa-learn", &["--spam", "--no-sync"])],
        "forget" => &[("sa-learn", &["--forget", "--no-sync"])],
        // learn as spam AND report to the collaborative networks
        "report" => &[
            ("sa-learn", &["--spam", "--no-sync"]),
            ("spamassassin", &["-r"]),
        ],
        _ => {
            return ControlOutcome {
                ok: false,
                transcript: vec![format!("unknown learn action '{action}'")],
            }
        }
    };
    let mut ok = true;
    for (cmd, args) in steps {
        transcript.push(format!("$ {cmd} {}", args.join(" ")));
        match run_with_stdin(cmd, args, message) {
            Ok((success, output)) => {
                for l in output.lines() {
                    if !l.trim().is_empty() {
                        transcript.push(l.to_string());
                    }
                }
                transcript.push(if success {
                    "→ ok".into()
                } else {
                    "→ failed".into()
                });
                ok &= success;
            }
            Err(e) => {
                transcript.push(format!("→ cannot run: {e}"));
                ok = false;
            }
        }
    }
    if ok {
        // one sync after training so the bayes db is written
        let _ = Command::new("sa-learn").arg("--sync").output();
    }
    ControlOutcome { ok, transcript }
}

/// SpamAssassin's Bayes database status (`sa-learn --dump magic`), parsed into
/// the handful of numbers that matter: how much ham/spam it has learned, token
/// count, and when it last expired old tokens.
pub fn bayes_status() -> Vec<(String, String)> {
    let out = Command::new("sa-learn").args(["--dump", "magic"]).output();
    let Ok(o) = out else {
        return vec![("error".into(), "sa-learn is not installed".into())];
    };
    let text = String::from_utf8_lossy(&o.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        // 0.000          0     3577          0  non-token data: nspam
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !line.contains("non-token data:") {
            continue;
        }
        let key = f[f.len() - 1];
        let value = f[2];
        let label = match key {
            "nspam" => "Spam messages learned",
            "nham" => "Ham messages learned",
            "ntokens" => "Tokens in the database",
            "oldest_token_age" => "Oldest token",
            "newest_token_age" => "Newest token",
            "last_expire" => "Last expiry run",
            "last_journal_sync" => "Last journal sync",
            "last_atime_delta" => "Last atime delta",
            "bayes_db_version" => "Bayes DB version",
            _ => continue,
        };
        let value = if key.ends_with("_age") || key.starts_with("last_") {
            format_epoch(value)
        } else {
            value.to_string()
        };
        rows.push((label.to_string(), value));
    }
    if rows.is_empty() {
        rows.push((
            "status".into(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ));
    }
    rows
}

/// Epoch seconds → a readable "N days ago"; passes other values through.
fn format_epoch(v: &str) -> String {
    let Ok(secs) = v.parse::<u64>() else {
        return v.to_string();
    };
    if secs == 0 {
        return "never".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if secs > 1_000_000_000 && secs <= now {
        let ago = now - secs;
        format!("{} days ago", ago / 86_400)
    } else {
        format!("{} days", secs / 86_400)
    }
}

/// SpamAssassin's own configuration self-check (`spamassassin --lint`).
pub fn lint() -> (bool, String) {
    match Command::new("spamassassin").arg("--lint").output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            let s = s.trim().to_string();
            (
                o.status.success(),
                if s.is_empty() {
                    "No problems found — SpamAssassin's configuration is valid.".into()
                } else {
                    s
                },
            )
        }
        Err(e) => (false, format!("cannot run spamassassin: {e}")),
    }
}

fn run_with_stdin(cmd: &str, args: &[&str], input: &[u8]) -> std::io::Result<(bool, String)> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input)?;
    let out = child.wait_with_output()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_report_components() {
        let r = "spam, SpamAssassin (not cached, score=10.508, required 5, ALL_TRUSTED -1.00, BAYES_99 5.00, HK_RANDOM_REPLYTO 1.00, KAM_DMARC_REJECT 3.00)";
        let c = parse_report(r);
        let names: Vec<&str> = c.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(
            names,
            [
                "ALL_TRUSTED",
                "BAYES_99",
                "HK_RANDOM_REPLYTO",
                "KAM_DMARC_REJECT"
            ]
        );
        assert_eq!(c[0].score, -1.00);
        assert_eq!(c[1].desc, Some("Bayes spam probability is 99 to 100%"));
        // "required" is not a rule; "score" token ignored
        assert!(!names.contains(&"SpamAssassin"));
    }

    #[test]
    fn extracts_header_ips() {
        let h = "Received: from [49.12.174.167] (port=58074 helo=bassetto.eu)\n    by gauss with esmtpsa\nReceived: from x [10.0.0.1]\n";
        let ips = header_ips(h);
        assert_eq!(ips[0].ip, "49.12.174.167");
        assert_eq!(ips[0].host, "bassetto.eu");
        assert_eq!(ips[1].ip, "10.0.0.1");
    }

    #[test]
    fn rejects_bad_learn_action() {
        assert!(!learn(b"x", "delete-everything").ok);
    }
}
