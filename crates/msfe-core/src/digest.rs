//! Quarantine digest emails.
//!
//! For each digest-enabled domain (from the `digestdomains` policy file) we
//! gather the messages held for that domain over the period and email an HTML
//! summary to the domain's digest address, so recipients know what was caught
//! and can log in to release. Spec (behavior only) from the original
//! `msdigest.pl` / `digest.html` / `digestdomains`; reimplemented clean-room.

use crate::config::Config;
use crate::db;
use crate::legacy::{self, DigestDomain};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// A held message shown in the digest.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldMsg {
    pub ts: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub kind: String,
}

/// Load digest configuration from `<policy>/digestdomains`.
pub fn load_digestdomains(policy_dir: &Path) -> Vec<DigestDomain> {
    let text = std::fs::read_to_string(policy_dir.join("digestdomains")).unwrap_or_default();
    legacy::parse_digestdomains(&text)
}

fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Messages held for `domain` in the last `hours`.
pub fn held_for_domain(cfg: &Config, domain: &str, hours: u32) -> io::Result<Vec<HeldMsg>> {
    let sql = format!(
        "SELECT msg_ts, from_address, to_address, subject, isspam, ishighspam, virusinfected \
         FROM maillog WHERE quarantined=1 AND to_domain={} \
         AND msg_ts >= (NOW() - INTERVAL {hours} HOUR) ORDER BY msg_ts DESC",
        sql_quote(domain)
    );
    let rows = db::query(cfg, &sql)?;
    Ok(rows
        .iter()
        .map(|r| {
            let f = |i: usize| r.get(i).cloned().unwrap_or_default();
            let num = |s: &str| s.trim() != "0" && !s.trim().is_empty();
            let kind = if num(&f(6)) {
                "virus"
            } else if num(&f(5)) {
                "high spam"
            } else {
                "spam"
            };
            HeldMsg {
                ts: f(0),
                from: f(1),
                to: f(2),
                subject: f(3),
                kind: kind.to_string(),
            }
        })
        .collect())
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render the HTML digest body for a domain.
pub fn render(domain: &str, period: &str, rows: &[HeldMsg]) -> String {
    let mut body = String::new();
    for m in rows {
        body.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&m.ts),
            esc(&m.from),
            esc(&m.to),
            esc(&m.subject),
            esc(&m.kind),
        ));
    }
    format!(
        "<!doctype html><html><body style=\"font:14px system-ui,sans-serif;color:#111\">\
         <h2>MailScanner quarantine digest — {domain}</h2>\
         <p>{count} message(s) held in the last {period}. Log in to your control \
         panel &rarr; MailScanner to review and release.</p>\
         <table border=\"1\" cellpadding=\"5\" cellspacing=\"0\" style=\"border-collapse:collapse\">\
         <tr><th>Date</th><th>From</th><th>To</th><th>Subject</th><th>Type</th></tr>\
         {body}</table>\
         <p style=\"color:#888;font-size:12px\">Sent by MSFE-NG.</p></body></html>",
        domain = esc(domain),
        count = rows.len(),
        period = esc(period),
    )
}

/// Send an HTML email via `sendmail -t`.
pub fn send_html(to: &str, from: &str, subject: &str, html: &str) -> io::Result<()> {
    let msg = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: {subject}\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}\r\n"
    );
    let mut child = Command::new("sendmail")
        .arg("-t")
        .stdin(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(msg.as_bytes())?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("sendmail failed"))
    }
}

/// Result of a per-domain digest attempt.
#[derive(Debug, Clone)]
pub struct DigestResult {
    pub domain: String,
    pub recipient: String,
    pub count: usize,
    pub sent: bool,
}

/// Run digests for all enabled domains. `dry` skips sending. Domains with no
/// held mail are skipped. Returns one result per domain considered.
pub fn run(cfg: &Config, policy_dir: &Path, dry: bool) -> Vec<DigestResult> {
    let mut out = Vec::new();
    for d in load_digestdomains(policy_dir) {
        if d.enabled != "yes" || d.domain.is_empty() {
            continue;
        }
        let hours = d.freq.trim().parse::<u32>().unwrap_or(24).clamp(1, 24 * 30);
        let rows = held_for_domain(cfg, &d.domain, hours).unwrap_or_default();
        if rows.is_empty() {
            continue;
        }
        let recipient = if d.to.is_empty() {
            format!("postmaster@{}", d.domain)
        } else {
            d.to.clone()
        };
        let period = format!("{hours} hours");
        let sent = if dry {
            false
        } else {
            let html = render(&d.domain, &period, &rows);
            send_html(
                &recipient,
                &format!("mailscanner@{}", d.domain),
                &format!("MailScanner quarantine digest — {}", d.domain),
                &html,
            )
            .is_ok()
        };
        out.push(DigestResult {
            domain: d.domain,
            recipient,
            count: rows.len(),
            sent,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_escapes_and_counts() {
        let rows = vec![HeldMsg {
            ts: "2026-07-21 10:00:00".into(),
            from: "a@x.example".into(),
            to: "b@y.example".into(),
            subject: "hi <script>".into(),
            kind: "spam".into(),
        }];
        let h = render("y.example", "24 hours", &rows);
        assert!(h.contains("y.example"));
        assert!(h.contains("1 message(s) held"));
        assert!(h.contains("hi &lt;script&gt;")); // escaped
        assert!(!h.contains("<script>")); // no raw injection
    }

    #[test]
    fn render_empty() {
        let h = render("d.example", "24 hours", &[]);
        assert!(h.contains("0 message(s) held"));
    }
}
