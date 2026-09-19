//! What this server's logs say about one address: Exim's main log (who sent
//! what, where it went, what failed), the reject log, the panic log,
//! Dovecot's logins in the maillog, MailScanner's own table, and the queues.
//! Bounded reads (a byte cap per file, the live file's tail plus a couple of
//! rotated ones), every other address masked.

use crate::config::Config;
use crate::cpaudit::{mask_address, tail_bytes, Cp};
use crate::delivery::Inputs;
use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::json::Json;
use std::path::Path;

const S: Scope = Scope::Server;
/// Bytes read from the live log and from each rotated file.
pub const MAX_BYTES_PER_FILE: u64 = 32 * 1024 * 1024;
/// Rotated files consulted besides the live one.
const ROTATED_FILES: usize = 2;

// ---- Exim main log --------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `<=` message accepted
    Arrival,
    /// `=>` delivered
    Delivered,
    /// `->` delivered (additional address, same transport)
    Forwarded,
    /// `**` delivery failed (bounced)
    Failed,
    /// `==` delivery deferred
    Deferred,
    /// `Completed`
    Completed,
    /// `*** frozen` / `Frozen`
    Frozen,
    /// `rejected …` (no message id, or with one)
    Reject,
    Other,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LogLine {
    pub ts: String,
    pub id: Option<String>,
    pub kind: Option<Kind>,
    /// The address the line is about (sender for `<=`, recipient otherwise).
    pub addr: String,
    pub host: Option<String>,
    pub ip: Option<String>,
    /// `A=dovecot_login:user` → `user`
    pub auth: Option<String>,
    pub router: Option<String>,
    pub transport: Option<String>,
    /// The remote response (`C="…"`) or the failure/deferral reason.
    pub response: Option<String>,
    /// The `for a@b c@d` recipients of an arrival.
    pub recipients: Vec<String>,
    pub raw: String,
}

fn kind_of(tok: &str) -> Kind {
    match tok {
        "<=" => Kind::Arrival,
        "=>" => Kind::Delivered,
        "->" => Kind::Forwarded,
        "**" => Kind::Failed,
        "==" => Kind::Deferred,
        "Completed" => Kind::Completed,
        "***" | "Frozen" => Kind::Frozen,
        _ => Kind::Other,
    }
}

fn is_exim_id(s: &str) -> bool {
    // 1x5ZA2-00000002VJa-0L1J (new) or 1x5ZA2-0002VJ-0L (old)
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// One Exim main-log line.
pub fn parse_mainlog_line(line: &str) -> Option<LogLine> {
    if line.len() < 20 || line.as_bytes()[4] != b'-' || line.as_bytes()[10] != b' ' {
        return None;
    }
    let ts = line[..19].to_string();
    let mut rest = line[20..].trim_start();
    let mut l = LogLine {
        ts,
        raw: line.to_string(),
        ..Default::default()
    };
    let first = rest.split_whitespace().next().unwrap_or("");
    if is_exim_id(first) {
        l.id = Some(first.to_string());
        rest = rest[first.len()..].trim_start();
    }
    let mut toks = rest.split_whitespace().peekable();
    let Some(k) = toks.peek().copied() else {
        return Some(l);
    };
    let kind = kind_of(k);
    l.kind = Some(if kind == Kind::Other && rest.contains(" rejected ") {
        Kind::Reject
    } else {
        kind
    });
    if kind != Kind::Other {
        toks.next(); // the marker itself
    }
    match kind {
        Kind::Arrival | Kind::Delivered | Kind::Forwarded | Kind::Failed | Kind::Deferred => {
            // "=> user <addr>" (local) or "=> addr"
            if let Some(a) = toks.next() {
                if !a.contains('@')
                    && toks
                        .peek()
                        .is_some_and(|n| n.starts_with('<') && n.ends_with('>'))
                {
                    l.addr = toks
                        .next()
                        .unwrap()
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_ascii_lowercase();
                } else {
                    l.addr = a
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_ascii_lowercase();
                }
            }
        }
        _ => {}
    }
    // tokens
    let mut after_for = false;
    let mut prev_h = false;
    for t in toks {
        if after_for {
            if t.contains('@') {
                l.recipients.push(t.to_ascii_lowercase());
                continue;
            }
            after_for = false;
        }
        if t == "for" {
            after_for = true;
        } else if let Some(v) = t.strip_prefix("H=") {
            l.host = Some(v.trim_matches(|c| c == '(' || c == ')').to_string());
            prev_h = true;
            continue;
        } else if prev_h && t.starts_with('[') {
            l.ip = Some(
                t.trim_matches(|c| c == '[' || c == ']' || c == ':')
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string(),
            );
            if t.contains("]:") {
                l.ip = t
                    .trim_start_matches('[')
                    .split(']')
                    .next()
                    .map(str::to_string);
            }
        } else if prev_h && t.starts_with('(') {
            // H=name (helo) [ip]
            continue;
        } else if let Some(v) = t.strip_prefix("A=") {
            l.auth = v
                .split(':')
                .nth(1)
                .map(str::to_string)
                .filter(|s| !s.is_empty());
        } else if let Some(v) = t.strip_prefix("R=") {
            l.router = Some(v.trim_end_matches(':').to_string());
        } else if let Some(v) = t.strip_prefix("T=") {
            l.transport = Some(v.trim_end_matches(':').to_string());
        }
        prev_h = false;
    }
    // the response: C="…" for deliveries; the text after the last token
    // group's ": " for failures/deferrals
    if let Some(i) = rest.find(" C=\"") {
        let c = &rest[i + 4..];
        l.response = Some(c.split('"').next().unwrap_or("").to_string());
    } else if matches!(kind, Kind::Failed | Kind::Deferred) {
        // "** addr R=r T=t H=h [ip]: SMTP error ..." / "** addr <orig>: retry timeout exceeded"
        let reason = rest.find(": ").map(|i| rest[i + 2..].to_string());
        // skip past "T=x:" when the reason starts after the transport token
        l.response = reason.map(|r| {
            if let Some(j) = r.find("]: ") {
                r[j + 3..].to_string()
            } else {
                r
            }
        });
    } else if kind == Kind::Other && l.kind == Some(Kind::Reject) {
        if let Some(i) = rest.find("rejected ") {
            l.response = Some(rest[i..].to_string());
        }
    }
    Some(l)
}

/// Everything the log has on one message.
#[derive(Debug, Clone, Default)]
pub struct MessageTrail {
    pub id: String,
    pub ts: String,
    pub sender: String,
    pub auth: Option<String>,
    pub recipients: Vec<String>,
    pub delivered: Vec<LogLine>,
    pub failed: Vec<LogLine>,
    pub deferred: Vec<LogLine>,
    pub completed: bool,
    pub frozen: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub messages: Vec<MessageTrail>,
    pub rejects: Vec<LogLine>,
    pub bytes_scanned: u64,
    pub truncated: bool,
    pub files: Vec<String>,
}

/// Text of the log files to scan: the live file's tail and the newest
/// rotated ones, each capped. Returns `(name, text)` newest last.
pub fn log_texts(base: &Path, rotated: usize, cap: u64) -> Vec<(String, String, bool)> {
    let files = crate::logindex::log_files(base);
    let mut out = Vec::new();
    let n = files.len();
    for (i, f) in files.iter().enumerate() {
        if i + 1 + rotated < n {
            continue; // older than we look
        }
        let path = match crate::logindex::plain_path(f, &crate::logindex::cache_dir()) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if let Some(text) = tail_bytes(&path, cap) {
            out.push((f.name.clone(), text, len > cap));
        }
    }
    out
}

/// Scan the Exim main log for `address` (as sender or recipient) in the
/// last `days` days.
pub fn scan(base: &Path, address: &str, days: u32) -> Scan {
    let cutoff = crate::civil::Date::from_unix(
        crate::delivery::now_secs().saturating_sub(days.max(1) as u64 * 86_400),
    )
    .to_string();
    let needle = address.to_ascii_lowercase();
    let mut scan = Scan::default();
    let mut ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut lines_by_id: std::collections::HashMap<String, Vec<LogLine>> =
        std::collections::HashMap::new();
    for (name, text, truncated) in log_texts(base, ROTATED_FILES, MAX_BYTES_PER_FILE) {
        scan.files.push(name);
        scan.bytes_scanned += text.len() as u64;
        scan.truncated |= truncated;
        // pass 1: lines that name the address
        for line in text.lines() {
            if line.len() < 10 || line[..10] < *cutoff {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if !lower.contains(&needle) {
                continue;
            }
            if let Some(l) = parse_mainlog_line(line) {
                match (&l.id, l.kind) {
                    (Some(id), _) => {
                        ids.insert(id.clone());
                    }
                    (None, Some(Kind::Reject)) => scan.rejects.push(l),
                    _ => {}
                }
            }
        }
        // pass 2: every line of those messages
        if !ids.is_empty() {
            for line in text.lines() {
                if line.len() < 45 {
                    continue;
                }
                let Some(l) = parse_mainlog_line(line) else {
                    continue;
                };
                if let Some(id) = &l.id {
                    if ids.contains(id) {
                        lines_by_id.entry(id.clone()).or_default().push(l);
                    }
                }
            }
        }
    }
    for (id, lines) in lines_by_id {
        let mut t = MessageTrail {
            id,
            ..Default::default()
        };
        for l in lines {
            match l.kind {
                Some(Kind::Arrival) => {
                    t.ts = l.ts.clone();
                    t.sender = l.addr.clone();
                    t.auth = l.auth.clone();
                    t.recipients = l.recipients.clone();
                }
                Some(Kind::Delivered) | Some(Kind::Forwarded) => t.delivered.push(l),
                Some(Kind::Failed) => t.failed.push(l),
                Some(Kind::Deferred) => t.deferred.push(l),
                Some(Kind::Completed) => t.completed = true,
                Some(Kind::Frozen) => t.frozen = true,
                _ => {}
            }
        }
        if t.ts.is_empty() {
            t.ts = t
                .delivered
                .first()
                .or(t.failed.first())
                .or(t.deferred.first())
                .map(|l| l.ts.clone())
                .unwrap_or_default();
        }
        scan.messages.push(t);
    }
    scan.messages.sort_by(|a, b| b.ts.cmp(&a.ts));
    scan
}

// ---- reject log ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Reject {
    pub ts: String,
    pub ip: Option<String>,
    /// `set_id=` of a failed AUTH, the sender of a rejected RCPT, …
    pub who: Option<String>,
    pub rcpt: Option<String>,
    pub auth_failure: bool,
    pub reason: String,
}

pub fn parse_rejectlog_line(line: &str) -> Option<Reject> {
    if line.len() < 20 || line.as_bytes()[4] != b'-' {
        return None;
    }
    let mut r = Reject {
        ts: line[..19].to_string(),
        ..Default::default()
    };
    let rest = &line[20..];
    if let Some(i) = rest.find(" [") {
        r.ip = rest[i + 2..].split(']').next().map(|s| s.to_string());
    }
    if let Some(i) = rest.find("set_id=") {
        r.who = Some(
            rest[i + 7..]
                .trim_end_matches(')')
                .split(')')
                .next()
                .unwrap_or("")
                .to_string(),
        );
        r.auth_failure = true;
    }
    if let Some(i) = rest.find("F=<") {
        r.who = Some(
            rest[i + 3..]
                .split('>')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase(),
        );
    }
    if let Some(i) = rest.find("RCPT <") {
        r.rcpt = Some(
            rest[i + 6..]
                .split('>')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase(),
        );
    }
    r.reason = match rest.find(": ") {
        Some(i) if rest.contains("authenticator failed") => rest[i + 2..].to_string(),
        _ => match rest.find("rejected ") {
            Some(i) => rest[i..].to_string(),
            None => rest.to_string(),
        },
    };
    Some(r)
}

// ---- Dovecot (maillog) ---------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Login {
    pub ts: String,
    pub user: String,
    pub ip: String,
    pub ok: bool,
    pub service: String,
}

/// `… dovecot[…]: imap-login: Login: user=<a@b>, method=PLAIN, rip=1.2.3.4, …`
/// and the `Login aborted … (auth_failed): user=<…>` / `Disconnected (auth failed…)` shapes.
pub fn parse_dovecot_line(line: &str) -> Option<Login> {
    let i = line.find("-login: ")?;
    let service = line[..i].rsplit(' ').next()?.to_string();
    let rest = &line[i + 8..];
    let ok = rest.starts_with("Login: ");
    let failed = rest.contains("auth failed")
        || rest.contains("(auth_failed)")
        || rest.contains("Disconnected (auth failed");
    if !ok && !failed {
        return None;
    }
    let user = rest
        .find("user=<")
        .map(|j| {
            rest[j + 6..]
                .split('>')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    let ip = rest
        .find("rip=")
        .map(|j| rest[j + 4..].split(',').next().unwrap_or("").to_string())
        .unwrap_or_default();
    Some(Login {
        ts: line.get(..15).unwrap_or("").to_string(),
        user,
        ip,
        ok,
        service,
    })
}

// ---- rejection classification ----------------------------------------------------

/// A known remote rejection: who says it, what it means, what to do.
#[derive(Debug, Clone, PartialEq)]
pub struct Rejection {
    pub provider: &'static str,
    pub meaning: &'static str,
    pub fix: &'static str,
    pub url: Option<&'static str>,
}

/// Classify a remote SMTP response (from a `**` line, a bounce, a DSN).
pub fn classify_rejection(text: &str) -> Option<Rejection> {
    let t = text.to_ascii_lowercase();
    let r = |provider, meaning, fix, url| {
        Some(Rejection {
            provider,
            meaning,
            fix,
            url,
        })
    };
    // Gmail
    if t.contains("gsmtp") || t.contains("google.com") || t.contains("gmail") {
        if t.contains("5.7.26") {
            return r("Gmail", "the message failed both SPF and DKIM (or DMARC) — Gmail requires at least one to pass", "Fix SPF for the sending IP and make DKIM signing work (see the sending rows)", Some("https://support.google.com/mail/answer/81126"));
        }
        if t.contains("5.7.1") && (t.contains("spam") || t.contains("policy")) {
            return r("Gmail", "Gmail classed the message as likely spam or the sender as unauthenticated", "Authenticate (SPF, DKIM, DMARC), clean the list, warm the IP; check Postmaster Tools", Some("https://support.google.com/mail/answer/81126"));
        }
        if t.contains("4.7.0")
            || t.contains("4.7.28")
            || t.contains("unusual rate")
            || t.contains("rate limit")
        {
            return r(
                "Gmail",
                "rate-limited: too much mail from this IP/domain, or a sudden volume change",
                "Slow down, spread sending, fix authentication; the block clears in hours",
                Some("https://support.google.com/mail/answer/81126"),
            );
        }
        if t.contains("5.1.1") {
            return r(
                "Gmail",
                "the recipient address does not exist",
                "Check the address; remove it from lists",
                None,
            );
        }
        if t.contains("5.2.1") && t.contains("disabled") {
            return r(
                "Gmail",
                "the recipient's account is disabled",
                "Nothing to do on your side",
                None,
            );
        }
        if t.contains("5.4.5") || t.contains("daily sending quota") {
            return r(
                "Gmail",
                "the recipient's Google Workspace domain hit its receiving quota",
                "Retry later; contact the recipient",
                None,
            );
        }
        if t.contains("blocked") && t.contains("ip") {
            return r(
                "Gmail",
                "this IP is blocked by Gmail for sending unsolicited mail",
                "Stop the abuse, fix authentication, then ask Gmail to review",
                Some("https://support.google.com/mail/contact/bulk_send_new"),
            );
        }
    }
    // Microsoft
    if t.contains("outlook.com")
        || t.contains("protection.outlook")
        || t.contains("hotmail")
        || t.contains("office365")
        || t.contains("s3140")
        || t.contains("s3150")
    {
        if t.contains("s3140") {
            return r(
                "Microsoft",
                "S3140: the sending IP has a poor reputation at Outlook.com",
                "Ask Microsoft to delist the IP (Sender Support), check SNDS",
                Some("https://sender.office.com/"),
            );
        }
        if t.contains("s3150") {
            return r(
                "Microsoft",
                "S3150: the sending IP is on Microsoft's block list",
                "Request removal via Outlook.com Sender Support",
                Some("https://sender.office.com/"),
            );
        }
        if t.contains("5.7.606") || t.contains("5.7.5") {
            return r(
                "Microsoft 365",
                "the IP is on Microsoft's blocklist (S3150/5.7.606)",
                "Delist at sender.office.com after stopping the cause",
                Some("https://sender.office.com/"),
            );
        }
        if t.contains("5.7.511") {
            return r(
                "Microsoft 365",
                "the sender or IP is banned by Microsoft's abuse system",
                "Contact delist@messaging.microsoft.com after fixing the cause",
                Some("https://sender.office.com/"),
            );
        }
        if t.contains("5.7.1") && t.contains("unauthenticated") {
            return r(
                "Microsoft",
                "unauthenticated mail: SPF/DKIM/DMARC failed",
                "Fix authentication for the sending IP",
                None,
            );
        }
        if t.contains("4.4.7") || t.contains("delivery time expired") {
            return r(
                "Microsoft",
                "greylisting or throttling — deliveries kept being deferred until Exim gave up",
                "Check the IP's reputation (SNDS); slow down; retry",
                Some("https://sendersupport.olc.protection.outlook.com/snds/"),
            );
        }
        if t.contains("5.4.1") && t.contains("recipient address rejected") {
            return r("Microsoft 365", "the recipient address does not exist at the tenant (Directory-Based Edge Blocking)", "Check the address", None);
        }
        if t.contains("5.1.10") {
            return r(
                "Microsoft 365",
                "the recipient address does not exist",
                "Check the address",
                None,
            );
        }
        if t.contains("5.7.1") && (t.contains("spam") || t.contains("blocked")) {
            return r(
                "Microsoft",
                "the message or sender was blocked as spam",
                "Check SNDS and the sender's reputation; fix authentication",
                Some("https://sendersupport.olc.protection.outlook.com/snds/"),
            );
        }
    }
    // Yahoo/AOL
    if t.contains("yahoo") || t.contains("aol.com") || t.contains("tss04") || t.contains("ts03") {
        if t.contains("tss04") || t.contains("tss") {
            return r(
                "Yahoo",
                "temporary defer: suspicious traffic from this IP/domain (TSS04)",
                "Fix authentication, reduce volume, apply the Yahoo bulk-sender guidelines",
                Some("https://senders.yahooinc.com/"),
            );
        }
        if t.contains("ts03") {
            return r(
                "Yahoo",
                "the IP is blocked for sending spam (TS03)",
                "Request review after stopping the cause",
                Some("https://senders.yahooinc.com/"),
            );
        }
    }
    if (t.contains("icloud") || t.contains("apple")) && (t.contains("cs01") || t.contains("hm08")) {
        return r(
            "iCloud",
            "Apple blocks this sender/IP for spam-like traffic",
            "Fix authentication; contact iCloud postmaster",
            Some("https://support.apple.com/en-us/102322"),
        );
    }
    if t.contains("proofpoint") || t.contains("pphosted") {
        return r(
            "Proofpoint",
            "the receiving side's Proofpoint gateway blocked the message",
            "Check the IP at ipcheck.proofpoint.com and request delisting",
            Some("https://ipcheck.proofpoint.com/"),
        );
    }
    if t.contains("mimecast") {
        return r(
            "Mimecast",
            "the receiving side's Mimecast gateway rejected the message",
            "Check the reason code on the Mimecast delisting page",
            Some("https://community.mimecast.com/s/article/Sender-Delisting"),
        );
    }
    // generic
    if t.contains("spamhaus")
        || t.contains("zen.spamhaus")
        || t.contains("sbl") && t.contains("listed")
    {
        return r(
            "blocklist",
            "the receiver rejects because the sending IP is on Spamhaus",
            "Delist at check.spamhaus.org after fixing the cause",
            Some("https://check.spamhaus.org/"),
        );
    }
    if t.contains("spamcop") {
        return r(
            "blocklist",
            "the receiver rejects because the sending IP is on SpamCop",
            "It expires by itself; stop the cause",
            Some("https://www.spamcop.net/bl.shtml"),
        );
    }
    if t.contains("max emails per hour") || t.contains("exceeded the max emails") {
        return r(
            "cPanel",
            "the account hit cPanel's hourly sending limit",
            "Raise the limit (WHM → Modify an Account) or look for a compromised account",
            None,
        );
    }
    if t.contains("max defer and failure") {
        return r(
            "cPanel",
            "the account hit cPanel's defer/failure percentage",
            "Clean the recipient list; the block lifts at the top of the hour",
            None,
        );
    }
    if t.contains("sender verify failed") || t.contains("sender address rejected") {
        return r(
            "receiver",
            "the receiver could not verify the sender address exists",
            "Make sure the sender address accepts mail (a real mailbox or forwarder)",
            None,
        );
    }
    if t.contains("relay not permitted")
        || t.contains("relaying denied")
        || t.contains("relay access denied")
    {
        return r(
            "receiver",
            "the receiver is not the MX for that domain (or requires authentication)",
            "Check the recipient domain's MX; if it is this server's customer, fix the routing",
            None,
        );
    }
    if t.contains("mailbox full")
        || t.contains("quota exceeded")
        || t.contains("over quota")
        || t.contains("5.2.2")
    {
        return r(
            "receiver",
            "the recipient's mailbox is full",
            "Nothing to do on your side; retry later",
            None,
        );
    }
    if t.contains("5.1.1")
        || t.contains("user unknown")
        || t.contains("no such user")
        || t.contains("does not exist")
        || t.contains("unknown user")
    {
        return r(
            "receiver",
            "the recipient address does not exist",
            "Check the address; remove it from lists",
            None,
        );
    }
    if t.contains("retry timeout exceeded") || t.contains("retry time not reached") {
        return r("Exim", "deliveries kept failing temporarily until the retry limit — the remote host was unreachable, greylisting, or throttling", "Check the remote MX (a delivery test of the recipient address) and this server's reputation", None);
    }
    if t.contains("starttls") || t.contains("tls") && (t.contains("fail") || t.contains("required"))
    {
        return r("receiver", "TLS negotiation failed or TLS is required and could not be established", "Check this server's TLS (openssl s_client) and the remote's certificate; DANE/MTA-STS may be in play", None);
    }
    if t.contains("ptr") || t.contains("reverse dns") || t.contains("rdns") {
        return r(
            "receiver",
            "the receiver requires forward-confirmed reverse DNS of the sending IP",
            "Set the PTR of the outbound IP to the HELO name (hosting provider)",
            None,
        );
    }
    if t.contains("dmarc") {
        return r(
            "receiver",
            "the message failed the sender domain's DMARC policy",
            "Fix SPF/DKIM alignment for the From domain",
            None,
        );
    }
    if t.contains("spf") {
        return r(
            "receiver",
            "the receiver rejects on SPF",
            "Add the sending IP to the domain's SPF record",
            None,
        );
    }
    if t.contains("greylist") {
        return r(
            "receiver",
            "greylisted: the first attempt is deferred on purpose",
            "Nothing to do; Exim retries",
            None,
        );
    }
    None
}

// ---- tasks ---------------------------------------------------------------------

pub fn tasks(inputs: &Inputs) -> Vec<Task> {
    if !inputs.audit {
        return vec![];
    }
    vec![
        Task::new("log", &["acct"], log_task),
        Task::new("queue", &["acct"], queue_task),
        Task::new("abuse", &["acct", "log"], abuse_task),
    ]
}

fn unknown(id: &str, cat: Category, title: &str, why: impl Into<String>) -> Check {
    Check::new(id, S, cat, Verdict::Unknown, Severity::Info, title, why)
}

/// Mask every address in a log line except the tested one and its domain.
pub fn mask_line(line: &str, keep_domain: &str, keep_addr: &str) -> String {
    let mut out = String::with_capacity(line.len());
    for (i, tok) in line.split(' ').enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let core = tok.trim_matches(|c: char| {
            matches!(c, '<' | '>' | ',' | ':' | '(' | ')' | '\'' | '"' | ';')
        });
        if core.contains('@')
            && core.len() > 3
            && !core.eq_ignore_ascii_case(keep_addr)
            && !core
                .to_ascii_lowercase()
                .ends_with(&format!("@{keep_domain}"))
        {
            out.push_str(&tok.replace(core, &mask_address(core)));
        } else {
            out.push_str(tok);
        }
    }
    out
}

fn mainlog_path(cp: &Cp, cfg: &Config) -> std::path::PathBuf {
    if cp.live() {
        std::path::PathBuf::from(&cfg.exim_mainlog_path)
    } else {
        cp.path("/var/log/exim_mainlog")
    }
}

fn log_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Logs;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let addr = ctx.inputs.address.to_ascii_lowercase();
    let d = &ctx.inputs.domain;
    let days = ctx.inputs.days;
    let mut out = Vec::new();
    let mask = |l: &str| mask_line(l, d, &addr);

    // ---- Exim main log: messages to and from the address
    let path = mainlog_path(&cp, &ctx.cfg);
    if !path.exists() {
        out.push(unknown(
            "log.received",
            cat,
            "Exim main log",
            format!("{} is not readable", path.display()),
        ));
    } else {
        let sc = scan(&path, &addr, days);
        let scope_note = format!(
            "{} day(s), {} file(s), {:.1} MB scanned{}",
            days,
            sc.files.len(),
            sc.bytes_scanned as f64 / 1_048_576.0,
            if sc.truncated {
                " (large files: only their tail)"
            } else {
                ""
            }
        );
        let inbound: Vec<&MessageTrail> = sc
            .messages
            .iter()
            .filter(|m| {
                m.recipients.iter().any(|r| r == &addr)
                    || m.delivered
                        .iter()
                        .chain(m.failed.iter())
                        .chain(m.deferred.iter())
                        .any(|l| l.addr == addr)
            })
            .collect();
        let outbound: Vec<&MessageTrail> = sc
            .messages
            .iter()
            .filter(|m| m.sender == addr || m.auth.as_deref() == Some(&addr))
            .collect();
        // inbound
        let in_failed: Vec<&LogLine> = inbound
            .iter()
            .flat_map(|m| m.failed.iter().filter(|l| l.addr == addr))
            .collect();
        let in_deferred: Vec<&LogLine> = inbound
            .iter()
            .flat_map(|m| m.deferred.iter().filter(|l| l.addr == addr))
            .collect();
        let in_delivered = inbound
            .iter()
            .filter(|m| m.delivered.iter().any(|l| l.addr == addr))
            .count();
        let ev_in: String = inbound
            .iter()
            .take(8)
            .map(|m| {
                format!(
                    "{} {} from {}{} → {}",
                    m.ts,
                    m.id,
                    if m.sender.is_empty() {
                        "<>".into()
                    } else {
                        mask_address(&m.sender)
                    },
                    m.auth
                        .as_ref()
                        .map(|a| format!(" (auth {})", mask(a)))
                        .unwrap_or_default(),
                    if let Some(f) = m.failed.iter().find(|l| l.addr == addr) {
                        format!("FAILED: {}", f.response.clone().unwrap_or_default())
                    } else if let Some(x) = m.deferred.iter().find(|l| l.addr == addr) {
                        format!("deferred: {}", x.response.clone().unwrap_or_default())
                    } else if m.delivered.iter().any(|l| l.addr == addr) {
                        "delivered".into()
                    } else if m.frozen {
                        "frozen".into()
                    } else {
                        "in progress".into()
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(if inbound.is_empty() {
            Check::new("log.received", S, cat, Verdict::Pass, Severity::Info, format!("no mail to {addr} in the last {days} day(s)"), format!("nothing addressed to it was accepted by Exim ({scope_note}) — either nobody wrote, or it was rejected at SMTP time (see the reject log row)"))
        } else if !in_failed.is_empty() {
            let reasons: Vec<String> = in_failed.iter().take(3).map(|l| l.response.clone().unwrap_or_default()).collect();
            let cls = reasons.iter().find_map(|r| classify_rejection(r));
            let mut c = Check::new("log.received", S, cat, Verdict::Fail, Severity::High, format!("{} of {} messages to {addr} failed delivery", in_failed.len(), inbound.len()), format!("{}{}", reasons.join(" · "), cls.as_ref().map(|c| format!(" — {}", c.meaning)).unwrap_or_default())).evidence("messages", ev_in);
            if let Some(c2) = cls {
                c = c.fix(Fix {
                    summary: c2.fix.into(),
                    url: c2.url.map(str::to_string),
                    ..Default::default()
                });
            }
            c
        } else if !in_deferred.is_empty() {
            Check::new("log.received", S, cat, Verdict::Warn, Severity::Medium, format!("{} of {} messages to {addr} are being deferred", in_deferred.len(), inbound.len()), in_deferred.iter().take(3).map(|l| l.response.clone().unwrap_or_default()).collect::<Vec<_>>().join(" · ")).evidence("messages", ev_in)
        } else {
            Check::new("log.received", S, cat, Verdict::Pass, Severity::Info, format!("{} message(s) to {addr}, {in_delivered} delivered", inbound.len()), scope_note.clone()).evidence("messages", ev_in)
        });
        // outbound
        let out_failed: Vec<&LogLine> = outbound.iter().flat_map(|m| m.failed.iter()).collect();
        let out_deferred: Vec<&LogLine> = outbound.iter().flat_map(|m| m.deferred.iter()).collect();
        let ev_out: String = outbound
            .iter()
            .take(8)
            .map(|m| {
                format!(
                    "{} {} → {}{}",
                    m.ts,
                    m.id,
                    m.recipients
                        .iter()
                        .map(|r| mask(r))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if let Some(f) = m.failed.first() {
                        format!(" FAILED: {}", f.response.clone().unwrap_or_default())
                    } else if let Some(x) = m.deferred.first() {
                        format!(" deferred: {}", x.response.clone().unwrap_or_default())
                    } else if !m.delivered.is_empty() {
                        format!(
                            " delivered ({})",
                            m.delivered
                                .first()
                                .and_then(|l| l.response.clone())
                                .unwrap_or_default()
                                .chars()
                                .take(80)
                                .collect::<String>()
                        )
                    } else if m.frozen {
                        " frozen".into()
                    } else {
                        String::new()
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(if outbound.is_empty() {
            Check::new(
                "log.sent",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                format!("no mail from {addr} in the last {days} day(s)"),
                scope_note.clone(),
            )
        } else if !out_failed.is_empty() {
            let reasons: Vec<String> = out_failed
                .iter()
                .take(3)
                .map(|l| l.response.clone().unwrap_or_default())
                .collect();
            let cls = reasons.iter().find_map(|r| classify_rejection(r));
            let mut c = Check::new(
                "log.sent",
                S,
                cat,
                Verdict::Fail,
                Severity::High,
                format!(
                    "{} of {} messages from {addr} bounced",
                    out_failed.len(),
                    outbound.len()
                ),
                format!(
                    "{}{}",
                    reasons
                        .iter()
                        .map(|r| r.chars().take(200).collect::<String>())
                        .collect::<Vec<_>>()
                        .join(" · "),
                    cls.as_ref()
                        .map(|c| format!(" — {}: {}", c.provider, c.meaning))
                        .unwrap_or_default()
                ),
            )
            .evidence("messages", ev_out);
            if let Some(c2) = cls {
                c = c.fix(Fix {
                    summary: c2.fix.into(),
                    url: c2.url.map(str::to_string),
                    ..Default::default()
                });
            }
            c
        } else if !out_deferred.is_empty() {
            let reasons: Vec<String> = out_deferred
                .iter()
                .take(3)
                .map(|l| {
                    l.response
                        .clone()
                        .unwrap_or_default()
                        .chars()
                        .take(200)
                        .collect()
                })
                .collect();
            let cls = reasons.iter().find_map(|r| classify_rejection(r));
            Check::new(
                "log.sent",
                S,
                cat,
                Verdict::Warn,
                Severity::Medium,
                format!(
                    "{} of {} messages from {addr} are deferred",
                    out_deferred.len(),
                    outbound.len()
                ),
                format!(
                    "{}{}",
                    reasons.join(" · "),
                    cls.as_ref()
                        .map(|c| format!(" — {}: {}", c.provider, c.meaning))
                        .unwrap_or_default()
                ),
            )
            .evidence("messages", ev_out)
        } else {
            Check::new(
                "log.sent",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                format!("{} message(s) from {addr}, all delivered", outbound.len()),
                scope_note.clone(),
            )
            .evidence("messages", ev_out)
        });
        if !sc.rejects.is_empty() {
            out.push(
                Check::new(
                    "log.rejected_here",
                    S,
                    cat,
                    Verdict::Warn,
                    Severity::Medium,
                    format!(
                        "{} rejection(s) involving {addr} in the main log",
                        sc.rejects.len()
                    ),
                    sc.rejects
                        .iter()
                        .take(3)
                        .map(|l| {
                            l.response
                                .clone()
                                .unwrap_or_default()
                                .chars()
                                .take(160)
                                .collect::<String>()
                        })
                        .collect::<Vec<_>>()
                        .join(" · "),
                )
                .evidence(
                    "lines",
                    sc.rejects
                        .iter()
                        .take(6)
                        .map(|l| mask(&l.raw))
                        .collect::<Vec<_>>()
                        .join("\n"),
                ),
            );
        }
    }

    // ---- reject log
    let rpath = if cp.live() {
        std::path::PathBuf::from("/var/log/exim_rejectlog")
    } else {
        cp.path("/var/log/exim_rejectlog")
    };
    if let Some(text) = tail_bytes(&rpath, 8 * 1024 * 1024) {
        let cutoff = crate::civil::Date::from_unix(
            crate::delivery::now_secs().saturating_sub(days.max(1) as u64 * 86_400),
        )
        .to_string();
        let mut auth_fail = 0usize;
        let mut auth_ips: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut as_sender = Vec::new();
        let mut as_rcpt = Vec::new();
        for line in text.lines() {
            if line.len() < 10 || line[..10] < *cutoff {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            if !lower.contains(&addr)
                && !lower.contains(&ctx.inputs.local_part.to_ascii_lowercase())
            {
                continue;
            }
            let Some(r) = parse_rejectlog_line(line) else {
                continue;
            };
            if r.auth_failure
                && r.who.as_deref().is_some_and(|w| {
                    w.eq_ignore_ascii_case(&addr) || w.eq_ignore_ascii_case(&ctx.inputs.local_part)
                })
            {
                auth_fail += 1;
                if let Some(ip) = &r.ip {
                    auth_ips.insert(ip.clone());
                }
            } else if r.who.as_deref() == Some(addr.as_str()) {
                as_sender.push(r);
            } else if r.rcpt.as_deref() == Some(addr.as_str()) {
                as_rcpt.push(r);
            }
        }
        if auth_fail > 0 {
            out.push(Check::new("log.auth_failures", S, cat, if auth_fail >= 20 { Verdict::Warn } else { Verdict::Pass }, if auth_fail >= 20 { Severity::Medium } else { Severity::Info }, format!("{auth_fail} failed login(s) as {addr} from {} address(es)", auth_ips.len()), if auth_fail >= 20 { "a password-guessing campaign against this mailbox; cPHulk and csf block the sources, but a weak password will eventually fall".to_string() } else { "a few wrong passwords — normal noise".to_string() }).evidence("sources", auth_ips.iter().take(20).cloned().collect::<Vec<_>>().join(", ")).fix_summary("Use a strong password for the mailbox; check WHM → cPHulk Brute Force Protection is on"));
        }
        if !as_rcpt.is_empty() {
            let reasons: Vec<String> = as_rcpt
                .iter()
                .rev()
                .take(3)
                .map(|r| {
                    format!(
                        "{} from {}: {}",
                        r.ts,
                        r.ip.clone().unwrap_or_default(),
                        mask(&r.reason).chars().take(140).collect::<String>()
                    )
                })
                .collect();
            let legit = as_rcpt
                .iter()
                .any(|r| r.reason.contains("No Such User") || r.reason.contains("does not exist"));
            out.push(Check::new("log.rejects", S, cat, if legit { Verdict::Fail } else { Verdict::Warn }, if legit { Severity::High } else { Severity::Low }, format!("{} inbound message(s) to {addr} rejected at SMTP time", as_rcpt.len()), if legit { "Exim answered \"No Such User Here\" — the address did not exist (or the account was suspended) when they arrived; the senders got a bounce".to_string() } else { "rejected by the ACLs (blocklist, sender verification, spam score) — usually spam, but check the reasons".to_string() }).evidence("recent", reasons.join("\n")));
        }
        if !as_sender.is_empty() {
            out.push(Check::new("log.rejects_as_sender", S, cat, Verdict::Warn, Severity::Medium, format!("{} message(s) claiming to be from {addr} were rejected here", as_sender.len()), "someone (a bot, a misconfigured client, or a forger) tried to send as this address without succeeding; if these come from outside, the address is being spoofed — DMARC with p=reject protects the recipients").evidence("recent", as_sender.iter().rev().take(4).map(|r| format!("{} from {}: {}", r.ts, r.ip.clone().unwrap_or_default(), mask(&r.reason).chars().take(140).collect::<String>())).collect::<Vec<_>>().join("\n")));
        }
    }

    // ---- panic log
    let ppath = if cp.live() {
        std::path::PathBuf::from("/var/log/exim_paniclog")
    } else {
        cp.path("/var/log/exim_paniclog")
    };
    match std::fs::metadata(&ppath) {
        Ok(m) if m.len() > 0 => {
            let tail = tail_bytes(&ppath, 4096).unwrap_or_default();
            let last: Vec<&str> = tail.lines().rev().take(5).collect();
            out.push(Check::new("log.panic", S, cat, Verdict::Fail, Severity::High, "Exim's panic log is not empty", "Exim writes here only when something is seriously wrong (a configuration error, a crashed transport, a full disk); every entry may mean lost or stuck mail").evidence("last lines", last.iter().rev().map(|l| mask(l)).collect::<Vec<_>>().join("\n")).fix(Fix {
                summary: "Read the panic log, fix the cause, then empty it so new entries stand out".into(),
                command: Some("tail -50 /var/log/exim_paniclog".into()),
                ..Default::default()
            }));
        }
        Ok(_) => out.push(Check::new(
            "log.panic",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "Exim's panic log is empty",
            "no serious Exim errors recorded",
        )),
        Err(_) => {}
    }

    // ---- Dovecot logins (maillog)
    let mpath = if cp.live() {
        std::path::PathBuf::from(&ctx.cfg.maillog_path)
    } else {
        cp.path("/var/log/maillog")
    };
    if let Some(text) = tail_bytes(&mpath, 16 * 1024 * 1024) {
        let mut ok: Vec<Login> = Vec::new();
        let mut failed = 0usize;
        for line in text.lines() {
            if !line.contains(&addr) && !line.contains(&format!("user=<{}>", ctx.inputs.local_part))
            {
                continue;
            }
            if let Some(l) = parse_dovecot_line(line) {
                if l.user == addr || l.user == ctx.inputs.local_part.to_ascii_lowercase() {
                    if l.ok {
                        ok.push(l);
                    } else {
                        failed += 1;
                    }
                }
            }
        }
        let ips: std::collections::BTreeSet<&str> = ok.iter().map(|l| l.ip.as_str()).collect();
        res.set_fact(
            "login_ips",
            Json::Array(ips.iter().map(|i| Json::str(*i)).collect()),
        );
        res.set_fact("login_count", Json::Int(ok.len() as i64));
        out.push(if ok.is_empty() && failed == 0 {
            Check::new("log.dovecot", S, cat, Verdict::Pass, Severity::Info, "no IMAP/POP logins for the mailbox in the log window", "the maillog tail has no login for it — the user reads via webmail on another path, or has not connected lately")
        } else {
            Check::new("log.dovecot", S, cat, if failed > 50 { Verdict::Warn } else { Verdict::Pass }, if failed > 50 { Severity::Medium } else { Severity::Info }, format!("{} successful login(s) from {} address(es), {failed} failed", ok.len(), ips.len()), format!("last: {}", ok.last().map(|l| format!("{} {} from {}", l.ts, l.service, l.ip)).unwrap_or_default())).evidence("addresses", ips.iter().take(30).cloned().collect::<Vec<_>>().join(", "))
        });
    }

    // ---- MailScanner's table
    if cp.live() {
        match crate::stats::sender_activity(&ctx.cfg, &addr, days) {
            Ok(v) => {
                let n = |k: &str| match v.get(k) {
                    Some(Json::Int(n)) => *n,
                    Some(Json::Num(s)) => s.parse().unwrap_or(0),
                    _ => 0,
                };
                let (total, spam, quarantined, infected) =
                    (n("total"), n("spam"), n("quarantined"), n("infected"));
                out.push(if total == 0 {
                    Check::new("log.mailscanner", S, cat, Verdict::Pass, Severity::Info, format!("MailScanner saw no mail from {addr} in {days} day(s)"), "nothing from this sender passed through the scanner")
                } else if spam > 0 || infected > 0 {
                    Check::new("log.mailscanner", S, cat, Verdict::Warn, Severity::Medium, format!("MailScanner flagged {spam} spam / {infected} infected of {total} messages from {addr}"), format!("{quarantined} quarantined — mail from this address is being classed as spam on the way out (a compromised mailbox, or a newsletter that looks like spam)")).fix_summary("Open Messages, filter by this sender, and look at the scores and rules; release false positives from Quarantine")
                } else {
                    Check::new("log.mailscanner", S, cat, Verdict::Pass, Severity::Info, format!("MailScanner passed all {total} message(s) from {addr}"), format!("average score {}", v.get("avg_score").and_then(Json::as_str).unwrap_or("0")))
                });
            }
            Err(e) => out.push(unknown(
                "log.mailscanner",
                cat,
                "MailScanner log table",
                format!("database: {e}"),
            )),
        }
    }
    (out, vec![])
}

fn queue_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Logs;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    if !cp.live() {
        return (vec![], vec![]);
    }
    let addr = ctx.inputs.address.to_ascii_lowercase();
    let d = &ctx.inputs.domain;
    let (incoming, outgoing) = crate::service::queue_dirs(&ctx.cfg);
    let mut mine = Vec::new();
    let mut total = 0usize;
    for (label, dir) in [
        ("MailScanner queue", incoming),
        ("delivery queue", outgoing),
    ] {
        let l = crate::queueview::list_queue(&dir, 5000);
        total += l.total;
        for m in l.msgs {
            if m.sender == addr || m.recipients.iter().any(|r| r.eq_ignore_ascii_case(&addr)) {
                mine.push((label, m));
            }
        }
    }
    let ev: String = mine
        .iter()
        .take(10)
        .map(|(q, m)| {
            format!(
                "{} {} {}{} from {} to {} ({}h)",
                q,
                m.id,
                if m.frozen { "FROZEN " } else { "" },
                if m.bounce { "bounce " } else { "" },
                if m.sender.is_empty() {
                    "<>".into()
                } else {
                    mask_line(&m.sender, d, &addr)
                },
                m.recipients
                    .iter()
                    .map(|r| mask_line(r, d, &addr))
                    .collect::<Vec<_>>()
                    .join(","),
                m.age_secs / 3600
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let frozen = mine.iter().filter(|(_, m)| m.frozen).count();
    let mut out = vec![if mine.is_empty() {
        Check::new(
            "queue.pending",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "nothing queued for or from the address",
            format!("{total} message(s) in the queues, none involving it"),
        )
    } else if frozen > 0 {
        let id = mine
            .iter()
            .find(|(_, m)| m.frozen)
            .map(|(_, m)| m.id.clone())
            .unwrap_or_default();
        let log = crate::service::queue_msg_view(&ctx.cfg, None, &id, "log");
        Check::new("queue.pending", S, cat, Verdict::Fail, Severity::High, format!("{frozen} frozen message(s) involving {addr}"), "frozen messages will not be retried: Exim gave up (undeliverable and the bounce failed too) — they sit until deleted or thawed").evidence("queued", ev).evidence(format!("log of {id}"), log.lines().rev().take(12).collect::<Vec<_>>().into_iter().rev().map(|l| mask_line(l, d, &addr)).collect::<Vec<_>>().join("\n")).fix(Fix {
            summary: "Read the message log in Queues, fix the cause, then Deliver (thaw) or Delete".into(),
            location: Some("Queues → search the address".into()),
            ..Default::default()
        })
    } else {
        Check::new(
            "queue.pending",
            S,
            cat,
            Verdict::Warn,
            Severity::Medium,
            format!("{} queued message(s) involving {addr}", mine.len()),
            "waiting for delivery or a retry; the oldest ones say why in their log",
        )
        .evidence("queued", ev)
        .fix(Fix {
            summary: "Open the message log in Queues for the deferral reason".into(),
            location: Some("Queues → search the address".into()),
            ..Default::default()
        })
    }];
    if total > 500 {
        out.push(Check::new("queue.size", S, cat, Verdict::Warn, Severity::Medium, format!("{total} messages in the queues"), "a large queue slows every delivery down and often means a spam run or a broken transport").fix_summary("Queues → Delete all spam / bounces; check the top senders"));
    }
    (out, vec![])
}

fn abuse_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Abuse;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let mut out = Vec::new();
    let addr = ctx.inputs.address.to_ascii_lowercase();
    let user = res.fact_str("acct_user").unwrap_or_default();

    // csf: the supplied IP and the recent login addresses
    if cp.live() && crate::csf::available() {
        let mut targets: Vec<String> = ctx.inputs.ip.map(|i| i.to_string()).into_iter().collect();
        for ip in res.fact_strs("login_ips").into_iter().rev().take(3) {
            if !targets.contains(&ip) {
                targets.push(ip);
            }
        }
        let mut hits = Vec::new();
        for t in &targets {
            let r = crate::csf::lookup(t);
            if !r.starts_with("no csf entries") && !r.contains("not installed") {
                hits.push(format!(
                    "{t}: {}",
                    r.lines()
                        .filter(|l| l.contains("DENY")
                            || l.contains("ALLOW")
                            || l.contains("csf.")
                            || l.contains("Temporary"))
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
        }
        out.push(if targets.is_empty() {
            Check::new("abuse.csf", S, cat, Verdict::NotApplicable, Severity::Info, "csf: no address to look up", "give a sending IP under Advanced, or wait for a login to appear in the log")
        } else if hits.is_empty() {
            Check::new("abuse.csf", S, cat, Verdict::Pass, Severity::Info, "csf has no entries for the relevant addresses", targets.join(", "))
        } else {
            Check::new("abuse.csf", S, cat, Verdict::Warn, Severity::Medium, "csf lists one of the relevant addresses", "a blocked address cannot connect at all — the user's own IP being blocked (after wrong passwords) is the classic \"I cannot send or receive\"").evidence("csf -g", hits.join("\n")).fix(Fix {
                summary: "If it is the user's IP, unblock it and fix the client's password".into(),
                command: Some("csf -dr <ip>   # or: csf -tr <ip> for a temporary block".into()),
                location: Some("WHM → ConfigServer Security & Firewall → Search for IP".into()),
                ..Default::default()
            })
        });
    }
    // cPHulk
    if let Some(v) = cp.whmapi1("cphulk_status", "cphulk_status", &[]) {
        let on = matches!(
            v.get("data").and_then(|d| d.get("is_enabled")),
            Some(Json::Int(1))
        );
        out.push(Check::new("abuse.cphulk", S, cat, if on { Verdict::Pass } else { Verdict::Warn }, if on { Severity::Info } else { Severity::Low }, if on { "cPHulk brute-force protection is on" } else { "cPHulk brute-force protection is off" }, if on { "repeated failed logins lock the source and, after many, the account for a while — a user typing a wrong password five times can lock themselves out" } else { "password guessing against mailboxes goes unhindered" }).fix_summary(if on { "If the user is locked out: WHM → cPHulk → History Reports → remove the entry" } else { "Enable it: WHM → cPHulk Brute Force Protection" }));
    }
    // outbound bursts (this hour) for the account's logins
    if cp.live() && ctx.cfg.alert_burst_per_hour > 0 {
        let bursts =
            crate::monitor::outbound_bursts(&ctx.cfg, ctx.cfg.alert_burst_per_hour as usize);
        let domains = crate::users::user_domains(&user);
        let mine: Vec<&(String, usize)> = bursts
            .iter()
            .filter(|(login, _)| {
                login == &user
                    || domains
                        .iter()
                        .any(|d| login.to_ascii_lowercase().ends_with(&format!("@{d}")))
            })
            .collect();
        if !mine.is_empty() {
            out.push(Check::new("abuse.outbound_bursts", S, cat, Verdict::Fail, Severity::High, "an outbound sending burst from this account this hour", mine.iter().map(|(l, n)| format!("{} sent {n} messages", mask_line(l, &ctx.inputs.domain, &addr))).collect::<Vec<_>>().join("; ")).fix(Fix {
                summary: "Treat as a compromised mailbox until proven otherwise: change the password, look at the queue for the spam run, delete it".into(),
                location: Some("Queues → Delete all spam; cPanel → Email Accounts → change password".into()),
                ..Default::default()
            }));
        } else {
            out.push(Check::new(
                "abuse.outbound_bursts",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                "no outbound burst from the account this hour",
                format!(
                    "threshold {} messages/hour (alert_burst_per_hour)",
                    ctx.cfg.alert_burst_per_hour
                ),
            ));
        }
    }
    // many login sources
    let ips = res.fact_strs("login_ips");
    if ips.len() >= 8 {
        out.push(Check::new("abuse.compromise_hints", S, cat, Verdict::Warn, Severity::Medium, format!("logins from {} different addresses", ips.len()), "a mailbox used from a phone, a laptop and an office is normal; dozens of addresses in the log window suggest shared or stolen credentials").evidence("addresses", ips.join(", ")).fix_summary("Check the addresses' countries (Dashboard → GeoIP), change the password if they do not fit the user"));
    }
    (out, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mainlog_lines() {
        let l = parse_mainlog_line("2026-09-13 08:03:35 1x5dJQ-00000002ksM-1pMm <= noreply@winservices.it H=ncc.transfervda.com ([127.0.0.1]) [78.47.94.167]:59324 P=esmtpsa X=TLS1.3:TLS_AES_256_GCM_SHA384:256 A=dovecot_login:noreply@winservices.it S=23324 Q=mailscanner id=x@y T=\"Contact\" for support@winservices.it").unwrap();
        assert_eq!(l.kind, Some(Kind::Arrival));
        assert_eq!(l.id.as_deref(), Some("1x5dJQ-00000002ksM-1pMm"));
        assert_eq!(l.addr, "noreply@winservices.it");
        assert_eq!(l.auth.as_deref(), Some("noreply@winservices.it"));
        assert_eq!(l.ip.as_deref(), Some("78.47.94.167"));
        assert_eq!(l.recipients, vec!["support@winservices.it"]);
        let l = parse_mainlog_line("2026-09-13 03:37:38 1x5ZA2-00000002VJa-0L1J => server <root@ncc.transfervda.com> R=virtual_user T=dovecot_virtual_delivery C=\"250 2.0.0 <server@transfervda.com> Saved\"").unwrap();
        assert_eq!(l.kind, Some(Kind::Delivered));
        assert_eq!(l.addr, "root@ncc.transfervda.com");
        assert_eq!(l.transport.as_deref(), Some("dovecot_virtual_delivery"));
        assert!(l.response.as_deref().unwrap().starts_with("250 2.0.0"));
        let l = parse_mainlog_line("2026-09-16 12:03:40 1x6mUB-00000006Pya-498Q => edhunt@hotmail.com R=dkim_lookuphost T=dkim_remote_smtp H=hotmail-com.olc.protection.outlook.com [52.101.91.152] X=TLS1.3:TLS_AES_256_GCM_SHA384:256 CV=yes C=\"250 2.6.0 <x@transfervda.com> Queued mail for delivery\"").unwrap();
        assert_eq!(l.addr, "edhunt@hotmail.com");
        assert_eq!(
            l.host.as_deref(),
            Some("hotmail-com.olc.protection.outlook.com")
        );
        assert_eq!(l.ip.as_deref(), Some("52.101.91.152"));
        let l = parse_mainlog_line("2026-09-16 12:03:40 1x6mUB-00000006Pya-498Q ** bad@gmail.com R=lookuphost T=remote_smtp H=gmail-smtp-in.l.google.com [1.2.3.4]: SMTP error from remote mail server after RCPT TO:<bad@gmail.com>: 550-5.1.1 The email account that you tried to reach does not exist. - gsmtp").unwrap();
        assert_eq!(l.kind, Some(Kind::Failed));
        assert_eq!(l.addr, "bad@gmail.com");
        assert!(
            l.response
                .as_deref()
                .unwrap()
                .starts_with("SMTP error from remote"),
            "{:?}",
            l.response
        );
        assert_eq!(
            classify_rejection(l.response.as_deref().unwrap())
                .unwrap()
                .provider,
            "Gmail"
        );
        let l = parse_mainlog_line("2026-09-16 12:03:40 1x6mUB-00000006Pya-498Q == x@y.test R=lookuphost T=remote_smtp defer (-53): retry time not reached for any host").unwrap();
        assert_eq!(l.kind, Some(Kind::Deferred));
        assert!(l
            .response
            .as_deref()
            .unwrap()
            .contains("retry time not reached"));
        let l =
            parse_mainlog_line("2026-09-13 03:37:38 1x5ZA2-00000002VJa-0L1J Completed").unwrap();
        assert_eq!(l.kind, Some(Kind::Completed));
        let l = parse_mainlog_line(
            "2026-09-13 03:37:38 1x5ZA2-00000002VJa-0L1J *** frozen (delivery error message)",
        )
        .unwrap();
        assert_eq!(l.kind, Some(Kind::Frozen));
        let l = parse_mainlog_line("2026-09-19 05:55:23 H=(dizel5267-66f18) [213.177.179.24]:58018 F=<booking@transfervda.com> rejected RCPT <honoring5267@outlook.com>: Rejected relay attempt").unwrap();
        assert_eq!(l.kind, Some(Kind::Reject));
        assert!(l.id.is_none());
        assert_eq!(l.ip.as_deref(), Some("213.177.179.24"));
        assert!(parse_mainlog_line("garbage").is_none());
    }

    #[test]
    fn parses_rejectlog_and_dovecot() {
        let r = parse_rejectlog_line("2026-09-19 20:54:38 dovecot_login authenticator failed for H=(72.20.167.124.adsl-pool.sx.cn) [179.185.227.77]:58062: 535 Incorrect authentication data (set_id=info@winservices.it)").unwrap();
        assert!(r.auth_failure);
        assert_eq!(r.who.as_deref(), Some("info@winservices.it"));
        assert_eq!(r.ip.as_deref(), Some("179.185.227.77"));
        assert!(r.reason.starts_with("535"));
        let r = parse_rejectlog_line("2026-09-19 05:55:23 H=(x) [213.177.179.24]:58018 F=<booking@transfervda.com> rejected RCPT <honoring5267@outlook.com>: Rejected relay attempt: '213.177.179.24'").unwrap();
        assert!(!r.auth_failure);
        assert_eq!(r.who.as_deref(), Some("booking@transfervda.com"));
        assert_eq!(r.rcpt.as_deref(), Some("honoring5267@outlook.com"));
        assert!(r.reason.starts_with("rejected RCPT"));
        let l = parse_dovecot_line("Sep 13 04:00:41 ncc dovecot[32629]: pop3-login: Login aborted: Connection closed (auth failed, 1 attempts in 2 secs) (auth_failed): user=<admin@taxiaosta.com>, method=PLAIN, rip=90.153.107.201, lip=78.47.94.167, session=<x>").unwrap();
        assert!(!l.ok);
        assert_eq!(
            (l.user.as_str(), l.ip.as_str(), l.service.as_str()),
            ("admin@taxiaosta.com", "90.153.107.201", "pop3")
        );
        let l = parse_dovecot_line("Sep 13 04:00:41 ncc dovecot[32629]: imap-login: Login: user=<info@x.test>, method=PLAIN, rip=1.2.3.4, lip=5.6.7.8, mpid=1, TLS, session=<y>").unwrap();
        assert!(l.ok);
        assert_eq!(l.user, "info@x.test");
        assert!(parse_dovecot_line("Sep 13 03:43:57 ncc dovecot[32629]: imap-login: Login aborted: Connection closed (no auth attempts in 0 secs) (no_auth_attempts): user=<>, rip=64.62.197.17").is_none());
    }

    #[test]
    fn classifies_rejections() {
        assert_eq!(classify_rejection("550-5.7.26 This mail has been blocked because the sender is unauthenticated. - gsmtp").unwrap().provider, "Gmail");
        assert_eq!(classify_rejection("550 5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus. To request removal from this list see https://www.spamhaus.org/query/ip/1.2.3.4 (S3140)").unwrap().meaning, "S3140: the sending IP has a poor reputation at Outlook.com");
        assert_eq!(classify_rejection("421 4.7.0 [TSS04] Messages from 1.2.3.4 temporarily deferred due to unexpected volume or user complaints - yahoo").unwrap().provider, "Yahoo");
        assert_eq!(classify_rejection("Domain transfervda.com has exceeded the max emails per hour (200/200 (100%)) allowed.").unwrap().provider, "cPanel");
        assert_eq!(
            classify_rejection("retry timeout exceeded")
                .unwrap()
                .provider,
            "Exim"
        );
        assert_eq!(classify_rejection("550 5.1.1 <x@y>: Recipient address rejected: User unknown in virtual mailbox table").unwrap().meaning, "the recipient address does not exist");
        assert!(classify_rejection("something new").is_none());
    }

    #[test]
    fn masks_and_scans() {
        assert_eq!(
            mask_line(
                "<= a@x.test for b@other.test c@x.test",
                "x.test",
                "a@x.test"
            ),
            "<= a@x.test for b***@other.test c@x.test"
        );
        let dir = std::env::temp_dir().join(format!("msfe-dlvlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let today = crate::civil::Date::from_unix(crate::delivery::now_secs()).to_string();
        let log = format!(
            "{today} 10:00:00 1xAAAA-000000000001-AAAA <= sender@else.test H=mx.else.test [1.2.3.4] P=esmtps S=100 for me@x.test\n\
             {today} 10:00:01 1xAAAA-000000000001-AAAA => me <me@x.test> R=virtual_user T=dovecot_virtual_delivery C=\"250 ok\"\n\
             {today} 10:00:01 1xAAAA-000000000001-AAAA Completed\n\
             {today} 11:00:00 1xBBBB-000000000002-BBBB <= me@x.test H=h [5.6.7.8] P=esmtpsa A=dovecot_login:me@x.test S=200 for bad@gmail.com\n\
             {today} 11:00:05 1xBBBB-000000000002-BBBB ** bad@gmail.com R=lookuphost T=remote_smtp H=gmail-smtp-in.l.google.com [1.1.1.1]: SMTP error from remote mail server after RCPT TO:<bad@gmail.com>: 550-5.1.1 The email account that you tried to reach does not exist. - gsmtp\n\
             {today} 11:00:06 1xBBBB-000000000002-BBBB Completed\n\
             {today} 12:00:00 1xCCCC-000000000003-CCCC <= other@x.test H=h [5.6.7.8] P=esmtpsa A=dovecot_login:other@x.test S=200 for z@z.test\n\
             2020-01-01 00:00:00 1xDDDD-000000000004-DDDD <= me@x.test H=h [5.6.7.8] S=1 for old@z.test\n"
        );
        std::fs::write(dir.join("exim_mainlog"), log).unwrap();
        let sc = scan(&dir.join("exim_mainlog"), "me@x.test", 2);
        assert_eq!(
            sc.messages.len(),
            2,
            "{:?}",
            sc.messages.iter().map(|m| m.id.clone()).collect::<Vec<_>>()
        );
        let sent = sc
            .messages
            .iter()
            .find(|m| m.sender == "me@x.test")
            .unwrap();
        assert_eq!(sent.failed.len(), 1);
        assert!(sent.completed);
        let recv = sc
            .messages
            .iter()
            .find(|m| m.recipients.contains(&"me@x.test".to_string()))
            .unwrap();
        assert_eq!(recv.delivered.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
