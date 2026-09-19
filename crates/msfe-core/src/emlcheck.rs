//! What an uploaded message says about its own delivery: the receiving
//! hop's Authentication-Results, the DKIM signature, alignment, the
//! Received chain and its delays, required headers, line lengths, bulk-mail
//! requirements, links, attachments and body shape. And the other direction:
//! a bounce (DSN) taken apart into recipient, status and the remote's words.

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliverylog::classify_rejection;
use crate::deliveryrun::{Ctx, Results, Task};
use crate::json::Json;
use crate::mime::{self, Entity};
use crate::psl::organizational_domain;
use std::net::IpAddr;

const CAT: Category = Category::Message;
const SC: Scope = Scope::Sending;
/// Longest a message line may be (RFC 5322 §2.1.1).
pub const MAX_LINE: usize = 998;

// ---- headers -------------------------------------------------------------------

/// All values of a header, in order.
pub fn headers_all(lines: &[String], name: &str) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
        .collect()
}

/// `Name <a@b>` / `a@b` / `"Name" <a@b>` → (display name, address lower-cased).
pub fn parse_mailbox(v: &str) -> (String, String) {
    let v = v.trim();
    if let (Some(lt), Some(gt)) = (v.rfind('<'), v.rfind('>')) {
        if lt < gt {
            let name = crate::queueview::decode_rfc2047(v[..lt].trim().trim_matches('"'));
            return (name, v[lt + 1..gt].trim().to_ascii_lowercase());
        }
    }
    (
        String::new(),
        v.trim_matches(|c| c == '<' || c == '>')
            .to_ascii_lowercase(),
    )
}

pub fn domain_of(addr: &str) -> String {
    addr.rsplit('@')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// The parsed `Authentication-Results` of one hop.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AuthResults {
    pub authserv_id: String,
    /// (method, result, the property=value tail)
    pub methods: Vec<(String, String, String)>,
}

impl AuthResults {
    pub fn result(&self, method: &str) -> Option<&(String, String, String)> {
        self.methods.iter().find(|(m, _, _)| m == method)
    }
}

/// `mx.google.com; dkim=pass header.i=@x.test header.s=s1; spf=pass (…) smtp.mailfrom=x.test; dmarc=pass (p=REJECT) header.from=x.test`
pub fn parse_authentication_results(v: &str) -> AuthResults {
    let mut r = AuthResults::default();
    let mut parts = v.split(';').map(str::trim);
    r.authserv_id = parts
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    for p in parts {
        if p.is_empty() {
            continue;
        }
        let Some((method, rest)) = p.split_once('=') else {
            continue;
        };
        let rest = rest.trim();
        // result is the first word; "(comment)" may follow
        let result = rest
            .split(|c: char| c.is_whitespace() || c == '(')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let tail = rest[result.len().min(rest.len())..].trim().to_string();
        r.methods
            .push((method.trim().to_ascii_lowercase(), result, tail));
    }
    r
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Received {
    pub from: Option<String>,
    pub from_ip: Option<IpAddr>,
    pub by: Option<String>,
    pub with: Option<String>,
    pub date: Option<u64>,
    pub raw: String,
}

/// `from a.example (b.example [1.2.3.4]) by mx.example with ESMTPS id …; Sat, 19 Sep 2026 10:00:00 +0200`
pub fn parse_received(v: &str) -> Received {
    let mut r = Received {
        raw: v.to_string(),
        ..Default::default()
    };
    let (clauses, date) = match v.rsplit_once(';') {
        Some((c, d)) => (c, Some(d.trim())),
        None => (v, None),
    };
    r.date = date.and_then(parse_date);
    let toks: Vec<&str> = clauses.split_whitespace().collect();
    let mut i = 0;
    while i < toks.len() {
        match toks[i].to_ascii_lowercase().as_str() {
            "from" if i + 1 < toks.len() => {
                r.from = Some(
                    toks[i + 1]
                        .trim_matches(|c| c == '(' || c == ')')
                        .to_string(),
                );
                i += 1;
            }
            "by" if i + 1 < toks.len() => {
                r.by = Some(
                    toks[i + 1]
                        .trim_matches(|c| c == '(' || c == ')')
                        .to_string(),
                );
                i += 1;
            }
            "with" if i + 1 < toks.len() => {
                r.with = Some(toks[i + 1].to_string());
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    // the first bracketed address after "from" (before "by") is the client
    let head = match clauses.to_ascii_lowercase().find(" by ") {
        Some(j) => &clauses[..j],
        None => clauses,
    };
    let mut rest = head;
    while let Some(s) = rest.find('[') {
        let after = &rest[s + 1..];
        let end = after.find(']').unwrap_or(after.len());
        let cand = after[..end].trim_start_matches("IPv6:").trim();
        if let Ok(ip) = cand.parse::<IpAddr>() {
            r.from_ip = Some(ip);
            break;
        }
        rest = &after[end.min(after.len())..];
    }
    r
}

/// RFC 5322 date (`Sat, 19 Sep 2026 10:00:00 +0200`, seconds optional,
/// obsolete zone names accepted) → Unix seconds.
pub fn parse_date(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = match s.find(',') {
        Some(i) if i < 4 => s[i + 1..].trim(),
        _ => s,
    };
    let toks: Vec<&str> = s.split_whitespace().collect();
    if toks.len() < 4 {
        return None;
    }
    let day: u32 = toks[0].parse().ok()?;
    let mon = match toks[1].to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let mut year: i32 = toks[2].parse().ok()?;
    if year < 100 {
        year += if year < 50 { 2000 } else { 1900 };
    }
    let mut hms = toks[3].split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let m: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next().unwrap_or("0").parse().ok()?;
    let zone = toks.get(4).copied().unwrap_or("+0000");
    let offset: i64 = if let Some(sign) = zone.chars().next().filter(|c| *c == '+' || *c == '-') {
        let digits = &zone[1..];
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let hh: i64 = digits[..2].parse().ok()?;
        let mm: i64 = digits[2..].parse().ok()?;
        let v = hh * 3600 + mm * 60;
        if sign == '-' {
            -v
        } else {
            v
        }
    } else {
        match zone.to_ascii_uppercase().as_str() {
            "EST" => -5 * 3600,
            "EDT" => -4 * 3600,
            "CST" => -6 * 3600,
            "CDT" => -5 * 3600,
            "MST" => -7 * 3600,
            "MDT" => -6 * 3600,
            "PST" => -8 * 3600,
            "PDT" => -7 * 3600,
            _ => 0,
        }
    };
    let date = crate::civil::Date::new(year, mon, day);
    let days = date.to_days();
    let local = days * 86_400 + h * 3600 + m * 60 + sec;
    let utc = local - offset;
    (utc >= 0).then_some(utc as u64)
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DkimSig {
    pub d: String,
    pub s: String,
    pub a: String,
    pub h: Vec<String>,
    pub l: Option<u64>,
    pub i: Option<String>,
}

pub fn parse_dkim_signature(v: &str) -> DkimSig {
    let mut sig = DkimSig::default();
    for part in v.split(';') {
        let Some((k, val)) = part.split_once('=') else {
            continue;
        };
        let val: String = val.chars().filter(|c| !c.is_whitespace()).collect();
        match k.trim() {
            "d" => sig.d = val.to_ascii_lowercase(),
            "s" => sig.s = val.to_ascii_lowercase(),
            "a" => sig.a = val.to_ascii_lowercase(),
            "h" => {
                sig.h = val
                    .split(':')
                    .map(|h| h.trim().to_ascii_lowercase())
                    .filter(|h| !h.is_empty())
                    .collect()
            }
            "l" => sig.l = val.parse().ok(),
            "i" => sig.i = Some(val.to_ascii_lowercase()),
            _ => {}
        }
    }
    sig
}

// ---- body ----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub href: String,
    pub text: String,
}

/// `href="…"` links with their anchor text from HTML, plus bare URLs from text.
pub fn extract_links(html: Option<&str>, text: Option<&str>) -> Vec<Link> {
    let mut out = Vec::new();
    if let Some(h) = html {
        let lower = h.to_ascii_lowercase();
        let mut pos = 0;
        while let Some(i) = lower[pos..].find("href=") {
            let start = pos + i + 5;
            let q = lower.as_bytes().get(start).copied();
            let (url_start, terminator) = if q == Some(b'"') || q == Some(b'\'') {
                (start + 1, q.unwrap() as char)
            } else {
                (start, ' ')
            };
            let end = h[url_start..]
                .find(|c: char| {
                    c == terminator || c == '>' || (terminator == ' ' && c.is_whitespace())
                })
                .map(|e| url_start + e)
                .unwrap_or(h.len());
            let href = h[url_start..end].trim().to_string();
            // anchor text: up to the closing </a>
            let text = match (h[end..].find('>'), lower[end..].find("</a>")) {
                (Some(gt), Some(close)) if gt < close => strip_tags(&h[end + gt + 1..end + close]),
                _ => String::new(),
            };
            if !href.is_empty() {
                out.push(Link { href, text });
            }
            pos = end.max(start + 1);
        }
    }
    if let Some(t) = text {
        for tok in t.split(|c: char| {
            c.is_whitespace() || c == '<' || c == '>' || c == '"' || c == '(' || c == ')'
        }) {
            let lower = tok.to_ascii_lowercase();
            if lower.starts_with("http://") || lower.starts_with("https://") {
                let href = tok.trim_end_matches(['.', ',', ';']).to_string();
                if !out.iter().any(|l| l.href == href) {
                    out.push(Link {
                        href,
                        text: String::new(),
                    });
                }
            }
        }
    }
    out
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The host of a URL, lower-cased (no port, no userinfo).
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if host.starts_with('[') {
        host.split(']').next()?.trim_start_matches('[')
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

pub const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "t.ly",
    "lnkd.in",
    "s.id",
    "v.gd",
    "clck.ru",
    "bl.ink",
    "short.io",
];
pub const RISKY_EXT: &[&str] = &[
    "exe", "scr", "js", "jse", "vbs", "vbe", "bat", "cmd", "com", "pif", "hta", "jar", "msi",
    "ps1", "lnk", "iso", "img", "wsf", "wsh", "cpl", "reg", "dll", "vhd", "vhdx",
];
pub const MACRO_EXT: &[&str] = &[
    "docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam",
];

#[derive(Debug, Clone, PartialEq)]
pub struct Attachment {
    pub name: String,
    pub ctype: String,
    pub size: usize,
}

/// A message taken apart for the checks.
pub struct Parsed {
    pub headers: Vec<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub has_text_alt: bool,
    pub image_only: bool,
    pub raw_len: usize,
}

pub fn parse_message(raw: &[u8]) -> Parsed {
    let root = mime::parse_entity(raw, 0);
    let mut p = Parsed {
        headers: root.headers.clone(),
        text: None,
        html: None,
        attachments: Vec::new(),
        has_text_alt: false,
        image_only: false,
        raw_len: raw.len(),
    };
    fn walk(e: &Entity, p: &mut Parsed, inline_images: &mut usize) {
        if !e.children.is_empty() {
            for c in &e.children {
                walk(c, p, inline_images);
            }
            return;
        }
        let disposition = mime::header(&e.headers, "content-disposition")
            .unwrap_or_default()
            .to_ascii_lowercase();
        let name = e.params.get("name").cloned().or_else(|| {
            mime::parse_content_type(&disposition)
                .1
                .get("filename")
                .cloned()
        });
        let is_attachment = disposition.starts_with("attachment")
            || (name.is_some() && !e.ctype.starts_with("text/"));
        if is_attachment {
            p.attachments.push(Attachment {
                name: crate::queueview::decode_rfc2047(&name.unwrap_or_else(|| "(unnamed)".into())),
                ctype: e.ctype.clone(),
                size: e.body.len(),
            });
            return;
        }
        let charset = e.params.get("charset").map(String::as_str);
        match e.ctype.as_str() {
            "text/plain" if p.text.is_none() => {
                p.text = Some(mime::decode_charset(&e.body, charset))
            }
            "text/html" if p.html.is_none() => {
                p.html = Some(mime::decode_charset(&e.body, charset))
            }
            t if t.starts_with("image/") => *inline_images += 1,
            _ => {}
        }
    }
    let mut inline_images = 0;
    walk(&root, &mut p, &mut inline_images);
    p.has_text_alt = p.text.as_ref().is_some_and(|t| !t.trim().is_empty());
    let visible = p.html.as_deref().map(strip_tags).unwrap_or_default();
    p.image_only = inline_images > 0 && !p.has_text_alt && visible.split_whitespace().count() < 5;
    p
}

// ---- the checks ----------------------------------------------------------------

fn check(
    id: &str,
    v: Verdict,
    sev: Severity,
    title: impl Into<String>,
    why: impl Into<String>,
) -> Check {
    Check::new(id, SC, CAT, v, sev, title, why)
}

/// Header-level checks (shared with the returned headers of a bounce).
pub fn header_checks(headers: &[String], address: &str, prefix: &str, cat: Category) -> Vec<Check> {
    let mut out = Vec::new();
    let id = |s: &str| format!("{prefix}.{s}");
    let c = |id: String, v: Verdict, sev: Severity, title: String, why: String| {
        Check::new(id, SC, cat, v, sev, title, why)
    };
    let from = headers_all(headers, "from");
    let (_, from_addr) = from.first().map(|f| parse_mailbox(f)).unwrap_or_default();
    let from_dom = domain_of(&from_addr);
    let (from_org, _) = organizational_domain(&from_dom);
    if !address.is_empty() && !from_addr.is_empty() && !from_addr.eq_ignore_ascii_case(address) {
        out.push(c(id("from_address"), Verdict::Warn, Severity::Low, format!("the message is From {from_addr}, the test is for {address}"), "the DNS, SPF, DKIM and DMARC rows above are about the tested address's domain; the message's own authentication depends on its From domain".into()));
    }

    // Authentication-Results of the last hop (the first header)
    let ars = headers_all(headers, "authentication-results");
    match ars.first() {
        None => out.push(c(id("auth_results"), Verdict::Unknown, Severity::Info, "no Authentication-Results header".into(), "the receiving server added none, or the message was saved before delivery; the upload cannot show what the receiver concluded — a message exported from the recipient's mailbox at Gmail/Outlook carries it".into())),
        Some(ar) => {
            let r = parse_authentication_results(ar);
            let pick = |m: &str| r.result(m).map(|(_, res, tail)| (res.clone(), tail.clone()));
            let (spf, dkim, dmarc, arc) = (pick("spf"), pick("dkim"), pick("dmarc"), pick("arc"));
            let failures: Vec<String> = [("spf", &spf), ("dkim", &dkim), ("dmarc", &dmarc)].iter().filter_map(|(m, r)| r.as_ref().filter(|(res, _)| matches!(res.as_str(), "fail" | "softfail" | "permerror" | "temperror" | "policy")).map(|(res, tail)| format!("{m}={res} {tail}"))).collect();
            let summary = [("spf", &spf), ("dkim", &dkim), ("dmarc", &dmarc), ("arc", &arc)].iter().filter_map(|(m, r)| r.as_ref().map(|(res, _)| format!("{m}={res}"))).collect::<Vec<_>>().join(", ");
            let ev = format!("authserv-id {}\n{}", r.authserv_id, ar);
            out.push(if !failures.is_empty() {
                c(id("auth_results"), Verdict::Fail, Severity::High, format!("the receiver ({}) saw authentication failures", r.authserv_id), format!("{} — the message reached the mailbox with these results; a stricter receiver, or a DMARC policy of reject, would have refused it", failures.join("; "))).evidence("Authentication-Results", ev).fix_summary("Fix the failing method in the sending rows above: SPF for the sending IP, DKIM signing with a published key, alignment with the From domain")
            } else if dmarc.as_ref().is_some_and(|(r, _)| r == "pass") || (spf.as_ref().is_some_and(|(r, _)| r == "pass") && dkim.as_ref().is_some_and(|(r, _)| r == "pass")) {
                c(id("auth_results"), Verdict::Pass, Severity::Info, format!("the receiver ({}) authenticated the message", r.authserv_id), summary).evidence("Authentication-Results", ev)
            } else if summary.is_empty() {
                c(id("auth_results"), Verdict::Unknown, Severity::Info, "Authentication-Results without SPF/DKIM/DMARC".into(), ar.chars().take(200).collect()).evidence("Authentication-Results", ev)
            } else {
                c(id("auth_results"), Verdict::Warn, Severity::Medium, format!("the receiver ({}) got only: {summary}", r.authserv_id), "none or neutral results mean the message was not authenticated — accepted this time, but scored as unknown".into()).evidence("Authentication-Results", ev)
            });
        }
    }

    // DKIM-Signature
    let sigs = headers_all(headers, "dkim-signature");
    match sigs.first() {
        None => out.push(c(id("dkim_signature"), Verdict::Warn, Severity::High, "the message is not DKIM-signed".into(), "no DKIM-Signature header — Gmail and Yahoo require signing for bulk senders and score unsigned mail down; DMARC then depends on SPF alone".into()).fix_summary("Enable DKIM signing on the sending server (cPanel: Email Deliverability → DKIM)")),
        Some(s) => {
            let sig = parse_dkim_signature(s);
            let (sig_org, _) = organizational_domain(&sig.d);
            let mut problems = Vec::new();
            if !from_dom.is_empty() && sig_org != from_org {
                problems.push(format!("d={} does not align with the From domain {from_dom} (DMARC needs the same organisational domain)", sig.d));
            }
            for must in ["from", "subject", "date"] {
                if !sig.h.contains(&must.to_string()) {
                    problems.push(format!("h= does not cover {must}"));
                }
            }
            if sig.l.is_some() {
                problems.push("l= (body length limit) lets anyone append content to the signed message".into());
            }
            if sig.a == "rsa-sha1" {
                problems.push("a=rsa-sha1: SHA-1 is rejected by modern verifiers (RFC 8301)".into());
            }
            let ev = format!("d={} s={} a={} h={}{}", sig.d, sig.s, sig.a, sig.h.join(":"), sig.l.map(|l| format!(" l={l}")).unwrap_or_default());
            out.push(if problems.iter().any(|p| p.contains("rsa-sha1")) {
                c(id("dkim_signature"), Verdict::Fail, Severity::High, "DKIM signature uses SHA-1".into(), problems.join("; ")).evidence("DKIM-Signature", ev).fix_summary("Sign with rsa-sha256 (every current signer does by default)")
            } else if !problems.is_empty() {
                c(id("dkim_signature"), Verdict::Warn, Severity::Medium, format!("DKIM signature by {} with remarks", sig.d), problems.join("; ")).evidence("DKIM-Signature", ev).fix_summary("Sign with a key at the From domain (d= aligned), cover From/Subject/Date, drop l=")
            } else {
                c(id("dkim_signature"), Verdict::Pass, Severity::Info, format!("DKIM-signed by {} (selector {})", sig.d, sig.s), "aligned with the From domain; the live DKIM rows above verify the published key".into()).evidence("DKIM-Signature", ev)
            });
        }
    }

    // alignment: From vs Return-Path / Sender
    let rp = headers_all(headers, "return-path")
        .first()
        .map(|r| parse_mailbox(r).1)
        .unwrap_or_default();
    let sender = headers_all(headers, "sender")
        .first()
        .map(|r| parse_mailbox(r).1)
        .unwrap_or_default();
    if !from_dom.is_empty() {
        let rp_org = organizational_domain(&domain_of(&rp)).0;
        if !rp.is_empty() && rp_org != from_org {
            out.push(c(id("alignment"), Verdict::Warn, Severity::Medium, format!("Return-Path domain {} differs from From domain {from_dom}", domain_of(&rp)), "SPF is checked on the Return-Path (envelope) domain; for DMARC it must align with the From domain — a mailing service or a forwarder in between breaks this unless DKIM aligns".into()).evidence("headers", format!("From: {from_addr}\nReturn-Path: {rp}")));
        } else if !sender.is_empty() && organizational_domain(&domain_of(&sender)).0 != from_org {
            out.push(c(
                id("alignment"),
                Verdict::Pass,
                Severity::Info,
                "sent on behalf of the From address".into(),
                format!(
                    "Sender: {} — fine as long as DKIM/SPF align on the From domain",
                    sender
                ),
            ));
        } else {
            out.push(c(id("alignment"), Verdict::Pass, Severity::Info, "envelope and From domains align".into(), if rp.is_empty() { "no Return-Path header (the message was not delivered yet, or the exporter dropped it)".to_string() } else { format!("Return-Path {rp}") }));
        }
    }

    // Received chain: hops, delays, the first external hop
    let recvs: Vec<Received> = headers_all(headers, "received")
        .iter()
        .map(|r| parse_received(r))
        .collect();
    if !recvs.is_empty() {
        // headers are newest first; walk oldest → newest
        let mut delays = Vec::new();
        let mut worst = 0u64;
        for w in recvs.windows(2) {
            if let (Some(newer), Some(older)) = (w[0].date, w[1].date) {
                let d = newer.saturating_sub(older);
                worst = worst.max(d);
                if d >= 300 {
                    delays.push(format!(
                        "{} s between {} and {}",
                        d,
                        older_label(&w[1]),
                        older_label(&w[0])
                    ));
                }
            }
        }
        let external = recvs
            .iter()
            .rev()
            .find(|r| r.from_ip.is_some_and(crate::netguard::is_public));
        let ev = recvs
            .iter()
            .rev()
            .enumerate()
            .map(|(i, r)| {
                format!(
                    "{}: from {} {} by {} {}",
                    i + 1,
                    r.from.clone().unwrap_or_else(|| "?".into()),
                    r.from_ip.map(|i| format!("[{i}]")).unwrap_or_default(),
                    r.by.clone().unwrap_or_else(|| "?".into()),
                    r.date
                        .map(|d| crate::civil::Date::from_unix(d).to_string())
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(if worst >= 3600 {
            c(id("received_chain"), Verdict::Fail, Severity::Medium, format!("{} hops, a delay of {} min on the way", recvs.len(), worst / 60), delays.join("; ")).evidence("Received", ev.clone()).fix_summary("The hop before the delay held the message: a queue on that server (greylisting, throttling by the next hop, or a stuck queue)")
        } else if worst >= 300 {
            c(id("received_chain"), Verdict::Warn, Severity::Low, format!("{} hops, a delay of {} min on the way", recvs.len(), worst / 60), delays.join("; ")).evidence("Received", ev.clone())
        } else {
            c(id("received_chain"), Verdict::Pass, Severity::Info, format!("{} hop(s), no delay worth noting", recvs.len()), external.and_then(|e| e.from_ip).map(|ip| format!("first external hop {ip}")).unwrap_or_else(|| "no public hop found (an internal or exported copy)".into())).evidence("Received", ev.clone())
        });
        if let Some(ip) = external.and_then(|e| e.from_ip) {
            out.push(c(id("origin_ip"), Verdict::Pass, Severity::Info, format!("sent from {ip}"), "the first public address in the Received chain — the sending server; its reputation rows are below".into()));
        }
    }

    // required headers
    let mut missing = Vec::new();
    for h in ["message-id", "date", "from"] {
        if headers_all(headers, h).is_empty() {
            missing.push(h.to_uppercase());
        }
    }
    let mime_version = !headers_all(headers, "mime-version").is_empty()
        || headers_all(headers, "content-type").is_empty();
    if from.len() > 1 {
        out.push(c(
            id("headers.from"),
            Verdict::Fail,
            Severity::High,
            "more than one From header".into(),
            "receivers reject messages with multiple From headers (RFC 5322 allows exactly one)"
                .into(),
        ));
    }
    if !missing.is_empty() {
        out.push(c(id("headers.required"), Verdict::Fail, Severity::High, format!("missing header(s): {}", missing.join(", ")), "Message-ID, Date and From are mandatory; many receivers reject or junk mail without them (a common mistake in scripts that call sendmail directly)".into()).fix_summary("Have the sending script or MTA add Message-ID and Date (Exim adds them for local submissions; PHP mail() does not add Message-ID)"));
    } else {
        let date_skew = headers_all(headers, "date")
            .first()
            .and_then(|d| parse_date(d))
            .zip(recvs.first().and_then(|r| r.date))
            .map(|(d, r)| r.abs_diff(d));
        out.push(match date_skew {
            Some(s) if s > 86_400 => c(id("headers.required"), Verdict::Warn, Severity::Medium, "the Date header is off by more than a day".into(), format!("{} h between the Date header and the receiving hop's timestamp — a wrong clock on the sender; receivers score it as suspicious", s / 3600)).fix_summary("Fix the clock (chrony/NTP) on the sending host"),
            _ => c(id("headers.required"), Verdict::Pass, Severity::Info, "Message-ID, Date and From present".into(), if mime_version { "MIME-Version present".into() } else { "Content-Type without MIME-Version".into() }),
        });
    }
    if !mime_version {
        out.push(c(
            id("headers.mime"),
            Verdict::Warn,
            Severity::Low,
            "Content-Type without MIME-Version".into(),
            "strict parsers treat the body as plain text".into(),
        ));
    }
    // raw 8-bit in headers
    let eightbit: Vec<&String> = headers
        .iter()
        .filter(|l| l.bytes().any(|b| b >= 0x80))
        .collect();
    if !eightbit.is_empty() {
        out.push(c(id("headers.8bit"), Verdict::Warn, Severity::Medium, "raw non-ASCII in headers".into(), format!("{} header(s) contain unencoded 8-bit characters (subject or names with accents); they must be RFC 2047 encoded (=?UTF-8?…?=) or some receivers mangle or reject them", eightbit.len())).evidence("headers", eightbit.iter().take(3).map(|l| l.chars().take(120).collect::<String>()).collect::<Vec<_>>().join("\n")));
    }
    // display name games
    if let Some(f) = from.first() {
        let (name, addr) = parse_mailbox(f);
        let lname = name.to_ascii_lowercase();
        if lname.contains('@') && !lname.contains(&addr) {
            out.push(c(
                id("from_display"),
                Verdict::Warn,
                Severity::Medium,
                "the display name looks like a different address".into(),
                format!("From: {f} — a phishing pattern; receivers flag it"),
            ));
        }
    }
    if let Some(r) = headers_all(headers, "reply-to").first() {
        let rd = domain_of(&parse_mailbox(r).1);
        if !rd.is_empty() && organizational_domain(&rd).0 != from_org {
            out.push(c(id("reply_to"), Verdict::Warn, Severity::Low, format!("Reply-To at another domain ({rd})"), "legitimate for services, but a classic phishing/BEC signal that scoring engines penalise".into()));
        }
    }
    out
}

fn older_label(r: &Received) -> String {
    r.by.clone()
        .or_else(|| r.from.clone())
        .unwrap_or_else(|| "?".into())
}

/// The whole-message checks: headers, lines, bulk, links, attachments, body.
pub fn analyse_message(raw: &[u8], address: &str, ctx: Option<&Ctx>) -> Vec<Check> {
    let p = parse_message(raw);
    let mut out = header_checks(&p.headers, address, "eml", CAT);
    // line lengths / line endings
    let long = raw
        .split(|b| *b == b'\n')
        .filter(|l| l.len() > MAX_LINE + 1)
        .count();
    let bare_lf = raw
        .windows(2)
        .filter(|w| w[1] == b'\n' && w[0] != b'\r')
        .count();
    let crlf = raw
        .windows(2)
        .filter(|w| w[0] == b'\r' && w[1] == b'\n')
        .count();
    if long > 0 {
        out.push(check("eml.lines", Verdict::Fail, Severity::High, format!("{long} line(s) longer than {MAX_LINE} characters"), "SMTP limits lines to 998 characters (RFC 5322); Exim and most MTAs reject or truncate longer ones (\"line too long\"), typically from HTML generators or unencoded base64").fix_summary("Encode the body (quoted-printable or base64) or wrap lines; set message_linelength_limit awareness in the generating software"));
    } else if bare_lf > 0 && crlf > 0 {
        out.push(check("eml.lines", Verdict::Warn, Severity::Low, "mixed line endings", format!("{crlf} CRLF and {bare_lf} bare LF line ends — some MTAs reject bare LF (Postfix with smtpd_forbid_bare_newline, Microsoft)")));
    } else {
        out.push(check(
            "eml.lines",
            Verdict::Pass,
            Severity::Info,
            "line lengths within limits",
            format!("longest line ≤ {MAX_LINE} characters"),
        ));
    }
    // bulk mail requirements
    let bulk = !headers_all(&p.headers, "list-unsubscribe").is_empty()
        || !headers_all(&p.headers, "list-id").is_empty()
        || headers_all(&p.headers, "precedence")
            .iter()
            .any(|v| v.eq_ignore_ascii_case("bulk") || v.eq_ignore_ascii_case("list"));
    if bulk {
        let lu = headers_all(&p.headers, "list-unsubscribe");
        let post = headers_all(&p.headers, "list-unsubscribe-post");
        let one_click = lu.iter().any(|v| v.contains("https://"))
            && post
                .iter()
                .any(|v| v.contains("List-Unsubscribe=One-Click"));
        out.push(if one_click {
            check("eml.list", Verdict::Pass, Severity::Info, "bulk mail with one-click unsubscribe", "List-Unsubscribe (https) and List-Unsubscribe-Post: List-Unsubscribe=One-Click — the Gmail/Yahoo bulk-sender requirement")
        } else {
            check("eml.list", Verdict::Fail, Severity::High, "bulk mail without one-click unsubscribe", format!("{}; since 2024 Gmail and Yahoo require both headers from bulk senders and reject or junk without them", if lu.is_empty() { "no List-Unsubscribe header" } else { "List-Unsubscribe present but no https URL with List-Unsubscribe-Post: List-Unsubscribe=One-Click (RFC 8058)" })).fix(Fix {
                summary: "Add the two headers to every bulk message".into(),
                command: Some("List-Unsubscribe: <https://example.com/unsub?u=…>, <mailto:unsub@example.com>\nList-Unsubscribe-Post: List-Unsubscribe=One-Click".into()),
                url: Some("https://support.google.com/a/answer/81126".into()),
                ..Default::default()
            })
        });
    } else {
        out.push(Check::new("eml.list", SC, CAT, Verdict::NotApplicable, Severity::Info, "not bulk mail", "no List-* or Precedence: bulk headers, so the one-click unsubscribe rule does not apply"));
    }
    // links
    let links = extract_links(p.html.as_deref(), p.text.as_deref());
    if !links.is_empty() {
        let mut raw_ip = Vec::new();
        let mut short = Vec::new();
        let mut mismatch = Vec::new();
        let mut hosts: Vec<String> = Vec::new();
        for l in &links {
            let Some(h) = url_host(&l.href) else { continue };
            if h.parse::<IpAddr>().is_ok() {
                raw_ip.push(l.href.clone());
            }
            if SHORTENERS.contains(&h.as_str()) {
                short.push(l.href.clone());
            }
            let t = l.text.to_ascii_lowercase();
            if (t.starts_with("http://") || t.starts_with("https://") || t.starts_with("www."))
                && url_host(&if t.starts_with("www.") {
                    format!("https://{t}")
                } else {
                    t.clone()
                })
                .is_some_and(|th| organizational_domain(&th).0 != organizational_domain(&h).0)
            {
                mismatch.push(format!("text {} → {}", l.text, l.href));
            }
            if !hosts.contains(&h) && h.parse::<IpAddr>().is_err() {
                hosts.push(h);
            }
        }
        let mut listed = Vec::new();
        if let Some(ctx) = ctx {
            if std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_none() {
                for h in hosts.iter().take(10) {
                    let (org, _) = organizational_domain(h);
                    for list in crate::dnsbl::lists_for(crate::dnsbl::Kind::Domain) {
                        if let crate::dnsbl::ListVerdict::Listed(l) =
                            crate::dnsbl::query_domain(&ctx.dns, list, &org)
                        {
                            listed.push(format!(
                                "{org} on {}: {}",
                                list.name,
                                l.iter()
                                    .map(|x| x.meaning.clone())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                        }
                    }
                }
            }
        }
        let ev = links
            .iter()
            .take(15)
            .map(|l| {
                if l.text.is_empty() {
                    l.href.clone()
                } else {
                    format!("{} → {}", l.text, l.href)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(if !listed.is_empty() {
            check("eml.links", Verdict::Fail, Severity::High, "links to blocklisted domains", listed.join("; ")).evidence("links", ev).fix_summary("Remove the links, or get the domain delisted (Spamhaus DBL / SURBL / URIBL) — mail carrying them is filtered everywhere")
        } else if !raw_ip.is_empty() {
            check("eml.links", Verdict::Fail, Severity::Medium, "links to raw IP addresses", raw_ip.join(", ")).evidence("links", ev).fix_summary("Link to host names; raw-IP URLs are a strong spam/phishing signal")
        } else if !mismatch.is_empty() {
            check("eml.links", Verdict::Warn, Severity::Medium, "link text and target disagree", mismatch.join("; ")).evidence("links", ev).fix_summary("Make the visible URL match the href (tracking redirects should keep the sender's domain)")
        } else if !short.is_empty() {
            check("eml.links", Verdict::Warn, Severity::Low, "URL shorteners in the body", short.join(", ")).evidence("links", ev).fix_summary("Use full URLs on your own domain; shortener domains are heavily abused and scored down")
        } else {
            check("eml.links", Verdict::Pass, Severity::Info, format!("{} link(s), nothing suspicious", links.len()), format!("{} domain(s){}", hosts.len(), if ctx.is_some() { ", none on the domain blocklists" } else { "" })).evidence("links", ev)
        });
    }
    // attachments
    if !p.attachments.is_empty() {
        let ext = |n: &str| n.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
        let risky: Vec<String> = p
            .attachments
            .iter()
            .filter(|a| RISKY_EXT.contains(&ext(&a.name).as_str()))
            .map(|a| a.name.clone())
            .collect();
        let double: Vec<String> = p
            .attachments
            .iter()
            .filter(|a| {
                let parts: Vec<&str> = a.name.rsplit('.').collect();
                parts.len() >= 3 && RISKY_EXT.contains(&parts[0].to_ascii_lowercase().as_str())
            })
            .map(|a| a.name.clone())
            .collect();
        let macros: Vec<String> = p
            .attachments
            .iter()
            .filter(|a| MACRO_EXT.contains(&ext(&a.name).as_str()))
            .map(|a| a.name.clone())
            .collect();
        let big: Vec<String> = p
            .attachments
            .iter()
            .filter(|a| a.size > 10 * 1024 * 1024)
            .map(|a| format!("{} ({} MB)", a.name, a.size / 1_048_576))
            .collect();
        let ev = p
            .attachments
            .iter()
            .map(|a| format!("{} — {} — {} KB", a.name, a.ctype, a.size / 1024))
            .collect::<Vec<_>>()
            .join("\n");
        out.push(if !risky.is_empty() || !double.is_empty() {
            check("eml.attachments", Verdict::Fail, Severity::High, format!("dangerous attachment type(s): {}", risky.iter().chain(double.iter()).cloned().collect::<Vec<_>>().join(", ")), "executables, scripts, disk images and double extensions are rejected outright by Gmail, Microsoft and MailScanner's filename rules").evidence("attachments", ev).fix_summary("Send them zipped with a password, through a file-sharing link, or as a PDF")
        } else if !macros.is_empty() {
            check("eml.attachments", Verdict::Warn, Severity::Medium, format!("macro-enabled Office file(s): {}", macros.join(", ")), "many receivers quarantine .docm/.xlsm/.pptm; MailScanner's default rules flag them").evidence("attachments", ev)
        } else if !big.is_empty() {
            check("eml.attachments", Verdict::Warn, Severity::Low, format!("large attachment(s): {}", big.join(", ")), "common size limits are 10–25 MB per message (after base64, ×1.37); this message may exceed the receiver's SIZE").evidence("attachments", ev)
        } else {
            check("eml.attachments", Verdict::Pass, Severity::Info, format!("{} attachment(s), nothing risky", p.attachments.len()), format!("{:.1} MB in total", p.raw_len as f64 / 1_048_576.0)).evidence("attachments", ev)
        });
    }
    // body shape
    let html_lower = p
        .html
        .as_deref()
        .map(|h| h.to_ascii_lowercase())
        .unwrap_or_default();
    if html_lower.contains("<script")
        || html_lower.contains("<form")
        || html_lower.contains("javascript:")
    {
        out.push(check("eml.body", Verdict::Fail, Severity::High, "scripts or forms in the HTML body", "HTML mail with <script>, <form> or javascript: URLs is a phishing signature; receivers strip or reject it").fix_summary("Remove scripts and forms; link to a page instead"));
    } else if p.image_only {
        out.push(check("eml.body", Verdict::Warn, Severity::Medium, "image-only message", "almost no text, one or more images — the classic image-spam shape, scored up by every filter (SpamAssassin HTML_IMAGE_ONLY_*)").fix_summary("Put the content in text; images should illustrate, not carry, the message"));
    } else if p.html.is_some() && !p.has_text_alt {
        out.push(check("eml.body", Verdict::Warn, Severity::Low, "HTML without a text alternative", "no text/plain part in the multipart/alternative — some filters score it (MIME_HTML_ONLY), and text-only clients show nothing").fix_summary("Send multipart/alternative with a plain-text version (every mail library can)"));
    } else if p.html.is_some() || p.text.is_some() {
        out.push(check(
            "eml.body",
            Verdict::Pass,
            Severity::Info,
            if p.html.is_some() {
                "HTML with a text alternative"
            } else {
                "plain-text message"
            },
            format!("{:.0} KB", p.raw_len as f64 / 1024.0),
        ));
    }
    out
}

// ---- bounces -------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DsnRecipient {
    pub final_recipient: String,
    pub action: String,
    pub status: String,
    pub diagnostic: String,
    pub remote_mta: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Dsn {
    pub reporting_mta: String,
    pub recipients: Vec<DsnRecipient>,
    /// Headers of the returned original message, when included.
    pub original_headers: Vec<String>,
    pub human_text: String,
}

/// A `multipart/report; report-type=delivery-status` message.
pub fn parse_dsn(raw: &[u8]) -> Option<Dsn> {
    let root = mime::parse_entity(raw, 0);
    fn find<'a>(e: &'a Entity, pred: &dyn Fn(&Entity) -> bool) -> Option<&'a Entity> {
        if pred(e) {
            return Some(e);
        }
        e.children.iter().find_map(|c| find(c, pred))
    }
    let status = find(&root, &|e| e.ctype == "message/delivery-status")?;
    let mut dsn = Dsn::default();
    let text = String::from_utf8_lossy(&status.body);
    // blocks separated by blank lines: the first is per-message, then per-recipient
    let mut blocks: Vec<Vec<(String, String)>> = vec![Vec::new()];
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if !blocks.last().unwrap().is_empty() {
                blocks.push(Vec::new());
            }
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, v)) = blocks.last_mut().unwrap().last_mut() {
                v.push(' ');
                v.push_str(line.trim());
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            blocks
                .last_mut()
                .unwrap()
                .push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }
    let get = |b: &[(String, String)], k: &str| {
        b.iter()
            .find(|(x, _)| x == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let strip_type = |v: String| {
        v.split_once(';')
            .map(|(_, a)| a.trim().to_string())
            .unwrap_or(v)
    };
    for (i, b) in blocks.iter().enumerate() {
        if b.is_empty() {
            continue;
        }
        if i == 0 && b.iter().any(|(k, _)| k == "reporting-mta") {
            dsn.reporting_mta = strip_type(get(b, "reporting-mta"));
            continue;
        }
        if b.iter()
            .any(|(k, _)| k == "final-recipient" || k == "original-recipient" || k == "action")
        {
            dsn.recipients.push(DsnRecipient {
                final_recipient: strip_type(if get(b, "final-recipient").is_empty() {
                    get(b, "original-recipient")
                } else {
                    get(b, "final-recipient")
                })
                .to_ascii_lowercase(),
                action: get(b, "action").to_ascii_lowercase(),
                status: get(b, "status"),
                diagnostic: strip_type(get(b, "diagnostic-code")),
                remote_mta: strip_type(get(b, "remote-mta")),
            });
        }
    }
    if let Some(orig) = find(&root, &|e| {
        e.ctype == "message/rfc822" || e.ctype == "text/rfc822-headers"
    }) {
        let (h, _) = mime::split_headers(&orig.body);
        dsn.original_headers = h;
    }
    if let Some(t) = find(&root, &|e| e.ctype == "text/plain") {
        dsn.human_text = String::from_utf8_lossy(&t.body)
            .chars()
            .take(4000)
            .collect();
    }
    Some(dsn)
}

/// What an enhanced status code class means.
pub fn status_meaning(status: &str) -> &'static str {
    let s = status.trim();
    let sub = s.get(2..).unwrap_or("");
    match sub {
        x if x.starts_with("1.1") => "bad destination mailbox address (the user does not exist)",
        x if x.starts_with("1.2") => "bad destination system (the domain does not exist / no MX)",
        x if x.starts_with("1.3") => "bad destination mailbox address syntax",
        x if x.starts_with("1.7") => "bad or missing sender address (sender verification)",
        x if x.starts_with("1.8") => "bad sender's system address",
        x if x.starts_with("2.1") => "mailbox disabled",
        x if x.starts_with("2.2") => "mailbox full",
        x if x.starts_with("2.3") => "message too long for the mailbox",
        x if x.starts_with("3.4") => "message too big for the system",
        x if x.starts_with("4.1") => "no answer from the destination host",
        x if x.starts_with("4.2") => "bad connection",
        x if x.starts_with("4.4") => "unable to route (DNS / MX problems)",
        x if x.starts_with("4.7") => {
            "delivery time expired (kept failing temporarily until the sender gave up)"
        }
        x if x.starts_with("5.1") => "invalid command / protocol error",
        x if x.starts_with("5.2") => "syntax error",
        x if x.starts_with("5.3") => "too many recipients",
        x if x.starts_with("6.") => "content problem (encoding, attachments, size)",
        x if x.starts_with("7.1") => {
            "delivery not authorised: message refused by policy (spam, blocklist, authentication)"
        }
        x if x.starts_with("7.") => "security or policy rejection",
        _ => "no enhanced status code",
    }
}

pub fn analyse_bounce(raw: &[u8], ctx: Option<&Ctx>) -> Vec<Check> {
    let cat = Category::Bounce;
    let c = |id: &str, v: Verdict, sev: Severity, title: String, why: String| {
        Check::new(id, SC, cat, v, sev, title, why)
    };
    let mut out = Vec::new();
    let _ = ctx;
    match parse_dsn(raw) {
        Some(dsn) if !dsn.recipients.is_empty() => {
            out.push(c(
                "bounce.dsn",
                Verdict::Pass,
                Severity::Info,
                format!(
                    "delivery status report from {}",
                    if dsn.reporting_mta.is_empty() {
                        "an unnamed MTA"
                    } else {
                        &dsn.reporting_mta
                    }
                ),
                format!("{} recipient(s)", dsn.recipients.len()),
            ));
            for r in &dsn.recipients {
                let hard = r.status.starts_with('5') || r.action == "failed";
                let temp = r.status.starts_with('4') || r.action == "delayed";
                let meaning = status_meaning(&r.status);
                let cls = classify_rejection(&r.diagnostic);
                let ev = format!("Final-Recipient: {}\nAction: {}\nStatus: {}\nRemote-MTA: {}\nDiagnostic-Code: {}", r.final_recipient, r.action, r.status, r.remote_mta, r.diagnostic);
                let title = format!(
                    "{}: {} ({})",
                    r.final_recipient,
                    if hard {
                        "permanent failure"
                    } else if temp {
                        "delayed"
                    } else {
                        &r.action
                    },
                    if r.status.is_empty() {
                        "no status".to_string()
                    } else {
                        r.status.clone()
                    }
                );
                let why = format!(
                    "{meaning}{}. Remote said: {}",
                    cls.as_ref()
                        .map(|c| format!(" — {}: {}", c.provider, c.meaning))
                        .unwrap_or_default(),
                    if r.diagnostic.is_empty() {
                        "(no diagnostic code)".to_string()
                    } else {
                        r.diagnostic.chars().take(300).collect()
                    }
                );
                let mut ch = c(
                    "bounce.status",
                    if hard {
                        Verdict::Fail
                    } else if temp {
                        Verdict::Warn
                    } else {
                        Verdict::Pass
                    },
                    if hard {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    title,
                    why,
                )
                .target(&r.final_recipient)
                .evidence("delivery-status", ev);
                if let Some(cl) = cls {
                    ch = ch.fix(Fix {
                        summary: cl.fix.into(),
                        url: cl.url.map(str::to_string),
                        ..Default::default()
                    });
                } else if hard && r.status.starts_with("5.1.1") {
                    ch = ch
                        .fix_summary("Check the recipient address for typos; remove it from lists");
                } else if hard && r.status.starts_with("5.7") {
                    ch = ch.fix_summary("A policy rejection at the receiver: look at the sending rows (SPF, DKIM, DMARC, reputation) and the remote's text");
                }
                out.push(ch);
            }
            if !dsn.original_headers.is_empty() {
                let from = headers_all(&dsn.original_headers, "from")
                    .first()
                    .map(|f| parse_mailbox(f).1)
                    .unwrap_or_default();
                out.push(
                    c(
                        "bounce.returned_headers",
                        Verdict::Pass,
                        Severity::Info,
                        "the original message's headers are attached".to_string(),
                        format!(
                            "From {} — checked below",
                            if from.is_empty() { "?" } else { &from }
                        ),
                    )
                    .evidence(
                        "original headers",
                        dsn.original_headers
                            .iter()
                            .take(40)
                            .map(|h| h.chars().take(200).collect::<String>())
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                );
                out.extend(
                    header_checks(&dsn.original_headers, &from, "bounce.original", cat)
                        .into_iter()
                        .filter(|c| {
                            // the sender's own copy never carries the receiver's verdict
                            !(c.id.ends_with(".auth_results") && c.verdict == Verdict::Unknown)
                                && !c.id.ends_with(".received_chain")
                                && !c.id.ends_with(".origin_ip")
                        }),
                );
            }
        }
        _ => {
            // no DSN structure: the human text, with anything that looks like an SMTP reply
            let p = parse_message(raw);
            let text = p
                .text
                .clone()
                .or_else(|| p.html.as_deref().map(strip_tags))
                .unwrap_or_default();
            let hints: Vec<String> = text
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    t.len() > 6
                        && (t.starts_with("550")
                            || t.starts_with("554")
                            || t.starts_with("552")
                            || t.starts_with("421")
                            || t.starts_with("450")
                            || t.starts_with("451")
                            || t.contains("5.7.")
                            || t.contains("5.1.1")
                            || t.contains("said:")
                            || t.to_ascii_lowercase().contains("error")
                            || t.to_ascii_lowercase().contains("rejected")
                            || t.to_ascii_lowercase().contains("blocked"))
                })
                .take(6)
                .map(|l| l.trim().chars().take(240).collect())
                .collect();
            let cls = hints.iter().find_map(|h| classify_rejection(h));
            let subject = headers_all(&p.headers, "subject")
                .first()
                .cloned()
                .unwrap_or_default();
            if hints.is_empty() {
                out.push(c("bounce.non_dsn", Verdict::Unknown, Severity::Info, "not a standard bounce".to_string(), format!("no delivery-status part and no SMTP reply in the text (subject: {subject}); upload the bounce as received (.eml), not a forwarded copy")));
            } else {
                let mut ch = c(
                    "bounce.non_dsn",
                    Verdict::Warn,
                    Severity::Medium,
                    "non-standard bounce with a remote reply in the text".to_string(),
                    format!(
                        "{}{}",
                        hints[0],
                        cls.as_ref()
                            .map(|c| format!(" — {}: {}", c.provider, c.meaning))
                            .unwrap_or_default()
                    ),
                )
                .evidence("excerpt", hints.join("\n"));
                if let Some(cl) = cls {
                    ch = ch.fix(Fix {
                        summary: cl.fix.into(),
                        url: cl.url.map(str::to_string),
                        ..Default::default()
                    });
                }
                out.push(ch);
            }
        }
    }
    out
}

// ---- what an upload tells about the run's inputs -----------------------------------

/// What the upload itself says: the address to test (From of a message,
/// the original From or the bounce's To for a bounce), the DKIM selector
/// in use, and the sending IP (first public Received hop).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Derived {
    pub address: Option<String>,
    pub selector: Option<String>,
    pub ip: Option<IpAddr>,
}

pub fn derive_inputs(raw: &[u8], kind: crate::delivery::EmlKind) -> Derived {
    let mut d = Derived::default();
    let headers: Vec<String> = match kind {
        crate::delivery::EmlKind::Message => mime::split_headers(raw).0,
        crate::delivery::EmlKind::Bounce => {
            let dsn = parse_dsn(raw);
            match dsn.as_ref().filter(|x| !x.original_headers.is_empty()) {
                Some(x) => x.original_headers.clone(),
                None => {
                    // the bounce's To is the original sender
                    let (h, _) = mime::split_headers(raw);
                    d.address = headers_all(&h, "to")
                        .first()
                        .map(|t| parse_mailbox(t).1)
                        .filter(|a| a.contains('@'));
                    return d;
                }
            }
        }
    };
    d.address = headers_all(&headers, "from")
        .first()
        .map(|f| parse_mailbox(f).1)
        .filter(|a| a.contains('@'));
    if let Some(sig) = headers_all(&headers, "dkim-signature").first() {
        let s = parse_dkim_signature(sig);
        if !s.s.is_empty()
            && d.address
                .as_deref()
                .map(domain_of)
                .is_some_and(|dom| organizational_domain(&dom).0 == organizational_domain(&s.d).0)
        {
            d.selector = Some(s.s);
        }
    }
    if kind == crate::delivery::EmlKind::Message {
        d.ip = headers_all(&headers, "received")
            .iter()
            .map(|r| parse_received(r))
            .rev()
            .find_map(|r| r.from_ip.filter(|ip| crate::netguard::is_public(*ip)));
    }
    d
}

// ---- the task -------------------------------------------------------------------

pub fn tasks(inputs: &crate::delivery::Inputs) -> Vec<Task> {
    if inputs.eml.is_none() {
        return vec![];
    }
    vec![Task::new("eml", &["dns.domain"], eml_task)]
}

fn eml_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let Some(eml) = &ctx.inputs.eml else {
        return (vec![], vec![]);
    };
    let raw = match std::fs::read(&eml.path) {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![Check::new(
                    "eml.file",
                    SC,
                    CAT,
                    Verdict::Unknown,
                    Severity::Info,
                    "uploaded message",
                    format!("the upload is no longer available: {e}"),
                )],
                vec![],
            )
        }
    };
    let mut checks = match eml.kind {
        crate::delivery::EmlKind::Message => analyse_message(&raw, &ctx.inputs.address, Some(ctx)),
        crate::delivery::EmlKind::Bounce => analyse_bounce(&raw, Some(ctx)),
    };
    // the origin IP gets the sender-side blocklist rows when none was given
    if ctx.inputs.ip.is_none() {
        if let Some(ip) = checks
            .iter()
            .find(|c| c.id == "eml.origin_ip")
            .and_then(|c| {
                c.title
                    .rsplit(' ')
                    .next()
                    .and_then(|s| s.parse::<IpAddr>().ok())
            })
        {
            res.set_fact("eml_origin_ip", Json::str(ip.to_string()));
            if std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_none() {
                let mut listed = Vec::new();
                for list in crate::dnsbl::lists_for(if ip.is_ipv4() {
                    crate::dnsbl::Kind::Ip4
                } else {
                    crate::dnsbl::Kind::Ip6
                })
                .into_iter()
                .filter(|l| l.polarity == crate::dnsbl::Polarity::Block)
                {
                    if let crate::dnsbl::ListVerdict::Listed(l) =
                        crate::dnsbl::query_ip(&ctx.dns, list, ip)
                    {
                        listed.push(format!(
                            "{}: {} (see {})",
                            list.name,
                            l.iter()
                                .map(|x| x.meaning.clone())
                                .collect::<Vec<_>>()
                                .join("; "),
                            list.removal_url
                        ));
                    }
                }
                checks.push(if listed.is_empty() {
                    Check::new(
                        "eml.origin_reputation",
                        SC,
                        Category::Reputation,
                        Verdict::Pass,
                        Severity::Info,
                        format!("origin {ip} is on no blocklist"),
                        "the first public hop of the Received chain",
                    )
                } else {
                    Check::new(
                        "eml.origin_reputation",
                        SC,
                        Category::Reputation,
                        Verdict::Fail,
                        Severity::High,
                        format!("origin {ip} is blocklisted"),
                        listed.join(" · "),
                    )
                    .evidence("listings", listed.join("\n"))
                });
            }
        }
    }
    (checks, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &str = "Return-Path: <bounce@mailer.example>\r\nReceived: from mx.example ([185.199.108.25]) by mail.receiver.test with ESMTPS id x; Sat, 19 Sep 2026 10:05:00 +0000\r\nReceived: from [10.0.0.5] (helo=app) by mx.example with esmtpsa id y; Sat, 19 Sep 2026 09:00:00 +0000\r\nAuthentication-Results: mail.receiver.test; dkim=pass header.i=@x.test header.s=s1; spf=fail smtp.mailfrom=mailer.example; dmarc=pass (p=REJECT) header.from=x.test\r\nDKIM-Signature: v=1; a=rsa-sha256; d=x.test; s=s1; h=from:subject:date:to; bh=abc; b=def\r\nFrom: \"Support\" <support@x.test>\r\nTo: user@receiver.test\r\nSubject: Hello\r\nDate: Sat, 19 Sep 2026 08:59:00 +0000\r\nMessage-ID: <1@x.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee https://x.test/page and http://bit.ly/abc\r\n--b\r\nContent-Type: text/html\r\n\r\n<p><a href=\"https://tracker.example/r?u=1\">https://x.test/page</a> <a href='https://x.test/x'>here</a></p>\r\n--b--\r\n";

    #[test]
    fn parses_headers_dates_and_received() {
        assert_eq!(
            parse_date("Sat, 19 Sep 2026 10:05:00 +0000"),
            parse_date("19 Sep 2026 12:05:00 +0200")
        );
        assert_eq!(parse_date("Thu, 1 Jan 1970 00:00:00 +0000"), Some(0));
        assert_eq!(
            parse_date("Tue, 14 Nov 2023 22:13:20 GMT"),
            Some(1_700_000_000)
        );
        assert!(parse_date("nonsense").is_none());
        let r = parse_received("from mx.example (mx.example. [185.199.108.25]) by mail.receiver.test with ESMTPS id x; Sat, 19 Sep 2026 10:05:00 +0000");
        assert_eq!(r.from.as_deref(), Some("mx.example"));
        assert_eq!(r.from_ip, Some("185.199.108.25".parse().unwrap()));
        assert_eq!(r.by.as_deref(), Some("mail.receiver.test"));
        assert_eq!(r.with.as_deref(), Some("ESMTPS"));
        assert!(r.date.is_some());
        let r = parse_received(
            "from [IPv6:2001:db8::1] by x with ESMTP; Sat, 19 Sep 2026 10:05:00 +0000",
        );
        assert_eq!(r.from_ip, Some("2001:db8::1".parse().unwrap()));
        let ar = parse_authentication_results("mail.receiver.test; dkim=pass header.i=@x.test header.s=s1; spf=fail (sender IP is 1.2.3.4) smtp.mailfrom=mailer.example; dmarc=pass (p=REJECT) header.from=x.test");
        assert_eq!(ar.authserv_id, "mail.receiver.test");
        assert_eq!(ar.result("spf").map(|r| r.1.as_str()), Some("fail"));
        assert_eq!(ar.result("dmarc").map(|r| r.1.as_str()), Some("pass"));
        let sig = parse_dkim_signature(
            "v=1; a=rsa-sha256; d=x.test; s=s1;\r\n h=from:subject:date; l=100; b=xx",
        );
        assert_eq!(
            (sig.d.as_str(), sig.s.as_str(), sig.l),
            ("x.test", "s1", Some(100))
        );
        assert_eq!(
            parse_mailbox("\"Support\" <Support@X.test>"),
            ("Support".into(), "support@x.test".into())
        );
        assert_eq!(
            parse_mailbox("a@b.test"),
            (String::new(), "a@b.test".into())
        );
        assert_eq!(
            url_host("https://user@Host.Example:8443/p?q"),
            Some("host.example".into())
        );
        let links = extract_links(Some("<a href=\"https://tracker.example/r\">https://x.test/page</a> <a href='https://x.test/x'>here</a>"), Some("see http://bit.ly/abc."));
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].text, "https://x.test/page");
        assert_eq!(links[2].href, "http://bit.ly/abc");
    }

    #[test]
    fn analyses_a_message() {
        std::env::set_var("MSFE_NG_DELIVERY_NO_NET", "1");
        let checks = analyse_message(MSG.as_bytes(), "support@x.test", None);
        std::env::remove_var("MSFE_NG_DELIVERY_NO_NET");
        let by = |id: &str| {
            checks.iter().find(|c| c.id == id).unwrap_or_else(|| {
                panic!(
                    "no {id}: {:?}",
                    checks.iter().map(|c| c.id.clone()).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(
            by("eml.auth_results").verdict,
            Verdict::Fail,
            "spf=fail is reported even with dmarc=pass"
        );
        assert_eq!(by("eml.dkim_signature").verdict, Verdict::Pass);
        assert_eq!(
            by("eml.alignment").verdict,
            Verdict::Warn,
            "Return-Path at mailer.example"
        );
        assert_eq!(
            by("eml.received_chain").verdict,
            Verdict::Fail,
            "65 minutes between hops"
        );
        assert!(by("eml.origin_ip").title.ends_with("185.199.108.25"));
        assert_eq!(by("eml.headers.required").verdict, Verdict::Pass);
        assert_eq!(by("eml.lines").verdict, Verdict::Pass);
        assert_eq!(by("eml.list").verdict, Verdict::NotApplicable);
        assert_eq!(
            by("eml.links").verdict,
            Verdict::Warn,
            "text/target mismatch beats the shortener"
        );
        assert_eq!(by("eml.body").verdict, Verdict::Pass);
        // a bulk message without one-click, a long line, a risky attachment, 8-bit subject
        let bad = "From: a@x.test\r\nSubject: Ciao è\r\nList-Unsubscribe: <mailto:u@x.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<img src=\"cid:x\">\r\n--b\r\nContent-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nMZ\r\n--b--\r\n".to_string() + &"x".repeat(1200) + "\r\n";
        let checks = analyse_message(bad.as_bytes(), "a@x.test", None);
        let by = |id: &str| {
            checks
                .iter()
                .find(|c| c.id == id)
                .unwrap_or_else(|| panic!("no {id}"))
        };
        assert_eq!(
            by("eml.headers.required").verdict,
            Verdict::Fail,
            "no Message-ID/Date"
        );
        assert_eq!(by("eml.headers.8bit").verdict, Verdict::Warn);
        assert_eq!(by("eml.list").verdict, Verdict::Fail);
        assert_eq!(by("eml.lines").verdict, Verdict::Fail);
        assert_eq!(by("eml.attachments").verdict, Verdict::Fail);
        assert_eq!(by("eml.dkim_signature").verdict, Verdict::Warn, "unsigned");
        assert_eq!(by("eml.auth_results").verdict, Verdict::Unknown);
    }

    #[test]
    fn derives_inputs_from_uploads() {
        let d = derive_inputs(MSG.as_bytes(), crate::delivery::EmlKind::Message);
        assert_eq!(d.address.as_deref(), Some("support@x.test"));
        assert_eq!(d.selector.as_deref(), Some("s1"));
        assert_eq!(d.ip, Some("185.199.108.25".parse().unwrap()));
    }

    #[test]
    fn parses_and_analyses_a_bounce() {
        let dsn = "From: Mail Delivery System <Mailer-Daemon@ncc.transfervda.com>\r\nTo: info@transfervda.com\r\nSubject: Mail delivery failed: returning message to sender\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=\"1x\"\r\n\r\n--1x\r\nContent-type: text/plain; charset=us-ascii\r\n\r\nThis message was created automatically by mail delivery software.\r\n\r\n--1x\r\nContent-type: message/delivery-status\r\n\r\nReporting-MTA: dns; ncc.transfervda.com\r\n\r\nAction: failed\r\nFinal-Recipient: rfc822;bad@gmail.com\r\nStatus: 5.1.1\r\nRemote-MTA: dns; gmail-smtp-in.l.google.com\r\nDiagnostic-Code: smtp; 550-5.1.1 The email account that you tried to reach does not\r\n exist. - gsmtp\r\n\r\n--1x\r\nContent-type: message/rfc822\r\n\r\nFrom: info@transfervda.com\r\nTo: bad@gmail.com\r\nSubject: hi\r\nDate: Sat, 19 Sep 2026 10:00:00 +0200\r\nMessage-ID: <x@transfervda.com>\r\n\r\nbody\r\n--1x--\r\n";
        let d = parse_dsn(dsn.as_bytes()).unwrap();
        assert_eq!(d.reporting_mta, "ncc.transfervda.com");
        assert_eq!(d.recipients.len(), 1);
        assert_eq!(d.recipients[0].final_recipient, "bad@gmail.com");
        assert_eq!(d.recipients[0].status, "5.1.1");
        assert!(d.recipients[0].diagnostic.contains("does not exist"));
        assert_eq!(
            headers_all(&d.original_headers, "from"),
            vec!["info@transfervda.com"]
        );
        assert_eq!(
            derive_inputs(dsn.as_bytes(), crate::delivery::EmlKind::Bounce)
                .address
                .as_deref(),
            Some("info@transfervda.com")
        );
        let checks = analyse_bounce(dsn.as_bytes(), None);
        let st = checks.iter().find(|c| c.id == "bounce.status").unwrap();
        assert_eq!(st.verdict, Verdict::Fail);
        assert!(st.explanation.contains("Gmail"), "{}", st.explanation);
        assert!(checks
            .iter()
            .any(|c| c.id == "bounce.original.headers.required"));
        // a non-DSN bounce
        let plain = "From: postmaster@x\r\nSubject: Undeliverable\r\nContent-Type: text/plain\r\n\r\nYour message could not be delivered.\r\nRemote server said: 550 5.7.1 Service unavailable, Client host blocked using Spamhaus (S3140)\r\n";
        let checks = analyse_bounce(plain.as_bytes(), None);
        let nd = checks.iter().find(|c| c.id == "bounce.non_dsn").unwrap();
        assert_eq!(nd.verdict, Verdict::Warn);
        assert!(nd.explanation.contains("Microsoft"));
        assert_eq!(status_meaning("5.2.2"), "mailbox full");
    }
}
