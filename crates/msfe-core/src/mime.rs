//! Minimal MIME decoder for the quarantine "rendered preview".
//!
//! Turns a raw RFC822 message into a single HTML fragment the browser can
//! show: walks `multipart/*` trees, decodes `quoted-printable` / `base64`
//! transfer encodings and the part charset, prefers `text/html` over
//! `text/plain` (which is wrapped in `<pre>`), and inlines `cid:` images from
//! `multipart/related` siblings as `data:` URIs so logos still show under a
//! no-network CSP. No external crates, like the rest of the core.

use std::collections::HashMap;

/// One MIME entity: decoded body plus children for `multipart/*`.
pub(crate) struct Entity {
    pub(crate) ctype: String, // lowercased media type, e.g. "text/html"
    pub(crate) params: HashMap<String, String>,
    pub(crate) headers: Vec<String>, // unfolded header lines
    pub(crate) body: Vec<u8>,        // transfer-decoded; for multiparts, the raw body
    pub(crate) children: Vec<Entity>,
}

/// Decoded representation of a message ready for display.
pub struct Preview {
    /// HTML fragment (safe to place inside a sandboxed document; scripts are
    /// left in but the caller's CSP blocks them).
    pub html: String,
}

const PRE_STYLE: &str =
    "white-space:pre-wrap;word-break:break-word;font:13px ui-monospace,monospace;margin:0;padding:1rem";
const CAPTION_STYLE: &str =
    "font:12px system-ui;color:#555;background:#f3f4f6;border-top:1px solid #ddd;border-bottom:1px solid #ddd;padding:.3rem 1rem;margin-top:.5rem";
const NESTED_STYLE: &str =
    "border-left:3px solid #cbd5e1;margin:.5rem 0 .5rem 1rem;padding-left:.5rem";

/// Build the HTML preview of a raw message. Always succeeds: a message with no
/// displayable part yields a short notice instead of nothing.
///
/// `multipart/alternative` shows the best variant (HTML over plain text);
/// every other multipart shows its parts in order, so a bounce
/// (`multipart/report`) reads as notification → delivery status → returned
/// headers. Encapsulated `message/rfc822` parts get a header summary and
/// their own rendered body; remaining attachments are listed by name.
pub fn preview(raw: &[u8]) -> Preview {
    let root = parse_entity(raw, 0);
    let mut images = HashMap::new();
    collect_cid_images(&root, &mut images);
    let mut out = String::new();
    render(&root, &images, 0, &mut out);
    if out.is_empty() {
        let mut kinds = Vec::new();
        list_types(&root, &mut kinds);
        out = format!(
            "<p style=\"font:13px system-ui;padding:1rem\">No text part to display ({}).</p>",
            escape_html(&if kinds.is_empty() {
                "empty message".to_string()
            } else {
                kinds.join(", ")
            })
        );
    }
    Preview { html: out }
}

/// Parse a (sub)message into an entity tree.
pub(crate) fn parse_entity(raw: &[u8], depth: usize) -> Entity {
    let (headers, body) = split_headers(raw);
    let ct = header(&headers, "content-type").unwrap_or_else(|| "text/plain".to_string());
    let (ctype, params) = parse_content_type(&ct);
    let cte = header(&headers, "content-transfer-encoding");

    let mut children = Vec::new();
    if ctype.starts_with("multipart/") && depth < 16 {
        if let Some(boundary) = params.get("boundary") {
            children = split_multipart(body, boundary)
                .into_iter()
                .map(|sub| parse_entity(sub, depth + 1))
                .collect();
        }
    }
    // a multipart without a usable boundary is shown as text
    let ctype = if ctype.starts_with("multipart/") && children.is_empty() {
        "text/plain".to_string()
    } else {
        ctype
    };
    let body = if children.is_empty() {
        transfer_decode(body, cte.as_deref())
    } else {
        Vec::new()
    };
    Entity {
        ctype,
        params,
        headers,
        body,
        children,
    }
}

fn collect_cid_images(e: &Entity, out: &mut HashMap<String, (String, Vec<u8>)>) {
    if e.ctype.starts_with("image/") {
        if let Some(cid) = header(&e.headers, "content-id") {
            let cid = cid
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string();
            out.insert(cid, (e.ctype.clone(), e.body.clone()));
        }
    }
    for c in &e.children {
        collect_cid_images(c, out);
    }
}

fn list_types(e: &Entity, out: &mut Vec<String>) {
    if e.children.is_empty() {
        out.push(e.ctype.clone());
    }
    for c in &e.children {
        list_types(c, out);
    }
}

fn charset_of(e: &Entity) -> Option<&str> {
    e.params.get("charset").map(String::as_str)
}

/// Render an entity into `out`. `depth` counts `message/rfc822` nesting.
fn render(e: &Entity, images: &HashMap<String, (String, Vec<u8>)>, depth: usize, out: &mut String) {
    match e.ctype.as_str() {
        "multipart/alternative" => {
            // best variant only: html, else plain, else the last part
            let pick = e
                .children
                .iter()
                .find(|c| c.ctype == "text/html" || contains_html(c))
                .or_else(|| e.children.iter().find(|c| c.ctype == "text/plain"))
                .or_else(|| e.children.last());
            if let Some(c) = pick {
                render(c, images, depth, out);
            }
        }
        t if t.starts_with("multipart/") => {
            for c in &e.children {
                render(c, images, depth, out);
            }
        }
        "text/html" => {
            let s = decode_charset(&e.body, charset_of(e));
            out.push_str(&inline_cid_images(&s, images));
        }
        "text/plain"
        | "text/rfc822-headers"
        | "message/delivery-status"
        | "message/feedback-report"
        | "message/disposition-notification" => {
            if e.ctype != "text/plain" {
                caption(e, out);
            }
            let s = decode_charset(&e.body, charset_of(e));
            out.push_str(&format!(
                "<pre style=\"{PRE_STYLE}\">{}</pre>",
                escape_html(&s)
            ));
        }
        "message/rfc822" if depth < 8 => {
            caption(e, out);
            let inner = parse_entity(&e.body, 0);
            out.push_str(&format!("<div style=\"{NESTED_STYLE}\">"));
            out.push_str(
                "<table style=\"font:12px system-ui;border-collapse:collapse;margin:.3rem 0\">",
            );
            for name in ["From", "To", "Date", "Subject"] {
                if let Some(v) = header(&inner.headers, &name.to_ascii_lowercase()) {
                    out.push_str(&format!(
                        "<tr><th style=\"text-align:left;padding:.1rem .6rem .1rem 0;color:#555\">{name}</th><td>{}</td></tr>",
                        escape_html(&crate::queueview::decode_rfc2047(&v))
                    ));
                }
            }
            out.push_str("</table>");
            let mut inner_imgs = images.clone();
            collect_cid_images(&inner, &mut inner_imgs);
            render(&inner, &inner_imgs, depth + 1, out);
            out.push_str("</div>");
        }
        t if t.starts_with("image/") && header(&e.headers, "content-id").is_some() => {
            // inline image referenced by cid: — already embedded where used
        }
        _ => {
            // anything else is an attachment: name it, don't show it
            let name = e
                .params
                .get("name")
                .cloned()
                .or_else(|| {
                    header(&e.headers, "content-disposition")
                        .map(|d| parse_content_type(&d).1)
                        .and_then(|p| p.get("filename").cloned())
                })
                .unwrap_or_else(|| "(unnamed)".to_string());
            out.push_str(&format!(
                "<div style=\"{CAPTION_STYLE}\">📎 {} — {} · {}</div>",
                escape_html(&crate::queueview::decode_rfc2047(&name)),
                escape_html(&e.ctype),
                human_size(e.body.len())
            ));
        }
    }
}

/// The attachments of a raw message: every non-multipart part that carries
/// a file name, as `(decoded name, transfer-decoded bytes)`, in order.
pub fn attachments(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    fn walk(e: &Entity, out: &mut Vec<(String, Vec<u8>)>) {
        if !e.children.is_empty() {
            for c in &e.children {
                walk(c, out);
            }
            return;
        }
        let name = e.params.get("name").cloned().or_else(|| {
            header(&e.headers, "content-disposition")
                .map(|d| parse_content_type(&d).1)
                .and_then(|p| p.get("filename").cloned())
        });
        if let Some(n) = name {
            out.push((crate::queueview::decode_rfc2047(&n), e.body.clone()));
        }
    }
    let mut out = Vec::new();
    walk(&parse_entity(raw, 0), &mut out);
    out
}

/// True when an alternative branch (e.g. `multipart/related`) holds HTML.
fn contains_html(e: &Entity) -> bool {
    e.ctype == "text/html" || e.children.iter().any(contains_html)
}

/// A small labelled bar before a non-primary part (bounce report, returned
/// headers, encapsulated message).
fn caption(e: &Entity, out: &mut String) {
    let label = header(&e.headers, "content-description").unwrap_or_else(|| {
        match e.ctype.as_str() {
            "message/rfc822" => "Encapsulated message",
            "message/delivery-status" => "Delivery status",
            "text/rfc822-headers" => "Returned message headers",
            "message/feedback-report" => "Feedback report",
            "message/disposition-notification" => "Disposition notification",
            _ => "Part",
        }
        .to_string()
    });
    out.push_str(&format!(
        "<div style=\"{CAPTION_STYLE}\">{} <span style=\"opacity:.7\">({})</span></div>",
        escape_html(&label),
        escape_html(&e.ctype)
    ));
}

fn human_size(n: usize) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{} KB", n / 1024)
    } else {
        format!("{n} B")
    }
}

/// Split at the first blank line into (unfolded header lines, body).
pub(crate) fn split_headers(raw: &[u8]) -> (Vec<String>, &[u8]) {
    let mut i = 0;
    let mut end = raw.len();
    let mut body_start = raw.len();
    while i < raw.len() {
        // line end
        let nl = raw[i..].iter().position(|&b| b == b'\n').map(|p| i + p);
        let line_end = nl.unwrap_or(raw.len());
        let line = &raw[i..line_end];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            end = i;
            body_start = nl.map(|p| p + 1).unwrap_or(raw.len());
            break;
        }
        i = nl.map(|p| p + 1).unwrap_or(raw.len());
    }
    let head = String::from_utf8_lossy(&raw[..end]);
    let mut lines: Vec<String> = Vec::new();
    for l in head.lines() {
        if (l.starts_with(' ') || l.starts_with('\t')) && !lines.is_empty() {
            let last = lines.last_mut().unwrap();
            last.push(' ');
            last.push_str(l.trim_start());
        } else {
            lines.push(l.to_string());
        }
    }
    (lines, &raw[body_start..])
}

pub(crate) fn header(lines: &[String], name: &str) -> Option<String> {
    lines.iter().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        if k.trim().eq_ignore_ascii_case(name) {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

/// `text/html; charset="utf-8"; name=x` → ("text/html", {charset: utf-8, name: x})
pub(crate) fn parse_content_type(v: &str) -> (String, HashMap<String, String>) {
    let mut it = v.split(';');
    let ctype = it.next().unwrap_or("").trim().to_ascii_lowercase();
    let mut params = HashMap::new();
    for p in it {
        if let Some((k, val)) = p.split_once('=') {
            let val = val.trim();
            let val = val
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(val);
            params.insert(k.trim().to_ascii_lowercase(), val.to_string());
        }
    }
    (ctype, params)
}

/// Return the sub-part byte ranges between `--boundary` delimiters, excluding
/// the preamble and epilogue.
fn split_multipart<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delim = format!("--{}", boundary);
    let delim = delim.as_bytes();
    let mut parts = Vec::new();
    let mut pos = 0;
    let mut current: Option<usize> = None;
    while let Some(p) = find(&body[pos..], delim).map(|p| p + pos) {
        // a delimiter must start a line
        if p > 0 && body[p - 1] != b'\n' {
            pos = p + delim.len();
            continue;
        }
        if let Some(start) = current {
            // strip the CRLF/LF that belongs to the delimiter
            let mut e = p;
            if e > start && body[e - 1] == b'\n' {
                e -= 1;
                if e > start && body[e - 1] == b'\r' {
                    e -= 1;
                }
            }
            parts.push(&body[start..e]);
        }
        let after = p + delim.len();
        if body[after..].starts_with(b"--") {
            break; // closing delimiter
        }
        // skip to the end of the delimiter line
        let nl = body[after..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| after + n + 1);
        match nl {
            Some(n) => {
                current = Some(n);
                pos = n;
            }
            None => break,
        }
    }
    parts
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

fn transfer_decode(body: &[u8], cte: Option<&str>) -> Vec<u8> {
    match cte.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("quoted-printable") => decode_qp(body),
        Some("base64") => decode_base64(body),
        _ => body.to_vec(),
    }
}

/// RFC 2045 quoted-printable: `=XX` hex escapes, `=\n` soft line breaks.
fn decode_qp(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            // soft break: "=\r\n" or "=\n"
            if b[i + 1..].starts_with(b"\r\n") {
                i += 3;
                continue;
            }
            if b[i + 1..].starts_with(b"\n") {
                i += 2;
                continue;
            }
            if i + 2 < b.len() {
                if let Ok(v) =
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn decode_base64(b: &[u8]) -> Vec<u8> {
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let clean: Vec<u8> = b
        .iter()
        .copied()
        .filter_map(|c| val(c).map(|_| c))
        .collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= (val(c).unwrap_or(0) as u32) << (18 - 6 * i);
        }
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        if chunk.len() > 1 {
            out.extend_from_slice(&bytes[..chunk.len() - 1]);
        }
    }
    out
}

/// Decode bytes in the given charset to a String. UTF-8 (and ASCII) pass
/// through; ISO-8859-1 / Windows-1252 are mapped byte-by-byte (cp1252's 0x80–
/// 0x9F block included, since mail labelled latin-1 is usually cp1252); any
/// other charset is treated as UTF-8 lossily — good enough for a preview.
pub fn decode_charset(b: &[u8], charset: Option<&str>) -> String {
    let cs = charset
        .map(|c| c.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match cs.as_str() {
        "iso-8859-1" | "latin1" | "iso8859-1" | "windows-1252" | "cp1252" | "us-ascii"
        | "ascii"
            if !b.is_ascii() =>
        {
            b.iter().map(|&c| cp1252_char(c)).collect()
        }
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

fn cp1252_char(c: u8) -> char {
    const HI: [char; 32] = [
        '€', '\u{81}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{8d}', 'Ž',
        '\u{8f}', '\u{90}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{9d}',
        'ž', 'Ÿ',
    ];
    match c {
        0x80..=0x9f => HI[(c - 0x80) as usize],
        _ => c as char,
    }
}

/// Replace `src="cid:xyz"` references with `data:` URIs of the matching part.
fn inline_cid_images(html: &str, images: &HashMap<String, (String, Vec<u8>)>) -> String {
    if !html.contains("cid:") {
        return html.to_string();
    }
    let mut out = html.to_string();
    for (cid, (ctype, body)) in images {
        let data = format!("data:{};base64,{}", ctype, encode_base64(body));
        for quote in ['"', '\''] {
            let needle = format!("{}cid:{}{}", quote, cid, quote);
            let repl = format!("{}{}{}", quote, data, quote);
            out = out.replace(&needle, &repl);
        }
    }
    out
}

fn encode_base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for chunk in b.chunks(3) {
        let n = chunk.len();
        let acc = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(T[(acc >> 18) as usize & 63] as char);
        out.push(T[(acc >> 12) as usize & 63] as char);
        out.push(if n > 1 {
            T[(acc >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if n > 2 {
            T[acc as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn escape_html(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            _ => o.push(c),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like the cPanel chkservd notice that exposed the bug:
    /// alternative → (plain QP, related → (html QP, inline PNG base64)).
    fn cpanel_notice() -> Vec<u8> {
        concat!(
            "From: cpanel@ns2.example.com\r\n",
            "Subject: =?utf-8?Q?p0f?=\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/alternative;\r\n",
            "\tboundary=\"alt-Cpanel::Email::Object-1-2-0.8\"\r\n",
            "\r\n",
            "--alt-Cpanel::Email::Object-1-2-0.8\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "The service =E2=80=9Cp0f=E2=80=9D is now operational.\r\n",
            "--alt-Cpanel::Email::Object-1-2-0.8\r\n",
            "Content-Type: multipart/related; boundary=\"rel-Cpanel::Email::Object-1-2-0.7\"\r\n",
            "\r\n",
            "--rel-Cpanel::Email::Object-1-2-0.7\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "Content-Transfer-Encoding: quoted-printable\r\n",
            "\r\n",
            "<p>The service =E2=80=9Cp0f=E2=80=\r\n",
            "=9D is now <b>operational</b>.</p>\r\n",
            "<img src=3D\"cid:logo@cpanel\" alt=3D\"cP\">\r\n",
            "--rel-Cpanel::Email::Object-1-2-0.7\r\n",
            "Content-Type: image/png; name=\"cpanel-logo-tiny.png\"\r\n",
            "Content-Disposition: attachment; filename=\"cpanel-logo-tiny.png\"\r\n",
            "Content-ID: <logo@cpanel>\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "iVBORw0KGgo=\r\n",
            "--rel-Cpanel::Email::Object-1-2-0.7--\r\n",
            "--alt-Cpanel::Email::Object-1-2-0.8--\r\n",
        )
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn prefers_html_alternative_and_decodes_qp() {
        let p = preview(&cpanel_notice());
        assert!(
            p.html
                .contains("<p>The service “p0f” is now <b>operational</b>.</p>"),
            "{}",
            p.html
        );
        // the plain-text sibling and the MIME scaffolding must not leak through
        assert!(!p.html.contains("=E2=80"), "{}", p.html);
        assert!(!p.html.contains("Cpanel::Email::Object"), "{}", p.html);
        assert!(!p.html.contains("Content-Type"), "{}", p.html);
    }

    #[test]
    fn inlines_cid_images_as_data_uris() {
        let p = preview(&cpanel_notice());
        assert!(
            p.html
                .contains("src=\"data:image/png;base64,iVBORw0KGgo=\""),
            "{}",
            p.html
        );
        assert!(!p.html.contains("cid:"), "{}", p.html);
    }

    #[test]
    fn plain_text_only_is_escaped_in_pre() {
        let raw = b"From: a@b\nContent-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: 8bit\n\nCaf\xe9 <b>not bold</b> \x93q\x94\n";
        let p = preview(raw);
        assert!(p.html.starts_with("<pre"), "{}", p.html);
        assert!(
            p.html.contains("Café &lt;b&gt;not bold&lt;/b&gt; “q”"),
            "{}",
            p.html
        );
    }

    #[test]
    fn unlabelled_message_is_plain_text() {
        let p = preview(b"Subject: x\n\nhello\n");
        assert!(
            p.html.contains("<pre") && p.html.contains("hello"),
            "{}",
            p.html
        );
    }

    #[test]
    fn base64_html_part() {
        // "<i>hi</i>" in base64, with a line wrap
        let raw =
            b"Content-Type: text/html\nContent-Transfer-Encoding: base64\n\nPGk+aGk8\n L2k+\n";
        assert!(preview(raw).html.contains("<i>hi</i>"));
    }

    /// Postfix bounce: multipart/report → notification, delivery-status,
    /// returned headers — all three must be shown, in order, and the MIME
    /// preamble/boundaries must not.
    #[test]
    fn dsn_shows_every_report_part_in_order() {
        let raw = concat!(
            "From: MAILER-DAEMON@ls229.example (Mail Delivery System)\n",
            "Subject: Undelivered Mail Returned to Sender\n",
            "Content-Type: multipart/report; report-type=delivery-status;\n",
            "\tboundary=\"9F6D265894D.1789175732/ls229.example\"\n",
            "\n",
            "This is a MIME-encapsulated message.\n",
            "\n",
            "--9F6D265894D.1789175732/ls229.example\n",
            "Content-Description: Notification\n",
            "Content-Type: text/plain; charset=us-ascii\n",
            "\n",
            "This is the mail system at host ls229.example.\n",
            "<jsm@x.example>: host mx01 said: 550 5.1.1 does not exist\n",
            "\n",
            "--9F6D265894D.1789175732/ls229.example\n",
            "Content-Description: Delivery report\n",
            "Content-Type: message/delivery-status\n",
            "\n",
            "Reporting-MTA: dns; ls229.example\n",
            "\n",
            "Final-Recipient: rfc822; jsm@x.example\n",
            "Action: failed\n",
            "Status: 5.1.1\n",
            "\n",
            "--9F6D265894D.1789175732/ls229.example\n",
            "Content-Description: Undelivered Message Headers\n",
            "Content-Type: text/rfc822-headers\n",
            "\n",
            "From: Crypto <support@spoofed.example>\n",
            "Subject: Connect Your External Wallet\n",
            "\n",
            "--9F6D265894D.1789175732/ls229.example--\n"
        );
        let h = preview(raw.as_bytes()).html;
        let i1 = h.find("This is the mail system").expect("notification");
        let i2 = h.find("Delivery report").expect("delivery caption");
        let i3 = h.find("Action: failed").expect("status");
        let i4 = h
            .find("Undelivered Message Headers")
            .expect("headers caption");
        let i5 = h
            .find("Connect Your External Wallet")
            .expect("returned subject");
        assert!(i1 < i2 && i2 < i3 && i3 < i4 && i4 < i5, "{h}");
        assert!(
            !h.contains("MIME-encapsulated") && !h.contains("--9F6D"),
            "{h}"
        );
        assert!(h.contains("&lt;jsm@x.example&gt;"), "text is escaped: {h}");
    }

    /// A forwarded message as message/rfc822: header summary + its own body,
    /// with the outer text shown first.
    #[test]
    fn encapsulated_rfc822_gets_summary_and_rendered_body() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=out\n\n",
            "--out\n",
            "Content-Type: text/plain\n\nFYI see below\n",
            "--out\n",
            "Content-Type: message/rfc822\n\n",
            "From: =?utf-8?Q?Andr=C3=A9?= <a@x.example>\n",
            "To: b@y.example\n",
            "Subject: inner subject\n",
            "Content-Type: multipart/alternative; boundary=in\n\n",
            "--in\n",
            "Content-Type: text/plain\n\nplain inner\n",
            "--in\n",
            "Content-Type: text/html\n\n<b>html inner</b>\n",
            "--in--\n",
            "--out--\n"
        );
        let h = preview(raw.as_bytes()).html;
        let a = h.find("FYI see below").unwrap();
        let b = h.find("Encapsulated message").unwrap();
        let c = h.find("inner subject").unwrap();
        let d = h.find("<b>html inner</b>").unwrap();
        assert!(a < b && b < c && c < d, "{h}");
        assert!(h.contains("André"), "rfc2047 in summary: {h}");
        assert!(
            !h.contains("plain inner"),
            "alternative picks html only: {h}"
        );
    }

    #[test]
    fn attachments_are_listed_not_shown() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=xx\n\n",
            "--xx\n",
            "Content-Type: text/plain\n\nsee attached\n",
            "--xx\n",
            "Content-Type: application/pdf; name=\"report.pdf\"\nContent-Transfer-Encoding: base64\n\nAAAAAAAA\n",
            "--xx--\n"
        );
        let h = preview(raw.as_bytes()).html;
        assert!(
            h.contains("report.pdf") && h.contains("application/pdf") && h.contains("6 B"),
            "{h}"
        );
        assert!(!h.contains("AAAAAAAA"), "{h}");
    }

    #[test]
    fn nested_mixed_with_attachment_still_finds_text() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=xx\n\n",
            "preamble to ignore\n",
            "--xx\n",
            "Content-Type: application/pdf; name=a.pdf\nContent-Transfer-Encoding: base64\n\nAAAA\n",
            "--xx\n",
            "Content-Type: text/plain\n\nthe body\n",
            "--xx--\n",
            "epilogue\n"
        );
        let p = preview(raw.as_bytes());
        assert!(p.html.contains("the body"), "{}", p.html);
        assert!(
            !p.html.contains("preamble") && !p.html.contains("epilogue"),
            "{}",
            p.html
        );
    }

    #[test]
    fn lone_attachment_is_listed_and_empty_message_gets_notice() {
        let raw =
            b"Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nAAAA\n";
        let p = preview(raw);
        assert!(
            p.html.contains("(unnamed)") && p.html.contains("application/octet-stream"),
            "{}",
            p.html
        );
        assert!(p.html.contains("3 B"), "{}", p.html);
        // an inline image nothing references renders nothing → the notice
        let raw = b"Content-Type: image/png\nContent-ID: <x>\nContent-Transfer-Encoding: base64\n\nAAAA\n";
        let p = preview(raw);
        assert!(
            p.html.contains("No text part") && p.html.contains("image/png"),
            "{}",
            p.html
        );
    }

    #[test]
    fn qp_decoder_handles_soft_breaks_and_bad_escapes() {
        assert_eq!(decode_qp(b"a=\r\nb=\nc=3Dd =zz"), b"abc=d =zz");
        assert_eq!(decode_qp(b"trailing="), b"trailing=");
    }
}
