//! Minimal MIME decoder for the quarantine "rendered preview".
//!
//! Turns a raw RFC822 message into a single HTML fragment the browser can
//! show: walks `multipart/*` trees, decodes `quoted-printable` / `base64`
//! transfer encodings and the part charset, prefers `text/html` over
//! `text/plain` (which is wrapped in `<pre>`), and inlines `cid:` images from
//! `multipart/related` siblings as `data:` URIs so logos still show under a
//! no-network CSP. No external crates, like the rest of the core.

use std::collections::HashMap;

/// One leaf part after decoding. `body` is raw bytes (already transfer-decoded).
struct Part {
    ctype: String, // lowercased media type, e.g. "text/html"
    params: HashMap<String, String>,
    body: Vec<u8>,
    content_id: Option<String>,
}

/// Decoded representation of a message ready for display.
pub struct Preview {
    /// HTML fragment (safe to place inside a sandboxed document; scripts are
    /// left in but the caller's CSP blocks them).
    pub html: String,
}

/// Build the HTML preview of a raw message. Always succeeds: a message with no
/// displayable part yields a short notice instead of nothing.
pub fn preview(raw: &[u8]) -> Preview {
    let mut leaves = Vec::new();
    collect_parts(raw, &mut leaves, 0);

    let html_part = leaves.iter().find(|p| p.ctype == "text/html");
    let text_part = leaves.iter().find(|p| p.ctype == "text/plain");

    let html = match (html_part, text_part) {
        (Some(h), _) => {
            let s = decode_charset(&h.body, h.params.get("charset").map(String::as_str));
            inline_cid_images(&s, &leaves)
        }
        (None, Some(t)) => {
            let s = decode_charset(&t.body, t.params.get("charset").map(String::as_str));
            format!(
                "<pre style=\"white-space:pre-wrap;word-break:break-word;font:13px ui-monospace,monospace;padding:1rem\">{}</pre>",
                escape_html(&s)
            )
        }
        (None, None) => {
            let kinds: Vec<&str> = leaves.iter().map(|p| p.ctype.as_str()).collect();
            format!(
                "<p style=\"font:13px system-ui;padding:1rem\">No text part to display ({}).</p>",
                escape_html(&if kinds.is_empty() {
                    "empty message".to_string()
                } else {
                    kinds.join(", ")
                })
            )
        }
    };
    Preview { html }
}

/// Recursively flatten a (sub)message into leaf parts.
fn collect_parts(raw: &[u8], out: &mut Vec<Part>, depth: usize) {
    let (headers, body) = split_headers(raw);
    let ct = header(&headers, "content-type").unwrap_or_else(|| "text/plain".to_string());
    let (ctype, params) = parse_content_type(&ct);

    if ctype.starts_with("multipart/") && depth < 16 {
        if let Some(boundary) = params.get("boundary") {
            for sub in split_multipart(body, boundary) {
                collect_parts(sub, out, depth + 1);
            }
            return;
        }
        // multipart without a boundary: fall through and show as text
    }
    if ctype == "message/rfc822" && depth < 16 {
        let decoded = transfer_decode(
            body,
            header(&headers, "content-transfer-encoding").as_deref(),
        );
        collect_parts(&decoded, out, depth + 1);
        return;
    }

    let cte = header(&headers, "content-transfer-encoding");
    let content_id = header(&headers, "content-id").map(|s| {
        s.trim()
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string()
    });
    out.push(Part {
        ctype,
        params,
        body: transfer_decode(body, cte.as_deref()),
        content_id,
    });
}

/// Split at the first blank line into (unfolded header lines, body).
fn split_headers(raw: &[u8]) -> (Vec<String>, &[u8]) {
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

fn header(lines: &[String], name: &str) -> Option<String> {
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
fn parse_content_type(v: &str) -> (String, HashMap<String, String>) {
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
fn inline_cid_images(html: &str, parts: &[Part]) -> String {
    if !html.contains("cid:") {
        return html.to_string();
    }
    let mut out = html.to_string();
    for p in parts {
        let Some(cid) = &p.content_id else { continue };
        if !p.ctype.starts_with("image/") {
            continue;
        }
        let data = format!("data:{};base64,{}", p.ctype, encode_base64(&p.body));
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
    fn no_text_part_gives_notice() {
        let raw =
            b"Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\n\nAAAA\n";
        let p = preview(raw);
        assert!(p.html.contains("No text part"), "{}", p.html);
        assert!(p.html.contains("application/octet-stream"), "{}", p.html);
    }

    #[test]
    fn qp_decoder_handles_soft_breaks_and_bad_escapes() {
        assert_eq!(decode_qp(b"a=\r\nb=\nc=3Dd =zz"), b"abc=d =zz");
        assert_eq!(decode_qp(b"trailing="), b"trailing=");
    }
}
