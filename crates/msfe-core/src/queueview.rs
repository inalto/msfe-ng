//! Rich Exim queue listing: parse `-H` spool header files directly so the
//! Queues tab can show sender, recipients, subject, spam score and frozen
//! state per message — without forking `exim -Mvh` once per message.
//!
//! Format facts (observed on Exim 4.9x spool files): line 1 repeats the id
//! with `-H`; line 2 is `user uid gid`; line 3 the envelope sender in `<>`
//! (empty = null sender / bounce); line 4 `received-epoch warning-count`.
//! Then dash-prefixed option lines — `-aclc`/`-aclm` values are BYTE-LENGTH
//! prefixed and may span lines that themselves start with `-`, so they must
//! be consumed by length, never by line. After the options: the
//! non-recipients tree, a pure-integer recipient count, that many recipient
//! lines, a blank line, and finally headers as `NNN{flag} text` where NNN is
//! the byte length of the header text including folded continuation lines.
//!
//! A file that fails to parse yields a metadata-only row (id/age/size) so the
//! message never disappears from the UI — and is never selected by automatic
//! cleanup rules.

use std::collections::HashMap;
use std::path::Path;

/// One queued message, as shown in the Queues tab.
pub struct QueueMsgInfo {
    pub id: String,
    /// Envelope sender; empty string = null sender (`<>`).
    pub sender: String,
    /// True when the envelope sender is `<>` — a bounce/notification, or spam
    /// sent with a null sender so it can never be bounced back.
    pub bounce: bool,
    pub recipients: Vec<String>,
    pub subject: String,
    /// Spam score recorded in the spool by the cPanel SpamAssassin ACL
    /// (`-spam_score`), falling back to an `X-Spam-Status: score=` header.
    pub spam_score: Option<f64>,
    pub frozen: bool,
    pub age_secs: u64,
    /// Size of the `-D` data file (message body) in bytes.
    pub size: u64,
    /// False when the `-H` file could not be parsed: only id/age/size are
    /// meaningful, and automatic cleanup must never select this message.
    pub parsed: bool,
}

/// A capped queue listing plus the true total.
pub struct QueueListing {
    pub total: usize,
    pub truncated: bool,
    pub msgs: Vec<QueueMsgInfo>,
}

/// Parse an Exim `-H` spool header file. `now` is the current Unix time (a
/// parameter so tests are deterministic). Returns `None` on any structural
/// surprise — the caller falls back to a metadata-only row.
pub fn parse_spool_header(id: &str, text: &str, now: u64) -> Option<QueueMsgInfo> {
    let b = text.as_bytes();
    let mut pos = 0usize;
    let line = |pos: &mut usize| -> Option<&str> {
        if *pos >= b.len() {
            return None;
        }
        let start = *pos;
        let end = b[start..]
            .iter()
            .position(|&c| c == b'\n')
            .map(|i| start + i)
            .unwrap_or(b.len());
        *pos = (end + 1).min(b.len());
        std::str::from_utf8(&b[start..end]).ok()
    };

    // line 1: "<id>-H"
    let l1 = line(&mut pos)?;
    if l1.trim() != format!("{id}-H") {
        return None;
    }
    line(&mut pos)?; // user uid gid
    let sender_line = line(&mut pos)?.trim().to_string();
    let sender = sender_line
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(&sender_line)
        .to_string();
    let bounce = sender.is_empty();
    let epoch: u64 = line(&mut pos)?
        .split_whitespace()
        .next()?
        .parse()
        .unwrap_or(0);

    let mut frozen = false;
    let mut spam_score: Option<f64> = None;

    // dash-option section (options may carry one or two leading dashes)
    loop {
        let save = pos;
        let Some(l) = line(&mut pos) else { break };
        if !l.starts_with('-') {
            pos = save;
            break;
        }
        let stripped = l.trim_start_matches('-');
        let mut toks = stripped.split_whitespace();
        let name = toks.next().unwrap_or("");
        match name {
            "frozen" => frozen = true,
            "spam_score" => spam_score = toks.next().and_then(|v| v.parse().ok()),
            // length-prefixed ACL variables: value is `len` bytes starting on
            // the next line and may itself contain lines beginning with '-'
            "aclc" | "aclm" => {
                let len: usize = toks.nth(1)?.parse().ok()?;
                pos = (pos + len).min(b.len());
                if pos < b.len() && b[pos] == b'\n' {
                    pos += 1;
                }
            }
            _ => {}
        }
    }

    // non-recipients tree, then a pure-integer recipient count
    let mut rcpt_count: Option<usize> = None;
    for _ in 0..10_000 {
        let l = line(&mut pos)?;
        let t = l.trim();
        if !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit()) {
            rcpt_count = t.parse().ok();
            break;
        }
    }
    let n = rcpt_count?;
    let mut recipients = Vec::new();
    for _ in 0..n.min(500) {
        // a recipient line may carry one_time/errors_to extras after the address
        if let Some(l) = line(&mut pos) {
            if let Some(addr) = l.split_whitespace().next() {
                recipients.push(addr.to_string());
            }
        }
    }

    // blank separator, then length-prefixed header lines
    let mut subject = String::new();
    while pos < b.len() {
        // skip blank lines between sections
        if b[pos] == b'\n' {
            pos += 1;
            continue;
        }
        // NNN digits
        let dstart = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == dstart || pos + 2 > b.len() {
            break; // not a header line
        }
        let len: usize = std::str::from_utf8(&b[dstart..pos]).ok()?.parse().ok()?;
        pos += 1; // flag byte (F/T/P/I/R/S/*/space)
        if pos < b.len() && b[pos] == b' ' {
            pos += 1;
        }
        let end = (pos + len).min(b.len());
        let htext = String::from_utf8_lossy(&b[pos..end]);
        pos = end;
        let lower = htext.to_ascii_lowercase();
        if lower.starts_with("subject:") {
            subject = decode_rfc2047(htext["Subject:".len()..].trim());
        } else if spam_score.is_none() && lower.starts_with("x-spam-status:") {
            // "X-Spam-Status: Yes, score=16.4" fallback for mail scored by a
            // scanner that didn't record -spam_score in the spool
            if let Some(i) = lower.find("score=") {
                let v: String = htext[i + 6..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                    .collect();
                spam_score = v.parse().ok();
            }
        }
    }

    Some(QueueMsgInfo {
        id: id.to_string(),
        sender,
        bounce,
        recipients,
        subject,
        spam_score,
        frozen,
        age_secs: now.saturating_sub(epoch),
        size: 0,
        parsed: true,
    })
}

/// List a queue directory (flat or split-spool) with parsed per-message info,
/// oldest first, capped at `cap` rows. `total` is the uncapped count.
pub fn list_queue(dir: &Path, cap: usize) -> QueueListing {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let files = crate::service::queue_files(dir);
    // pair up -H and -D by id
    let mut dsize: HashMap<String, u64> = HashMap::new();
    let mut hfiles: Vec<(String, std::path::PathBuf)> = Vec::new();
    for p in files {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(id) = name.strip_suffix("-D") {
            let sz = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            dsize.insert(id.to_string(), sz);
        } else if let Some(id) = name.strip_suffix("-H") {
            hfiles.push((id.to_string(), p));
        }
    }
    let total = hfiles.len();
    let mut msgs: Vec<QueueMsgInfo> = hfiles
        .into_iter()
        .map(|(id, path)| {
            // a message can be delivered (and its files removed) mid-walk;
            // then the read fails and we still emit a metadata-only row
            let text = std::fs::read_to_string(&path).ok();
            let mut info = text
                .as_deref()
                .and_then(|t| parse_spool_header(&id, t, now))
                .unwrap_or_else(|| QueueMsgInfo {
                    id: id.clone(),
                    sender: String::new(),
                    bounce: false,
                    recipients: Vec::new(),
                    subject: String::new(),
                    spam_score: None,
                    frozen: false,
                    age_secs: std::fs::metadata(&path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    size: 0,
                    parsed: false,
                });
            info.size = dsize.get(&info.id).copied().unwrap_or(0);
            info
        })
        .collect();
    msgs.sort_by_key(|m| std::cmp::Reverse(m.age_secs));
    let truncated = msgs.len() > cap;
    msgs.truncate(cap);
    QueueListing {
        total,
        truncated,
        msgs,
    }
}

/// Decode RFC 2047 encoded words (`=?charset?Q?…?=` / `=?charset?B?…?=`) for
/// display. Unknown or malformed tokens are left as-is; charsets are treated
/// as UTF-8 (lossy) which covers the overwhelmingly common utf-8/iso-8859-1
/// spam subjects well enough for a queue listing.
pub fn decode_rfc2047(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("=?") {
        out.push_str(&rest[..start]);
        let token = &rest[start..];
        // =?charset?E?payload?=
        let mut parts = token[2..].splitn(3, '?');
        let (Some(_cs), Some(enc), Some(tail)) = (parts.next(), parts.next(), parts.next()) else {
            out.push_str("=?");
            rest = &token[2..];
            continue;
        };
        let Some(end) = tail.find("?=") else {
            out.push_str("=?");
            rest = &token[2..];
            continue;
        };
        let payload = &tail[..end];
        let decoded: Option<Vec<u8>> = match enc.to_ascii_uppercase().as_str() {
            "Q" => Some(decode_q(payload)),
            "B" => decode_base64(payload),
            _ => None,
        };
        match decoded {
            Some(bytes) => out.push_str(&String::from_utf8_lossy(&bytes)),
            None => out.push_str(&token[..2 + (token[2..].len() - tail.len()) + end + 2]),
        }
        // advance past "=?cs?E?payload?="
        let consumed = 2 + (token[2..].len() - tail.len()) + end + 2;
        rest = &token[consumed..];
        // RFC 2047: whitespace between adjacent encoded words is dropped
        if rest.trim_start().starts_with("=?") {
            rest = rest.trim_start();
        }
    }
    out.push_str(rest);
    out
}

fn decode_q(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'_' => out.push(b' '),
            b'=' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 2;
                } else {
                    out.push(b'=');
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    out
}

fn decode_base64(s: &str) -> Option<Vec<u8>> {
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
    let clean: Vec<u8> = s.bytes().filter(|&c| c != b'=' && c != b'\n').collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut acc: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            acc |= (val(c)? as u32) << (18 - 6 * i);
        }
        let bytes = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        out.extend_from_slice(&bytes[..chunk.len() - 1]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exim writes each header as `NNN{flag} text\n` where NNN counts the text
    /// bytes including the trailing newline — compute it, don't hand-count.
    fn hline(flag: char, text: &str) -> String {
        format!("{:03}{} {}\n", text.len() + 1, flag, text)
    }

    /// Modelled on a real Exim 4.99 spool file from the live server (spam with
    /// null sender, cPanel SA score, aclm vars, encoded subject).
    fn sample() -> String {
        concat!(
            "1woYPl-0000000B09r-3Wiu-H\n",
            "mailnull 47 12\n",
            "<>\n",
            "1785209012 0\n",
            "-received_time_usec .593260\n",
            "--helo_name [10.88.0.3]\n",
            "-host_address [34.62.217.144]:45748\n",
            "-received_protocol esmtp\n",
            "-aclm 1 8\n",
            "tranyhdd\n",
            "-aclm 0 14\n",
            "-looks-dashed\n",
            "-body_linecount 153\n",
            "-deliver_firsttime\n",
            "-spam_bar ++++++++++++++++\n",
            "-spam_score 16.4\n",
            "-spam_score_int 164\n",
            "-tls_resumption A\n",
            "XX\n",
            "1\n",
            "info@taxivalledaosta.com\n",
            "\n",
        )
        .to_string()
            + &hline(' ', "Subject: =?utf-8?q?E-mail_Account_Verification_ok?=")
            + &hline('F', "From: Spammer <s@bad.example>")
    }

    #[test]
    fn parses_live_style_spool_header() {
        let m = parse_spool_header("1woYPl-0000000B09r-3Wiu", &sample(), 1785219012).unwrap();
        assert!(m.bounce);
        assert_eq!(m.sender, "");
        assert_eq!(m.recipients, ["info@taxivalledaosta.com"]);
        assert_eq!(m.spam_score, Some(16.4));
        assert!(!m.frozen);
        assert_eq!(m.age_secs, 10_000);
        // encoded word decoded, aclm value with a leading dash didn't derail parsing
        assert_eq!(m.subject, "E-mail Account Verification ok");
        assert!(m.parsed);
    }

    #[test]
    fn frozen_flag_and_plain_sender() {
        let text = sample()
            .replace("<>\n", "<real@sender.example>\n")
            .replace("-deliver_firsttime\n", "-frozen 1785209100\n");
        let m = parse_spool_header("1woYPl-0000000B09r-3Wiu", &text, 1785219012).unwrap();
        assert!(!m.bounce);
        assert_eq!(m.sender, "real@sender.example");
        assert!(m.frozen);
    }

    #[test]
    fn spam_status_header_fallback() {
        let text = sample().replace("-spam_score 16.4\n", "").replace(
            &hline(' ', "Subject: =?utf-8?q?E-mail_Account_Verification_ok?="),
            &hline(' ', "X-Spam-Status: Yes, score=12.8"),
        );
        let m = parse_spool_header("1woYPl-0000000B09r-3Wiu", &text, 1785219012).unwrap();
        assert_eq!(m.spam_score, Some(12.8));
    }

    #[test]
    fn garbage_yields_none() {
        assert!(parse_spool_header("someid", "not a spool file\n", 0).is_none());
        assert!(parse_spool_header("someid", "", 0).is_none());
        // wrong id on line 1
        assert!(parse_spool_header("otherid", &sample(), 0).is_none());
    }

    #[test]
    fn decodes_rfc2047_q_and_b() {
        assert_eq!(decode_rfc2047("=?utf-8?q?Hello_World?="), "Hello World");
        assert_eq!(decode_rfc2047("=?UTF-8?B?SGVsbG8=?="), "Hello");
        assert_eq!(decode_rfc2047("plain subject"), "plain subject");
        // adjacent encoded words: separating whitespace dropped
        assert_eq!(decode_rfc2047("=?utf-8?q?a?= =?utf-8?q?b?="), "ab");
        // malformed stays visible
        assert_eq!(decode_rfc2047("=?utf-8?q?broken"), "=?utf-8?q?broken");
    }

    #[test]
    fn lists_fake_split_spool() {
        let d = std::env::temp_dir().join(format!("msfe-qv-{}", std::process::id()));
        let sub = d.join("Y");
        std::fs::create_dir_all(&sub).unwrap();
        // valid pair in a split subdir
        std::fs::write(sub.join("1woYPl-0000000B09r-3Wiu-H"), sample()).unwrap();
        std::fs::write(
            sub.join("1woYPl-0000000B09r-3Wiu-D"),
            b"1woYPl-0000000B09r-3Wiu-D\nbody",
        )
        .unwrap();
        // unparsable header at top level → metadata-only row
        std::fs::write(d.join("1woXXX-0000000B09r-0Bad-H"), b"garbage\n").unwrap();
        let l = list_queue(&d, 10);
        assert_eq!(l.total, 2);
        assert!(!l.truncated);
        let good = l.msgs.iter().find(|m| m.id.ends_with("3Wiu")).unwrap();
        assert!(good.parsed);
        assert_eq!(good.size, 30); // -D file byte length
        let bad = l.msgs.iter().find(|m| m.id.ends_with("0Bad")).unwrap();
        assert!(!bad.parsed);
        // cap smaller than total → truncated
        let l2 = list_queue(&d, 1);
        assert_eq!(l2.total, 2);
        assert!(l2.truncated);
        assert_eq!(l2.msgs.len(), 1);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
