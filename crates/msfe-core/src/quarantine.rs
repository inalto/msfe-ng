//! Locating, viewing and releasing quarantined messages.
//!
//! MailScanner stores held messages under a dated tree
//! (`<base>/<YYYYMMDD>/<message-id>/…`). We locate a message by id (validated to
//! a safe charset so it can never escape `base`), read its raw bytes for the
//! viewer, and re-inject it via `sendmail -t` on release. The filesystem/MTA
//! parts only do real work on a live mail host; the path logic is unit-tested.

use std::io;
use std::path::{Path, PathBuf};

/// MailScanner message ids look like `1abcDe-0001Yz-2B`. Restrict to a charset
/// that cannot contain path separators or `..`.
pub fn valid_message_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Find a quarantined message directory or file by id, searching `base` up to a
/// few levels deep (dated subdirs). Returns the first match.
pub fn find_message(base: &Path, message_id: &str) -> Option<PathBuf> {
    if !valid_message_id(message_id) {
        return None;
    }
    find_rec(base, message_id, 0)
}

/// Does `name` identify this message? MailScanner stores a body as a single
/// file/dir named `<id>` (quarantine) or as an Exim spool *pair* `<id>-D`
/// (body) and `<id>-H` (headers) when archiving. `<id>.<ext>` is also accepted.
fn id_match(name: &str, id: &str) -> bool {
    name == id
        || name == format!("{id}-D")
        || name == format!("{id}-H")
        || name.starts_with(&format!("{id}."))
}

fn find_rec(dir: &Path, id: &str, depth: usize) -> Option<PathBuf> {
    if depth > 3 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    let mut hit: Option<PathBuf> = None;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if id_match(&name, id) {
            // Prefer the `-D` body file when a spool pair is present.
            if name.ends_with("-D") {
                return Some(e.path());
            }
            hit.get_or_insert_with(|| e.path());
        } else if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            subdirs.push(e.path());
        }
    }
    if let Some(h) = hit {
        return Some(h);
    }
    for sd in subdirs {
        if let Some(h) = find_rec(&sd, id, depth + 1) {
            return Some(h);
        }
    }
    None
}

/// Directories a message body may legitimately live under: the quarantine
/// spool and, when archiving is on, the archive tree.
pub fn body_roots(cfg: &crate::Config) -> Vec<PathBuf> {
    let mut roots = vec![PathBuf::from(&cfg.quarantine_dir)];
    if !cfg.archive_dir.trim().is_empty() {
        roots.push(PathBuf::from(&cfg.archive_dir));
    }
    roots
}

/// Resolve a message body. Prefers the path MailScanner reported (recorded in
/// `maillog.body_path`), falling back to the legacy recursive scan for rows
/// logged before that column existed.
///
/// The stored path is trusted only after validation: it must sit under one of
/// the configured roots and be named after the message id. A poisoned database
/// value must never turn the raw-message endpoint into an arbitrary-file read.
pub fn resolve_body(cfg: &crate::Config, message_id: &str, stored: &str) -> Option<PathBuf> {
    if !valid_message_id(message_id) {
        return None;
    }
    let roots = body_roots(cfg);
    let stored = stored.trim();
    if !stored.is_empty() {
        let p = Path::new(stored);
        let named_for_id = p
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| id_match(n, message_id))
            .unwrap_or(false);
        let under_root = roots.iter().any(|r| p.starts_with(r));
        // `..` can only appear in a hand-edited value; reject rather than resolve
        let traversal = p.components().any(|c| c == std::path::Component::ParentDir);
        if named_for_id && under_root && !traversal && p.exists() {
            return Some(p.to_path_buf());
        }
    }
    roots.iter().find_map(|r| find_message(r, message_id))
}

/// True when the message still has a body on disk (the only honest basis for
/// offering View source / release / Bayes training in the UI).
pub fn body_exists(cfg: &crate::Config, message_id: &str, stored: &str) -> bool {
    resolve_body(cfg, message_id, stored).is_some()
}

/// Which tree a resolved body came from, for display ("quarantine"/"archive").
pub fn body_kind(cfg: &crate::Config, path: &Path) -> &'static str {
    if path.starts_with(&cfg.quarantine_dir) {
        "quarantine"
    } else if !cfg.archive_dir.trim().is_empty() && path.starts_with(&cfg.archive_dir) {
        "archive"
    } else {
        "unknown"
    }
}

/// True for an Exim spool data file (`<id>-D`), whose first line repeats the id
/// and whose remainder is the raw message body.
fn is_exim_data(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with("-D"))
        .unwrap_or(false)
}

/// Read the raw message bytes. Handles the three shapes MailScanner produces:
/// a single file, a directory (first file inside), and an Exim spool `-D` data
/// file (the leading id line is stripped, leaving the body).
pub fn read_message(path: &Path) -> io::Result<Vec<u8>> {
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();
        let pick = files
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "empty quarantine dir"))?;
        return read_message(&pick);
    }
    let bytes = std::fs::read(path)?;
    if is_exim_data(path) {
        // drop the first line ("<id>-D\n"); the rest is the body
        if let Some(nl) = bytes.iter().position(|&b| b == b'\n') {
            return Ok(bytes[nl + 1..].to_vec());
        }
    }
    Ok(bytes)
}

/// A readable RFC822 message for viewing or re-sending. For an Exim `-D` body
/// (which carries no headers), the logged `headers` are prepended so "view
/// source" and release produce a complete message; other formats are returned
/// as-is.
pub fn read_rfc822(path: &Path, logged_headers: &str) -> io::Result<Vec<u8>> {
    let body = read_message(path)?;
    if is_exim_data(path) && !logged_headers.trim().is_empty() {
        let mut out = logged_headers.trim_end().as_bytes().to_vec();
        out.extend_from_slice(b"\n\n");
        out.extend_from_slice(&body);
        return Ok(out);
    }
    Ok(body)
}

/// Rewrite a message for forwarding: optionally replace `Subject:`/`From:` and
/// prepend an intro line to the body. Empty overrides keep the original. Splits
/// headers from body at the first blank line.
pub fn rewrite_for_forward(bytes: &[u8], subject: &str, from: &str, body_prefix: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    // find the header/body separator (blank line)
    let sep = text
        .find("\r\n\r\n")
        .map(|i| (i, 4))
        .or_else(|| text.find("\n\n").map(|i| (i, 2)));
    let (mut headers, body) = match sep {
        Some((i, w)) => (text[..i].to_string(), text[i + w..].to_string()),
        None => (text.to_string(), String::new()),
    };
    let set_header = |h: &mut String, name: &str, val: &str| {
        if val.is_empty() {
            return;
        }
        let mut out = Vec::new();
        let mut replaced = false;
        for line in h.lines() {
            if line
                .to_ascii_lowercase()
                .starts_with(&format!("{}:", name.to_ascii_lowercase()))
            {
                out.push(format!("{name}: {val}"));
                replaced = true;
            } else {
                out.push(line.to_string());
            }
        }
        if !replaced {
            out.push(format!("{name}: {val}"));
        }
        *h = out.join("\n");
    };
    set_header(&mut headers, "Subject", subject);
    set_header(&mut headers, "From", from);
    let mut out = headers.into_bytes();
    out.extend_from_slice(b"\n\n");
    if !body_prefix.is_empty() {
        out.extend_from_slice(body_prefix.as_bytes());
        out.extend_from_slice(b"\n\n");
    }
    out.extend_from_slice(body.as_bytes());
    out
}

/// Deliver a message straight into a local account's mailbox via the LDA
/// (dovecot-lda), the legacy "Release (direct)". The recipient must be a valid
/// address; the caller is responsible for confirming it is a local account.
pub fn deliver_inbox(bytes: &[u8], lda: &str, account: &str) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if !valid_recipient(account) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad account"));
    }
    let mut child = Command::new(lda)
        .args(["-d", account])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("stdin piped").write_all(bytes)?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("local delivery (dovecot-lda) failed"))
    }
}

/// Send an already-assembled RFC822 message: to its own recipients (`to` None)
/// or to an explicit address (`to` Some). Shared by every release path so an
/// Exim `-D` body reconstructed with its headers is what actually goes out.
pub fn send_message(bytes: &[u8], to: Option<&str>) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("sendmail");
    match to {
        Some(addr) => {
            if !valid_recipient(addr) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad recipient"));
            }
            cmd.arg("--").arg(addr);
        }
        None => {
            cmd.arg("-t");
        }
    }
    let mut child = cmd.stdin(Stdio::piped()).spawn()?;
    child.stdin.take().expect("stdin piped").write_all(bytes)?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("sendmail failed"))
    }
}

/// Re-inject a released message into the MTA via `sendmail -t`.
pub fn release(path: &Path) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let bytes = read_message(path)?;
    let mut child = Command::new("sendmail")
        .arg("-t")
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("stdin piped").write_all(&bytes)?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("sendmail failed"))
    }
}

/// Forward a quarantined message to an explicit recipient (envelope-to that
/// address, original message unchanged) — the legacy "Release (forward)".
pub fn release_to(path: &Path, recipient: &str) -> io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    if !valid_recipient(recipient) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad recipient"));
    }
    let bytes = read_message(path)?;
    let mut child = Command::new("sendmail")
        .arg("--")
        .arg(recipient)
        .stdin(Stdio::piped())
        .spawn()?;
    child.stdin.take().expect("stdin piped").write_all(&bytes)?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err(io::Error::other("sendmail failed"))
    }
}

/// A single safe email address (no spaces, no option injection).
pub fn valid_recipient(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 254
        && !s.starts_with('-')
        && s.contains('@')
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-' | b'+' | b'=')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_rewrite_replaces_headers_and_prepends_body() {
        let msg = b"Subject: Original
From: spammer@bad.example
To: me@x.com

body line
";
        let out = rewrite_for_forward(
            msg,
            "Fwd: caught spam",
            "postmaster@x.com",
            "Released by admin",
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Subject: Fwd: caught spam"));
        assert!(text.contains("From: postmaster@x.com"));
        assert!(!text.contains("Subject: Original"));
        assert!(text.contains("To: me@x.com")); // untouched header kept
                                                // intro line precedes the original body
        let b = text.split("\n\n").collect::<Vec<_>>();
        assert_eq!(b[1], "Released by admin");
        assert!(text.trim_end().ends_with("body line"));
        // empty overrides keep the originals
        let keep = String::from_utf8(rewrite_for_forward(msg, "", "", "")).unwrap();
        assert!(keep.contains("Subject: Original"));
        assert!(keep.contains("From: spammer@bad.example"));
    }

    #[test]
    fn reads_exim_spool_pair_as_full_message() {
        let base = std::env::temp_dir().join(format!("msfe-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let day = base.join("archive").join("20260726");
        std::fs::create_dir_all(&day).unwrap();
        let id = "1wnyXN-00000007fSr-0Vds";
        // MailScanner archives an Exim spool pair: <id>-D (body) and <id>-H
        std::fs::write(
            day.join(format!("{id}-D")),
            format!(
                "{id}-D
Hello world body
"
            ),
        )
        .unwrap();
        std::fs::write(
            day.join(format!("{id}-H")),
            "exim header spool junk
",
        )
        .unwrap();
        let cfg = crate::Config {
            quarantine_dir: base.join("q").display().to_string(),
            archive_dir: base.join("archive").display().to_string(),
            ..Default::default()
        };
        // resolution prefers the -D file
        let p = resolve_body(&cfg, id, "").unwrap();
        assert!(p.to_string_lossy().ends_with("-D"));
        // read_message strips the leading id line, leaving the body
        assert_eq!(
            read_message(&p).unwrap(),
            b"Hello world body
"
        );
        // read_rfc822 prepends the logged headers to make a full message
        let full = read_rfc822(
            &p,
            "Subject: Hi
From: a@b",
        )
        .unwrap();
        assert_eq!(
            full,
            b"Subject: Hi
From: a@b

Hello world body
"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn resolves_bodies_by_stored_path_with_scan_fallback() {
        let base = std::env::temp_dir().join(format!("msfe-body-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (qdir, adir) = (base.join("quarantine"), base.join("archive"));
        std::fs::create_dir_all(qdir.join("20260725")).unwrap();
        std::fs::create_dir_all(adir.join("20260725")).unwrap();
        let id = "1wnE6V-00000004Oi2-3lJH";
        let archived = adir.join("20260725").join(id);
        std::fs::write(&archived, b"archived body").unwrap();
        let cfg = crate::Config {
            quarantine_dir: qdir.display().to_string(),
            archive_dir: adir.display().to_string(),
            ..Default::default()
        };

        // stored path is used as-is
        assert_eq!(
            resolve_body(&cfg, id, archived.to_str().unwrap()),
            Some(archived.clone())
        );
        assert!(body_exists(&cfg, id, archived.to_str().unwrap()));
        assert_eq!(body_kind(&cfg, &archived), "archive");

        // A poisoned stored path must never be read. Use an id with no body of
        // its own, so nothing masks the rejection via the fallback scan.
        let ghost = "1ghost-00000000AAA-0aaa";
        let outside = base.join("passwd");
        std::fs::write(&outside, b"secret").unwrap();
        assert_eq!(resolve_body(&cfg, ghost, outside.to_str().unwrap()), None);
        // traversal out of a root is refused too
        let sneaky = adir.join("20260725").join("..").join("..").join("passwd");
        assert_eq!(resolve_body(&cfg, ghost, sneaky.to_str().unwrap()), None);
        // a path belonging to a different message is not accepted for this id
        assert_eq!(resolve_body(&cfg, ghost, archived.to_str().unwrap()), None);
        // rejecting a bad stored path still falls back to this id's real body
        assert_eq!(
            resolve_body(&cfg, id, outside.to_str().unwrap()),
            Some(archived.clone())
        );

        // legacy row (no stored path): the scan still finds a quarantined body
        let qid = "1wnLIy-00000004OtQ-1CTr";
        let quarantined = qdir.join("20260725").join(qid);
        std::fs::write(&quarantined, b"quarantined body").unwrap();
        assert_eq!(resolve_body(&cfg, qid, ""), Some(quarantined.clone()));
        assert_eq!(body_kind(&cfg, &quarantined), "quarantine");

        // gone from disk → no body, whatever the database says
        std::fs::remove_file(&archived).unwrap();
        assert!(!body_exists(&cfg, id, archived.to_str().unwrap()));

        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recipient_validation() {
        assert!(valid_recipient("user@example.com"));
        assert!(valid_recipient("a.b+tag@ex-ample.co"));
        assert!(!valid_recipient("-oQ/tmp@x.com"));
        assert!(!valid_recipient("two words@x.com"));
        assert!(!valid_recipient("noat.example.com"));
        assert!(!valid_recipient(""));
    }

    #[test]
    fn id_validation() {
        assert!(valid_message_id("1abcDe-0001Yz-2B"));
        assert!(!valid_message_id("../../etc/passwd"));
        assert!(!valid_message_id("a/b"));
        assert!(!valid_message_id(""));
    }

    #[test]
    fn finds_dated_message() {
        let base = std::env::temp_dir().join(format!("msfe-q-{}", std::process::id()));
        let dated = base.join("20260721").join("1abcDe-0001Yz-2B");
        std::fs::create_dir_all(&dated).unwrap();
        std::fs::write(dated.join("message"), b"raw").unwrap();
        let hit = find_message(&base, "1abcDe-0001Yz-2B").unwrap();
        assert!(hit.ends_with("1abcDe-0001Yz-2B"));
        assert_eq!(read_message(&hit).unwrap(), b"raw");
        // traversal attempt returns nothing
        assert!(find_message(&base, "../../etc").is_none());
        std::fs::remove_dir_all(&base).ok();
    }
}
