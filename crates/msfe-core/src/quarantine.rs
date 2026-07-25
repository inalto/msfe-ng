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

fn find_rec(dir: &Path, id: &str, depth: usize) -> Option<PathBuf> {
    if depth > 3 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name == id || name.starts_with(&format!("{id}.")) {
            return Some(e.path());
        }
        if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            subdirs.push(e.path());
        }
    }
    for sd in subdirs {
        if let Some(hit) = find_rec(&sd, id, depth + 1) {
            return Some(hit);
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
            .map(|n| n == message_id || n.starts_with(&format!("{message_id}.")))
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

/// Read the raw message bytes. If `path` is a directory (MailScanner keeps the
/// message next to metadata), prefer a file literally named after the id or the
/// first regular file inside.
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
        std::fs::read(pick)
    } else {
        std::fs::read(path)
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
