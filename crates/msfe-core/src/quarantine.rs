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

#[cfg(test)]
mod tests {
    use super::*;

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
