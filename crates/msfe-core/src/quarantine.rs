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
        // a quarantine dir may hold only a removed attachment (a name-blocked
        // message with `Quarantine Whole Message = no`): no message there —
        // the archive copy is the one to show
        if named_for_id && under_root && !traversal && p.exists() && holds_message(p) {
            return Some(p.to_path_buf());
        }
    }
    roots
        .iter()
        .filter_map(|r| find_message(r, message_id))
        .find(|p| holds_message(p))
}

/// Does this path give us a message? A file named for the id is one by
/// MailScanner's own naming; a directory must contain one (it may hold only
/// a removed attachment).
fn holds_message(p: &Path) -> bool {
    !p.is_dir() || message_file_in(p).is_some()
}

/// The message inside a MailScanner quarantine/archive directory: the Exim
/// `-D` data file, a file named `message`, an `.eml`, or the first file that
/// starts like RFC822 mail. `None` when the directory only holds removed
/// attachments.
fn message_file_in(dir: &Path) -> Option<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let name = |p: &PathBuf| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    };
    files
        .iter()
        .find(|p| name(p).ends_with("-D"))
        .or_else(|| files.iter().find(|p| name(p) == "message"))
        .or_else(|| files.iter().find(|p| name(p).ends_with(".eml")))
        .or_else(|| files.iter().find(|p| looks_like_message(p)))
        .cloned()
}

/// Do the first bytes read like a mail message (a header line, an mbox
/// `From ` line, or an Exim `-D` id line)?
fn looks_like_message(p: &Path) -> bool {
    use std::io::Read;
    if is_exim_data(p) {
        return true;
    }
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut buf = [0u8; 512];
    let n = f.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let first = head.lines().next().unwrap_or("").trim_end();
    first.starts_with("From ")
        || first.split_once(':').is_some_and(|(k, v)| {
            !k.is_empty()
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (v.starts_with(' ') || v.is_empty() || v.starts_with('\t'))
        })
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
        let pick = message_file_in(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no message in the quarantine directory — only removed attachments",
            )
        })?;
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

// ---- admin quarantine browser + purge -----------------------------------------

/// One item in the on-disk quarantine: a spam copy (`<date>/spam/<id>`) or a
/// held message (`<date>/<id>` file or directory).
pub struct QuarantineEntry {
    pub date: String,
    pub id: String,
    pub kind: &'static str,
    pub size: u64,
    pub mtime: u64,
}

pub struct QuarantineListing {
    /// Items matching the filter (all of them, not just the capped page).
    pub total: usize,
    pub bytes: u64,
    /// Everything found on disk, filter or not.
    pub disk_total: usize,
    pub disk_bytes: u64,
    pub truncated: bool,
    pub entries: Vec<QuarantineEntry>,
}

/// What a listing keeps. Dates are `YYYYMMDD`, inclusive. When either
/// `id_contains` or `ids` is set, an entry must satisfy one of them: its id
/// holds the text (case-insensitive) or is in the set (ids the message log
/// matched on sender, recipient or subject).
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    pub kind: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub id_contains: Option<String>,
    pub ids: Option<std::collections::HashSet<String>>,
}

impl ListFilter {
    fn is_empty(&self) -> bool {
        self.kind.is_none()
            && self.from.is_none()
            && self.to.is_none()
            && self.id_contains.is_none()
            && self.ids.is_none()
    }
    fn date_ok(&self, date: &str) -> bool {
        self.from.as_deref().map_or(true, |f| date >= f)
            && self.to.as_deref().map_or(true, |t| date <= t)
    }
    fn keep(&self, e: &QuarantineEntry) -> bool {
        if self.kind.as_deref().is_some_and(|k| k != e.kind) {
            return false;
        }
        if !self.date_ok(&e.date) {
            return false;
        }
        match (&self.id_contains, &self.ids) {
            (None, None) => true,
            (needle, set) => {
                needle.as_deref().is_some_and(|n| {
                    !n.is_empty() && e.id.to_ascii_lowercase().contains(&n.to_ascii_lowercase())
                }) || set.as_ref().is_some_and(|s| s.contains(&e.id))
            }
        }
    }
}

pub struct PurgeReport {
    pub removed: usize,
    pub bytes: u64,
    pub errors: Vec<String>,
}

/// What is actually in the quarantine directory, newest date first, capped at
/// `cap` entries (`total`/`bytes` always reflect everything found). The disk
/// is the source of truth here: files the DB never logged still appear.
pub fn list_quarantine(base: &Path, cap: usize) -> QuarantineListing {
    list_quarantine_where(base, cap, &ListFilter::default())
}

/// `list_quarantine` keeping only what `filter` accepts; the cap applies to
/// the matches, so a search reaches the whole quarantine. `disk_total` and
/// `disk_bytes` still describe everything found.
pub fn list_quarantine_where(base: &Path, cap: usize, filter: &ListFilter) -> QuarantineListing {
    let mut entries: Vec<QuarantineEntry> = Vec::new();
    let (mut disk_total, mut disk_bytes) = (0usize, 0u64);
    let mut push = |e: QuarantineEntry| {
        disk_total += 1;
        disk_bytes += e.size;
        if filter.is_empty() || filter.keep(&e) {
            entries.push(e);
        }
    };
    for date in date_dirs(base) {
        let ddir = base.join(&date);
        let Ok(rd) = std::fs::read_dir(&ddir) else {
            continue;
        };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if name == "spam" && is_dir {
                if let Ok(sd) = std::fs::read_dir(e.path()) {
                    for s in sd.flatten() {
                        push(entry_for(
                            &date,
                            &s.file_name().to_string_lossy(),
                            "spam",
                            &s.path(),
                        ));
                    }
                }
            } else {
                push(entry_for(&date, &name, "held", &e.path()));
            }
        }
    }
    // newest first, stable within a date
    entries.sort_by(|a, b| b.date.cmp(&a.date).then(a.id.cmp(&b.id)));
    let total = entries.len();
    let bytes = entries.iter().map(|e| e.size).sum();
    let truncated = total > cap;
    entries.truncate(cap);
    QuarantineListing {
        total,
        bytes,
        disk_total,
        disk_bytes,
        truncated,
        entries,
    }
}

/// A `YYYYMMDD` date for the listing filter from user input: `YYYYMMDD` or
/// `YYYY-MM-DD`; anything else is `None`.
pub fn filter_date(s: &str) -> Option<String> {
    let d: String = s.trim().chars().filter(|c| *c != '-').collect();
    (d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit())).then_some(d)
}

/// `YYYYMMDD`-named subdirectories of the quarantine root.
fn date_dirs(base: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    rd.flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.len() == 8 && n.bytes().all(|b| b.is_ascii_digit()))
        .collect()
}

fn entry_for(date: &str, id: &str, kind: &'static str, path: &Path) -> QuarantineEntry {
    QuarantineEntry {
        date: date.to_string(),
        id: id.to_string(),
        kind,
        size: size_of(path),
        mtime: std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0),
    }
}

/// File size, or the recursive size of a held-message directory.
fn size_of(path: &Path) -> u64 {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => m.len(),
        Ok(m) if m.is_dir() => std::fs::read_dir(path)
            .map(|rd| rd.flatten().map(|e| size_of(&e.path())).sum())
            .unwrap_or(0),
        _ => 0,
    }
}

/// A (date, id) purge address is sound: a real date-dir name and a plain
/// entry name with no path tricks.
fn valid_purge_pair(date: &str, id: &str) -> bool {
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && !id.is_empty()
        && id.len() <= 128
        && !id.contains('/')
        && !id.contains("..")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'%'))
}

/// Delete specific quarantine items, each addressed as a (date, id) pair —
/// never a path, so nothing can escape the quarantine root. Invalid pairs are
/// reported, not silently skipped. `dry` counts without deleting.
/// Resolve a validated (date, id) pair to its on-disk location under `base`
/// (spam copy first, then held entry). None when the pair is malformed or the
/// item is gone — the only way callers may address quarantine content.
pub fn item_path(base: &Path, date: &str, id: &str) -> Option<std::path::PathBuf> {
    if !valid_purge_pair(date, id) {
        return None;
    }
    [
        base.join(date).join("spam").join(id),
        base.join(date).join(id),
    ]
    .into_iter()
    .find(|p| p.exists())
}

pub fn purge_items(base: &Path, items: &[(String, String)], dry: bool) -> PurgeReport {
    let mut removed = 0usize;
    let mut bytes = 0u64;
    let mut errors = Vec::new();
    for (date, id) in items {
        if !valid_purge_pair(date, id) {
            errors.push(format!("invalid item '{date}/{id}' — skipped"));
            continue;
        }
        let Some(path) = item_path(base, date, id) else {
            errors.push(format!("{date}/{id}: not found"));
            continue;
        };
        let sz = size_of(&path);
        if !dry {
            let res = if path.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            if let Err(e) = res {
                errors.push(format!("{date}/{id}: {e}"));
                continue;
            }
            // tidy now-empty spam/ and date dirs (best-effort)
            let _ = std::fs::remove_dir(base.join(date).join("spam"));
            let _ = std::fs::remove_dir(base.join(date));
        }
        removed += 1;
        bytes += sz;
    }
    PurgeReport {
        removed,
        bytes,
        errors,
    }
}

/// Delete whole date directories strictly older than `cutoff` (a `YYYYMMDD`
/// string — the format sorts lexicographically). The date dir is the natural
/// purge unit; the dir exactly at the cutoff survives.
pub fn purge_older_than(base: &Path, cutoff: &str, dry: bool) -> PurgeReport {
    let mut removed = 0usize;
    let mut bytes = 0u64;
    let mut errors = Vec::new();
    for date in date_dirs(base) {
        if date.as_str() >= cutoff {
            continue; // YYYYMMDD sorts lexicographically
        }
        let ddir = base.join(&date);
        // count entries the way the listing does, so preview and purge agree
        let in_dir = list_quarantine_date(&ddir, &date);
        if !dry {
            if let Err(e) = std::fs::remove_dir_all(&ddir) {
                errors.push(format!("{date}: {e}"));
                continue;
            }
        }
        removed += in_dir.0;
        bytes += in_dir.1;
    }
    PurgeReport {
        removed,
        bytes,
        errors,
    }
}

/// (entries, bytes) inside one date dir, counted like `list_quarantine`.
fn list_quarantine_date(ddir: &Path, _date: &str) -> (usize, u64) {
    let mut n = 0usize;
    let mut b = 0u64;
    if let Ok(rd) = std::fs::read_dir(ddir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if name == "spam" && is_dir {
                if let Ok(sd) = std::fs::read_dir(e.path()) {
                    for s in sd.flatten() {
                        n += 1;
                        b += size_of(&s.path());
                    }
                }
            } else {
                n += 1;
                b += size_of(&e.path());
            }
        }
    }
    (n, b)
}

/// Today minus `days`, as `YYYYMMDD`, via GNU date (EL9/cPanel — same pattern
/// as the monitor's burst window).
pub fn cutoff_days_ago(days: u32) -> Option<String> {
    let out = std::process::Command::new("date")
        .args(["-d", &format!("{days} days ago"), "+%Y%m%d"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture matching production layouts: `<date>/spam/<id>` flat files and
    /// `<date>/<id>/message` held dirs, plus junk that must be ignored.
    fn fixture(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("msfe-quar-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("20260801/spam")).unwrap();
        std::fs::write(
            base.join("20260801/spam/1waaaa-000000000001-aaaa"),
            b"old spam",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("20260804/spam")).unwrap();
        std::fs::write(
            base.join("20260804/spam/1wbbbb-000000000002-bbbb"),
            b"spam!",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("20260804/1wcccc-000000000003-cccc")).unwrap();
        std::fs::write(
            base.join("20260804/1wcccc-000000000003-cccc/message"),
            b"held message body",
        )
        .unwrap();
        std::fs::create_dir_all(base.join("not-a-date")).unwrap();
        std::fs::write(base.join("not-a-date/junk"), b"ignored").unwrap();
        base
    }

    #[test]
    fn lists_both_layouts_newest_first_and_ignores_junk() {
        let base = fixture("list");
        let l = list_quarantine(&base, 100);
        assert_eq!(l.total, 3);
        assert!(!l.truncated);
        assert_eq!(l.bytes, 8 + 5 + 17);
        let keys: Vec<(String, String, &str)> = l
            .entries
            .iter()
            .map(|e| (e.date.clone(), e.id.clone(), e.kind))
            .collect();
        assert_eq!(keys[0].0, "20260804", "newest date first");
        assert!(keys.contains(&("20260804".into(), "1wcccc-000000000003-cccc".into(), "held")));
        assert!(keys.contains(&("20260801".into(), "1waaaa-000000000001-aaaa".into(), "spam")));
        // cap: totals stay true while entries truncate
        let capped = list_quarantine(&base, 1);
        assert_eq!(capped.total, 3);
        assert!(capped.truncated);
        assert_eq!(capped.entries.len(), 1);
        assert_eq!((capped.disk_total, capped.disk_bytes), (3, 30));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn filtered_listing_searches_the_whole_quarantine() {
        let base = fixture("filter");
        let by = |f: ListFilter| list_quarantine_where(&base, 1, &f);
        // kind + the cap on the matches, not on the disk
        let spam = by(ListFilter {
            kind: Some("spam".into()),
            ..Default::default()
        });
        assert_eq!((spam.total, spam.bytes, spam.disk_total), (2, 13, 3));
        assert!(spam.truncated && spam.entries.len() == 1);
        // date window, inclusive
        let old = by(ListFilter {
            to: Some("20260801".into()),
            ..Default::default()
        });
        assert_eq!(old.total, 1);
        assert_eq!(old.entries[0].id, "1waaaa-000000000001-aaaa");
        let none = by(ListFilter {
            from: Some("20260805".into()),
            ..Default::default()
        });
        assert_eq!((none.total, none.disk_total), (0, 3));
        // id substring, case-insensitive
        let sub = by(ListFilter {
            id_contains: Some("CCCC".into()),
            ..Default::default()
        });
        assert_eq!(sub.total, 1);
        assert_eq!(sub.entries[0].kind, "held");
        // ids the message log matched, or the substring — either suffices
        let mut set = std::collections::HashSet::new();
        set.insert("1waaaa-000000000001-aaaa".to_string());
        let either = list_quarantine_where(
            &base,
            10,
            &ListFilter {
                id_contains: Some("bbbb".into()),
                ids: Some(set),
                ..Default::default()
            },
        );
        assert_eq!(either.total, 2);
        // an empty needle with an empty set matches nothing, not everything
        let nothing = by(ListFilter {
            id_contains: Some(String::new()),
            ids: Some(Default::default()),
            ..Default::default()
        });
        assert_eq!(nothing.total, 0);
        assert_eq!(filter_date("2026-08-04").as_deref(), Some("20260804"));
        assert_eq!(filter_date(" 20260804 ").as_deref(), Some("20260804"));
        assert_eq!(filter_date("2026-8-4"), None);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn purge_items_deletes_only_validated_pairs() {
        let base = fixture("purge");
        let items = vec![
            ("20260804".into(), "1wbbbb-000000000002-bbbb".into()),
            ("20260804".into(), "1wcccc-000000000003-cccc".into()),
            ("../../etc".into(), "passwd".into()),
            ("20260804".into(), "../spam".into()),
        ];
        let r = purge_items(&base, &items, false);
        assert_eq!(r.removed, 2);
        assert_eq!(r.bytes, 5 + 17);
        assert_eq!(r.errors.len(), 2, "traversal attempts are reported");
        assert!(!base.join("20260804/spam/1wbbbb-000000000002-bbbb").exists());
        assert!(!base.join("20260804/1wcccc-000000000003-cccc").exists());
        assert!(base.join("20260801/spam/1waaaa-000000000001-aaaa").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn purge_older_than_keeps_the_cutoff_date_and_honors_dry_run() {
        let base = fixture("older");
        let dry = purge_older_than(&base, "20260804", true);
        assert_eq!(dry.removed, 1, "only the 20260801 entry is older");
        assert_eq!(dry.bytes, 8);
        assert!(
            base.join("20260801/spam/1waaaa-000000000001-aaaa").exists(),
            "dry-run must not delete"
        );
        let real = purge_older_than(&base, "20260804", false);
        assert_eq!(real.removed, dry.removed);
        assert_eq!(real.bytes, dry.bytes);
        assert!(!base.join("20260801").exists());
        assert!(
            base.join("20260804").exists(),
            "the dir at the cutoff survives"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

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

    // A name-blocked message with `Quarantine Whole Message = no`: the
    // quarantine dir holds only the removed PDF; the archive has the message.
    #[test]
    fn attachment_only_quarantine_dir_falls_back_to_the_archive_copy() {
        let base = std::env::temp_dir().join(format!("msfe-qattach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let id = "1x8e1Y-0000000BTzz-1Bn6";
        let q = base.join("quarantine/20260921").join(id);
        let a = base.join("archive/20260921");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(q.join("2026-09-147 Ac.pdf"), b"%PDF-1.7\n\x00\x01 binary").unwrap();
        std::fs::write(a.join(format!("{id}-D")), format!("{id}-D\nhello body\n")).unwrap();
        std::fs::write(a.join(format!("{id}-H")), "headers").unwrap();
        let cfg = crate::Config {
            quarantine_dir: base.join("quarantine").display().to_string(),
            archive_dir: base.join("archive").display().to_string(),
            ..crate::Config::default()
        };
        // the stored path is the attachment-only dir: skipped for the archive
        let p = resolve_body(&cfg, id, &q.display().to_string()).expect("a body");
        assert_eq!(p, a.join(format!("{id}-D")));
        assert_eq!(read_message(&p).unwrap(), b"hello body\n");
        // reading the attachment-only dir directly is refused, not garbage
        assert!(read_message(&q).is_err());
        // a real quarantined message dir still wins
        std::fs::write(q.join("message"), "Received: from x\nSubject: hi\n\nbody\n").unwrap();
        let p = resolve_body(&cfg, id, &q.display().to_string()).expect("a body");
        assert_eq!(p, q);
        assert!(read_message(&p).unwrap().starts_with(b"Received:"));
        let _ = std::fs::remove_dir_all(&base);
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
