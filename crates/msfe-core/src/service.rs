//! MailScanner service operations: process status and control, mail-queue
//! inspection and repair, maillog tailing, ruleset/config file access, and an
//! on-demand release check.
//!
//! Everything here is root-only surface, exposed through the admin API and the
//! `msfe-ng service` CLI command. External commands follow the same
//! systemd-first / SysV-fallback pattern as `sync::reload_mailscanner`.

use crate::mailscanner;
use crate::Config;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// systemd unit / SysV service names for MailScanner.
const SYSTEMD_UNIT: &str = "mailscanner";
const SYSV_NAME: &str = "MailScanner";

/// Fallback queue locations for a cPanel split-spool MailScanner setup, used
/// when MailScanner.conf does not declare `Incoming/Outgoing Queue Dir`.
const DEFAULT_INCOMING_QUEUE: &str = "/var/spool/exim_incoming/input";
const DEFAULT_OUTGOING_QUEUE: &str = "/var/spool/exim/input";

/// A queue file pair missing its other half must be at least this old before
/// it is considered orphaned (Exim/MailScanner write -H and -D moments apart).
const ORPHAN_MIN_AGE_SECS: u64 = 600;

// ---- process status & control ------------------------------------------------

pub struct ServiceStatus {
    /// Service reported active by systemd (or SysV status as fallback).
    pub active: bool,
    /// Number of running MailScanner processes.
    pub procs: usize,
}

pub fn status() -> ServiceStatus {
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", SYSTEMD_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        || Command::new("service")
            .args([SYSV_NAME, "status"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    ServiceStatus {
        active,
        procs: count_processes(),
    }
}

/// Count running MailScanner processes by scanning /proc cmdlines.
fn count_processes() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter(|e| {
            std::fs::read(e.path().join("cmdline"))
                .map(|c| {
                    String::from_utf8_lossy(&c).contains("MailScanner")
                })
                .unwrap_or(false)
        })
        .count()
}

/// Run a service action (`start|stop|reload|restart`), systemd first then SysV.
/// Returns Err with the failing command's output for the API/CLI to surface.
pub fn control(action: &str) -> Result<(), String> {
    if !matches!(action, "start" | "stop" | "reload" | "restart") {
        return Err(format!("unknown action '{action}'"));
    }
    // Units without an ExecReload= still honor reload-or-restart.
    let sysd_verb = if action == "reload" {
        "reload-or-restart"
    } else {
        action
    };
    let sysd = Command::new("systemctl")
        .args([sysd_verb, SYSTEMD_UNIT])
        .output();
    if let Ok(o) = &sysd {
        if o.status.success() {
            return Ok(());
        }
    }
    let sysv = Command::new("service").args([SYSV_NAME, action]).output();
    match sysv {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(String::from_utf8_lossy(&o.stderr).trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

// ---- mail queues -------------------------------------------------------------

/// Incoming/outgoing Exim queue input dirs: MailScanner.conf directives when
/// present, cPanel split-spool defaults otherwise. Env overrides for tests.
pub fn queue_dirs(cfg: &Config) -> (PathBuf, PathBuf) {
    if let (Ok(i), Ok(o)) = (
        std::env::var("MSFE_NG_INCOMING_QUEUE"),
        std::env::var("MSFE_NG_OUTGOING_QUEUE"),
    ) {
        return (i.into(), o.into());
    }
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let dir = |key: &str, fallback: &str| -> PathBuf {
        mailscanner::get_directive(&conf, key)
            .filter(|v| !v.is_empty())
            .unwrap_or(fallback)
            .into()
    };
    (
        dir("Incoming Queue Dir", DEFAULT_INCOMING_QUEUE),
        dir("Outgoing Queue Dir", DEFAULT_OUTGOING_QUEUE),
    )
}

/// Count queued messages (`*-H` header files) in an Exim input dir, following
/// split-spool subdirectories one level down.
pub fn count_queue(dir: &Path) -> usize {
    queue_files(dir)
        .iter()
        .filter(|p| p.to_string_lossy().ends_with("-H"))
        .count()
}

/// All -H/-D files in an Exim input dir (flat or split-spool).
fn queue_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.filter_map(|e| e.ok()) {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() && name.len() == 1 {
            // split_spool_directory: single-character subdirs
            if let Ok(sub) = std::fs::read_dir(&p) {
                out.extend(sub.filter_map(|e| e.ok()).map(|e| e.path()));
            }
        } else {
            out.push(p);
        }
    }
    out.retain(|p| {
        let n = p.to_string_lossy();
        n.ends_with("-H") || n.ends_with("-D")
    });
    out
}

/// Queue files whose -H/-D partner is missing and that are older than
/// `min_age_secs` — stuck remnants that block or confuse queue runs.
pub fn find_orphans(dir: &Path, min_age_secs: u64) -> Vec<PathBuf> {
    use std::collections::HashMap;
    let files = queue_files(dir);
    let mut pairs: HashMap<String, (bool, bool)> = HashMap::new();
    for p in &files {
        let name = p.to_string_lossy().into_owned();
        let (id, is_h) = if let Some(s) = name.strip_suffix("-H") {
            (s.to_string(), true)
        } else if let Some(s) = name.strip_suffix("-D") {
            (s.to_string(), false)
        } else {
            continue;
        };
        let e = pairs.entry(id).or_insert((false, false));
        if is_h {
            e.0 = true;
        } else {
            e.1 = true;
        }
    }
    files
        .into_iter()
        .filter(|p| {
            let name = p.to_string_lossy().into_owned();
            let id = name
                .strip_suffix("-H")
                .or_else(|| name.strip_suffix("-D"))
                .unwrap_or(&name)
                .to_string();
            let Some((h, d)) = pairs.get(&id) else {
                return false;
            };
            (!h || !d) && older_than(p, min_age_secs)
        })
        .collect()
}

fn older_than(p: &Path, secs: u64) -> bool {
    if secs == 0 {
        return true;
    }
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() >= secs)
        .unwrap_or(false)
}

pub struct QueueFixReport {
    pub moved: usize,
    pub badqueue_dir: PathBuf,
    pub flush_started: bool,
}

/// Move orphaned queue files out of the way (into a sibling `msfe-ng-badqueue`
/// dir — never deleted) and kick off a forced Exim delivery run.
pub fn queue_fix(cfg: &Config) -> io::Result<QueueFixReport> {
    let (inc, out) = queue_dirs(cfg);
    let badqueue = out
        .parent()
        .unwrap_or(Path::new("/var/spool"))
        .join("msfe-ng-badqueue");
    let mut moved = 0usize;
    for dir in [&inc, &out] {
        let orphans = find_orphans(dir, orphan_min_age());
        if orphans.is_empty() {
            continue;
        }
        std::fs::create_dir_all(&badqueue)?;
        for p in orphans {
            if let Some(name) = p.file_name() {
                if std::fs::rename(&p, badqueue.join(name)).is_ok() {
                    moved += 1;
                }
            }
        }
    }
    Ok(QueueFixReport {
        moved,
        badqueue_dir: badqueue,
        flush_started: force_queue_run(),
    })
}

fn orphan_min_age() -> u64 {
    std::env::var("MSFE_NG_ORPHAN_MIN_AGE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(ORPHAN_MIN_AGE_SECS)
}

/// Spawn a forced queue run (`exim -qff`) in the background; a large queue can
/// take minutes, so the API never waits for it.
fn force_queue_run() -> bool {
    if std::env::var("MSFE_NG_SKIP_QUEUE_RUN").is_ok() {
        return false;
    }
    for exim in ["/usr/sbin/exim", "exim"] {
        let spawned = Command::new(exim)
            .arg("-qff")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return true;
        }
    }
    false
}

// ---- maillog tail ------------------------------------------------------------

/// Read the last `lines` lines of `path`, scanning at most the final 1 MiB.
pub fn tail_file(path: &Path, lines: usize) -> io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_SCAN: u64 = 1024 * 1024;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(MAX_SCAN);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text.lines().collect();
    let from = all.len().saturating_sub(lines);
    // When we started mid-file the first line is likely partial — drop it.
    let from = if start > 0 && from == 0 { 1.min(all.len()) } else { from };
    Ok(all[from..].join("\n"))
}

// ---- ruleset / config file access --------------------------------------------

/// True for plain filenames safe to resolve inside a managed directory.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Ruleset files in the managed rules dir as (name, size) pairs, sorted.
pub fn list_rules(cfg: &Config) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = std::fs::read_dir(&cfg.mailscanner_rules_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let size = e.metadata().ok()?.len();
                    safe_name(&name).then_some((name, size))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

pub fn read_rule(cfg: &Config, name: &str) -> io::Result<String> {
    if !safe_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad name"));
    }
    std::fs::read_to_string(Path::new(&cfg.mailscanner_rules_dir).join(name))
}

/// Save an editable config file, keeping a one-time `.msfe-ng.bak` of the
/// original and writing atomically.
pub fn save_conf(path: &Path, content: &str) -> io::Result<()> {
    if path.exists() {
        let backup = PathBuf::from(format!("{}.msfe-ng.bak", path.display()));
        if !backup.exists() {
            std::fs::copy(path, &backup)?;
        }
    }
    crate::sync::atomic_write(path, content.as_bytes())
}

// ---- release check -----------------------------------------------------------

const UPDATE_REPO: &str = "inalto/msfe-ng";

/// Latest released version, resolved on demand from the GitHub release-page
/// redirect via curl (the codebase has no TLS client). Never called
/// automatically — only from the admin's explicit "check for updates".
pub fn latest_version() -> Option<String> {
    let repo =
        std::env::var("MSFE_NG_UPDATE_REPO").unwrap_or_else(|_| UPDATE_REPO.to_string());
    let url = format!("https://github.com/{repo}/releases/latest");
    let out = Command::new("curl")
        .args(["-sSfL", "-o", "/dev/null", "-w", "%{url_effective}", "-m", "8", &url])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    extract_tag(String::from_utf8_lossy(&out.stdout).trim())
}

/// `…/releases/tag/v1.2.3` → `1.2.3`.
fn extract_tag(url: &str) -> Option<String> {
    let tag = url.rsplit('/').next()?;
    let ver = tag.strip_prefix('v')?;
    (!ver.is_empty() && ver.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        .then(|| ver.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-svc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn tail_returns_last_lines() {
        let d = tmpdir("tail");
        let f = d.join("log");
        std::fs::write(&f, "one\ntwo\nthree\nfour\n").unwrap();
        assert_eq!(tail_file(&f, 2).unwrap(), "three\nfour");
        assert_eq!(tail_file(&f, 99).unwrap(), "one\ntwo\nthree\nfour");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn queue_count_and_orphans() {
        let d = tmpdir("queue");
        // complete pair + orphaned -H + orphaned -D in a split-spool subdir
        std::fs::write(d.join("1aaaaa-000001-AA-H"), "h").unwrap();
        std::fs::write(d.join("1aaaaa-000001-AA-D"), "d").unwrap();
        std::fs::write(d.join("1bbbbb-000002-BB-H"), "h").unwrap();
        std::fs::create_dir(d.join("c")).unwrap();
        std::fs::write(d.join("c/1ccccc-000003-CC-D"), "d").unwrap();
        std::fs::write(d.join("ignore.txt"), "x").unwrap();

        assert_eq!(count_queue(&d), 2); // two -H files
        let orphans = find_orphans(&d, 0); // min age 0 → all orphans count
        let names: Vec<String> = orphans
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(orphans.len(), 2);
        assert!(names.contains(&"1bbbbb-000002-BB-H".to_string()));
        assert!(names.contains(&"1ccccc-000003-CC-D".to_string()));
        // with a huge min-age nothing is old enough
        assert!(find_orphans(&d, 3600).is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn safe_name_rejects_traversal() {
        assert!(safe_name("spam.whitelist.rules"));
        assert!(safe_name("a_b-c.1"));
        assert!(!safe_name(""));
        assert!(!safe_name(".hidden"));
        assert!(!safe_name("../etc/passwd"));
        assert!(!safe_name("a/b"));
        assert!(!safe_name("a b"));
    }

    #[test]
    fn save_conf_backs_up_once() {
        let d = tmpdir("conf");
        let f = d.join("test.conf");
        std::fs::write(&f, "original\n").unwrap();
        save_conf(&f, "edited\n").unwrap();
        save_conf(&f, "edited again\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "edited again\n");
        let bak = d.join("test.conf.msfe-ng.bak");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "original\n");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn extracts_release_tag() {
        assert_eq!(
            extract_tag("https://github.com/inalto/msfe-ng/releases/tag/v0.0.3"),
            Some("0.0.3".into())
        );
        assert_eq!(extract_tag("https://github.com/inalto/msfe-ng/releases"), None);
        assert_eq!(extract_tag("https://github.com/x/y/releases/tag/main"), None);
    }
}
