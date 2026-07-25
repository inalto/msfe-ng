//! Mail-log housekeeping: prune old rows so the database doesn't grow forever.
//!
//! Spec (behavior only): the original `mssql.pl` deletes `maillog` rows older
//! than the `cleanmysql` setting (days) and optimizes the table. We do the same
//! for `maillog` and `quarantine`. Reimplemented clean-room.

use crate::config::Config;
use crate::db;
use std::io;

/// Retention in days, from the `cleanmysql` policy setting (default 90),
/// clamped to a sane range.
pub fn retention_days(settings: &[(String, String)]) -> u32 {
    settings
        .iter()
        .find(|(k, _)| k == "cleanmysql")
        .and_then(|(_, v)| v.trim().parse::<u32>().ok())
        .unwrap_or(90)
        .clamp(1, 3650)
}

/// How many days message *bodies* (the quarantine copies that back the message
/// view, source/rendered display and Bayes training) are kept on disk, from the
/// `bodydays` policy setting. Bodies are the disk-heavy part, so this is
/// separate from the log-row retention above; default 14 days, `0` disables
/// body pruning entirely.
pub fn body_retention_days(settings: &[(String, String)]) -> u32 {
    settings
        .iter()
        .find(|(k, _)| k == "bodydays")
        .and_then(|(_, v)| v.trim().parse::<u32>().ok())
        .unwrap_or(14)
        .min(3650)
}

/// Delete rows older than `days` from `maillog` and `quarantine`, then optimize.
pub fn prune(cfg: &Config, days: u32) -> io::Result<()> {
    let sql = format!(
        "DELETE FROM maillog WHERE msg_ts < (NOW() - INTERVAL {days} DAY);\n\
         DELETE FROM quarantine WHERE quarantined_at < (NOW() - INTERVAL {days} DAY);\n\
         OPTIMIZE TABLE maillog;\n"
    );
    db::exec_stdin(cfg, &sql)
}

pub struct BodyPruneReport {
    pub removed: usize,
    pub bytes: u64,
    pub scanned: usize,
    /// Bodies still on disk after the prune, measured in the same walk.
    pub kept: usize,
    pub kept_bytes: u64,
}

/// Remove quarantined message bodies older than `days` (0 = keep forever).
/// Only files/dirs under the quarantine spool are touched; the maillog rows
/// stay, so the message keeps its entry, headers and reports in the UI — only
/// the body, source view and release/training stop being available.
pub fn prune_bodies(cfg: &Config, days: u32) -> io::Result<BodyPruneReport> {
    let mut report = BodyPruneReport {
        removed: 0,
        bytes: 0,
        scanned: 0,
        kept: 0,
        kept_bytes: 0,
    };
    if days == 0 {
        return Ok(report);
    }
    let cutoff = std::time::Duration::from_secs(days as u64 * 86_400);
    // Both trees hold message bodies and share the retention window.
    for root in [&cfg.quarantine_dir, &cfg.archive_dir] {
        if !root.trim().is_empty() {
            prune_root(std::path::Path::new(root), cutoff, &mut report)?;
        }
    }
    Ok(report)
}

/// Prune one body tree (`<root>/<date>/<entry>`), accumulating into `report`.
fn prune_root(
    base: &std::path::Path,
    cutoff: std::time::Duration,
    report: &mut BodyPruneReport,
) -> io::Result<()> {
    // MailScanner stores <root>/<date>/<message-id>{,dir}
    let Ok(days_dirs) = std::fs::read_dir(base) else {
        return Ok(());
    };
    for day in days_dirs.flatten() {
        let Ok(entries) = std::fs::read_dir(day.path()) else {
            continue;
        };
        for e in entries.flatten() {
            report.scanned += 1;
            let path = e.path();
            let old = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map(|age| age > cutoff)
                .unwrap_or(false);
            if !old {
                report.kept += 1;
                report.kept_bytes += dir_size(&path);
                continue;
            }
            let size = dir_size(&path);
            let gone = if path.is_dir() {
                std::fs::remove_dir_all(&path).is_ok()
            } else {
                std::fs::remove_file(&path).is_ok()
            };
            if gone {
                report.removed += 1;
                report.bytes += size;
            }
        }
        // drop the date directory once it is empty
        if std::fs::read_dir(day.path())
            .map(|mut d| d.next().is_none())
            .unwrap_or(false)
        {
            let _ = std::fs::remove_dir(day.path());
        }
    }
    Ok(())
}

/// Forget body paths whose files the prune just removed, so the database never
/// advertises a body that is gone (the UI asks the filesystem, but this keeps
/// list queries cheap and the data honest).
pub fn clear_pruned_paths(cfg: &Config, days: u32) -> io::Result<()> {
    if days == 0 {
        return Ok(());
    }
    db::exec_stdin(
        cfg,
        &format!(
            "UPDATE maillog SET body_path='' \
             WHERE body_path <> '' AND msg_ts < (NOW() - INTERVAL {days} DAY);\n"
        ),
    )
}

/// Record measured archive usage for the Settings disclosure.
pub fn record_usage(cfg: &Config, bytes: u64, files: usize) -> io::Result<()> {
    let sql = format!(
        "INSERT INTO msfe_config (scope, scope_id, ckey, cvalue) VALUES \
           ('global','','archive_usage_bytes','{bytes}'), \
           ('global','','archive_usage_files','{files}'), \
           ('global','','archive_usage_at', NOW()) \
         ON DUPLICATE KEY UPDATE cvalue = VALUES(cvalue);\n"
    );
    db::exec_stdin(cfg, &sql)
}

/// (total, available) bytes of the filesystem holding `path`, via `df -kP`.
pub fn disk_free(path: &str) -> Option<(u64, u64)> {
    let out = std::process::Command::new("df")
        .args(["-kP", path])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().nth(1)?;
    let f: Vec<&str> = line.split_whitespace().collect();
    let total: u64 = f.get(1)?.parse().ok()?;
    let avail: u64 = f.get(3)?.parse().ok()?;
    Some((total * 1024, avail * 1024))
}

fn dir_size(p: &std::path::Path) -> u64 {
    let Ok(meta) = std::fs::metadata(p) else {
        return 0;
    };
    if meta.is_file() {
        return meta.len();
    }
    std::fs::read_dir(p)
        .map(|entries| entries.flatten().map(|e| dir_size(&e.path())).sum())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_retention_default_and_disable() {
        assert_eq!(body_retention_days(&[]), 14);
        assert_eq!(body_retention_days(&[("bodydays".into(), "3".into())]), 3);
        assert_eq!(body_retention_days(&[("bodydays".into(), "0".into())]), 0); // keep forever
        assert_eq!(
            body_retention_days(&[("bodydays".into(), "99999".into())]),
            3650
        );
    }

    #[test]
    fn prunes_only_old_bodies() {
        let base = std::env::temp_dir().join(format!("msfe-bodies-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let day = base.join("20260724");
        std::fs::create_dir_all(&day).unwrap();
        let fresh = day.join("1aaaaa-0000000AAAA-1aaa");
        let old = day.join("1bbbbb-0000000BBBB-2bbb");
        std::fs::write(&fresh, b"fresh body").unwrap();
        std::fs::write(&old, b"old body").unwrap();
        // backdate the "old" one by 30 days
        let past = std::time::SystemTime::now() - std::time::Duration::from_secs(30 * 86_400);
        let f = std::fs::File::options().write(true).open(&old).unwrap();
        f.set_modified(past).unwrap();

        // an archived copy in a second tree must be pruned by the same window
        let arch = base
            .parent()
            .unwrap()
            .join(format!("msfe-arch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&arch);
        std::fs::create_dir_all(arch.join("20260724")).unwrap();
        let old_arch = arch.join("20260724").join("1ccccc-0000000CCCC-3ccc");
        std::fs::write(&old_arch, b"old archived body").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&old_arch)
            .unwrap()
            .set_modified(past)
            .unwrap();

        let cfg = Config {
            quarantine_dir: base.display().to_string(),
            archive_dir: arch.display().to_string(),
            ..Default::default()
        };
        // days=0 keeps everything
        assert_eq!(prune_bodies(&cfg, 0).unwrap().removed, 0);
        let r = prune_bodies(&cfg, 14).unwrap();
        assert_eq!(r.removed, 2, "both the quarantine and archive copies go");
        assert!(r.bytes > 0);
        assert_eq!(r.kept, 1, "the recent body is counted as kept");
        assert!(r.kept_bytes > 0);
        assert!(fresh.exists(), "recent body must be kept");
        assert!(!old.exists(), "body past the retention window must go");
        assert!(
            !old_arch.exists(),
            "archived body past the window must go too"
        );
        std::fs::remove_dir_all(&base).unwrap();
        let _ = std::fs::remove_dir_all(&arch);
    }

    #[test]
    fn retention_default_and_clamp() {
        assert_eq!(retention_days(&[]), 90);
        assert_eq!(retention_days(&[("cleanmysql".into(), "30".into())]), 30);
        assert_eq!(
            retention_days(&[("cleanmysql".into(), "99999".into())]),
            3650
        );
        assert_eq!(retention_days(&[("cleanmysql".into(), "x".into())]), 90);
    }
}
