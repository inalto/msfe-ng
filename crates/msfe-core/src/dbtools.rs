//! Database maintenance: timestamped SQL dumps and a "fix common problems"
//! pass (apply pending migrations, then MySQL table maintenance). Consumed by
//! the CLI `db` subcommand and the `/api/db/*` endpoints that the panel's
//! Config → Database card drives.

use crate::config::Config;
use crate::{db, migrate};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Tables MSFE-NG owns and maintains. (The dump covers the whole database; this
/// list is only what table maintenance operates on.)
const TABLES: &[&str] = &["maillog", "quarantine", "msfe_config"];

/// UTC `YYYYMMDD-HHMMSS` from Unix seconds, for backup filenames — no external
/// date crate (civil-from-days per Howard Hinnant's algorithm).
fn stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}{m:02}{d:02}-{:02}{:02}{:02}",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a timestamped `mysqldump` into `cfg.backup_dir`, returning its path.
/// The directory is created 0700 (the dump holds message metadata) and the file
/// itself is tightened to 0600.
pub fn backup(cfg: &Config) -> io::Result<PathBuf> {
    let dir = Path::new(&cfg.backup_dir);
    std::fs::create_dir_all(dir)?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let path = dir.join(format!("msfe-ng-{}.sql", stamp(now_secs())));
    db::dump(cfg, &path)?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(path)
}

/// Outcome of a `fix` pass: a human-readable transcript plus overall success.
pub struct FixReport {
    pub ok: bool,
    pub log: Vec<String>,
}

/// Fix common database problems: apply any pending migrations, then run MySQL
/// table maintenance (`OPTIMIZE`/`ANALYZE`) over the MSFE-NG tables. Best-effort
/// — a failure in one step is recorded and the pass continues.
pub fn fix(cfg: &Config, migrations_dir: &Path) -> FixReport {
    let mut log = Vec::new();
    let mut ok = true;

    // 1. pending migrations
    match migrate::discover(migrations_dir) {
        Ok(all) => match migrate::applied_versions(cfg) {
            Ok(applied) => {
                let todo = migrate::pending(&all, &applied);
                if todo.is_empty() {
                    log.push(format!(
                        "migrations: up to date ({} applied)",
                        applied.len()
                    ));
                } else {
                    for m in &todo {
                        match migrate::apply(cfg, m) {
                            Ok(()) => {
                                log.push(format!("migration {:04}_{}: applied", m.version, m.name))
                            }
                            Err(e) => {
                                log.push(format!(
                                    "migration {:04}_{}: FAILED — {e}",
                                    m.version, m.name
                                ));
                                ok = false;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                log.push(format!("migrations: cannot query DB — {e}"));
                ok = false;
            }
        },
        Err(e) => {
            log.push(format!(
                "migrations: cannot read {} — {e}",
                migrations_dir.display()
            ));
            ok = false;
        }
    }

    // 2. table maintenance (reclaims space + refreshes optimizer stats)
    for op in ["OPTIMIZE", "ANALYZE"] {
        let sql = format!("{op} TABLE {}", TABLES.join(", "));
        match db::query(cfg, &sql) {
            Ok(rows) => {
                for r in rows {
                    // rows are: Table | Op | Msg_type | Msg_text
                    log.push(format!("{}: {}", op.to_lowercase(), r.join(" ")));
                }
            }
            Err(e) => {
                log.push(format!("{}: FAILED — {e}", op.to_lowercase()));
                ok = false;
            }
        }
    }

    FixReport { ok, log }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_formats_known_epochs() {
        assert_eq!(stamp(0), "19700101-000000");
        // 1_700_000_000 = 2023-11-14 22:13:20 UTC
        assert_eq!(stamp(1_700_000_000), "20231114-221320");
        // a leap day: 2024-02-29 00:00:00 UTC = 1_709_164_800
        assert_eq!(stamp(1_709_164_800), "20240229-000000");
    }
}
