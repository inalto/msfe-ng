//! Database migration runner.
//!
//! Migrations are plain `.sql` files named `NNNN_name.sql` in a directory. We
//! apply them with the system `mysql` client (no Rust DB driver needed in M1),
//! tracking applied versions in the `schema_migrations` table. The pure logic
//! (discovery, ordering, pending diff) is unit-tested; the apply/query steps
//! shell out and are covered by integration testing on a real DB.

use crate::config::Config;
use crate::db;
use std::io::{self};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Migration {
    pub version: u32,
    pub name: String,
    pub path: PathBuf,
}

/// Discover `NNNN_name.sql` files, sorted ascending by version. Files that don't
/// match the pattern are skipped.
pub fn discover(dir: &Path) -> io::Result<Vec<Migration>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let stem = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s,
            None => continue,
        };
        let (num, rest) = match stem.split_once('_') {
            Some(p) => p,
            None => continue,
        };
        if let Ok(version) = num.parse::<u32>() {
            out.push(Migration {
                version,
                name: rest.to_string(),
                path,
            });
        }
    }
    out.sort_by_key(|m| m.version);
    Ok(out)
}

/// Migrations whose version is not already applied, in order.
pub fn pending(all: &[Migration], applied: &[u32]) -> Vec<Migration> {
    all.iter()
        .filter(|m| !applied.contains(&m.version))
        .cloned()
        .collect()
}

/// Query applied versions from `schema_migrations`. Returns an empty vec if the
/// table doesn't exist yet (fresh database).
pub fn applied_versions(cfg: &Config) -> io::Result<Vec<u32>> {
    // A fresh DB has no schema_migrations table → query errors → treat as none.
    let rows = match db::query(
        cfg,
        "SELECT version FROM schema_migrations ORDER BY version",
    ) {
        Ok(r) => r,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(rows
        .iter()
        .filter_map(|r| r.first().and_then(|c| c.trim().parse::<u32>().ok()))
        .collect())
}

/// Apply one migration file, then record it in `schema_migrations`.
pub fn apply(cfg: &Config, m: &Migration) -> io::Result<()> {
    let sql = std::fs::read_to_string(&m.path)?;
    db::exec_stdin(cfg, &sql)?;
    let record = format!(
        "INSERT INTO schema_migrations (version, name) VALUES ({}, '{}')",
        m.version,
        m.name.replace('\'', "''")
    );
    db::exec_stdin(cfg, &record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_orders_and_filters() {
        let dir = std::env::temp_dir().join(format!("msfe-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for n in ["0002_second.sql", "0001_init.sql", "notes.txt", "bad.sql"] {
            std::fs::write(dir.join(n), "SELECT 1;").unwrap();
        }
        let all = discover(&dir).unwrap();
        let versions: Vec<u32> = all.iter().map(|m| m.version).collect();
        assert_eq!(versions, vec![1, 2]); // ordered; non-numeric 'bad'/'notes' skipped
        assert_eq!(all[0].name, "init");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pending_excludes_applied() {
        let all = vec![
            Migration {
                version: 1,
                name: "a".into(),
                path: "a".into(),
            },
            Migration {
                version: 2,
                name: "b".into(),
                path: "b".into(),
            },
            Migration {
                version: 3,
                name: "c".into(),
                path: "c".into(),
            },
        ];
        let p = pending(&all, &[1, 2]);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].version, 3);
    }
}
