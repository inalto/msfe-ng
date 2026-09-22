//! The legacy front-end's message history. ConfigServer's MailControl logged
//! every message into its own MySQL database (`mailscanner`, a MailWatch-shaped
//! `maillog`), and ConfigServer's uninstaller drops that database. Before the
//! guided migration runs the uninstaller, the history is dumped into the
//! backup directory and copied into MSFE-NG's own `maillog`, so the Messages
//! tab keeps showing what happened before the switch.
//!
//! Everything here talks to MySQL as the local root (the way `setup.rs`
//! provisions the database), because MSFE-NG's own user has no grant on the
//! legacy database. Under `MSFE_NG_MIGRATION_ROOT` (tests) there is no live
//! database and `detect` answers `None`.

use crate::Config;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where ConfigServer's MailControl logs.
pub const LEGACY_DB: &str = "mailscanner";

/// What the legacy database holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyHistory {
    pub database: String,
    pub rows: u64,
    pub oldest: Option<String>,
    pub newest: Option<String>,
}

impl LegacyHistory {
    /// One line for a preflight or a log.
    pub fn describe(&self) -> String {
        match (&self.oldest, &self.newest) {
            (Some(o), Some(n)) if self.rows > 0 => format!(
                "{} message(s) of history in database `{}` ({} … {})",
                self.rows, self.database, o, n
            ),
            _ => format!(
                "{} message(s) of history in database `{}`",
                self.rows, self.database
            ),
        }
    }
}

/// What an import did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Legacy column → MSFE-NG column, in the order copied.
    pub columns: Vec<(String, String)>,
    pub inserted: u64,
    /// Rows of the legacy table (before: total; the difference is what was
    /// already present or had no message id).
    pub legacy_rows: u64,
}

/// A name safe to put between backticks.
fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'$')
}

/// The columns to copy: the legacy `timestamp` and `id` become `msg_ts` and
/// `message_id`; every other column present under the same name on both
/// sides is copied as is. Legacy-only columns (`date`, `time`) and ours
/// (`row_id`, `token`, …) are left out. Empty when the two key columns are
/// not both available.
pub fn column_map(legacy: &[String], ours: &[String]) -> Vec<(String, String)> {
    let has = |list: &[String], name: &str| list.iter().any(|c| c.eq_ignore_ascii_case(name));
    if !(has(legacy, "timestamp")
        && has(legacy, "id")
        && has(ours, "msg_ts")
        && has(ours, "message_id"))
    {
        return Vec::new();
    }
    let mut map = vec![
        ("timestamp".to_string(), "msg_ts".to_string()),
        ("id".to_string(), "message_id".to_string()),
    ];
    for c in legacy {
        let lc = c.to_ascii_lowercase();
        if matches!(lc.as_str(), "timestamp" | "id" | "date" | "time" | "row_id") {
            continue;
        }
        if has(ours, &lc) && !map.iter().any(|(l, _)| l.eq_ignore_ascii_case(&lc)) {
            map.push((lc.clone(), lc));
        }
    }
    map
}

/// The copy statement: rows whose message id MSFE-NG does not have yet.
/// `INSERT IGNORE` keeps going past a row the stricter schema refuses.
pub fn import_sql(legacy_db: &str, our_db: &str, map: &[(String, String)]) -> String {
    let ours: Vec<String> = map.iter().map(|(_, o)| format!("`{o}`")).collect();
    let theirs: Vec<String> = map.iter().map(|(l, _)| format!("l.`{l}`")).collect();
    format!(
        "INSERT IGNORE INTO `{our_db}`.`maillog` ({}) SELECT {} FROM `{legacy_db}`.`maillog` l \
         LEFT JOIN `{our_db}`.`maillog` m ON m.`message_id` = l.`id` \
         WHERE m.`row_id` IS NULL AND l.`id` IS NOT NULL AND l.`id` <> '';",
        ours.join(", "),
        theirs.join(", ")
    )
}

/// True when there is a live host to ask (not a test fixture root).
fn live() -> bool {
    std::env::var("MSFE_NG_MIGRATION_ROOT").map_or(true, |r| r == "/")
}

/// A read query as the local MySQL root: rows of tab-separated columns.
fn root_query(sql: &str) -> io::Result<Vec<Vec<String>>> {
    let out = Command::new("mysql")
        .args(["-N", "-B", "-e", sql])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| io::Error::other(format!("cannot run the mysql client: {e}")))?;
    if !out.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('\t').map(|c| c.to_string()).collect())
        .collect())
}

/// A statement as the local MySQL root, fed over stdin.
fn root_exec(sql: &str) -> io::Result<()> {
    let mut child = Command::new("mysql")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run the mysql client: {e}")))?;
    child.stdin.as_mut().unwrap().write_all(sql.as_bytes())?;
    let out = child.wait_with_output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

/// The legacy database, if it exists here and is not MSFE-NG's own.
pub fn detect(cfg: &Config, database: &str) -> Option<LegacyHistory> {
    if !live() || !valid_ident(database) || database == cfg.db_name {
        return None;
    }
    let exists = root_query(&format!(
        "SELECT 1 FROM information_schema.tables WHERE table_schema='{database}' AND table_name='maillog'"
    ))
    .ok()?;
    if exists.is_empty() {
        return None;
    }
    let row = root_query(&format!(
        "SELECT COUNT(*), IFNULL(MIN(`timestamp`),''), IFNULL(MAX(`timestamp`),'') FROM `{database}`.`maillog`"
    ))
    .ok()?
    .into_iter()
    .next()?;
    let rows = row.first().and_then(|c| c.parse().ok()).unwrap_or(0);
    let opt = |i: usize| row.get(i).filter(|s| !s.is_empty()).cloned();
    Some(LegacyHistory {
        database: database.to_string(),
        rows,
        oldest: opt(1),
        newest: opt(2),
    })
}

/// `mysqldump` of the legacy database, gzipped, into `backup_dir`
/// (`legacy-<database>-<stamp>.sql.gz`, 0600). Nothing half-written is left
/// behind on failure.
pub fn dump(backup_dir: &Path, database: &str) -> io::Result<PathBuf> {
    if !valid_ident(database) {
        return Err(io::Error::other(format!(
            "'{database}' is not a database name"
        )));
    }
    std::fs::create_dir_all(backup_dir)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = backup_dir.join(format!("legacy-{database}-{stamp}.sql.gz"));
    let out = Command::new("sh")
        .arg("-c")
        .arg("set -o pipefail; umask 077; mysqldump --single-transaction --quick \"$1\" | gzip > \"$2\"")
        .arg("sh")
        .arg(database)
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()?;
    if !out.status.success() {
        let _ = std::fs::remove_file(&path);
        return Err(io::Error::other(format!(
            "mysqldump of {database} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(path)
}

/// Copy the legacy rows MSFE-NG does not have into its `maillog`.
pub fn import(cfg: &Config, database: &str) -> io::Result<ImportReport> {
    if !valid_ident(database) || !valid_ident(&cfg.db_name) {
        return Err(io::Error::other("database names must be alphanumeric"));
    }
    if database == cfg.db_name {
        return Err(io::Error::other(
            "the legacy database is MSFE-NG's own — nothing to copy",
        ));
    }
    let columns = |db: &str| -> io::Result<Vec<String>> {
        Ok(root_query(&format!(
            "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' \
             AND table_name='maillog' ORDER BY ordinal_position"
        ))?
        .into_iter()
        .filter_map(|r| r.into_iter().next())
        .collect())
    };
    let legacy = columns(database)?;
    if legacy.is_empty() {
        return Err(io::Error::other(format!(
            "no `maillog` table in database {database}"
        )));
    }
    let ours = columns(&cfg.db_name)?;
    if ours.is_empty() {
        return Err(io::Error::other(format!(
            "no `maillog` table in database {} — run `msfe-ng db-migrate` first",
            cfg.db_name
        )));
    }
    let map = column_map(&legacy, &ours);
    if map.is_empty() {
        return Err(io::Error::other(
            "the legacy maillog has no `timestamp`/`id` columns — not a MailControl table",
        ));
    }
    let count = |db: &str| -> io::Result<u64> {
        Ok(
            root_query(&format!("SELECT COUNT(*) FROM `{db}`.`maillog`"))?
                .first()
                .and_then(|r| r.first())
                .and_then(|c| c.parse().ok())
                .unwrap_or(0),
        )
    };
    let legacy_rows = count(database)?;
    let before = count(&cfg.db_name)?;
    root_exec(&import_sql(database, &cfg.db_name, &map))?;
    let after = count(&cfg.db_name)?;
    Ok(ImportReport {
        columns: map,
        inserted: after.saturating_sub(before),
        legacy_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn column_map_renames_the_keys_and_keeps_shared_columns() {
        let legacy = cols(&[
            "timestamp",
            "id",
            "size",
            "from_address",
            "to_address",
            "subject",
            "sascore",
            "headers",
            "date",
            "time",
            "to_domains",
            "ISSPAM",
        ]);
        let ours = cols(&[
            "row_id",
            "msg_ts",
            "message_id",
            "size",
            "from_address",
            "to_address",
            "subject",
            "sascore",
            "headers",
            "isspam",
            "token",
        ]);
        let map = column_map(&legacy, &ours);
        assert_eq!(map[0], ("timestamp".into(), "msg_ts".into()));
        assert_eq!(map[1], ("id".into(), "message_id".into()));
        let rest: Vec<&str> = map[2..].iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            rest,
            vec![
                "size",
                "from_address",
                "to_address",
                "subject",
                "sascore",
                "headers",
                "isspam"
            ]
        );
        // legacy-only and ours-only columns are left out
        assert!(!map
            .iter()
            .any(|(l, _)| l == "date" || l == "time" || l == "to_domains"));
        assert!(!map.iter().any(|(_, o)| o == "row_id" || o == "token"));
        // not a MailControl table → nothing to copy
        assert!(column_map(&cols(&["msg_ts", "message_id"]), &ours).is_empty());
        assert!(column_map(&legacy, &cols(&["row_id", "size"])).is_empty());
    }

    #[test]
    fn import_sql_copies_only_rows_we_do_not_have() {
        let map = vec![
            ("timestamp".to_string(), "msg_ts".to_string()),
            ("id".to_string(), "message_id".to_string()),
            ("subject".to_string(), "subject".to_string()),
        ];
        let sql = import_sql("mailscanner", "msfe_ng", &map);
        assert_eq!(
            sql,
            "INSERT IGNORE INTO `msfe_ng`.`maillog` (`msg_ts`, `message_id`, `subject`) \
             SELECT l.`timestamp`, l.`id`, l.`subject` FROM `mailscanner`.`maillog` l \
             LEFT JOIN `msfe_ng`.`maillog` m ON m.`message_id` = l.`id` \
             WHERE m.`row_id` IS NULL AND l.`id` IS NOT NULL AND l.`id` <> '';"
        );
    }

    #[test]
    fn detect_and_dump_refuse_bad_names_and_fixture_roots() {
        assert!(!valid_ident("mail;scanner"));
        assert!(!valid_ident(""));
        assert!(valid_ident("mailscanner"));
        let cfg = Config::default();
        // no env games here (other tests set the fixture root concurrently):
        // a bad name and our own database are refused before MySQL is asked
        assert_eq!(detect(&cfg, "not a name"), None);
        assert_eq!(detect(&cfg, &cfg.db_name), None, "never our own database");
        let err = dump(Path::new("/tmp"), "bad name").unwrap_err();
        assert!(err.to_string().contains("not a database name"));
        assert!(LegacyHistory {
            database: "mailscanner".into(),
            rows: 3,
            oldest: Some("2026-01-01 00:00:00".into()),
            newest: Some("2026-02-01 00:00:00".into()),
        }
        .describe()
        .contains("3 message(s) of history in database `mailscanner` (2026-01-01"));
    }
}
