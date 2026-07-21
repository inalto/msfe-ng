//! Thin MySQL access via the system `mysql` client.
//!
//! We shell out rather than link a driver so the build stays dependency-free and
//! offline. Queries return tab-separated rows parsed into `Vec<Vec<String>>`.
//! Fine for MSFE-NG's small aggregate/reporting queries; a real driver can
//! replace this later without changing callers.

use crate::config::Config;
use std::io::{self, Write};
use std::process::{Command, Stdio};

/// Common `mysql` client args from config. NOTE: the password rides on argv and
/// is visible in `ps`; a temporary `--defaults-extra-file` is a later hardening.
pub fn mysql_args(cfg: &Config) -> Vec<String> {
    let mut a = vec![
        format!("--host={}", cfg.db_host),
        format!("--port={}", cfg.db_port),
        format!("--user={}", cfg.db_user),
    ];
    if !cfg.db_pass.is_empty() {
        a.push(format!("--password={}", cfg.db_pass));
    }
    a.push(cfg.db_name.clone());
    a
}

/// Run a read query, returning rows of column strings (NULLs become empty).
/// `-N` skips headers, `-B` is batch/tab-separated, `--raw` avoids escaping.
pub fn query(cfg: &Config, sql: &str) -> io::Result<Vec<Vec<String>>> {
    let out = Command::new("mysql")
        .args(mysql_args(cfg))
        .args(["-N", "-B", "--raw", "-e", sql])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "mysql query failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('\t').map(|c| c.to_string()).collect())
        .collect())
}

/// Feed a SQL script to the `mysql` client over stdin (for DDL / inserts).
pub fn exec_stdin(cfg: &Config, sql: &str) -> io::Result<()> {
    let mut child = Command::new("mysql")
        .args(mysql_args(cfg))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(sql.as_bytes())?;
    if !child.wait()?.success() {
        return Err(io::Error::other("mysql exited non-zero"));
    }
    Ok(())
}
