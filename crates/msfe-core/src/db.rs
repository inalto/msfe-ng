//! Thin MySQL access via the system `mysql` client.
//!
//! We shell out rather than link a driver so the build stays dependency-free and
//! offline. Credentials are passed through a private, 0600 `--defaults-extra-file`
//! (never on argv, so they don't show up in `ps`). Queries return tab-separated
//! rows parsed into `Vec<Vec<String>>` — fine for MSFE-NG's small aggregate
//! queries; a real driver can replace this later without changing callers.

use crate::config::Config;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// A temp `[client]` options file, removed on drop.
struct DefaultsFile(PathBuf);

impl Drop for DefaultsFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write the connection credentials to a private temp file for `--defaults-extra-file`.
fn defaults_file(cfg: &Config) -> io::Result<DefaultsFile> {
    let name = format!(
        "msfe-ng-my-{}-{}.cnf",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(name);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    // password is intentionally NOT quoted the my.cnf way here; values with
    // special chars still work because mysql reads the raw line after '='.
    writeln!(
        f,
        "[client]\nhost={}\nport={}\nuser={}\npassword={}",
        cfg.db_host, cfg.db_port, cfg.db_user, cfg.db_pass
    )?;
    Ok(DefaultsFile(path))
}

fn base_cmd(cfg: &Config, df: &DefaultsFile) -> Command {
    let mut c = Command::new("mysql");
    c.arg(format!("--defaults-extra-file={}", df.0.display()));
    c.arg(&cfg.db_name);
    c
}

/// Run a read query, returning rows of column strings (NULLs become empty).
/// `-N` skips headers, `-B` is batch/tab-separated, `--raw` avoids escaping.
pub fn query(cfg: &Config, sql: &str) -> io::Result<Vec<Vec<String>>> {
    let df = defaults_file(cfg)?;
    let out = base_cmd(cfg, &df)
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
    let df = defaults_file(cfg)?;
    let mut child = base_cmd(cfg, &df)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn defaults_file_is_private_and_removed() {
        let cfg = Config::default();
        let path;
        {
            let df = defaults_file(&cfg).unwrap();
            path = df.0.clone();
            let meta = std::fs::metadata(&path).unwrap();
            // 0600 permissions
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            let body = std::fs::read_to_string(&path).unwrap();
            assert!(body.contains("[client]"));
            assert!(body.contains("user=msfe_ng"));
        }
        // dropped → removed
        assert!(!path.exists());
    }
}
