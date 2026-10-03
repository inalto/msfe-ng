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
/// `-N` skips headers, `-B` is batch/tab-separated. Batch mode escapes the
/// characters that would break that framing (newline, tab, NUL, backslash)
/// as `\n` `\t` `\0` `\\`, which `parse_batch` undoes — multi-line values
/// such as `maillog.headers` come back whole. (`--raw` would emit them
/// verbatim and split one value across rows and columns.)
pub fn query(cfg: &Config, sql: &str) -> io::Result<Vec<Vec<String>>> {
    let df = defaults_file(cfg)?;
    let out = base_cmd(cfg, &df).args(["-N", "-B", "-e", sql]).output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "mysql query failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(parse_batch(&String::from_utf8_lossy(&out.stdout)))
}

/// Split `mysql -B` output into rows and columns, decoding its escapes.
fn parse_batch(out: &str) -> Vec<Vec<String>> {
    out.lines()
        .map(|l| l.split('\t').map(unescape_batch).collect())
        .collect()
}

fn unescape_batch(cell: &str) -> String {
    let mut s = String::with_capacity(cell.len());
    let mut it = cell.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            s.push(c);
            continue;
        }
        match it.next() {
            Some('n') => s.push('\n'),
            Some('t') => s.push('\t'),
            Some('0') => s.push('\0'),
            Some('\\') => s.push('\\'),
            Some(o) => {
                s.push('\\');
                s.push(o);
            }
            None => s.push('\\'),
        }
    }
    s
}

/// The `mysql` client connects with a 3-byte UTF-8 character set (it follows
/// the locale), so a statement carrying a character beyond the Basic
/// Multilingual Plane (an emoji) fails with `ERROR 1366` even though the
/// tables are `utf8mb4`. The connection character set is deliberately left
/// alone (forcing utf8mb4 could turn rows written through a latin1-mode
/// client into mojibake). Instead no statement ever carries such a character:
/// plain text goes through `bmp_only`, JSON text through `bmp_escape`.
///
/// Every character above U+FFFF becomes U+FFFD (lossy; for plain text).
pub fn bmp_only(s: &str) -> String {
    s.chars()
        .map(|c| if (c as u32) > 0xFFFF { '\u{fffd}' } else { c })
        .collect()
}

/// Every character above U+FFFF written as a `\uXXXX\uXXXX` surrogate-pair
/// escape. ONLY valid for text that is JSON: the escapes are read back by a
/// JSON parser, never by SQL, so the result is exact for a JSON document.
pub fn bmp_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if (c as u32) > 0xFFFF {
            let mut b = [0u16; 2];
            for u in c.encode_utf16(&mut b) {
                out.push_str(&format!("\\u{u:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// SQL single-quote a string literal (quotes doubled, backslashes escaped).
/// Characters beyond the BMP are replaced (see `bmp_only`); a JSON document
/// must be passed through `bmp_escape` first to keep them.
pub fn quote(s: &str) -> String {
    format!(
        "'{}'",
        bmp_only(s).replace('\\', "\\\\").replace('\'', "''")
    )
}

/// A quoted `LIKE` pattern matching `needle` anywhere, with the wildcard
/// characters of the needle itself escaped (MySQL's default `\` escape).
pub fn like_contains(needle: &str) -> String {
    let escaped = needle
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    quote(&format!("%{escaped}%"))
}

/// Read a global key from the `msfe_config` kv table (daemon-writable state:
/// alert cooldowns, last-run summaries). `None` when unset or the DB is down.
pub fn kv_get(cfg: &Config, ckey: &str) -> Option<String> {
    if !ckey
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'@' || b == b'-')
    {
        return None;
    }
    let sql = format!(
        "SELECT cvalue FROM msfe_config WHERE scope='global' AND scope_id='' AND ckey='{ckey}'"
    );
    query(cfg, &sql)
        .ok()?
        .first()
        .and_then(|r| r.first())
        .cloned()
}

/// Upsert a global key in the `msfe_config` kv table. Values are SQL-escaped
/// by doubling quotes; keys are restricted to a safe charset.
pub fn kv_set(cfg: &Config, ckey: &str, cvalue: &str) -> io::Result<()> {
    if !ckey
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'@' || b == b'-')
    {
        return Err(io::Error::other("invalid kv key"));
    }
    let v = quote(cvalue);
    let sql = format!(
        "INSERT INTO msfe_config (scope, scope_id, ckey, cvalue) VALUES ('global','','{ckey}',{v}) \
         ON DUPLICATE KEY UPDATE cvalue = VALUES(cvalue);\n"
    );
    exec_stdin(cfg, &sql)
}

/// Dump the whole database to `path` via `mysqldump`, authenticating through the
/// same private defaults file (credentials never touch argv). A consistent,
/// low-lock snapshot (`--single-transaction`) suitable for InnoDB.
pub fn dump(cfg: &Config, path: &std::path::Path) -> io::Result<()> {
    let df = defaults_file(cfg)?;
    let out = std::fs::File::create(path)?;
    let status = Command::new("mysqldump")
        .arg(format!("--defaults-extra-file={}", df.0.display()))
        .args(["--single-transaction", "--quick", "--routines"])
        .arg(&cfg.db_name)
        .stdout(Stdio::from(out))
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        // don't leave a half-written/empty file behind
        let _ = std::fs::remove_file(path);
        return Err(io::Error::other("mysqldump failed"));
    }
    Ok(())
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

/// Like `exec_stdin`, but the client's stderr is captured and carried in the
/// error (so callers can tell a duplicate key from a dead server). The client
/// stops at the first failing statement; callers that need all-or-nothing
/// wrap their script in a transaction, which the closing session rolls back.
pub fn exec_stdin_captured(cfg: &Config, sql: &str) -> io::Result<()> {
    let df = defaults_file(cfg)?;
    let mut child = base_cmd(cfg, &df)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(sql.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "mysql exited non-zero: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMOJI: &str = "\u{1F600}";

    #[test]
    fn bmp_only_replaces_astral_characters() {
        assert_eq!(bmp_only(""), "");
        assert_eq!(bmp_only("plain \u{e9}\u{65e5}"), "plain \u{e9}\u{65e5}");
        assert_eq!(bmp_only("a\u{1F600}b"), "a\u{fffd}b");
        assert_eq!(bmp_only("\u{FFFF}"), "\u{FFFF}");
        assert_eq!(bmp_only("\u{10000}"), "\u{fffd}");
        assert_eq!(bmp_only("\u{10FFFF}x\u{1F600}"), "\u{fffd}x\u{fffd}");
    }

    #[test]
    fn bmp_escape_writes_surrogate_pairs() {
        assert_eq!(bmp_escape(""), "");
        assert_eq!(bmp_escape("plain \u{e9}\u{65e5}"), "plain \u{e9}\u{65e5}");
        assert_eq!(bmp_escape("\u{FFFF}"), "\u{FFFF}");
        assert_eq!(bmp_escape("\u{10000}"), "\\ud800\\udc00");
        assert_eq!(bmp_escape("a\u{1F600}b"), "a\\ud83d\\ude00b");
        assert_eq!(bmp_escape("\u{10FFFF}"), "\\udbff\\udfff");
    }

    #[test]
    fn quote_never_carries_an_astral_character() {
        let q = quote(&format!("it's {EMOJI} \\ \u{10000}"));
        assert!(q.chars().all(|c| (c as u32) <= 0xFFFF), "{q}");
        assert_eq!(q, "'it''s \u{fffd} \\\\ \u{fffd}'");
        assert!(like_contains(EMOJI).chars().all(|c| (c as u32) <= 0xFFFF));
    }

    #[test]
    fn a_json_document_with_an_emoji_survives_the_escape() {
        let doc = crate::json::Json::Object(vec![(
            "t".into(),
            crate::json::Json::str(format!("x {EMOJI} \"q\" \\ y")),
        )]);
        let stored = bmp_escape(&doc.to_string());
        assert!(stored.chars().all(|c| (c as u32) <= 0xFFFF));
        // through the SQL literal and back (the server undoes the quoting)
        let lit = quote(&stored);
        assert!(lit.chars().all(|c| (c as u32) <= 0xFFFF));
        let back = crate::json::Json::parse(&stored).unwrap();
        assert_eq!(back.to_string(), doc.to_string());
    }

    #[test]
    fn like_contains_escapes_wildcards_and_quotes() {
        assert_eq!(like_contains("bob"), "'%bob%'");
        assert_eq!(like_contains("50%_off"), "'%50\\\\%\\\\_off%'");
        assert_eq!(like_contains("o'neil"), "'%o''neil%'");
        assert_eq!(like_contains("a\\b"), "'%a\\\\\\\\b%'");
    }
    use std::os::unix::fs::PermissionsExt;

    /// A `headers` column folded with a tab and spanning lines must come back
    /// as one cell — the preview/release code rebuilds the message from it.
    #[test]
    fn batch_output_decodes_escaped_newlines_and_tabs() {
        let out = "/var/spool/x/1abc-D\tContent-Type: multipart/report;\\n\\tboundary=\"b\"\\nX-A: 1\\\\2\\0\n\t\n";
        let rows = parse_batch(out);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0][0], "/var/spool/x/1abc-D");
        assert_eq!(
            rows[0][1],
            "Content-Type: multipart/report;\n\tboundary=\"b\"\nX-A: 1\\2\0"
        );
        // second row: two empty cells (NULL-ish), not a crash
        assert_eq!(rows[1], vec!["", ""]);
    }

    #[test]
    fn batch_unescape_leaves_unknown_escapes_alone() {
        assert_eq!(unescape_batch("a\\qb\\"), "a\\qb\\");
        assert_eq!(unescape_batch("plain"), "plain");
    }

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
