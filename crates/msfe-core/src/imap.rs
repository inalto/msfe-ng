//! Just enough IMAP for the DMARC report mailbox, driven through `curl`.
//!
//! Every operation is one curl run. Commands whose answer fits on one line go
//! as custom requests (`-X`): `STATUS`, `UID SEARCH`, `UID STORE`, `EXPUNGE`
//! — curl logs in and, when the URL names the folder, selects it first. A
//! message body comes back as an IMAP literal, which curl only writes out for
//! its own URL fetch (`…/INBOX;UID=n`), not for a custom `FETCH`. And curl
//! before 7.62 (AlmaLinux 8 ships 7.61) sends that URL as `FETCH n`, a
//! sequence number: there the message is fetched by its position and checked
//! against the UID's `RFC822.SIZE` before anything acts on it. The login goes
//! through a 0600 curl config file, never argv, like `report.rs` does with
//! the AbuseIPDB key.

use crate::config::Config;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct CurlConfig(PathBuf);

impl Drop for CurlConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A quoted curl config value: `\`, `"` and control whitespace escaped.
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

/// Host and folder checks: nothing that could smuggle a second command or
/// change the URL's meaning.
pub fn validate(cfg: &Config) -> Result<(), String> {
    let h = &cfg.dmarc_imap_host;
    if h.is_empty() {
        return Err("no IMAP host set".into());
    }
    if !h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
    {
        return Err(format!("bad IMAP host {h:?}"));
    }
    let f = &cfg.dmarc_imap_folder;
    if f.is_empty()
        || f.len() > 200
        || !f
            .bytes()
            .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
    {
        return Err(format!("bad IMAP folder {f:?} (ASCII only, no quotes)"));
    }
    if cfg.dmarc_imap_user.is_empty() || cfg.dmarc_imap_pass.is_empty() {
        return Err("IMAP user and password are required".into());
    }
    if cfg.dmarc_imap_user.contains(':') {
        return Err("the IMAP user cannot contain ':'".into());
    }
    Ok(())
}

fn pct_encode(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// `imaps://host:port/` (or `imap://`), with the folder when `folder`.
pub fn url(cfg: &Config, folder: bool) -> String {
    let scheme = if cfg.dmarc_imap_tls { "imaps" } else { "imap" };
    let mut u = format!(
        "{scheme}://{}:{}/",
        cfg.dmarc_imap_host, cfg.dmarc_imap_port
    );
    if folder {
        u.push_str(&pct_encode(&cfg.dmarc_imap_folder));
    }
    u
}

/// The curl config lines, the login included: kept off argv.
pub fn config_lines(cfg: &Config) -> Vec<String> {
    let mut l = vec![format!(
        "user = \"{}\"",
        esc(&format!("{}:{}", cfg.dmarc_imap_user, cfg.dmarc_imap_pass))
    )];
    if !cfg.dmarc_imap_tls {
        l.push("ssl-reqd".into()); // STARTTLS, never plaintext logins
    }
    if !cfg.dmarc_imap_verify {
        l.push("insecure".into());
    }
    l
}

/// What curl said, for the UI transcript and error texts.
fn curl_error(code: Option<i32>, stderr: &str) -> String {
    let hint = match code {
        Some(6) => "cannot resolve the IMAP host",
        Some(7) => "cannot connect to the IMAP server (host, port, firewall)",
        Some(28) => "the IMAP server did not answer in time",
        Some(35) | Some(60) => "TLS failed (certificate or TLS mode — try the other TLS setting, or turn off verification for localhost)",
        Some(64) => "the server does not offer STARTTLS",
        Some(67) => "login refused: check the user and password",
        Some(78) => "folder not found",
        Some(8) => "the server's reply could not be read",
        _ => "IMAP command failed",
    };
    let detail = stderr
        .lines()
        .rfind(|l| l.starts_with("curl:"))
        .unwrap_or("")
        .trim();
    if detail.is_empty() {
        hint.to_string()
    } else {
        format!("{hint} — {detail}")
    }
}

/// Run one IMAP command; returns curl's stdout (the untagged responses).
fn run(cfg: &Config, folder: bool, command: &str, max_secs: u32) -> Result<Vec<u8>, String> {
    run_url(cfg, &url(cfg, folder), Some(command), max_secs)
}

/// curl ≥ 7.62 fetches `;UID=n` by UID; older ones by sequence number.
/// `MSFE_NG_CURL_SEQFETCH=1` forces the old behaviour (tests).
fn uid_urls() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        if std::env::var("MSFE_NG_CURL_SEQFETCH").is_ok_and(|v| v == "1") {
            return false;
        }
        let out = Command::new("curl")
            .arg("-V")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default();
        curl_at_least(&String::from_utf8_lossy(&out), 7, 62)
    })
}

/// `curl 7.61.1 (x86_64-redhat-linux-gnu) …` → whether it is ≥ major.minor.
pub fn curl_at_least(version_output: &str, major: u32, minor: u32) -> bool {
    let v = version_output.split_whitespace().nth(1).unwrap_or("");
    let mut it = v.split('.').map(|n| n.parse::<u32>().unwrap_or(0));
    let (a, b) = (it.next().unwrap_or(0), it.next().unwrap_or(0));
    (a, b) >= (major, minor)
}

fn run_url(
    cfg: &Config,
    url: &str,
    command: Option<&str>,
    max_secs: u32,
) -> Result<Vec<u8>, String> {
    validate(cfg)?;
    let path = std::env::temp_dir().join(format!(
        "msfe-ng-imap-{}-{}.cfg",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let write = || -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        for l in config_lines(cfg) {
            writeln!(f, "{l}")?;
        }
        Ok(())
    };
    write().map_err(|e| format!("cannot write curl config: {e}"))?;
    let _guard = CurlConfig(path.clone());
    let mut cmd = Command::new("curl");
    cmd.arg("-sS")
        .arg("--connect-timeout")
        .arg("15")
        .arg("--max-time")
        .arg(max_secs.to_string())
        .arg("-K")
        .arg(&path);
    if let Some(c) = command {
        cmd.arg("-X").arg(c);
    }
    let out = cmd
        .arg(url)
        .output()
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if !out.status.success() {
        return Err(curl_error(
            out.status.code(),
            &String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(out.stdout)
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    pub messages: u64,
    pub uidvalidity: u64,
}

/// `* STATUS "INBOX" (MESSAGES 3 UIDVALIDITY 17)` → numbers.
pub fn parse_status(out: &str) -> Option<Status> {
    let line = out.lines().find(|l| l.starts_with("* STATUS"))?;
    let inner =
        line[line.rfind('(')? + 1..].trim_end_matches(|c: char| c == ')' || c.is_whitespace());
    let mut s = Status::default();
    let toks: Vec<&str> = inner.split_whitespace().collect();
    for w in toks.chunks(2) {
        if let [k, v] = w {
            match k.to_ascii_uppercase().as_str() {
                "MESSAGES" => s.messages = v.parse().ok()?,
                "UIDVALIDITY" => s.uidvalidity = v.parse().ok()?,
                _ => {}
            }
        }
    }
    Some(s)
}

/// `* SEARCH 4 7 9` → UIDs (several SEARCH lines are joined).
pub fn parse_search(out: &str) -> Vec<u32> {
    out.lines()
        .filter_map(|l| l.strip_prefix("* SEARCH"))
        .flat_map(|r| {
            r.split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect::<Vec<u32>>()
        })
        .collect()
}

/// `* 3 FETCH (UID 9 RFC822.SIZE 1234)` → 1234.
pub fn parse_size(out: &str) -> Option<usize> {
    let l = out.lines().find(|l| l.contains("FETCH"))?;
    let i = l.find("RFC822.SIZE ")? + "RFC822.SIZE ".len();
    l[i..]
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn uid_set(uids: &[u32]) -> String {
    uids.iter()
        .map(|u| u.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Message count and UIDVALIDITY of the report folder.
pub fn status(cfg: &Config) -> Result<Status, String> {
    let cmd = format!(
        "STATUS \"{}\" (MESSAGES UIDVALIDITY)",
        cfg.dmarc_imap_folder
    );
    let out = run(cfg, false, &cmd, 30)?;
    parse_status(&String::from_utf8_lossy(&out))
        .ok_or_else(|| "the server gave no STATUS answer".into())
}

pub fn uids(cfg: &Config) -> Result<Vec<u32>, String> {
    let out = run(cfg, true, "UID SEARCH ALL", 60)?;
    Ok(parse_search(&String::from_utf8_lossy(&out)))
}

/// One whole message. `seq` is its position in the folder (1-based, from
/// the ascending UID list), used only with curl older than 7.62.
pub fn fetch(cfg: &Config, uid: u32, seq: u32) -> Result<Vec<u8>, String> {
    let base = url(cfg, true);
    if uid_urls() {
        let m = run_url(cfg, &format!("{base};UID={uid}"), None, 120)?;
        return if m.is_empty() {
            Err(format!("message UID {uid} not returned"))
        } else {
            Ok(m)
        };
    }
    let m = run_url(cfg, &format!("{base};UID={seq}"), None, 120)?;
    let size = run(cfg, true, &format!("UID FETCH {uid} (RFC822.SIZE)"), 60)?;
    match parse_size(&String::from_utf8_lossy(&size)) {
        Some(n) if n == m.len() => Ok(m),
        Some(n) => Err(format!(
            "message {seq} is {} bytes but UID {uid} is {n}: the folder changed during the fetch, retried next run",
            m.len()
        )),
        None => Err(format!("message UID {uid} is gone")),
    }
}

pub fn mark_seen(cfg: &Config, uids: &[u32]) -> Result<(), String> {
    if uids.is_empty() {
        return Ok(());
    }
    run(
        cfg,
        true,
        &format!("UID STORE {} +FLAGS.SILENT (\\Seen)", uid_set(uids)),
        60,
    )
    .map(|_| ())
}

/// Flag as \Deleted and expunge: gone from the mailbox.
pub fn delete(cfg: &Config, uids: &[u32]) -> Result<(), String> {
    if uids.is_empty() {
        return Ok(());
    }
    run(
        cfg,
        true,
        &format!("UID STORE {} +FLAGS.SILENT (\\Deleted)", uid_set(uids)),
        60,
    )?;
    run(cfg, true, "EXPUNGE", 60).map(|_| ())
}

/// The Config tab's "Test connection": log in, look at the folder.
pub fn test(cfg: &Config) -> (bool, Vec<String>) {
    let mut t = vec![format!(
        "▶ {} as {} ({}{})",
        url(cfg, true),
        cfg.dmarc_imap_user,
        if cfg.dmarc_imap_tls {
            "TLS"
        } else {
            "STARTTLS"
        },
        if cfg.dmarc_imap_verify {
            ""
        } else {
            ", certificate not verified"
        }
    )];
    match status(cfg) {
        Ok(s) => {
            t.push(format!(
                "✓ logged in; folder {} holds {} message(s) (UIDVALIDITY {})",
                cfg.dmarc_imap_folder, s.messages, s.uidvalidity
            ));
            (true, t)
        }
        Err(e) => {
            t.push(format!("✗ {e}"));
            (false, t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config {
            dmarc_imap_host: "mail.example.net".into(),
            dmarc_imap_user: "dmarc@example.net".into(),
            dmarc_imap_pass: "p\"w\\d".into(),
            dmarc_imap_folder: "DMARC Reports".into(),
            ..Config::default()
        }
    }

    #[test]
    fn urls_and_login_lines() {
        let mut c = cfg();
        assert_eq!(
            url(&c, true),
            "imaps://mail.example.net:993/DMARC%20Reports"
        );
        assert_eq!(url(&c, false), "imaps://mail.example.net:993/");
        assert_eq!(
            config_lines(&c),
            vec!["user = \"dmarc@example.net:p\\\"w\\\\d\"".to_string()]
        );
        c.dmarc_imap_tls = false;
        c.dmarc_imap_port = 143;
        c.dmarc_imap_verify = false;
        assert_eq!(url(&c, true), "imap://mail.example.net:143/DMARC%20Reports");
        assert_eq!(
            config_lines(&c)[1..],
            ["ssl-reqd".to_string(), "insecure".to_string()]
        );
    }

    #[test]
    fn validation() {
        assert!(validate(&cfg()).is_ok());
        let mut c = cfg();
        c.dmarc_imap_host = "evil host/x".into();
        assert!(validate(&c).is_err());
        let mut c = cfg();
        c.dmarc_imap_folder = "INBOX\"\r\nA1 LOGOUT".into();
        assert!(validate(&c).is_err());
        let mut c = cfg();
        c.dmarc_imap_pass.clear();
        assert!(validate(&c).is_err());
    }

    #[test]
    fn parses_responses() {
        assert_eq!(
            parse_status("* STATUS \"INBOX\" (MESSAGES 3 UIDVALIDITY 1712345)\r\n"),
            Some(Status {
                messages: 3,
                uidvalidity: 1712345
            })
        );
        assert_eq!(
            parse_status("* STATUS INBOX (UIDVALIDITY 9 MESSAGES 0)"),
            Some(Status {
                messages: 0,
                uidvalidity: 9
            })
        );
        assert_eq!(parse_status("nothing"), None);
        assert_eq!(parse_search("* SEARCH 4 7 19\r\n"), vec![4, 7, 19]);
        assert_eq!(parse_search("* SEARCH\r\n"), Vec::<u32>::new());
        assert_eq!(
            parse_size("* 2 FETCH (UID 7 RFC822.SIZE 1234)\r\n"),
            Some(1234)
        );
        assert_eq!(parse_size("* 2 FETCH (RFC822.SIZE 55 UID 7)"), Some(55));
        assert_eq!(parse_size(""), None);
        assert!(curl_at_least(
            "curl 7.76.1 (x86_64-redhat-linux-gnu) libcurl/7.76.1",
            7,
            62
        ));
        assert!(curl_at_least("curl 8.2.0 (x)", 7, 62));
        assert!(!curl_at_least(
            "curl 7.61.1 (x86_64-redhat-linux-gnu)",
            7,
            62
        ));
        assert!(!curl_at_least("", 7, 62));
    }

    #[test]
    fn curl_errors_read_well() {
        assert!(curl_error(Some(67), "curl: (67) Login denied\n").starts_with("login refused"));
        assert!(
            curl_error(Some(67), "curl: (67) Login denied\n").ends_with("curl: (67) Login denied")
        );
        assert_eq!(curl_error(Some(99), ""), "IMAP command failed");
    }
}
