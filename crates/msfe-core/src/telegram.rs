//! Telegram notifications, shelling to `curl` like the rest of the codebase.
//!
//! The bot token is a secret: it goes into a private 0600 curl config file
//! passed via `--config`, never onto argv where `ps` would show it (the same
//! discipline db.rs applies to the MySQL password).

use crate::config::Config;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// True when both the bot token and the chat id are set.
pub fn configured(cfg: &Config) -> bool {
    !cfg.telegram_bot_token.trim().is_empty() && !cfg.telegram_chat_id.trim().is_empty()
}

struct CurlConfig(PathBuf);
impl Drop for CurlConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Send a plain-text message to the configured chat. Returns a human-readable
/// error string (for transcripts) rather than an io::Error chain.
pub fn send(cfg: &Config, text: &str) -> Result<(), String> {
    if !configured(cfg) {
        return Err("Telegram is not configured (bot token / chat id missing)".into());
    }
    let name = format!(
        "msfe-ng-tg-{}-{}.cfg",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let path = std::env::temp_dir().join(name);
    let write = || -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        // curl config format: one option per line, values quoted. data-urlencode
        // handles arbitrary message text; quotes in values are escaped as \".
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        writeln!(
            f,
            "url = \"https://api.telegram.org/bot{}/sendMessage\"\n\
             data-urlencode = \"chat_id={}\"\n\
             data-urlencode = \"text={}\"",
            esc(cfg.telegram_bot_token.trim()),
            esc(cfg.telegram_chat_id.trim()),
            esc(text)
        )
    };
    if let Err(e) = write() {
        return Err(format!("cannot write curl config: {e}"));
    }
    let guard = CurlConfig(path);
    let out = Command::new("curl")
        .args(["-sS", "--max-time", "10", "-A", "msfe-ng", "--config"])
        .arg(&guard.0)
        .output();
    match out {
        Ok(o) => {
            let body = String::from_utf8_lossy(&o.stdout);
            if o.status.success() && body.contains("\"ok\":true") {
                Ok(())
            } else {
                let err = String::from_utf8_lossy(&o.stderr);
                Err(format!(
                    "Telegram API refused the message: {}",
                    if body.trim().is_empty() {
                        err.trim().to_string()
                    } else {
                        body.trim().to_string()
                    }
                ))
            }
        }
        Err(e) => Err(format!("cannot run curl: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_needs_both_fields() {
        let mut cfg = Config::default();
        assert!(!configured(&cfg));
        cfg.telegram_bot_token = "123:abc".into();
        assert!(!configured(&cfg));
        cfg.telegram_chat_id = "-100200300".into();
        assert!(configured(&cfg));
    }

    #[test]
    fn unconfigured_send_fails_without_network() {
        let cfg = Config::default();
        assert!(send(&cfg, "hi").is_err());
    }
}
