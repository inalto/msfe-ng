//! Runtime configuration loaded from `/etc/msfe-ng/config.toml`.
//!
//! We parse a tiny, flat subset of TOML (dependency-free): `key = value` lines,
//! optional `"quotes"`, `#` comments, and `[section]` headers are ignored (keys
//! are flat). This is enough for M1; a real TOML crate can replace it later.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct Config {
    pub panel: String,
    pub socket: String,
    pub webroot: String,
    pub db_host: String,
    pub db_port: u16,
    pub db_name: String,
    pub db_user: String,
    pub db_pass: String,
    /// Path to the live MailScanner.conf (for opt-in logging enable/disable).
    pub mailscanner_conf: String,
    /// MailScanner custom-functions directory (where the logging plugin installs).
    pub mailscanner_custom_dir: String,
    /// MailScanner ruleset directory that `sync` writes the managed rules into.
    pub mailscanner_rules_dir: String,
    /// Standalone SpamBox Exim fragment file (`.include_if_exists`-ed by Exim).
    pub spambox_conf: String,
    /// MailScanner quarantine spool directory (for the user quarantine viewer).
    pub quarantine_dir: String,
    /// Mail log file watched by the admin Service tab.
    pub maillog_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            panel: "none".into(),
            socket: msfe_api::DEFAULT_SOCKET_PATH.into(),
            webroot: "/opt/msfe-ng/web".into(),
            db_host: "localhost".into(),
            db_port: 3306,
            db_name: "msfe_ng".into(),
            db_user: "msfe_ng".into(),
            db_pass: String::new(),
            mailscanner_conf: "/etc/MailScanner/MailScanner.conf".into(),
            mailscanner_custom_dir: "/etc/MailScanner/custom".into(),
            mailscanner_rules_dir: "/etc/MailScanner/rules".into(),
            spambox_conf: "/etc/msfe-ng/spambox.exim".into(),
            quarantine_dir: "/var/spool/MailScanner/quarantine".into(),
            maillog_path: "/var/log/maillog".into(),
        }
    }
}

impl Config {
    /// Load config from `path`, falling back to defaults for anything absent.
    pub fn load(path: &Path) -> Config {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        Config::from_toml_str(&text)
    }

    pub fn from_toml_str(text: &str) -> Config {
        let mut c = Config::default();
        for (k, v) in parse_flat(text) {
            match k.as_str() {
                "panel" => c.panel = v,
                "socket" => c.socket = v,
                "webroot" => c.webroot = v,
                "db_host" => c.db_host = v,
                "db_port" => {
                    if let Ok(n) = v.parse() {
                        c.db_port = n;
                    }
                }
                "db_name" => c.db_name = v,
                "db_user" => c.db_user = v,
                "db_pass" => c.db_pass = v,
                "mailscanner_conf" => c.mailscanner_conf = v,
                "mailscanner_custom_dir" => c.mailscanner_custom_dir = v,
                "mailscanner_rules_dir" => c.mailscanner_rules_dir = v,
                "spambox_conf" => c.spambox_conf = v,
                "quarantine_dir" => c.quarantine_dir = v,
                "maillog_path" => c.maillog_path = v,
                _ => {} // unknown keys ignored
            }
        }
        c
    }

    /// True when enough DB fields are set to attempt a connection.
    pub fn db_configured(&self) -> bool {
        !self.db_name.is_empty() && !self.db_user.is_empty()
    }

    /// JSON view with the password redacted (shared by the CLI and daemon API).
    pub fn to_public_json(&self) -> crate::json::Json {
        use crate::json::Json;
        Json::Object(vec![
            ("panel".into(), Json::str(&self.panel)),
            ("socket".into(), Json::str(&self.socket)),
            ("webroot".into(), Json::str(&self.webroot)),
            ("db_host".into(), Json::str(&self.db_host)),
            ("db_port".into(), Json::Int(self.db_port as i64)),
            ("db_name".into(), Json::str(&self.db_name)),
            ("db_user".into(), Json::str(&self.db_user)),
            ("db_pass_set".into(), Json::Bool(!self.db_pass.is_empty())),
            ("mailscanner_conf".into(), Json::str(&self.mailscanner_conf)),
            ("db_configured".into(), Json::Bool(self.db_configured())),
        ])
    }
}

/// Parse `key = value` lines. Strips `#` comments, ignores `[section]` headers,
/// and unquotes `"…"` / `'…'` values.
pub fn parse_flat(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let val = unquote(line[eq + 1..].trim());
            if !key.is_empty() {
                out.push((key, val));
            }
        }
    }
    out
}

/// Strip a `#` comment, but not inside a quoted value.
fn strip_comment(line: &str) -> &str {
    let mut in_s = false;
    let mut in_d = false;
    for (i, ch) in line.char_indices() {
        match ch {
            '\'' if !in_d => in_s = !in_s,
            '"' if !in_s => in_d = !in_d,
            '#' if !in_s && !in_d => return &line[..i],
            _ => {}
        }
    }
    line
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_with_quotes_and_comments() {
        let c = Config::from_toml_str(
            r#"
            # comment
            panel = "cpanel"
            [database]
            db_host = 'db.example'   # inline comment
            db_port = 3307
            db_pass = "p#ss=word"
        "#,
        );
        assert_eq!(c.panel, "cpanel");
        assert_eq!(c.db_host, "db.example");
        assert_eq!(c.db_port, 3307);
        assert_eq!(c.db_pass, "p#ss=word"); // # and = preserved inside quotes
    }

    #[test]
    fn defaults_when_missing() {
        let c = Config::from_toml_str("");
        assert_eq!(c.db_name, "msfe_ng");
        assert!(c.db_configured());
    }
}
