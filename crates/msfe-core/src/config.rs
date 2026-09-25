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
    /// Fallback custom-functions directory, used only when MailScanner.conf has
    /// no `Custom Functions Dir` (the plugin installs where MailScanner loads from).
    pub mailscanner_custom_dir: String,
    /// MailScanner ruleset directory that `sync` writes the managed rules into.
    pub mailscanner_rules_dir: String,
    /// Standalone SpamBox Exim fragment file (`.include_if_exists`-ed by Exim).
    pub spambox_conf: String,
    /// MailScanner quarantine spool directory (for the user quarantine viewer).
    pub quarantine_dir: String,
    /// Where `Archive Mail` copies of scanned messages land
    /// (`<dir>/<YYYYMMDD>/<message-id>`), backing the message content view.
    pub archive_dir: String,
    /// Mail log file watched by the admin Service tab.
    pub maillog_path: String,
    /// Exim main log (cPanel: /var/log/exim_mainlog), also viewable there.
    pub exim_mainlog_path: String,
    /// Exim ACL fragment that routes mail into the MailScanner named queue
    /// (written by `engine wire`; its absence = direct delivery).
    pub mailscannerq_conf: String,
    /// Geolocation lookup URL for the client-IP modal, `{ip}` substituted.
    /// Empty disables lookups (the address is sent to this third party).
    pub geoip_url: String,
    // ---- delivery test --------------------------------------------------------
    /// Diagnostic runs allowed per minute (daemon-wide).
    pub delivery_runs_per_min: u32,
    /// A finished report is served again for this long (seconds).
    pub delivery_cache_secs: u64,
    /// Days of Exim logs the server audit scans by default (1–7).
    pub delivery_log_days: u32,
    pub delivery_max_monitors: u32,
    /// The EHLO name the probes introduce themselves with; empty = hostname -f.
    pub delivery_helo: String,
    // ---- interface & release preferences (MailControl-style settings) --------
    /// Messages tab auto-refresh interval in seconds (0 = off).
    pub refresh_secs: u32,
    /// Rows per page in the message list.
    pub rows_per_page: u32,
    /// Open a message's full view in a new browser window/tab.
    pub view_new_window: bool,
    /// Subject for forwarded (release-forward) mail; empty = keep the original.
    pub forward_subject: String,
    /// Plain-text line prepended to forwarded mail; empty = none.
    pub forward_body: String,
    /// Default reason recorded in csf.deny when blocking an IP from the UI.
    pub csf_comment_default: String,
    /// Envelope/From address used when releasing mail; empty = postmaster@<host>.
    pub release_from: String,
    /// SpamCop submission address; empty disables the "Report to SpamCop" action.
    pub spamcop_address: String,
    /// Local delivery agent for release-to-INBOX.
    pub dovecot_lda: String,
    /// Update maillog isfp/isfn/isspam when Learn as ham/spam is used.
    pub learn_updates_db: bool,
    /// Directory for database/Bayes backups.
    pub backup_dir: String,

    // ---- queue auto-clean (delivery queue only; every rule ships OFF) --------
    /// Remove frozen messages older than N hours (0 = off).
    pub queue_clean_frozen_hours: u32,
    /// Remove null-sender (bounce) messages older than N hours (0 = off).
    pub queue_clean_bounce_hours: u32,
    /// Remove messages whose spool spam score is at least this (0 = off).
    pub queue_clean_spam_score: f64,

    /// The admin keeps cPanel's own ClamAV pass in Exim (exiscan) on purpose:
    /// the doctor's double-virus-scan notice becomes a plain OK line.
    pub accept_exiscan: bool,

    // ---- auto-ban of spam sources in csf (every rule ships OFF) --------------
    /// Ban an IP after `autoban_high_count` high-spam messages within
    /// `autoban_high_window_secs`, for `autoban_high_ban_secs`.
    pub autoban_high_enabled: bool,
    pub autoban_high_count: u32,
    pub autoban_high_window_secs: u64,
    pub autoban_high_ban_secs: u64,
    /// The same for (low-scoring) spam.
    pub autoban_spam_enabled: bool,
    pub autoban_spam_count: u32,
    pub autoban_spam_window_secs: u64,
    pub autoban_spam_ban_secs: u64,
    /// One Telegram line per auto-ban (when Telegram is configured).
    pub autoban_telegram: bool,

    // ---- Telegram alerts (empty token disables everything) -------------------
    /// Telegram bot token (from @BotFather). Secret: never exposed via the API.
    pub telegram_bot_token: String,
    /// Telegram chat id the alerts are sent to.
    pub telegram_chat_id: String,
    /// AbuseIPDB API key, for manual reports from the client-IP view.
    /// Secret: never exposed via the API (only `abuseipdb_configured`).
    pub abuseipdb_key: String,
    /// Alert when the delivery queue holds at least this many messages (0 = off).
    pub alert_queue_size: u32,
    /// Alert when the oldest scanning-queue message is at least N minutes old (0 = off).
    pub alert_scan_stuck_mins: u32,
    /// Alert when one authenticated account sends at least N messages/hour (0 = off).
    pub alert_burst_per_hour: u32,
    /// Minimum minutes between repeats of the same alert.
    pub alert_cooldown_mins: u32,
}

/// `true`/`yes`/`1` (case-insensitive) is on; anything else off.
fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "1" | "on"
    )
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
            archive_dir: "/var/spool/MailScanner/archive".into(),
            maillog_path: "/var/log/maillog".into(),
            exim_mainlog_path: "/var/log/exim_mainlog".into(),
            mailscannerq_conf: "/etc/msfe-ng/mailscannerq.conf".into(),
            geoip_url: "https://ipwho.is/{ip}".into(),
            delivery_runs_per_min: 6,
            delivery_cache_secs: 600,
            delivery_log_days: 2,
            delivery_max_monitors: 20,
            delivery_helo: String::new(),
            refresh_secs: 0,
            rows_per_page: 50,
            view_new_window: false,
            forward_subject: String::new(),
            forward_body: String::new(),
            csf_comment_default: String::new(),
            release_from: String::new(),
            spamcop_address: String::new(),
            dovecot_lda: "/usr/libexec/dovecot/dovecot-lda".into(),
            learn_updates_db: true,
            backup_dir: "/opt/msfe-ng/backups".into(),
            queue_clean_frozen_hours: 0,
            queue_clean_bounce_hours: 0,
            queue_clean_spam_score: 0.0,
            accept_exiscan: false,
            autoban_high_enabled: false,
            autoban_high_count: 1,
            autoban_high_window_secs: 600,
            autoban_high_ban_secs: 86_400,
            autoban_spam_enabled: false,
            autoban_spam_count: 3,
            autoban_spam_window_secs: 3_600,
            autoban_spam_ban_secs: 7_200,
            autoban_telegram: true,
            telegram_bot_token: String::new(),
            telegram_chat_id: String::new(),
            abuseipdb_key: String::new(),
            alert_queue_size: 0,
            alert_scan_stuck_mins: 0,
            alert_burst_per_hour: 0,
            alert_cooldown_mins: 60,
        }
    }
}

/// Where MailScanner.conf lives, in preference order: the MailScanner RPM's,
/// then ConfigServer's bundled tree.
pub const MS_CONF_CANDIDATES: [&str; 2] = [
    "/etc/MailScanner/MailScanner.conf",
    "/usr/mailscanner/etc/MailScanner.conf",
];

impl Config {
    /// Load config from `path`, falling back to defaults for anything absent,
    /// then follow the engine actually installed (see `resolve_engine_paths`).
    pub fn load(path: &Path) -> Config {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut c = Config::from_toml_str(&text);
        c.resolve_engine_paths(&MS_CONF_CANDIDATES);
        c
    }

    /// Follow the engine that is really installed: when the `mailscanner_conf`
    /// file does not exist, take the first existing candidate (ConfigServer
    /// keeps its conf under /usr/mailscanner, where the RPM default never
    /// exists — and after that tree is decommissioned, the RPM's is the one
    /// left); when `mailscanner_rules_dir` is still the default, use the
    /// conf's own `%rules-dir%` — rules written anywhere else are never read.
    /// A conf that exists, or an explicit rules dir, is always respected.
    pub fn resolve_engine_paths(&mut self, candidates: &[&str]) {
        if !Path::new(&self.mailscanner_conf).is_file() {
            if let Some(c) = candidates.iter().find(|c| Path::new(c).is_file()) {
                self.mailscanner_conf = c.to_string();
            }
        }
        if self.mailscanner_rules_dir == Config::default().mailscanner_rules_dir {
            let text = std::fs::read_to_string(&self.mailscanner_conf).unwrap_or_default();
            if let Some(dir) = crate::mailscanner::variable(&text, "%rules-dir%") {
                self.mailscanner_rules_dir = dir;
            }
        }
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
                "archive_dir" => c.archive_dir = v,
                "maillog_path" => c.maillog_path = v,
                "exim_mainlog_path" => c.exim_mainlog_path = v,
                "mailscannerq_conf" => c.mailscannerq_conf = v,
                "geoip_url" => c.geoip_url = v,
                "delivery_runs_per_min" => {
                    c.delivery_runs_per_min = v.parse().unwrap_or(6).clamp(1, 60)
                }
                "delivery_cache_secs" => c.delivery_cache_secs = v.parse().unwrap_or(600),
                "delivery_log_days" => c.delivery_log_days = v.parse().unwrap_or(2).clamp(1, 7),
                "delivery_max_monitors" => c.delivery_max_monitors = v.parse().unwrap_or(20),
                "delivery_helo" => c.delivery_helo = v,
                "refresh_secs" => c.refresh_secs = v.parse().unwrap_or(0),
                "rows_per_page" => c.rows_per_page = v.parse().unwrap_or(50).clamp(10, 500),
                "view_new_window" => c.view_new_window = v == "yes" || v == "true" || v == "1",
                "forward_subject" => c.forward_subject = v,
                "forward_body" => c.forward_body = v,
                "csf_comment_default" => c.csf_comment_default = v,
                "release_from" => c.release_from = v,
                "spamcop_address" => c.spamcop_address = v,
                "dovecot_lda" => c.dovecot_lda = v,
                "learn_updates_db" => c.learn_updates_db = v != "no" && v != "false" && v != "0",
                "backup_dir" => c.backup_dir = v,
                "queue_clean_frozen_hours" => c.queue_clean_frozen_hours = v.parse().unwrap_or(0),
                "queue_clean_bounce_hours" => c.queue_clean_bounce_hours = v.parse().unwrap_or(0),
                "queue_clean_spam_score" => c.queue_clean_spam_score = v.parse().unwrap_or(0.0),
                "accept_exiscan" => c.accept_exiscan = truthy(&v),
                "autoban_high_enabled" => c.autoban_high_enabled = truthy(&v),
                "autoban_high_count" => c.autoban_high_count = v.parse().unwrap_or(1).max(1),
                "autoban_high_window_secs" => c.autoban_high_window_secs = v.parse().unwrap_or(600),
                "autoban_high_ban_secs" => c.autoban_high_ban_secs = v.parse().unwrap_or(86_400),
                "autoban_spam_enabled" => c.autoban_spam_enabled = truthy(&v),
                "autoban_spam_count" => c.autoban_spam_count = v.parse().unwrap_or(3).max(1),
                "autoban_spam_window_secs" => {
                    c.autoban_spam_window_secs = v.parse().unwrap_or(3_600)
                }
                "autoban_spam_ban_secs" => c.autoban_spam_ban_secs = v.parse().unwrap_or(7_200),
                "autoban_telegram" => c.autoban_telegram = truthy(&v),
                "telegram_bot_token" => c.telegram_bot_token = v,
                "telegram_chat_id" => c.telegram_chat_id = v,
                "abuseipdb_key" => c.abuseipdb_key = v,
                "alert_queue_size" => c.alert_queue_size = v.parse().unwrap_or(0),
                "alert_scan_stuck_mins" => c.alert_scan_stuck_mins = v.parse().unwrap_or(0),
                "alert_burst_per_hour" => c.alert_burst_per_hour = v.parse().unwrap_or(0),
                "alert_cooldown_mins" => c.alert_cooldown_mins = v.parse().unwrap_or(60),
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
            (
                "mailscanner_rules_dir".into(),
                Json::str(&self.mailscanner_rules_dir),
            ),
            ("db_configured".into(), Json::Bool(self.db_configured())),
            ("refresh_secs".into(), Json::Int(self.refresh_secs as i64)),
            ("rows_per_page".into(), Json::Int(self.rows_per_page as i64)),
            ("view_new_window".into(), Json::Bool(self.view_new_window)),
            ("forward_subject".into(), Json::str(&self.forward_subject)),
            ("forward_body".into(), Json::str(&self.forward_body)),
            (
                "csf_comment_default".into(),
                Json::str(&self.csf_comment_default),
            ),
            ("release_from".into(), Json::str(&self.release_from)),
            ("spamcop_address".into(), Json::str(&self.spamcop_address)),
            ("learn_updates_db".into(), Json::Bool(self.learn_updates_db)),
            ("backup_dir".into(), Json::str(&self.backup_dir)),
            (
                "delivery_runs_per_min".into(),
                Json::Int(self.delivery_runs_per_min as i64),
            ),
            (
                "delivery_cache_secs".into(),
                Json::Int(self.delivery_cache_secs as i64),
            ),
            (
                "delivery_log_days".into(),
                Json::Int(self.delivery_log_days as i64),
            ),
            (
                "delivery_max_monitors".into(),
                Json::Int(self.delivery_max_monitors as i64),
            ),
            ("delivery_helo".into(), Json::str(&self.delivery_helo)),
            (
                "queue_clean_frozen_hours".into(),
                Json::Int(self.queue_clean_frozen_hours as i64),
            ),
            (
                "queue_clean_bounce_hours".into(),
                Json::Int(self.queue_clean_bounce_hours as i64),
            ),
            (
                "queue_clean_spam_score".into(),
                Json::Num(format!("{}", self.queue_clean_spam_score)),
            ),
            ("accept_exiscan".into(), Json::Bool(self.accept_exiscan)),
            (
                "autoban_high_enabled".into(),
                Json::Bool(self.autoban_high_enabled),
            ),
            (
                "autoban_high_count".into(),
                Json::Int(self.autoban_high_count as i64),
            ),
            (
                "autoban_high_window_secs".into(),
                Json::Int(self.autoban_high_window_secs as i64),
            ),
            (
                "autoban_high_ban_secs".into(),
                Json::Int(self.autoban_high_ban_secs as i64),
            ),
            (
                "autoban_spam_enabled".into(),
                Json::Bool(self.autoban_spam_enabled),
            ),
            (
                "autoban_spam_count".into(),
                Json::Int(self.autoban_spam_count as i64),
            ),
            (
                "autoban_spam_window_secs".into(),
                Json::Int(self.autoban_spam_window_secs as i64),
            ),
            (
                "autoban_spam_ban_secs".into(),
                Json::Int(self.autoban_spam_ban_secs as i64),
            ),
            ("autoban_telegram".into(), Json::Bool(self.autoban_telegram)),
            // the bot token is a secret: expose only whether it is set
            (
                "telegram_configured".into(),
                Json::Bool(
                    !self.telegram_bot_token.is_empty() && !self.telegram_chat_id.is_empty(),
                ),
            ),
            ("telegram_chat_id".into(), Json::str(&self.telegram_chat_id)),
            // the AbuseIPDB key is a secret too
            (
                "abuseipdb_configured".into(),
                Json::Bool(!self.abuseipdb_key.trim().is_empty()),
            ),
            (
                "alert_queue_size".into(),
                Json::Int(self.alert_queue_size as i64),
            ),
            (
                "alert_scan_stuck_mins".into(),
                Json::Int(self.alert_scan_stuck_mins as i64),
            ),
            (
                "alert_burst_per_hour".into(),
                Json::Int(self.alert_burst_per_hour as i64),
            ),
            (
                "alert_cooldown_mins".into(),
                Json::Int(self.alert_cooldown_mins as i64),
            ),
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

    fn fake_engine(tag: &str) -> (std::path::PathBuf, String, String) {
        let base = std::env::temp_dir().join(format!("msfe-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("usr/mailscanner/etc");
        std::fs::create_dir_all(&etc).unwrap();
        let conf = etc.join("MailScanner.conf");
        let rules = etc.join("rules").display().to_string();
        std::fs::write(
            &conf,
            format!(
                "%etc-dir% = {}\n%rules-dir% = {rules}\nMTA = exim\n",
                etc.display()
            ),
        )
        .unwrap();
        (base, conf.display().to_string(), rules)
    }

    #[test]
    fn follows_the_engine_conf_when_the_default_is_missing() {
        let (base, conf, rules) = fake_engine("follow");
        let missing = base.join("etc/MailScanner/MailScanner.conf");
        let mut c = Config::default();
        c.resolve_engine_paths(&[&missing.display().to_string(), &conf]);
        assert_eq!(c.mailscanner_conf, conf);
        assert_eq!(
            c.mailscanner_rules_dir, rules,
            "rules dir follows %rules-dir%"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn keeps_an_existing_conf_and_an_explicit_rules_dir() {
        let (base, conf, _) = fake_engine("explicit");
        let mine = base.join("mine.conf");
        std::fs::write(&mine, "%rules-dir% = /theirs\n").unwrap();
        let mut c = Config::from_toml_str(&format!(
            "mailscanner_conf = \"{}\"\nmailscanner_rules_dir = \"/my/rules\"\n",
            mine.display()
        ));
        c.resolve_engine_paths(&[&conf]);
        assert_eq!(c.mailscanner_conf, mine.display().to_string());
        assert_eq!(c.mailscanner_rules_dir, "/my/rules");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_configured_conf_that_is_gone_falls_back_to_the_engine_left() {
        // the ConfigServer tree was decommissioned; config.toml still names it
        let (base, conf, rules) = fake_engine("gone");
        let mut c = Config::from_toml_str(&format!(
            "mailscanner_conf = \"{}\"\n",
            base.join("usr/mailscanner-removed/etc/MailScanner.conf")
                .display()
        ));
        c.resolve_engine_paths(&[&conf]);
        assert_eq!(c.mailscanner_conf, conf);
        assert_eq!(c.mailscanner_rules_dir, rules);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn default_rules_dir_stays_when_the_conf_defines_none() {
        let (base, conf, _) = fake_engine("norules");
        std::fs::write(&conf, "MTA = exim\n").unwrap();
        let mut c = Config::default();
        c.resolve_engine_paths(&[&conf]);
        assert_eq!(c.mailscanner_conf, conf);
        assert_eq!(c.mailscanner_rules_dir, "/etc/MailScanner/rules");
        let _ = std::fs::remove_dir_all(&base);
    }
}
