//! One-click first-run setup, driven from the WHM dashboard: provision the
//! MySQL database (create DB + user with a generated password as the local
//! MySQL root, store credentials in config.toml, apply migrations) and enable
//! per-message logging (install the MailScanner plugin + directive).
//!
//! Works because both the daemon and cPanel's MySQL grant root passwordless
//! local access (unix-socket auth).

use crate::{conffile, db, mailscanner, migrate, service, Config};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

pub struct SetupStatus {
    /// config.toml has database credentials.
    pub db_configured: bool,
    /// The configured credentials actually connect.
    pub db_ready: bool,
    /// Logging plugin installed and hooked into MailScanner.conf.
    pub logging_enabled: bool,
}

pub fn status(cfg: &Config) -> SetupStatus {
    let db_configured = !cfg.db_pass.is_empty();
    let db_ready = db_configured && db::query(cfg, "SELECT 1").is_ok();
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let logging_enabled = mailscanner::get_directive(&conf, mailscanner::LOGGING_DIRECTIVE)
        == Some(mailscanner::LOGGING_VALUE)
        && Path::new(&cfg.mailscanner_custom_dir)
            .join(msfe_api::MS_PLUGIN_FILENAME)
            .exists();
    SetupStatus {
        db_configured,
        db_ready,
        logging_enabled,
    }
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// 48 hex chars from the kernel RNG.
fn generate_password() -> io::Result<String> {
    use std::io::Read;
    let mut buf = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Run SQL as the local MySQL root (unix-socket auth) via stdin.
fn mysql_root(sql: &str) -> io::Result<()> {
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

/// Provision the database end to end. Returns a human-readable transcript.
pub fn setup_database(cfg: &Config, config_file: &Path) -> io::Result<Vec<String>> {
    let mut log = Vec::new();
    if !valid_ident(&cfg.db_name) || !valid_ident(&cfg.db_user) {
        return Err(io::Error::other("db_name/db_user must be alphanumeric"));
    }

    // Reuse existing credentials when they already work; otherwise (re)create
    // the DB + user with a fresh generated password.
    let mut eff = cfg.clone();
    if cfg.db_pass.is_empty() || db::query(cfg, "SELECT 1").is_err() {
        mysql_root("SELECT 1")
            .map_err(|e| io::Error::other(format!("cannot administer MySQL as root: {e}")))?;
        let pass = generate_password()?;
        let sql = format!(
            "CREATE DATABASE IF NOT EXISTS `{db}` CHARACTER SET utf8mb4;\n\
             CREATE USER IF NOT EXISTS '{u}'@'localhost' IDENTIFIED BY '{p}';\n\
             ALTER USER '{u}'@'localhost' IDENTIFIED BY '{p}';\n\
             GRANT ALL PRIVILEGES ON `{db}`.* TO '{u}'@'localhost';\n\
             FLUSH PRIVILEGES;\n",
            db = cfg.db_name,
            u = cfg.db_user,
            p = pass
        );
        mysql_root(&sql)?;
        log.push(format!(
            "created database `{}` and user '{}'@'localhost' (generated password)",
            cfg.db_name, cfg.db_user
        ));

        // Persist credentials into config.toml, preserving comments.
        let text = std::fs::read_to_string(config_file)?;
        let changes = vec![
            ("db_host".to_string(), "localhost".to_string()),
            ("db_name".to_string(), cfg.db_name.clone()),
            ("db_user".to_string(), cfg.db_user.clone()),
            ("db_pass".to_string(), pass.clone()),
        ];
        let (new_text, _) = conffile::apply(&text, &changes, conffile::Style::Toml);
        service::save_conf(config_file, &new_text)?;
        log.push(format!("credentials saved to {}", config_file.display()));
        eff.db_host = "localhost".into();
        eff.db_pass = pass;
    } else {
        log.push("existing database credentials work — reusing them".into());
    }

    // Apply pending migrations.
    let mig_dir = std::env::var("MSFE_NG_MIGRATIONS")
        .unwrap_or_else(|_| msfe_api::DEFAULT_MIGRATIONS_DIR.to_string());
    let all = migrate::discover(Path::new(&mig_dir))?;
    let applied = migrate::applied_versions(&eff).unwrap_or_default();
    let pending = migrate::pending(&all, &applied);
    if pending.is_empty() {
        log.push("schema up to date (no pending migrations)".into());
    } else {
        for m in &pending {
            migrate::apply(&eff, m)?;
            log.push(format!("applied migration {}", m.name));
        }
    }
    Ok(log)
}

/// Install the logging plugin, hook the directive, restart MailScanner.
pub fn enable_logging(cfg: &Config) -> io::Result<Vec<String>> {
    let mut log = Vec::new();
    let dst = Path::new(&cfg.mailscanner_custom_dir).join(msfe_api::MS_PLUGIN_FILENAME);
    let src = std::env::var("MSFE_NG_MS_PLUGIN_SRC")
        .unwrap_or_else(|_| msfe_api::DEFAULT_MS_PLUGIN_SRC.to_string());
    std::fs::create_dir_all(&cfg.mailscanner_custom_dir)?;
    std::fs::copy(&src, &dst)?;
    log.push(format!("installed logging plugin to {}", dst.display()));

    let conf_path = Path::new(&cfg.mailscanner_conf);
    let text = std::fs::read_to_string(conf_path)?;
    let new_text = mailscanner::set_directive(
        &text,
        mailscanner::LOGGING_DIRECTIVE,
        mailscanner::LOGGING_VALUE,
    );
    if new_text != text {
        service::save_conf(conf_path, &new_text)?;
        log.push(format!(
            "set {} = {}",
            mailscanner::LOGGING_DIRECTIVE,
            mailscanner::LOGGING_VALUE
        ));
    }
    let o = service::control("restart");
    log.push(format!(
        "restarted MailScanner: {}",
        if o.ok {
            "ok"
        } else {
            "FAILED (restart it manually)"
        }
    ));
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_validation() {
        assert!(valid_ident("msfe_ng"));
        assert!(!valid_ident(""));
        assert!(!valid_ident("bad-name"));
        assert!(!valid_ident("x; DROP TABLE"));
    }

    #[test]
    fn password_is_long_hex() {
        let p = generate_password().unwrap();
        assert_eq!(p.len(), 48);
        assert!(p.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}
