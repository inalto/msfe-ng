//! `msfe-ng` — the MSFE-NG command line tool.
//!
//! Used by admins directly and by the installer / cron / panel hooks. M1 adds
//! `import`, `db-migrate`, and `config`. The heavier `sync`/`selftest` remain
//! honest stubs until M2.

use msfe_api::{DEFAULT_CONFIG_FILE, DEFAULT_MIGRATIONS_DIR, DEFAULT_SOCKET_PATH, VERSION};
use msfe_core::config::Config;
use msfe_core::{detect_panel, import_legacy, migrate};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn socket_path() -> String {
    std::env::var("MSFE_NG_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
}
fn config_path() -> PathBuf {
    std::env::var("MSFE_NG_CONFIG")
        .unwrap_or_else(|_| DEFAULT_CONFIG_FILE.to_string())
        .into()
}
fn migrations_dir() -> PathBuf {
    std::env::var("MSFE_NG_MIGRATIONS")
        .unwrap_or_else(|_| DEFAULT_MIGRATIONS_DIR.to_string())
        .into()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "version" | "--version" | "-V" => {
            println!("msfe-ng {VERSION}");
            ExitCode::SUCCESS
        }
        "panel" => {
            let p = detect_panel();
            println!("{}\t{}", p.kind().as_str(), p.display_name());
            ExitCode::SUCCESS
        }
        "health" => cmd_health(),
        "config" => cmd_config(),
        "import" => cmd_import(args.get(1).map(String::as_str)),
        "db-migrate" => cmd_db_migrate(args.get(1).map(String::as_str)),
        "mailscanner" => cmd_mailscanner(args.get(1).map(String::as_str)),
        "sync" => {
            eprintln!("msfe-ng sync: not implemented yet (arrives in M2: rule reconciliation).");
            ExitCode::from(3)
        }
        "selftest" => {
            eprintln!(
                "msfe-ng selftest: not implemented yet (arrives in M2: GTUBE/EICAR/clean mail probe)."
            );
            ExitCode::from(3)
        }
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("msfe-ng: unknown command '{other}'\n");
            print_help();
            ExitCode::from(2)
        }
    }
}

fn cmd_health() -> ExitCode {
    let path = socket_path();
    let mut stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("msfe-ng health: cannot connect to {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        eprintln!("msfe-ng health: write failed");
        return ExitCode::from(1);
    }
    let mut buf = String::new();
    if stream.read_to_string(&mut buf).is_err() {
        eprintln!("msfe-ng health: read failed");
        return ExitCode::from(1);
    }
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    if buf.starts_with("HTTP/1.1 200") {
        println!("{body}");
        ExitCode::SUCCESS
    } else {
        eprintln!("msfe-ng health: daemon returned:\n{buf}");
        ExitCode::from(1)
    }
}

/// Print the loaded config as JSON (password redacted).
fn cmd_config() -> ExitCode {
    let c = Config::load(&config_path());
    println!("{}", c.to_public_json());
    ExitCode::SUCCESS
}

/// Import a legacy MSFE directory and print the normalized config as JSON.
fn cmd_import(dir: Option<&str>) -> ExitCode {
    let dir = match dir {
        Some(d) => d,
        None => {
            eprintln!("usage: msfe-ng import <legacy-msfe-dir>   (e.g. /usr/msfe)");
            return ExitCode::from(2);
        }
    };
    match import_legacy(Path::new(dir)) {
        Ok(imp) => {
            println!("{}", imp.to_json());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng import: {e}");
            ExitCode::from(1)
        }
    }
}

/// Apply pending SQL migrations (or `--status` to list state).
fn cmd_db_migrate(flag: Option<&str>) -> ExitCode {
    let cfg = Config::load(&config_path());
    let dir = migrations_dir();
    let all = match migrate::discover(&dir) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("msfe-ng db-migrate: cannot read {}: {e}", dir.display());
            return ExitCode::from(1);
        }
    };
    if all.is_empty() {
        eprintln!(
            "msfe-ng db-migrate: no migrations found in {}",
            dir.display()
        );
        return ExitCode::from(1);
    }

    if flag == Some("--status") {
        match migrate::applied_versions(&cfg) {
            Ok(applied) => {
                for m in &all {
                    let mark = if applied.contains(&m.version) {
                        "applied"
                    } else {
                        "pending"
                    };
                    println!("{:04} {:<20} {}", m.version, m.name, mark);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng db-migrate: cannot query DB: {e}");
                ExitCode::from(1)
            }
        }
    } else {
        if !cfg.db_configured() {
            eprintln!(
                "msfe-ng db-migrate: database not configured in {}",
                config_path().display()
            );
            return ExitCode::from(1);
        }
        let applied = match migrate::applied_versions(&cfg) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("msfe-ng db-migrate: cannot query DB (is mysql reachable?): {e}");
                return ExitCode::from(1);
            }
        };
        let todo = migrate::pending(&all, &applied);
        if todo.is_empty() {
            println!("database up to date ({} migrations applied)", applied.len());
            return ExitCode::SUCCESS;
        }
        for m in &todo {
            print!("applying {:04}_{} ... ", m.version, m.name);
            let _ = std::io::stdout().flush();
            match migrate::apply(&cfg, m) {
                Ok(()) => println!("ok"),
                Err(e) => {
                    println!("FAILED");
                    eprintln!("msfe-ng db-migrate: {e}");
                    return ExitCode::from(1);
                }
            }
        }
        println!("applied {} migration(s)", todo.len());
        ExitCode::SUCCESS
    }
}

/// Opt-in activation of the MailScanner logging plugin. Edits the live
/// MailScanner.conf (with a `.msfe-ng.bak` backup) and copies the plugin into
/// the custom-functions dir. Never run by the installer.
fn cmd_mailscanner(sub: Option<&str>) -> ExitCode {
    use msfe_core::mailscanner as ms;
    let cfg = Config::load(&config_path());
    match sub {
        Some("status") => {
            let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
            let cur = ms::get_directive(&conf, ms::LOGGING_DIRECTIVE).unwrap_or("(unset)");
            let plugin = Path::new(&cfg.mailscanner_custom_dir).join(msfe_api::MS_PLUGIN_FILENAME);
            println!("MailScanner.conf: {}", cfg.mailscanner_conf);
            println!("  {} = {}", ms::LOGGING_DIRECTIVE, cur);
            println!(
                "  logging enabled: {}",
                cur == ms::LOGGING_VALUE && plugin.exists()
            );
            println!(
                "  plugin installed: {} ({})",
                plugin.display(),
                plugin.exists()
            );
            ExitCode::SUCCESS
        }
        Some("enable-logging") => {
            // 1. copy the plugin into the custom-functions directory
            let dst = Path::new(&cfg.mailscanner_custom_dir).join(msfe_api::MS_PLUGIN_FILENAME);
            let src = std::env::var("MSFE_NG_MS_PLUGIN_SRC")
                .unwrap_or_else(|_| msfe_api::DEFAULT_MS_PLUGIN_SRC.to_string());
            if let Err(e) = std::fs::create_dir_all(&cfg.mailscanner_custom_dir)
                .and_then(|_| std::fs::copy(&src, &dst).map(|_| ()))
            {
                eprintln!(
                    "msfe-ng mailscanner: cannot install plugin to {}: {e}",
                    dst.display()
                );
                return ExitCode::from(1);
            }
            // 2. set the directive with a one-time backup
            match edit_conf(&cfg.mailscanner_conf, |t| {
                ms::set_directive(t, ms::LOGGING_DIRECTIVE, ms::LOGGING_VALUE)
            }) {
                Ok(()) => {
                    println!("logging enabled. Restart MailScanner to apply (e.g. systemctl restart mailscanner).");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng mailscanner: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("disable-logging") => {
            let dst = Path::new(&cfg.mailscanner_custom_dir).join(msfe_api::MS_PLUGIN_FILENAME);
            let _ = std::fs::remove_file(&dst);
            match edit_conf(&cfg.mailscanner_conf, |t| {
                ms::set_directive(t, ms::LOGGING_DIRECTIVE, "no")
            }) {
                Ok(()) => {
                    println!("logging disabled. Restart MailScanner to apply.");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng mailscanner: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => {
            eprintln!("usage: msfe-ng mailscanner <status|enable-logging|disable-logging>");
            ExitCode::from(2)
        }
    }
}

/// Read a config file, transform it, and write it back after making a one-time
/// `.msfe-ng.bak` backup of the original.
fn edit_conf(path: &str, f: impl FnOnce(&str) -> String) -> std::io::Result<()> {
    let original = std::fs::read_to_string(path)?;
    let backup = format!("{path}.msfe-ng.bak");
    if !Path::new(&backup).exists() {
        std::fs::write(&backup, &original)?;
    }
    std::fs::write(path, f(&original))
}

fn print_help() {
    println!(
        "msfe-ng {VERSION} — MailScanner Front-End (open-source)

USAGE:
    msfe-ng <command>

COMMANDS:
    health              Check the running daemon via its Unix socket
    panel               Report the detected control panel
    config              Print effective config as JSON (password redacted)
    import <dir>        Import a legacy MSFE dir (e.g. /usr/msfe) → JSON
    db-migrate          Apply pending SQL migrations
    db-migrate --status Show which migrations are applied/pending
    mailscanner status  Show MailScanner logging plugin state
    mailscanner enable-logging   Hook the logging plugin into MailScanner.conf
    mailscanner disable-logging  Unhook it (restart MailScanner after either)
    version             Print version
    sync                [M2] Reconcile policy into MailScanner rules
    selftest            [M2] GTUBE/EICAR/clean mail scan test
    help                Show this help

ENVIRONMENT:
    MSFE_NG_SOCKET      Daemon socket path (default: {DEFAULT_SOCKET_PATH})
    MSFE_NG_CONFIG      Config file (default: {DEFAULT_CONFIG_FILE})
    MSFE_NG_MIGRATIONS  Migrations dir (default: {DEFAULT_MIGRATIONS_DIR})"
    );
}
