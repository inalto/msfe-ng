//! `msfe-ng` — the MSFE-NG command line tool.
//!
//! Used by admins directly and by the installer / cron / panel hooks. Commands:
//! health, panel, config, import[/--save], sync[/--dry-run], spambox, selftest,
//! db-migrate, mailscanner.

use msfe_api::{DEFAULT_CONFIG_FILE, DEFAULT_MIGRATIONS_DIR, DEFAULT_SOCKET_PATH, VERSION};
use msfe_core::config::Config;
use msfe_core::{detect_panel, import_legacy, migrate, rules, spambox, sync};
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
        "import" => cmd_import(&args[1..]),
        "db-migrate" => cmd_db_migrate(args.get(1).map(String::as_str)),
        "mailscanner" => cmd_mailscanner(args.get(1).map(String::as_str)),
        "sync" => cmd_sync(args.get(1).map(String::as_str)),
        "spambox" => cmd_spambox(args.get(1).map(String::as_str)),
        "selftest" => cmd_selftest(),
        "housekeeping" => cmd_housekeeping(),
        "digest" => cmd_digest(args.get(1).map(String::as_str)),
        "exim" => cmd_exim(args.get(1).map(String::as_str)),
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

/// Import a legacy MSFE directory. Prints the normalized config as JSON, or with
/// `--save` writes the normalized policy files into `<confdir>/policy/` so `sync`
/// can consume them.
fn cmd_import(args: &[String]) -> ExitCode {
    let dir = args.iter().find(|a| !a.starts_with("--"));
    let save = args.iter().any(|a| a == "--save");
    let dir = match dir {
        Some(d) => d,
        None => {
            eprintln!("usage: msfe-ng import <legacy-msfe-dir> [--save]   (e.g. /usr/msfe)");
            return ExitCode::from(2);
        }
    };
    let imp = match import_legacy(Path::new(dir)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("msfe-ng import: {e}");
            return ExitCode::from(1);
        }
    };
    if save {
        let pdir = sync::policy_dir(&config_path());
        if let Err(e) = sync::save_policy(&pdir, &imp.settings, &imp.whitelist, &imp.blacklist) {
            eprintln!(
                "msfe-ng import: cannot save policy to {}: {e}",
                pdir.display()
            );
            return ExitCode::from(1);
        }
        // Persist digest configuration too (colon format, for `msfe-ng digest`).
        let dd = imp
            .digest_domains
            .iter()
            .map(|d| {
                format!(
                    "{}:{}:{}:{}:{}:{}",
                    d.domain, d.enabled, d.to, d.freq, d.digest_virus, d.spambox
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let _ = std::fs::write(pdir.join("digestdomains"), format!("{dd}\n"));
        println!(
            "saved policy to {} ({} settings, {} whitelist, {} blacklist). Run: msfe-ng sync",
            pdir.display(),
            imp.settings.len(),
            imp.whitelist.len(),
            imp.blacklist.len()
        );
    } else {
        println!("{}", imp.to_json());
    }
    ExitCode::SUCCESS
}

/// Reconcile the policy into MailScanner rule files. `--dry-run` prints the
/// generated files without writing or reloading.
fn cmd_sync(flag: Option<&str>) -> ExitCode {
    let cfg = Config::load(&config_path());
    let pdir = sync::policy_dir(&config_path());
    let (settings, wl, bl) = sync::load_policy(&pdir);
    let domains = sync::gather_domains(None);

    if flag == Some("--dry-run") {
        let rs = rules::RuleSettings::from_settings(&settings);
        let overrides = sync::load_overrides(&pdir);
        let files = rules::generate(&rs, &domains, &wl, &bl, &overrides);
        println!(
            "# dry-run: {} domains, {} whitelist, {} blacklist → {} files in {}",
            domains.len(),
            wl.len(),
            bl.len(),
            files.len(),
            cfg.mailscanner_rules_dir
        );
        for f in &files {
            println!("\n===== {} =====", f.name);
            print!("{}", f.contents);
        }
        return ExitCode::SUCCESS;
    }

    match sync::run(&cfg, &config_path(), None) {
        Ok(n) => {
            println!(
                "wrote {n} rule files for {} domains to {}",
                domains.len(),
                cfg.mailscanner_rules_dir
            );
            if sync::reload_mailscanner() {
                println!("reloaded MailScanner");
            } else {
                eprintln!("note: could not reload MailScanner automatically — reload it to apply");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng sync: {e}");
            ExitCode::from(1)
        }
    }
}

/// Manage the SpamBox Exim fragment file.
fn cmd_spambox(sub: Option<&str>) -> ExitCode {
    let cfg = Config::load(&config_path());
    let path = Path::new(&cfg.spambox_conf);
    match sub {
        Some("enable") => match sync::atomic_write(path, spambox::fragment().as_bytes()) {
            Ok(()) => {
                println!("wrote SpamBox fragment to {}", path.display());
                println!(
                    "add to your Exim config:  .include_if_exists {}\nthen rebuild/restart Exim.",
                    path.display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng spambox: cannot write {}: {e}", path.display());
                ExitCode::from(1)
            }
        },
        Some("disable") => {
            let _ = std::fs::remove_file(path);
            println!("removed {} (rebuild/restart Exim to apply)", path.display());
            ExitCode::SUCCESS
        }
        Some("status") => {
            println!("SpamBox fragment: {} ({})", path.display(), path.exists());
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: msfe-ng spambox <enable|disable|status>");
            ExitCode::from(2)
        }
    }
}

/// End-to-end scan test: send GTUBE (spam), EICAR (virus) and a clean message
/// to the local MTA, then (if the DB is configured) confirm they were logged.
fn cmd_selftest() -> ExitCode {
    const GTUBE: &str = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";
    const EICAR: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let from = "msfe-ng-selftest@localhost";
    let to = "root@localhost";

    let cases = [
        (
            "clean",
            "MSFE-NG selftest: clean message. Nothing to see here.".to_string(),
        ),
        (
            "spam(GTUBE)",
            format!("MSFE-NG selftest spam.\n\n{GTUBE}\n"),
        ),
        (
            "virus(EICAR)",
            format!("MSFE-NG selftest virus.\n\n{EICAR}\n"),
        ),
    ];

    let mut sent = 0;
    for (label, body) in &cases {
        match smtp_send("127.0.0.1:25", from, to, label, body) {
            Ok(()) => {
                println!("sent {label} → {to}");
                sent += 1;
            }
            Err(e) => eprintln!("failed to send {label}: {e}"),
        }
    }
    if sent == 0 {
        eprintln!("selftest: could not send any mail (is the MTA listening on 127.0.0.1:25?)");
        return ExitCode::from(1);
    }
    println!(
        "sent {sent}/3 test messages. Check results in the MSFE-NG report / maillog once scanned."
    );
    ExitCode::SUCCESS
}

/// Minimal SMTP submission over plain TCP (enough for localhost selftest).
fn smtp_send(addr: &str, from: &str, to: &str, subject: &str, body: &str) -> std::io::Result<()> {
    use std::io::{BufRead, BufReader};
    use std::net::TcpStream;
    use std::time::Duration;

    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut w = stream;

    let mut line = String::new();
    let expect = |reader: &mut BufReader<TcpStream>, line: &mut String| -> std::io::Result<()> {
        line.clear();
        reader.read_line(line)?;
        if line.starts_with('4') || line.starts_with('5') {
            return Err(std::io::Error::other(format!(
                "SMTP error: {}",
                line.trim()
            )));
        }
        Ok(())
    };

    expect(&mut reader, &mut line)?; // greeting
    let steps = [
        "HELO localhost\r\n".to_string(),
        format!("MAIL FROM:<{from}>\r\n"),
        format!("RCPT TO:<{to}>\r\n"),
        "DATA\r\n".to_string(),
    ];
    for s in steps {
        w.write_all(s.as_bytes())?;
        expect(&mut reader, &mut line)?;
    }
    let data = format!(
        "From: {from}\r\nTo: {to}\r\nSubject: [MSFE-NG selftest] {subject}\r\n\r\n{body}\r\n.\r\n"
    );
    w.write_all(data.as_bytes())?;
    expect(&mut reader, &mut line)?; // 250 queued
    w.write_all(b"QUIT\r\n")?;
    Ok(())
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

/// Prune old mail-log rows (retention from the `cleanmysql` policy setting).
fn cmd_housekeeping() -> ExitCode {
    let cfg = Config::load(&config_path());
    let (settings, _, _) = sync::load_policy(&sync::policy_dir(&config_path()));
    let days = msfe_core::housekeeping::retention_days(&settings);
    match msfe_core::housekeeping::prune(&cfg, days) {
        Ok(()) => {
            println!("housekeeping: pruned maillog/quarantine rows older than {days} days");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng housekeeping: {e}");
            ExitCode::from(1)
        }
    }
}

/// Send quarantine digests to digest-enabled domains (`--dry-run` to preview).
fn cmd_digest(flag: Option<&str>) -> ExitCode {
    let cfg = Config::load(&config_path());
    let dry = flag == Some("--dry-run");
    let results = msfe_core::digest::run(&cfg, &sync::policy_dir(&config_path()), dry);
    if results.is_empty() {
        println!("digest: nothing to send");
        return ExitCode::SUCCESS;
    }
    for r in &results {
        let state = if dry {
            "(dry-run)"
        } else if r.sent {
            "sent"
        } else {
            "FAILED"
        };
        println!(
            "digest: {} — {} held → {} {state}",
            r.domain, r.count, r.recipient
        );
    }
    ExitCode::SUCCESS
}

/// Toggle / report MailScanner scanning via the exiscandisable flag.
fn cmd_exim(sub: Option<&str>) -> ExitCode {
    use msfe_core::mailflow;
    match sub {
        Some("status") => {
            println!(
                "MailScanner scanning: {}",
                if mailflow::scanning_enabled() {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            ExitCode::SUCCESS
        }
        Some("enable-scanning") => match mailflow::set_scanning(true) {
            Ok(()) => {
                println!("scanning enabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng exim: {e}");
                ExitCode::from(1)
            }
        },
        Some("disable-scanning") => match mailflow::set_scanning(false) {
            Ok(()) => {
                println!(
                    "scanning disabled ({} created)",
                    mailflow::exiscandisable_path().display()
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng exim: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!("usage: msfe-ng exim <status|enable-scanning|disable-scanning>");
            ExitCode::from(2)
        }
    }
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
    import <dir> --save Import and save policy for `sync` to use
    sync                Reconcile policy into MailScanner rule files
    sync --dry-run      Show the rule files that would be written
    spambox <enable|disable|status>   Manage the SpamBox Exim fragment
    selftest            Send GTUBE/EICAR/clean test mail through the MTA
    digest [--dry-run]  Email quarantine digests to digest-enabled domains
    housekeeping        Prune old mail-log rows (cleanmysql retention)
    exim <status|enable-scanning|disable-scanning>   Toggle MailScanner scanning
    db-migrate          Apply pending SQL migrations
    db-migrate --status Show which migrations are applied/pending
    mailscanner status  Show MailScanner logging plugin state
    mailscanner enable-logging   Hook the logging plugin into MailScanner.conf
    mailscanner disable-logging  Unhook it (restart MailScanner after either)
    version             Print version
    help                Show this help

ENVIRONMENT:
    MSFE_NG_SOCKET      Daemon socket path (default: {DEFAULT_SOCKET_PATH})
    MSFE_NG_CONFIG      Config file (default: {DEFAULT_CONFIG_FILE})
    MSFE_NG_MIGRATIONS  Migrations dir (default: {DEFAULT_MIGRATIONS_DIR})"
    );
}
