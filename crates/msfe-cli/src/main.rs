//! `msfe-ng` — the MSFE-NG command line tool.
//!
//! Used by admins directly and by the installer / cron / panel hooks. Commands:
//! health, panel, config, import[/--save], sync[/--dry-run], spambox, selftest,
//! db-migrate, db, mailscanner.

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

/// Flags a `<cmd> <sub>` pair accepts. Commands whose grammar is fully known
/// are listed; an option outside the list is refused up front, so a flag a
/// subcommand does not understand can never fall through to the action
/// (`exim enable-scanning --dry-run` once enabled scanning for real).
fn accepted_flags(cmd: &str, sub: Option<&str>) -> Option<&'static [&'static str]> {
    const NONE: &[&str] = &[];
    const DRY: &[&str] = &["--dry-run"];
    match (cmd, sub) {
        ("exim", _) => Some(NONE),
        ("engine", Some("wire" | "unwire")) => Some(DRY),
        ("engine", Some("migrate-legacy")) => Some(&["--run"]),
        ("legacy", Some("decommission")) => Some(&["--run"]),
        ("legacy", _) => Some(NONE),
        ("engine", _) => Some(NONE),
        ("service", Some("spool-repair")) => Some(DRY),
        ("service", _) => Some(NONE),
        ("mailscanner", _) => Some(NONE),
        ("upgrade", _) => Some(&["--check"]),
        ("doctor", _) => Some(&["--fix"]),
        ("resolver", _) => Some(NONE),
        ("snapshot", Some("export")) => Some(&["--only"]),
        ("snapshot", Some("import")) => Some(&["--dry-run", "--only", "--yes", "--no-lint"]),
        ("snapshot", _) => Some(NONE),
        ("backup", _) => Some(NONE),
        ("restore", _) => Some(&["--yes"]),
        ("conf", Some("test")) => Some(&["--no-lint", "--json", "--with"]),
        ("conf", Some("test-message")) => Some(&["--offline", "--json"]),
        ("conf", _) => Some(NONE),
        ("delivery", Some("test")) => Some(&[
            "--ip",
            "--selector",
            "--audit",
            "--days",
            "--json",
            "--html",
            "--force",
        ]),
        ("delivery", Some("inbox")) => Some(&["--dry-run", "--json"]),
        ("delivery", Some("testmail")) => Some(&["--from", "--to", "--tag", "--json", "--follow"]),
        ("delivery", Some("monitor")) => Some(&[
            "--interval-mins",
            "--audit",
            "--ip",
            "--selector",
            "--days",
            "--dry-run",
            "--id",
            "--json",
        ]),
        ("delivery", Some("eml")) => Some(&[
            "--bounce",
            "--address",
            "--ip",
            "--selector",
            "--audit",
            "--days",
            "--json",
            "--html",
        ]),
        ("delivery", _) => Some(NONE),
        _ => None,
    }
}

/// The first `-flag` in `rest` that `<cmd> <sub>` does not take, if any.
fn rejected_flag<'a>(cmd: &str, sub: Option<&str>, rest: &'a [String]) -> Option<&'a str> {
    let accepted = accepted_flags(cmd, sub)?;
    rest.iter()
        .map(String::as_str)
        .find(|a| a.starts_with('-') && !accepted.contains(a))
}

fn usage_of(cmd: &str) -> &'static str {
    match cmd {
        "exim" => "msfe-ng exim <status|enable-scanning|disable-scanning|enable-cpanel-spamassassin|disable-cpanel-spamassassin>",
        "engine" => {
            "msfe-ng engine <status|install|configure|enable|disable|lint|wire|unwire> [--dry-run]"
        }
        "service" => {
            "msfe-ng service <status|start|stop|reload|restart|queue-fix|spool-repair [--dry-run]>"
        }
        "mailscanner" => "msfe-ng mailscanner <status|enable-logging|disable-logging>",
        "legacy" => "msfe-ng legacy decommission [--run]",
        "upgrade" => "msfe-ng upgrade [--check]",
        "doctor" => "msfe-ng doctor [--fix]",
        "resolver" => "msfe-ng resolver <status|install>",
        "snapshot" => "msfe-ng snapshot <export [file] [--only mailscanner|msfe] | import <file> [--dry-run] [--only mailscanner|msfe] [--no-lint] [--yes] | list>",
        "backup" => "msfe-ng backup <file.tar.gz>   (alias: snapshot export --only msfe)",
        "restore" => "msfe-ng restore <file.tar.gz> [--yes]   (alias: snapshot import --only msfe)",
        "conf" => "msfe-ng conf <test [--no-lint] [--json] [--with <id>=<file>]... | test-message <clean|gtube|eicar|file.eml> [--offline] [--json]>",
        "delivery" => "msfe-ng delivery <test <address> [--ip <sending ip>] [--selector <dkim selector>] [--audit] [--days <1-7>] [--json | --html] [--force] | eml <file.eml> [--bounce] [--address <a>] [--ip <ip>] [--selector <s>] [--audit] [--json | --html] | inbox <install [--dry-run] | uninstall [--dry-run] | status | new | poll <token> [--json] | remove <token> | sweep> | testmail --from <local address> --to <address> [--tag <t>] [--follow <secs>] [--json] | monitor <list [--json] | add <address> [--interval-mins n] [--audit] [--ip ..] [--selector ..] [--days n] | remove <id|address> | run [--dry-run] [--id n]>>",
        _ => "msfe-ng help",
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    // `doctor --fix`: a flag right after the command is an option, not a
    // subcommand, and gets checked like any other
    let (sub, rest) = match args.get(1) {
        Some(a) if a.starts_with('-') => (None, &args[1..]),
        _ => (
            args.get(1).map(String::as_str),
            args.get(2..).unwrap_or(&[]),
        ),
    };
    if let Some(flag) = rejected_flag(cmd, sub, rest) {
        eprintln!(
            "msfe-ng {cmd}: unknown option '{flag}'\nusage: {}",
            usage_of(cmd)
        );
        return ExitCode::from(2);
    }

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
        "db" => cmd_db(args.get(1).map(String::as_str)),
        "mailscanner" => cmd_mailscanner(args.get(1).map(String::as_str)),
        "upgrade" => cmd_upgrade(args.iter().any(|a| a == "--check")),
        "resolver" => cmd_resolver(args.get(1).map(String::as_str)),
        "conf" => cmd_conf(sub, rest),
        "sync" => cmd_sync(args.get(1).map(String::as_str)),
        "spambox" => cmd_spambox(args.get(1).map(String::as_str)),
        "selftest" => cmd_selftest(),
        "housekeeping" => cmd_housekeeping(),
        "monitor" => cmd_monitor(args.get(1).map(String::as_str)),
        "digest" => cmd_digest(args.get(1).map(String::as_str)),
        "exim" => cmd_exim(args.get(1).map(String::as_str)),
        "service" => cmd_service(args.get(1).map(String::as_str)),
        "rules" => cmd_rules(args.get(1).map(String::as_str)),
        "engine" => cmd_engine(args.get(1).map(String::as_str)),
        "legacy" => cmd_legacy(args.get(1).map(String::as_str)),
        "doctor" => cmd_doctor(args.iter().any(|a| a == "--fix")),
        "backup" => cmd_backup(sub),
        "restore" => cmd_restore(sub, rest),
        "snapshot" => cmd_snapshot(sub, rest),
        "delivery" => cmd_delivery(sub, rest),
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
/// `msfe-ng legacy decommission [--run]`: ConfigServer's front-end goes,
/// its engine stays; the preflight alone without `--run`.
fn cmd_legacy(sub: Option<&str>) -> ExitCode {
    use msfe_core::legacy_decommission as decom;
    if sub != Some("decommission") {
        eprintln!("usage: msfe-ng legacy decommission [--run]");
        return ExitCode::from(2);
    }
    let cfg = Config::load(&config_path());
    let run = std::env::args().any(|x| x == "--run");
    let pf = decom::preflight(&cfg, &config_path());
    if !run {
        println!(
            "ConfigServer front-end: {}",
            if pf.remnants.is_empty() {
                "nothing left".to_string()
            } else {
                pf.remnants.join(", ")
            }
        );
        for l in &pf.crontab_lines {
            println!("root's crontab: {l}");
        }
        println!(
            "ConfigServer engine at /usr/mailscanner: {} (never touched here); policy imported: {}; backup dir: {}",
            if pf.legacy_engine { "present" } else { "absent" },
            pf.policy_imported,
            pf.backup_dir
        );
        for w in &pf.warnings {
            println!("note: {w}");
        }
        for b in &pf.blockers {
            println!("blocked: {b}");
        }
        println!("procedure: {}", decom::WIKI_URL);
        if pf.ok() {
            println!(
                "\nrun it with: msfe-ng legacy decommission --run   (or from the Service tab)"
            );
        }
        return if pf.ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    match decom::run(&cfg, &config_path()) {
        Ok(rep) => {
            for l in &rep.done {
                println!("{l}");
            }
            if rep.left.is_empty() {
                println!(
                    "decommissioned — restore with: tar xzf {} -C /",
                    rep.backup
                        .map(|b| b.display().to_string())
                        .unwrap_or_default()
                );
                ExitCode::SUCCESS
            } else {
                println!("still present (remove by hand): {}", rep.left.join(", "));
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("msfe-ng legacy decommission: {e}");
            ExitCode::from(1)
        }
    }
}

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
        let rs = rules::RuleSettings::from_settings(&settings, &cfg.archive_dir);
        let overrides = sync::load_overrides(&pdir);
        let mut files = rules::generate(&rs, &domains, &wl, &bl, &overrides);
        rules::merge_custom(
            &mut files,
            &msfe_core::rulefile::load_all_custom(&pdir, &rules::managed_files()),
        );
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
        Ok(r) => {
            println!(
                "wrote {} rule files ({} changed) for {} domains to {}",
                r.files,
                r.changed,
                domains.len(),
                cfg.mailscanner_rules_dir
            );
            // Reload = full restart for the LSB MailScanner service: only pay
            // that (and only interrupt in-flight batches) for a real change.
            if r.changed == 0 {
                println!("ruleset unchanged — MailScanner not reloaded");
            } else if sync::reload_mailscanner() {
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
        // ClamAV's Eicar-Test-Signature only matches a file that *starts*
        // with the string: any text before it (even a greeting line) and the
        // body part MailScanner hands to clamd never triggers.
        ("virus(EICAR)", format!("{EICAR}\n")),
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

/// Minimal SMTP submission to the local MTA (the selftest's three messages).
fn smtp_send(addr: &str, from: &str, to: &str, subject: &str, body: &str) -> std::io::Result<()> {
    let subject = format!("[MSFE-NG selftest] {subject}");
    msfe_core::smtpprobe::submit_local(
        addr,
        from,
        to,
        &[("From", from), ("To", to), ("Subject", &subject)],
        body,
    )
    .map(|_| ())
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
/// MailScanner's own `Custom Functions Dir`. Never run by the installer.
/// The private DNS resolver for the blocklists: report, or install unbound
/// on loopback (PowerDNS rebound to the public addresses) and switch to it.
fn cmd_resolver(sub: Option<&str>) -> ExitCode {
    use msfe_core::resolver;
    match sub {
        Some("status") => {
            let s = resolver::state();
            println!(
                "resolver: {} ({})",
                if s.nameservers.is_empty() {
                    "none".into()
                } else {
                    s.nameservers.join(", ")
                },
                if s.done() {
                    "unbound on loopback — the blocklists answer this host"
                } else if s.on_loopback {
                    "loopback, but unbound is not active"
                } else {
                    "shared/provider resolver — Spamhaus and DNSWL refuse it"
                }
            );
            println!(
                "unbound: {}; port 53 also served by: {}; network manager: {}",
                match (s.unbound_active, s.unbound_answers) {
                    (true, Some(true)) => "active, resolving",
                    (true, _) => "active but NOT resolving (journalctl -u unbound)",
                    (false, _) if s.unbound_installed => "installed, not active",
                    _ => "not installed",
                },
                if s.port53.is_empty() {
                    "nothing".into()
                } else {
                    s.port53.join(", ")
                },
                s.manager
            );
            for n in &s.notes {
                println!("note: {n}");
            }
            for b in &s.blockers {
                println!("blocked: {b}");
            }
            if !s.done() && s.ok() {
                println!("\ninstall it with: msfe-ng resolver install   (or from the Service tab)");
            }
            ExitCode::SUCCESS
        }
        Some("install") => match resolver::install() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("\nmsfe-ng resolver install: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!("usage: msfe-ng resolver <status|install>");
            ExitCode::from(2)
        }
    }
}

/// Upgrade MSFE-NG to the latest release (get.sh in the foreground), or
/// just compare versions with --check.
fn cmd_upgrade(check_only: bool) -> ExitCode {
    use msfe_core::{service, upgrade};
    let current = msfe_api::VERSION;
    let Some(latest) = service::latest_version() else {
        eprintln!("msfe-ng upgrade: cannot reach the release server");
        return ExitCode::from(1);
    };
    let newer = service::version_newer(&latest, current);
    println!(
        "MSFE-NG {current} installed, {latest} latest{}",
        if newer {
            " — upgrade available"
        } else {
            " — up to date"
        }
    );
    let cfg = Config::load(&config_path());
    let e = upgrade::engine_update(&cfg);
    println!(
        "MailScanner {} installed, {} latest{}",
        e.version.as_deref().unwrap_or("?"),
        e.latest.as_deref().unwrap_or("?"),
        if e.upgradable {
            " — upgrade available: msfe-ng engine install (forced) or the Service tab"
        } else if !e.rpm {
            " — not the RPM engine: see the wiki, Migration"
        } else {
            " — up to date"
        }
    );
    if check_only || !newer {
        return ExitCode::SUCCESS;
    }
    if !Path::new(upgrade::GET_SCRIPT).exists() {
        eprintln!(
            "msfe-ng upgrade: {} not found (reinstall MSFE-NG)",
            upgrade::GET_SCRIPT
        );
        return ExitCode::from(1);
    }
    match std::process::Command::new("sh")
        .arg(upgrade::GET_SCRIPT)
        .status()
    {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => {
            eprintln!("msfe-ng upgrade: failed (see output above)");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("msfe-ng upgrade: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_mailscanner(sub: Option<&str>) -> ExitCode {
    use msfe_core::mailscanner as ms;
    let cfg = Config::load(&config_path());
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let dir = ms::custom_functions_dir(&conf, &cfg.mailscanner_custom_dir);
    let plugin = dir.join(msfe_api::MS_PLUGIN_FILENAME);
    match sub {
        Some("status") => {
            let cur = ms::get_directive(&conf, ms::LOGGING_DIRECTIVE).unwrap_or("(unset)");
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
            if !Path::new(&cfg.mailscanner_conf).is_file() {
                eprintln!(
                    "msfe-ng mailscanner: {}: not found — set mailscanner_conf in {} to this engine's conf",
                    cfg.mailscanner_conf,
                    config_path().display()
                );
                return ExitCode::from(1);
            }
            // 1. copy the plugin into the custom-functions directory
            let src = std::env::var("MSFE_NG_MS_PLUGIN_SRC")
                .unwrap_or_else(|_| msfe_api::DEFAULT_MS_PLUGIN_SRC.to_string());
            if let Err(e) =
                std::fs::create_dir_all(&dir).and_then(|_| std::fs::copy(&src, &plugin).map(|_| ()))
            {
                eprintln!(
                    "msfe-ng mailscanner: cannot install plugin to {}: {e}",
                    plugin.display()
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
            let _ = std::fs::remove_file(&plugin);
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
    let named = |e: std::io::Error| std::io::Error::new(e.kind(), format!("{path}: {e}"));
    let original = std::fs::read_to_string(path).map_err(named)?;
    let backup = format!("{path}.msfe-ng.bak");
    if !Path::new(&backup).exists() {
        std::fs::write(&backup, &original).map_err(named)?;
    }
    std::fs::write(path, f(&original)).map_err(named)
}

/// Prune old mail-log rows (retention from the `cleanmysql` policy setting).
fn cmd_housekeeping() -> ExitCode {
    let cfg = Config::load(&config_path());
    let (settings, _, _) = sync::load_policy(&sync::policy_dir(&config_path()));
    let days = msfe_core::housekeeping::retention_days(&settings);
    let body_days = msfe_core::housekeeping::body_retention_days(&settings);
    msfe_core::deliveryrun::sweep();
    msfe_core::diaginbox::sweep();
    let _ = msfe_core::deliverymon::prune(&cfg, 90);
    match msfe_core::housekeeping::prune(&cfg, days) {
        Ok(()) => {
            println!("housekeeping: pruned maillog/quarantine rows older than {days} days");
            match msfe_core::housekeeping::prune_bodies(&cfg, body_days) {
                Ok(r) if body_days == 0 => {
                    println!("housekeeping: message bodies kept forever (bodydays=0)");
                    let _ = r;
                }
                Ok(r) => {
                    println!(
                        "housekeeping: removed {} message bodies older than {body_days} days ({} MB freed, {} checked)",
                        r.removed,
                        r.bytes / 1_048_576,
                        r.scanned
                    );
                    println!(
                        "housekeeping: {} bodies kept, using {} MB",
                        r.kept,
                        r.kept_bytes / 1_048_576
                    );
                    let _ = msfe_core::housekeeping::clear_pruned_paths(&cfg, body_days);
                    let _ = msfe_core::housekeeping::record_usage(&cfg, r.kept_bytes, r.kept);
                }
                Err(e) => eprintln!("msfe-ng housekeeping: body prune: {e}"),
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng housekeeping: {e}");
            ExitCode::from(1)
        }
    }
}

/// Periodic queue monitor (cron, every 5 min): auto-clean the delivery queue
/// per the queue_clean_* rules, relocate misfiled spool files, and send
/// Telegram alerts for queue growth, stuck scanning and per-account sending
/// bursts. `--dry-run` previews everything.
fn cmd_monitor(flag: Option<&str>) -> ExitCode {
    let cfg = Config::load(&config_path());
    let dry = flag == Some("--dry-run");
    let r = msfe_core::monitor::run(&cfg, dry);
    if r.notes.is_empty() {
        println!(
            "monitor: nothing to do (spool files in place; no cleanup rules or alerts configured)"
        );
    }
    for n in &r.notes {
        println!("{n}");
    }
    ExitCode::SUCCESS
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

/// One pass over every link of the scanning chain; each problem names its fix.
/// Exit code 1 when anything FAILS (warnings alone stay 0).
fn cmd_doctor(fix: bool) -> ExitCode {
    use msfe_core::doctor::{self, Level};
    let cfg = Config::load(&config_path());
    if fix {
        let done = doctor::fix(&cfg, &config_path());
        if done.is_empty() {
            println!("doctor --fix: nothing to fix automatically");
        } else {
            for l in &done {
                println!("fix: {l}");
            }
        }
        println!();
    }
    let checks = doctor::run(&cfg, &config_path());
    for c in &checks {
        let tag = match c.level {
            Level::Ok => " OK ",
            Level::Warn => "WARN",
            Level::Fail => "FAIL",
        };
        println!("[{tag}] {} — {}", c.name, c.detail);
        if let Some(fix) = &c.fix {
            println!("       fix: {fix}");
        }
        if let Some(url) = c.url {
            println!("       see: {url}");
        }
    }
    if doctor::healthy(&checks) {
        println!("doctor: no failures");
        ExitCode::SUCCESS
    } else {
        println!("doctor: FAILURES found — see fixes above");
        ExitCode::from(1)
    }
}

/// MailScanner engine management: `status` reports whether the engine is
/// installed and running; `install` runs the bundled unattended installer
/// (official MailScanner v5 rpm + dependencies; never touches Exim).
fn cmd_engine(sub: Option<&str>) -> ExitCode {
    use msfe_core::service;
    let cfg = Config::load(&config_path());
    let lay = msfe_core::layout::resolve(&cfg);
    let installed = service::engine_installed_at(&lay);
    match sub {
        Some("status") => {
            if installed {
                let st = service::status();
                println!(
                    "engine: MailScanner {} at {} (conf {}), {} ({} processes)",
                    lay.version_string(),
                    lay.bin.display(),
                    lay.conf.display(),
                    if st.active { "active" } else { "stopped" },
                    st.procs
                );
            } else {
                println!("engine: NOT installed — run: msfe-ng engine install");
            }
            ExitCode::SUCCESS
        }
        Some("install") => {
            let script = "/opt/msfe-ng/bin/msfe-ng-engine-install";
            if !Path::new(script).exists() {
                eprintln!("msfe-ng engine: {script} not found (reinstall MSFE-NG)");
                return ExitCode::from(1);
            }
            match std::process::Command::new("sh").arg(script).status() {
                Ok(s) if s.success() => ExitCode::SUCCESS,
                Ok(_) => {
                    eprintln!("msfe-ng engine install: failed (see output above)");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("msfe-ng engine install: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("configure") => {
            let cfg = Config::load(&config_path());
            match msfe_core::engine::configure(&cfg) {
                Ok(r) => {
                    for s in &r.set {
                        println!("set: {s}");
                    }
                    for c in &r.created {
                        println!("created: {c}");
                    }
                    for f in &r.chown_failed {
                        println!("WARNING: could not set ownership on {f}");
                    }
                    for p in &r.repaired {
                        println!("repaired: {p}");
                    }
                    for w in &r.warnings {
                        println!("WARNING: {w}");
                    }
                    if r.restarted {
                        println!("restarted MailScanner to apply the changes");
                    }
                    if r.set.is_empty() && r.created.is_empty() && r.repaired.is_empty() {
                        println!("already configured — nothing to change");
                    } else {
                        println!("engine configured for Exim; verify with: msfe-ng engine lint");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng engine configure: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("migrate-legacy") => {
            use msfe_core::engine_migration as mig;
            let run = std::env::args().any(|x| x == "--run");
            if !run {
                let pf = mig::preflight(&cfg, &config_path());
                println!("engine: {}", pf.engine);
                println!(
                    "legacy ConfigServer tree: {}; uninstaller: {}; policy imported: {}; wiring: {}",
                    if pf.legacy_engine { "present" } else { "absent" },
                    if pf.uninstaller { "present" } else { "absent" },
                    pf.policy_imported,
                    pf.wiring.as_deref().unwrap_or("none")
                );
                for w in &pf.warnings {
                    println!("note: {w}");
                }
                for b in &pf.blockers {
                    println!("blocked: {b}");
                }
                if pf.ok() {
                    println!("\nrun it with: msfe-ng engine migrate-legacy --run   (or from the Service tab)");
                }
                return if pf.ok() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                };
            }
            match mig::run(&config_path()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("\nmsfe-ng engine migrate-legacy: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some(a @ ("wire" | "unwire")) => {
            let dry = std::env::args().any(|x| x == "--dry-run");
            let cfg = Config::load(&config_path());
            let res = if a == "wire" {
                msfe_core::engine::wire(&cfg, dry)
            } else {
                msfe_core::engine::unwire(&cfg, dry)
            };
            match res {
                Ok(r) => {
                    for l in &r.actions {
                        println!("{l}");
                    }
                    if r.dry_run {
                        println!("dry-run: nothing was changed");
                    } else if a == "wire" {
                        println!("WIRED: incoming mail is now routed through MailScanner");
                    } else {
                        println!("UNWIRED: direct delivery restored (mail is not scanned)");
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng engine {a}: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some(a @ ("enable" | "disable")) => {
            let on = a == "enable";
            match service::set_engine_run(&cfg, on) {
                Ok(()) => {
                    println!(
                        "safety switch (run_mailscanner) is now {}",
                        if on { "ON" } else { "OFF" }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng engine {a}: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("lint") => {
            let r = service::lint(&cfg);
            println!("{}", r.output);
            if r.ok {
                println!("RESULT: everything is OK");
                ExitCode::SUCCESS
            } else {
                println!("RESULT: problems found (see above)");
                ExitCode::from(1)
            }
        }
        _ => {
            eprintln!("usage: msfe-ng engine <status|install|configure|enable|disable|lint|wire|unwire> [--dry-run]");
            ExitCode::from(2)
        }
    }
}

/// Structured rules tooling: `lint` parses every managed on-disk ruleset with
/// the tolerant parser and reports lines that MailScanner may misread; `adopt`
/// absorbs existing on-disk rules into the custom store ("borrow" them).
/// `conf test`: MailScanner --lint, spamassassin --lint and the cross-file
/// checks as one list of findings; `--with ms:<rel>=<file>` tests a candidate
/// on a staged copy instead of the live tree. Exit 1 on any failure.
fn cmd_conf(sub: Option<&str>, rest: &[String]) -> ExitCode {
    use msfe_core::conftest::{self, Level, Parts, PendingEdit};
    if sub == Some("test-message") {
        return cmd_conf_test_message(rest);
    }
    if sub != Some("test") {
        eprintln!("usage: {}", usage_of("conf"));
        return ExitCode::from(2);
    }
    let no_lint = rest.iter().any(|a| a == "--no-lint");
    let json = rest.iter().any(|a| a == "--json");
    let mut edits = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a != "--with" {
            continue;
        }
        let Some((id, file)) = it.next().and_then(|s| s.split_once('=')) else {
            eprintln!("msfe-ng conf test: --with takes <id>=<file>, e.g. --with ms:MailScanner.conf=/tmp/candidate.conf");
            return ExitCode::from(2);
        };
        match std::fs::read_to_string(file) {
            Ok(new_text) => edits.push(PendingEdit {
                id: id.to_string(),
                new_text,
            }),
            Err(e) => {
                eprintln!("msfe-ng conf test: cannot read {file}: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let cfg = Config::load(&config_path());
    let parts = Parts {
        ms_lint: !no_lint,
        sa_lint: !no_lint,
        checks: true,
    };
    let r = match conftest::run(&cfg, &config_path(), &edits, parts) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("msfe-ng conf test: {e}");
            return ExitCode::from(1);
        }
    };
    let (fail, warn, ok) = r.summary();
    if json {
        println!("{}", r.to_json());
    } else {
        for f in &r.findings {
            let mut place = f.file.clone().unwrap_or_default();
            if let Some(n) = f.line {
                place.push_str(&format!(":{n}"));
            }
            if let Some(k) = &f.key {
                if !place.is_empty() {
                    place.push(' ');
                }
                place.push_str(&format!("[{k}]"));
            }
            println!(
                "{:<4} {:<12} {}{}{}",
                f.level.as_str().to_uppercase(),
                f.source.as_str(),
                place,
                if place.is_empty() { "" } else { "  " },
                f.message
            );
        }
        println!(
            "
{} scope: {fail} failed, {warn} warning(s), {ok} ok ({:.1} s)",
            r.scope,
            r.duration_ms as f64 / 1000.0
        );
    }
    if fail > 0 || r.findings.iter().any(|f| f.level == Level::Fail) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// `conf test-message`: what the chain would do with a message — SpamAssassin
/// score, virus verdict, filename/filetype rule matches and the MailScanner
/// actions predicted from the rulesets — without delivering it.
fn cmd_conf_test_message(rest: &[String]) -> ExitCode {
    use msfe_core::msgtest;
    let offline = rest.iter().any(|a| a == "--offline");
    let json = rest.iter().any(|a| a == "--json");
    let Some(what) = rest.iter().find(|a| !a.starts_with('-')) else {
        eprintln!("usage: {}", usage_of("conf"));
        return ExitCode::from(2);
    };
    let path: PathBuf = match msgtest::sample_eml(what) {
        Some(text) => {
            let p = std::env::temp_dir().join(format!(
                "msfe-ng-sample-{}-{}.eml",
                what,
                std::process::id()
            ));
            if let Err(e) = std::fs::write(&p, text) {
                eprintln!("msfe-ng conf test-message: cannot write the sample: {e}");
                return ExitCode::from(1);
            }
            p
        }
        None => {
            let p = PathBuf::from(what);
            if !p.is_file() {
                eprintln!("msfe-ng conf test-message: {what} is neither a sample (clean|gtube|eicar) nor a readable file");
                return ExitCode::from(2);
            }
            p
        }
    };
    let cfg = Config::load(&config_path());
    let r = msgtest::run_message(&cfg, &path, !offline);
    if msgtest::sample_eml(what).is_some() {
        let _ = std::fs::remove_file(&path);
    }
    let r = match r {
        Ok(r) => r,
        Err(e) => {
            eprintln!("msfe-ng conf test-message: {e}");
            return ExitCode::from(1);
        }
    };
    if json {
        println!("{}", r.to_json());
        return ExitCode::SUCCESS;
    }
    let sa = &r.spamassassin;
    println!(
        "SpamAssassin: {}",
        if !sa.ran {
            sa.note.clone()
        } else {
            format!(
                "{} score={} required={} tests={}{}",
                match sa.spam {
                    Some(true) => "SPAM",
                    Some(false) => "not spam",
                    None => "no verdict",
                },
                sa.score
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                sa.required
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                if sa.tests.is_empty() {
                    "-".to_string()
                } else {
                    sa.tests.join(",")
                },
                if sa.note.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", sa.note)
                }
            )
        }
    );
    let av = &r.virus;
    println!(
        "Virus:        {}",
        match av.infected {
            Some(true) => format!("INFECTED {} ({})", av.signature, av.tool),
            Some(false) => format!("clean ({})", av.tool),
            None => av.note.clone(),
        }
    );
    if r.content.is_empty() {
        println!("Content:      no filename/filetype rule matched");
    }
    for c in &r.content {
        println!(
            "Content:      {} → {} by {} ({}: {})",
            c.filename, c.action, c.rule_file, c.pattern, c.log_text
        );
    }
    println!(
        "Predicted:    {} → {}: {}",
        r.predicted.from, r.predicted.to, r.predicted.outcome
    );
    for (k, v) in &r.predicted.resolved {
        println!("              {k} = {v}");
    }
    println!(
        "
(simulation — the stages were asked directly; `msfe-ng selftest` sends real mail through the MTA)"
    );
    ExitCode::SUCCESS
}

fn cmd_rules(sub: Option<&str>) -> ExitCode {
    use msfe_core::rulefile;
    if sub == Some("adopt") {
        return cmd_rules_adopt();
    }
    match sub {
        Some("lint") => {
            let cfg = Config::load(&config_path());
            let mut problems = 0;
            for name in rules::managed_files() {
                let path = Path::new(&cfg.mailscanner_rules_dir).join(&name);
                let Ok(text) = std::fs::read_to_string(&path) else {
                    println!("{name}: missing (run msfe-ng sync)");
                    continue;
                };
                let lines = rulefile::parse(&text);
                let rules_n = rulefile::rules_of(&lines).len();
                let bad: Vec<&str> = lines
                    .iter()
                    .filter_map(|l| match l {
                        rulefile::Line::Unparsed(u) => Some(u.as_str()),
                        _ => None,
                    })
                    .collect();
                if bad.is_empty() {
                    println!("{name}: ok ({rules_n} rules)");
                } else {
                    problems += bad.len();
                    println!("{name}: {rules_n} rules, {} UNPARSABLE line(s):", bad.len());
                    for b in &bad {
                        println!("    {b}");
                    }
                }
            }
            if problems == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        _ => {
            eprintln!("usage: msfe-ng rules <lint|adopt [--from <dir>]>");
            ExitCode::from(2)
        }
    }
}

/// Borrow all rules present in the on-disk ruleset files (or a legacy install's
/// rules dir via `--from`) into the custom store, then resync.
fn cmd_rules_adopt() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(3).collect();
    let from = args
        .iter()
        .position(|a| a == "--from")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from);
    let cfg = Config::load(&config_path());
    match sync::adopt_rules(&cfg, &config_path(), from.as_deref(), None) {
        Ok(r) => {
            for (f, n) in &r.per_file {
                println!("{f}: adopted {n} rule(s)");
            }
            println!(
                "adopted {} rule(s) into the custom store ({} default line(s) skipped — defaults come from policy; {} unparsable line(s) ignored)",
                r.adopted, r.skipped_defaults, r.unparsed
            );
            if r.adopted > 0 {
                match sync::run(&cfg, &config_path(), None) {
                    Ok(r) => {
                        println!("resynced {} rule files ({} changed)", r.files, r.changed);
                        if r.changed > 0 && !sync::reload_mailscanner() {
                            eprintln!("note: could not reload MailScanner automatically");
                        }
                    }
                    Err(e) => {
                        eprintln!("msfe-ng rules adopt: sync failed: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng rules adopt: {e}");
            ExitCode::from(1)
        }
    }
}

/// MailScanner service control and queue tooling (mirrors the Service tab).
fn cmd_service(sub: Option<&str>) -> ExitCode {
    use msfe_core::{mailflow, service};
    let cfg = Config::load(&config_path());
    match sub {
        Some("status") => {
            let st = service::status();
            let (inc, out) = service::queue_dirs(&cfg);
            if !service::engine_installed(&cfg) {
                println!(
                    "WARNING: MailScanner engine is NOT installed — mail is not being scanned. Run: msfe-ng engine install"
                );
            } else if !service::engine_configured(&cfg) {
                println!(
                    "WARNING: MailScanner engine installed but {} is missing — run: msfe-ng engine install",
                    cfg.mailscanner_conf
                );
            } else if service::engine_run_enabled(&cfg) == Some(false) {
                println!(
                    "NOTE: MailScanner is held by its startup latch (run_mailscanner=0 in its defaults file) — not yet wired into Exim; start will fail until the wiring step enables it"
                );
            }
            println!(
                "MailScanner: {} ({} processes), scanning {}",
                if st.active { "active" } else { "stopped" },
                st.procs,
                if mailflow::scanning_enabled(&cfg) {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "queues: incoming {} ({}), outgoing {} ({})",
                service::count_queue(&inc),
                inc.display(),
                service::count_queue(&out),
                out.display()
            );
            ExitCode::SUCCESS
        }
        Some(a @ ("start" | "stop" | "reload" | "restart")) => {
            let outcome = service::control(a);
            for line in &outcome.transcript {
                println!("{line}");
            }
            if outcome.ok {
                println!("MailScanner {a}: ok");
                ExitCode::SUCCESS
            } else {
                eprintln!("msfe-ng service {a}: failed (see transcript above)");
                ExitCode::from(1)
            }
        }
        Some("spool-repair") => {
            let dry = std::env::args().any(|a| a == "--dry-run");
            let (_, outq) = service::queue_dirs(&cfg);
            match service::repair_spool(&outq, dry) {
                Ok(r) => {
                    for a in &r.actions {
                        println!("{a}");
                    }
                    println!(
                        "{} file(s) moved{}",
                        r.moved,
                        if r.dry_run {
                            " (dry-run: nothing changed)"
                        } else if r.flush_started {
                            ", delivery run started"
                        } else {
                            ""
                        }
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng service spool-repair: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("queue-fix") => match service::queue_fix(&cfg) {
            Ok(r) => {
                println!(
                    "queue-fix: {} orphaned files moved to {}, delivery run {}",
                    r.moved,
                    r.badqueue_dir.display(),
                    if r.flush_started {
                        "started"
                    } else {
                        "NOT started"
                    }
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng service queue-fix: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!(
                "usage: msfe-ng service <status|start|stop|reload|restart|queue-fix|spool-repair>"
            );
            ExitCode::from(2)
        }
    }
}

/// Toggle / report MailScanner scanning via the named-queue kill switch.
fn cmd_exim(sub: Option<&str>) -> ExitCode {
    use msfe_core::mailflow;
    let cfg = Config::load(&config_path());
    match sub {
        Some("status") => {
            println!(
                "MailScanner scanning: {}",
                mailflow::scanning_state(&cfg).describe()
            );
            if cfg.panel == "cpanel" {
                let (_, detail) = mailflow::cpanel_sa_verdict(&mailflow::cpanel_sa_state());
                println!("cPanel SpamAssassin: {detail}");
            }
            ExitCode::SUCCESS
        }
        Some(a @ ("enable-cpanel-spamassassin" | "disable-cpanel-spamassassin")) => {
            let enable = a.starts_with("enable");
            match mailflow::set_cpanel_sa(enable) {
                Ok(changed) => {
                    println!(
                        "cPanel Spam Filters turned {} for {} account(s){}",
                        if enable { "on" } else { "off" },
                        changed.len(),
                        if changed.is_empty() {
                            String::new()
                        } else {
                            format!(": {}", changed.join(", "))
                        }
                    );
                    let (_, detail) = mailflow::cpanel_sa_verdict(&mailflow::cpanel_sa_state());
                    println!("cPanel SpamAssassin: {detail}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng exim: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("enable-scanning") => match mailflow::set_scanning(&cfg, true) {
            Ok(()) => {
                println!("scanning enabled");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng exim: {e}");
                ExitCode::from(1)
            }
        },
        Some("disable-scanning") => match mailflow::set_scanning(&cfg, false) {
            Ok(()) => {
                println!("scanning disabled — mail bypasses MailScanner until enable-scanning");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng exim: {e}");
                ExitCode::from(1)
            }
        },
        _ => {
            eprintln!("usage: msfe-ng exim <status|enable-scanning|disable-scanning|enable-cpanel-spamassassin|disable-cpanel-spamassassin>");
            ExitCode::from(2)
        }
    }
}

/// The MSFE-NG config directory (parent of the config file).
fn conf_dir() -> PathBuf {
    config_path()
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .to_path_buf()
}

/// Back up config + policy (the config dir) to a gzip tarball.
/// Database maintenance: `backup` (timestamped mysqldump into `backup_dir`),
/// `fix` (apply migrations + table maintenance), and Bayes `bayes-repair` /
/// `bayes-recreate`.
fn cmd_db(sub: Option<&str>) -> ExitCode {
    use msfe_core::{dbtools, sa};
    let cfg = Config::load(&config_path());
    match sub {
        Some("backup") => match dbtools::backup(&cfg) {
            Ok(path) => {
                println!("wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng db backup: {e}");
                ExitCode::from(1)
            }
        },
        Some("fix") => {
            let r = dbtools::fix(&cfg, &migrations_dir());
            for l in &r.log {
                println!("{l}");
            }
            if r.ok {
                ExitCode::SUCCESS
            } else {
                eprintln!("msfe-ng db fix: completed with errors (see above)");
                ExitCode::from(1)
            }
        }
        Some(a @ ("bayes-repair" | "bayes-recreate")) => {
            // recreate is destructive — snapshot the SQL side first
            if a == "bayes-recreate" {
                match dbtools::backup(&cfg) {
                    Ok(p) => println!("backed up database to {}", p.display()),
                    Err(e) => eprintln!("warning: pre-reset backup failed: {e}"),
                }
            }
            let out = if a == "bayes-repair" {
                sa::bayes_repair(&cfg)
            } else {
                sa::bayes_reset(&cfg)
            };
            for l in &out.transcript {
                println!("{l}");
            }
            if out.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        _ => {
            eprintln!("usage: msfe-ng db <backup|fix|bayes-repair|bayes-recreate>");
            ExitCode::from(2)
        }
    }
}

/// `backup <file>`: the MSFE-NG config dir as a snapshot (alias of
/// `snapshot export --only msfe <file>`; the archive is the new format, which
/// `restore` and `snapshot import` both read, as they read the old one).
fn cmd_backup(file: Option<&str>) -> ExitCode {
    let Some(file) = file else {
        eprintln!("usage: {}", usage_of("backup"));
        return ExitCode::from(2);
    };
    let cfg = Config::load(&config_path());
    match msfe_core::snapshot::export(
        &cfg,
        &config_path(),
        msfe_core::snapshot::Only::Msfe,
        Some(Path::new(file)),
    ) {
        Ok((path, m)) => {
            println!(
                "backed up {} ({} files) to {}",
                conf_dir().display(),
                m.files.len(),
                path.display()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("msfe-ng backup: {e}");
            ExitCode::from(1)
        }
    }
}

/// `restore <file>`: every MSFE-NG config file in the archive (alias of
/// `snapshot import --only msfe --no-lint`).
fn cmd_restore(file: Option<&str>, rest: &[String]) -> ExitCode {
    let Some(file) = file else {
        eprintln!("usage: {}", usage_of("restore"));
        return ExitCode::from(2);
    };
    let mut args: Vec<String> = vec![
        file.to_string(),
        "--only".into(),
        "msfe".into(),
        "--no-lint".into(),
    ];
    if rest.iter().any(|a| a == "--yes") {
        args.push("--yes".into());
    }
    cmd_snapshot(Some("import"), &args)
}

/// `snapshot export|import|list`: the MailScanner etc tree and /etc/msfe-ng
/// as one tar.gz with a manifest — backup, restore, or move to another host.
fn cmd_snapshot(sub: Option<&str>, rest: &[String]) -> ExitCode {
    use msfe_core::snapshot::{self, Only, Status};
    let cfg = Config::load(&config_path());
    let mut only = Only::All;
    let mut positional: Vec<&String> = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if a == "--only" {
            match it.next().map(String::as_str).and_then(Only::parse) {
                Some(o) => only = o,
                None => {
                    eprintln!("msfe-ng snapshot: --only takes mailscanner or msfe");
                    return ExitCode::from(2);
                }
            }
        } else if !a.starts_with('-') {
            positional.push(a);
        }
    }
    match sub {
        Some("list") => {
            let l = snapshot::list(&cfg);
            if l.is_empty() {
                println!(
                    "no snapshots in {}",
                    snapshot::snapshots_dir(&cfg).display()
                );
                return ExitCode::SUCCESS;
            }
            for (p, size, mtime) in l {
                println!("{}\t{}\t{}", fmt_when(mtime), fmt_size(size), p.display());
            }
            ExitCode::SUCCESS
        }
        Some("export") => {
            let out = positional.first().map(|s| PathBuf::from(s.as_str()));
            match snapshot::export(&cfg, &config_path(), only, out.as_deref()) {
                Ok((path, m)) => {
                    println!(
                        "snapshot written: {} ({} files, {} · MailScanner {})",
                        path.display(),
                        m.files.len(),
                        fmt_size(std::fs::metadata(&path).map(|x| x.len()).unwrap_or(0)),
                        m.mailscanner_version.unwrap_or_else(|| "unknown".into())
                    );
                    println!("contains config.toml with the database password — keep it private");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng snapshot export: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("import") => {
            let Some(file) = positional.first() else {
                eprintln!("usage: {}", usage_of("snapshot"));
                return ExitCode::from(2);
            };
            let dry = rest.iter().any(|a| a == "--dry-run");
            let yes = rest.iter().any(|a| a == "--yes");
            let lint = if rest.iter().any(|a| a == "--no-lint") {
                msfe_core::confsave::LintMode::Skip
            } else {
                msfe_core::confsave::LintMode::Auto
            };
            let insp = match snapshot::inspect(&cfg, &config_path(), Path::new(file)) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("msfe-ng snapshot import: {e}");
                    return ExitCode::from(1);
                }
            };
            let m = &insp.manifest;
            if m.legacy {
                println!("legacy msfe-ng backup archive (MSFE-NG config dir only)");
            } else {
                println!(
                    "snapshot from {} taken {} (MSFE-NG {}, MailScanner {})",
                    m.host,
                    fmt_when(m.created),
                    m.msfe_ng,
                    m.mailscanner_version
                        .clone()
                        .unwrap_or_else(|| "unknown".into())
                );
            }
            let wanted = |id: &str| match only {
                Only::All => true,
                Only::Mailscanner => id.starts_with("ms:"),
                Only::Msfe => id.starts_with("msfe:"),
            };
            let mut select: Vec<String> = Vec::new();
            for f in &insp.files {
                if !wanted(&f.id) {
                    continue;
                }
                let pick = f.importable && f.status != Status::Same;
                println!(
                    "{:<8} {} {}{}",
                    f.status.as_str(),
                    if pick { "*" } else { " " },
                    f.id,
                    if f.id == "msfe:config.toml" && pick {
                        "   (host-specific: paths, database password)"
                    } else {
                        ""
                    }
                );
                if pick {
                    select.push(f.id.clone());
                }
            }
            if select.is_empty() {
                println!("nothing to import — every selected file is identical or not importable");
                snapshot::discard(&insp);
                return ExitCode::SUCCESS;
            }
            if dry {
                println!(
                    "dry run: {} file(s) would be imported (marked *)",
                    select.len()
                );
                snapshot::discard(&insp);
                return ExitCode::SUCCESS;
            }
            if !yes {
                print!(
                    "import {} file(s) marked *? The current versions are kept in history. [y/N] ",
                    select.len()
                );
                let _ = std::io::stdout().flush();
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
                if !matches!(line.trim(), "y" | "Y" | "yes") {
                    println!("aborted");
                    snapshot::discard(&insp);
                    return ExitCode::from(1);
                }
            }
            let done = match snapshot::import(&cfg, &config_path(), &insp, &select, lint) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("msfe-ng snapshot import: {e}");
                    snapshot::discard(&insp);
                    return ExitCode::from(1);
                }
            };
            snapshot::discard(&insp);
            let mut failed = 0;
            for (id, r) in &done {
                if r.changed {
                    println!(
                        "imported {id}{}",
                        r.backup_id
                            .as_ref()
                            .map(|b| format!(" (previous kept as {b})"))
                            .unwrap_or_default()
                    );
                } else {
                    failed += 1;
                    println!(
                        "NOT imported {id}: {}",
                        r.error.clone().unwrap_or_else(|| "unchanged".into())
                    );
                }
            }
            if let Some((_, r)) = done.iter().find(|(_, r)| r.changed || r.error.is_some()) {
                if let Some(v) = &r.validation {
                    println!(
                        "validation: {} {}",
                        v.tool,
                        if v.ok { "ok" } else { "FAILED" }
                    );
                    if !v.ok {
                        for p in &v.problems {
                            println!("  {p}");
                        }
                    }
                }
                if r.reloaded.action != "none" {
                    println!(
                        "MailScanner {}: {}",
                        r.reloaded.action,
                        if r.reloaded.ok { "done" } else { "FAILED" }
                    );
                }
                for l in &r.reloaded.transcript {
                    println!("  {l}");
                }
            }
            if failed > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        _ => {
            eprintln!("usage: {}", usage_of("snapshot"));
            ExitCode::from(2)
        }
    }
}

/// `msfe-ng delivery test <address> …`: the same run the panel makes,
/// streamed as it happens. Exit 0 = no failure, 1 = at least one failed
/// check, 2 = usage, 3 = the address was refused.
fn cmd_delivery(sub: Option<&str>, rest: &[String]) -> ExitCode {
    use msfe_core::delivery::Verdict;
    use msfe_core::deliveryrun;
    if sub == Some("inbox") {
        return cmd_delivery_inbox(rest);
    }
    if sub == Some("testmail") {
        return cmd_delivery_testmail(rest);
    }
    if sub == Some("monitor") {
        return cmd_delivery_monitor(rest);
    }
    let eml_mode = match sub {
        Some("test") => false,
        Some("eml") => true,
        _ => {
            eprintln!("usage: {}", usage_of("delivery"));
            return ExitCode::from(2);
        }
    };
    let cfg = Config::load(&config_path());
    let (mut ip, mut selector, mut days, mut address_opt) = (None, None, None, None);
    let (mut audit, mut json, mut html, mut force, mut bounce) =
        (false, false, false, false, false);
    let mut positional: Vec<&String> = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ip" => ip = it.next().map(String::as_str),
            "--selector" => selector = it.next().map(String::as_str),
            "--address" => address_opt = it.next().map(String::as_str),
            "--days" => days = it.next().and_then(|d| d.parse::<i64>().ok()),
            "--audit" => audit = true,
            "--json" => json = true,
            "--html" => html = true,
            "--force" => force = true,
            "--bounce" => bounce = true,
            x if !x.starts_with('-') => positional.push(a),
            _ => {}
        }
    }
    let Some(first) = positional.first() else {
        eprintln!("usage: {}", usage_of("delivery"));
        return ExitCode::from(2);
    };
    // an upload: what the file says fills in whatever was not given
    let mut eml = None;
    let (address, ip, selector): (String, Option<String>, Option<String>) = if eml_mode {
        use msfe_core::delivery::EmlKind;
        let raw = match std::fs::read(first) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("msfe-ng delivery eml: cannot read {first}: {e}");
                return ExitCode::from(3);
            }
        };
        let kind = if bounce {
            EmlKind::Bounce
        } else {
            EmlKind::Message
        };
        let d = msfe_core::emlcheck::derive_inputs(&raw, kind);
        let Some(address) = address_opt.map(str::to_string).or(d.address) else {
            eprintln!(
                "msfe-ng delivery eml: the message has no usable From address — give --address"
            );
            return ExitCode::from(3);
        };
        match deliveryrun::store_eml(kind, first.rsplit('/').next().unwrap_or("upload.eml"), &raw) {
            Ok(e) => eml = Some(e),
            Err(e) => {
                eprintln!("msfe-ng delivery eml: {e}");
                return ExitCode::from(3);
            }
        }
        force = true;
        (
            address,
            ip.map(str::to_string).or(d.ip.map(|i| i.to_string())),
            selector.map(str::to_string).or(d.selector),
        )
    } else {
        (
            first.to_string(),
            ip.map(str::to_string),
            selector.map(str::to_string),
        )
    };
    let mut inputs = match deliveryrun::parse_inputs(
        &address,
        ip.as_deref(),
        selector.as_deref(),
        days,
        audit,
        force,
        None,
    ) {
        Ok(i) => i,
        Err(e) => {
            eprintln!(
                "msfe-ng delivery {}: {e}",
                if eml_mode { "eml" } else { "test" }
            );
            return ExitCode::from(3);
        }
    };
    inputs.eml = eml;
    let quiet = json || html;
    let report = match (!force)
        .then(|| deliveryrun::cached_report(&inputs, cfg.delivery_cache_secs))
        .flatten()
    {
        Some(r) => {
            if !quiet {
                println!(
                    "(cached report from {} — use --force for a fresh run)",
                    fmt_when(r.started)
                );
            }
            r
        }
        None => {
            if !quiet {
                println!("testing {} …", inputs.address);
            }
            deliveryrun::run_blocking(&cfg, inputs, deliveryrun::plan, &mut |c| {
                if !quiet {
                    let tgt = c
                        .target
                        .as_deref()
                        .map(|t| format!(" [{t}]"))
                        .unwrap_or_default();
                    println!(
                        "[{:<7}] {:<22} {}{}",
                        c.verdict.as_str().to_uppercase(),
                        c.id,
                        c.title,
                        tgt
                    );
                }
            })
        }
    };
    if json {
        println!("{}", report.to_json());
    } else if html {
        println!("{}", msfe_core::deliveryhtml::render(&report));
    } else {
        println!();
        for (scope, n) in report.summary() {
            println!(
                "{:<10} {} fail, {} warning, {} unknown, {} pass, {} n/a",
                scope.as_str(),
                n[0],
                n[1],
                n[2],
                n[3],
                n[4]
            );
        }
        let problems: Vec<_> = report
            .sorted()
            .into_iter()
            .filter(|c| matches!(c.verdict, Verdict::Fail | Verdict::Warn))
            .collect();
        if !problems.is_empty() {
            println!("\nWhat to fix, most important first:");
            for c in problems {
                let tgt = c
                    .target
                    .as_deref()
                    .map(|t| format!(" [{t}]"))
                    .unwrap_or_default();
                println!(
                    "  {} {} — {}{}",
                    if c.verdict == Verdict::Fail {
                        "✗"
                    } else {
                        "!"
                    },
                    c.severity.as_str(),
                    c.title,
                    tgt
                );
                println!("      {}", c.explanation);
                if let Some(f) = &c.fix {
                    println!("      fix: {}", f.summary);
                    if let Some(r) = &f.dns_record {
                        println!("      DNS: {r}");
                    }
                    if let Some(l) = &f.location {
                        println!("      where: {l}");
                    }
                    if let Some(cmd) = &f.command {
                        println!("      run: {cmd}");
                    }
                    if let Some(u) = &f.url {
                        println!("      see: {u}");
                    }
                }
            }
        }
        for n in &report.tool_notes {
            println!("note: {n}");
        }
        println!("report id {}", report.id);
    }
    if report.checks.iter().any(|c| c.verdict == Verdict::Fail) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_delivery_monitor(rest: &[String]) -> ExitCode {
    use msfe_core::deliverymon;
    let cfg = Config::load(&config_path());
    let json = rest.iter().any(|a| a == "--json");
    let dry = rest.iter().any(|a| a == "--dry-run");
    let positional: Vec<&String> = rest.iter().filter(|a| !a.starts_with('-')).collect();
    let opt = |name: &str| {
        rest.iter()
            .position(|a| a == name)
            .and_then(|i| rest.get(i + 1))
            .cloned()
    };
    let db_err = |e: std::io::Error| -> ExitCode {
        eprintln!("msfe-ng delivery monitor: {e}\n(the monitors live in MySQL: is the database configured and migration 0003 applied? `msfe-ng db-migrate`)");
        ExitCode::from(1)
    };
    match positional.first().map(|s| s.as_str()) {
        Some("list") => {
            match deliverymon::list(&cfg, None) {
                Ok(ms) => {
                    if json {
                        println!(
                            "{}",
                            msfe_core::json::Json::Array(ms.iter().map(|m| m.to_json()).collect())
                        );
                    } else if ms.is_empty() {
                        println!("no delivery monitors (add one: msfe-ng delivery monitor add <address>)");
                    } else {
                        for m in ms {
                            println!(
                                "{:<5} {:<40} every {:>4} min  {}  last {}  {}",
                                m.id,
                                m.address,
                                m.interval_mins,
                                if m.enabled { "on " } else { "off" },
                                if m.last_run_at == 0 {
                                    "never".to_string()
                                } else {
                                    fmt_when(m.last_run_at)
                                },
                                m.last_summary
                            );
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => db_err(e),
            }
        }
        Some("add") => {
            let Some(address) = positional.get(1) else {
                eprintln!("usage: {}", usage_of("delivery"));
                return ExitCode::from(2);
            };
            let inputs = match msfe_core::deliveryrun::parse_inputs(
                address,
                opt("--ip").as_deref(),
                opt("--selector").as_deref(),
                opt("--days").and_then(|d| d.parse().ok()),
                rest.iter().any(|a| a == "--audit"),
                true,
                None,
            ) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("msfe-ng delivery monitor: {e}");
                    return ExitCode::from(3);
                }
            };
            let interval = opt("--interval-mins")
                .and_then(|v| v.parse().ok())
                .unwrap_or(deliverymon::DEFAULT_INTERVAL_MINS);
            match deliverymon::add(&cfg, &inputs, interval, "") {
                Ok(m) => {
                    println!("monitor {} for {} every {} min (first run at the next `msfe-ng monitor` pass)", m.id, m.address, m.interval_mins);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng delivery monitor: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("remove") => {
            let Some(what) = positional.get(1) else {
                eprintln!("usage: {}", usage_of("delivery"));
                return ExitCode::from(2);
            };
            let id = match what.parse::<u32>() {
                Ok(id) => Some(id),
                Err(_) => deliverymon::list(&cfg, None).ok().and_then(|ms| {
                    ms.into_iter()
                        .find(|m| m.address.eq_ignore_ascii_case(what))
                        .map(|m| m.id)
                }),
            };
            match id {
                Some(id) => match deliverymon::remove(&cfg, id, None) {
                    Ok(true) => {
                        println!("removed monitor {id}");
                        ExitCode::SUCCESS
                    }
                    Ok(false) => {
                        eprintln!("no monitor {id}");
                        ExitCode::from(1)
                    }
                    Err(e) => db_err(e),
                },
                None => {
                    eprintln!("no monitor for {what}");
                    ExitCode::from(1)
                }
            }
        }
        Some("run") => {
            if let Some(id) = opt("--id").and_then(|v| v.parse::<u32>().ok()) {
                // force one monitor now, regardless of its schedule
                let _ = msfe_core::db::exec_stdin(
                    &cfg,
                    &format!("UPDATE delivery_monitors SET last_run_at = 0 WHERE id = {id};\n"),
                );
            }
            for n in deliverymon::run_due(&cfg, dry) {
                println!("{n}");
            }
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: {}", usage_of("delivery"));
            ExitCode::from(2)
        }
    }
}

fn cmd_delivery_testmail(rest: &[String]) -> ExitCode {
    use msfe_core::testmail;
    let cfg = Config::load(&config_path());
    let (mut from, mut to, mut tag, mut follow) = (None, None, None, testmail::FOLLOW_SECS);
    let json = rest.iter().any(|a| a == "--json");
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--from" => from = it.next().cloned(),
            "--to" => to = it.next().cloned(),
            "--tag" => tag = it.next().cloned(),
            "--follow" => follow = it.next().and_then(|v| v.parse().ok()).unwrap_or(follow),
            _ => {}
        }
    }
    let (Some(from), Some(to)) = (from, to) else {
        eprintln!("usage: {}", usage_of("delivery"));
        return ExitCode::from(2);
    };
    let (from, to) = match testmail::validate(&from, &to) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("msfe-ng delivery testmail: {e}");
            return ExitCode::from(3);
        }
    };
    let tag = tag.unwrap_or_else(testmail::new_tag);
    let smtp = std::env::var("MSFE_NG_TESTMAIL_SMTP").unwrap_or_else(|_| "127.0.0.1:25".into());
    let result = testmail::run(
        &cfg,
        &from,
        &to,
        &tag,
        &smtp,
        std::time::Duration::from_secs(follow.clamp(10, 900)),
        &mut |p| {
            if !json {
                println!("{p}");
            } else {
                eprintln!("{p}");
            }
        },
    );
    if json {
        println!("{result}");
    } else {
        println!();
        if let Some(checks) = result.get("checks").and_then(|c| c.as_array()) {
            for c in checks {
                println!(
                    "[{:<7}] {:<20} {}",
                    c.str_field("verdict").to_uppercase(),
                    c.str_field("id"),
                    c.str_field("title")
                );
                if matches!(c.str_field("verdict").as_str(), "fail" | "warn" | "unknown") {
                    println!("          {}", c.str_field("explanation"));
                }
            }
        }
    }
    if matches!(result.get("ok"), Some(msfe_core::json::Json::Bool(true))) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn cmd_delivery_inbox(rest: &[String]) -> ExitCode {
    use msfe_core::diaginbox;
    let cfg = Config::load(&config_path());
    let dry = rest.iter().any(|a| a == "--dry-run");
    let what = rest
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str);
    let report = |r: std::io::Result<diaginbox::WireReport>| -> ExitCode {
        match r {
            Ok(w) => {
                for a in &w.actions {
                    println!("{}{a}", if w.dry_run { "[dry-run] " } else { "" });
                }
                println!(
                    "diagnostic inbox: {}",
                    if diaginbox::installed() {
                        "installed"
                    } else {
                        "not installed"
                    }
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("msfe-ng delivery inbox: {e}");
                ExitCode::from(1)
            }
        }
    };
    match what {
        Some("install") => report(diaginbox::wire(&cfg, dry)),
        Some("uninstall") => report(diaginbox::unwire(dry)),
        Some("status") => {
            let c = diaginbox::status_check();
            println!("{}: {} — {}", c.verdict.as_str(), c.title, c.explanation);
            if let Some(f) = c.fix {
                println!("fix: {}", f.summary);
            }
            println!("addresses: dt-<token>@{}", diaginbox::hostname(&cfg));
            ExitCode::SUCCESS
        }
        Some("sweep") => {
            diaginbox::sweep();
            println!("swept expired tokens and old boxes");
            ExitCode::SUCCESS
        }
        Some("new") => {
            if !diaginbox::installed() {
                eprintln!("msfe-ng delivery inbox: not installed — run `msfe-ng delivery inbox install` first");
                return ExitCode::from(1);
            }
            match diaginbox::create(&cfg) {
                Ok(i) => {
                    println!("{}", i.address);
                    println!("token {} · accepts mail for {} minutes · poll with: msfe-ng delivery inbox poll {}", i.token, diaginbox::TTL_SECS / 60, i.token);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("msfe-ng delivery inbox: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Some("poll") | Some("remove") => {
            let json = rest.iter().any(|a| a == "--json");
            let Some(token) = rest.iter().filter(|a| !a.starts_with('-')).nth(1) else {
                eprintln!("usage: {}", usage_of("delivery"));
                return ExitCode::from(2);
            };
            if what == Some("remove") {
                diaginbox::remove(token);
                println!("removed");
                return ExitCode::SUCCESS;
            }
            match diaginbox::poll(&cfg, token) {
                None => {
                    eprintln!("msfe-ng delivery inbox: no such inbox (expired or removed)");
                    ExitCode::from(1)
                }
                Some(st) => {
                    if json {
                        println!("{}", st.to_json());
                        return ExitCode::SUCCESS;
                    }
                    println!(
                        "{} · {}",
                        st.address,
                        if st.expired {
                            "expired"
                        } else if st.waiting {
                            "waiting for a message"
                        } else {
                            "message(s) received"
                        }
                    );
                    for m in &st.messages {
                        println!("\nmessage from {} at {}", m.from, fmt_when(m.received_at));
                        for c in &m.checks {
                            let tgt = c
                                .target
                                .as_deref()
                                .map(|t| format!(" [{t}]"))
                                .unwrap_or_default();
                            println!(
                                "[{:<7}] {:<22} {}{}",
                                c.verdict.as_str().to_uppercase(),
                                c.id,
                                c.title,
                                tgt
                            );
                            if matches!(
                                c.verdict,
                                msfe_core::delivery::Verdict::Fail
                                    | msfe_core::delivery::Verdict::Warn
                            ) {
                                println!("          {}", c.explanation);
                            }
                        }
                    }
                    ExitCode::SUCCESS
                }
            }
        }
        _ => {
            eprintln!("usage: {}", usage_of("delivery"));
            ExitCode::from(2)
        }
    }
}

fn fmt_size(n: u64) -> String {
    if n >= 1_048_576 {
        format!("{:.1} MB", n as f64 / 1_048_576.0)
    } else if n >= 1024 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn fmt_when(secs: u64) -> String {
    if secs == 0 {
        return "-".into();
    }
    let d = msfe_core::civil::Date::from_unix(secs);
    let sod = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.y,
        d.m,
        d.d,
        sod / 3600,
        (sod % 3600) / 60
    )
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
    conf test           Test the MailScanner configuration: lint + cross-file checks
                        (--with ms:<file>=<candidate> tests an edit on a staged copy)
    conf test-message   Simulate what the chain does with a message (clean|gtube|eicar|file.eml)
    snapshot export     Snapshot MailScanner's etc tree + /etc/msfe-ng into one tar.gz
    snapshot import     Compare a snapshot with this host and import chosen files (--dry-run first)
    snapshot list       Snapshots kept in backup_dir/snapshots
    delivery test <address>   Deliverability diagnostic: DNS, SPF/DKIM/DMARC, MX and TLS, MTA-STS/DANE,
                        blocklists (--ip, --selector, --audit, --json, --html)
    delivery eml <file>  The same for a saved message (headers, authentication results, links,
                        attachments) or, with --bounce, a bounce taken apart
    delivery testmail --from <a> --to <b>   Send a real test message from a hosted address and follow it
                        through the Exim log until the remote accepts or refuses it
    delivery monitor <list|add <address>|remove <id>|run>   Scheduled re-tests (msfe-ng monitor runs the due
                        ones; regressions go to Telegram); history in MySQL
    delivery inbox <install|uninstall|status|new|poll <token>|remove <token>|sweep>
                        The diagnostic inbox: one-time dt-<token>@<host> addresses wired into
                        Exim via /etc/exim.conf.local; `new` prints one, `poll` analyses what arrived
    digest [--dry-run]  Email quarantine digests to digest-enabled domains
    housekeeping        Prune old mail-log rows (cleanmysql retention)
    monitor [--dry-run] Auto-clean the delivery queue, fix misfiled spool files, send Telegram alerts (cron)
    engine migrate-legacy [--run]     ConfigServer MailScanner → the MailScanner RPM (preflight without --run)
    legacy decommission [--run]       Remove ConfigServer's MSFE front-end only, backed up first (preflight without --run)
    exim <status|enable-scanning|disable-scanning>   Toggle MailScanner scanning
    exim <enable|disable>-cpanel-spamassassin        cPanel's own SpamAssassin (double scan)
    upgrade [--check]                 Upgrade MSFE-NG to the latest release (or just compare)
    resolver <status|install>         Private DNS resolver (unbound on loopback) so the blocklists answer
    service <status|start|stop|reload|restart|queue-fix|spool-repair>   MailScanner service & queues
    doctor [--fix]      Check every link of the scanning chain; names each fix (--fix applies the mechanical ones)
    rules lint          Check managed ruleset files for unparsable lines
    rules adopt [--from <dir>]   Borrow existing on-disk rules into the custom store
    engine <status|install|configure|enable|disable|lint>   Manage the MailScanner engine itself
    engine <wire|unwire> [--dry-run]   Route mail through MailScanner via Exim (or undo)
    backup <file.tgz>   Back up config + policy to a tarball
    restore <file.tgz>  Restore config + policy from a tarball
    db-migrate          Apply pending SQL migrations
    db-migrate --status Show which migrations are applied/pending
    db backup           Dump the database to backup_dir (timestamped)
    db fix              Apply migrations + optimize/analyze MSFE-NG tables
    db bayes-repair     Expire & sync the SpamAssassin Bayes database
    db bayes-recreate   Back up, then wipe Bayes so it retrains from scratch
    mailscanner status  Show MailScanner logging plugin state
    mailscanner enable-logging   Hook the logging plugin into MailScanner.conf
    mailscanner disable-logging  Unhook it (restart MailScanner after either)
    version             Print version
    help                Show this help

ENVIRONMENT:
    MSFE_NG_SOCKET      Daemon socket path (default: {DEFAULT_SOCKET_PATH})
    MSFE_NG_CONFIG      Config file (default: {DEFAULT_CONFIG_FILE})
    MSFE_NG_MIGRATIONS  Migrations dir (default: {DEFAULT_MIGRATIONS_DIR})

PROJECT:
    https://github.com/inalto/msfe-ng        source, releases, issues
    https://github.com/inalto/msfe-ng/wiki   usage wiki"
    );
}
