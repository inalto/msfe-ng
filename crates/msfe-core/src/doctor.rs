//! System doctor: one pass over every link of the mail-scanning chain, each
//! finding paired with the exact command or button that fixes it.
//!
//! Surfaced as `msfe-ng doctor` (run at the end of every install/upgrade),
//! `GET /api/doctor`, and the warning banner in the WHM UI. Checks are
//! read-only — the doctor diagnoses, the named fixes repair.

use crate::{db, engine, mailflow, mailscanner, migrate, service, setup, Config};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "fail",
        }
    }
}

pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// How to fix it (command or UI button), when not ok.
    pub fix: Option<String>,
}

fn check(name: &'static str, ok: bool, level: Level, detail: String, fix: &str) -> Check {
    Check {
        name,
        level: if ok { Level::Ok } else { level },
        detail,
        fix: if ok { None } else { Some(fix.to_string()) },
    }
}

/// Run every check. Read-only; safe to call any time.
pub fn run(cfg: &Config, config_file: &Path) -> Vec<Check> {
    let mut out = Vec::new();

    // ---- engine ----------------------------------------------------------
    let engine = service::engine_installed();
    out.push(check(
        "MailScanner engine installed",
        engine,
        Level::Fail,
        if engine {
            "engine binaries present".into()
        } else {
            "mail cannot be scanned without the engine".into()
        },
        "msfe-ng engine install (or reinstall with --with-engine)",
    ));
    if !engine {
        return out; // everything else depends on it
    }

    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let configured = mailscanner::get_directive(&conf, "MTA") == Some("exim")
        && mailscanner::get_directive(&conf, "Exim Command").is_some_and(|v| !v.is_empty());
    out.push(check(
        "engine configured for Exim",
        configured,
        Level::Fail,
        if configured {
            "MTA=exim, Exim Command set".into()
        } else {
            "MailScanner.conf still carries sendmail defaults".into()
        },
        "msfe-ng engine configure (or Service tab → Configure for Exim)",
    ));

    let latch = service::engine_run_enabled();
    out.push(check(
        "safety switch (run_mailscanner)",
        latch == Some(true),
        Level::Warn,
        match latch {
            Some(true) => "ON — MailScanner may run".into(),
            Some(false) => "OFF — MailScanner cannot start".into(),
            None => "defaults file not found".into(),
        },
        "msfe-ng engine enable (or the Safety switch on the Service tab)",
    ));

    let st = service::status();
    out.push(check(
        "MailScanner running",
        st.active && st.procs > 0,
        Level::Fail,
        format!(
            "{}, {} process(es)",
            if st.active { "active" } else { "stopped" },
            st.procs
        ),
        "msfe-ng service start (or Start on the Service tab)",
    ));

    // ---- wiring ----------------------------------------------------------
    let wired = engine::is_wired(cfg);
    out.push(check(
        "Exim wired to MailScanner",
        wired,
        Level::Warn,
        if wired {
            "incoming mail is routed through the scanner".into()
        } else {
            "mail is delivered directly, without scanning".into()
        },
        "msfe-ng engine wire (or Wire Exim → MailScanner on the Service tab)",
    ));
    if wired {
        let (inc, _) = service::queue_dirs(cfg);
        let consistent = inc.to_string_lossy().contains("mailscanner");
        out.push(check(
            "queue dirs consistent with wiring",
            consistent,
            Level::Fail,
            format!("MailScanner scans {}", inc.display()),
            "msfe-ng engine wire (re-run to repair the queue directives)",
        ));
        let age = service::oldest_queue_age(&inc);
        let stuck = age.map(|a| a > 600).unwrap_or(false);
        // Engine down → the whole queue is blocked (fix the engine); engine up
        // but a message is old → that one message is stuck (deal with it in
        // the Queues tab), which shouldn't read as "the scanner is dead".
        let (detail, fix): (String, &str) = match age {
            Some(a) if stuck && st.active => (
                format!(
                    "a message has waited {} min while MailScanner is running — it is stuck on that message",
                    a / 60
                ),
                "Queues tab → the message → Deliver now (reads the error) or Delete; MailScanner --lint",
            ),
            Some(a) if stuck => (
                format!(
                    "oldest message has waited {} min and MailScanner is not running",
                    a / 60
                ),
                "start MailScanner (Service tab / msfe-ng service start)",
            ),
            Some(a) => (format!("oldest message {a}s old — flowing"), ""),
            None => ("queue is empty".into(), ""),
        };
        out.push(check(
            "scanning queue flowing",
            !stuck,
            Level::Fail,
            detail,
            fix,
        ));
    }
    // Misplaced spool files are invisible to delivery: Exim lists them but
    // computes their path from the message id, so they wait forever.
    let (_, outq) = service::queue_dirs(cfg);
    let misplaced = service::misplaced_spool(&outq).len();
    out.push(check(
        "spool files correctly placed",
        misplaced == 0,
        Level::Fail,
        if misplaced == 0 {
            "delivery queue files are in the subdirectories Exim expects".into()
        } else {
            format!("{misplaced} message(s) in the wrong split-spool subdirectory — Exim cannot deliver them")
        },
        "msfe-ng service spool-repair (or Queues tab → Fix misplaced spool files), then msfe-ng engine configure to stop it recurring",
    ));
    let scanning = mailflow::scanning_enabled();
    out.push(check(
        "scanning kill switch",
        scanning,
        Level::Warn,
        if scanning {
            "scanning enabled".into()
        } else {
            "scanning DISABLED via mailflow toggle".into()
        },
        "msfe-ng exim enable-scanning (or the mailflow toggle on the Service tab)",
    ));

    // ---- scanners --------------------------------------------------------
    let sa = setup::perl_module_ok("Mail::SpamAssassin");
    out.push(check(
        "SpamAssassin available to MailScanner",
        sa,
        Level::Warn,
        if sa {
            "Mail::SpamAssassin loads".into()
        } else {
            "no spam scoring without it".into()
        },
        "dnf -y install spamassassin (or re-run msfe-ng engine install with MSFE_NG_ENGINE_FORCE=1)",
    ));
    let clam = mailscanner::get_directive(&conf, "Virus Scanners")
        .map(|v| v.contains("clamd"))
        .unwrap_or(false);
    out.push(check(
        "virus scanning (clamd)",
        clam,
        Level::Warn,
        if clam {
            "MailScanner uses clamd".into()
        } else {
            "no virus scanner configured".into()
        },
        "install clamd (msfe-ng engine install) then msfe-ng engine configure",
    ));

    // ---- message bodies (archive) ----------------------------------------
    let (settings, _, _) = crate::sync::load_policy(&crate::sync::policy_dir(config_file));
    let archive_on = settings
        .iter()
        .find(|(k, _)| k == "archive")
        .map(|(_, v)| v != "no")
        .unwrap_or(true);
    if archive_on {
        let rules_ok = mailscanner::get_directive(&conf, "Archive Mail")
            .is_some_and(|v| !v.trim().is_empty())
            && Path::new(&cfg.mailscanner_rules_dir)
                .join("archive.rules")
                .exists();
        out.push(check(
            "message archive configured",
            rules_ok,
            Level::Warn,
            if rules_ok {
                "MailScanner is keeping a copy of every message".into()
            } else {
                "archiving is enabled in policy but MailScanner is not set up for it".into()
            },
            "msfe-ng sync",
        ));
        let dir = Path::new(&cfg.archive_dir);
        let writable = dir.is_dir()
            && std::fs::metadata(dir)
                .map(|m| {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o700 != 0
                })
                .unwrap_or(false);
        out.push(check(
            "archive directory ready",
            writable,
            Level::Fail,
            format!("{}", dir.display()),
            "msfe-ng engine configure",
        ));
        let bodydays = crate::housekeeping::body_retention_days(&settings);
        let (headroom_ok, detail) = match crate::housekeeping::disk_free(&cfg.archive_dir) {
            Some((total, avail)) if total > 0 => {
                let used_pct = 100 - (avail * 100 / total);
                (
                    used_pct < 85 && bodydays > 0,
                    if bodydays == 0 {
                        format!("{used_pct}% of the filesystem used, and body retention is set to keep forever")
                    } else {
                        format!(
                            "{used_pct}% used, {} GB free, keeping bodies {bodydays} days",
                            avail / 1_073_741_824
                        )
                    },
                )
            }
            _ => (true, "disk usage unknown".into()),
        };
        out.push(check(
            "archive disk headroom",
            headroom_ok,
            Level::Warn,
            detail,
            "lower 'Keep message bodies for (days)' in Settings, or turn archiving off",
        ));
    }

    // ---- database + logging ---------------------------------------------
    let db_conf = !cfg.db_pass.is_empty();
    out.push(check(
        "database credentials configured",
        db_conf,
        Level::Fail,
        if db_conf {
            "config.toml has credentials".into()
        } else {
            "no DB — nothing can be recorded".into()
        },
        "Dashboard → Create database & apply schema",
    ));
    if db_conf {
        let db_ok = db::query(cfg, "SELECT 1").is_ok();
        out.push(check(
            "database connection",
            db_ok,
            Level::Fail,
            if db_ok {
                "connects".into()
            } else {
                "configured credentials do not connect".into()
            },
            "Dashboard → Create database & apply schema (re-run)",
        ));
        if db_ok {
            let mig_dir = std::env::var("MSFE_NG_MIGRATIONS")
                .unwrap_or_else(|_| msfe_api::DEFAULT_MIGRATIONS_DIR.to_string());
            let pending = migrate::discover(Path::new(&mig_dir))
                .map(|all| {
                    let applied = migrate::applied_versions(cfg).unwrap_or_default();
                    migrate::pending(&all, &applied).len()
                })
                .unwrap_or(0);
            out.push(check(
                "database schema",
                pending == 0,
                Level::Fail,
                if pending == 0 {
                    "up to date".into()
                } else {
                    format!("{pending} migration(s) pending")
                },
                "msfe-ng db-migrate",
            ));
        }
    }

    let plugin = Path::new(&cfg.mailscanner_custom_dir).join(msfe_api::MS_PLUGIN_FILENAME);
    let logging = plugin.exists()
        && mailscanner::get_directive(&conf, mailscanner::LOGGING_DIRECTIVE)
            == Some(mailscanner::LOGGING_VALUE);
    out.push(check(
        "message logging enabled",
        logging,
        Level::Warn,
        if logging {
            "plugin installed and hooked".into()
        } else {
            "scanned messages are not recorded (Messages/stats stay empty)".into()
        },
        "Dashboard → Enable message logging (or msfe-ng mailscanner enable-logging)",
    ));
    if logging {
        for (module, pkg) in [("DBI", "perl-DBI"), ("DBD::mysql", "perl-DBD-MySQL")] {
            let ok = setup::perl_module_ok(module);
            out.push(check(
                "logging perl modules",
                ok,
                Level::Fail,
                if ok {
                    format!("{module} loads")
                } else {
                    format!("{module} missing — the logging plugin cannot write to the DB")
                },
                &format!("dnf -y install {pkg}"),
            ));
            if !ok {
                break;
            }
        }
        // the plugin (group mail) must read the credentials; the world must not
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = std::fs::metadata(config_file) {
            let mode = meta.mode() & 0o777;
            let world = mode & 0o004 != 0;
            let group_ok = mode & 0o040 != 0
                && engine::gid_of("mail")
                    .map(|g| g == meta.gid())
                    .unwrap_or(false);
            out.push(check(
                "credentials file permissions",
                !world && group_ok,
                Level::Warn,
                if world {
                    format!("{config_file:?} is world-readable (db_pass exposed)")
                } else if !group_ok {
                    format!("{config_file:?} not readable by group mail — the logging plugin cannot read db_pass")
                } else {
                    "root:mail 0640".into()
                },
                &format!(
                    "chown root:mail {} && chmod 640 {}",
                    config_file.display(),
                    config_file.display()
                ),
            ));
        }
    }
    out
}

/// True when nothing failed (warnings allowed).
pub fn healthy(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.level != Level::Fail)
}
