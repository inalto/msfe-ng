//! System doctor: one pass over every link of the mail-scanning chain, each
//! finding paired with the exact command or button that fixes it.
//!
//! Surfaced as `msfe-ng doctor` (run at the end of every install/upgrade),
//! `GET /api/doctor`, and the warning banner in the WHM UI. Checks are
//! read-only — the doctor diagnoses, the named fixes repair.

use crate::{db, engine, mailflow, mailscanner, migrate, service, setup, Config};
use std::path::Path;
use std::process::Command;

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
    // MailScanner decides long vs short Exim message ids from `Exim Command
    // -bV` at startup with a naive numeric compare that misreads "4.100"
    // (cPanel 138) as 4.1: outgoing spool files then land in the wrong split
    // subdirectory and every quarantined/archived body is copied from the
    // wrong offset. Run both the real binary and the configured probe and
    // compare what each says.
    if configured {
        let probe_cmd = mailscanner::get_directive(&conf, "Exim Command").unwrap_or_default();
        let real_bv = exim_bv("/usr/sbin/exim");
        let probe_bv = exim_bv(probe_cmd);
        let (ok, detail) = exim_probe_verdict(&real_bv, &probe_bv);
        out.push(check(
            "MailScanner reads the Exim message-id format",
            ok,
            Level::Fail,
            detail,
            "msfe-ng engine configure (points Exim Command at the msfe-ng-exim shim), then restart MailScanner and run msfe-ng service spool-repair",
        ));
    }

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
    // The quarantine must be writable by the scanning children: spam-store and
    // the max-attempts archive create per-day subdirs from inside a child, and
    // a failed write there kills the child at batch build — one high-spam
    // message then wedges the entire scanning queue (seen in production as a
    // 15-hour mail outage with children dying before they could log a line).
    let run_user = engine::run_user_for(cfg);
    if let Ok(meta) = std::fs::metadata(&cfg.quarantine_dir) {
        if let (Some(uid), Some(gid)) = (engine::uid_of(run_user), engine::gid_of("mail")) {
            use std::os::unix::fs::MetadataExt;
            let ok = dir_writable_by(meta.uid(), meta.gid(), meta.mode(), uid, &[gid]);
            out.push(check(
                "quarantine writable by scan user",
                ok,
                Level::Fail,
                if ok {
                    format!("{} is writable by {run_user}", cfg.quarantine_dir)
                } else {
                    format!(
                        "{} is not writable by {run_user} — every quarantine/archive write kills a scanning child",
                        cfg.quarantine_dir
                    )
                },
                &format!(
                    "chown {run_user}:mail {} (or msfe-ng engine apply)",
                    cfg.quarantine_dir
                ),
            ));
        }
    }
    // Bayes and the network checks live in per-user homes, and the children
    // inherit root's HOME: without a shared state dir they scan with no Bayes
    // DB at all while the UI trains root's, and pyzor dies on /root/.pyzor.
    {
        use std::os::unix::fs::MetadataExt;
        let state = mailscanner::get_directive(&conf, "SpamAssassin User State Dir")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|dir| {
                let writable = std::fs::metadata(dir).ok().is_some_and(|meta| {
                    match (engine::uid_of(run_user), engine::gid_of("mail")) {
                        (Some(uid), Some(gid)) => {
                            dir_writable_by(meta.uid(), meta.gid(), meta.mode(), uid, &[gid])
                        }
                        _ => false,
                    }
                });
                (dir, Path::new(dir).is_dir(), writable)
            });
        let (ok, detail) = bayes_verdict(state, run_user);
        out.push(check(
            "Bayes DB shared with MailScanner",
            ok,
            Level::Warn,
            detail,
            "msfe-ng engine configure (sets SpamAssassin User State Dir and hands the dir to the scan user)",
        ));
        let site = engine::sa_site_rules_dir(&conf);
        let (ok, detail) = razor_verdict(
            engine::razor_admin_available(),
            engine::razor_home(&site).join("razor-agent.conf").is_file(),
            engine::razor_identity(&site).exists(),
        );
        out.push(check(
            "Razor reporting identity",
            ok,
            Level::Warn,
            detail,
            "msfe-ng engine configure (creates the shared razor home and runs razor-admin -register)",
        ));
        let pyzor = engine::pyzor_home(&site);
        let ok = pyzor.is_dir();
        out.push(check(
            "Pyzor shared home",
            ok,
            Level::Warn,
            if ok {
                format!("{} present", pyzor.display())
            } else {
                format!(
                    "{} missing — PYZOR_CHECK never fires under MailScanner",
                    pyzor.display()
                )
            },
            "msfe-ng engine configure (creates the shared pyzor home)",
        ));
    }
    out.push(dnsbl_check(&conf, Path::new(&cfg.mailscanner_conf)));
    // Mail over `Max Spam Check Size` bypasses every spam check; the DB
    // records those as "too large" reports.
    if let Some(limit) = mailscanner::get_directive(&conf, "Max Spam Check Size") {
        let bytes = engine::parse_ms_size(limit).unwrap_or(u64::MAX);
        let (skipped, total) = db::query(cfg, &skipped_over_limit_sql(bytes))
            .ok()
            .and_then(|rows| rows.into_iter().next())
            .map(|r| {
                let n = |i: usize| r.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                (n(0), n(1))
            })
            .unwrap_or((0, 0));
        let (ok, detail) = spam_check_size_verdict(limit, skipped, total);
        out.push(check(
            "large messages get spam-checked",
            ok,
            Level::Warn,
            detail,
            "msfe-ng engine configure (raises the stock 200k limit to 2M), or set Max Spam Check Size in MailScanner.conf",
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
    if clam {
        // A directive is not a scanner: after a clamav package update moved
        // the socket, MailScanner wedged every batch in its silent retry loop
        // for two days while this check stayed green. Actually connect.
        let sock = mailscanner::get_directive(&conf, "Clamd Socket")
            .unwrap_or("/var/clamd")
            .to_string();
        let port: u16 = mailscanner::get_directive(&conf, "Clamd Port")
            .and_then(|v| v.parse().ok())
            .unwrap_or(3310);
        let target = if sock.starts_with('/') {
            sock.clone()
        } else {
            format!("{sock}:{port}")
        };
        let alive = engine::clamd_reachable(&sock, port);
        let fix = match engine::detect_clamd_socket() {
            Some(live) if !alive => format!(
                "clamd answers at {live} — run msfe-ng engine configure to repoint MailScanner, then restart it"
            ),
            _ => "start clamd (systemctl restart clamd) or msfe-ng engine configure to re-detect its socket".into(),
        };
        out.push(check(
            "virus scanning (clamd)",
            alive,
            Level::Fail,
            if alive {
                format!("clamd reachable at {target}")
            } else {
                format!(
                    "clamd is NOT reachable at {target} — every scan batch wedges in MailScanner's retry loop and mail stops flowing"
                )
            },
            &fix,
        ));
    } else {
        out.push(check(
            "virus scanning (clamd)",
            false,
            Level::Warn,
            "no virus scanner configured".into(),
            "install clamd (msfe-ng engine install) then msfe-ng engine configure",
        ));
    }

    // ---- phishing site lists ----------------------------------------------
    // ms-cron DAILY refreshes phishing.{bad,safe}.sites.conf from
    // phishing.mailscanner.info. Behind Cloudflare that host answers older
    // curls' HTTP/2 with a 403 challenge page, which the upstream script saves
    // as the .gz — gunzip fails, the lists stay at whatever the RPM shipped,
    // and only a cron mail full of gzip errors says so.
    out.push(phishing_lists_check(cfg));

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

    let plugin = mailscanner::custom_functions_dir(&conf, &cfg.mailscanner_custom_dir)
        .join(msfe_api::MS_PLUGIN_FILENAME);
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
    // ---- alerting --------------------------------------------------------
    let token = !cfg.telegram_bot_token.trim().is_empty();
    let chat = !cfg.telegram_chat_id.trim().is_empty();
    if token != chat {
        out.push(check(
            "Telegram alerts half-configured",
            false,
            Level::Warn,
            if token {
                "bot token is set but the chat id is empty — alerts cannot be delivered".into()
            } else {
                "chat id is set but the bot token is empty — alerts cannot be delivered".into()
            },
            "Config → Telegram alerts",
        ));
    }
    let thresholds_set =
        cfg.alert_queue_size > 0 || cfg.alert_scan_stuck_mins > 0 || cfg.alert_burst_per_hour > 0;
    if thresholds_set && !(token && chat) {
        out.push(check(
            "alert thresholds without a delivery channel",
            false,
            Level::Warn,
            "alert thresholds are set but Telegram is not configured — alerts are only logged"
                .into(),
            "Config → Telegram alerts (bot token + chat id), then Send test message",
        ));
    }

    out
}

/// True when nothing failed (warnings allowed).
pub fn healthy(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.level != Level::Fail)
}

/// Can a user with `uid`/`gids` create entries in a directory owned by
/// `meta_uid`:`meta_gid` with `mode`? Creating an entry needs both write and
/// search (execute) permission on the directory.
fn dir_writable_by(meta_uid: u32, meta_gid: u32, mode: u32, uid: u32, gids: &[u32]) -> bool {
    if uid == 0 {
        return true;
    }
    let class = if uid == meta_uid {
        mode >> 6
    } else if gids.contains(&meta_gid) {
        mode >> 3
    } else {
        mode
    };
    class & 0o3 == 0o3 // write + search
}

/// What the phishing-list check looks at, gathered from disk.
#[derive(Debug, Clone, Copy)]
pub struct PhishingListState {
    /// `ms_cron_ps` in /etc/MailScanner/defaults (absent file counts as on).
    pub enabled: bool,
    /// Age of phishing.bad.sites.conf — rewritten by every successful update.
    pub list_age_days: Option<u64>,
    /// A `.master.gz` left behind that is not gzip data (the challenge page).
    pub junk_gz: bool,
    /// ms-update-phishing already fetches over HTTP/1.1.
    pub updater_patched: bool,
}

/// Successful updates rewrite the list daily; allow a few missed days for an
/// upstream hiccup before complaining.
const PHISHING_LIST_MAX_AGE_DAYS: u64 = 3;

fn phishing_lists_check(cfg: &Config) -> Check {
    let etc = Path::new(&cfg.mailscanner_conf)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into());
    let age_days = |p: &Path| {
        std::fs::metadata(p)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs() / 86_400)
    };
    let junk_gz = !engine::phishing_junk_downloads(&etc).is_empty();
    let updater_patched = std::fs::read_to_string(engine::phishing_updater_path())
        .is_ok_and(|s| engine::patch_phishing_updater(&s).is_none());
    let state = PhishingListState {
        enabled: service::phishing_update_enabled().unwrap_or(true),
        list_age_days: age_days(&etc.join("phishing.bad.sites.conf")),
        junk_gz,
        updater_patched,
    };
    let (ok, detail, fix) = phishing_lists_verdict(&state);
    check(
        "phishing site lists updating",
        ok,
        Level::Warn,
        detail,
        &fix,
    )
}

// ---- DNS blocklists ---------------------------------------------------------
//
// SpamAssassin's highest-value rules (Spamhaus ZEN/DBL, DNSWL, URIBL) and
// MailScanner's own `Spam List` are DNS lookups, and the lists answer with a
// code instead of data when they refuse the query — Spamhaus and DNSWL
// reject anything relayed through a shared/public resolver. Scoring then
// silently runs without them; only a `*_BLOCKED` 0.0 rule in the report
// tells. This check asks each list for its documented test record.

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ListState {
    Ok,
    /// The list answered, but with a "not serving you" code.
    Blocked(&'static str),
    /// Nothing came back: dead list, or DNS unreachable.
    NoAnswer,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ListKind {
    Spamhaus,
    Dnswl,
    Uribl,
    /// Any 127/8 answer to the 127.0.0.2 test entry means alive.
    Generic,
}

pub struct DnsblProbe {
    pub name: String,
    pub query: String,
    kind: ListKind,
}

impl DnsblProbe {
    pub fn spamhaus(zone: &str) -> Self {
        let query = if zone.starts_with("dbl.") {
            format!("dbltest.com.{zone}")
        } else {
            format!("2.0.0.127.{zone}")
        };
        Self {
            name: zone.to_string(),
            query,
            kind: ListKind::Spamhaus,
        }
    }
    pub fn dnswl() -> Self {
        Self {
            name: "list.dnswl.org".into(),
            query: "2.0.0.127.list.dnswl.org".into(),
            kind: ListKind::Dnswl,
        }
    }
    pub fn uribl() -> Self {
        Self {
            name: "multi.uribl.com".into(),
            query: "test.uribl.com.multi.uribl.com".into(),
            kind: ListKind::Uribl,
        }
    }
    /// A MailScanner `Spam List` entry from spam.lists.conf.
    pub fn mailscanner(name: &str, domain: &str) -> Self {
        Self {
            name: name.to_string(),
            query: format!("2.0.0.127.{domain}"),
            kind: ListKind::Generic,
        }
    }

    pub fn classify(&self, answers: &[std::net::Ipv4Addr]) -> ListState {
        if answers.is_empty() {
            return ListState::NoAnswer;
        }
        let o = |a: &std::net::Ipv4Addr| a.octets();
        match self.kind {
            ListKind::Spamhaus => {
                if answers.iter().any(|a| o(a) == [127, 255, 255, 254]) {
                    ListState::Blocked("refuses shared/public resolvers")
                } else if answers.iter().any(|a| o(a) == [127, 255, 255, 255]) {
                    ListState::Blocked("query limit exceeded")
                } else {
                    ListState::Ok
                }
            }
            ListKind::Dnswl => {
                if answers.iter().any(|a| o(a) == [127, 0, 0, 255]) {
                    ListState::Blocked("query limit exceeded for this resolver")
                } else {
                    ListState::Ok
                }
            }
            ListKind::Uribl => {
                if answers.iter().any(|a| o(a) == [127, 0, 0, 1]) {
                    ListState::Blocked("refuses this resolver (public or over its query limit)")
                } else {
                    ListState::Ok
                }
            }
            ListKind::Generic => {
                if answers.iter().any(|a| o(a)[0] == 127) {
                    ListState::Ok
                } else {
                    ListState::NoAnswer
                }
            }
        }
    }
}

/// The lists worth probing: SpamAssassin's network rules plus whatever
/// MailScanner's `Spam List` names (resolved through spam.lists.conf).
fn dnsbl_probes(ms_conf: &str, conf_path: &Path) -> Vec<DnsblProbe> {
    let mut probes = vec![
        DnsblProbe::spamhaus("zen.spamhaus.org"),
        DnsblProbe::spamhaus("dbl.spamhaus.org"),
        DnsblProbe::dnswl(),
        DnsblProbe::uribl(),
    ];
    if let Some(list) = mailscanner::get_directive(ms_conf, "Spam List") {
        let defs = std::fs::read_to_string(engine::spam_list_definitions(ms_conf, conf_path))
            .unwrap_or_default();
        let defs = engine::parse_rbl_definitions(&defs);
        for name in list.split_whitespace() {
            match defs.iter().find(|(n, _)| n == name) {
                Some((_, domain)) => probes.push(DnsblProbe::mailscanner(name, domain)),
                None => probes.push(DnsblProbe {
                    name: format!("{name} (not in spam.lists.conf)"),
                    query: String::new(),
                    kind: ListKind::Generic,
                }),
            }
        }
    }
    probes
}

/// Resolve every probe through the system resolver, in parallel, within one
/// deadline: the daemon is single-threaded and polls the doctor every minute,
/// so a dead list must cost a bounded wait, not a hang.
fn dnsbl_results(probes: &[DnsblProbe]) -> Vec<(String, ListState)> {
    use std::net::ToSocketAddrs;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let (tx, rx) = mpsc::channel();
    for (i, p) in probes.iter().enumerate() {
        if p.query.is_empty() {
            let _ = tx.send((i, Vec::new()));
            continue;
        }
        let tx = tx.clone();
        let q = p.query.clone();
        std::thread::spawn(move || {
            let ips: Vec<std::net::Ipv4Addr> = (q.as_str(), 0)
                .to_socket_addrs()
                .map(|it| {
                    it.filter_map(|a| match a.ip() {
                        std::net::IpAddr::V4(v4) => Some(v4),
                        _ => None,
                    })
                    .collect()
                })
                .unwrap_or_default();
            let _ = tx.send((i, ips));
        });
    }
    drop(tx);
    let mut answers: Vec<Option<Vec<std::net::Ipv4Addr>>> = vec![None; probes.len()];
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut pending = probes.len();
    while pending > 0 {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok((i, ips)) => {
                answers[i] = Some(ips);
                pending -= 1;
            }
            Err(_) => break,
        }
    }
    probes
        .iter()
        .zip(answers)
        .map(|(p, a)| (p.name.clone(), p.classify(&a.unwrap_or_default())))
        .collect()
}

/// First `nameserver` in resolv.conf when it is not a loopback address —
/// the usual reason Spamhaus and DNSWL refuse the queries.
pub fn shared_resolver() -> Option<String> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let first = text
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("nameserver"))?
        .trim()
        .to_string();
    let loopback = first
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);
    (!loopback).then_some(first)
}

/// `(ok, detail, fix)` for the probed lists.
pub fn dnsbl_verdict(
    results: &[(&str, ListState)],
    shared_resolver: Option<&str>,
) -> (bool, String, String) {
    let blocked: Vec<String> = results
        .iter()
        .filter_map(|(n, s)| match s {
            ListState::Blocked(why) => Some(format!("{n}: {why}")),
            _ => None,
        })
        .collect();
    let dead: Vec<String> = results
        .iter()
        .filter(|(_, s)| *s == ListState::NoAnswer)
        .map(|(n, _)| format!("{n}: no answer"))
        .collect();
    if blocked.is_empty() && dead.is_empty() {
        return (
            true,
            format!("{} lists answer their test records", results.len()),
            String::new(),
        );
    }
    let mut detail: Vec<String> = blocked.iter().chain(dead.iter()).cloned().collect();
    if let Some(r) = shared_resolver {
        detail.push(format!(
            "resolver in use: {r} (shared — the lists refuse it)"
        ));
    }
    let mut fix = Vec::new();
    if !blocked.is_empty() || shared_resolver.is_some() {
        fix.push(
            "run a private recursive resolver (unbound on 127.0.0.1) and point /etc/resolv.conf at it — see the wiki, Troubleshooting → DNS blocklists"
                .to_string(),
        );
    }
    if !dead.is_empty() {
        fix.push(
            "a list that never answers is dead or unreachable: drop it from MailScanner's Spam List (msfe-ng engine configure removes known-defunct ones)"
                .to_string(),
        );
    }
    (false, detail.join("; "), fix.join(". "))
}

/// How long one round of list probes stands: the UI's health poll runs the
/// doctor every minute, the lists need not hear from us that often.
pub const DNSBL_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Default)]
pub struct DnsblCache {
    at: Option<std::time::Instant>,
    results: Vec<(String, ListState)>,
}

impl DnsblCache {
    pub fn stale(&self, now: std::time::Instant) -> bool {
        match self.at {
            None => true,
            Some(t) => now.saturating_duration_since(t) > DNSBL_CACHE_TTL,
        }
    }
    /// Store a fresh round; true when the verdict differs from the last one
    /// (a first round counts as a change).
    pub fn store(&mut self, results: Vec<(String, ListState)>, now: std::time::Instant) -> bool {
        let changed = self.at.is_none() || self.results != results;
        self.at = Some(now);
        self.results = results;
        changed
    }
    pub fn results(&self) -> Vec<(String, ListState)> {
        self.results.clone()
    }
}

static DNSBL_CACHE: std::sync::Mutex<Option<DnsblCache>> = std::sync::Mutex::new(None);

fn dnsbl_check(ms_conf: &str, conf_path: &Path) -> Check {
    let now = std::time::Instant::now();
    let mut guard = DNSBL_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(DnsblCache::default);
    if cache.stale(now) {
        let probes = dnsbl_probes(ms_conf, conf_path);
        let fresh = dnsbl_results(&probes);
        if cache.store(fresh, now) {
            // journal trail for a verdict that comes and goes
            let line: Vec<String> = cache
                .results()
                .iter()
                .map(|(n, s)| format!("{n}={s:?}"))
                .collect();
            eprintln!("doctor: DNS blocklists: {}", line.join(" "));
        }
    }
    let results = cache.results();
    drop(guard);
    let results: Vec<(&str, ListState)> = results
        .iter()
        .map(|(n, s)| (n.as_str(), s.clone()))
        .collect();
    let (ok, detail, fix) = dnsbl_verdict(&results, shared_resolver().as_deref());
    check("DNS blocklists answering", ok, Level::Warn, detail, &fix)
}

/// 30-day count of mail skipped as too large that the current limit
/// (`bytes`) would still skip, plus the total.
pub fn skipped_over_limit_sql(bytes: u64) -> String {
    format!(
        "SELECT COALESCE(SUM(spamreport LIKE '%too large%' AND size > {bytes}),0), COUNT(*) \
         FROM maillog WHERE msg_ts >= (NOW() - INTERVAL 30 DAY)"
    )
}

/// `(ok, detail)` for `Max Spam Check Size`: `skipped` is the 30-day count
/// of mail the current limit would still skip; rulesets are the admin's
/// business.
pub fn spam_check_size_verdict(limit: &str, skipped: u64, total: u64) -> (bool, String) {
    let bytes = engine::parse_ms_size(limit);
    if skipped == 0 || bytes.is_none() {
        return (
            true,
            format!(
                "Max Spam Check Size = {}; no message in 30 days would be skipped as too large",
                limit.trim()
            ),
        );
    }
    (
        false,
        format!(
            "{skipped} of {total} messages in 30 days skipped every spam check as too large (Max Spam Check Size = {}) — HTML mail with images routinely exceeds it",
            limit.trim()
        ),
    )
}

/// `(ok, detail)` for the shared Bayes state dir: `state` is the configured
/// `SpamAssassin User State Dir` as `(path, exists, writable by run_user)`.
pub fn bayes_verdict(state: Option<(&str, bool, bool)>, run_user: &str) -> (bool, String) {
    match state {
        None => (
            false,
            "SpamAssassin User State Dir is not set — MailScanner scans with no Bayes DB and UI training goes to root's ~/.spamassassin".into(),
        ),
        Some((dir, false, _)) => (false, format!("{dir} is missing")),
        Some((dir, true, false)) => (
            false,
            format!("{dir} is not writable by {run_user} — Bayes cannot auto-learn or read UI training"),
        ),
        Some((dir, true, true)) => (true, format!("{dir} is writable by {run_user}")),
    }
}

/// `(ok, detail)` for Razor reporting: needs the client, a shared home, and
/// the identity `razor-admin -register` creates.
pub fn razor_verdict(razor_admin: bool, home: bool, identity: bool) -> (bool, String) {
    if !razor_admin {
        return (
            false,
            "razor-admin not installed (perl-Razor-Agent) — no Razor checks or reports".into(),
        );
    }
    if !home {
        return (
            false,
            "no shared razor home — razor falls back to $HOME/.razor, unreadable for the scan user"
                .into(),
        );
    }
    if !identity {
        return (
            false,
            "no registered identity — spam reports fail with \"report requires authentication\""
                .into(),
        );
    }
    (true, "shared home with a registered identity".into())
}

/// `(ok, detail, fix)` for the phishing-list state.
pub fn phishing_lists_verdict(s: &PhishingListState) -> (bool, String, String) {
    if !s.enabled {
        return (
            true,
            "daily update disabled in /etc/MailScanner/defaults (ms_cron_ps=0)".into(),
            String::new(),
        );
    }
    let days = |d: u64| format!("{d} day{}", if d == 1 { "" } else { "s" });
    let fix = if s.updater_patched {
        "run /usr/sbin/ms-update-phishing and check its output (the daily cron mail has the errors)"
            .to_string()
    } else {
        "msfe-ng engine configure (patches ms-update-phishing to fetch over HTTP/1.1 and clears the bad download), then run /usr/sbin/ms-update-phishing".to_string()
    };
    match s.list_age_days {
        Some(d) if d <= PHISHING_LIST_MAX_AGE_DAYS => (
            true,
            format!("phishing.bad.sites.conf updated {} ago", days(d)),
            String::new(),
        ),
        Some(d) if s.junk_gz => (
            false,
            format!(
                "lists last updated {} ago — the daily download returned an HTML page (Cloudflare challenge), not a gzip",
                days(d)
            ),
            fix,
        ),
        Some(d) => (
            false,
            format!(
                "lists last updated {} ago — the daily update is not succeeding",
                days(d)
            ),
            fix,
        ),
        None => (
            false,
            "phishing.bad.sites.conf is missing — MailScanner's phishing checks run without the site lists".into(),
            fix,
        ),
    }
}

/// `<cmd> -bV` output, empty when the command cannot run or hangs.
fn exim_bv(cmd: &str) -> String {
    if cmd.is_empty() {
        return String::new();
    }
    service::run_with_timeout(
        Command::new(cmd).arg("-bV"),
        std::time::Duration::from_secs(10),
    )
    .map(|o| o.stdout)
    .unwrap_or_default()
}

/// Compare the real Exim version with what MailScanner's startup probe will
/// conclude from the configured `Exim Command`. `(ok, detail)`.
pub fn exim_probe_verdict(real_bv: &str, probe_bv: &str) -> (bool, String) {
    let Some(real) = engine::exim_version(real_bv) else {
        return (
            false,
            "cannot read the Exim version from /usr/sbin/exim -bV".into(),
        );
    };
    let (major, minor) = real;
    let want_long = engine::exim_long_ids(real);
    let reads_long = engine::mailscanner_probe_long_ids(probe_bv);
    let fmt = |long: bool| if long { "long" } else { "short" };
    if want_long == reads_long {
        let via = if probe_bv.contains("msfe-ng shim") {
            " via the msfe-ng-exim shim"
        } else {
            ""
        };
        return (
            true,
            format!(
                "Exim {major}.{minor}: MailScanner reads {} message ids{via}",
                fmt(want_long)
            ),
        );
    }
    if probe_bv.trim().is_empty() {
        return (
            false,
            format!(
                "Exim {major}.{minor} writes {} ids but `Exim Command -bV` gives no output — MailScanner assumes short ids",
                fmt(want_long)
            ),
        );
    }
    let token = probe_bv
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(2))
        .unwrap_or("?");
    (
        false,
        format!(
            "Exim {major}.{minor} writes {} ids but MailScanner's probe reads '{token}' as {} — outgoing spool files misfiled, quarantined bodies copied from the wrong offset",
            fmt(want_long),
            fmt(reads_long)
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Spamhaus and DNSWL refuse queries relayed through shared/public
    // resolvers and say so in the answer; URIBL uses 127.0.0.1; a list that
    // answers nothing for its own test record is dead or unreachable.
    #[test]
    fn dnsbl_answers_are_classified_by_return_code() {
        use std::net::Ipv4Addr;
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let zen = DnsblProbe::spamhaus("zen.spamhaus.org");
        assert_eq!(
            zen.classify(&[ip("127.0.0.2"), ip("127.0.0.4")]),
            ListState::Ok
        );
        assert_eq!(
            zen.classify(&[ip("127.255.255.254")]),
            ListState::Blocked("refuses shared/public resolvers")
        );
        assert_eq!(
            zen.classify(&[ip("127.255.255.255")]),
            ListState::Blocked("query limit exceeded")
        );
        assert_eq!(zen.classify(&[]), ListState::NoAnswer);
        let dnswl = DnsblProbe::dnswl();
        assert_eq!(dnswl.classify(&[ip("127.0.10.0")]), ListState::Ok);
        assert!(matches!(
            dnswl.classify(&[ip("127.0.0.255")]),
            ListState::Blocked(_)
        ));
        let uribl = DnsblProbe::uribl();
        assert_eq!(uribl.classify(&[ip("127.0.0.14")]), ListState::Ok);
        assert!(matches!(
            uribl.classify(&[ip("127.0.0.1")]),
            ListState::Blocked(_)
        ));
        // a MailScanner Spam List entry: any 127/8 answer to 2.0.0.127 is alive
        let ms = DnsblProbe::mailscanner("BARRACUDA", "b.barracudacentral.org");
        assert_eq!(ms.query, "2.0.0.127.b.barracudacentral.org");
        assert_eq!(ms.classify(&[ip("127.0.0.2")]), ListState::Ok);
        assert_eq!(ms.classify(&[]), ListState::NoAnswer);
    }

    #[test]
    fn dnsbl_verdict_names_the_resolver_when_lists_block_it() {
        let results = vec![
            (
                "zen.spamhaus.org",
                ListState::Blocked("refuses shared/public resolvers"),
            ),
            ("list.dnswl.org", ListState::Ok),
            ("BARRACUDA", ListState::Ok),
        ];
        let (ok, detail, fix) = dnsbl_verdict(&results, Some("2a01:4ff:ff00::add:1"));
        assert!(!ok);
        assert!(
            detail.contains("zen.spamhaus.org") && detail.contains("refuses"),
            "{detail}"
        );
        assert!(detail.contains("2a01:4ff:ff00::add:1"), "{detail}");
        assert!(fix.contains("unbound"), "{fix}");

        let results = vec![("SORBS", ListState::NoAnswer), ("BARRACUDA", ListState::Ok)];
        let (ok, detail, fix) = dnsbl_verdict(&results, None);
        assert!(!ok);
        assert!(
            detail.contains("SORBS") && detail.contains("no answer"),
            "{detail}"
        );
        assert!(fix.contains("Spam List"), "{fix}");

        let results = vec![
            ("zen.spamhaus.org", ListState::Ok),
            ("BARRACUDA", ListState::Ok),
        ];
        let (ok, detail, _) = dnsbl_verdict(&results, None);
        assert!(ok, "{detail}");
        assert!(detail.contains("2 lists"), "{detail}");
    }

    // Counts only mail the *current* limit would still skip: after raising
    // 200k → 2M the month's history must not keep the warning on.
    #[test]
    fn spam_check_size_verdict_counts_mail_still_over_the_limit() {
        let (ok, d) = spam_check_size_verdict("200k", 52, 603);
        assert!(!ok);
        assert!(
            d.contains("52") && d.contains("603") && d.contains("200k"),
            "{d}"
        );
        let (ok, d) = spam_check_size_verdict("2M", 0, 500);
        assert!(ok, "{d}");
        assert!(d.contains("2M"), "{d}");
        assert!(spam_check_size_verdict("200k", 0, 10).0);
        // a ruleset value cannot be judged here
        assert!(spam_check_size_verdict("/etc/MailScanner/rules/size.rules", 3, 10).0);
        assert_eq!(
            skipped_over_limit_sql(2_000_000),
            "SELECT COALESCE(SUM(spamreport LIKE '%too large%' AND size > 2000000),0), COUNT(*) \
             FROM maillog WHERE msg_ts >= (NOW() - INTERVAL 30 DAY)"
        );
    }

    // The health poll runs the doctor every minute: the lists are asked at
    // most once per TTL, and a changed verdict is what gets logged.
    #[test]
    fn dnsbl_cache_serves_within_ttl_and_reports_changes() {
        use std::time::{Duration, Instant};
        let mut c = DnsblCache::default();
        let a = vec![("zen".to_string(), ListState::Ok)];
        let b = vec![("zen".to_string(), ListState::NoAnswer)];
        let t0 = Instant::now();
        assert!(c.stale(t0));
        assert!(c.store(a.clone(), t0), "first result is a change");
        assert!(!c.stale(t0 + Duration::from_secs(60)));
        assert!(c.stale(t0 + DNSBL_CACHE_TTL + Duration::from_secs(1)));
        assert_eq!(c.results(), a);
        assert!(!c.store(a.clone(), t0), "same verdict, nothing to log");
        assert!(c.store(b.clone(), t0), "verdict changed");
        assert_eq!(c.results(), b);
    }

    // The scanning children ran with no Bayes DB for months while the UI
    // trained root's: the check must fail on a missing directive, a missing
    // dir and a dir the run-as user cannot write, and pass only on a live one.
    #[test]
    fn bayes_verdict_requires_a_shared_writable_state_dir() {
        let (ok, d) = bayes_verdict(None, "mailnull");
        assert!(!ok);
        assert!(d.contains("SpamAssassin User State Dir"), "{d}");
        let (ok, d) = bayes_verdict(Some(("/x", false, false)), "mailnull");
        assert!(!ok);
        assert!(d.contains("/x") && d.contains("missing"), "{d}");
        let (ok, d) = bayes_verdict(Some(("/x", true, false)), "mailnull");
        assert!(!ok);
        assert!(d.contains("not writable by mailnull"), "{d}");
        let (ok, d) = bayes_verdict(Some(("/x", true, true)), "mailnull");
        assert!(ok, "{d}");
    }

    // "razor2 report failed: ... report requires authentication": a home
    // with no registered identity, or no razor at all.
    #[test]
    fn razor_verdict_needs_a_registered_identity() {
        let (ok, d) = razor_verdict(false, false, false);
        assert!(!ok);
        assert!(d.contains("razor-admin"), "{d}");
        let (ok, d) = razor_verdict(true, false, false);
        assert!(!ok);
        assert!(d.contains("home"), "{d}");
        let (ok, d) = razor_verdict(true, true, false);
        assert!(!ok);
        assert!(d.contains("identity"), "{d}");
        assert!(razor_verdict(true, true, true).0);
    }

    #[test]
    fn root_owned_0750_quarantine_is_not_writable_by_scan_user() {
        let (mailnull, mail) = (47, 12);
        // the production incident: root:mail 0750 — group can only read/search
        assert!(!dir_writable_by(0, mail, 0o750, mailnull, &[mail]));
        // owner mailnull 0750 — fine
        assert!(dir_writable_by(mailnull, mail, 0o750, mailnull, &[mail]));
        // root-owned but group-writable 0770 — fine via the mail group
        assert!(dir_writable_by(0, mail, 0o770, mailnull, &[mail]));
        // group write without search bit still cannot create entries
        assert!(!dir_writable_by(0, mail, 0o760, mailnull, &[mail]));
        // root can always write
        assert!(dir_writable_by(0, mail, 0o750, 0, &[]));
    }

    // Exim 4.100 (cPanel 138): MailScanner's `$ver >= 4.97` reads "4.100" as
    // 4.1 and drops back to short message ids — the check must catch it.
    #[test]
    fn exim_probe_verdict_catches_the_4_100_misread() {
        let real = "Exim version 4.100 #2 built 20-Aug-2026\n";
        let (ok, detail) = exim_probe_verdict(real, real);
        assert!(!ok);
        assert!(
            detail.contains("4.100") && detail.contains("4.1"),
            "{detail}"
        );

        let shimmed = "Exim version 4.99 #2 built 20-Aug-2026 (msfe-ng shim: real 4.100)\n";
        let (ok, detail) = exim_probe_verdict(real, shimmed);
        assert!(ok, "{detail}");
        assert!(detail.contains("long"), "{detail}");

        // pre-4.100 versions read correctly with or without the shim
        let v499 = "Exim version 4.99.2 #2 built\n";
        assert!(exim_probe_verdict(v499, v499).0);
        let v496 = "Exim version 4.96 #2 built\n";
        assert!(exim_probe_verdict(v496, v496).0);

        // probe command missing/broken → MailScanner sees short ids → fail
        let (ok, detail) = exim_probe_verdict(real, "");
        assert!(!ok);
        assert!(detail.contains("no output"), "{detail}");

        // real exim unreadable → cannot vouch → fail
        assert!(!exim_probe_verdict("", shimmed).0);
    }

    // phishing.mailscanner.info behind Cloudflare: the daily updater saved a
    // 403 challenge page as the .gz for weeks and the lists stayed at the
    // RPM's 2024 copies. The check reads the list's age, spots the HTML
    // leftover, and names the shim (engine configure) when it isn't applied.
    #[test]
    fn phishing_lists_verdict_reads_age_and_the_cloudflare_leftover() {
        let s = PhishingListState {
            enabled: true,
            list_age_days: Some(1),
            junk_gz: false,
            updater_patched: true,
        };
        let (ok, detail, _) = phishing_lists_verdict(&s);
        assert!(ok, "{detail}");
        assert!(detail.contains("1 day"), "{detail}");

        // fresh enough even a couple of days late (upstream hiccup)
        assert!(
            phishing_lists_verdict(&PhishingListState {
                list_age_days: Some(3),
                ..s
            })
            .0
        );

        // stale + HTML saved as .gz → the Cloudflare failure, fix = the shim
        let bad = PhishingListState {
            list_age_days: Some(320),
            junk_gz: true,
            updater_patched: false,
            ..s
        };
        let (ok, detail, fix) = phishing_lists_verdict(&bad);
        assert!(!ok);
        assert!(
            detail.contains("320 days") && detail.contains("HTML"),
            "{detail}"
        );
        assert!(fix.contains("engine configure"), "{fix}");

        // stale but already patched → the shim is not the answer
        let (ok, detail, fix) = phishing_lists_verdict(&PhishingListState {
            junk_gz: false,
            updater_patched: true,
            ..bad
        });
        assert!(!ok);
        assert!(
            detail.contains("320 days") && !detail.contains("HTML"),
            "{detail}"
        );
        assert!(
            !fix.contains("engine configure") && fix.contains("ms-update-phishing"),
            "{fix}"
        );

        // list file missing entirely
        let (ok, detail, _) = phishing_lists_verdict(&PhishingListState {
            list_age_days: None,
            ..bad
        });
        assert!(!ok);
        assert!(detail.contains("missing"), "{detail}");

        // operator turned the update off in /etc/MailScanner/defaults → not our business
        let (ok, detail, _) = phishing_lists_verdict(&PhishingListState {
            enabled: false,
            ..bad
        });
        assert!(ok);
        assert!(detail.contains("ms_cron_ps=0"), "{detail}");
    }
}
