//! Guided migration from ConfigServer's bundled MailScanner (`/usr/mailscanner`
//! + the `/usr/msfe` front-end) to the MailScanner v5 RPM.
//!
//! ConfigServer's uninstaller removes its front-end *and* its engine, and the
//! RPM installer refuses to install beside `/usr/mailscanner` — so the two
//! must happen in one sequence, with mail spooling meanwhile (Exim keeps
//! queuing into the scanning spool; nothing is lost, it is scanned once the
//! new engine runs). `preflight` says what will happen; `run` does it step by
//! step, printing each, and stops at the first failure with the doctor's fix
//! — never half-applying the next step. The Service tab runs it as the
//! `engine-migrate` job; `msfe-ng engine migrate-legacy --run` from a shell.

use crate::{engine, layout, legacy, service, setup, sync, upgrade, Config};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const JOB: &str = "engine-migrate";
pub const LEGACY_TREE: &str = "/usr/mailscanner";
/// Copy of the legacy engine's etc, kept for reference (org name, custom
/// rules, spamassassin.conf) after `/usr/mailscanner` is gone.
pub const SNAPSHOT_DIR: &str = "/etc/msfe-ng/legacy-engine-etc";
/// Files ConfigServer's uninstaller is known to leave behind, besides the
/// cron entries `legacy::remnants` finds (csget is its shared updater, also
/// csf's — never touched).
const LEGACY_FILES: [&str; 1] = ["/etc/init.d/MailScanner"];

/// ConfigServer's uninstaller, whatever it is called: `uninstall.msfe.sh` in
/// the versions seen, so any `uninstall*.sh` under /usr/msfe counts.
pub fn find_uninstaller(root: &Path) -> Option<PathBuf> {
    let dir = root.join("usr/msfe");
    let mut found: Vec<PathBuf> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with("uninstall") && n.ends_with(".sh")
                })
        })
        .collect();
    found.sort();
    found.into_iter().next()
}

fn root() -> PathBuf {
    std::env::var("MSFE_NG_MIGRATION_ROOT")
        .unwrap_or_else(|_| "/".to_string())
        .into()
}
fn at(p: &str) -> PathBuf {
    root().join(p.trim_start_matches('/'))
}

#[derive(Debug, Clone, Default)]
pub struct Preflight {
    /// The ConfigServer tree is present.
    pub legacy_engine: bool,
    pub engine: String,
    pub uninstaller: bool,
    pub remnants: Vec<String>,
    pub policy_imported: bool,
    pub db_configured: bool,
    pub queue_incoming: usize,
    /// How Exim routes mail through MailScanner now, if at all.
    pub wiring: Option<String>,
    pub latest_rpm: Option<String>,
    /// Reasons the migration cannot start.
    pub blockers: Vec<String>,
    /// Things worth knowing before starting.
    pub warnings: Vec<String>,
}

impl Preflight {
    pub fn ok(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// What the migration would do; `starting` adds the "already running" blocker
/// (meaningless from inside the running job itself).
pub fn preflight(cfg: &Config, config_file: &Path) -> Preflight {
    preflight_for(cfg, config_file, true)
}

pub fn preflight_for(cfg: &Config, config_file: &Path, starting: bool) -> Preflight {
    let lay = layout::resolve(cfg);
    let legacy_engine = at(LEGACY_TREE).is_dir();
    let (settings, _, _) = sync::load_policy(&sync::policy_dir(config_file));
    let (inc, _) = service::queue_dirs(cfg);
    let mut p = Preflight {
        legacy_engine,
        engine: format!(
            "MailScanner {} at {}",
            lay.version_string(),
            lay.bin.display()
        ),
        uninstaller: find_uninstaller(&root()).is_some(),
        remnants: legacy::remnants(&root()),
        policy_imported: !settings.is_empty(),
        db_configured: cfg.db_configured(),
        queue_incoming: service::count_queue(&inc),
        wiring: engine::exim_method(cfg).map(|m| m.describe().to_string()),
        latest_rpm: None,
        blockers: Vec::new(),
        warnings: Vec::new(),
    };
    if !legacy_engine {
        p.blockers.push(format!(
            "no ConfigServer engine at {LEGACY_TREE} — nothing to migrate"
        ));
    }
    if starting && crate::jobs::status(JOB).running {
        p.blockers.push("a migration is already running".into());
    }
    if !p.policy_imported {
        p.warnings.push("no policy imported yet — run `msfe-ng import /usr/msfe --save` first: the legacy settings are deleted together with /usr/msfe".into());
    }
    if !p.db_configured {
        p.warnings.push("database not configured — messages will not be logged until it is (Dashboard → Create database)".into());
    }
    if !p.uninstaller {
        p.warnings
            .push("no uninstall*.sh under /usr/msfe — the legacy tree is removed directly".into());
    }
    if p.queue_incoming > 0 {
        p.warnings.push(format!(
            "{} message(s) wait in the scanning queue; they are scanned once the new engine runs",
            p.queue_incoming
        ));
    }
    if p.wiring.is_none() {
        p.warnings.push("Exim is not routing mail through MailScanner; the named-queue wiring is set up at the end".into());
    }
    p
}

fn step(n: usize, what: &str) {
    println!("\n==> step {n}: {what}");
}

fn run_logged(cmd: &mut Command) -> io::Result<bool> {
    // inherit stdout/stderr: in a job that is the log, in a shell the terminal
    let st = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;
    Ok(st.success())
}

fn fail(msg: String) -> io::Error {
    io::Error::other(msg)
}

/// The migration, start to finish. Prints every step; returns the first
/// failure with what to do next.
pub fn run(config_file: &Path) -> io::Result<()> {
    let cfg = Config::load(config_file);
    // this very run is the job: the "already running" blocker must not apply
    let pf = preflight_for(&cfg, config_file, false);
    println!("preflight: {}", pf.engine);
    for w in &pf.warnings {
        println!("  note: {w}");
    }
    if let Some(b) = pf.blockers.first() {
        return Err(fail(format!("cannot start: {b}")));
    }
    let root = root();
    let live = root == Path::new("/");

    step(1, "backup of /etc/msfe-ng");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = Path::new(&cfg.backup_dir).join(format!("pre-migration-{stamp}.tar.gz"));
    std::fs::create_dir_all(&cfg.backup_dir)?;
    let conf_dir = config_file.parent().unwrap_or(Path::new("/etc/msfe-ng"));
    let ok = run_logged(
        Command::new("tar")
            .arg("czf")
            .arg(&backup)
            .arg("-C")
            .arg(conf_dir.parent().unwrap_or(Path::new("/etc")))
            .arg(conf_dir.file_name().unwrap_or_default()),
    )?;
    if !ok {
        return Err(fail(format!("backup to {} failed", backup.display())));
    }
    println!("  {}", backup.display());

    step(2, "snapshot of the legacy engine's etc");
    let snapshot = at(SNAPSHOT_DIR);
    let legacy_etc = at(LEGACY_TREE).join("etc");
    if legacy_etc.is_dir() {
        let _ = std::fs::remove_dir_all(&snapshot);
        if !run_logged(Command::new("cp").arg("-a").arg(&legacy_etc).arg(&snapshot))? {
            return Err(fail("cannot copy the legacy etc".into()));
        }
        println!("  {} → {}", legacy_etc.display(), snapshot.display());
    } else {
        println!("  no {} — skipped", legacy_etc.display());
    }
    let legacy_conf =
        std::fs::read_to_string(snapshot.join("MailScanner.conf")).unwrap_or_default();

    step(3, "stop the legacy MailScanner");
    if live {
        let o = service::control("stop");
        for l in &o.transcript {
            println!("  {l}");
        }
    }

    step(4, "remove the ConfigServer front-end and engine");
    for l in remove_legacy(&root, live)? {
        println!("  {l}");
    }

    step(5, "install the MailScanner RPM");
    let latest = if live {
        service::latest_release(service::MAILSCANNER_REPO)
    } else {
        None
    };
    let mut c = Command::new("sh");
    c.arg(at(upgrade::ENGINE_INSTALL_SCRIPT));
    if let Some(v) = &latest {
        println!("  latest release: {v}");
        c.env("MSFE_NG_MS_VERSION", v);
    }
    if !run_logged(&mut c)? {
        return Err(fail(
            "the engine installer failed — see above; re-run `msfe-ng engine install`, then `msfe-ng engine migrate-legacy --run` picks up here".into(),
        ));
    }

    step(6, "point MSFE-NG at the new engine");
    // config.toml may still name /usr/mailscanner; the RPM conf is what is
    // left and what Config::load already falls back to — make it explicit.
    let cfg = Config::load(config_file);
    let text = std::fs::read_to_string(config_file).unwrap_or_default();
    let fixed: String = text
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("mailscanner_conf") {
                format!("mailscanner_conf = \"{}\"", cfg.mailscanner_conf)
            } else {
                l.to_string()
            }
        })
        .map(|l| l + "\n")
        .collect();
    if fixed != text {
        sync::atomic_write(config_file, fixed.as_bytes())?;
    }
    println!("  mailscanner_conf = {}", cfg.mailscanner_conf);

    step(7, "carry the site identity over");
    let ms_text = std::fs::read_to_string(&cfg.mailscanner_conf)?;
    let (ms_text, carried) = carry_identity(&legacy_conf, &ms_text);
    for l in &carried {
        println!("  {l}");
    }
    service::save_conf(Path::new(&cfg.mailscanner_conf), &ms_text)?;

    step(8, "configure the engine for Exim");
    let r = engine::configure(&cfg)?;
    for l in r
        .set
        .iter()
        .chain(r.created.iter())
        .chain(r.repaired.iter())
    {
        println!("  {l}");
    }
    for w in &r.warnings {
        println!("  warning: {w}");
    }

    step(9, "hook the message logging plugin");
    for l in setup::enable_logging(&cfg)? {
        println!("  {l}");
    }

    step(10, "write the rule files");
    let s = sync::run(&cfg, config_file, None)?;
    println!("  {} rule files ({} changed)", s.files, s.changed);

    step(11, "Exim wiring");
    match engine::exim_method(&cfg) {
        Some(m) => println!("  kept: {}", m.describe()),
        None => {
            let r = engine::wire(&cfg, false)?;
            for l in &r.actions {
                println!("  {l}");
            }
        }
    }

    step(12, "start the new engine");
    if live {
        if let Err(e) = service::set_engine_run(&cfg, true) {
            println!("  startup latch: {e}");
        }
        let unit = layout::service_unit();
        let _ = Command::new("systemctl").args(["enable", unit]).status();
        let o = service::control("restart");
        for l in &o.transcript {
            println!("  {l}");
        }
        if !o.ok {
            return Err(fail(
                "MailScanner did not start — run `msfe-ng engine lint`".into(),
            ));
        }
    }

    step(13, "doctor (repairing what is mechanical first)");
    for l in crate::doctor::fix(&cfg, config_file) {
        println!("  fix: {l}");
    }
    let checks = crate::doctor::run(&cfg, config_file);
    for c in checks
        .iter()
        .filter(|c| c.level != crate::doctor::Level::Ok)
    {
        println!("  [{}] {} — {}", c.level.as_str(), c.name, c.detail);
        if let Some(f) = &c.fix {
            println!("        fix: {f}");
        }
    }
    println!("\nmigration finished — the legacy etc is kept at {SNAPSHOT_DIR}");
    Ok(())
}

/// Remove what ConfigServer installed: its uninstaller first when present
/// (answering yes), then whatever it left — the engine tree and its SysV
/// service, then the front-end (`legacy::remove_front_end`). Returns what
/// was done.
pub fn remove_legacy(root: &Path, live: bool) -> io::Result<Vec<String>> {
    let mut done = Vec::new();
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    if let Some(uninstaller) = find_uninstaller(root) {
        done.push(format!(
            "running {} (answers yes to its prompts)",
            uninstaller.display()
        ));
        let ok = run_logged(
            Command::new("sh")
                .arg("-c")
                .arg(format!("yes | sh {}", uninstaller.display())),
        )?;
        if !ok {
            done.push("WARNING: the uninstaller exited non-zero — removing what is left".into());
        }
    }
    let engine_tree = at(LEGACY_TREE);
    if engine_tree.exists() {
        std::fs::remove_dir_all(&engine_tree)?;
        done.push(format!("removed {LEGACY_TREE}"));
    }
    for f in LEGACY_FILES {
        let p = at(f);
        if p.is_file() {
            std::fs::remove_file(&p)?;
            done.push(format!("removed {f}"));
        }
    }
    if live {
        let _ = Command::new("chkconfig")
            .args(["--del", "MailScanner"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("systemctl").arg("daemon-reload").status();
    }
    // a hand-written MailScanner.service pointing at the removed tree would
    // fail at every boot from now on
    done.extend(legacy::remove_stale_engine_units(root, live)?);
    // the front-end itself: the tree, its cron files, root's crontab lines,
    // the WHM app — shared with `legacy_decommission`
    done.extend(legacy::remove_front_end(root, live)?);
    let left = legacy::remnants(root);
    if !left.is_empty() {
        done.push(format!(
            "still present (remove by hand): {}",
            left.join(", ")
        ));
    }
    Ok(done)
}

/// The new conf with the legacy conf's site identity (`%org-name%`,
/// `%org-long-name%`, `%web-site%`) and what was carried.
pub fn carry_identity(legacy_conf: &str, new_conf: &str) -> (String, Vec<String>) {
    let mut text = new_conf.to_string();
    let mut carried = Vec::new();
    for name in ["%org-name%", "%org-long-name%", "%web-site%"] {
        if let Some(v) = crate::mailscanner::variable(legacy_conf, name) {
            text = crate::mailscanner::set_variable(&text, name, &v);
            carried.push(format!("{name} = {v}"));
        }
    }
    (text, carried)
}

/// Start the migration as a background job followed by the UI.
pub fn start_job() -> io::Result<()> {
    crate::jobs::start(JOB, "msfe-ng engine migrate-legacy --run", &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("msfe-mig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in [
            "usr/mailscanner/etc/rules",
            "usr/msfe",
            "etc/cron.d",
            "etc/cron.daily",
            "etc/init.d",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(
            root.join("usr/mailscanner/etc/MailScanner.conf"),
            "%org-name% = acme\n%org-long-name% = Acme Mail\n%web-site% = www.acme.example\nMTA = exim\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("etc/cron.hourly")).unwrap();
        std::fs::write(
            root.join("etc/cron.hourly/msdigest.pl"),
            "#!/usr/bin/perl\n# /usr/msfe/msdigest.pl\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.d/msfe.sh"),
            "0 * * * * root /usr/msfe/msbe.pl\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.daily/mailscanner_daily.cron"),
            "/usr/msfe/x\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/cron.daily/csget"), "/usr/msfe /usr/csf\n").unwrap();
        std::fs::write(root.join("etc/init.d/MailScanner"), "#!/bin/sh\n").unwrap();
        root
    }

    #[test]
    fn remove_legacy_runs_the_uninstaller_then_clears_what_is_left() {
        let root = fixture("remove");
        // an uninstaller that prompts and removes only the front-end dir
        std::fs::write(
            root.join("usr/msfe/uninstall.sh"),
            format!(
                "#!/bin/sh\nread -r a; echo \"answer=$a\" > {}/uninstall.ran\nrm -rf {}/usr/msfe\n",
                root.display(),
                root.display()
            ),
        )
        .unwrap();
        let done = remove_legacy(&root, false).unwrap();
        assert_eq!(
            std::fs::read_to_string(root.join("uninstall.ran"))
                .unwrap()
                .trim(),
            "answer=y",
            "prompts answered yes"
        );
        assert!(!root.join("usr/msfe").exists());
        assert!(
            !root.join("usr/mailscanner").exists(),
            "engine tree removed too"
        );
        assert!(!root.join("etc/cron.d/msfe.sh").exists());
        assert!(
            !root.join("etc/cron.hourly/msdigest.pl").exists(),
            "every legacy cron entry goes"
        );
        assert!(!root.join("etc/cron.daily/mailscanner_daily.cron").exists());
        assert!(!root.join("etc/init.d/MailScanner").exists());
        assert!(
            root.join("etc/cron.daily/csget").exists(),
            "csget is csf's updater: kept"
        );
        assert!(
            done.iter().any(|l| l == "removed /usr/mailscanner"),
            "{done:?}"
        );
        assert!(
            !done.iter().any(|l| l.starts_with("still present")),
            "{done:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn remove_legacy_without_an_uninstaller_removes_the_trees_itself() {
        let root = fixture("plain");
        let done = remove_legacy(&root, false).unwrap();
        assert!(!root.join("usr/mailscanner").exists() && !root.join("usr/msfe").exists());
        assert!(!done.iter().any(|l| l.contains("uninstall")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn carry_identity_moves_the_three_site_variables() {
        let legacy =
            "%org-name% = acme\n%org-long-name% = Acme Mail\n%web-site% = www.acme.example\n";
        let fresh = "%org-name% = yoursite\n%org-long-name% = Your Organisation Name Here\n%web-site% = www.your-organisation.com\n%etc-dir% = /etc/MailScanner\n";
        let (out, carried) = carry_identity(legacy, fresh);
        assert_eq!(
            out,
            "%org-name% = acme\n%org-long-name% = Acme Mail\n%web-site% = www.acme.example\n%etc-dir% = /etc/MailScanner\n"
        );
        assert_eq!(carried.len(), 3);
        let (same, none) = carry_identity("MTA = exim\n", fresh);
        assert_eq!(same, fresh);
        assert!(none.is_empty());
    }

    #[test]
    fn preflight_blocks_without_a_legacy_engine_and_warns_about_the_rest() {
        let root = std::env::temp_dir().join(format!("msfe-mig-pf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/msfe-ng")).unwrap();
        std::env::set_var("MSFE_NG_MIGRATION_ROOT", &root);
        let cfg = Config::default();
        let pf = preflight(&cfg, &root.join("etc/msfe-ng/config.toml"));
        assert!(!pf.ok());
        assert!(
            pf.blockers[0].contains("nothing to migrate"),
            "{:?}",
            pf.blockers
        );
        std::fs::create_dir_all(root.join("usr/mailscanner")).unwrap();
        let pf = preflight(&cfg, &root.join("etc/msfe-ng/config.toml"));
        assert!(pf.ok(), "{:?}", pf.blockers);

        // the job itself is running (its pid file names this process): the
        // run's own preflight must not block, the start path must
        // same per-process dir the jobs tests use (the env var is process-wide)
        let jobs = std::env::temp_dir().join(format!("msfe-jobs-{}", std::process::id()));
        std::fs::create_dir_all(&jobs).unwrap();
        std::env::set_var("MSFE_NG_JOBS_DIR", &jobs);
        std::fs::write(jobs.join(format!("{JOB}.log")), "").unwrap();
        std::fs::write(
            jobs.join(format!("{JOB}.pid")),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        assert!(crate::jobs::status(JOB).running);
        let pf = preflight_for(&cfg, &root.join("etc/msfe-ng/config.toml"), false);
        assert!(pf.ok(), "inside the job: {:?}", pf.blockers);
        let pf = preflight(&cfg, &root.join("etc/msfe-ng/config.toml"));
        assert!(pf.blockers.iter().any(|b| b.contains("already running")));
        let _ = std::fs::remove_file(jobs.join(format!("{JOB}.pid")));
        assert!(
            pf.warnings.iter().any(|w| w.contains("no policy imported")),
            "{:?}",
            pf.warnings
        );
        assert!(pf.warnings.iter().any(|w| w.contains("no uninstall*.sh")));
        std::env::remove_var("MSFE_NG_MIGRATION_ROOT");
        let _ = std::fs::remove_dir_all(&root);
    }
}
