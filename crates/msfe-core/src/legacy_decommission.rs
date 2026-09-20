//! Decommissioning ConfigServer's MSFE front-end — and only the front-end.
//!
//! ConfigServer's own uninstaller takes its bundled `/usr/mailscanner` engine
//! with it, so it is never run here: whatever MailScanner engine is scanning
//! keeps scanning. What goes is `/usr/msfe`, the cron entries that run it,
//! the `/usr/msfe` lines in root's crontab and the WHM plugin registration —
//! after a tarball of all of it lands in the backup dir, so one `tar x` puts
//! it back. `preflight` says what would happen; `run` does it, step by step,
//! stopping at the first failure. Seconds of work with no engine restart, so
//! it runs synchronously: `msfe-ng legacy decommission --run` from a shell,
//! `POST /api/legacy/decommission` from the Service tab. A host still on the
//! ConfigServer engine is told that the guided migration is the tool for
//! switching engines; the front-end can still go on its own.

use crate::{legacy, sync, Config};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The wiki section the doctor and the Service tab point at.
pub const WIKI_URL: &str =
    "https://github.com/inalto/msfe-ng/wiki/Migration#decommissioning-configserver-msfe";
/// Backups are `<backup_dir>/legacy-msfe-<unix time>.tar.gz`.
pub const BACKUP_PREFIX: &str = "legacy-msfe-";
/// Root's crontab as saved inside the tarball.
const CRONTAB_MEMBER: &str = "root.crontab";

#[derive(Debug, Clone, Default)]
pub struct Preflight {
    /// What is left of the front-end (`legacy::remnants`).
    pub remnants: Vec<String>,
    /// Lines of root's crontab that run it.
    pub crontab_lines: Vec<String>,
    /// ConfigServer's engine tree is still there (kept; the migration is the
    /// tool for that).
    pub legacy_engine: bool,
    pub policy_imported: bool,
    pub backup_dir: String,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
}

impl Preflight {
    pub fn ok(&self) -> bool {
        self.blockers.is_empty()
    }
}

/// What `run` did, in order, plus where the backup went.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub done: Vec<String>,
    pub backup: Option<PathBuf>,
    /// Still present afterwards — for the admin's hands.
    pub left: Vec<String>,
}

/// The live host's view.
pub fn preflight(cfg: &Config, config_file: &Path) -> Preflight {
    let (settings, _, _) = sync::load_policy(&sync::policy_dir(config_file));
    preflight_at(
        Path::new("/"),
        root_crontab_live().as_deref(),
        !settings.is_empty(),
        &cfg.backup_dir,
    )
}

/// The same under a fixture root, with root's crontab text supplied.
pub fn preflight_at(
    root: &Path,
    crontab: Option<&str>,
    policy_imported: bool,
    backup_dir: &str,
) -> Preflight {
    let remnants = legacy::remnants(root)
        .into_iter()
        // root's crontab is handled as lines, not as a file
        .filter(|f| !f.starts_with("/var/spool/cron/"))
        .collect::<Vec<_>>();
    let crontab_lines = crontab
        .map(legacy::legacy_crontab_lines)
        .unwrap_or_default();
    let mut p = Preflight {
        remnants,
        crontab_lines,
        legacy_engine: root
            .join(crate::engine_migration::LEGACY_TREE.trim_start_matches('/'))
            .is_dir(),
        policy_imported,
        backup_dir: backup_dir.to_string(),
        blockers: Vec::new(),
        warnings: Vec::new(),
    };
    if p.remnants.is_empty() && p.crontab_lines.is_empty() {
        p.blockers
            .push("nothing of the ConfigServer front-end is left — already decommissioned".into());
    }
    if !p.policy_imported && root.join("usr/msfe").is_dir() {
        p.warnings.push("no policy imported yet — run `msfe-ng import /usr/msfe --save` first: the legacy settings go with /usr/msfe (the backup keeps a copy)".into());
    }
    if p.legacy_engine {
        p.warnings.push("ConfigServer's MailScanner at /usr/mailscanner is kept and keeps scanning — Service → Migrate from ConfigServer MailScanner is the tool for switching to the RPM engine".into());
    }
    p
}

/// Decommission on the live host.
pub fn run(cfg: &Config, config_file: &Path) -> io::Result<Report> {
    let pf = preflight(cfg, config_file);
    if let Some(b) = pf.blockers.first() {
        return Err(io::Error::other(format!("cannot start: {b}")));
    }
    run_at(Path::new("/"), &cfg.backup_dir, true)
}

/// Decommission under `root`: back up, then remove. `live` runs
/// `crontab`/`unregister_appconfig`; under a fixture the crontab file and
/// the app file are edited directly.
pub fn run_at(root: &Path, backup_dir: &str, live: bool) -> io::Result<Report> {
    let mut rep = Report::default();
    let crontab = if live {
        root_crontab_live()
    } else {
        std::fs::read_to_string(root.join("var/spool/cron/root")).ok()
    };
    let pf = preflight_at(root, crontab.as_deref(), true, backup_dir);
    if let Some(b) = pf.blockers.first() {
        return Err(io::Error::other(format!("cannot start: {b}")));
    }

    // 1. the backup: every file that goes, plus root's crontab
    let backup = backup_path(backup_dir);
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| io::Error::other(format!("backup dir {backup_dir}: {e} — nothing removed")))?;
    let staging = backup.with_extension("staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;
    std::fs::write(staging.join(CRONTAB_MEMBER), crontab.unwrap_or_default())?;
    let mut tar = Command::new("tar");
    tar.arg("czf").arg(&backup).arg("-C").arg(root);
    for f in &pf.remnants {
        tar.arg(f.trim_start_matches('/'));
    }
    tar.arg("-C").arg(&staging).arg(CRONTAB_MEMBER);
    let out = tar.output()?;
    let _ = std::fs::remove_dir_all(&staging);
    if !out.status.success() {
        let _ = std::fs::remove_file(&backup);
        return Err(io::Error::other(format!(
            "backup to {} failed — nothing removed: {}",
            backup.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    rep.done.push(format!(
        "backed up {} and root's crontab to {}",
        pf.remnants.join(", "),
        backup.display()
    ));
    rep.backup = Some(backup);

    // 2. remove the front-end
    rep.done.extend(legacy::remove_front_end(root, live)?);
    rep.left = legacy::remnants(root)
        .into_iter()
        .filter(|f| !f.starts_with("/var/spool/cron/"))
        .collect();
    Ok(rep)
}

fn backup_path(backup_dir: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Path::new(backup_dir).join(format!("{BACKUP_PREFIX}{stamp}.tar.gz"))
}

/// `crontab -l` on the live host; `None` when root has no crontab.
fn root_crontab_live() -> Option<String> {
    let out = Command::new("crontab").arg("-l").output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("msfe-decom-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in [
            "usr/msfe/rules",
            "usr/mailscanner/etc",
            "etc/cron.d",
            "etc/cron.hourly",
            "etc/cron.daily",
            "var/spool/cron",
            "var/cpanel/apps",
            "backups",
        ] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("usr/msfe/msconfig.txt"), "MAXSPAM=5\n").unwrap();
        std::fs::write(
            root.join("usr/msfe/rules/x.rules"),
            "FromOrTo: default yes\n",
        )
        .unwrap();
        std::fs::write(
            root.join("usr/mailscanner/etc/MailScanner.conf"),
            "%org-name% = acme\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.d/msfe.sh"),
            "0 * * * * root /usr/msfe/msbe.pl\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.hourly/msdigest.pl"),
            "#!/usr/bin/perl\n# /usr/msfe/msdigest.pl\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/cron.daily/csget"), "/usr/msfe /usr/csf\n").unwrap();
        std::fs::write(
            root.join("var/spool/cron/root"),
            "MAILTO=root\n0 3 * * * /usr/msfe/msstats.pl\n*/5 * * * * /opt/msfe-ng/bin/msfe-ng monitor\n",
        )
        .unwrap();
        std::fs::write(
            root.join("var/cpanel/apps/msfe.conf"),
            "name=msfe\nurl=/cgi/msfe/index.cgi\n# /usr/msfe\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn preflight_lists_the_front_end_and_keeps_the_engine_out_of_it() {
        let root = fixture("pf");
        let crontab = std::fs::read_to_string(root.join("var/spool/cron/root")).unwrap();
        let pf = preflight_at(&root, Some(&crontab), false, "/b");
        assert!(pf.ok(), "{:?}", pf.blockers);
        assert_eq!(
            pf.remnants,
            vec![
                "/usr/msfe",
                "/etc/cron.d/msfe.sh",
                "/etc/cron.hourly/msdigest.pl",
                "/var/cpanel/apps/msfe.conf"
            ],
            "csget and root's crontab file are not listed as files"
        );
        assert_eq!(pf.crontab_lines, vec!["0 3 * * * /usr/msfe/msstats.pl"]);
        assert!(pf.legacy_engine);
        assert!(
            pf.warnings.iter().any(|w| w.contains("no policy imported")),
            "{:?}",
            pf.warnings
        );
        assert!(
            pf.warnings
                .iter()
                .any(|w| w.contains("/usr/mailscanner is kept")),
            "{:?}",
            pf.warnings
        );
        // nothing left: blocked
        let empty = fixture("pf-empty");
        for p in [
            "usr/msfe",
            "etc/cron.d/msfe.sh",
            "etc/cron.hourly/msdigest.pl",
            "var/cpanel/apps/msfe.conf",
        ] {
            let p = empty.join(p);
            let _ = std::fs::remove_dir_all(&p);
            let _ = std::fs::remove_file(&p);
        }
        let pf = preflight_at(&empty, Some("0 1 * * * /bin/true\n"), true, "/b");
        assert!(!pf.ok());
        assert!(pf.blockers[0].contains("already decommissioned"));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn run_backs_everything_up_then_removes_only_the_front_end() {
        let root = fixture("run");
        let backups = root.join("backups");
        let rep = run_at(&root, backups.to_str().unwrap(), false).unwrap();
        let backup = rep.backup.clone().expect("a backup");
        assert!(backup.exists(), "{}", backup.display());
        assert!(backup
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(BACKUP_PREFIX));
        // the tarball holds the tree, the cron files, the app file and the crontab
        let out = Command::new("tar")
            .arg("tzf")
            .arg(&backup)
            .output()
            .unwrap();
        let members = String::from_utf8_lossy(&out.stdout);
        for m in [
            "usr/msfe/msconfig.txt",
            "usr/msfe/rules/x.rules",
            "etc/cron.d/msfe.sh",
            "etc/cron.hourly/msdigest.pl",
            "var/cpanel/apps/msfe.conf",
            "root.crontab",
        ] {
            assert!(
                members.lines().any(|l| l == m),
                "{m} missing from {members}"
            );
        }
        assert!(!members.contains("usr/mailscanner"), "{members}");
        assert!(
            !backup.with_extension("staging").exists(),
            "staging cleaned"
        );

        // gone: the front-end
        assert!(!root.join("usr/msfe").exists());
        assert!(!root.join("etc/cron.d/msfe.sh").exists());
        assert!(!root.join("etc/cron.hourly/msdigest.pl").exists());
        assert!(!root.join("var/cpanel/apps/msfe.conf").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("var/spool/cron/root")).unwrap(),
            "MAILTO=root\n*/5 * * * * /opt/msfe-ng/bin/msfe-ng monitor\n",
            "only the /usr/msfe line leaves root's crontab"
        );
        // kept: the engine and csf's updater
        assert!(root.join("usr/mailscanner/etc/MailScanner.conf").exists());
        assert!(root.join("etc/cron.daily/csget").exists());
        assert!(rep.left.is_empty(), "{:?}", rep.left);
        assert!(
            rep.done
                .iter()
                .any(|l| l.starts_with("backed up /usr/msfe")),
            "{:?}",
            rep.done
        );
        assert!(
            rep.done.iter().any(|l| l == "removed /usr/msfe"),
            "{:?}",
            rep.done
        );
        assert!(
            rep.done.iter().any(|l| l.contains("root's crontab")),
            "{:?}",
            rep.done
        );

        // a second run has nothing to do and says so, without a new backup
        let n = std::fs::read_dir(&backups).unwrap().count();
        let err = run_at(&root, backups.to_str().unwrap(), false).unwrap_err();
        assert!(err.to_string().contains("already decommissioned"), "{err}");
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), n);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_backup_removes_nothing() {
        let root = fixture("nobackup");
        // the backup dir is a file: tar cannot write there
        let bad = root.join("backups-file");
        std::fs::write(&bad, "").unwrap();
        let err = run_at(&root, bad.to_str().unwrap(), false).unwrap_err();
        assert!(err.to_string().contains("nothing removed"), "{err}");
        assert!(root.join("usr/msfe/msconfig.txt").exists());
        assert!(root.join("etc/cron.d/msfe.sh").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
