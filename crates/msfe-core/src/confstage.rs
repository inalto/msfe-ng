//! A staged copy of the MailScanner etc tree, where a candidate edit is
//! validated before anything live changes.
//!
//! `MailScanner --lint <conf>` honours a conf path (verified on 5.5.3), but
//! the conf names its companions through `%etc-dir%` and, on some hosts, by
//! absolute path (`%rules-dir% = /etc/MailScanner/rules`). So the copy's
//! `MailScanner.conf` is rewritten: every variable definition and every
//! directive whose value starts with the live etc dir points into the stage
//! instead. Spool, work and quarantine directories are outside etc and stay
//! live — exactly what `--lint` has always used. `conf.d/` is the exception
//! the engine reads from the live directory regardless; its fragments are
//! validated after apply by `confsave`.
//!
//! The same stage serves a save (validate, then promote the changed files)
//! and the tester's "test my unsaved changes" (validate, discard).

use crate::{conffile, Config};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static SEQ: AtomicU32 = AtomicU32::new(0);

pub struct Stage {
    /// `backup_dir/.stage/<pid>-<n>`
    pub dir: PathBuf,
    /// `dir/etc` — the copy of the live etc dir.
    pub etc: PathBuf,
    pub live_etc: PathBuf,
    /// Relative paths written through `apply`, in order.
    pub changed: Vec<String>,
}

fn live_etc_of(cfg: &Config) -> PathBuf {
    Path::new(&cfg.mailscanner_conf)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into())
}

/// `value` starts with `prefix` on a path boundary (`/etc/MailScanner` matches
/// `/etc/MailScanner/rules` and itself, never `/etc/MailScannerX`).
fn path_prefixed(value: &str, prefix: &str) -> bool {
    value == prefix
        || value
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn swap_prefix(value: &str, from: &str, to: &str) -> String {
    format!("{to}{}", &value[from.len()..])
}

/// The staged `MailScanner.conf`: variable definitions and directives that
/// name the live etc dir by absolute path now name the stage. Values built
/// from `%etc-dir%` follow automatically.
pub fn rewrite_conf(text: &str, live_etc: &Path, stage_etc: &Path) -> String {
    let live = live_etc.display().to_string();
    let stage = stage_etc.display().to_string();
    let mut out: Vec<String> = Vec::with_capacity(text.lines().count());
    let mut changes: Vec<(String, String)> = Vec::new();
    for raw in text.lines() {
        let t = raw.trim_start();
        if t.starts_with('%') {
            if let Some((name, val)) = t.split_once('=') {
                let (name, val) = (name.trim(), val.trim());
                if name.ends_with('%') && path_prefixed(val, &live) {
                    out.push(format!("{name} = {}", swap_prefix(val, &live, &stage)));
                    continue;
                }
            }
        }
        out.push(raw.to_string());
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    for line in conffile::parse(&s) {
        if let conffile::ConfLine::Entry { key, value } = line {
            if path_prefixed(&value, &live) {
                changes.push((key, swap_prefix(&value, &live, &stage)));
            }
        }
    }
    if changes.is_empty() {
        s
    } else {
        conffile::apply(&s, &changes, conffile::Style::Plain).0
    }
}

impl Stage {
    /// Copy the live etc dir (`cp -a`: modes kept, symlinks stay symlinks) and
    /// rewrite the staged conf.
    pub fn new(cfg: &Config) -> io::Result<Stage> {
        let live_etc = live_etc_of(cfg);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = Path::new(&cfg.backup_dir)
            .join(".stage")
            .join(format!("{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                dir.parent().unwrap_or(&dir),
                std::fs::Permissions::from_mode(0o700),
            );
        }
        let etc = dir.join("etc");
        let st = std::process::Command::new("cp")
            .arg("-a")
            .arg(&live_etc)
            .arg(&etc)
            .status()?;
        if !st.success() {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(io::Error::other(format!(
                "cannot copy {} into the stage",
                live_etc.display()
            )));
        }
        let mut stage = Stage {
            dir,
            etc,
            live_etc,
            changed: Vec::new(),
        };
        stage.rewrite_staged_conf()?;
        Ok(stage)
    }

    fn rewrite_staged_conf(&mut self) -> io::Result<()> {
        let conf = self.conf();
        if let Ok(text) = std::fs::read_to_string(&conf) {
            let new = rewrite_conf(&text, &self.live_etc, &self.etc);
            if new != text {
                std::fs::write(&conf, new)?;
            }
        }
        Ok(())
    }

    /// Write a candidate for `rel` (relative to etc) into the stage.
    pub fn apply(&mut self, rel: &str, text: &str) -> io::Result<()> {
        if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad path"));
        }
        // through a symlinked dir (reports) the target is the live tree:
        // never write there from a stage
        let mut probe = self.etc.clone();
        for comp in rel.split('/').take(rel.split('/').count() - 1) {
            probe.push(comp);
            if std::fs::symlink_metadata(&probe).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file lives behind a symlink; validated in place",
                ));
            }
        }
        let path = self.etc.join(rel);
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        std::fs::write(&path, text)?;
        if rel == "MailScanner.conf" {
            self.rewrite_staged_conf()?;
        }
        if !self.changed.iter().any(|c| c == rel) {
            self.changed.push(rel.to_string());
        }
        Ok(())
    }

    pub fn conf(&self) -> PathBuf {
        self.etc.join("MailScanner.conf")
    }

    /// The catalog id (`ms:<rel>`) a path inside the stage or the live etc
    /// dir refers to.
    pub fn to_live_id(&self, path: &str) -> Option<String> {
        for root in [&self.etc, &self.live_etc] {
            let r = root.display().to_string();
            if let Some(rest) = path.strip_prefix(&r) {
                if let Some(rel) = rest.strip_prefix('/') {
                    return Some(format!("ms:{rel}"));
                }
            }
        }
        None
    }

    /// The staged text of `rel`.
    pub fn read(&self, rel: &str) -> io::Result<String> {
        std::fs::read_to_string(self.etc.join(rel))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Remove stages left behind by a daemon that died mid-save.
pub fn sweep(cfg: &Config) {
    let dir = Path::new(&cfg.backup_dir).join(".stage");
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.filter_map(Result::ok) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(tag: &str) -> (PathBuf, Config) {
        let base = std::env::temp_dir().join(format!("msfe-stage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("rules")).unwrap();
        std::fs::create_dir_all(etc.join("conf.d")).unwrap();
        std::fs::create_dir_all(base.join("share/reports/en")).unwrap();
        std::os::unix::fs::symlink(base.join("share/reports"), etc.join("reports")).unwrap();
        let conf = format!(
            "# conf\n%org-name% = X\n%etc-dir% = {etc}\n%report-dir% = {base}/share/reports/en\n%rules-dir% = {etc}/rules\n\
             Max Children = 5\nFilename Rules = {etc}/filename.rules.conf\nFiletype Rules = %etc-dir%/filetype.rules.conf\n\
             Incoming Work Dir = /var/spool/MailScanner/incoming\nSpam List Definitions = {etc}/spam.lists.conf\n",
            etc = etc.display(),
            base = base.display()
        );
        std::fs::write(etc.join("MailScanner.conf"), conf).unwrap();
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
        std::fs::write(etc.join("filename.rules.conf"), "deny\t\\.exe$\ta\tb\n").unwrap();
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        (base, cfg)
    }

    #[test]
    fn rewrite_points_absolute_etc_paths_into_the_stage() {
        let live = Path::new("/etc/MailScanner");
        let stage = Path::new("/opt/msfe-ng/backups/.stage/1-0/etc");
        let text = "%etc-dir% = /etc/MailScanner\n%rules-dir% = /etc/MailScanner/rules\n%report-dir% = /usr/share/MailScanner/reports/en\n\
                    %mcp-dir% = %etc-dir%/mcp\nFilename Rules = /etc/MailScanner/filename.rules.conf\nFiletype Rules = %etc-dir%/filetype.rules.conf\n\
                    Lockfile Dir = /etc/MailScannerX/locks\nQuarantine Dir = /var/spool/MailScanner/quarantine\n";
        let out = rewrite_conf(text, live, stage);
        assert!(out.contains("%etc-dir% = /opt/msfe-ng/backups/.stage/1-0/etc\n"));
        assert!(out.contains("%rules-dir% = /opt/msfe-ng/backups/.stage/1-0/etc/rules\n"));
        assert!(out.contains("%report-dir% = /usr/share/MailScanner/reports/en\n"));
        assert!(out.contains("%mcp-dir% = %etc-dir%/mcp\n"));
        assert!(out.contains(
            "Filename Rules = /opt/msfe-ng/backups/.stage/1-0/etc/filename.rules.conf\n"
        ));
        assert!(out.contains("Filetype Rules = %etc-dir%/filetype.rules.conf\n"));
        assert!(out.contains("Lockfile Dir = /etc/MailScannerX/locks\n"));
        assert!(out.contains("Quarantine Dir = /var/spool/MailScanner/quarantine\n"));
        // idempotent on a staged text
        assert_eq!(rewrite_conf(&out, live, stage), out);
    }

    #[test]
    fn stage_copies_rewrites_applies_and_cleans_up() {
        let (base, cfg) = tree("lifecycle");
        let etc = base.join("etc/MailScanner");
        let dir;
        {
            let mut st = Stage::new(&cfg).unwrap();
            dir = st.dir.clone();
            assert!(st.dir.starts_with(base.join("backups/.stage")));
            assert!(st.etc.join("rules/bounce.rules").is_file());
            // symlinked reports copied as a symlink
            assert!(std::fs::symlink_metadata(st.etc.join("reports"))
                .unwrap()
                .file_type()
                .is_symlink());
            let conf = std::fs::read_to_string(st.conf()).unwrap();
            let se = st.etc.display().to_string();
            assert!(conf.contains(&format!("%etc-dir% = {se}\n")), "{conf}");
            assert!(conf.contains(&format!("%rules-dir% = {se}/rules\n")));
            assert!(conf.contains(&format!("Filename Rules = {se}/filename.rules.conf\n")));
            assert!(conf.contains("Incoming Work Dir = /var/spool/MailScanner/incoming\n"));
            assert!(conf.contains("%org-name% = X\n"));
            // live untouched
            let live = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
            assert!(live.contains(&format!("%etc-dir% = {}\n", etc.display())));

            // an edit of the live conf text is rewritten too
            let edited = live.replace("Max Children = 5", "Max Children = 9");
            st.apply("MailScanner.conf", &edited).unwrap();
            let conf = std::fs::read_to_string(st.conf()).unwrap();
            assert!(conf.contains("Max Children = 9\n"));
            assert!(conf.contains(&format!("%etc-dir% = {se}\n")));
            st.apply("rules/new.rules", "To: default yes\n").unwrap();
            assert_eq!(st.read("rules/new.rules").unwrap(), "To: default yes\n");
            st.apply("MailScanner.conf", &edited).unwrap();
            assert_eq!(st.changed, vec!["MailScanner.conf", "rules/new.rules"]);
            assert!(st.apply("../x", "no").is_err());
            assert!(st.apply("/abs", "no").is_err());
            assert!(st.apply("reports/en/x.txt", "no").is_err());
            assert!(!base.join("share/reports/en/x.txt").exists());

            assert_eq!(
                st.to_live_id(&format!("{se}/rules/bounce.rules")),
                Some("ms:rules/bounce.rules".into())
            );
            assert_eq!(
                st.to_live_id(&format!("{}/MailScanner.conf", etc.display())),
                Some("ms:MailScanner.conf".into())
            );
            assert_eq!(st.to_live_id("/var/spool/x"), None);
        }
        assert!(!dir.exists(), "stage removed on drop");

        // sweep clears leftovers
        let stale = base.join("backups/.stage/999-0");
        std::fs::create_dir_all(&stale).unwrap();
        sweep(&cfg);
        assert!(!stale.exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
