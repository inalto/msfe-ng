//! Which perl the RPM MailScanner engine runs under.
//!
//! The RPM's scripts start with `#!/usr/bin/perl …`: system perl, where every
//! module MailScanner needs has to be installed (cpanm for what EL does not
//! package) and where a second SpamAssassin ends up next to cPanel's. cPanel's
//! own perl (`/usr/local/cpanel/3rdparty/bin/perl`) already carries
//! Mail::SpamAssassin, DBI, DBD::mysql, MIME::Parser and the rest, with rules
//! cPanel keeps updated — which is how the ConfigServer engine always ran.
//! `engine_perl = "cpanel"` opts in: the shebangs of the engine's perl
//! scripts are pointed at the real path of cPanel's perl (the symlink would
//! let a cPanel update switch the engine to a perl nobody checked) and
//! re-asserted by `engine configure`, after an RPM upgrade (which resets
//! them) and by the monitor cron (a cPanel perl bump removes the old
//! directory and MailScanner would not start). cPanel's perl is only ever
//! used when it loads the modules the engine needs; nothing is installed
//! into it — when it lacks something the engine stays on system perl and the
//! doctor says why. The ConfigServer engine is left alone.

use crate::config::Config;
use crate::layout;
use crate::service;
use std::io;
use std::path::{Path, PathBuf};

/// cPanel's perl, the stable symlink.
pub const CPANEL_PERL_LINK: &str = "/usr/local/cpanel/3rdparty/bin/perl";
/// The RPM's perl.
pub const SYSTEM_PERL: &str = "/usr/bin/perl";
/// The RPM's perl scripts (the rest under /usr/sbin are shell).
pub const SCRIPTS: [&str; 5] = [
    "MailScanner",
    "ms-create-locks",
    "ms-peek",
    "ms-sa-cache",
    "ms-upgrade-conf",
];
/// What a perl must load before the engine is switched to it.
pub const REQUIRED_MODULES: [&str; 3] = ["Mail::SpamAssassin", "DBI", "MIME::Parser"];

/// `engine_perl` as the operator set it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    System,
    Cpanel,
}

impl Choice {
    pub fn parse(s: &str) -> Choice {
        match s.trim().to_ascii_lowercase().as_str() {
            "cpanel" => Choice::Cpanel,
            _ => Choice::System,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Choice::System => "system",
            Choice::Cpanel => "cpanel",
        }
    }
}

/// Where the host's files are: `/` live, a fixture tree under
/// `MSFE_NG_ENGINE_PERL_ROOT` in tests. Paths are kept as the host sees them
/// (`/usr/sbin/MailScanner`) and resolved under the root for every read,
/// write and run.
fn root() -> PathBuf {
    std::env::var("MSFE_NG_ENGINE_PERL_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/"))
}

fn at(root: &Path, logical: &str) -> PathBuf {
    root.join(logical.trim_start_matches('/'))
}

/// Follow the symlink chain of `logical` under `root` (at most ten hops) to
/// the file it names, as a host path. `None` when nothing is there.
fn resolve_link(root: &Path, logical: &str) -> Option<String> {
    let mut cur = PathBuf::from(logical);
    for _ in 0..10 {
        let p = at(root, &cur.to_string_lossy());
        let meta = std::fs::symlink_metadata(&p).ok()?;
        if !meta.file_type().is_symlink() {
            return meta.is_file().then(|| cur.to_string_lossy().into_owned());
        }
        let target = std::fs::read_link(&p).ok()?;
        cur = if target.is_absolute() {
            target
        } else {
            cur.parent().unwrap_or(Path::new("/")).join(target)
        };
        // normalise `..` and `.` without touching the filesystem
        let mut norm = PathBuf::from("/");
        for c in cur.components() {
            match c {
                std::path::Component::ParentDir => {
                    norm.pop();
                }
                std::path::Component::Normal(n) => norm.push(n),
                _ => {}
            }
        }
        cur = norm;
    }
    None
}

/// Does `perl` load every required module? The interpreter is run under the
/// root (a fixture's fake perl is a shell script whose exit status is the
/// answer).
fn loads_required(root: &Path, perl: &str) -> Result<(), String> {
    let mut c = std::process::Command::new(at(root, perl));
    for m in REQUIRED_MODULES {
        c.arg(format!("-M{m}"));
    }
    c.arg("-e").arg("1");
    match crate::service::run_with_timeout(&mut c, std::time::Duration::from_secs(60)) {
        Ok(out) if out.ok => Ok(()),
        Ok(out) => {
            let first = out
                .stderr
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("does not load the modules the engine needs")
                .to_string();
            Err(first)
        }
        Err(e) => Err(format!("cannot run {perl}: {e}")),
    }
}

/// One of the engine's perl scripts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    /// Host path.
    pub path: String,
    /// The interpreter its shebang names; `None` when the file is missing
    /// or does not start with a perl shebang.
    pub interp: Option<String>,
    /// That interpreter exists.
    pub interp_exists: bool,
}

/// The engine's perl situation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub setting: Choice,
    /// The RPM engine (`/usr/sbin/MailScanner`): the only one this manages.
    pub applicable: bool,
    /// cPanel's perl, resolved to its real path, when the symlink is there.
    pub cpanel_perl: Option<String>,
    /// Why cPanel's perl cannot be used, when it cannot.
    pub cpanel_problem: Option<String>,
    /// The interpreter the shebangs should name.
    pub wanted: String,
    pub scripts: Vec<Script>,
}

impl State {
    /// Scripts whose shebang does not name `wanted`.
    pub fn stale(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| s.interp.is_some() && s.interp.as_deref() != Some(self.wanted.as_str()))
            .collect()
    }
    /// A script names a perl that is not there: MailScanner cannot start.
    pub fn broken(&self) -> Vec<&Script> {
        self.scripts
            .iter()
            .filter(|s| s.interp.is_some() && !s.interp_exists)
            .collect()
    }
    pub fn ok(&self) -> bool {
        self.stale().is_empty()
    }
    /// The interpreter the engine runs under now (its main script's).
    pub fn current(&self) -> Option<&str> {
        self.scripts.first().and_then(|s| s.interp.as_deref())
    }
    pub fn to_json(&self) -> crate::json::Json {
        use crate::json::Json;
        let opt = |v: &Option<String>| v.as_deref().map(Json::str).unwrap_or(Json::Null);
        Json::Object(vec![
            ("setting".into(), Json::str(self.setting.as_str())),
            ("applicable".into(), Json::Bool(self.applicable)),
            ("cpanel_perl".into(), opt(&self.cpanel_perl)),
            ("cpanel_problem".into(), opt(&self.cpanel_problem)),
            ("wanted".into(), Json::str(&self.wanted)),
            (
                "current".into(),
                self.current().map(Json::str).unwrap_or(Json::Null),
            ),
            ("ok".into(), Json::Bool(self.ok())),
            (
                "scripts".into(),
                Json::Array(
                    self.scripts
                        .iter()
                        .map(|s| {
                            Json::Object(vec![
                                ("path".into(), Json::str(&s.path)),
                                ("interp".into(), opt(&s.interp)),
                                ("interp_exists".into(), Json::Bool(s.interp_exists)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

/// Look, without changing anything.
pub fn state(cfg: &Config) -> State {
    let root = root();
    let setting = Choice::parse(&cfg.engine_perl);
    let lay = layout::resolve(cfg);
    let bin = lay.bin.display().to_string();
    let logical_bin = bin
        .strip_prefix(&root.display().to_string().trim_end_matches('/').to_string())
        .map(str::to_string)
        .unwrap_or(bin);
    let applicable = logical_bin == "/usr/sbin/MailScanner";
    let sbin = "/usr/sbin";
    let (cpanel_perl, cpanel_problem) = match resolve_link(&root, CPANEL_PERL_LINK) {
        Some(real) => match loads_required(&root, &real) {
            Ok(()) => (Some(real), None),
            Err(e) => (Some(real), Some(e)),
        },
        None => (None, Some(format!("{CPANEL_PERL_LINK} is not here"))),
    };
    let wanted = match (setting, &cpanel_perl, &cpanel_problem) {
        (Choice::Cpanel, Some(p), None) => p.clone(),
        _ => SYSTEM_PERL.to_string(),
    };
    let scripts = SCRIPTS
        .iter()
        .map(|name| {
            let path = format!("{sbin}/{name}");
            let first = std::fs::read_to_string(at(&root, &path))
                .ok()
                .and_then(|t| t.lines().next().map(str::to_string))
                .unwrap_or_default();
            let interp = first
                .starts_with("#!")
                .then(|| layout::perl_from_shebang(&first))
                .and_then(|v| v.into_iter().next())
                .filter(|i| i != "perl");
            let interp_exists = interp.as_deref().is_some_and(|i| at(&root, i).is_file());
            Script {
                path,
                interp,
                interp_exists,
            }
        })
        .collect();
    State {
        setting,
        applicable,
        cpanel_perl,
        cpanel_problem,
        wanted,
        scripts,
    }
}

/// What `apply` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Scripts rewritten, as "path: old → new".
    pub changed: Vec<String>,
    pub notes: Vec<String>,
    pub restarted: bool,
}

/// The first line with its interpreter replaced, flags kept.
fn reshebang(line: &str, wanted: &str) -> String {
    let rest = line.strip_prefix("#!").unwrap_or("");
    let mut words = rest.split_whitespace();
    let _old = words.next();
    let tail: Vec<&str> = words.collect();
    if tail.is_empty() {
        format!("#!{wanted}")
    } else {
        format!("#!{wanted} {}", tail.join(" "))
    }
}

/// Point every stale script at the wanted perl, keeping each file's mode,
/// then restart MailScanner when it is running (live only) so the running
/// children follow. `dry` only reports. `restart` false leaves the restart
/// to the caller (`engine configure` does its own).
pub fn apply(cfg: &Config, dry: bool, restart: bool) -> io::Result<Report> {
    let root = root();
    let s = state(cfg);
    let mut rep = Report::default();
    if !s.applicable {
        rep.notes
            .push("not the RPM engine — its perl is left as it is".into());
        return Ok(rep);
    }
    if let (Choice::Cpanel, Some(why)) = (s.setting, &s.cpanel_problem) {
        rep.notes.push(format!(
            "engine_perl = cpanel, but cPanel's perl cannot be used ({why}) — staying on {SYSTEM_PERL}"
        ));
    }
    for sc in s.stale() {
        let p = at(&root, &sc.path);
        let text = std::fs::read_to_string(&p)?;
        let Some((first, rest)) = text.split_once('\n') else {
            continue;
        };
        let new_first = reshebang(first, &s.wanted);
        let line = format!(
            "{}: {} → {}",
            sc.path,
            sc.interp.as_deref().unwrap_or("?"),
            s.wanted
        );
        if dry {
            rep.changed.push(format!("would rewrite {line}"));
            continue;
        }
        let new_text = format!("{new_first}\n{rest}");
        let mode = std::fs::metadata(&p)?.permissions();
        crate::sync::atomic_write(&p, new_text.as_bytes())?;
        std::fs::set_permissions(&p, mode)?;
        rep.changed.push(line);
    }
    if !dry
        && !rep.changed.is_empty()
        && restart
        && root == Path::new("/")
        && service::status().active
    {
        rep.restarted = service::control("restart").ok;
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deliveryrun::tests::ENV_LOCK;
    use std::os::unix::fs::PermissionsExt;

    fn tree(tag: &str, fake_perl_exit: i32) -> PathBuf {
        let root = std::env::temp_dir().join(format!("msfe-engperl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let w = |rel: &str, text: &str| {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, text).unwrap();
            p
        };
        let ms = w(
            "usr/sbin/MailScanner",
            "#!/usr/bin/perl -U -I /usr/share/MailScanner/perl\nprint 1;\n",
        );
        std::fs::set_permissions(&ms, std::fs::Permissions::from_mode(0o755)).unwrap();
        for s in &SCRIPTS[1..] {
            w(&format!("usr/sbin/{s}"), "#!/usr/bin/perl\nprint 1;\n");
        }
        w("usr/sbin/ms-update-sa", "#!/bin/sh\n");
        w("usr/bin/perl", "");
        // cPanel's perl: the symlink chain of a real host, ending in a fake
        // perl whose exit status says whether the modules load
        let real = w(
            "usr/local/cpanel/3rdparty/perl/542/bin/perl",
            &format!("#!/bin/sh\necho 'Can'\"'\"'t locate Foo.pm' >&2\nexit {fake_perl_exit}\n"),
        );
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.join("usr/local/cpanel/3rdparty/bin")).unwrap();
        std::os::unix::fs::symlink(
            "../perl/542/bin/perl",
            root.join("usr/local/cpanel/3rdparty/bin/perl"),
        )
        .unwrap();
        root
    }

    fn cfg(root: &Path, choice: &str) -> Config {
        std::env::set_var("MSFE_NG_ENGINE_PERL_ROOT", root);
        std::env::set_var("MSFE_NG_MS_BIN", root.join("usr/sbin/MailScanner"));
        Config {
            engine_perl: choice.into(),
            mailscanner_conf: root
                .join("etc/MailScanner/MailScanner.conf")
                .display()
                .to_string(),
            ..Default::default()
        }
    }

    fn cleanup(root: &Path) {
        std::env::remove_var("MSFE_NG_ENGINE_PERL_ROOT");
        std::env::remove_var("MSFE_NG_MS_BIN");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn choice_and_shebang_rewrite() {
        assert_eq!(Choice::parse(" CPanel "), Choice::Cpanel);
        assert_eq!(Choice::parse("anything"), Choice::System);
        assert_eq!(
            reshebang(
                "#!/usr/bin/perl -U -I /usr/share/MailScanner/perl",
                "/x/perl"
            ),
            "#!/x/perl -U -I /usr/share/MailScanner/perl"
        );
        assert_eq!(reshebang("#!/usr/bin/perl", "/x/perl"), "#!/x/perl");
    }

    #[test]
    fn system_setting_is_satisfied_by_the_rpm_shebangs() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("system", 0);
        let c = cfg(&root, "system");
        let s = state(&c);
        assert!(s.applicable);
        assert_eq!(s.wanted, SYSTEM_PERL);
        assert_eq!(
            s.cpanel_perl.as_deref(),
            Some("/usr/local/cpanel/3rdparty/perl/542/bin/perl")
        );
        assert!(s.cpanel_problem.is_none());
        assert!(s.ok(), "{s:?}");
        assert_eq!(s.current(), Some("/usr/bin/perl"));
        let r = apply(&c, false, true).unwrap();
        assert!(r.changed.is_empty() && !r.restarted);
        cleanup(&root);
    }

    #[test]
    fn cpanel_setting_rewrites_the_five_scripts_to_the_real_perl_and_keeps_modes() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("cpanel", 0);
        let c = cfg(&root, "cpanel");
        let s = state(&c);
        assert_eq!(s.wanted, "/usr/local/cpanel/3rdparty/perl/542/bin/perl");
        assert_eq!(s.stale().len(), 5);
        assert!(s.broken().is_empty());
        // dry run touches nothing
        let r = apply(&c, true, true).unwrap();
        assert_eq!(r.changed.len(), 5);
        assert!(r.changed[0].starts_with("would rewrite /usr/sbin/MailScanner: /usr/bin/perl → /usr/local/cpanel/3rdparty/perl/542/bin/perl"), "{:?}", r.changed);
        assert!(std::fs::read_to_string(root.join("usr/sbin/MailScanner"))
            .unwrap()
            .starts_with("#!/usr/bin/perl -U"));
        let r = apply(&c, false, true).unwrap();
        assert_eq!(r.changed.len(), 5);
        assert!(!r.restarted, "never restarts under a fixture root");
        let ms = std::fs::read_to_string(root.join("usr/sbin/MailScanner")).unwrap();
        assert_eq!(
            ms,
            "#!/usr/local/cpanel/3rdparty/perl/542/bin/perl -U -I /usr/share/MailScanner/perl\nprint 1;\n"
        );
        let mode = std::fs::metadata(root.join("usr/sbin/MailScanner"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
        assert_eq!(
            std::fs::read_to_string(root.join("usr/sbin/ms-peek")).unwrap(),
            "#!/usr/local/cpanel/3rdparty/perl/542/bin/perl\nprint 1;\n"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("usr/sbin/ms-update-sa")).unwrap(),
            "#!/bin/sh\n"
        );
        let s = state(&c);
        assert!(s.ok());
        assert!(
            apply(&c, false, true).unwrap().changed.is_empty(),
            "idempotent"
        );
        // cPanel moves to a new perl: the old directory is gone, the
        // scripts name a perl that is not there — repaired to the new one
        std::fs::rename(
            root.join("usr/local/cpanel/3rdparty/perl/542"),
            root.join("usr/local/cpanel/3rdparty/perl/544"),
        )
        .unwrap();
        let _ = std::fs::remove_file(root.join("usr/local/cpanel/3rdparty/bin/perl"));
        std::os::unix::fs::symlink(
            "../perl/544/bin/perl",
            root.join("usr/local/cpanel/3rdparty/bin/perl"),
        )
        .unwrap();
        let s = state(&c);
        assert_eq!(s.broken().len(), 5);
        assert_eq!(s.wanted, "/usr/local/cpanel/3rdparty/perl/544/bin/perl");
        let r = apply(&c, false, true).unwrap();
        assert_eq!(r.changed.len(), 5);
        assert!(state(&c).ok());
        // back to system: rewritten back
        let c2 = cfg(&root, "system");
        let r = apply(&c2, false, true).unwrap();
        assert_eq!(r.changed.len(), 5);
        assert!(std::fs::read_to_string(root.join("usr/sbin/MailScanner"))
            .unwrap()
            .starts_with("#!/usr/bin/perl -U -I"));
        let j = state(&c2).to_json();
        assert!(matches!(j.get("ok"), Some(crate::json::Json::Bool(true))));
        cleanup(&root);
    }

    #[test]
    fn an_unusable_cpanel_perl_keeps_system_perl_and_says_why() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("unusable", 2);
        let c = cfg(&root, "cpanel");
        let s = state(&c);
        assert_eq!(s.wanted, SYSTEM_PERL);
        assert!(
            s.cpanel_problem
                .as_deref()
                .unwrap()
                .contains("Can't locate Foo.pm"),
            "{s:?}"
        );
        assert!(s.ok());
        let r = apply(&c, false, true).unwrap();
        assert!(r.changed.is_empty());
        assert!(
            r.notes[0].contains("staying on /usr/bin/perl"),
            "{:?}",
            r.notes
        );
        // no cPanel at all
        let _ = std::fs::remove_file(root.join("usr/local/cpanel/3rdparty/bin/perl"));
        let s = state(&c);
        assert!(s.cpanel_perl.is_none());
        assert_eq!(
            s.cpanel_problem.as_deref(),
            Some("/usr/local/cpanel/3rdparty/bin/perl is not here")
        );
        assert_eq!(s.wanted, SYSTEM_PERL);
        cleanup(&root);
    }

    #[test]
    fn the_configserver_engine_is_left_alone() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("csf", 0);
        let mut c = cfg(&root, "cpanel");
        let csf = root.join("usr/mailscanner/usr/sbin/MailScanner");
        std::fs::create_dir_all(csf.parent().unwrap()).unwrap();
        std::fs::write(&csf, "#!/usr/local/cpanel/3rdparty/bin/perl\n").unwrap();
        std::env::set_var("MSFE_NG_MS_BIN", &csf);
        c.mailscanner_conf = root
            .join("usr/mailscanner/etc/MailScanner.conf")
            .display()
            .to_string();
        let s = state(&c);
        assert!(!s.applicable);
        let r = apply(&c, false, true).unwrap();
        assert!(r.changed.is_empty());
        assert!(r.notes[0].contains("not the RPM engine"));
        cleanup(&root);
    }
}
