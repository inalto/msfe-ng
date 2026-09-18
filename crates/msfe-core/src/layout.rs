//! Where the MailScanner engine actually lives on this server.
//!
//! Two layouts exist in the wild: the MailScanner v5 RPM (`/usr/sbin/MailScanner`,
//! `/etc/MailScanner`, system perl) and ConfigServer's bundled tree
//! (`/usr/mailscanner/usr/sbin/MailScanner`, `/usr/mailscanner/etc`, cPanel's
//! perl). Both can be present at once; what matters is the engine that
//! `MailScanner.service` runs and the conf `mailscanner_conf` names. Every
//! binary/config path MSFE-NG needs is derived here, never hard-coded at the
//! call site.

use crate::Config;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The RPM's engine binary — the fallback when nothing else is found.
pub const DEFAULT_BIN: &str = "/usr/sbin/MailScanner";

#[derive(Debug, Clone)]
pub struct EngineLayout {
    /// MailScanner.conf (`mailscanner_conf`).
    pub conf: PathBuf,
    /// Its directory: `/etc/MailScanner` or `/usr/mailscanner/etc`.
    pub etc: PathBuf,
    /// The MailScanner executable that runs (or would run) on this server.
    pub bin: PathBuf,
    /// ms-init's startup latch file (`run_mailscanner=`); may not exist.
    pub defaults: PathBuf,
    /// The phishing-list updater belonging to this engine.
    pub phishing_updater: PathBuf,
    /// The perl the engine runs under — interpreter plus its `-I` paths, from
    /// the binary's shebang — so module checks see what MailScanner sees.
    pub perl: Vec<String>,
    /// `MailScanner Version Number` from the conf.
    pub version: Option<(u32, u32, u32)>,
    /// Whether this engine knows the `Exim Command` directive (5.5+): its
    /// ConfigDefs.pl lists `eximcommand`.
    pub supports_exim_command: bool,
}

impl EngineLayout {
    pub fn version_string(&self) -> String {
        match self.version {
            Some((a, b, c)) => format!("{a}.{b}.{c}"),
            None => "unknown version".into(),
        }
    }
}

/// Resolve the engine layout for this server. Env overrides (tests, unusual
/// installs): `MSFE_NG_MS_BIN`, `MSFE_NG_MS_DEFAULTS`, `MSFE_NG_PHISHING_UPDATER`.
pub fn resolve(cfg: &Config) -> EngineLayout {
    let conf = PathBuf::from(&cfg.mailscanner_conf);
    let etc = conf
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| "/etc/MailScanner".into());
    let bin = match std::env::var("MSFE_NG_MS_BIN") {
        Ok(b) => PathBuf::from(b),
        Err(_) => bin_for(&conf, unit_exec_start().as_deref()),
    };
    let defaults = std::env::var("MSFE_NG_MS_DEFAULTS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| etc.join("defaults"));
    let phishing_updater = std::env::var("MSFE_NG_PHISHING_UPDATER")
        .map(PathBuf::from)
        .unwrap_or_else(|_| sibling_sbin(&etc, "ms-update-phishing"));
    let shebang = std::fs::read_to_string(&bin)
        .ok()
        .and_then(|t| t.lines().next().map(str::to_string))
        .unwrap_or_default();
    let perl = perl_from_shebang(&shebang);
    let text = std::fs::read_to_string(&conf).unwrap_or_default();
    let version = version_of(&text);
    let supports_exim_command = supports_exim_command(&perl, version);
    EngineLayout {
        conf,
        etc,
        bin,
        defaults,
        phishing_updater,
        perl,
        version,
        supports_exim_command,
    }
}

/// The engine binary: the unit's ExecStart when that is the engine itself
/// (ConfigServer units run `…/usr/sbin/MailScanner` directly; the RPM's runs
/// ms-init), else the conf's sibling tree, else the RPM location.
pub fn bin_for(conf: &Path, exec_start: Option<&Path>) -> PathBuf {
    if let Some(p) = exec_start {
        if p.file_name().is_some_and(|n| n == "MailScanner") && p.is_file() {
            return p.to_path_buf();
        }
    }
    let etc = conf.parent().unwrap_or(Path::new("/etc/MailScanner"));
    sibling_sbin(etc, "MailScanner")
}

/// `<etc>/../usr/sbin/<name>` when that tree exists (ConfigServer's
/// `/usr/mailscanner/{etc,usr/sbin}`), else `/usr/sbin/<name>`.
fn sibling_sbin(etc: &Path, name: &str) -> PathBuf {
    if let Some(root) = etc.parent() {
        let p = root.join("usr/sbin").join(name);
        if p.is_file() {
            return p;
        }
    }
    Path::new("/usr/sbin").join(name)
}

/// Interpreter + `-I` include paths from a `#!` line; `["perl"]` when the
/// line is not a perl shebang.
pub fn perl_from_shebang(line: &str) -> Vec<String> {
    let Some(rest) = line.strip_prefix("#!") else {
        return vec!["perl".into()];
    };
    let mut words = rest.split_whitespace();
    let Some(interp) = words.next().filter(|w| w.ends_with("perl")) else {
        return vec!["perl".into()];
    };
    let mut out = vec![interp.to_string()];
    let mut words = words.peekable();
    while let Some(w) = words.next() {
        if let Some(dir) = w.strip_prefix("-I") {
            let dir = if dir.is_empty() {
                words.next().unwrap_or("")
            } else {
                dir
            };
            if !dir.is_empty() {
                out.push("-I".into());
                out.push(dir.to_string());
            }
        }
    }
    out
}

/// `MailScanner Version Number = a.b.c` from the conf text.
pub fn version_of(conf_text: &str) -> Option<(u32, u32, u32)> {
    let v = crate::mailscanner::get_directive(conf_text, "MailScanner Version Number")?;
    let mut it = v.trim().split('.').map(|n| n.parse::<u32>().ok());
    Some((it.next()??, it.next()??, it.next().flatten().unwrap_or(0)))
}

/// Does the engine's config parser know `Exim Command`? Read from its
/// ConfigDefs.pl (found through the perl `-I` paths, else the RPM's lib);
/// without a readable file, 5.5 is where the directive appeared. An unknown
/// engine is assumed current.
pub fn supports_exim_command(perl: &[String], version: Option<(u32, u32, u32)>) -> bool {
    let mut libs: Vec<PathBuf> = perl
        .windows(2)
        .filter(|w| w[0] == "-I")
        .map(|w| PathBuf::from(&w[1]))
        .collect();
    libs.push("/usr/share/MailScanner/perl".into());
    for lib in libs {
        if let Ok(defs) = std::fs::read_to_string(lib.join("MailScanner/ConfigDefs.pl")) {
            return defs.contains("eximcommand");
        }
    }
    version.map_or(true, |v| v >= (5, 5, 0))
}

/// `path=` of the first ExecStart entry as `systemctl show -p ExecStart` prints it.
pub fn exec_start_path(show_output: &str) -> Option<PathBuf> {
    let rest = show_output.split("path=").nth(1)?;
    let p = rest.split([' ', ';']).next()?.trim();
    if p.is_empty() {
        None
    } else {
        Some(PathBuf::from(p))
    }
}

/// ExecStart of the live MailScanner unit, whichever spelling it uses.
fn unit_exec_start() -> Option<PathBuf> {
    for unit in ["mailscanner", "MailScanner"] {
        let out = Command::new("systemctl")
            .args(["show", "-p", "ExecStart", "--value", unit])
            .output()
            .ok()?;
        if let Some(p) = exec_start_path(&String::from_utf8_lossy(&out.stdout)) {
            return Some(p);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn perl_from_shebang_keeps_interpreter_and_include_paths() {
        assert_eq!(
            perl_from_shebang(
                "#!/usr/local/cpanel/3rdparty/bin/perl -U -I /usr/mailscanner/usr/share/MailScanner/perl"
            ),
            vec![
                "/usr/local/cpanel/3rdparty/bin/perl",
                "-I",
                "/usr/mailscanner/usr/share/MailScanner/perl"
            ]
        );
        assert_eq!(
            perl_from_shebang("#!/usr/bin/perl -U -I /usr/share/MailScanner/perl"),
            vec!["/usr/bin/perl", "-I", "/usr/share/MailScanner/perl"]
        );
        // not a perl script (or unreadable): system perl
        assert_eq!(perl_from_shebang("#!/bin/sh"), vec!["perl"]);
        assert_eq!(perl_from_shebang(""), vec!["perl"]);
    }

    #[test]
    fn version_comes_from_the_conf_directive() {
        assert_eq!(
            version_of("# x\nMailScanner Version Number = 5.5.3\n"),
            Some((5, 5, 3))
        );
        assert_eq!(
            version_of("MailScanner Version Number = 5.4.4"),
            Some((5, 4, 4))
        );
        assert_eq!(version_of("MTA = exim\n"), None);
    }

    #[test]
    fn binary_prefers_the_unit_then_the_conf_sibling_tree() {
        let base = std::env::temp_dir().join(format!("msfe-layout-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // ConfigServer tree: <root>/etc/MailScanner.conf + <root>/usr/sbin/MailScanner
        let root = base.join("usr/mailscanner");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::fs::write(root.join("usr/sbin/MailScanner"), "#!/usr/bin/perl\n").unwrap();
        let conf = root.join("etc/MailScanner.conf");
        std::fs::write(&conf, "").unwrap();

        // no unit: the sibling tree wins over the RPM default
        assert_eq!(bin_for(&conf, None), root.join("usr/sbin/MailScanner"));
        // the unit's ExecStart, when it is the engine itself, wins
        let other = base.join("opt/MailScanner");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, "").unwrap();
        assert_eq!(bin_for(&conf, Some(&other)), other);
        // ms-init (the RPM unit) is not the engine: ignored
        let init = base.join("ms-init");
        std::fs::write(&init, "").unwrap();
        assert_eq!(
            bin_for(&conf, Some(&init)),
            root.join("usr/sbin/MailScanner")
        );
        // RPM layout: /etc/MailScanner has no ../usr/sbin tree → default
        assert_eq!(
            bin_for(Path::new("/etc/MailScanner/MailScanner.conf"), None),
            Path::new(DEFAULT_BIN)
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn exim_command_support_is_read_from_configdefs_else_version() {
        let base = std::env::temp_dir().join(format!("msfe-layout-defs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let lib = base.join("perl");
        std::fs::create_dir_all(lib.join("MailScanner")).unwrap();
        let defs = lib.join("MailScanner/ConfigDefs.pl");
        std::fs::write(&defs, "sendmail2 = /usr/sbin/exim\n").unwrap();
        let perl = vec!["perl".to_string(), "-I".into(), lib.display().to_string()];
        assert!(!supports_exim_command(&perl, Some((5, 5, 3))));
        std::fs::write(&defs, "sendmail2\neximcommand\n").unwrap();
        assert!(supports_exim_command(&perl, Some((5, 4, 4))));
        // no readable definitions: decide by version
        let none = vec!["perl".to_string()];
        assert!(supports_exim_command(&none, Some((5, 5, 0))));
        assert!(!supports_exim_command(&none, Some((5, 4, 4))));
        assert!(
            supports_exim_command(&none, None),
            "unknown engine: assume current"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn exec_start_path_is_parsed_from_systemctl_show() {
        assert_eq!(
            exec_start_path("{ path=/usr/mailscanner/usr/sbin/MailScanner ; argv[]=/usr/mailscanner/usr/sbin/MailScanner ; ignore_errors=no }"),
            Some(Path::new("/usr/mailscanner/usr/sbin/MailScanner").to_path_buf())
        );
        assert_eq!(
            exec_start_path("{ path=/usr/lib/MailScanner/init/ms-init ; argv[]=/usr/lib/MailScanner/init/ms-init start ; ignore_errors=no }"),
            Some(Path::new("/usr/lib/MailScanner/init/ms-init").to_path_buf())
        );
        assert_eq!(exec_start_path(""), None);
    }
}
