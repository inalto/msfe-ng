//! MailScanner engine configuration for panel platforms.
//!
//! A fresh MailScanner install assumes sendmail (`/var/spool/mqueue*`), which
//! does not exist on cPanel/DirectAdmin Exim servers — its own lint fails on
//! the queue directories. `configure` points MailScanner.conf at Exim and
//! creates the incoming split-spool skeleton. Deliberately safe: it never
//! touches Exim's configuration, the safety latch, or mail routing — that is
//! the separate wiring step.
//!
//! Clean-room: the directive names/values are behavioral facts of MailScanner
//! configuration on Exim panel servers (run-as user `mailnull:mail` on cPanel,
//! `mail:mail` otherwise, split incoming/outgoing spools).

use crate::{mailscanner, service, Config};
use std::io;
use std::path::Path;

pub struct ConfigureReport {
    /// Directives that were changed, as "Key = value".
    pub set: Vec<String>,
    /// Directories created.
    pub created: Vec<String>,
    /// Paths whose ownership could not be set (non-fatal; reported).
    pub chown_failed: Vec<String>,
    /// MailScanner was restarted to apply changed directives.
    pub restarted: bool,
}

/// Point MailScanner.conf at Exim and create the incoming spool skeleton.
/// Idempotent; keeps a one-time backup of MailScanner.conf via `save_conf`.
pub fn configure(cfg: &Config) -> io::Result<ConfigureReport> {
    let run_user = if cfg.panel == "directadmin" {
        "mail"
    } else {
        "mailnull"
    };
    let (inc, out) = service::queue_dir_targets();

    let mut directives: Vec<(String, String)> = [
        ("MTA", "exim"),
        ("Run As User", run_user),
        ("Run As Group", "mail"),
        ("Sendmail", "/usr/sbin/exim"),
        ("Sendmail2", "/usr/sbin/exim"),
        // Without an explicit path, MailScanner 5.5.3's `which exim` fallback
        // leaves a trailing newline, its exim version probe silently fails,
        // and it assumes short message IDs — placing outgoing spool files in
        // the wrong split subdirectory, where Exim never finds them.
        ("Exim Command", "/usr/sbin/exim"),
        ("Incoming Work Group", "mail"),
        ("Incoming Work Permissions", "0640"),
        ("Quarantine Group", "mail"),
        ("Quarantine Permissions", "0660"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    // When the Exim wiring is active, the queue dirs belong to it: re-assert
    // the named-queue values instead of resetting them to the unwired defaults
    // (which would leave MailScanner watching an empty directory while the
    // ACL queues mail where nothing scans it).
    let wired = is_wired(cfg);
    if wired {
        let split = exim_split_spool();
        let input = named_queue_base().join("input");
        let incoming = if split {
            format!("{}/*", input.display())
        } else {
            input.display().to_string()
        };
        directives.push(("Incoming Queue Dir".into(), incoming));
        directives.push((
            "Split Exim Spool".into(),
            if split { "yes" } else { "no" }.into(),
        ));
    } else {
        directives.push(("Incoming Queue Dir".into(), inc.display().to_string()));
    }
    directives.push(("Outgoing Queue Dir".into(), out.display().to_string()));
    // Point MailScanner at clamd when its socket is present (the engine
    // installer sets clamd up; without a scanner "auto" finds nothing).
    if let Some(sock) = detect_clamd_socket() {
        directives.push(("Virus Scanners".into(), "clamd".into()));
        directives.push(("Clamd Socket".into(), sock));
    }

    let conf_path = Path::new(&cfg.mailscanner_conf);
    let original = std::fs::read_to_string(conf_path)?;
    let mut text = original.clone();
    let mut set = Vec::new();
    for (k, v) in &directives {
        // Always normalize (set_directive is idempotent): comparing values via
        // get_directive would miss live duplicates that override the edit.
        let new_text = mailscanner::set_directive(&text, k, v);
        if new_text != text {
            text = new_text;
            set.push(format!("{k} = {v}"));
        }
    }
    if text != original {
        service::save_conf(conf_path, &text)?;
    }

    // Incoming split-spool skeleton (ours to create and own; pointless when the
    // named-queue wiring owns the incoming path). The outgoing dir is the
    // MTA's real spool — never created or chowned here.
    let mut created = Vec::new();
    let mut chown_failed = Vec::new();
    if wired {
        // named-queue dirs are managed by wire()
    } else if let Some(base) = inc.parent() {
        for d in [base, &inc, &base.join("msglog"), &base.join("db")] {
            if !d.exists() {
                std::fs::create_dir_all(d)?;
                created.push(d.display().to_string());
            }
            set_perms_0750(d);
            if !chown_user_mail(d, run_user) {
                chown_failed.push(d.display().to_string());
            }
        }
    }
    // MailScanner work dirs, owned by the run-as user: created root-owned (by
    // a pre-repair root run or the rpm), the mailnull children cannot write
    // Processing.db and every message stalls in the scanning queue.
    let work_base = ms_work_dir();
    let quarantine = Path::new(&cfg.quarantine_dir).to_path_buf();
    for (d, owner) in [
        (&work_base, run_user),
        (&work_base.join("incoming"), run_user),
        (&quarantine, "root"),
    ] {
        if !d.exists() {
            if std::fs::create_dir_all(d).is_err() {
                chown_failed.push(format!("{} (create failed)", d.display()));
                continue;
            }
            created.push(d.display().to_string());
        }
        set_perms_0750(d);
        if !chown_deep(d, owner) {
            chown_failed.push(d.display().to_string());
        }
    }

    // MailScanner reads its config only at startup: leaving it running with
    // stale directives is how misfiled spool files kept happening after the
    // Exim Command fix was written to disk.
    let restarted = if !set.is_empty() && service::status().active {
        service::control("restart").ok
    } else {
        false
    };

    Ok(ConfigureReport {
        set,
        created,
        chown_failed,
        restarted,
    })
}

/// MailScanner's work directory (`Incoming Work Dir` parent).
fn ms_work_dir() -> std::path::PathBuf {
    std::env::var("MSFE_NG_MS_WORK_DIR")
        .unwrap_or_else(|_| "/var/spool/MailScanner".to_string())
        .into()
}

/// Find a live clamd socket (env override, cPanel's, then EL's clamd@scan).
fn detect_clamd_socket() -> Option<String> {
    if let Ok(p) = std::env::var("MSFE_NG_CLAMD_SOCKET") {
        return Path::new(&p).exists().then_some(p);
    }
    use std::os::unix::fs::FileTypeExt;
    [
        "/var/clamd",
        "/run/clamd.scan/clamd.sock",
        "/run/clamd.socket",
    ]
    .iter()
    .find(|p| {
        std::fs::metadata(p)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    })
    .map(|p| p.to_string())
}

/// chown `path` (and its direct children) to `<user>:mail`; best-effort.
fn chown_deep(path: &Path, user: &str) -> bool {
    let mut ok = chown_user_mail(path, user);
    if let Ok(entries) = std::fs::read_dir(path) {
        for e in entries.flatten() {
            ok &= chown_user_mail(&e.path(), user);
        }
    }
    ok
}

// ---- Exim wiring (named-queue method) ----------------------------------------
//
// Behavioral facts from the legacy integration's "new method": a cPanel-
// supported custom ACL include (`custom_begin_mail_pre`, survives
// buildeximconf) routes every incoming message into the Exim *named queue*
// `mailscanner` with `control = queue_only`; MailScanner scans that queue and
// moves messages into the normal queue, where Exim delivers them. No split
// spool root, no second Exim config. The include is `.include_if_exists`, so
// removing the fragment file instantly restores direct (unscanned) delivery.

const DEFAULT_ACL_HOOK: &str =
    "/usr/local/cpanel/etc/exim/acls/ACL_MAIL_PRE_BLOCK/custom_begin_mail_pre";
const DEFAULT_NAMED_QUEUE_BASE: &str = "/var/spool/exim/mailscanner";

fn acl_hook_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_EXIM_ACL_HOOK")
        .unwrap_or_else(|_| DEFAULT_ACL_HOOK.to_string())
        .into()
}
fn named_queue_base() -> std::path::PathBuf {
    std::env::var("MSFE_NG_NAMED_QUEUE_DIR")
        .unwrap_or_else(|_| DEFAULT_NAMED_QUEUE_BASE.to_string())
        .into()
}
fn exim_conf_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_EXIM_CONF")
        .unwrap_or_else(|_| "/etc/exim.conf".to_string())
        .into()
}

fn acl_fragment() -> String {
    "# Managed by MSFE-NG (engine wire). Routes incoming mail into the\n\
     # 'mailscanner' named queue for scanning. Deleting/renaming this file\n\
     # instantly restores direct delivery (the include is include_if_exists).\n\
     accept\n\
     \tremove_header = X-MailScanner-SpamBox\n\
     \tqueue         = mailscanner\n\
     \tcontrol       = queue_only\n"
        .to_string()
}

fn include_line(cfg: &Config) -> String {
    format!(".include_if_exists {}", cfg.mailscannerq_conf)
}

/// Does cPanel's generated exim.conf use a split spool? Decides whether the
/// named queue needs single-character subdirs and the `/*` glob.
pub fn exim_split_spool() -> bool {
    let text = std::fs::read_to_string(exim_conf_path()).unwrap_or_default();
    text.lines().any(|l| {
        let t = l.trim();
        t.strip_prefix("split_spool_directory")
            .map(|rest| {
                let v = rest.trim_start_matches([' ', '=']).trim();
                v.is_empty() || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
    })
}

/// True when mail is currently routed through MailScanner: the ACL hook
/// includes our fragment and the fragment file is live.
pub fn is_wired(cfg: &Config) -> bool {
    Path::new(&cfg.mailscannerq_conf).exists()
        && std::fs::read_to_string(acl_hook_path())
            .map(|t| t.contains(&include_line(cfg)))
            .unwrap_or(false)
}

pub struct WireReport {
    pub actions: Vec<String>,
    pub dry_run: bool,
}

fn exim_rebuild(actions: &mut Vec<String>, dry: bool) {
    for cmd in ["/scripts/buildeximconf", "/scripts/restartsrv_exim"] {
        if dry || std::env::var("MSFE_NG_SKIP_EXIM_CMDS").is_ok() {
            actions.push(format!("would run: {cmd}"));
            continue;
        }
        let ok = std::process::Command::new(cmd)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        actions.push(format!("ran {cmd}: {}", if ok { "ok" } else { "FAILED" }));
    }
}

/// Route mail through MailScanner (cPanel named-queue method). Idempotent.
/// `dry` reports every step without changing anything.
pub fn wire(cfg: &Config, dry: bool) -> io::Result<WireReport> {
    if cfg.panel != "cpanel" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exim wiring is currently implemented for cPanel only",
        ));
    }
    if !service::engine_configured() && std::env::var("MSFE_NG_EXIM_ACL_HOOK").is_err() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "MailScanner engine is not installed/configured — run engine install + configure first",
        ));
    }
    let mut actions = Vec::new();
    let split = exim_split_spool();
    let base = named_queue_base();
    let input = base.join("input");
    let run_user = "mailnull";

    // 1. named-queue spool skeleton
    let mut dirs: Vec<std::path::PathBuf> = vec![base.clone(), input.clone(), base.join("msglog")];
    if split {
        for c in ('a'..='z').chain('A'..='Z').chain('0'..='9') {
            dirs.push(input.join(c.to_string()));
        }
    }
    for d in &dirs {
        if !d.exists() {
            if dry {
                actions.push(format!("would create {}", d.display()));
            } else {
                std::fs::create_dir_all(d)?;
                actions.push(format!("created {}", d.display()));
            }
        }
        if !dry {
            set_perms_0750(d);
            chown_user_mail(d, run_user);
        }
    }

    // 2. MailScanner.conf: scan the named queue, emit into the normal queue
    let (_, outgoing) = service::queue_dir_targets();
    let incoming = if split {
        format!("{}/*", input.display())
    } else {
        input.display().to_string()
    };
    let directives = [
        ("Incoming Queue Dir", incoming.as_str()),
        ("Outgoing Queue Dir", &outgoing.display().to_string()),
        ("Split Exim Spool", if split { "yes" } else { "no" }),
        ("Sendmail", "/usr/sbin/exim"),
        ("Sendmail2", "/usr/sbin/exim"),
        // See configure(): required for MailScanner's long-message-ID
        // detection on Exim >= 4.97 (wrong split subdir otherwise).
        ("Exim Command", "/usr/sbin/exim"),
    ];
    let conf_path = Path::new(&cfg.mailscanner_conf);
    if let Ok(original) = std::fs::read_to_string(conf_path) {
        let mut text = original.clone();
        for (k, v) in directives {
            // always normalize — repairs live duplicates too (last one wins)
            let new_text = mailscanner::set_directive(&text, k, v);
            if new_text != text {
                text = new_text;
                actions.push(format!(
                    "{} MailScanner.conf: {k} = {v}",
                    if dry { "would set" } else { "set" }
                ));
            }
        }
        if !dry && text != original {
            service::save_conf(conf_path, &text)?;
        }
    }

    // 3. the ACL fragment + cPanel hook include
    let frag = Path::new(&cfg.mailscannerq_conf);
    if dry {
        actions.push(format!("would write {}", frag.display()));
    } else {
        if let Some(dir) = frag.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::sync::atomic_write(frag, acl_fragment().as_bytes())?;
        actions.push(format!("wrote {}", frag.display()));
    }
    let hook = acl_hook_path();
    let hook_text = std::fs::read_to_string(&hook).unwrap_or_default();
    if !hook_text.contains(&include_line(cfg)) {
        if dry {
            actions.push(format!("would add include to {}", hook.display()));
        } else {
            if let Some(dir) = hook.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut t = hook_text;
            if !t.is_empty() && !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&include_line(cfg));
            t.push('\n');
            crate::sync::atomic_write(&hook, t.as_bytes())?;
            actions.push(format!("added include to {}", hook.display()));
        }
    }

    // 4. rebuild + restart Exim so the ACL takes effect
    exim_rebuild(&mut actions, dry);

    // 5. restart MailScanner so it re-reads its queue dirs (only if allowed)
    if !dry && service::engine_run_enabled() == Some(true) {
        let o = service::control("restart");
        actions.push(format!(
            "restarted MailScanner: {}",
            if o.ok { "ok" } else { "FAILED" }
        ));
    }
    Ok(WireReport {
        actions,
        dry_run: dry,
    })
}

/// Restore direct delivery: drop the include from the cPanel hook, remove the
/// fragment, rebuild Exim. MailScanner may keep running — with nothing routed
/// into its queue it simply idles.
pub fn unwire(cfg: &Config, dry: bool) -> io::Result<WireReport> {
    let mut actions = Vec::new();
    let hook = acl_hook_path();
    if let Ok(text) = std::fs::read_to_string(&hook) {
        if text.contains(&include_line(cfg)) {
            if dry {
                actions.push(format!("would remove include from {}", hook.display()));
            } else {
                let new: String = text
                    .lines()
                    .filter(|l| l.trim() != include_line(cfg))
                    .map(|l| l.to_string() + "\n")
                    .collect();
                crate::sync::atomic_write(&hook, new.as_bytes())?;
                actions.push(format!("removed include from {}", hook.display()));
            }
        }
    }
    let frag = Path::new(&cfg.mailscannerq_conf);
    if frag.exists() {
        if dry {
            actions.push(format!("would remove {}", frag.display()));
        } else {
            std::fs::remove_file(frag)?;
            actions.push(format!("removed {}", frag.display()));
        }
    }
    exim_rebuild(&mut actions, dry);
    Ok(WireReport {
        actions,
        dry_run: dry,
    })
}

fn set_perms_0750(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o750));
}

/// chown `path` to `<user>:mail`, resolving ids from /etc/passwd//etc/group.
/// Best-effort: returns false when the user/group is missing or chown fails
/// (e.g. tests running unprivileged).
fn chown_user_mail(path: &Path, user: &str) -> bool {
    let (Some(uid), Some(gid)) = (uid_of(user), gid_of("mail")) else {
        return false;
    };
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).is_ok()
}

pub(crate) fn uid_of(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != name {
            return None;
        }
        f.next(); // password field
        f.next()?.parse().ok()
    })
}

pub(crate) fn gid_of(name: &str) -> Option<u32> {
    let group = std::fs::read_to_string("/etc/group").ok()?;
    group.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != name {
            return None;
        }
        f.next(); // password field
        f.next()?.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Both tests mutate shared process env vars — serialize them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn wire_and_unwire_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-wire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let msconf = base.join("MailScanner.conf");
        std::fs::write(&msconf, "MTA = exim\n# a comment\n").unwrap();
        std::fs::write(base.join("exim.conf"), "split_spool_directory = true\n").unwrap();
        std::env::set_var("MSFE_NG_EXIM_ACL_HOOK", base.join("hook"));
        std::env::set_var("MSFE_NG_NAMED_QUEUE_DIR", base.join("msqueue"));
        std::env::set_var("MSFE_NG_EXIM_CONF", base.join("exim.conf"));
        std::env::set_var("MSFE_NG_SKIP_EXIM_CMDS", "1");
        std::env::set_var("MSFE_NG_INCOMING_QUEUE", base.join("in"));
        std::env::set_var("MSFE_NG_OUTGOING_QUEUE", base.join("exim/input"));

        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: msconf.display().to_string(),
            mailscannerq_conf: base.join("mailscannerq.conf").display().to_string(),
            ..Default::default()
        };

        // dry run changes nothing
        let dry = wire(&cfg, true).unwrap();
        assert!(dry.dry_run && !dry.actions.is_empty());
        assert!(!Path::new(&cfg.mailscannerq_conf).exists());
        assert!(!is_wired(&cfg));

        // real wire
        wire(&cfg, false).unwrap();
        assert!(is_wired(&cfg));
        let hook = std::fs::read_to_string(base.join("hook")).unwrap();
        assert_eq!(hook.matches(".include_if_exists").count(), 1);
        let frag = std::fs::read_to_string(&cfg.mailscannerq_conf).unwrap();
        assert!(frag.contains("queue         = mailscanner"));
        assert!(frag.contains("control       = queue_only"));
        let text = std::fs::read_to_string(&msconf).unwrap();
        assert!(mailscanner::get_directive(&text, "Incoming Queue Dir")
            .unwrap()
            .ends_with("msqueue/input/*"));
        assert_eq!(
            mailscanner::get_directive(&text, "Split Exim Spool"),
            Some("yes")
        );
        assert!(text.contains("# a comment"));
        assert!(base.join("msqueue/input/a").is_dir()); // split subdirs

        // idempotent: no duplicate include
        wire(&cfg, false).unwrap();
        let hook = std::fs::read_to_string(base.join("hook")).unwrap();
        assert_eq!(hook.matches(".include_if_exists").count(), 1);

        // regression: configure while wired must NOT revert the queue dirs —
        // it re-asserts the named-queue values instead.
        std::env::set_var("MSFE_NG_MS_WORK_DIR", base.join("work"));
        let cfg_q = Config {
            quarantine_dir: base.join("quarantine").display().to_string(),
            ..cfg.clone()
        };
        configure(&cfg_q).unwrap();
        let text = std::fs::read_to_string(&msconf).unwrap();
        assert!(mailscanner::get_directive(&text, "Incoming Queue Dir")
            .unwrap()
            .ends_with("msqueue/input/*"));
        std::env::remove_var("MSFE_NG_MS_WORK_DIR");

        // unwire restores direct delivery
        unwire(&cfg, false).unwrap();
        assert!(!is_wired(&cfg));
        assert!(!Path::new(&cfg.mailscannerq_conf).exists());
        assert!(!std::fs::read_to_string(base.join("hook"))
            .unwrap()
            .contains(".include_if_exists"));

        for v in [
            "MSFE_NG_EXIM_ACL_HOOK",
            "MSFE_NG_NAMED_QUEUE_DIR",
            "MSFE_NG_EXIM_CONF",
            "MSFE_NG_SKIP_EXIM_CMDS",
            "MSFE_NG_INCOMING_QUEUE",
            "MSFE_NG_OUTGOING_QUEUE",
        ] {
            std::env::remove_var(v);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn configures_conf_and_creates_spool() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let conf = base.join("MailScanner.conf");
        std::fs::write(
            &conf,
            "MTA = sendmail\nIncoming Queue Dir = /var/spool/mqueue.in\nOutgoing Queue Dir = /var/spool/mqueue\nRun As User = \n",
        )
        .unwrap();
        let inc = base.join("exim_incoming/input");
        let out = base.join("exim/input");
        std::env::set_var("MSFE_NG_INCOMING_QUEUE", &inc);
        std::env::set_var("MSFE_NG_OUTGOING_QUEUE", &out);
        std::env::set_var("MSFE_NG_MS_WORK_DIR", base.join("work"));

        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: conf.display().to_string(),
            quarantine_dir: base.join("quarantine").display().to_string(),
            ..Default::default()
        };
        let r = configure(&cfg).unwrap();
        let text = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(mailscanner::get_directive(&text, "MTA"), Some("exim"));
        assert_eq!(
            mailscanner::get_directive(&text, "Run As User"),
            Some("mailnull")
        );
        assert_eq!(
            mailscanner::get_directive(&text, "Incoming Queue Dir"),
            Some(inc.display().to_string().as_str())
        );
        assert!(inc.is_dir());
        assert!(inc.parent().unwrap().join("msglog").is_dir());
        assert!(!out.exists(), "outgoing spool must never be created");
        assert!(r.set.iter().any(|s| s.starts_with("MTA = exim")));
        // backup of the original was kept
        assert!(conf.with_extension("conf.msfe-ng.bak").exists());

        // second run is a no-op on the conf
        let r2 = configure(&cfg).unwrap();
        assert!(r2.set.is_empty());
        assert!(r2.created.is_empty());

        std::env::remove_var("MSFE_NG_INCOMING_QUEUE");
        std::env::remove_var("MSFE_NG_OUTGOING_QUEUE");
        std::env::remove_var("MSFE_NG_MS_WORK_DIR");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
