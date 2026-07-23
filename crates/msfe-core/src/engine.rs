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
    let inc_s = inc.display().to_string();
    let out_s = out.display().to_string();

    let directives: [(&str, &str); 11] = [
        ("MTA", "exim"),
        ("Run As User", run_user),
        ("Run As Group", "mail"),
        ("Incoming Queue Dir", &inc_s),
        ("Outgoing Queue Dir", &out_s),
        ("Sendmail", "/usr/sbin/exim"),
        ("Sendmail2", "/usr/sbin/exim"),
        ("Incoming Work Group", "mail"),
        ("Incoming Work Permissions", "0640"),
        ("Quarantine Group", "mail"),
        ("Quarantine Permissions", "0660"),
    ];

    let conf_path = Path::new(&cfg.mailscanner_conf);
    let original = std::fs::read_to_string(conf_path)?;
    let mut text = original.clone();
    let mut set = Vec::new();
    for (k, v) in directives {
        if mailscanner::get_directive(&text, k) != Some(v) {
            text = mailscanner::set_directive(&text, k, v);
            set.push(format!("{k} = {v}"));
        }
    }
    if text != original {
        service::save_conf(conf_path, &text)?;
    }

    // Incoming split-spool skeleton (ours to create and own). The outgoing dir
    // is the MTA's real spool — never created or chowned here.
    let mut created = Vec::new();
    let mut chown_failed = Vec::new();
    if let Some(base) = inc.parent() {
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
    Ok(ConfigureReport {
        set,
        created,
        chown_failed,
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

fn uid_of(name: &str) -> Option<u32> {
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

fn gid_of(name: &str) -> Option<u32> {
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

    #[test]
    fn configures_conf_and_creates_spool() {
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

        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: conf.display().to_string(),
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
        std::fs::remove_dir_all(&base).unwrap();
    }
}
