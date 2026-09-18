//! Mail-flow control: turn MailScanner scanning on/off without touching the mail
//! server config.
//!
//! cPanel's Exim/MailScanner integration honors the presence of
//! `/etc/exiscandisable` to bypass scanning. Rather than blindly patch cPanel
//! internals (the original `mschange.pl`/`EximPatch` edited `Cpanel::Exim`),
//! MSFE-NG just toggles that flag — safe and fully reversible. The deeper
//! Exim.pm patching stays with cPanel's own MailScanner package.

use std::io;
use std::path::{Path, PathBuf};

/// Path of the flag file whose presence disables scanning.
pub fn exiscandisable_path() -> PathBuf {
    std::env::var("MSFE_NG_EXISCANDISABLE")
        .unwrap_or_else(|_| "/etc/exiscandisable".to_string())
        .into()
}

/// True when scanning is active (the disable flag is absent).
pub fn scanning_enabled() -> bool {
    !exiscandisable_path().exists()
}

/// Enable (`true`) or disable (`false`) MailScanner scanning.
///
/// Besides the legacy flag file, this toggles the real kill switch when the
/// Exim wiring is present: the named-queue ACL fragment is renamed to
/// `.disabled` (its include is `include_if_exists`, so mail immediately flows
/// direct again) and Exim is rebuilt.
pub fn set_scanning(enabled: bool) -> io::Result<()> {
    let path = exiscandisable_path();
    if enabled {
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }?;
    } else {
        if let Some(dir) = Path::new(&path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, b"MailScanner scanning disabled by MSFE-NG\n")?;
    }
    toggle_wiring_fragment(enabled)
}

/// Rename the wiring ACL fragment live↔disabled to match the scanning state,
/// rebuilding Exim when something actually changed. No-op when unwired.
fn toggle_wiring_fragment(enabled: bool) -> io::Result<()> {
    let frag = PathBuf::from(
        std::env::var("MSFE_NG_MAILSCANNERQ")
            .unwrap_or_else(|_| "/etc/msfe-ng/mailscannerq.conf".to_string()),
    );
    let disabled = frag.with_extension("conf.disabled");
    let (from, to) = if enabled {
        (&disabled, &frag)
    } else {
        (&frag, &disabled)
    };
    if !from.exists() {
        return Ok(());
    }
    std::fs::rename(from, to)?;
    if std::env::var("MSFE_NG_SKIP_EXIM_CMDS").is_err() {
        for cmd in ["/scripts/buildeximconf", "/scripts/restartsrv_exim"] {
            let _ = std::process::Command::new(cmd).status();
        }
    }
    Ok(())
}

// ---- cPanel's own Apache SpamAssassin -------------------------------------
//
// cPanel's Exim runs Apache SpamAssassin (spamd) from its DATA ACL before the
// message ever reaches MailScanner, when `/etc/global_spamassassin_enable`
// exists (WHM "Forced Global ON"), never when `/etc/global_spamassassin_disable`
// exists ("Forced Global OFF"), and otherwise per account when the account's
// home holds `.spamassassinenable` (cPanel → Spam Filters). With MailScanner
// scoring every message that is a second scan with its own threshold and
// its own +spam folder. Both switches are plain flag files Exim tests per
// message: no rebuild, instantly reversible.

/// Where cPanel's flag files live (`/`; tests point it at a fixture tree).
fn cpanel_root() -> PathBuf {
    std::env::var("MSFE_NG_CPANEL_ROOT")
        .unwrap_or_else(|_| "/".to_string())
        .into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpanelSa {
    /// `/etc/global_spamassassin_enable` — every account, no opt-out.
    pub forced_on: bool,
    /// `/etc/global_spamassassin_disable` — no account, no opt-in.
    pub forced_off: bool,
    /// Accounts whose home has `.spamassassinenable`.
    pub accounts_on: usize,
}

impl CpanelSa {
    /// Would cPanel's Exim hand mail to spamd for at least one account?
    pub fn would_scan(&self) -> bool {
        self.forced_on || (!self.forced_off && self.accounts_on > 0)
    }
}

/// cPanel's Apache SpamAssassin switches as Exim sees them.
pub fn cpanel_sa_state() -> CpanelSa {
    cpanel_sa_state_at(&cpanel_root())
}

pub fn cpanel_sa_state_at(root: &Path) -> CpanelSa {
    let etc = root.join("etc");
    let accounts_on = std::fs::read_to_string(etc.join("passwd"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(':').nth(5))
        .filter(|home| {
            root.join(home.trim_start_matches('/'))
                .join(".spamassassinenable")
                .is_file()
        })
        .count();
    CpanelSa {
        forced_on: etc.join("global_spamassassin_enable").is_file(),
        forced_off: etc.join("global_spamassassin_disable").is_file(),
        accounts_on,
    }
}

/// Forced Global OFF (`enabled == false`: create the disable flag) or back to
/// cPanel's per-account setting (`true`: remove it). Never forces it on.
pub fn set_cpanel_sa(enabled: bool) -> io::Result<()> {
    let flag = cpanel_root().join("etc/global_spamassassin_disable");
    if enabled {
        match std::fs::remove_file(&flag) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        std::fs::write(
            &flag,
            b"cPanel Apache SpamAssassin disabled by MSFE-NG: MailScanner scans instead\n",
        )
    }
}

/// Is mail scored twice? `(ok, detail)` for the doctor.
pub fn cpanel_sa_verdict(state: &CpanelSa) -> (bool, String) {
    if state.forced_on {
        return (false, "Forced Global ON — every message is scored by cPanel's spamd before MailScanner scores it again".into());
    }
    if state.forced_off {
        return (
            true,
            "Forced Global OFF — MailScanner is the only spam scanner".into(),
        );
    }
    match state.accounts_on {
        0 => (true, "no account has cPanel Spam Filters on".into()),
        n => (
            false,
            format!("{n} account(s) have cPanel Spam Filters on — their mail is scored twice, with cPanel's own threshold and +spam folder"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpanel_fixture(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("msfe-cpsa-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["etc", "home/alice", "home/bob", "home2/carol"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:/bin/bash\ncarol:x:1003:1003::/home2/carol:/bin/bash\n",
        )
        .unwrap();
        root
    }

    #[test]
    fn cpanel_sa_state_reads_the_flags_exim_tests() {
        let root = cpanel_fixture("state");
        let s = cpanel_sa_state_at(&root);
        assert_eq!(
            s,
            CpanelSa {
                forced_on: false,
                forced_off: false,
                accounts_on: 0
            }
        );
        assert!(!s.would_scan());
        assert!(cpanel_sa_verdict(&s).0);

        std::fs::write(root.join("home/alice/.spamassassinenable"), "").unwrap();
        std::fs::write(root.join("home2/carol/.spamassassinenable"), "").unwrap();
        let s = cpanel_sa_state_at(&root);
        assert_eq!(s.accounts_on, 2, "homes outside /home count too");
        assert!(s.would_scan());
        let (ok, d) = cpanel_sa_verdict(&s);
        assert!(!ok);
        assert!(d.starts_with("2 account(s)"), "{d}");

        std::fs::write(root.join("etc/global_spamassassin_disable"), "").unwrap();
        let s = cpanel_sa_state_at(&root);
        assert!(
            s.forced_off && !s.would_scan(),
            "Forced Global OFF wins over accounts"
        );
        assert!(cpanel_sa_verdict(&s).0);

        std::fs::write(root.join("etc/global_spamassassin_enable"), "").unwrap();
        let s = cpanel_sa_state_at(&root);
        assert!(s.forced_on && s.would_scan(), "Forced Global ON wins");
        assert!(!cpanel_sa_verdict(&s).0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_cpanel_sa_toggles_only_the_disable_flag() {
        let root = cpanel_fixture("toggle");
        std::env::set_var("MSFE_NG_CPANEL_ROOT", &root);
        std::fs::write(root.join("home/bob/.spamassassinenable"), "").unwrap();
        set_cpanel_sa(false).unwrap();
        assert!(root.join("etc/global_spamassassin_disable").is_file());
        assert!(!cpanel_sa_state().would_scan());
        set_cpanel_sa(true).unwrap();
        set_cpanel_sa(true).unwrap(); // idempotent
        assert!(!root.join("etc/global_spamassassin_disable").exists());
        assert!(
            !root.join("etc/global_spamassassin_enable").exists(),
            "never forced on"
        );
        assert!(
            root.join("home/bob/.spamassassinenable").exists(),
            "account choice untouched"
        );
        assert!(cpanel_sa_state().would_scan());
        std::env::remove_var("MSFE_NG_CPANEL_ROOT");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn toggle_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("msfe-exiscan-{}", std::process::id()));
        std::env::set_var("MSFE_NG_EXISCANDISABLE", &tmp);
        let _ = std::fs::remove_file(&tmp);
        assert!(scanning_enabled());
        set_scanning(false).unwrap();
        assert!(!scanning_enabled());
        assert!(tmp.exists());
        set_scanning(true).unwrap();
        assert!(scanning_enabled());
        set_scanning(true).unwrap(); // idempotent
        std::env::remove_var("MSFE_NG_EXISCANDISABLE");
    }
}
