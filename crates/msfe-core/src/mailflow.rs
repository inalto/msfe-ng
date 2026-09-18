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
// exists (WHM "Apache SpamAssassin: Forced Global ON") or when the account's
// home holds `.spamassassinenable` (cPanel → Spam Filters). That ACL has no
// off switch: with MailScanner scoring every message it is a second scan
// with its own threshold and its own +spam folder. Turning it off therefore
// means turning Spam Filters off per account — through cPanel's own API, so
// cPanel's bookkeeping stays right — and remembering who had it on.

/// Where cPanel's files live (`/`; tests point it at a fixture tree, which
/// also switches the per-account calls from `uapi` to plain file operations).
fn cpanel_root() -> PathBuf {
    std::env::var("MSFE_NG_CPANEL_ROOT")
        .unwrap_or_else(|_| "/".to_string())
        .into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpanelSa {
    /// `/etc/global_spamassassin_enable` — every account, no opt-out.
    pub forced_on: bool,
    /// Accounts whose home has `.spamassassinenable`.
    pub accounts_on: Vec<String>,
    /// Accounts MSFE-NG turned off earlier, restorable.
    pub restorable: Vec<String>,
}

impl CpanelSa {
    /// Would cPanel's Exim hand mail to spamd for at least one account?
    pub fn would_scan(&self) -> bool {
        self.forced_on || !self.accounts_on.is_empty()
    }
}

fn sa_record_path(root: &Path) -> PathBuf {
    root.join("etc/msfe-ng/cpanel-sa-accounts")
}

/// `(user, home)` for every passwd entry.
fn passwd_homes(root: &Path) -> Vec<(String, PathBuf)> {
    std::fs::read_to_string(root.join("etc/passwd"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 5).then(|| (f[0].to_string(), root.join(f[5].trim_start_matches('/'))))
        })
        .collect()
}

/// cPanel's Apache SpamAssassin switches as Exim sees them.
pub fn cpanel_sa_state() -> CpanelSa {
    cpanel_sa_state_at(&cpanel_root())
}

pub fn cpanel_sa_state_at(root: &Path) -> CpanelSa {
    let accounts_on = passwd_homes(root)
        .into_iter()
        .filter(|(_, home)| home.join(".spamassassinenable").is_file())
        .map(|(user, _)| user)
        .collect();
    let restorable = std::fs::read_to_string(sa_record_path(root))
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    CpanelSa {
        forced_on: root.join("etc/global_spamassassin_enable").is_file(),
        accounts_on,
        restorable,
    }
}

/// Spam Filters on/off for one account: cPanel's UAPI on a live host, the
/// flag file itself under a fixture root.
fn set_account_sa(root: &Path, user: &str, home: &Path, on: bool) -> io::Result<()> {
    if root == Path::new("/") {
        let call = if on {
            "enable_spam_assassin"
        } else {
            "disable_spam_assassin"
        };
        let out = std::process::Command::new("uapi")
            .args([
                "--output=json",
                &format!("--user={user}"),
                "SpamAssassin",
                call,
            ])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !text.contains("\"status\":1") {
            return Err(io::Error::other(format!(
                "uapi SpamAssassin {call} for {user} failed: {}",
                text.trim()
            )));
        }
        return Ok(());
    }
    let flag = home.join(".spamassassinenable");
    if on {
        std::fs::write(flag, b"")
    } else {
        match std::fs::remove_file(flag) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Turn cPanel's SpamAssassin off for every account (`enabled == false`),
/// remembering them, or back on for the remembered ones (`true`). Never
/// forces it globally on. Returns the accounts changed.
pub fn set_cpanel_sa(enabled: bool) -> io::Result<Vec<String>> {
    let root = cpanel_root();
    let homes = passwd_homes(&root);
    let record = sa_record_path(&root);
    let mut changed = Vec::new();
    if enabled {
        let restore = cpanel_sa_state_at(&root).restorable;
        for user in restore {
            if let Some((_, home)) = homes.iter().find(|(u, _)| *u == user) {
                set_account_sa(&root, &user, home, true)?;
                changed.push(user);
            }
        }
        match std::fs::remove_file(&record) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
    } else {
        let global = root.join("etc/global_spamassassin_enable");
        if global.is_file() {
            std::fs::remove_file(&global)?;
            let opts = root.join("etc/exim.conf.localopts");
            if let Ok(text) = std::fs::read_to_string(&opts) {
                let fixed: String = text
                    .lines()
                    .map(|l| {
                        if l.starts_with("globalspamassassin=") {
                            "globalspamassassin=0".to_string()
                        } else {
                            l.to_string()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n";
                if fixed != text {
                    std::fs::write(&opts, fixed)?;
                }
            }
        }
        for (user, home) in &homes {
            if home.join(".spamassassinenable").is_file() {
                set_account_sa(&root, user, home, false)?;
                changed.push(user.clone());
            }
        }
        if !changed.is_empty() {
            if let Some(dir) = record.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut all = cpanel_sa_state_at(&root).restorable;
            all.extend(changed.iter().cloned());
            all.sort();
            all.dedup();
            std::fs::write(&record, all.join("\n") + "\n")?;
        }
    }
    Ok(changed)
}

/// Is mail scored twice? `(ok, detail)` for the doctor.
pub fn cpanel_sa_verdict(state: &CpanelSa) -> (bool, String) {
    if state.forced_on {
        return (false, "Forced Global ON (/etc/global_spamassassin_enable) — every message is scored by cPanel's spamd before MailScanner scores it again".into());
    }
    match state.accounts_on.len() {
        0 => (
            true,
            "no account has cPanel Spam Filters on — MailScanner is the only spam scanner".into(),
        ),
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
        assert!(!s.forced_on && s.accounts_on.is_empty() && !s.would_scan());
        assert!(cpanel_sa_verdict(&s).0);

        std::fs::write(root.join("home/alice/.spamassassinenable"), "").unwrap();
        std::fs::write(root.join("home2/carol/.spamassassinenable"), "").unwrap();
        let s = cpanel_sa_state_at(&root);
        assert_eq!(
            s.accounts_on,
            vec!["alice", "carol"],
            "homes outside /home count too"
        );
        assert!(s.would_scan());
        let (ok, d) = cpanel_sa_verdict(&s);
        assert!(!ok);
        assert!(d.starts_with("2 account(s)"), "{d}");

        std::fs::write(root.join("etc/global_spamassassin_enable"), "").unwrap();
        let s = cpanel_sa_state_at(&root);
        assert!(s.forced_on && s.would_scan());
        assert!(cpanel_sa_verdict(&s).1.starts_with("Forced Global ON"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn set_cpanel_sa_turns_accounts_off_and_restores_exactly_them() {
        let root = cpanel_fixture("toggle");
        std::env::set_var("MSFE_NG_CPANEL_ROOT", &root);
        std::fs::write(root.join("home/bob/.spamassassinenable"), "").unwrap();
        std::fs::write(root.join("home2/carol/.spamassassinenable"), "").unwrap();
        std::fs::write(root.join("etc/global_spamassassin_enable"), "").unwrap();
        std::fs::write(
            root.join("etc/exim.conf.localopts"),
            "spam_deferok=1\nglobalspamassassin=1\n",
        )
        .unwrap();

        assert_eq!(set_cpanel_sa(false).unwrap(), vec!["bob", "carol"]);
        let s = cpanel_sa_state();
        assert!(!s.would_scan());
        assert!(!root.join("etc/global_spamassassin_enable").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/exim.conf.localopts")).unwrap(),
            "spam_deferok=1\nglobalspamassassin=0\n"
        );
        assert_eq!(s.restorable, vec!["bob", "carol"]);
        assert_eq!(
            set_cpanel_sa(false).unwrap(),
            Vec::<String>::new(),
            "idempotent"
        );
        assert_eq!(
            cpanel_sa_state().restorable,
            vec!["bob", "carol"],
            "record kept"
        );

        // alice turned hers on meanwhile: restore brings back only bob + carol
        std::fs::write(root.join("home/alice/.spamassassinenable"), "").unwrap();
        assert_eq!(set_cpanel_sa(true).unwrap(), vec!["bob", "carol"]);
        let s = cpanel_sa_state();
        assert_eq!(s.accounts_on, vec!["alice", "bob", "carol"]);
        assert!(s.restorable.is_empty());
        assert!(!s.forced_on, "never forced globally on");
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
