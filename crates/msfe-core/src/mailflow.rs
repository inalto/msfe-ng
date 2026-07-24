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

#[cfg(test)]
mod tests {
    use super::*;

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
