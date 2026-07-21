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
pub fn set_scanning(enabled: bool) -> io::Result<()> {
    let path = exiscandisable_path();
    if enabled {
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        if let Some(dir) = Path::new(&path).parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, b"MailScanner scanning disabled by MSFE-NG\n")
    }
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
