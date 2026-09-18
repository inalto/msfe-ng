//! Upgrades run from the UI: MSFE-NG itself and the MailScanner engine, each
//! a background job (see `jobs`) whose log the Service tab follows.

use crate::{jobs, layout, service, Config};
use std::io;

/// Job names the API may start.
pub const SELF_JOB: &str = "upgrade";
pub const ENGINE_JOB: &str = "engine-upgrade";

/// get.sh as installed next to the daemon: download the latest release,
/// verify its checksum, run install.sh.
pub const GET_SCRIPT: &str = "/opt/msfe-ng/bin/msfe-ng-get";
pub const ENGINE_INSTALL_SCRIPT: &str = "/opt/msfe-ng/bin/msfe-ng-engine-install";

/// Start the self-upgrade. The job outlives this daemon: install.sh restarts
/// it, and the UI waits for `/api/health` to report the new version.
pub fn start_self(version: Option<&str>) -> io::Result<()> {
    let mut env = Vec::new();
    if let Some(v) = version {
        env.push(("MSFE_NG_VERSION", v.to_string()));
    }
    jobs::start(SELF_JOB, &format!("sh {GET_SCRIPT}"), &env)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineUpdate {
    /// Installed engine version (`MailScanner Version Number`), if known.
    pub version: Option<String>,
    /// Latest MailScanner v5 release tag (`5.5.3-2`), when reachable.
    pub latest: Option<String>,
    /// The RPM engine (`/usr/sbin/MailScanner`): the only one upgraded in place.
    pub rpm: bool,
    pub upgradable: bool,
}

/// Compare the installed engine with the latest MailScanner release.
pub fn engine_update(cfg: &Config) -> EngineUpdate {
    let lay = layout::resolve(cfg);
    let version = lay.version.map(|_| lay.version_string());
    let rpm = lay.bin == std::path::Path::new(layout::DEFAULT_BIN);
    let latest = service::latest_release(service::MAILSCANNER_REPO);
    engine_update_verdict(version, latest, rpm)
}

pub fn engine_update_verdict(
    version: Option<String>,
    latest: Option<String>,
    rpm: bool,
) -> EngineUpdate {
    let upgradable = rpm
        && match (&latest, &version) {
            (Some(l), Some(v)) => service::version_newer(l, v),
            _ => false,
        };
    EngineUpdate {
        version,
        latest,
        rpm,
        upgradable,
    }
}

/// Start the engine upgrade to `version`: reinstall the RPM (forced, since an
/// engine is present), re-apply our configuration, restart MailScanner.
pub fn start_engine(version: &str) -> io::Result<()> {
    if !version
        .bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(io::Error::other(format!("bad engine version '{version}'")));
    }
    let script = format!(
        "sh {ENGINE_INSTALL_SCRIPT} && msfe-ng engine configure && msfe-ng service restart"
    );
    jobs::start(
        ENGINE_JOB,
        &script,
        &[
            ("MSFE_NG_ENGINE_FORCE", "1".into()),
            ("MSFE_NG_MS_VERSION", version.to_string()),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_is_upgradable_only_for_a_newer_rpm_release() {
        let v = |s: &str| Some(s.to_string());
        assert!(engine_update_verdict(v("5.5.3"), v("5.5.4-1"), true).upgradable);
        assert!(!engine_update_verdict(v("5.5.3"), v("5.5.3-2"), true).upgradable);
        assert!(
            !engine_update_verdict(v("5.4.4"), v("5.5.4-1"), false).upgradable,
            "ConfigServer engine: migration, not an in-place upgrade"
        );
        assert!(!engine_update_verdict(None, v("5.5.4-1"), true).upgradable);
        assert!(!engine_update_verdict(v("5.5.3"), None, true).upgradable);
    }

    #[test]
    fn engine_version_must_look_like_one() {
        assert!(start_engine("5.5.4; rm -rf /").is_err());
    }
}
