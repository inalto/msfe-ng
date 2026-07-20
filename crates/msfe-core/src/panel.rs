//! Control-panel abstraction.
//!
//! Every path or command that differs between cPanel and DirectAdmin is hidden
//! behind the [`Panel`] trait so the rest of the core stays panel-agnostic.
//! M0 only needs detection + identity; the reconcile/registration methods are
//! stubbed and filled in during M1–M2.

use msfe_api::PanelKind;

/// A control panel MSFE-NG can integrate with.
pub trait Panel {
    fn kind(&self) -> PanelKind;

    /// Human-readable name for logs and the placeholder UI.
    fn display_name(&self) -> &'static str;

    /// Where the panel records which domains are local (spec: msbe.pl reads
    /// `/etc/localdomains` on cPanel; DA uses `/etc/virtual/domains`).
    fn local_domains_path(&self) -> &'static str;
}

pub struct Cpanel;
impl Panel for Cpanel {
    fn kind(&self) -> PanelKind {
        PanelKind::Cpanel
    }
    fn display_name(&self) -> &'static str {
        "cPanel / WHM"
    }
    fn local_domains_path(&self) -> &'static str {
        "/etc/localdomains"
    }
}

pub struct DirectAdmin;
impl Panel for DirectAdmin {
    fn kind(&self) -> PanelKind {
        PanelKind::DirectAdmin
    }
    fn display_name(&self) -> &'static str {
        "DirectAdmin"
    }
    fn local_domains_path(&self) -> &'static str {
        "/etc/virtual/domains"
    }
}

/// No panel detected — lets the daemon run on a dev box or bare MailScanner host.
pub struct NoPanel;
impl Panel for NoPanel {
    fn kind(&self) -> PanelKind {
        PanelKind::None
    }
    fn display_name(&self) -> &'static str {
        "no control panel"
    }
    fn local_domains_path(&self) -> &'static str {
        "/etc/localdomains"
    }
}

/// Detect the running control panel by probing well-known marker files.
/// Mirrors the `-e /usr/local/cpanel/version` / `-d /usr/local/directadmin`
/// checks used throughout the original scripts.
pub fn detect_panel() -> Box<dyn Panel> {
    if std::path::Path::new("/usr/local/cpanel/version").exists() {
        Box::new(Cpanel)
    } else if std::path::Path::new("/usr/local/directadmin/directadmin").exists() {
        Box::new(DirectAdmin)
    } else {
        Box::new(NoPanel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_have_stable_strings() {
        assert_eq!(Cpanel.kind().as_str(), "cpanel");
        assert_eq!(DirectAdmin.kind().as_str(), "directadmin");
        assert_eq!(NoPanel.kind().as_str(), "none");
    }

    #[test]
    fn detect_never_panics() {
        // On the CI/dev box this returns NoPanel; just assert it resolves.
        let _ = detect_panel().display_name();
    }
}
