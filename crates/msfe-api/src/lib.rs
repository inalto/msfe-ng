//! Shared types, constants and the wire contract between the MSFE-NG daemon,
//! the CLI, and the thin panel (cPanel/DirectAdmin) shims.
//!
//! M0 keeps this intentionally tiny and dependency-free. Later milestones will
//! introduce `serde` and richer request/response enums here.

/// Semantic version of the whole product, surfaced by every component.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default path of the Unix domain socket the daemon listens on.
/// Every panel shim connects here to reach the privileged core.
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/msfe-ng/msfe-ng.sock";

/// Default configuration directory (our own namespace, never `/usr/msfe`).
pub const DEFAULT_CONFIG_DIR: &str = "/etc/msfe-ng";

/// Default install prefix for binaries and web assets.
pub const DEFAULT_PREFIX: &str = "/opt/msfe-ng";

/// Which control panel we are integrated with. The daemon detects this at
/// runtime; the value drives the `Panel` abstraction in `msfe-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelKind {
    Cpanel,
    DirectAdmin,
    /// No supported panel detected (bare MailScanner host or dev machine).
    None,
}

impl PanelKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PanelKind::Cpanel => "cpanel",
            PanelKind::DirectAdmin => "directadmin",
            PanelKind::None => "none",
        }
    }
}

/// The audience a rendered page is for. Drives which placeholder view the
/// daemon serves in M0 and which permission context applies later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// WHM / DirectAdmin admin (root/reseller) surface.
    Admin,
    /// End-user (cPanel/DA account) surface.
    User,
}
