//! MSFE-NG core library.
//!
//! Holds the panel abstraction, runtime config, the legacy flat-file importer,
//! the DB migration runner, and a tiny JSON writer. The rule engine and
//! MailScanner/Exim ops arrive in M2.
//!
//! Clean-room note: behavior here is modeled on the *observed* responsibilities
//! of the original `msbe.pl` / `msrules.pl` / `mschange.pl` and on MailWatch,
//! but no original code is copied. See CONTRIBUTING.md.

pub mod config;
pub mod db;
pub mod digest;
pub mod housekeeping;
pub mod json;
pub mod legacy;
pub mod mailflow;
pub mod mailscanner;
pub mod migrate;
pub mod panel;
pub mod quarantine;
pub mod rules;
pub mod spambox;
pub mod stats;
pub mod sync;
pub mod users;

pub use config::Config;
pub use json::Json;
pub use legacy::{import_legacy, LegacyImport};
pub use panel::{detect_panel, Panel};
