//! MSFE-NG core library.
//!
//! This crate will eventually hold the rule engine, config model and all the
//! MailScanner/Exim integration. In M0 it provides the `Panel` abstraction and
//! panel autodetection so the daemon and CLI can report where they are running.
//!
//! Clean-room note: behavior here is modeled on the *observed* responsibilities
//! of the original `msbe.pl` / `msrules.pl` / `mschange.pl` and on MailWatch,
//! but no original code is copied. See CONTRIBUTING.md.

pub mod panel;

pub use panel::{detect_panel, Panel};
