//! MSFE-NG core library.
//!
//! Holds the panel abstraction, runtime config, the legacy flat-file importer,
//! the DB migration runner, and a tiny JSON writer. The rule engine and
//! MailScanner/Exim ops arrive in M2.
//!
//! Clean-room note: behavior here is modeled on the *observed* responsibilities
//! of the original `msbe.pl` / `msrules.pl` / `mschange.pl` and on MailWatch,
//! but no original code is copied. See CONTRIBUTING.md.

pub mod authchecks;
pub mod b64;
pub mod civil;
pub mod confcatalog;
pub mod confcheck;
pub mod conffile;
pub mod config;
pub mod confsave;
pub mod confstage;
pub mod conftest;
pub mod cpaudit;
pub mod csf;
pub mod db;
pub mod dbtools;
pub mod delivery;
pub mod deliveryhtml;
pub mod deliverylog;
pub mod deliverymon;
pub mod deliveryrun;
pub mod diaginbox;
pub mod digest;
pub mod dkim;
pub mod dmarc;
pub mod dns;
pub mod dnsbl;
pub mod dnschecks;
pub mod dnsx;
pub mod doctor;
pub mod emlcheck;
pub mod engine;
pub mod engine_migration;
pub mod geoip;
pub mod housekeeping;
pub mod httpclient;
pub mod jobs;
pub mod json;
pub mod layout;
pub mod legacy;
pub mod logindex;
pub mod mailflow;
pub mod mailscanner;
pub mod migrate;
pub mod mime;
pub mod monitor;
pub mod msdefs;
pub mod msgrammar;
pub mod msgtest;
pub mod mtasts;
pub mod mxchecks;
pub mod netguard;
pub mod panel;
pub mod psl;
pub mod quarantine;
pub mod queueview;
pub mod repchecks;
pub mod resolver;
pub mod rulefile;
pub mod rules;
pub mod sa;
pub mod service;
pub mod setup;
pub mod smtpprobe;
pub mod snapshot;
pub mod spambox;
pub mod spf;
pub mod stats;
pub mod sync;
pub mod telegram;
pub mod testmail;
pub mod tlsprobe;
pub mod tschecks;
pub mod upgrade;
pub mod users;

pub use config::Config;
pub use json::Json;
pub use legacy::{import_legacy, LegacyImport};
pub use panel::{detect_panel, Panel};
