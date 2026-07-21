//! Mail-log housekeeping: prune old rows so the database doesn't grow forever.
//!
//! Spec (behavior only): the original `mssql.pl` deletes `maillog` rows older
//! than the `cleanmysql` setting (days) and optimizes the table. We do the same
//! for `maillog` and `quarantine`. Reimplemented clean-room.

use crate::config::Config;
use crate::db;
use std::io;

/// Retention in days, from the `cleanmysql` policy setting (default 90),
/// clamped to a sane range.
pub fn retention_days(settings: &[(String, String)]) -> u32 {
    settings
        .iter()
        .find(|(k, _)| k == "cleanmysql")
        .and_then(|(_, v)| v.trim().parse::<u32>().ok())
        .unwrap_or(90)
        .clamp(1, 3650)
}

/// Delete rows older than `days` from `maillog` and `quarantine`, then optimize.
pub fn prune(cfg: &Config, days: u32) -> io::Result<()> {
    let sql = format!(
        "DELETE FROM maillog WHERE msg_ts < (NOW() - INTERVAL {days} DAY);\n\
         DELETE FROM quarantine WHERE quarantined_at < (NOW() - INTERVAL {days} DAY);\n\
         OPTIMIZE TABLE maillog;\n"
    );
    db::exec_stdin(cfg, &sql)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_default_and_clamp() {
        assert_eq!(retention_days(&[]), 90);
        assert_eq!(retention_days(&[("cleanmysql".into(), "30".into())]), 30);
        assert_eq!(
            retention_days(&[("cleanmysql".into(), "99999".into())]),
            3650
        );
        assert_eq!(retention_days(&[("cleanmysql".into(), "x".into())]), 90);
    }
}
