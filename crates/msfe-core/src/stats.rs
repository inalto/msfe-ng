//! Reporting queries over `maillog`, returned as JSON for the admin dashboard.
//!
//! All time windows and limits are sanitized to integers and the "top" dimension
//! is allow-listed, so no caller input reaches SQL unchecked. Every function
//! returns `io::Result`; the daemon turns an `Err` (DB down / not configured)
//! into an `{"available":false}` payload so the UI degrades gracefully.

use crate::config::Config;
use crate::db;
use crate::json::Json;
use std::io;

fn count(s: &str) -> Json {
    Json::Int(s.trim().parse::<i64>().unwrap_or(0))
}

/// Headline counts over the last `days` days.
pub fn summary(cfg: &Config, days: u32) -> io::Result<Json> {
    let sql = format!(
        "SELECT COUNT(*), \
                COALESCE(SUM(isspam=1 AND ishighspam=0),0), \
                COALESCE(SUM(ishighspam=1),0), \
                COALESCE(SUM(virusinfected=1),0), \
                COALESCE(SUM(isspam=0 AND virusinfected=0),0), \
                COALESCE(SUM(quarantined=1),0) \
         FROM maillog WHERE msg_ts >= (NOW() - INTERVAL {days} DAY)"
    );
    let rows = db::query(cfg, &sql)?;
    let r = rows.first().cloned().unwrap_or_default();
    let g = |i: usize| count(r.get(i).map(String::as_str).unwrap_or("0"));
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("days".into(), Json::Int(days as i64)),
        ("total".into(), g(0)),
        ("spam".into(), g(1)),
        ("highspam".into(), g(2)),
        ("virus".into(), g(3)),
        ("clean".into(), g(4)),
        ("quarantined".into(), g(5)),
    ]))
}

/// Daily volume for a stacked/line chart over the last `days` days.
pub fn series(cfg: &Config, days: u32) -> io::Result<Json> {
    let sql = format!(
        "SELECT DATE(msg_ts), COUNT(*), \
                COALESCE(SUM(isspam=1),0), COALESCE(SUM(virusinfected=1),0) \
         FROM maillog WHERE msg_ts >= (NOW() - INTERVAL {days} DAY) \
         GROUP BY DATE(msg_ts) ORDER BY DATE(msg_ts)"
    );
    let rows = db::query(cfg, &sql)?;
    let points = rows
        .iter()
        .map(|r| {
            Json::Object(vec![
                (
                    "date".into(),
                    Json::str(r.first().cloned().unwrap_or_default()),
                ),
                (
                    "total".into(),
                    count(r.get(1).map(String::as_str).unwrap_or("0")),
                ),
                (
                    "spam".into(),
                    count(r.get(2).map(String::as_str).unwrap_or("0")),
                ),
                (
                    "virus".into(),
                    count(r.get(3).map(String::as_str).unwrap_or("0")),
                ),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("points".into(), Json::Array(points)),
    ]))
}

/// The dimensions `top` may group by (allow-list → safe to interpolate).
pub fn valid_top_field(field: &str) -> Option<&'static str> {
    match field {
        "from_domain" => Some("from_domain"),
        "to_domain" => Some("to_domain"),
        "from_address" => Some("from_address"),
        "clientip" => Some("clientip"),
        _ => None,
    }
}

/// Top `limit` values of an allow-listed dimension over the last `days` days.
pub fn top(cfg: &Config, days: u32, field: &str, limit: u32) -> io::Result<Json> {
    let col = valid_top_field(field)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad field"))?;
    let sql = format!(
        "SELECT {col}, COUNT(*) FROM maillog \
         WHERE msg_ts >= (NOW() - INTERVAL {days} DAY) AND {col} <> '' \
         GROUP BY {col} ORDER BY COUNT(*) DESC LIMIT {limit}"
    );
    let rows = db::query(cfg, &sql)?;
    let items = rows
        .iter()
        .map(|r| {
            Json::Object(vec![
                (
                    "key".into(),
                    Json::str(r.first().cloned().unwrap_or_default()),
                ),
                (
                    "count".into(),
                    count(r.get(1).map(String::as_str).unwrap_or("0")),
                ),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("field".into(), Json::str(col)),
        ("items".into(), Json::Array(items)),
    ]))
}

/// Most recent `limit` messages for the message list.
pub fn messages(cfg: &Config, limit: u32) -> io::Result<Json> {
    let sql = format!(
        "SELECT msg_ts, from_address, to_address, subject, sascore, \
                isspam, ishighspam, virusinfected, quarantined \
         FROM maillog ORDER BY msg_ts DESC LIMIT {limit}"
    );
    let rows = db::query(cfg, &sql)?;
    let items = rows
        .iter()
        .map(|r| {
            let f = |i: usize| r.get(i).cloned().unwrap_or_default();
            Json::Object(vec![
                ("ts".into(), Json::str(f(0))),
                ("from".into(), Json::str(f(1))),
                ("to".into(), Json::str(f(2))),
                ("subject".into(), Json::str(f(3))),
                ("score".into(), Json::str(f(4))),
                ("isspam".into(), count(&f(5))),
                ("ishighspam".into(), count(&f(6))),
                ("virus".into(), count(&f(7))),
                ("quarantined".into(), count(&f(8))),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("items".into(), Json::Array(items)),
    ]))
}

/// Clamp a query-string integer to a sane range with a default.
pub fn clamp_int(raw: Option<&str>, default: u32, min: u32, max: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(default)
        .clamp(min, max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_allowlist() {
        assert_eq!(valid_top_field("from_domain"), Some("from_domain"));
        assert_eq!(valid_top_field("from_domain; DROP TABLE maillog"), None);
        assert_eq!(valid_top_field("password"), None);
    }

    #[test]
    fn clamp() {
        assert_eq!(clamp_int(Some("7"), 30, 1, 365), 7);
        assert_eq!(clamp_int(Some("9999"), 30, 1, 365), 365);
        assert_eq!(clamp_int(None, 30, 1, 365), 30);
        assert_eq!(clamp_int(Some("x"), 30, 1, 365), 30);
    }
}
