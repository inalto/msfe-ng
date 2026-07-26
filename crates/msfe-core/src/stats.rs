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

/// Per-day totals for the last `days` days: the legacy "Daily Summary".
pub fn daily_summary(cfg: &Config, days: u32) -> io::Result<Json> {
    let days = days.clamp(1, 365);
    let sql = format!(
        "SELECT DATE(msg_ts), COUNT(*), \
                COALESCE(SUM(isspam=0 AND virusinfected=0 AND nameinfected=0 AND otherinfected=0),0), \
                COALESCE(SUM(isspam=1 AND ishighspam=0),0), \
                COALESCE(SUM(ishighspam=1),0), \
                COALESCE(SUM(virusinfected=1 OR nameinfected=1 OR otherinfected=1),0), \
                COALESCE(SUM(quarantined=1),0), \
                COALESCE(SUM(size),0) \
         FROM maillog WHERE msg_ts >= (NOW() - INTERVAL {days} DAY) \
         GROUP BY DATE(msg_ts) ORDER BY DATE(msg_ts) DESC"
    );
    let rows = db::query(cfg, &sql)?;
    let items = rows
        .iter()
        .map(|r| {
            let f = |i: usize| r.get(i).map(String::as_str).unwrap_or("0");
            Json::Object(vec![
                ("date".into(), Json::str(f(0))),
                ("total".into(), count(f(1))),
                ("clean".into(), count(f(2))),
                ("spam".into(), count(f(3))),
                ("highspam".into(), count(f(4))),
                ("infected".into(), count(f(5))),
                ("quarantined".into(), count(f(6))),
                ("bytes".into(), count(f(7))),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("days".into(), Json::Int(days as i64)),
        ("items".into(), Json::Array(items)),
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

/// Message-list filter (MailControl-style): status buttons, field search,
/// pagination. All inputs are allow-listed or SQL-quoted.
pub struct MessageFilter {
    pub status: String,
    pub field: String,
    pub text: String,
    /// Only messages from the last N days (0 = no limit).
    pub days: u32,
    pub offset: u32,
    pub limit: u32,
}

fn status_where(status: &str) -> &'static str {
    match status {
        "clean" => "isspam=0 AND virusinfected=0 AND nameinfected=0 AND otherinfected=0",
        "lowspam" => "isspam=1 AND ishighspam=0",
        "highspam" => "ishighspam=1",
        "infected" => "(virusinfected=1 OR nameinfected=1 OR otherinfected=1)",
        // blocked by a filename/content rule rather than a virus signature —
        // the legacy "Attachment Emails" view
        "attachments" => "(nameinfected=1 OR otherinfected=1)",
        "wl" => "spamwhitelisted=1",
        "bl" => "spamblacklisted=1",
        "quarantined" => "quarantined=1",
        // "blocked" = held rather than delivered, i.e. we still have a copy to
        // release: quarantined spam/virus mail.
        "blocked" => "quarantined=1",
        _ => "1=1",
    }
}

/// Filtered, searchable, paginated message list with a total count.
pub fn messages(cfg: &Config, f: &MessageFilter) -> io::Result<Json> {
    let mut wheres = vec![status_where(&f.status).to_string()];
    if !f.text.is_empty() {
        let col = match f.field.as_str() {
            "to" => "to_address",
            "subject" => "subject",
            "id" => "message_id",
            "ip" => "clientip",
            _ => "from_address",
        };
        let like = sql_quote(&format!("%{}%", f.text));
        wheres.push(format!("{col} LIKE {like}"));
    }
    if f.days > 0 {
        let days = f.days.clamp(1, 3650);
        wheres.push(format!("msg_ts >= (NOW() - INTERVAL {days} DAY)"));
    }
    let where_sql = wheres.join(" AND ");
    let total: i64 = db::query(
        cfg,
        &format!("SELECT COUNT(*) FROM maillog WHERE {where_sql}"),
    )?
    .first()
    .and_then(|r| r.first())
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);
    let limit = f.limit.clamp(1, 500);
    let offset = f.offset;
    let sql = format!(
        "SELECT msg_ts, from_address, to_address, subject, sascore, \
                isspam, ishighspam, virusinfected, quarantined, message_id, size, \
                spamwhitelisted, spamblacklisted, body_path, clientip \
         FROM maillog WHERE {where_sql} \
         ORDER BY msg_ts DESC LIMIT {limit} OFFSET {offset}"
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
                ("id".into(), Json::str(f(9))),
                ("size".into(), Json::str(f(10))),
                ("wl".into(), count(&f(11))),
                ("bl".into(), count(&f(12))),
                // availability is the filesystem's answer, never the flag
                (
                    "hasbody".into(),
                    Json::Bool(crate::quarantine::body_exists(cfg, &f(9), &f(13))),
                ),
                ("clientip".into(), Json::str(f(14))),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("total".into(), Json::Int(total)),
        ("offset".into(), Json::Int(offset as i64)),
        ("items".into(), Json::Array(items)),
    ]))
}

/// Mark a message as ham/spam after Bayes training, so the list, badges and
/// stats follow the correction ("Modify database when Learn as Ham/Spam").
/// A message re-marked as spam sets the false-negative flag; as ham, the
/// false-positive flag.
pub fn reclassify(cfg: &Config, message_id: &str, spam: bool) -> io::Result<()> {
    if !crate::service::valid_exim_id(message_id) {
        return Ok(());
    }
    let (isspam, isfn, isfp) = if spam { (1, 1, 0) } else { (0, 0, 1) };
    let sql = format!(
        "UPDATE maillog SET isspam={isspam}, isfn={isfn}, isfp={isfp} WHERE message_id = {};\n",
        sql_quote(message_id)
    );
    db::exec_stdin(cfg, &sql)
}

/// The recorded body location and logged headers for a message. Empty strings
/// when unknown. One query so callers reconstruct an Exim `-D` body into a full
/// message without a second round trip.
pub fn body_ref_of(cfg: &Config, message_id: &str) -> io::Result<(String, String)> {
    if !crate::service::valid_exim_id(message_id) {
        return Ok((String::new(), String::new()));
    }
    let sql = format!(
        "SELECT body_path, headers FROM maillog WHERE message_id = {} ORDER BY msg_ts DESC LIMIT 1",
        sql_quote(message_id)
    );
    let rows = db::query(cfg, &sql)?;
    let r = rows.first().cloned().unwrap_or_default();
    Ok((
        r.first().cloned().unwrap_or_default(),
        r.get(1).cloned().unwrap_or_default(),
    ))
}

/// The recorded body location for a message (empty when unknown/pruned).
pub fn body_path_of(cfg: &Config, message_id: &str) -> io::Result<Option<String>> {
    Ok(Some(body_ref_of(cfg, message_id)?.0).filter(|s| !s.is_empty()))
}

/// Volume figures behind the storage/retention disclosure in Settings.
pub fn storage(cfg: &Config, bodydays: u32) -> io::Result<Json> {
    let rows = db::query(
        cfg,
        "SELECT COUNT(*), COALESCE(AVG(size),0) FROM maillog \
         WHERE msg_ts >= (NOW() - INTERVAL 1 DAY)",
    )?;
    let r = rows.first().cloned().unwrap_or_default();
    let per_day: f64 = r.first().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let avg: f64 = r.get(1).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("per_day".into(), Json::Int(per_day as i64)),
        ("avg_size".into(), Json::Int(avg as i64)),
        ("bodydays".into(), Json::Int(bodydays as i64)),
        (
            "projected_bytes".into(),
            Json::Int((per_day * avg * bodydays as f64) as i64),
        ),
    ]))
}

/// What this server has seen from one sender address (or a whole domain when
/// `addr` starts with `@`), for the sender modal's blacklist decision.
pub fn sender_activity(cfg: &Config, addr: &str, days: u32) -> io::Result<Json> {
    let addr = addr.trim().to_lowercase();
    let (col, needle) = match addr.strip_prefix('@') {
        Some(domain) => ("from_domain", domain.to_string()),
        None => ("from_address", addr.clone()),
    };
    let window = if days > 0 {
        format!(
            " AND msg_ts >= (NOW() - INTERVAL {} DAY)",
            days.clamp(1, 3650)
        )
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT COUNT(*), \
                COALESCE(SUM(isspam=1),0), COALESCE(SUM(ishighspam=1),0), \
                COALESCE(SUM(virusinfected=1 OR nameinfected=1 OR otherinfected=1),0), \
                COALESCE(SUM(quarantined=1),0), \
                COALESCE(MIN(msg_ts),''), COALESCE(MAX(msg_ts),''), \
                COALESCE(ROUND(AVG(sascore),2),0) \
         FROM maillog WHERE {col} = {}{window}",
        sql_quote(&needle)
    );
    let rows = db::query(cfg, &sql)?;
    let r = rows.first().cloned().unwrap_or_default();
    let g = |i: usize| r.get(i).cloned().unwrap_or_default();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("addr".into(), Json::str(&addr)),
        ("days".into(), Json::Int(days as i64)),
        ("total".into(), count(&g(0))),
        ("spam".into(), count(&g(1))),
        ("highspam".into(), count(&g(2))),
        ("infected".into(), count(&g(3))),
        ("quarantined".into(), count(&g(4))),
        ("first_seen".into(), Json::str(g(5))),
        ("last_seen".into(), Json::str(g(6))),
        ("avg_score".into(), Json::str(g(7))),
    ]))
}

/// What this server has seen from one client IP: volume, verdict mix, when it
/// first and last appeared, and its most frequent senders/recipients.
pub fn ip_activity(cfg: &Config, ip: &str, days: u32) -> io::Result<Json> {
    // MailScanner records the client address in several shapes ("1.2.3.4",
    // "[1.2.3.4]:45570", "1.2.3.4:45570") — match them all.
    let ip = crate::csf::normalize_ip(ip);
    let q = format!(
        "(clientip = {} OR clientip LIKE {} OR clientip LIKE {})",
        sql_quote(&ip),
        sql_quote(&format!("[{ip}]:%")),
        sql_quote(&format!("{ip}:%"))
    );
    let window = if days > 0 {
        format!(
            " AND msg_ts >= (NOW() - INTERVAL {} DAY)",
            days.clamp(1, 3650)
        )
    } else {
        String::new()
    };
    let sql = format!(
        "SELECT COUNT(*), \
                COALESCE(SUM(isspam=1),0), COALESCE(SUM(ishighspam=1),0), \
                COALESCE(SUM(virusinfected=1 OR nameinfected=1 OR otherinfected=1),0), \
                COALESCE(SUM(quarantined=1),0), \
                COALESCE(MIN(msg_ts),''), COALESCE(MAX(msg_ts),''), \
                COALESCE(ROUND(AVG(sascore),2),0) \
         FROM maillog WHERE {q}{window}"
    );
    let rows = db::query(cfg, &sql)?;
    let r = rows.first().cloned().unwrap_or_default();
    let g = |i: usize| r.get(i).cloned().unwrap_or_default();
    let top = |col: &str| -> Json {
        let sql = format!(
            "SELECT {col}, COUNT(*) FROM maillog WHERE {q}{window} AND {col} <> '' \
             GROUP BY {col} ORDER BY COUNT(*) DESC LIMIT 5"
        );
        Json::Array(
            db::query(cfg, &sql)
                .unwrap_or_default()
                .iter()
                .map(|row| {
                    Json::Object(vec![
                        (
                            "key".into(),
                            Json::str(row.first().cloned().unwrap_or_default()),
                        ),
                        (
                            "count".into(),
                            count(row.get(1).map(String::as_str).unwrap_or("0")),
                        ),
                    ])
                })
                .collect(),
        )
    };
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("ip".into(), Json::str(&ip)),
        ("days".into(), Json::Int(days as i64)),
        ("total".into(), count(&g(0))),
        ("spam".into(), count(&g(1))),
        ("highspam".into(), count(&g(2))),
        ("infected".into(), count(&g(3))),
        ("quarantined".into(), count(&g(4))),
        ("first_seen".into(), Json::str(g(5))),
        ("last_seen".into(), Json::str(g(6))),
        ("avg_score".into(), Json::str(g(7))),
        ("top_senders".into(), top("from_address")),
        ("top_recipients".into(), top("to_address")),
    ]))
}

/// Everything recorded about one message, for the detail view.
pub fn message_detail(cfg: &Config, message_id: &str) -> io::Result<Json> {
    if !crate::service::valid_exim_id(message_id) {
        return Ok(Json::Object(vec![("available".into(), Json::Bool(false))]));
    }
    let sql = format!(
        "SELECT msg_ts, message_id, from_address, to_address, subject, size, clientip, \
                sascore, spamreport, rblspamreport, report, isspam, ishighspam, \
                spamwhitelisted, spamblacklisted, virusinfected, nameinfected, \
                otherinfected, quarantined, hostname, headers, body_path \
         FROM maillog WHERE message_id = {} ORDER BY msg_ts DESC LIMIT 1",
        sql_quote(message_id)
    );
    let rows = db::query(cfg, &sql)?;
    let Some(r) = rows.first() else {
        return Ok(Json::Object(vec![("available".into(), Json::Bool(false))]));
    };
    let f = |i: usize| r.get(i).cloned().unwrap_or_default();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("ts".into(), Json::str(f(0))),
        ("id".into(), Json::str(f(1))),
        ("from".into(), Json::str(f(2))),
        ("to".into(), Json::str(f(3))),
        ("subject".into(), Json::str(f(4))),
        ("size".into(), Json::str(f(5))),
        ("clientip".into(), Json::str(f(6))),
        ("score".into(), Json::str(f(7))),
        ("spamreport".into(), Json::str(f(8))),
        ("rblreport".into(), Json::str(f(9))),
        ("report".into(), Json::str(f(10))),
        ("isspam".into(), count(&f(11))),
        ("ishighspam".into(), count(&f(12))),
        ("wl".into(), count(&f(13))),
        ("bl".into(), count(&f(14))),
        ("virus".into(), count(&f(15))),
        ("nameinfected".into(), count(&f(16))),
        ("otherinfected".into(), count(&f(17))),
        ("quarantined".into(), count(&f(18))),
        ("hostname".into(), Json::str(f(19))),
        ("headers".into(), Json::str(f(20))),
        ("body_path".into(), Json::str(f(21))),
    ]))
}

/// SQL single-quote a string literal safely.
fn sql_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Quarantined messages addressed to any of `domains` (the user's own domains).
/// Empty domain list → empty result (no leakage).
pub fn quarantine_list(cfg: &Config, domains: &[String], limit: u32) -> io::Result<Json> {
    if domains.is_empty() {
        return Ok(Json::Object(vec![
            ("available".into(), Json::Bool(true)),
            ("items".into(), Json::Array(vec![])),
        ]));
    }
    let in_list = domains
        .iter()
        .map(|d| sql_quote(d))
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT message_id, msg_ts, from_address, to_address, subject, \
                isspam, ishighspam, virusinfected \
         FROM maillog WHERE quarantined=1 AND to_domain IN ({in_list}) \
         ORDER BY msg_ts DESC LIMIT {limit}"
    );
    let rows = db::query(cfg, &sql)?;
    let items = rows
        .iter()
        .map(|r| {
            let f = |i: usize| r.get(i).cloned().unwrap_or_default();
            let mut kind = "spam";
            if count(&f(7)).to_string() != "0" {
                kind = "virus";
            } else if count(&f(6)).to_string() != "0" {
                kind = "high spam";
            }
            Json::Object(vec![
                ("id".into(), Json::str(f(0))),
                ("ts".into(), Json::str(f(1))),
                ("from".into(), Json::str(f(2))),
                ("to".into(), Json::str(f(3))),
                ("subject".into(), Json::str(f(4))),
                ("kind".into(), Json::str(kind)),
            ])
        })
        .collect();
    Ok(Json::Object(vec![
        ("available".into(), Json::Bool(true)),
        ("items".into(), Json::Array(items)),
    ]))
}

/// Recipient domain of a logged message id (for ownership checks). Validate the
/// id with `quarantine::valid_message_id` before calling.
pub fn to_domain_of(cfg: &Config, message_id: &str) -> io::Result<Option<String>> {
    let sql = format!(
        "SELECT to_domain FROM maillog WHERE message_id={} LIMIT 1",
        sql_quote(message_id)
    );
    let rows = db::query(cfg, &sql)?;
    Ok(rows.first().and_then(|r| r.first()).cloned())
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
