//! Periodic queue monitor, run from cron every 5 minutes (`msfe-ng monitor`).
//!
//! Two jobs, both disabled until configured:
//! 1. **Auto-clean** the delivery queue per the `queue_clean_*` rules (frozen
//!    older than N h, null-sender bounces older than N h, spam score ≥ Y).
//!    Structurally limited to the delivery queue — the scanning queue is never
//!    passed in, so a mis-set rule cannot delete unscanned mail.
//! 2. **Alerts** via Telegram: delivery-queue size, stuck scanning queue, and
//!    per-account outbound sending bursts (parsed from exim_mainlog `A=`
//!    authentication tags). Each alert repeats no more often than
//!    `alert_cooldown_mins`, tracked in the msfe_config kv table.

use crate::config::Config;
use crate::{db, queueview, service, telegram};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::process::Command;

/// How much of the end of exim_mainlog is examined for the burst window.
const LOG_TAIL_BYTES: u64 = 8 * 1024 * 1024;

pub struct MonitorReport {
    pub cleaned: usize,
    pub alerts_sent: usize,
    pub notes: Vec<String>,
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True when `key` may fire again (no record, or the cooldown has elapsed).
/// A missing/unreachable kv store errs on the side of alerting.
fn cooled_down(cfg: &Config, key: &str, now: u64) -> bool {
    let cooldown = cfg.alert_cooldown_mins.max(1) as u64 * 60;
    db::kv_get(cfg, key)
        .and_then(|v| v.parse::<u64>().ok())
        .map(|last| now.saturating_sub(last) >= cooldown)
        .unwrap_or(true)
}

/// One monitor pass. `dry` previews everything: rules select but nothing is
/// removed, alerts print but nothing is sent.
pub fn run(cfg: &Config, dry: bool) -> MonitorReport {
    let mut notes = Vec::new();
    let mut cleaned = 0usize;
    let mut alerts: Vec<String> = Vec::new();
    let now = now_epoch();
    let (in_dir, out_dir) = service::queue_dirs(cfg);

    // ---- 1. auto-clean (delivery queue ONLY) -------------------------------
    let criteria = queueview::CleanCriteria::from_config(cfg);
    if criteria.any_enabled() {
        let listing = queueview::list_queue(&out_dir, 100_000);
        let ids = queueview::select_removals(&listing.msgs, &criteria);
        if ids.is_empty() {
            notes.push("auto-clean: no queued message matches the rules".into());
        } else {
            let o = service::queue_bulk_action(None, &ids, "delete", dry);
            if o.ok && !dry {
                cleaned = ids.len();
                let _ = db::kv_set(
                    cfg,
                    "queueclean_last",
                    &format!("{{\"at\":{now},\"removed\":{cleaned}}}"),
                );
            }
            notes.push(format!(
                "auto-clean: {}{} message(s) matched the rules",
                if dry { "dry-run — " } else { "removed " },
                ids.len()
            ));
            notes.extend(o.transcript.into_iter().map(|l| format!("  {l}")));
        }
    }

    // ---- 2. alert checks ---------------------------------------------------
    let tg = telegram::configured(cfg);
    if cfg.alert_queue_size > 0 {
        let n = service::count_queue(&out_dir);
        if n >= cfg.alert_queue_size as usize && cooled_down(cfg, "alert_qsize", now) {
            alerts.push(format!(
                "Delivery queue holds {n} messages (limit {}).",
                cfg.alert_queue_size
            ));
            if !dry {
                let _ = db::kv_set(cfg, "alert_qsize", &now.to_string());
            }
        }
    }
    if cfg.alert_scan_stuck_mins > 0 && service::count_queue(&in_dir) > 0 {
        if let Some(age) = service::oldest_queue_age(&in_dir) {
            if age >= cfg.alert_scan_stuck_mins as u64 * 60
                && cooled_down(cfg, "alert_scanstuck", now)
            {
                alerts.push(format!(
                    "Scanning queue stuck: oldest message has waited {} min (MailScanner may be down or wedged).",
                    age / 60
                ));
                if !dry {
                    let _ = db::kv_set(cfg, "alert_scanstuck", &now.to_string());
                }
            }
        }
    }
    if cfg.alert_burst_per_hour > 0 {
        for (account, count) in outbound_bursts(cfg, cfg.alert_burst_per_hour as usize) {
            let key = format!("alert_burst_{account}");
            if cooled_down(cfg, &key, now) {
                alerts.push(format!(
                    "Sending burst: {account} sent {count} messages in the last hour (limit {}/h) — possibly a compromised account.",
                    cfg.alert_burst_per_hour
                ));
                if !dry {
                    let _ = db::kv_set(cfg, &key, &now.to_string());
                }
            }
        }
    }

    // ---- deliver the combined alert ---------------------------------------
    let mut alerts_sent = 0;
    if !alerts.is_empty() {
        // routine cleanup rides along only when a real alert fires
        if cleaned > 0 {
            alerts.push(format!("Auto-clean removed {cleaned} queued message(s)."));
        }
        let host = hostname();
        let text = format!("⚠ MSFE-NG — {host}\n• {}", alerts.join("\n• "));
        notes.extend(alerts.iter().map(|a| format!("alert: {a}")));
        if dry {
            notes.push("dry-run — alert not sent".into());
        } else if tg {
            match telegram::send(cfg, &text) {
                Ok(()) => {
                    alerts_sent = alerts.len();
                    notes.push("alert sent via Telegram".into());
                }
                Err(e) => notes.push(format!("Telegram send failed: {e}")),
            }
        } else {
            notes.push(
                "Telegram not configured — alert only logged (Config → Telegram alerts)".into(),
            );
        }
    }

    MonitorReport {
        cleaned,
        alerts_sent,
        notes,
    }
}

fn hostname() -> String {
    Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "server".into())
}

/// Count messages received via authenticated submission per account, from
/// exim_mainlog lines newer than `cutoff` (a `YYYY-MM-DD HH:MM:SS` string —
/// Exim's timestamp format sorts lexicographically, so plain `>=` works).
/// Pure and fixture-testable.
pub fn count_auth_sends(text: &str, cutoff: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        if line.len() < 19 || &line[..19] < cutoff {
            continue;
        }
        // "<= sender ... A=dovecot_login:user@dom ..." marks an accepted
        // message with SMTP AUTH — the authoritative "which account sent it"
        if !line.contains(" <= ") {
            continue;
        }
        let Some(a) = line.split_whitespace().find(|t| t.starts_with("A=")) else {
            continue;
        };
        let Some(account) = a.split(':').nth(1).filter(|s| !s.is_empty()) else {
            continue;
        };
        *out.entry(account.to_string()).or_insert(0) += 1;
    }
    out
}

/// Accounts whose authenticated sends in the trailing hour reach `threshold`.
pub fn outbound_bursts(cfg: &Config, threshold: usize) -> Vec<(String, usize)> {
    let Some(text) = tail_of_file(&cfg.exim_mainlog_path, LOG_TAIL_BYTES) else {
        return Vec::new();
    };
    // GNU date (EL9/cPanel) computes the window edge in the log's local time
    let Ok(out) = Command::new("date")
        .args(["-d", "60 minutes ago", "+%Y-%m-%d %H:%M:%S"])
        .output()
    else {
        return Vec::new();
    };
    let cutoff = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if cutoff.len() != 19 {
        return Vec::new();
    }
    count_auth_sends(&text, &cutoff)
        .into_iter()
        .filter(|(_, n)| *n >= threshold)
        .collect()
}

/// Last `max` bytes of a file, first partial line dropped. Stateless (no
/// offset bookkeeping) so log rotation can never confuse it.
fn tail_of_file(path: &str, max: u64) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf).ok()?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        if let Some(nl) = text.find('\n') {
            text = text.split_off(nl + 1);
        }
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "\
2026-07-28 09:00:01 1woA-0001-Aa <= boss@corp.example H=x [1.2.3.4] P=esmtpsa A=dovecot_login:boss@corp.example S=1234
2026-07-28 09:10:02 1woA-0002-Bb <= info@other.example H=y [5.6.7.8] P=esmtp S=999
2026-07-28 09:20:03 1woA-0003-Cc <= boss@corp.example H=x [1.2.3.4] P=esmtpsa A=dovecot_login:boss@corp.example S=222
2026-07-28 09:30:04 1woA-0004-Dd => someone@dest R=remote T=remote_smtp A=dovecot_login:notasend@x
2026-07-28 08:00:00 1woA-0000-Zz <= boss@corp.example A=dovecot_login:boss@corp.example S=1 (too old)
2026-07-28 09:40:05 1woA-0005-Ee <= mule@hacked.example H=z [9.9.9.9] P=esmtpsa A=dovecot_plain:mule@hacked.example S=555
";

    #[test]
    fn counts_authenticated_sends_in_window() {
        let c = count_auth_sends(LOG, "2026-07-28 09:00:00");
        assert_eq!(c.get("boss@corp.example"), Some(&2)); // 08:00 line excluded
        assert_eq!(c.get("mule@hacked.example"), Some(&1));
        // unauthenticated and delivery (=>) lines don't count
        assert_eq!(c.len(), 2);
        // window narrows correctly
        let later = count_auth_sends(LOG, "2026-07-28 09:30:00");
        assert_eq!(later.get("boss@corp.example"), None);
        assert_eq!(later.get("mule@hacked.example"), Some(&1));
    }

    #[test]
    fn monitor_is_a_noop_when_nothing_enabled() {
        // default config: no rules, no telegram, DB unreachable — must not panic
        let cfg = Config::default();
        let r = run(&cfg, true);
        assert_eq!(r.cleaned, 0);
        assert_eq!(r.alerts_sent, 0);
    }
}
