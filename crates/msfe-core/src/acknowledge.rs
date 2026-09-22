//! Acknowledged doctor notices. A notice the admin has looked at and decided
//! to live with (a raised limit that is fine at 1 %, a kept exiscan) should
//! stop colouring the rail and the banner — without being forgotten. An
//! acknowledgement names the check, keeps the level and detail it had, an
//! optional note, and lasts a number of days or for good. It hides the notice
//! only while the notice stays at that level or below: a warning that turns
//! into a failure is shown again at once.
//!
//! Kept in `acknowledged.json` next to `config.toml` (a file, not the
//! database: the doctor runs on hosts without one).

use crate::doctor::{Check, Level};
use crate::json::Json;
use std::io;
use std::path::{Path, PathBuf};

/// One acknowledged notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub name: String,
    /// The level when acknowledged; a higher level shows the notice again.
    pub level: Level,
    /// The detail when acknowledged, for the list.
    pub detail: String,
    pub note: String,
    pub at: u64,
    /// Expiry (epoch seconds); `None` = for good.
    pub until: Option<u64>,
}

/// How an acknowledgement stands right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Hiding a notice that is still reported.
    Active,
    /// Past its expiry, or the notice got worse: the notice shows again.
    Expired,
    /// The notice is not reported any more (fixed, or gone).
    Resolved,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Active => "active",
            Status::Expired => "expired",
            Status::Resolved => "resolved",
        }
    }
}

/// An acknowledgement with what the doctor says about it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub ack: Ack,
    pub status: Status,
    /// The current level, when the notice is still reported.
    pub now: Option<Level>,
}

/// The doctor's checks split into what is shown and what is acknowledged.
#[derive(Debug, Clone, Default)]
pub struct Split {
    pub shown: Vec<Check>,
    pub acknowledged: Vec<Entry>,
}

fn rank(l: Level) -> u8 {
    match l {
        Level::Ok => 0,
        Level::Warn => 1,
        Level::Fail => 2,
    }
}

fn parse_level(s: &str) -> Level {
    match s {
        "fail" => Level::Fail,
        "warn" => Level::Warn,
        _ => Level::Ok,
    }
}

/// Where the acknowledgements live: next to the config file.
pub fn file_for(config_file: &Path) -> PathBuf {
    if let Ok(p) = std::env::var("MSFE_NG_ACK_FILE") {
        return PathBuf::from(p);
    }
    config_file
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .join("acknowledged.json")
}

pub fn load(path: &Path) -> Vec<Ack> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(v) = Json::parse(&text) else {
        return Vec::new();
    };
    v.get("acknowledged")
        .and_then(Json::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    let name = a.str_field("name");
                    if name.is_empty() {
                        return None;
                    }
                    Some(Ack {
                        name,
                        level: parse_level(&a.str_field("level")),
                        detail: a.str_field("detail"),
                        note: a.str_field("note"),
                        at: a.get("at").and_then(Json::as_i64).unwrap_or(0).max(0) as u64,
                        until: a
                            .get("until")
                            .and_then(Json::as_i64)
                            .filter(|n| *n > 0)
                            .map(|n| n as u64),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn save(path: &Path, acks: &[Ack]) -> io::Result<()> {
    let list: Vec<Json> = acks
        .iter()
        .map(|a| {
            Json::Object(vec![
                ("name".into(), Json::str(&a.name)),
                ("level".into(), Json::str(a.level.as_str())),
                ("detail".into(), Json::str(&a.detail)),
                ("note".into(), Json::str(&a.note)),
                ("at".into(), Json::Int(a.at as i64)),
                (
                    "until".into(),
                    a.until.map(|u| Json::Int(u as i64)).unwrap_or(Json::Null),
                ),
            ])
        })
        .collect();
    let doc = Json::Object(vec![("acknowledged".into(), Json::Array(list))]);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    crate::sync::atomic_write(path, doc.to_string().as_bytes())
}

/// Acknowledge `check` for `days` (None = for good) with a note. Replaces an
/// earlier acknowledgement of the same check. Only warnings and failures can
/// be acknowledged.
pub fn ack(
    path: &Path,
    check: &Check,
    days: Option<u32>,
    note: &str,
    now: u64,
) -> Result<Ack, String> {
    if check.level == Level::Ok {
        return Err(format!("{} is not a notice right now", check.name));
    }
    let note = note.trim();
    if note.chars().count() > 300 {
        return Err("the note is longer than 300 characters".into());
    }
    let a = Ack {
        name: check.name.to_string(),
        level: check.level,
        detail: check.detail.clone(),
        note: note.to_string(),
        at: now,
        until: days.map(|d| now + u64::from(d.clamp(1, 3650)) * 86_400),
    };
    let mut acks = load(path);
    acks.retain(|x| x.name != a.name);
    acks.push(a.clone());
    save(path, &acks).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(a)
}

/// Forget an acknowledgement. `Ok(false)` when there was none.
pub fn unack(path: &Path, name: &str) -> Result<bool, String> {
    let mut acks = load(path);
    let before = acks.len();
    acks.retain(|x| x.name != name);
    if acks.len() == before {
        return Ok(false);
    }
    save(path, &acks).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(true)
}

/// Is `a` hiding a notice at `level` at time `now`?
fn hides(a: &Ack, level: Level, now: u64) -> bool {
    a.until.map_or(true, |u| now < u) && rank(level) <= rank(a.level)
}

/// Split the doctor's checks: those acknowledged (and not worse than when
/// acknowledged, and not expired) are set aside with their status; every
/// acknowledgement is reported, including the resolved ones.
pub fn split(checks: Vec<Check>, acks: &[Ack], now: u64) -> Split {
    let mut out = Split::default();
    for c in checks {
        match acks.iter().find(|a| a.name == c.name) {
            Some(a) if c.level != Level::Ok && hides(a, c.level, now) => {
                out.acknowledged.push(Entry {
                    ack: a.clone(),
                    status: Status::Active,
                    now: Some(c.level),
                });
            }
            Some(a) if c.level != Level::Ok => {
                out.acknowledged.push(Entry {
                    ack: a.clone(),
                    status: Status::Expired,
                    now: Some(c.level),
                });
                out.shown.push(c);
            }
            Some(a) => {
                out.acknowledged.push(Entry {
                    ack: a.clone(),
                    status: Status::Resolved,
                    now: Some(c.level),
                });
                out.shown.push(c);
            }
            None => out.shown.push(c),
        }
    }
    // acknowledgements of checks the doctor no longer reports at all
    for a in acks {
        if !out.acknowledged.iter().any(|e| e.ack.name == a.name) {
            out.acknowledged.push(Entry {
                ack: a.clone(),
                status: Status::Resolved,
                now: None,
            });
        }
    }
    out
}

/// The doctor's checks for this host with the acknowledgements applied.
pub fn split_for(config_file: &Path, checks: Vec<Check>) -> Split {
    let acks = load(&file_for(config_file));
    split(checks, &acks, crate::delivery::now_secs())
}

impl Entry {
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("name".into(), Json::str(&self.ack.name)),
            ("level".into(), Json::str(self.ack.level.as_str())),
            ("detail".into(), Json::str(&self.ack.detail)),
            ("note".into(), Json::str(&self.ack.note)),
            ("at".into(), Json::Int(self.ack.at as i64)),
            (
                "until".into(),
                self.ack
                    .until
                    .map(|u| Json::Int(u as i64))
                    .unwrap_or(Json::Null),
            ),
            ("status".into(), Json::str(self.status.as_str())),
            (
                "now".into(),
                self.now
                    .map(|l| Json::str(l.as_str()))
                    .unwrap_or(Json::Null),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(name: &'static str, level: Level) -> Check {
        Check {
            name,
            level,
            detail: format!("{name} detail"),
            fix: None,
            url: None,
            proposal: None,
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-ack-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d.join("acknowledged.json")
    }

    #[test]
    fn ack_hides_until_expiry_or_a_worse_level() {
        let path = tmp("basic");
        let warn = check("large messages get spam-checked", Level::Warn);
        let a = ack(&path, &warn, Some(30), " fine at 1 % ", 1_000).unwrap();
        assert_eq!(a.until, Some(1_000 + 30 * 86_400));
        assert_eq!(a.note, "fine at 1 %");
        // hidden now
        let s = split(
            vec![warn.clone(), check("other", Level::Fail)],
            &load(&path),
            2_000,
        );
        assert_eq!(s.shown.len(), 1);
        assert_eq!(s.shown[0].name, "other");
        assert_eq!(s.acknowledged.len(), 1);
        assert_eq!(s.acknowledged[0].status, Status::Active);
        // expired: shown again, listed as expired
        let s = split(vec![warn.clone()], &load(&path), 1_000 + 31 * 86_400);
        assert_eq!(s.shown.len(), 1);
        assert_eq!(s.acknowledged[0].status, Status::Expired);
        // worse than when acknowledged: shown again
        let worse = check("large messages get spam-checked", Level::Fail);
        let s = split(vec![worse], &load(&path), 2_000);
        assert_eq!(s.shown.len(), 1);
        assert_eq!(s.acknowledged[0].status, Status::Expired);
        // resolved: the check is ok now, or gone
        let s = split(
            vec![check("large messages get spam-checked", Level::Ok)],
            &load(&path),
            2_000,
        );
        assert_eq!(s.shown.len(), 1);
        assert_eq!(s.acknowledged[0].status, Status::Resolved);
        let s = split(vec![], &load(&path), 2_000);
        assert_eq!(s.acknowledged[0].status, Status::Resolved);
        assert_eq!(s.acknowledged[0].now, None);
        // for good
        let b = ack(&path, &warn, None, "", 3_000).unwrap();
        assert_eq!(b.until, None);
        assert_eq!(load(&path).len(), 1, "re-acknowledging replaces");
        let s = split(vec![warn.clone()], &load(&path), 9_999_999_999);
        assert_eq!(s.shown.len(), 0);
        // an ok check cannot be acknowledged; unack forgets
        assert!(ack(&path, &check("x", Level::Ok), None, "", 1).is_err());
        assert_eq!(unack(&path, "nope"), Ok(false));
        assert_eq!(unack(&path, "large messages get spam-checked"), Ok(true));
        assert!(load(&path).is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn the_file_round_trips_and_tolerates_junk() {
        let path = tmp("file");
        assert!(load(&path).is_empty());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "not json").unwrap();
        assert!(load(&path).is_empty());
        let acks = vec![Ack {
            name: "n".into(),
            level: Level::Fail,
            detail: "d \"quoted\"".into(),
            note: "why".into(),
            at: 5,
            until: None,
        }];
        save(&path, &acks).unwrap();
        assert_eq!(load(&path), acks);
        let e = Entry {
            ack: acks[0].clone(),
            status: Status::Active,
            now: Some(Level::Warn),
        };
        let j = e.to_json().to_string();
        assert!(j.contains("\"status\":\"active\"") && j.contains("\"now\":\"warn\""));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
