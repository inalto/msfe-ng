//! Service tab → System services: are the daemons the mail system needs
//! running now, and will they start again after a reboot?
//!
//! One `systemctl show` over every candidate unit name answers both (its
//! `ActiveState` and `UnitFileState`); the first candidate systemd has loaded
//! is the unit in use (MailScanner is `mailscanner` or `MailScanner`, ClamAV
//! `clamd` or `clamd@scan`, the database `mysqld`, `mariadb` or `mysql`).
//! Actions are limited to those units and to enable / start / restart —
//! msfe-ng's own daemon only to enable, since restarting it from a request
//! would cut that request off.

use crate::config::Config;
use crate::json::Json;
use std::collections::HashMap;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// mail stops or goes unscanned without it
    Required,
    /// used when installed (firewall, resolver, mailboxes)
    Optional,
}

#[derive(Debug, Clone)]
pub struct Spec {
    pub label: &'static str,
    pub candidates: Vec<&'static str>,
    pub role: Role,
    pub why: &'static str,
}

/// The units the mail system relies on, in display order.
pub fn specs() -> Vec<Spec> {
    let s = |label, candidates: Vec<&'static str>, role, why| Spec {
        label,
        candidates,
        role,
        why,
    };
    vec![
        s(
            "MSFE-NG",
            vec!["msfe-ng"],
            Role::Required,
            "this panel's daemon: the WHM and cPanel pages, the API",
        ),
        s(
            "MailScanner",
            crate::layout::UNIT_NAMES.to_vec(),
            Role::Required,
            "scans the mail Exim queues for it; without it scanned mail waits in the queue",
        ),
        s(
            "Exim",
            vec!["exim"],
            Role::Required,
            "receives and delivers all mail",
        ),
        s(
            "ClamAV (clamd)",
            vec!["clamd", "clamd@scan"],
            Role::Required,
            "the virus scanner MailScanner asks",
        ),
        s(
            "Database",
            vec!["mysqld", "mariadb", "mysql"],
            Role::Required,
            "the message log, quarantine index, DMARC reports",
        ),
        s(
            "Cron",
            vec!["crond", "cron"],
            Role::Required,
            "msfe-ng's scheduled jobs: rule sync, monitor, digests, DMARC fetch, auto-ban",
        ),
        s(
            "Dovecot",
            vec!["dovecot"],
            Role::Optional,
            "delivery into mailboxes (IMAP/POP)",
        ),
        s(
            "csf firewall",
            vec!["csf"],
            Role::Optional,
            "the firewall rules; bans from the IP view and auto-ban",
        ),
        s(
            "lfd",
            vec!["lfd"],
            Role::Optional,
            "csf's login-failure daemon (temporary bans expire through it)",
        ),
        s(
            "Unbound resolver",
            vec!["unbound"],
            Role::Optional,
            "the local DNS resolver blocklist lookups go through",
        ),
    ]
}

/// Parse `systemctl show -p … a b c`: one property block per unit,
/// separated by blank lines.
pub fn parse_show(text: &str) -> Vec<HashMap<String, String>> {
    let mut out = Vec::new();
    let mut cur: HashMap<String, String> = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            cur.insert(k.to_string(), v.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Ok,
    /// running, but will not start at boot
    NotAtBoot,
    /// enabled (or required) but not running
    NotRunning,
    /// required and not installed
    Missing,
    /// optional and not installed or not in use
    NotUsed,
    /// MailScanner held by its safety switch (run_mailscanner=0): stopped on purpose
    Held,
}

impl Verdict {
    pub fn key(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::NotAtBoot => "not_at_boot",
            Verdict::NotRunning => "not_running",
            Verdict::Missing => "missing",
            Verdict::NotUsed => "not_used",
            Verdict::Held => "held",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Unit {
    pub label: &'static str,
    pub why: &'static str,
    pub role: Role,
    /// the unit in use (`mailscanner.service`), None when none is installed
    pub id: Option<String>,
    pub active: String,
    pub sub: String,
    pub file_state: String,
    pub since: String,
    pub restarts: u64,
    pub description: String,
    pub verdict: Verdict,
}

impl Unit {
    pub fn running(&self) -> bool {
        matches!(self.active.as_str(), "active" | "reloading")
    }
    /// Starts at boot: enabled, or pulled in by something that is.
    pub fn at_boot(&self) -> bool {
        matches!(
            self.file_state.as_str(),
            "enabled"
                | "enabled-runtime"
                | "static"
                | "alias"
                | "indirect"
                | "generated"
                | "linked"
                | "linked-runtime"
        )
    }
    pub fn name(&self) -> String {
        self.id
            .clone()
            .unwrap_or_default()
            .trim_end_matches(".service")
            .to_string()
    }
}

/// Pick the unit in use for a spec from the parsed blocks, and judge it.
/// `held` is MailScanner's safety switch being off.
pub fn judge(spec: &Spec, blocks: &[HashMap<String, String>], held: bool) -> Unit {
    let want: Vec<String> = spec
        .candidates
        .iter()
        .map(|c| format!("{c}.service"))
        .collect();
    let block = blocks.iter().find(|b| {
        b.get("LoadState").map(String::as_str) == Some("loaded")
            && b.get("Id").is_some_and(|id| want.contains(id))
    });
    let g = |k: &str| block.and_then(|b| b.get(k)).cloned().unwrap_or_default();
    let mut u = Unit {
        label: spec.label,
        why: spec.why,
        role: spec.role,
        id: block.and_then(|b| b.get("Id").cloned()),
        active: g("ActiveState"),
        sub: g("SubState"),
        file_state: g("UnitFileState"),
        since: g("ActiveEnterTimestamp"),
        restarts: g("NRestarts").parse().unwrap_or(0),
        description: g("Description"),
        verdict: Verdict::Ok,
    };
    let is_mailscanner = spec
        .candidates
        .iter()
        .any(|c| crate::layout::UNIT_NAMES.contains(c));
    u.verdict = match (&u.id, spec.role) {
        (None, Role::Required) => Verdict::Missing,
        (None, Role::Optional) => Verdict::NotUsed,
        _ if u.file_state == "masked" => Verdict::NotRunning,
        _ if is_mailscanner && held && !u.running() => Verdict::Held,
        _ if u.running() && u.at_boot() => Verdict::Ok,
        _ if u.running() => Verdict::NotAtBoot,
        (_, Role::Optional) if !u.at_boot() => Verdict::NotUsed,
        _ => Verdict::NotRunning,
    };
    u
}

#[derive(Debug, Clone)]
pub struct Report {
    /// `systemctl is-system-running`: running, degraded, starting…
    pub system: String,
    /// every failed unit on the host: (unit, description)
    pub failed: Vec<(String, String)>,
    pub units: Vec<Unit>,
}

const PROPS: &str =
    "Id,LoadState,ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,NRestarts,Description";

fn systemctl(args: &[&str]) -> String {
    let mut c = Command::new("systemctl");
    c.args(args);
    crate::service::run_with_timeout(&mut c, Duration::from_secs(15))
        .map(|o| o.stdout)
        .unwrap_or_default()
}

/// Parse `systemctl list-units --state=failed --no-legend --plain`.
pub fn parse_failed(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            // without --plain systemctl prefixes a "●" bullet
            let mut w = l
                .split_whitespace()
                .skip_while(|t| t.chars().all(|c| !c.is_ascii()));
            let unit = w.next()?.to_string();
            let rest: Vec<&str> = w.skip(3).collect();
            Some((unit, rest.join(" ")))
        })
        .collect()
}

pub fn report(cfg: &Config) -> Report {
    let specs = specs();
    let names: Vec<String> = specs
        .iter()
        .flat_map(|s| s.candidates.iter().map(|c| format!("{c}.service")))
        .collect();
    let mut args = vec!["show", "-p", PROPS];
    args.extend(names.iter().map(String::as_str));
    let blocks = parse_show(&systemctl(&args));
    let held = crate::service::engine_run_enabled(cfg) == Some(false);
    Report {
        system: systemctl(&["is-system-running"]).trim().to_string(),
        failed: parse_failed(&systemctl(&[
            "list-units",
            "--state=failed",
            "--no-legend",
            "--plain",
            "--type=service",
        ])),
        units: specs.iter().map(|s| judge(s, &blocks, held)).collect(),
    }
}

/// The doctor's "services start at boot": `(ok, detail, enable commands)`.
/// Only units that run now but are not enabled count — a stopped one is
/// reported by its own checks (and may be stopped on purpose).
pub fn boot_verdict(units: &[Unit]) -> (bool, String, Vec<Vec<String>>) {
    let off: Vec<&Unit> = units
        .iter()
        .filter(|u| u.verdict == Verdict::NotAtBoot)
        .collect();
    if off.is_empty() {
        let n = units.iter().filter(|u| u.verdict == Verdict::Ok).count();
        return (
            true,
            format!("{n} service(s) running and enabled at boot"),
            Vec::new(),
        );
    }
    let names: Vec<String> = off.iter().map(|u| u.name()).collect();
    (
        false,
        format!(
            "running now but not enabled: {} — after a reboot {} stay{} stopped",
            names.join(", "),
            if off.len() == 1 { "it" } else { "they" },
            if off.len() == 1 { "s" } else { "" }
        ),
        off.iter()
            .filter_map(|u| u.id.clone())
            .map(|id| vec!["systemctl".to_string(), "enable".into(), id])
            .collect(),
    )
}

pub const ACTIONS: [&str; 4] = ["enable", "start", "restart", "enable-now"];

/// Check an action before running it: the unit must be one of the units in
/// use, and msfe-ng's own daemon can only be enabled.
pub fn allowed(units: &[Unit], unit: &str, action: &str) -> Result<String, String> {
    if !ACTIONS.contains(&action) {
        return Err(format!("action must be one of {}", ACTIONS.join(", ")));
    }
    let u = units
        .iter()
        .find(|u| u.id.is_some() && (u.name() == unit || u.id.as_deref() == Some(unit)))
        .ok_or_else(|| format!("{unit}: not one of the services this view manages"))?;
    if u.name() == "msfe-ng" && action != "enable" {
        return Err("msfe-ng's own daemon can only be enabled from here (restart it with systemctl restart msfe-ng)".into());
    }
    if u.verdict == Verdict::Held && action != "enable" {
        return Err("MailScanner is held by its safety switch (Service tab → Safety switch): turn that on first".into());
    }
    Ok(u.id.clone().unwrap_or_default())
}

/// Run one action; the transcript for the UI.
pub fn act(cfg: &Config, unit: &str, action: &str) -> (bool, Vec<String>) {
    let r = report(cfg);
    let id = match allowed(&r.units, unit, action) {
        Ok(id) => id,
        Err(e) => return (false, vec![e]),
    };
    let args: Vec<&str> = match action {
        "enable-now" => vec!["enable", "--now", &id],
        a => vec![a, &id],
    };
    let mut c = Command::new("systemctl");
    c.args(&args);
    let mut t = vec![format!("$ systemctl {}", args.join(" "))];
    match crate::service::run_with_timeout(&mut c, Duration::from_secs(120)) {
        Ok(o) => {
            t.extend(
                o.stdout
                    .lines()
                    .chain(o.stderr.lines())
                    .filter(|l| !l.trim().is_empty())
                    .map(str::to_string),
            );
            t.push(if o.ok {
                "→ ok".into()
            } else {
                "→ failed".into()
            });
            (o.ok, t)
        }
        Err(e) => {
            t.push(format!("→ {e}"));
            (false, t)
        }
    }
}

pub fn report_json(r: &Report) -> Json {
    Json::Object(vec![
        ("system".into(), Json::str(&r.system)),
        (
            "failed".into(),
            Json::Array(
                r.failed
                    .iter()
                    .map(|(u, d)| {
                        Json::Object(vec![
                            ("unit".into(), Json::str(u)),
                            ("description".into(), Json::str(d)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "units".into(),
            Json::Array(
                r.units
                    .iter()
                    .map(|u| {
                        Json::Object(vec![
                            ("label".into(), Json::str(u.label)),
                            ("why".into(), Json::str(u.why)),
                            ("required".into(), Json::Bool(u.role == Role::Required)),
                            (
                                "unit".into(),
                                u.id.clone().map(Json::Str).unwrap_or(Json::Null),
                            ),
                            ("name".into(), Json::str(u.name())),
                            ("active".into(), Json::str(&u.active)),
                            ("sub".into(), Json::str(&u.sub)),
                            ("running".into(), Json::Bool(u.running())),
                            ("file_state".into(), Json::str(&u.file_state)),
                            ("at_boot".into(), Json::Bool(u.at_boot())),
                            ("since".into(), Json::str(&u.since)),
                            ("restarts".into(), Json::Int(u.restarts as i64)),
                            ("verdict".into(), Json::str(u.verdict.key())),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // shaped like `systemctl show` on a cPanel host (NRestarts comes first)
    const SHOW: &str = "NRestarts=0\nId=msfe-ng.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nActiveEnterTimestamp=Wed 2026-09-30 12:53:14 CEST\n\n\
NRestarts=0\nId=mailscanner.service\nLoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=disabled\nActiveEnterTimestamp=Wed 2026-09-30 13:02:42 CEST\n\n\
NRestarts=0\nId=MailScanner.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\nActiveEnterTimestamp=\n\n\
NRestarts=2\nId=clamd.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\nActiveEnterTimestamp=\n\n\
NRestarts=0\nId=csf.service\nLoadState=loaded\nActiveState=active\nSubState=exited\nUnitFileState=enabled\nActiveEnterTimestamp=Tue 2026-09-29 08:42:48 CEST\n\n\
NRestarts=0\nId=dovecot.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nActiveEnterTimestamp=\n";

    fn spec(label: &'static str) -> Spec {
        specs().into_iter().find(|s| s.label == label).unwrap()
    }

    #[test]
    fn judges_running_boot_and_missing() {
        let b = parse_show(SHOW);
        assert_eq!(b.len(), 6);
        let ms = judge(&spec("MailScanner"), &b, false);
        assert_eq!(ms.id.as_deref(), Some("mailscanner.service"));
        assert_eq!(ms.verdict, Verdict::NotAtBoot, "running but disabled");
        assert_eq!(judge(&spec("MSFE-NG"), &b, false).verdict, Verdict::Ok);
        let clam = judge(&spec("ClamAV (clamd)"), &b, false);
        assert_eq!(
            (clam.verdict.clone(), clam.restarts),
            (Verdict::NotRunning, 2)
        );
        assert_eq!(
            judge(&spec("csf firewall"), &b, false).verdict,
            Verdict::Ok,
            "active (exited) oneshot counts"
        );
        assert_eq!(
            judge(&spec("Dovecot"), &b, false).verdict,
            Verdict::NotUsed,
            "optional, off and disabled"
        );
        assert_eq!(judge(&spec("Exim"), &b, false).verdict, Verdict::Missing);
        assert_eq!(judge(&spec("lfd"), &b, false).verdict, Verdict::NotUsed);
    }

    #[test]
    fn safety_switch_holds_mailscanner_on_purpose() {
        let stopped = SHOW.replace(
            "Id=mailscanner.service\nLoadState=loaded\nActiveState=active",
            "Id=mailscanner.service\nLoadState=loaded\nActiveState=inactive",
        );
        let b = parse_show(&stopped);
        assert_eq!(judge(&spec("MailScanner"), &b, true).verdict, Verdict::Held);
        assert_eq!(
            judge(&spec("MailScanner"), &b, false).verdict,
            Verdict::NotRunning
        );
    }

    #[test]
    fn actions_are_limited() {
        let b = parse_show(SHOW);
        let units: Vec<Unit> = specs().iter().map(|s| judge(s, &b, false)).collect();
        assert_eq!(
            allowed(&units, "mailscanner", "enable").unwrap(),
            "mailscanner.service"
        );
        assert_eq!(
            allowed(&units, "mailscanner.service", "enable-now").unwrap(),
            "mailscanner.service"
        );
        assert!(allowed(&units, "sshd", "start").is_err());
        assert!(
            allowed(&units, "exim", "start").is_err(),
            "not installed here"
        );
        assert!(allowed(&units, "mailscanner", "stop").is_err());
        assert!(allowed(&units, "msfe-ng", "restart").is_err());
        assert!(allowed(&units, "msfe-ng", "enable").is_ok());
    }

    #[test]
    fn boot_verdict_names_the_disabled_running_units() {
        let b = parse_show(SHOW);
        let units: Vec<Unit> = specs().iter().map(|s| judge(s, &b, false)).collect();
        let (ok, detail, cmds) = boot_verdict(&units);
        assert!(!ok);
        assert!(
            detail.contains("mailscanner") && detail.contains("stays stopped"),
            "{detail}"
        );
        assert_eq!(
            cmds,
            vec![vec![
                "systemctl".to_string(),
                "enable".into(),
                "mailscanner.service".into()
            ]]
        );
        let fine = parse_show(&SHOW.replace(
            "UnitFileState=disabled\nActiveEnterTimestamp=Wed",
            "UnitFileState=enabled\nActiveEnterTimestamp=Wed",
        ));
        let units: Vec<Unit> = specs().iter().map(|s| judge(s, &fine, false)).collect();
        assert!(boot_verdict(&units).0);
    }

    #[test]
    fn failed_units_list() {
        let f = parse_failed("cpgreylistd.service loaded failed failed cPanel Greylisting Daemon\n● x.service loaded failed failed X\n");
        assert_eq!(
            f[0],
            (
                "cpgreylistd.service".into(),
                "cPanel Greylisting Daemon".into()
            )
        );
        assert_eq!(f[1].0, "x.service");
    }
}
