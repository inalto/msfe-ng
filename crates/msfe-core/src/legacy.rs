//! Importer for the original MSFE flat-file config.
//!
//! Reads a legacy `/usr/msfe`-style directory and normalizes it into typed
//! structures we can persist into `msfe_config` and reuse. The file *formats*
//! are facts (safe to parse); no original code is reused. Behavior spec comes
//! from observing `msconfig.txt`, `mailscannerbw`, `spam.*.rules`,
//! `digestdomains`, and `mslang.*.txt`.

use crate::json::Json;
use std::io;
use std::path::Path;

/// A parsed MailScanner-style rule line: an optional TAB-separated match
/// expression and its value (`yes`/`no`/score/action).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub matchexpr: String,
    pub value: String,
}

/// One line of `digestdomains`: colon-separated fields.
#[derive(Debug, Clone, PartialEq)]
pub struct DigestDomain {
    pub domain: String,
    pub enabled: String,
    pub to: String,
    pub freq: String,
    pub digest_virus: String,
    pub spambox: String,
}

/// Everything we can recover from a legacy MSFE install directory.
#[derive(Debug, Clone, Default)]
pub struct LegacyImport {
    pub settings: Vec<(String, String)>,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
    pub spam_whitelist_rules: Vec<Rule>,
    pub spam_blacklist_rules: Vec<Rule>,
    pub digest_domains: Vec<DigestDomain>,
    pub lang: Vec<(String, String)>,
}

/// The original front-end's install directory.
pub const LEGACY_DIR: &str = "/usr/msfe";

/// Where the legacy front-end leaves cron entries: its own `/etc/cron.d/msfe.sh`,
/// ConfigServer's `csget` updater and the `mailscanner_daily.cron` it ships in
/// cron.daily, plus root's crontab.
const CRON_DIRS: [&str; 6] = [
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
];

/// What is left of the original ConfigServer front-end under `root` (`/` on a
/// live host): its directory, cron entries that still run it, and its WHM app
/// registration — absolute paths, deterministic order. Empty when it is gone.
pub fn remnants(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let at = |rel: &str| root.join(rel.trim_start_matches('/'));
    if at(LEGACY_DIR).is_dir() {
        found.push(LEGACY_DIR.to_string());
    }
    let mentions_legacy =
        |p: &Path| std::fs::read_to_string(p).is_ok_and(|t| mentions_legacy_dir(&t));
    for dir in CRON_DIRS.into_iter().chain(["/var/cpanel/apps"]) {
        let Ok(rd) = std::fs::read_dir(at(dir)) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .flatten()
            // csget is ConfigServer's shared updater (csf, cxs, …), not the front-end's
            .filter(|e| e.file_name() != "csget")
            .filter(|e| e.path().is_file() && mentions_legacy(&e.path()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        found.extend(names.into_iter().map(|n| format!("{dir}/{n}")));
    }
    found
}

/// The lines of a crontab that run the legacy front-end.
pub fn legacy_crontab_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| mentions_legacy_dir(l))
        .map(str::to_string)
        .collect()
}

/// The crontab without its legacy lines — `None` when there were none.
pub fn strip_legacy_crontab(text: &str) -> Option<String> {
    if !mentions_legacy_dir(text) {
        return None;
    }
    Some(
        text.lines()
            .filter(|l| !mentions_legacy_dir(l))
            .map(|l| format!("{l}\n"))
            .collect(),
    )
}

/// Remove the front-end and only the front-end: `/usr/msfe`, the cron files
/// under `/etc/cron*` that run it, the `/usr/msfe` lines of root's crontab
/// and the WHM plugin registration. `live` goes through `crontab` and
/// `unregister_appconfig`; under a fixture root the crontab file
/// (`var/spool/cron/root`) and the app file are edited directly. `csget`
/// (ConfigServer's shared updater, csf's too) and any engine are never
/// touched. Returns what was done.
pub fn remove_front_end(root: &Path, live: bool) -> io::Result<Vec<String>> {
    let mut done = Vec::new();
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let tree = at(LEGACY_DIR);
    if tree.exists() {
        std::fs::remove_dir_all(&tree)?;
        done.push(format!("removed {LEGACY_DIR}"));
    }
    for f in remnants(root)
        .into_iter()
        .filter(|f| f.starts_with("/etc/cron"))
    {
        let p = at(&f);
        if p.is_file() {
            std::fs::remove_file(&p)?;
            done.push(format!("removed {f}"));
        }
    }
    // root's crontab
    if live {
        if let Ok(out) = std::process::Command::new("crontab").arg("-l").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(kept) = strip_legacy_crontab(&text) {
                let mut c = std::process::Command::new("crontab")
                    .arg("-")
                    .stdin(std::process::Stdio::piped())
                    .spawn()?;
                if let Some(mut si) = c.stdin.take() {
                    use std::io::Write;
                    si.write_all(kept.as_bytes())?;
                }
                let _ = c.wait();
                done.push("removed the legacy entries from root's crontab".into());
            }
        }
    } else {
        let f = at("/var/spool/cron/root");
        if let Ok(text) = std::fs::read_to_string(&f) {
            if let Some(kept) = strip_legacy_crontab(&text) {
                std::fs::write(&f, kept)?;
                done.push("removed the legacy entries from root's crontab".into());
            }
        }
    }
    // the WHM plugin registration
    if let Ok(rd) = std::fs::read_dir(at("/var/cpanel/apps")) {
        for e in rd.flatten() {
            let text = std::fs::read_to_string(e.path()).unwrap_or_default();
            if !mentions_legacy_dir(&text) {
                continue;
            }
            let name = text
                .lines()
                .find_map(|l| l.strip_prefix("name="))
                .unwrap_or("msfe")
                .trim()
                .to_string();
            if live {
                let _ = std::process::Command::new("/usr/local/cpanel/bin/unregister_appconfig")
                    .arg(&name)
                    .status();
            }
            let _ = std::fs::remove_file(e.path());
            done.push(format!("unregistered the legacy WHM plugin ({name})"));
        }
    }
    Ok(done)
}

/// Where a hand-written `MailScanner.service` may sit (the RPM engine runs
/// as `mailscanner.service`, generated from its LSB `ms-init`).
const UNIT_DIRS: [&str; 2] = ["/etc/systemd/system", "/usr/lib/systemd/system"];
/// Where a stale unit is parked so it can be read later.
pub const PARKED_UNITS_DIR: &str = "/etc/msfe-ng/legacy-engine-etc";

/// `MailScanner.service` files whose `ExecStart` binary no longer exists —
/// ConfigServer's era left one pointing at `/usr/mailscanner/...`, enabled,
/// failing at every boot. `(unit path, ExecStart binary)`.
pub fn stale_engine_units(root: &Path) -> Vec<(String, String)> {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let mut found = Vec::new();
    for dir in UNIT_DIRS {
        let unit = format!("{dir}/MailScanner.service");
        let Ok(text) = std::fs::read_to_string(at(&unit)) else {
            continue;
        };
        let Some(bin) = text.lines().find_map(|l| {
            l.trim()
                .strip_prefix("ExecStart=")
                .and_then(|v| v.split_whitespace().next())
                .map(|b| b.trim_start_matches(['-', '@', '+', '!', ':']).to_string())
        }) else {
            continue;
        };
        if !at(&bin).exists() {
            found.push((unit, bin));
        }
    }
    found
}

/// Disable and park every stale `MailScanner.service` (`live`: through
/// systemctl, then `daemon-reload`). Returns what was done.
pub fn remove_stale_engine_units(root: &Path, live: bool) -> io::Result<Vec<String>> {
    let at = |p: &str| root.join(p.trim_start_matches('/'));
    let mut done = Vec::new();
    let stale = stale_engine_units(root);
    if stale.is_empty() {
        return Ok(done);
    }
    if live {
        let _ = std::process::Command::new("systemctl")
            .args(["disable", "--now", "MailScanner.service"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let park = at(PARKED_UNITS_DIR);
    std::fs::create_dir_all(&park)?;
    for (unit, bin) in stale {
        let src = at(&unit);
        let name = format!(
            "{}.{}",
            Path::new(&unit)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "MailScanner.service".into()),
            unit.trim_start_matches('/').replace('/', "_")
        );
        let dst = park.join(&name);
        std::fs::rename(&src, &dst)
            .or_else(|_| std::fs::copy(&src, &dst).and_then(|_| std::fs::remove_file(&src)))?;
        done.push(format!(
            "disabled and parked {unit} (ExecStart {bin} is gone) as {}",
            dst.display()
        ));
    }
    if live {
        let _ = std::process::Command::new("systemctl")
            .arg("daemon-reload")
            .status();
    }
    Ok(done)
}

/// Does `text` refer to `/usr/msfe` itself — not `/usr/msfe-ng` or any other
/// path that merely starts with it?
pub fn mentions_legacy_dir(text: &str) -> bool {
    text.match_indices(LEGACY_DIR).any(|(i, m)| {
        !text[i + m.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '-' || c == '_')
    })
}

/// Parse `key=value` lines (msconfig.txt / mslang.*.txt). Splits on the FIRST
/// `=` so values may contain `=`. Skips blanks and `#` comments. Order-preserving.
pub fn parse_keyval(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r']);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let val = line[eq + 1..].to_string();
            if !key.is_empty() {
                out.push((key, val));
            }
        }
    }
    out
}

/// Parse `mailscannerbw`: line 1 = whitelist, line 2 = blacklist, each a
/// comma-separated list of address/domain patterns. Trims, drops empties, and
/// de-duplicates (an improvement over the original, which kept duplicates).
pub fn parse_bw(text: &str) -> (Vec<String>, Vec<String>) {
    let mut lines = text.lines();
    let wl = split_csv_dedup(lines.next().unwrap_or(""));
    let bl = split_csv_dedup(lines.next().unwrap_or(""));
    (wl, bl)
}

fn split_csv_dedup(line: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for part in line.split(',') {
        let p = part.trim();
        if !p.is_empty() && seen.insert(p.to_string()) {
            out.push(p.to_string());
        }
    }
    out
}

/// Parse MailScanner rule files (`spam.whitelist.rules`, etc). Each non-empty
/// line is `<match expression>\t<value>`; if there's no TAB the whole line is
/// treated as the match expression with an empty value.
pub fn parse_rules(text: &str) -> Vec<Rule> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end_matches(['\r']);
        if line.trim().is_empty() {
            continue;
        }
        let (matchexpr, value) = match line.split_once('\t') {
            Some((m, v)) => (m.trim().to_string(), v.trim().to_string()),
            None => (line.trim().to_string(), String::new()),
        };
        out.push(Rule { matchexpr, value });
    }
    out
}

/// Parse `digestdomains`: `domain:on:to:freq:dvirus:spambox` per line.
pub fn parse_digestdomains(text: &str) -> Vec<DigestDomain> {
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        let get = |i: usize| f.get(i).unwrap_or(&"").to_string();
        out.push(DigestDomain {
            domain: get(0),
            enabled: get(1),
            to: get(2),
            freq: get(3),
            digest_virus: get(4),
            spambox: get(5),
        });
    }
    out
}

/// Read a legacy MSFE directory. Missing individual files yield empty sections;
/// a missing directory is an error.
pub fn import_legacy(dir: &Path) -> io::Result<LegacyImport> {
    if !dir.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("legacy directory not found: {}", dir.display()),
        ));
    }
    let read =
        |name: &str| -> String { std::fs::read_to_string(dir.join(name)).unwrap_or_default() };

    let (whitelist, blacklist) = parse_bw(&read("mailscannerbw"));
    let lang = {
        // Prefer the English catalog, fall back to mslang.txt.
        let en = read("mslang.en.txt");
        let text = if en.is_empty() {
            read("mslang.txt")
        } else {
            en
        };
        parse_keyval(&text)
    };

    Ok(LegacyImport {
        settings: parse_keyval(&read("msconfig.txt")),
        whitelist,
        blacklist,
        spam_whitelist_rules: parse_rules(&read("spam.whitelist.rules")),
        spam_blacklist_rules: parse_rules(&read("spam.blacklist.rules")),
        digest_domains: parse_digestdomains(&read("digestdomains")),
        lang,
    })
}

impl LegacyImport {
    /// Serialize to JSON for the CLI/daemon.
    pub fn to_json(&self) -> Json {
        let kv = |pairs: &[(String, String)]| {
            Json::Object(
                pairs
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::str(v)))
                    .collect(),
            )
        };
        let strs = |v: &[String]| Json::Array(v.iter().map(Json::str).collect());
        let rules = |v: &[Rule]| {
            Json::Array(
                v.iter()
                    .map(|r| {
                        Json::Object(vec![
                            ("match".into(), Json::str(&r.matchexpr)),
                            ("value".into(), Json::str(&r.value)),
                        ])
                    })
                    .collect(),
            )
        };
        let digests = Json::Array(
            self.digest_domains
                .iter()
                .map(|d| {
                    Json::Object(vec![
                        ("domain".into(), Json::str(&d.domain)),
                        ("enabled".into(), Json::str(&d.enabled)),
                        ("to".into(), Json::str(&d.to)),
                        ("freq".into(), Json::str(&d.freq)),
                        ("digest_virus".into(), Json::str(&d.digest_virus)),
                        ("spambox".into(), Json::str(&d.spambox)),
                    ])
                })
                .collect(),
        );

        Json::Object(vec![
            ("settings".into(), kv(&self.settings)),
            ("whitelist".into(), strs(&self.whitelist)),
            ("blacklist".into(), strs(&self.blacklist)),
            (
                "spam_whitelist_rules".into(),
                rules(&self.spam_whitelist_rules),
            ),
            (
                "spam_blacklist_rules".into(),
                rules(&self.spam_blacklist_rules),
            ),
            ("digest_domains".into(), digests),
            ("lang".into(), kv(&self.lang)),
            (
                "summary".into(),
                Json::Object(vec![
                    ("settings".into(), Json::Int(self.settings.len() as i64)),
                    ("whitelist".into(), Json::Int(self.whitelist.len() as i64)),
                    ("blacklist".into(), Json::Int(self.blacklist.len() as i64)),
                    (
                        "digest_domains".into(),
                        Json::Int(self.digest_domains.len() as i64),
                    ),
                ]),
            ),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // a migrated host: a 2020 hand-written MailScanner.service pointing at the removed
    // ConfigServer tree, enabled, failing at every boot next to the RPM's
    // mailscanner.service.
    #[test]
    fn stale_engine_units_are_the_ones_whose_binary_is_gone() {
        let root = std::env::temp_dir().join(format!("msfe-units-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        std::fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        std::fs::write(
            root.join("usr/lib/systemd/system/MailScanner.service"),
            "[Unit]\nDescription=MailScanner AntiSpam and AntiVirus\n[Service]\nExecStart=/usr/mailscanner/usr/sbin/MailScanner\nType=forking\n",
        )
        .unwrap();
        // a unit whose binary exists is somebody's live unit: not stale
        std::fs::write(root.join("usr/sbin/MailScanner"), "").unwrap();
        std::fs::write(
            root.join("etc/systemd/system/MailScanner.service"),
            "[Service]\nExecStart=-/usr/sbin/MailScanner --foreground\n",
        )
        .unwrap();
        assert_eq!(
            stale_engine_units(&root),
            vec![(
                "/usr/lib/systemd/system/MailScanner.service".to_string(),
                "/usr/mailscanner/usr/sbin/MailScanner".to_string()
            )]
        );
        let done = remove_stale_engine_units(&root, false).unwrap();
        assert_eq!(done.len(), 1, "{done:?}");
        assert!(!root
            .join("usr/lib/systemd/system/MailScanner.service")
            .exists());
        assert!(root
            .join("etc/msfe-ng/legacy-engine-etc/MailScanner.service.usr_lib_systemd_system_MailScanner.service")
            .exists(), "parked, not deleted");
        assert!(
            root.join("etc/systemd/system/MailScanner.service").exists(),
            "live unit kept"
        );
        assert!(stale_engine_units(&root).is_empty());
        assert!(
            remove_stale_engine_units(&root, false).unwrap().is_empty(),
            "idempotent"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn mentions_legacy_dir_ignores_our_own_paths() {
        assert!(mentions_legacy_dir("0 * * * * root /usr/msfe/msbe.pl"));
        assert!(mentions_legacy_dir("target=/usr/msfe\n"));
        assert!(!mentions_legacy_dir("PATH=/usr/msfe-ng/bin"));
        assert!(!mentions_legacy_dir("/usr/msfe_ng/x"));
    }

    #[test]
    fn remnants_lists_the_legacy_front_ends_footprint() {
        let root = std::env::temp_dir().join(format!("msfe-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/cron.d")).unwrap();
        assert!(remnants(&root).is_empty(), "clean host");

        std::fs::create_dir_all(root.join("usr/msfe")).unwrap();
        std::fs::create_dir_all(root.join("var/spool/cron")).unwrap();
        std::fs::create_dir_all(root.join("etc/cron.daily")).unwrap();
        std::fs::write(
            root.join("etc/cron.daily/csget"),
            "#!/bin/sh\n/usr/msfe/csget.pl\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.daily/mailscanner_daily.cron"),
            "/usr/msfe/ms_daily\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.daily/logrotate"),
            "/usr/sbin/logrotate\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join("var/cpanel/apps")).unwrap();
        std::fs::write(
            root.join("etc/cron.d/msfe"),
            "0 * * * * root /usr/msfe/msbe.pl\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/cron.d/other"), "0 * * * * root /bin/true\n").unwrap();
        std::fs::write(
            root.join("var/spool/cron/root"),
            "5 * * * * /usr/msfe/msfe.cron\n",
        )
        .unwrap();
        std::fs::write(
            root.join("var/cpanel/apps/msfe.conf"),
            "url=/cgi/msfe/index.cgi\ntarget=/usr/msfe\n",
        )
        .unwrap();
        std::fs::write(
            root.join("var/cpanel/apps/msfe_ng.conf"),
            "url=/cgi/msfe_ng/\n",
        )
        .unwrap();
        std::fs::write(
            root.join("etc/cron.d/msfe-ng"),
            "*/10 * * * * root /usr/msfe-ng/bin/x\n",
        )
        .unwrap();
        let found = remnants(&root);
        assert_eq!(
            found,
            vec![
                "/usr/msfe".to_string(),
                "/etc/cron.d/msfe".to_string(),
                "/etc/cron.daily/mailscanner_daily.cron".to_string(),
                "/var/spool/cron/root".to_string(),
                "/var/cpanel/apps/msfe.conf".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn keyval_splits_on_first_equals() {
        let kv = parse_keyval("highscore=20\nmc_forwmail=a=b=c\n\n# comment\nlowscore=5\n");
        assert_eq!(kv.len(), 3);
        assert_eq!(kv[0], ("highscore".into(), "20".into()));
        assert_eq!(kv[1], ("mc_forwmail".into(), "a=b=c".into()));
        assert_eq!(kv[2], ("lowscore".into(), "5".into()));
    }

    #[test]
    fn bw_two_lines_dedup() {
        // synthetic — never the real customer list
        let (wl, bl) = parse_bw("*@a.example, foo@b.example, *@a.example\n*.ru,*@spam.example\n");
        assert_eq!(wl, vec!["*@a.example", "foo@b.example"]); // duplicate dropped
        assert_eq!(bl, vec!["*.ru", "*@spam.example"]);
    }

    #[test]
    fn rules_tab_separated() {
        let r = parse_rules("To: *@* and From: foo@a.example\tyes\nFromOrTo: default\tno\n");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].matchexpr, "To: *@* and From: foo@a.example");
        assert_eq!(r[0].value, "yes");
        assert_eq!(r[1].value, "no");
    }

    #[test]
    fn digestdomains_colons() {
        let d = parse_digestdomains("a.example:yes::24:no:yes\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].domain, "a.example");
        assert_eq!(d[0].enabled, "yes");
        assert_eq!(d[0].to, "");
        assert_eq!(d[0].freq, "24");
        assert_eq!(d[0].spambox, "yes");
    }

    #[test]
    fn missing_dir_errors() {
        assert!(import_legacy(Path::new("/nonexistent/msfe-xyz")).is_err());
    }

    #[test]
    fn json_roundtrip_is_valid_ish() {
        let mut imp = LegacyImport::default();
        imp.settings.push(("k".into(), "v\"q".into()));
        imp.whitelist.push("*@a.example".into());
        let s = imp.to_json().to_string();
        assert!(s.contains("\"settings\""));
        assert!(s.contains("\\\"q")); // escaped quote
        assert!(s.contains("\"summary\""));
    }
}
