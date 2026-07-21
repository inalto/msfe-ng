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
