//! MailScanner rule-file generation.
//!
//! MSFE-NG owns a fixed set of MailScanner ruleset files and regenerates them
//! deterministically from the policy (global settings + local domains + the
//! system white/black lists). Regenerating (rather than in-place splicing like
//! the original `msrules.pl`) keeps the files drift-free and idempotent.
//!
//! Clean-room: the file names, the `<direction>\t*@domain\t<value>` line format,
//! the action tokens, and the `store`/`[domain]` handling are behavioral facts
//! observed from `msrules.pl` / `msconfig.txt`; no original code is reused.
//!
//! Rule line format (TAB-separated): `<direction>\t<match>\t<value>` where
//! direction ∈ {To:, From:, FromOrTo:, FromAndTo:}.

use std::collections::BTreeMap;

/// Resolved policy driving rule generation. Built from the flat `msconfig`-style
/// settings via [`RuleSettings::from_settings`].
#[derive(Debug, Clone)]
pub struct RuleSettings {
    pub spam_scan_dir: String,
    pub spam_scan_def: String,
    pub virus_scan_dir: String,
    pub virus_scan_def: String,
    pub spam_action_dir: String,
    pub spam_action_def: String, // resolved MailScanner action (may contain [domain])
    pub spamhigh_action_dir: String,
    pub spamhigh_action_def: String,
    pub virus_delivery_dir: String,
    pub virus_delivery_def: String,
    pub lowscore: String,
    pub highscore: String,
    pub store: bool,
}

impl Default for RuleSettings {
    fn default() -> Self {
        RuleSettings {
            spam_scan_dir: "To:".into(),
            spam_scan_def: "yes".into(),
            virus_scan_dir: "To:".into(),
            virus_scan_def: "yes".into(),
            spam_action_dir: "To:".into(),
            spam_action_def: "deliver".into(),
            spamhigh_action_dir: "To:".into(),
            spamhigh_action_def: "deliver".into(),
            virus_delivery_dir: "FromOrTo:".into(),
            virus_delivery_def: "no".into(),
            lowscore: "5".into(),
            highscore: "20".into(),
            store: false,
        }
    }
}

/// A generated rule file: its MailScanner basename and full contents.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleFile {
    pub name: String,
    pub contents: String,
}

/// The seven domain-policy rule files MSFE-NG manages (order stable for tests).
pub const DOMAIN_RULE_FILES: [&str; 7] = [
    "spam.scanning.rules",
    "virus.scanning.rules",
    "spam.action.rules",
    "spamhigh.action.rules",
    "virus.delivery.rules",
    "spam.score.rules",
    "spamhigh.score.rules",
];
/// The two list rule files (generated from the system white/black lists).
pub const LIST_RULE_FILES: [&str; 2] = ["spam.whitelist.rules", "spam.blacklist.rules"];

/// Every rule file MSFE-NG manages — used by `sync` to prune stale ones.
pub fn managed_files() -> Vec<String> {
    DOMAIN_RULE_FILES
        .iter()
        .chain(LIST_RULE_FILES.iter())
        .map(|s| s.to_string())
        .collect()
}

impl RuleSettings {
    /// Build from flat `msconfig.txt`-style key/values, resolving action tokens
    /// (`def_lspam`/`def_hspam` name a token whose MailScanner action string
    /// lives in `spam_action_<token>` / `spamhigh_action_<token>`), and applying
    /// the `store` prefix like the original did.
    pub fn from_settings(pairs: &[(String, String)]) -> RuleSettings {
        let m = |k: &str| pairs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        let or = |k: &str, d: &str| m(k).filter(|s| !s.is_empty()).unwrap_or_else(|| d.into());

        let store = or("store", "no") == "yes";
        let resolve = |prefix: &str, token: &str| -> String {
            // e.g. token "spambox" → key "spamhigh_action_spambox"
            let key = format!("{prefix}_{token}");
            m(&key)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| token.into())
        };
        let with_store = |action: String| -> String {
            if store && !action.contains("store") {
                format!("store {action}")
            } else {
                action
            }
        };

        let low_token = or("def_lspam", "deliver");
        let high_token = or("def_hspam", "deliver");

        RuleSettings {
            spam_scan_dir: or("spam_scanning_rules_ini", "To:"),
            spam_scan_def: or("def_spam", "yes"),
            virus_scan_dir: or("virus_scanning_rules_ini", "To:"),
            virus_scan_def: or("def_virus", "yes"),
            spam_action_dir: or("spam_action_rules_ini", "To:"),
            spam_action_def: with_store(resolve("spam_action", &low_token)),
            spamhigh_action_dir: or("spamhigh_action_rules_ini", "To:"),
            spamhigh_action_def: with_store(resolve("spamhigh_action", &high_token)),
            virus_delivery_dir: or("virus_delivery_rules_ini", "FromOrTo:"),
            virus_delivery_def: or("def_dvirus", "no"),
            lowscore: or("lowscore", "5"),
            highscore: or("highscore", "20"),
            store,
        }
    }
}

/// Resolve a spam-action token (`deliver`/`delete`/`spambox`/`forward`) into its
/// MailScanner action string using the settings map, applying the `store` prefix.
/// `prefix` is `spam_action` or `spamhigh_action`. Shared by global settings and
/// per-domain overrides so both resolve tokens identically.
pub fn resolve_action(settings: &[(String, String)], prefix: &str, token: &str) -> String {
    let m = |k: &str| {
        settings
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.clone())
    };
    let store = m("store").as_deref() == Some("yes");
    let action = m(&format!("{prefix}_{token}"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| token.to_string());
    if store && !action.contains("store") {
        format!("store {action}")
    } else {
        action
    }
}

/// Per-domain policy overrides (set by the end-user UI). Any `None`/empty field
/// falls back to the global default; resolved MailScanner action strings are
/// stored (the daemon resolves action tokens at save time).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DomainPolicy {
    pub spam_scan: Option<String>,
    pub virus_scan: Option<String>,
    pub spam_action: Option<String>,
    pub spamhigh_action: Option<String>,
    pub virus_delivery: Option<String>,
    pub lowscore: Option<String>,
    pub highscore: Option<String>,
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

/// A domain that is safe to emit a rule for.
fn valid_domain(d: &str) -> bool {
    !d.is_empty() && !d.starts_with('#') && !d.ends_with(".zz")
}

/// Generate all managed rule files from global settings, the local domains, the
/// system lists, and per-domain overrides.
pub fn generate(
    s: &RuleSettings,
    domains: &[String],
    whitelist: &[String],
    blacklist: &[String],
    overrides: &BTreeMap<String, DomainPolicy>,
) -> Vec<RuleFile> {
    // Catch-all defaults for virus scanning and the action files are deliberately
    // safe ("yes"/"deliver") so unknown domains are never dropped.
    vec![
        domain_file(
            "spam.scanning.rules",
            &s.spam_scan_dir,
            &s.spam_scan_def,
            domains,
            &s.spam_scan_def,
            overrides,
            |p| p.spam_scan.as_deref(),
        ),
        domain_file(
            "virus.scanning.rules",
            &s.virus_scan_dir,
            &s.virus_scan_def,
            domains,
            "yes",
            overrides,
            |p| p.virus_scan.as_deref(),
        ),
        domain_file(
            "spam.action.rules",
            &s.spam_action_dir,
            &s.spam_action_def,
            domains,
            "deliver",
            overrides,
            |p| p.spam_action.as_deref(),
        ),
        domain_file(
            "spamhigh.action.rules",
            &s.spamhigh_action_dir,
            &s.spamhigh_action_def,
            domains,
            "deliver",
            overrides,
            |p| p.spamhigh_action.as_deref(),
        ),
        domain_file(
            "virus.delivery.rules",
            &s.virus_delivery_dir,
            &s.virus_delivery_def,
            domains,
            &s.virus_delivery_def,
            overrides,
            |p| p.virus_delivery.as_deref(),
        ),
        domain_file(
            "spam.score.rules",
            "FromOrTo:",
            &s.lowscore,
            domains,
            &s.lowscore,
            overrides,
            |p| p.lowscore.as_deref(),
        ),
        domain_file(
            "spamhigh.score.rules",
            "FromOrTo:",
            &s.highscore,
            domains,
            &s.highscore,
            overrides,
            |p| p.highscore.as_deref(),
        ),
        list_file("spam.whitelist.rules", whitelist, domains, overrides, |p| {
            &p.whitelist
        }),
        list_file("spam.blacklist.rules", blacklist, domains, overrides, |p| {
            &p.blacklist
        }),
    ]
}

const HEADER: &str =
    "# Managed by MSFE-NG — do not edit by hand; changes are overwritten by `msfe-ng sync`.\n";
const CUSTOM_HEADER: &str = "# Custom rules (managed via the WHM Rules tab):\n";

/// Splice admin-defined custom rules into the generated files, right after the
/// header — ahead of the domain lines, since MailScanner rulesets are
/// first-match-wins, so custom rules take precedence and survive regeneration.
pub fn merge_custom(
    files: &mut [RuleFile],
    customs: &std::collections::BTreeMap<String, Vec<crate::rulefile::Rule>>,
) {
    for f in files {
        let Some(rules) = customs.get(&f.name).filter(|r| !r.is_empty()) else {
            continue;
        };
        let block: String = String::from(CUSTOM_HEADER)
            + &rules.iter().map(|r| r.to_line() + "\n").collect::<String>();
        if let Some(rest) = f.contents.strip_prefix(HEADER) {
            f.contents = format!("{HEADER}{block}{rest}");
        } else {
            f.contents = format!("{block}{}", f.contents);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn domain_file(
    name: &str,
    dir: &str,
    global_value: &str,
    domains: &[String],
    default: &str,
    overrides: &BTreeMap<String, DomainPolicy>,
    pick: impl Fn(&DomainPolicy) -> Option<&str>,
) -> RuleFile {
    let mut c = String::from(HEADER);
    for d in domains {
        let d = d.trim();
        if !valid_domain(d) {
            continue;
        }
        let v = overrides
            .get(d)
            .and_then(&pick)
            .unwrap_or(global_value)
            .replace("[domain]", d);
        c.push_str(&format!("{dir}\t*@{d}\t{v}\n"));
    }
    c.push_str(&format!("FromOrTo:\tdefault\t{default}\n"));
    RuleFile {
        name: name.into(),
        contents: c,
    }
}

fn list_file(
    name: &str,
    patterns: &[String],
    domains: &[String],
    overrides: &BTreeMap<String, DomainPolicy>,
    pick: impl Fn(&DomainPolicy) -> &Vec<String>,
) -> RuleFile {
    let mut c = String::from(HEADER);
    // System-wide list: matches any recipient.
    for p in patterns {
        let p = p.trim();
        if !p.is_empty() {
            c.push_str(&format!("To: *@* and From: {p}\tyes\n"));
        }
    }
    // Per-domain lists: scoped to recipients at that domain.
    for d in domains {
        let d = d.trim();
        if !valid_domain(d) {
            continue;
        }
        if let Some(pol) = overrides.get(d) {
            for p in pick(pol) {
                let p = p.trim();
                if !p.is_empty() {
                    c.push_str(&format!("To: *@{d} and From: {p}\tyes\n"));
                }
            }
        }
    }
    RuleFile {
        name: name.into(),
        contents: c,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Vec<(String, String)> {
        vec![
            ("def_spam".into(), "yes".into()),
            ("def_hspam".into(), "spambox".into()),
            (
                "spamhigh_action_spambox".into(),
                "deliver header \"X-MailScanner-SpamBox: yes\"".into(),
            ),
            ("def_lspam".into(), "deliver".into()),
            ("spam_action_deliver".into(), "deliver".into()),
            ("store".into(), "yes".into()),
            ("lowscore".into(), "5".into()),
            ("highscore".into(), "20".into()),
        ]
    }

    #[test]
    fn resolves_action_tokens_and_store_prefix() {
        let s = RuleSettings::from_settings(&settings());
        // def_hspam=spambox → resolved action, with store prefix
        assert_eq!(
            s.spamhigh_action_def,
            "store deliver header \"X-MailScanner-SpamBox: yes\""
        );
        assert_eq!(s.spam_action_def, "store deliver");
    }

    #[test]
    fn generates_expected_domain_lines() {
        let s = RuleSettings::default();
        let files = generate(
            &s,
            &["a.example".into(), "b.example".into()],
            &[],
            &[],
            &BTreeMap::new(),
        );
        let scan = files
            .iter()
            .find(|f| f.name == "spam.scanning.rules")
            .unwrap();
        assert!(scan.contents.contains("To:\t*@a.example\tyes\n"));
        assert!(scan.contents.contains("To:\t*@b.example\tyes\n"));
        assert!(scan.contents.contains("FromOrTo:\tdefault\tyes\n"));
        assert!(scan.contents.starts_with("# Managed by MSFE-NG"));
    }

    #[test]
    fn substitutes_domain_placeholder() {
        let pairs = vec![
            ("def_lspam".to_string(), "forward".to_string()),
            (
                "spam_action_forward".to_string(),
                "forward spam@[domain] delete".to_string(),
            ),
        ];
        let s = RuleSettings::from_settings(&pairs);
        let files = generate(&s, &["x.example".into()], &[], &[], &BTreeMap::new());
        let act = files
            .iter()
            .find(|f| f.name == "spam.action.rules")
            .unwrap();
        assert!(act
            .contents
            .contains("To:\t*@x.example\tforward spam@x.example delete\n"));
    }

    #[test]
    fn skips_bad_domains() {
        let s = RuleSettings::default();
        let files = generate(
            &s,
            &["#comment".into(), "host.zz".into(), "ok.example".into()],
            &[],
            &[],
            &BTreeMap::new(),
        );
        let scan = &files[0];
        assert!(!scan.contents.contains("#comment"));
        assert!(!scan.contents.contains("host.zz"));
        assert!(scan.contents.contains("*@ok.example"));
    }

    #[test]
    fn list_rules_format() {
        let files = generate(
            &RuleSettings::default(),
            &[],
            &["*@good.example".into()],
            &["*@bad.example".into()],
            &BTreeMap::new(),
        );
        let wl = files
            .iter()
            .find(|f| f.name == "spam.whitelist.rules")
            .unwrap();
        let bl = files
            .iter()
            .find(|f| f.name == "spam.blacklist.rules")
            .unwrap();
        assert!(wl
            .contents
            .contains("To: *@* and From: *@good.example\tyes\n"));
        assert!(bl
            .contents
            .contains("To: *@* and From: *@bad.example\tyes\n"));
    }

    #[test]
    fn managed_files_count() {
        assert_eq!(managed_files().len(), 9);
    }

    #[test]
    fn per_domain_override() {
        let s = RuleSettings::default(); // global spam scan = yes
        let mut ov = BTreeMap::new();
        ov.insert(
            "opt-out.example".to_string(),
            DomainPolicy {
                spam_scan: Some("no".into()),
                whitelist: vec!["*@vip.example".into()],
                ..Default::default()
            },
        );
        let files = generate(
            &s,
            &["normal.example".into(), "opt-out.example".into()],
            &[],
            &[],
            &ov,
        );
        let scan = files
            .iter()
            .find(|f| f.name == "spam.scanning.rules")
            .unwrap();
        assert!(scan.contents.contains("To:\t*@normal.example\tyes\n")); // global
        assert!(scan.contents.contains("To:\t*@opt-out.example\tno\n")); // override
        let wl = files
            .iter()
            .find(|f| f.name == "spam.whitelist.rules")
            .unwrap();
        assert!(wl
            .contents
            .contains("To: *@opt-out.example and From: *@vip.example\tyes\n"));
    }
}
