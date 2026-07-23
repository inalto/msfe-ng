//! Policy → MailScanner rules orchestration, shared by the CLI (`msfe-ng sync`)
//! and the daemon (PUT /api/policy). Reads the active policy files, gathers the
//! local domains, generates the rule files and writes them atomically.

use crate::config::Config;
use crate::legacy;
use crate::panel::detect_panel;
use crate::rules::{self, DomainPolicy};
use msfe_api::PanelKind;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// Directory holding the active policy (normalized legacy files), derived from
/// the config file location: `<confdir>/policy`.
pub fn policy_dir(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .join("policy")
}

/// Load the active policy: (settings, whitelist, blacklist). Missing files → empty.
pub fn load_policy(dir: &Path) -> (Vec<(String, String)>, Vec<String>, Vec<String>) {
    let settings = legacy::parse_keyval(
        &std::fs::read_to_string(dir.join("msconfig.txt")).unwrap_or_default(),
    );
    let (wl, bl) =
        legacy::parse_bw(&std::fs::read_to_string(dir.join("mailscannerbw")).unwrap_or_default());
    (settings, wl, bl)
}

/// Persist policy for `sync` to consume (normalized `msconfig.txt` + `mailscannerbw`).
pub fn save_policy(
    dir: &Path,
    settings: &[(String, String)],
    whitelist: &[String],
    blacklist: &[String],
) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let mut msconfig = String::new();
    for (k, v) in settings {
        msconfig.push_str(&format!("{k}={v}\n"));
    }
    atomic_write(&dir.join("msconfig.txt"), msconfig.as_bytes())?;
    let bw = format!("{}\n{}\n", whitelist.join(","), blacklist.join(","));
    atomic_write(&dir.join("mailscannerbw"), bw.as_bytes())
}

/// Directory holding per-domain override files (`<domain>.txt`).
pub fn domains_dir(policy_dir: &Path) -> PathBuf {
    policy_dir.join("domains")
}

/// Parse a per-domain override file body into a [`DomainPolicy`].
pub fn parse_domain_policy(text: &str) -> DomainPolicy {
    let kv = legacy::parse_keyval(text);
    let get = |k: &str| kv.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
    let some = |k: &str| get(k).filter(|s| !s.is_empty());
    let list = |k: &str| {
        get(k)
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
    };
    DomainPolicy {
        spam_scan: some("spam_scan"),
        virus_scan: some("virus_scan"),
        spam_action: some("spam_action"),
        spamhigh_action: some("spamhigh_action"),
        virus_delivery: some("virus_delivery"),
        lowscore: some("lowscore"),
        highscore: some("highscore"),
        whitelist: list("whitelist"),
        blacklist: list("blacklist"),
    }
}

/// Serialize a [`DomainPolicy`] back to the `<domain>.txt` body.
pub fn domain_policy_text(p: &DomainPolicy) -> String {
    let mut s = String::new();
    let mut put = |k: &str, v: &Option<String>| {
        if let Some(val) = v {
            s.push_str(&format!("{k}={val}\n"));
        }
    };
    put("spam_scan", &p.spam_scan);
    put("virus_scan", &p.virus_scan);
    put("spam_action", &p.spam_action);
    put("spamhigh_action", &p.spamhigh_action);
    put("virus_delivery", &p.virus_delivery);
    put("lowscore", &p.lowscore);
    put("highscore", &p.highscore);
    if !p.whitelist.is_empty() {
        s.push_str(&format!("whitelist={}\n", p.whitelist.join(",")));
    }
    if !p.blacklist.is_empty() {
        s.push_str(&format!("blacklist={}\n", p.blacklist.join(",")));
    }
    s
}

/// Load all per-domain overrides from `<policy>/domains/*.txt`.
pub fn load_overrides(policy_dir: &Path) -> BTreeMap<String, DomainPolicy> {
    let mut out = BTreeMap::new();
    let dir = domains_dir(policy_dir);
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("txt") {
                continue;
            }
            if let Some(domain) = path.file_stem().and_then(|x| x.to_str()) {
                let body = std::fs::read_to_string(&path).unwrap_or_default();
                out.insert(domain.to_string(), parse_domain_policy(&body));
            }
        }
    }
    out
}

/// Read one domain's override (empty default if absent).
pub fn load_override(policy_dir: &Path, domain: &str) -> DomainPolicy {
    let path = domains_dir(policy_dir).join(format!("{domain}.txt"));
    parse_domain_policy(&std::fs::read_to_string(path).unwrap_or_default())
}

/// Write one domain's override (removing the file when the policy is empty).
pub fn save_override(policy_dir: &Path, domain: &str, policy: &DomainPolicy) -> io::Result<()> {
    let dir = domains_dir(policy_dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{domain}.txt"));
    let body = domain_policy_text(policy);
    if body.is_empty() {
        let _ = std::fs::remove_file(&path);
        Ok(())
    } else {
        atomic_write(&path, body.as_bytes())
    }
}

/// Local domains to generate rules for. `override_file` (or `MSFE_NG_DOMAINS_FILE`)
/// wins for testing; otherwise the panel's local-domains file (+ secondarymx on cPanel).
pub fn gather_domains(override_file: Option<&str>) -> Vec<String> {
    let env_override = std::env::var("MSFE_NG_DOMAINS_FILE").ok();
    if let Some(f) = override_file.map(str::to_string).or(env_override) {
        return read_domains(Path::new(&f));
    }
    let panel = detect_panel();
    let mut d = read_domains(Path::new(panel.local_domains_path()));
    if panel.kind() == PanelKind::Cpanel {
        d.extend(read_domains(Path::new("/etc/secondarymx")));
    }
    let mut seen = std::collections::HashSet::new();
    d.retain(|x| seen.insert(x.clone()));
    d
}

pub fn read_domains(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Write `data` to `path` atomically (temp file + rename in the same dir).
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp.msfe-ng");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Generate + write all rule files from the current policy. Returns (files, domains).
pub fn run(cfg: &Config, policy_path: &Path, override_domains: Option<&str>) -> io::Result<usize> {
    let dir = policy_dir(policy_path);
    let (settings, wl, bl) = load_policy(&dir);
    let mut overrides = load_overrides(&dir);
    // Per-domain action fields are stored as tokens; resolve them like the global
    // defaults so the generated rules carry real MailScanner action strings.
    for pol in overrides.values_mut() {
        if let Some(t) = pol.spam_action.take() {
            pol.spam_action = Some(rules::resolve_action(&settings, "spam_action", &t));
        }
        if let Some(t) = pol.spamhigh_action.take() {
            pol.spamhigh_action = Some(rules::resolve_action(&settings, "spamhigh_action", &t));
        }
    }
    let domains = gather_domains(override_domains);
    let rs = rules::RuleSettings::from_settings(&settings);
    let mut files = rules::generate(&rs, &domains, &wl, &bl, &overrides);
    rules::merge_custom(
        &mut files,
        &crate::rulefile::load_all_custom(&dir, &rules::managed_files()),
    );

    let rules_dir = Path::new(&cfg.mailscanner_rules_dir);
    std::fs::create_dir_all(rules_dir)?;
    for f in &files {
        atomic_write(&rules_dir.join(&f.name), f.contents.as_bytes())?;
    }
    Ok(files.len())
}

/// Canonical rule lines a managed file is expected to contain, regenerated from
/// the current policy with custom rules merged. Baseline for stray detection.
pub fn expected_rule_lines(config_file: &Path, name: &str) -> Vec<String> {
    let dir = policy_dir(config_file);
    let (settings, wl, bl) = load_policy(&dir);
    let overrides = load_overrides(&dir);
    let rs = rules::RuleSettings::from_settings(&settings);
    let domains = gather_domains(None);
    let mut files = rules::generate(&rs, &domains, &wl, &bl, &overrides);
    rules::merge_custom(
        &mut files,
        &crate::rulefile::load_all_custom(&dir, &rules::managed_files()),
    );
    files
        .iter()
        .find(|f| f.name == name)
        .map(|f| {
            crate::rulefile::rules_of(&crate::rulefile::parse(&f.contents))
                .iter()
                .map(|r| r.to_line())
                .collect()
        })
        .unwrap_or_default()
}

pub struct AdoptReport {
    pub adopted: usize,
    /// `default` rules are never adopted: merged custom rules sit ahead of
    /// everything else, so an adopted catch-all would shadow every other rule.
    /// Defaults are policy, not custom rules.
    pub skipped_defaults: usize,
    pub unparsed: usize,
    /// (file, adopted-count) for files that gained rules.
    pub per_file: Vec<(String, usize)>,
}

/// Absorb ("borrow") rules found in existing on-disk ruleset files into the
/// custom store, normalized to canonical form — regardless of the whitespace
/// style they were written in. Only rules that differ from what policy already
/// generates are taken. `source` overrides the rules dir (e.g. a legacy MSFE
/// install's rules directory when migrating); `only` restricts to one file.
/// The caller is responsible for running `run()` + reload afterwards.
pub fn adopt_rules(
    cfg: &Config,
    config_file: &Path,
    source: Option<&Path>,
    only: Option<&str>,
) -> io::Result<AdoptReport> {
    let src_dir = source.unwrap_or(Path::new(&cfg.mailscanner_rules_dir));
    let pdir = policy_dir(config_file);
    let mut report = AdoptReport {
        adopted: 0,
        skipped_defaults: 0,
        unparsed: 0,
        per_file: Vec::new(),
    };
    for name in rules::managed_files() {
        if only.is_some_and(|f| f != name) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(src_dir.join(&name)) else {
            continue;
        };
        let expected = expected_rule_lines(config_file, &name);
        let mut custom = crate::rulefile::load_custom(&pdir, &name);
        let mut added = 0;
        for line in crate::rulefile::parse(&text) {
            match line {
                crate::rulefile::Line::Unparsed(_) => report.unparsed += 1,
                crate::rulefile::Line::Rule(r) => {
                    if r.pattern.eq_ignore_ascii_case("default") {
                        if !expected.contains(&r.to_line()) {
                            report.skipped_defaults += 1;
                        }
                        continue;
                    }
                    if !expected.contains(&r.to_line())
                        && !custom.contains(&r)
                        && r.validate().is_ok()
                    {
                        custom.push(r);
                        added += 1;
                    }
                }
                _ => {}
            }
        }
        if added > 0 {
            crate::rulefile::save_custom(&pdir, &name, &custom)?;
            report.adopted += added;
            report.per_file.push((name, added));
        }
    }
    Ok(report)
}

/// Best-effort MailScanner reload (systemd first, then SysV). Returns success.
pub fn reload_mailscanner() -> bool {
    std::process::Command::new("systemctl")
        .args(["reload-or-restart", "mailscanner"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        || std::process::Command::new("service")
            .args(["MailScanner", "reload"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}
