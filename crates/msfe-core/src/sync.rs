//! Policy → MailScanner rules orchestration, shared by the CLI (`msfe-ng sync`)
//! and the daemon (PUT /api/policy). Reads the active policy files, gathers the
//! local domains, generates the rule files and writes them atomically.

use crate::config::Config;
use crate::legacy;
use crate::panel::detect_panel;
use crate::rules;
use msfe_api::PanelKind;
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
    let domains = gather_domains(override_domains);
    let rs = rules::RuleSettings::from_settings(&settings);
    let files = rules::generate(&rs, &domains, &wl, &bl);

    let rules_dir = Path::new(&cfg.mailscanner_rules_dir);
    std::fs::create_dir_all(rules_dir)?;
    for f in &files {
        atomic_write(&rules_dir.join(&f.name), f.contents.as_bytes())?;
    }
    Ok(files.len())
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
