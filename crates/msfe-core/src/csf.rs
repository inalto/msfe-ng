//! ConfigServer Security & Firewall (csf) integration: look up what csf knows
//! about an address and block/unblock it from the message view.
//!
//! Bans are dangerous — a wrong entry can cut off a customer or the admin — so
//! targets are validated strictly, loopback and the server's own addresses are
//! refused outright, and networks wider than /24 (IPv4) or /64 (IPv6) need an
//! explicit force. Commands are executed argv-style (never through a shell).

use crate::service::ControlOutcome;
use std::process::Command;

const CSF_BIN: &str = "/usr/sbin/csf";

fn csf_path() -> String {
    std::env::var("MSFE_NG_CSF_BIN").unwrap_or_else(|_| CSF_BIN.to_string())
}

/// Normalize a client address as recorded by MailScanner/Exim, which may
/// arrive as `[ip]`, `[ip]:port`, `ip:port` (IPv4) or bare — csf, DNS and our
/// own queries all want the bare address.
pub fn normalize_ip(raw: &str) -> String {
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return rest[..end].to_string();
        }
    }
    // ipv4:port — a single colon with a valid IPv4 on the left
    if s.matches(':').count() == 1 {
        if let Some((left, _)) = s.split_once(':') {
            if left.split('.').count() == 4 && left.split('.').all(|o| o.parse::<u8>().is_ok()) {
                return left.to_string();
            }
        }
    }
    s.to_string()
}

/// True when csf is installed on this host.
pub fn available() -> bool {
    std::path::Path::new(&csf_path()).exists()
}

/// Split `addr[/mask]` into its parts, validating both.
fn parse_target(target: &str) -> Result<(String, Option<u8>, bool), String> {
    let (addr, mask) = match target.split_once('/') {
        Some((a, m)) => {
            let m: u8 = m
                .parse()
                .map_err(|_| format!("invalid network mask in '{target}'"))?;
            (a, Some(m))
        }
        None => (target, None),
    };
    let v6 = addr.contains(':');
    if v6 {
        if !addr
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
        {
            return Err(format!("invalid IPv6 address '{addr}'"));
        }
        if let Some(m) = mask {
            if !(16..=128).contains(&m) {
                return Err("IPv6 mask must be between /16 and /128".into());
            }
        }
    } else {
        let octets: Vec<&str> = addr.split('.').collect();
        if octets.len() != 4 || octets.iter().any(|o| o.parse::<u8>().is_err()) {
            return Err(format!("invalid IPv4 address '{addr}'"));
        }
        if let Some(m) = mask {
            if !(8..=32).contains(&m) {
                return Err("IPv4 mask must be between /8 and /32".into());
            }
        }
    }
    Ok((addr.to_string(), mask, v6))
}

/// Addresses that must never be blocked: loopback, unspecified, and every
/// address this host answers on (blocking one would cut off the server).
fn is_protected(addr: &str) -> bool {
    if addr.starts_with("127.") || addr == "::1" || addr == "0.0.0.0" || addr.is_empty() {
        return true;
    }
    own_addresses().iter().any(|a| a == addr)
}

fn own_addresses() -> Vec<String> {
    if let Ok(v) = std::env::var("MSFE_NG_OWN_IPS") {
        return v.split(',').map(|s| s.trim().to_string()).collect();
    }
    Command::new("hostname")
        .arg("-I")
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Validate a ban target. `force` allows networks wider than /24 (IPv4) or
/// /64 (IPv6), which affect many hosts at once.
pub fn validate_target(target: &str, force: bool) -> Result<(), String> {
    let (addr, mask, v6) = parse_target(target)?;
    if is_protected(&addr) {
        return Err(format!(
            "{addr} is this server's own or a loopback address — refusing to block it"
        ));
    }
    if let Some(m) = mask {
        let wide = if v6 { m < 64 } else { m < 24 };
        if wide && !force {
            return Err(format!(
                "/{m} covers a large network — re-run with force to confirm"
            ));
        }
    }
    Ok(())
}

/// Keep a csf.deny comment to one safe line.
fn sanitize_comment(c: &str) -> String {
    let s: String = c
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || " ._:@/-()".contains(*ch))
        .take(120)
        .collect();
    if s.trim().is_empty() {
        "blocked from MSFE-NG".into()
    } else {
        format!("MSFE-NG: {}", s.trim())
    }
}

fn run(args: &[&str]) -> (bool, String) {
    match Command::new(csf_path()).args(args).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s.trim().to_string())
        }
        Err(e) => (false, format!("cannot run csf: {e}")),
    }
}

/// What csf currently knows about an address (`csf -g`): deny/allow entries,
/// temporary bans and matching firewall rules.
pub fn lookup(ip: &str) -> String {
    if !available() {
        return "ConfigServer Security & Firewall (csf) is not installed on this server".into();
    }
    if parse_target(ip).is_err() {
        return "invalid address".into();
    }
    let (_, out) = run(&["-g", ip]);
    if out.is_empty() {
        "no csf entries for this address".into()
    } else {
        out
    }
}

/// Block an address or network. `hours` makes it a temporary ban.
pub fn ban(
    target: &str,
    comment: &str,
    hours: Option<u32>,
    restart: bool,
    force: bool,
) -> ControlOutcome {
    let mut transcript = Vec::new();
    if !available() {
        return ControlOutcome {
            ok: false,
            transcript: vec!["csf is not installed on this server".into()],
        };
    }
    if let Err(e) = validate_target(target, force) {
        return ControlOutcome {
            ok: false,
            transcript: vec![e],
        };
    }
    let comment = sanitize_comment(comment);
    let secs;
    let args: Vec<&str> = match hours {
        Some(h) => {
            secs = (h.clamp(1, 8760) as u64 * 3600).to_string();
            vec!["-td", target, &secs, &comment]
        }
        None => vec!["-d", target, &comment],
    };
    transcript.push(format!("$ csf {}", args.join(" ")));
    let (mut ok, out) = run(&args);
    for l in out.lines() {
        transcript.push(l.to_string());
    }
    if ok && restart {
        transcript.push("$ csf -r".into());
        let (rok, rout) = run(&["-r"]);
        for l in rout.lines().take(20) {
            transcript.push(l.to_string());
        }
        ok &= rok;
    }
    transcript.push(if ok {
        format!("→ {target} blocked")
    } else {
        "→ FAILED".into()
    });
    ControlOutcome { ok, transcript }
}

/// Remove an address from csf's deny lists (permanent and temporary).
pub fn unban(target: &str) -> ControlOutcome {
    let mut transcript = Vec::new();
    if !available() {
        return ControlOutcome {
            ok: false,
            transcript: vec!["csf is not installed on this server".into()],
        };
    }
    if let Err(e) = parse_target(target).map(|_| ()) {
        return ControlOutcome {
            ok: false,
            transcript: vec![e],
        };
    }
    let mut ok = false;
    for args in [vec!["-dr", target], vec!["-tr", target]] {
        transcript.push(format!("$ csf {}", args.join(" ")));
        let (o, out) = run(&args);
        for l in out.lines() {
            transcript.push(l.to_string());
        }
        ok |= o;
    }
    transcript.push(if ok {
        format!("→ {target} unblocked")
    } else {
        "→ nothing removed".into()
    });
    ControlOutcome { ok, transcript }
}

/// Reverse DNS for an address (system resolver; empty when there is none).
pub fn reverse_dns(ip: &str) -> String {
    if parse_target(ip).is_err() {
        return String::new();
    }
    Command::new("getent")
        .args(["hosts", ip])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_addresses_and_masks() {
        std::env::set_var("MSFE_NG_OWN_IPS", "203.0.113.5");
        assert!(validate_target("49.12.174.167", false).is_ok());
        assert!(validate_target("49.12.174.0/24", false).is_ok());
        // wide networks need force
        assert!(validate_target("49.12.0.0/16", false).is_err());
        assert!(validate_target("49.12.0.0/16", true).is_ok());
        // protected addresses are never bannable
        assert!(validate_target("127.0.0.1", true).is_err());
        assert!(validate_target("203.0.113.5", true).is_err());
        assert!(validate_target("::1", true).is_err());
        // malformed input
        assert!(validate_target("not-an-ip", false).is_err());
        assert!(validate_target("1.2.3.4/99", false).is_err());
        assert!(validate_target("1.2.3.999", false).is_err());
        std::env::remove_var("MSFE_NG_OWN_IPS");
    }

    #[test]
    fn normalizes_recorded_client_addresses() {
        // what MailScanner/Exim actually store
        assert_eq!(normalize_ip("[35.247.160.179]:45570"), "35.247.160.179");
        assert_eq!(normalize_ip("[35.247.160.179]"), "35.247.160.179");
        assert_eq!(normalize_ip("35.247.160.179:45570"), "35.247.160.179");
        assert_eq!(normalize_ip(" 35.247.160.179 "), "35.247.160.179");
        // IPv6 must not lose anything to the port rule
        assert_eq!(normalize_ip("2a00:1450:4025::200e"), "2a00:1450:4025::200e");
        assert_eq!(normalize_ip("[2a00:1450::1]:25"), "2a00:1450::1");
        // and the normalized form validates
        std::env::set_var("MSFE_NG_OWN_IPS", "203.0.113.5");
        assert!(validate_target(&normalize_ip("[35.247.160.179]:45570"), false).is_ok());
        std::env::remove_var("MSFE_NG_OWN_IPS");
    }

    #[test]
    fn comment_is_single_line_and_prefixed() {
        assert_eq!(
            sanitize_comment("spam from bassetto.eu"),
            "MSFE-NG: spam from bassetto.eu"
        );
        // newline and shell metacharacters never reach csf.deny
        let hostile = sanitize_comment("x\n$(rm -rf /);`id`\ndeny all");
        assert!(!hostile.contains('\n'));
        for bad in ['$', ';', '`', '\\', '"', '\'', '|', '&'] {
            assert!(
                !hostile.contains(bad),
                "{bad} survived sanitising: {hostile}"
            );
        }
        assert_eq!(sanitize_comment("   "), "blocked from MSFE-NG");
    }
}
