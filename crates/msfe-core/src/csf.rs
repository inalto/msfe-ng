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

// ---- csf's own lists, read from its files -----------------------------------
//
// `csf -g` walks iptables and takes ~13 s on a host with a long csf.deny —
// not for a minute cron. The lists themselves are plain files: one entry per
// line (`ip`, `ip/cidr`, `ip # comment`, `Include /other/file`) and, for
// temporary blocks, `time|ip|port|inout|timeout|message`.

/// Where csf keeps its lists (`/etc/csf` and `/var/lib/csf`; tests point
/// `MSFE_NG_CSF_ROOT` at a fixture).
fn csf_root() -> std::path::PathBuf {
    std::env::var("MSFE_NG_CSF_ROOT")
        .unwrap_or_else(|_| "/".to_string())
        .into()
}

/// What csf's lists say about `ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListState {
    /// csf.allow or csf.ignore: never to be blocked.
    Allowed,
    /// csf.deny or a temporary block: already blocked.
    Denied,
    Unlisted,
}

/// Entries of a csf list file, `Include`s followed (one level, relative to
/// the root), comments stripped.
fn list_entries(root: &std::path::Path, file: &str, depth: u8) -> Vec<String> {
    let path = root.join(file.trim_start_matches('/'));
    let mut out = Vec::new();
    for line in std::fs::read_to_string(path).unwrap_or_default().lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        if let Some(inc) = t.strip_prefix("Include ") {
            if depth < 2 {
                out.extend(list_entries(root, inc.trim(), depth + 1));
            }
            continue;
        }
        // "tcp|in|d=22|s=1.2.3.4" advanced entries: take the s= address
        let entry = t
            .split('|')
            .find_map(|f| f.strip_prefix("s="))
            .unwrap_or(t)
            .to_string();
        out.push(entry);
    }
    out
}

/// Does a list entry (`ip` or `ip/cidr`) cover `ip`? IPv4 CIDRs are
/// evaluated; IPv6 only exact.
pub fn entry_covers(entry: &str, ip: &str) -> bool {
    if entry == ip {
        return true;
    }
    let Some((net, bits)) = entry.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(ip)) = (
        net.parse::<std::net::Ipv4Addr>(),
        ip.parse::<std::net::Ipv4Addr>(),
    ) else {
        return false;
    };
    let Ok(bits) = bits.parse::<u32>() else {
        return false;
    };
    if bits > 32 {
        return false;
    }
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

/// csf's verdict on `ip` from its files: allow/ignore first, then deny and
/// the temporary blocks.
pub fn list_state(ip: &str) -> ListState {
    list_state_at(&csf_root(), ip)
}

pub fn list_state_at(root: &std::path::Path, ip: &str) -> ListState {
    for f in ["/etc/csf/csf.allow", "/etc/csf/csf.ignore"] {
        if list_entries(root, f, 0).iter().any(|e| entry_covers(e, ip)) {
            return ListState::Allowed;
        }
    }
    if list_entries(root, "/etc/csf/csf.deny", 0)
        .iter()
        .any(|e| entry_covers(e, ip))
    {
        return ListState::Denied;
    }
    let temp = std::fs::read_to_string(root.join("var/lib/csf/csf.tempban")).unwrap_or_default();
    if temp
        .lines()
        .filter_map(|l| l.split('|').nth(1))
        .any(|e| entry_covers(e.trim(), ip))
    {
        return ListState::Denied;
    }
    ListState::Unlisted
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
    ban_for(
        target,
        comment,
        hours.map(|h| h.clamp(1, 8760) as u64 * 3600),
        restart,
        force,
    )
}

/// A temporary block in seconds (`csf -td`), as the auto-ban uses it.
pub fn ban_secs(target: &str, comment: &str, secs: u64) -> ControlOutcome {
    ban_for(
        target,
        comment,
        Some(secs.clamp(60, 365 * 86_400)),
        false,
        false,
    )
}

fn ban_for(
    target: &str,
    comment: &str,
    secs: Option<u64>,
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
    let secs_text;
    let args: Vec<&str> = match secs {
        Some(s) => {
            secs_text = s.to_string();
            vec!["-td", target, &secs_text, &comment]
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
    fn list_state_reads_csf_files_with_includes_and_cidrs() {
        let root = std::env::temp_dir().join(format!("msfe-csf-lists-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/csf")).unwrap();
        std::fs::create_dir_all(root.join("var/lib/csf")).unwrap();
        std::fs::write(
            root.join("etc/csf/csf.allow"),
            "# comment\nInclude /etc/csf/cpanel.allow\n10.0.0.0/8 # office\ntcp|in|d=22|s=203.0.113.9\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/csf/cpanel.allow"), "198.51.100.7\n").unwrap();
        std::fs::write(root.join("etc/csf/csf.ignore"), "127.0.0.1\n").unwrap();
        std::fs::write(
            root.join("etc/csf/csf.deny"),
            "192.0.2.1 # do not delete\n192.0.2.0/30\n",
        )
        .unwrap();
        std::fs::write(
            root.join("var/lib/csf/csf.tempban"),
            "1758380000|192.0.2.200|*|in|3600|MSFE-NG auto-ban\n",
        )
        .unwrap();
        assert_eq!(
            list_state_at(&root, "198.51.100.7"),
            ListState::Allowed,
            "via Include"
        );
        assert_eq!(
            list_state_at(&root, "10.20.30.40"),
            ListState::Allowed,
            "CIDR"
        );
        assert_eq!(
            list_state_at(&root, "203.0.113.9"),
            ListState::Allowed,
            "advanced entry"
        );
        assert_eq!(
            list_state_at(&root, "127.0.0.1"),
            ListState::Allowed,
            "ignore"
        );
        assert_eq!(list_state_at(&root, "192.0.2.1"), ListState::Denied);
        assert_eq!(
            list_state_at(&root, "192.0.2.3"),
            ListState::Denied,
            "deny CIDR"
        );
        assert_eq!(
            list_state_at(&root, "192.0.2.200"),
            ListState::Denied,
            "temporary block"
        );
        assert_eq!(list_state_at(&root, "192.0.2.201"), ListState::Unlisted);
        assert!(!entry_covers("10.0.0.0/33", "10.0.0.1"));
        assert!(
            entry_covers("2001:db8::1", "2001:db8::1")
                && !entry_covers("2001:db8::/32", "2001:db8::1")
        );
        let _ = std::fs::remove_dir_all(&root);
    }
    use std::sync::Mutex;

    // Two tests set/remove MSFE_NG_OWN_IPS; process env is shared across test
    // threads, so without this the other test's remove_var races the assert.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn validates_addresses_and_masks() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("MSFE_NG_OWN_IPS", "203.0.113.5");
        assert!(validate_target("203.0.113.7", false).is_ok());
        assert!(validate_target("203.0.113.0/24", false).is_ok());
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
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
