//! Input validation and the SSRF guard of the delivery test.
//!
//! The tab makes the daemon connect to hosts the *user* named or that DNS
//! answered with. Every outbound connection is therefore judged on the
//! resolved address: nothing private, loopback, link-local, multicast or
//! reserved, and never this server's own addresses unless the check is the
//! local audit itself.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

/// A syntactically valid public hostname: ASCII letters, digits and hyphens
/// in labels of 1–63 characters, at least two labels, total ≤ 253, the last
/// label not all digits (that would be an IPv4 literal).
pub fn valid_hostname(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 || !s.contains('.') {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.iter().any(|l| {
        l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return false;
    }
    !labels.last().unwrap().bytes().all(|b| b.is_ascii_digit())
}

/// `local@domain` → `(local, domain)`; the domain lowercased and valid, the
/// local part 1–64 printable ASCII characters without spaces.
pub fn parse_address(s: &str) -> Result<(String, String), String> {
    let s = s.trim();
    if s.len() > 254 {
        return Err("address is too long".into());
    }
    let Some((local, domain)) = s.rsplit_once('@') else {
        return Err("an email address looks like user@domain".into());
    };
    if local.is_empty() || local.len() > 64 {
        return Err("the part before @ must be 1–64 characters".into());
    }
    if local
        .bytes()
        .any(|b| !(0x21..0x7f).contains(&b) || b == b'@' || b == b'<' || b == b'>' || b == b'"')
    {
        return Err("the part before @ contains characters that are not allowed".into());
    }
    let domain = domain.to_ascii_lowercase();
    if !valid_hostname(&domain) {
        return Err(format!("'{domain}' is not a valid domain name"));
    }
    Ok((local.to_string(), domain.trim_end_matches('.').to_string()))
}

fn v4_public(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_documentation()
        || o[0] == 100 && (64..128).contains(&o[1]) // CGNAT
        || o[0] == 192 && o[1] == 0 && o[2] == 0 // IETF protocol assignments
        || o[0] == 198 && (o[1] == 18 || o[1] == 19) // benchmarking
        || o[0] >= 240) // reserved
}

fn v6_public(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return v4_public(v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link local
        || s[0] == 0x2001 && s[1] == 0x0db8 // documentation
        || s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 well-known prefix → not a server
}

/// Routable on the public internet.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_public(v4),
        IpAddr::V6(v6) => v6_public(v6),
    }
}

static OWN: Mutex<Option<Vec<IpAddr>>> = Mutex::new(None);

/// This server's own addresses (`ip -o addr`), cached; `MSFE_NG_OWN_IPS`
/// (comma-separated) overrides for tests.
pub fn own_addresses() -> Vec<IpAddr> {
    if let Ok(v) = std::env::var("MSFE_NG_OWN_IPS") {
        return v.split(',').filter_map(|s| s.trim().parse().ok()).collect();
    }
    let mut g = OWN.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(v) = g.as_ref() {
        return v.clone();
    }
    let mut out = Vec::new();
    for fam in ["-4", "-6"] {
        if let Ok(o) = std::process::Command::new("ip")
            .args(["-o", fam, "addr", "show"])
            .output()
        {
            for a in crate::resolver::parse_ip_addr(&String::from_utf8_lossy(&o.stdout)) {
                if let Ok(ip) = a.parse() {
                    out.push(ip);
                }
            }
        }
    }
    *g = Some(out.clone());
    out
}

/// May the delivery test open a connection to `ip`? `local_audit` allows
/// this server's own addresses (the audit probes itself).
pub fn outbound_allowed(ip: IpAddr, local_audit: bool) -> Result<(), String> {
    if local_audit && (ip.is_loopback() || own_addresses().contains(&ip)) {
        return Ok(());
    }
    if !is_public(ip) {
        return Err(format!("{ip} is not a public address — not probed"));
    }
    if own_addresses().contains(&ip) {
        return Err(format!(
            "{ip} is this server — use the server audit for local checks"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        for ok in [
            "example.com",
            "mail.example.co.uk",
            "a-b.example",
            "xn--bcher-kva.example",
            "1a.example",
        ] {
            assert!(valid_hostname(ok), "{ok}");
        }
        for bad in [
            "",
            "localhost",
            "-a.example",
            "a..b",
            "a.b-",
            "a b.example",
            "192.0.2.1",
            "a.123",
            &format!("{}.example", "x".repeat(64)),
        ] {
            assert!(!valid_hostname(bad), "{bad}");
        }
        assert!(valid_hostname("example.com."));
    }

    #[test]
    fn addresses() {
        assert_eq!(
            parse_address(" User@Example.COM ").unwrap(),
            ("User".into(), "example.com".into())
        );
        assert!(parse_address("nobody").is_err());
        assert!(parse_address("@example.com").is_err());
        assert!(parse_address("a@localhost").is_err());
        assert!(parse_address("a b@example.com").is_err());
        assert!(parse_address("\"quoted\"@example.com").is_err());
        assert!(parse_address(&format!("{}@example.com", "x".repeat(65))).is_err());
        assert!(parse_address("a@10.0.0.1").is_err());
    }

    #[test]
    fn public_addresses() {
        for ok in ["8.8.8.8", "78.47.94.167", "2a01:4f8::1", "2606:4700::1111"] {
            assert!(is_public(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "224.0.0.1",
            "0.0.0.0",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "203.0.113.5",
            "240.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1",
            "64:ff9b::1",
        ] {
            assert!(!is_public(bad.parse().unwrap()), "{bad}");
        }
        assert!(is_public("::ffff:8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn outbound_guard_respects_own_addresses() {
        std::env::set_var("MSFE_NG_OWN_IPS", "78.47.94.167, 2a01:4f8::1");
        assert!(outbound_allowed("8.8.8.8".parse().unwrap(), false).is_ok());
        assert!(outbound_allowed("78.47.94.167".parse().unwrap(), false).is_err());
        assert!(outbound_allowed("78.47.94.167".parse().unwrap(), true).is_ok());
        assert!(outbound_allowed("127.0.0.1".parse().unwrap(), false).is_err());
        assert!(outbound_allowed("127.0.0.1".parse().unwrap(), true).is_ok());
        assert!(outbound_allowed("10.0.0.1".parse().unwrap(), true).is_err());
        std::env::remove_var("MSFE_NG_OWN_IPS");
    }
}
