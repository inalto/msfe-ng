//! A private recursive resolver for the DNS blocklists.
//!
//! Spamhaus (ZEN, DBL) and DNSWL refuse queries relayed through shared or
//! public resolvers and URIBL rate-limits them, so on a host using its
//! provider's resolver SpamAssassin scores without its best lists. The fix
//! is unbound on loopback. On cPanel the port is held by PowerDNS
//! (authoritative) on every address, so it is first bound to the public
//! ones. Every file edited keeps a `.msfe-ng.bak`; the system is pointed at
//! unbound only after it answered a real blocklist query on 127.0.0.1.
//!
//! `msfe-ng resolver <status|install>`, the Service tab's card (job
//! `resolver-install`), doctor fix hint.

use crate::service;
use std::io;
use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub const JOB: &str = "resolver-install";
const RESOLV_CONF: &str = "/etc/resolv.conf";
const PDNS_CONF: &str = "/etc/pdns/pdns.conf";
const UNBOUND_LOCAL: &str = "/etc/unbound/local.d/msfe-ng.conf";
const UNBOUND_DROPIN: &str = "/etc/systemd/system/unbound.service.d/msfe-ng.conf";
/// Spamhaus' documented test record: a working resolver returns 127.0.0.x.
const TEST_NAME: &str = "2.0.0.127.zen.spamhaus.org";

fn root() -> PathBuf {
    std::env::var("MSFE_NG_RESOLVER_ROOT")
        .unwrap_or_else(|_| "/".to_string())
        .into()
}
fn at(p: &str) -> PathBuf {
    root().join(p.trim_start_matches('/'))
}

#[derive(Debug, Clone, Default)]
pub struct State {
    /// `nameserver` entries of resolv.conf.
    pub nameservers: Vec<String>,
    pub on_loopback: bool,
    pub unbound_installed: bool,
    pub unbound_active: bool,
    /// What else serves port 53 here (`pdns`, `named`, `dnsmasq`, …).
    pub port53: Vec<String>,
    pub public_v4: Vec<String>,
    pub public_v6: Vec<String>,
    pub has_v6_loopback: bool,
    /// `networkmanager`, `network-scripts` or `none`.
    pub manager: String,
    pub blockers: Vec<String>,
    pub notes: Vec<String>,
}

impl State {
    pub fn ok(&self) -> bool {
        self.blockers.is_empty()
    }
    /// Already done: unbound answering and resolv.conf on loopback.
    pub fn done(&self) -> bool {
        self.on_loopback && self.unbound_active
    }
}

pub fn nameservers_of(resolv: &str) -> Vec<String> {
    resolv
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("nameserver"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// `ip -o -<4|6> addr show scope global` → addresses.
pub fn parse_ip_addr(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let _idx = f.next()?;
            let _dev = f.next()?;
            let fam = f.next()?;
            let addr = f.next()?;
            (fam == "inet" || fam == "inet6")
                .then(|| addr.split('/').next().unwrap_or(addr).to_string())
        })
        .collect()
}

fn public_addrs(family: &str) -> Vec<String> {
    Command::new("ip")
        .args(["-o", family, "addr", "show", "scope", "global"])
        .output()
        .map(|o| parse_ip_addr(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

pub fn state() -> State {
    let live = root() == Path::new("/");
    let resolv = std::fs::read_to_string(at(RESOLV_CONF)).unwrap_or_default();
    let nameservers = nameservers_of(&resolv);
    let on_loopback = nameservers
        .first()
        .and_then(|n| n.parse::<IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    let mut s = State {
        nameservers,
        on_loopback,
        unbound_installed: at("/usr/sbin/unbound").exists(),
        unbound_active: live && unit_active("unbound"),
        manager: if at("/etc/NetworkManager").is_dir() && (!live || unit_active("NetworkManager")) {
            "networkmanager".into()
        } else if at("/etc/sysconfig/network-scripts").is_dir() {
            "network-scripts".into()
        } else {
            "none".into()
        },
        ..Default::default()
    };
    if live {
        s.public_v4 = public_addrs("-4");
        s.public_v6 = public_addrs("-6");
        s.has_v6_loopback = Command::new("ip")
            .args(["-o", "-6", "addr", "show", "dev", "lo"])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("::1"));
        for (unit, name) in [
            ("pdns", "pdns"),
            ("named", "named"),
            ("dnsmasq", "dnsmasq"),
            ("systemd-resolved", "systemd-resolved"),
        ] {
            if unit_active(unit) {
                s.port53.push(name.into());
            }
        }
    }
    if at(PDNS_CONF).exists() && !s.port53.iter().any(|p| p == "pdns") && !live {
        s.port53.push("pdns".into());
    }
    if s.public_v4.is_empty() && live {
        s.blockers
            .push("no public IPv4 address found (ip -4 addr show scope global) — PowerDNS cannot be rebound".into());
    }
    for holder in &s.port53 {
        match holder.as_str() {
            "pdns" => s.notes.push(format!(
                "PowerDNS holds port 53 on every address: it is bound to {} first",
                s.public_v4.iter().chain(s.public_v6.iter()).cloned().collect::<Vec<_>>().join(", ")
            )),
            "named" => s.blockers.push("BIND (named) serves port 53 on every address — set `listen-on { <public IPs>; };` and `listen-on-v6` in named.conf so 127.0.0.1:53 is free, then retry".into()),
            other => s.blockers.push(format!("{other} serves port 53 on loopback — stop or reconfigure it first")),
        }
    }
    if s.manager == "none" {
        s.notes.push("no network manager found: resolv.conf is written directly and may be overwritten by the provider's DHCP client".into());
    }
    s
}

// ---- pure edits -----------------------------------------------------------------

/// pdns.conf with `local-address=` set to `ips` (replacing any existing
/// line, commented or not); `None` when it already says so.
pub fn pdns_conf_with_local_address(text: &str, ips: &[String]) -> Option<String> {
    let want = format!("local-address={}", ips.join(", "));
    let mut found = false;
    let mut lines: Vec<String> = text
        .lines()
        .map(|l| {
            let t = l.trim_start();
            if t.starts_with("local-address=")
                || t.starts_with("# local-address=")
                || t.starts_with("#local-address=")
            {
                if found {
                    return format!("# {}", l.trim_start_matches('#').trim_start());
                }
                found = true;
                want.clone()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(
            "# msfe-ng: authoritative only on the public addresses; unbound recurses on loopback"
                .into(),
        );
        lines.push(want);
    }
    let out = lines.join("\n") + "\n";
    (out != text).then_some(out)
}

/// unbound's server config for loopback recursion.
pub fn unbound_local_conf(v6: bool) -> String {
    let mut s = String::from(
        "# managed by msfe-ng (resolver install): recursion for this host only\n\
         server:\n\
         \x20   interface: 127.0.0.1\n",
    );
    if v6 {
        s.push_str("    interface: ::1\n");
    }
    // no private-address filtering: the blocklists answer 127.0.0.x on purpose
    s.push_str(
        "    access-control: 127.0.0.0/8 allow\n\
         \x20   access-control: ::1 allow\n\
         \x20   do-ip6: yes\n\
         \x20   prefetch: yes\n",
    );
    s
}

/// resolv.conf pointing at loopback only, keeping search/domain/options.
/// No provider fallback on purpose: glibc and SpamAssassin switch to it on
/// any error and the lists' refusal codes come back.
pub fn resolv_conf_for_loopback(existing: &str, v6: bool) -> String {
    let mut out = String::from(
        "# managed by msfe-ng (resolver install): unbound on loopback\nnameserver 127.0.0.1\n",
    );
    if v6 {
        out.push_str("nameserver ::1\n");
    }
    for l in existing.lines() {
        let t = l.trim();
        if t.starts_with("search") || t.starts_with("domain") || t.starts_with("options") {
            out.push_str(t);
            out.push('\n');
        }
    }
    out
}

/// ifcfg-* with PEERDNS=no and DNS1=127.0.0.1 (other DNSn dropped);
/// `None` when unchanged.
pub fn ifcfg_with_local_dns(text: &str, v6: bool) -> Option<String> {
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("PEERDNS=")
                || t.starts_with("DNS1=")
                || t.starts_with("DNS2=")
                || t.starts_with("DNS3="))
        })
        .map(str::to_string)
        .collect();
    lines.push("PEERDNS=no".into());
    lines.push("DNS1=127.0.0.1".into());
    if v6 {
        lines.push("DNS2=::1".into());
    }
    let out = lines.join("\n") + "\n";
    (out != text).then_some(out)
}

// ---- a raw DNS query, to verify unbound before switching to it ------------------

/// Query `name` (A) at `server`:53 over UDP; the answer's A records.
pub fn query_a(server: &str, name: &str) -> io::Result<Vec<String>> {
    let sock = UdpSocket::bind(if server.contains(':') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })?;
    sock.set_read_timeout(Some(Duration::from_secs(4)))?;
    let mut q = vec![0x4d, 0x53, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    sock.send_to(&q, (server, 53))?;
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf)?;
    Ok(parse_a_answers(&buf[..n]))
}

/// A records in a DNS response (compression handled by skipping names).
pub fn parse_a_answers(msg: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12;
    let skip_name = |i: &mut usize| {
        while *i < msg.len() {
            let l = msg[*i] as usize;
            if l == 0 {
                *i += 1;
                return;
            }
            if l & 0xc0 == 0xc0 {
                *i += 2;
                return;
            }
            *i += 1 + l;
        }
    };
    for _ in 0..qd {
        skip_name(&mut i);
        i += 4;
    }
    for _ in 0..an {
        skip_name(&mut i);
        if i + 10 > msg.len() {
            break;
        }
        let ty = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let len = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if ty == 1 && len == 4 && i + 4 <= msg.len() {
            out.push(format!(
                "{}.{}.{}.{}",
                msg[i],
                msg[i + 1],
                msg[i + 2],
                msg[i + 3]
            ));
        }
        i += len;
    }
    out
}

// ---- the installation ------------------------------------------------------------

fn step(n: usize, what: &str) {
    println!("\n==> step {n}: {what}");
}

fn run_logged(cmd: &mut Command) -> io::Result<bool> {
    Ok(cmd
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?
        .success())
}

/// Install and switch to the local resolver, step by step (printed).
pub fn install() -> io::Result<()> {
    let s = state();
    for n in &s.notes {
        println!("note: {n}");
    }
    if let Some(b) = s.blockers.first() {
        return Err(io::Error::other(format!("cannot start: {b}")));
    }
    if s.done() {
        println!("already done: unbound active and resolv.conf on loopback");
        return Ok(());
    }
    let live = root() == Path::new("/");

    step(1, "install unbound");
    if s.unbound_installed {
        println!("  already installed");
    } else if !run_logged(Command::new("dnf").args(["-y", "install", "unbound"]))? {
        return Err(io::Error::other("dnf install unbound failed"));
    }

    step(2, "bind PowerDNS to the public addresses");
    let pdns = at(PDNS_CONF);
    if pdns.exists() {
        let ips: Vec<String> = s
            .public_v4
            .iter()
            .chain(s.public_v6.iter())
            .cloned()
            .collect();
        let text = std::fs::read_to_string(&pdns)?;
        match pdns_conf_with_local_address(&text, &ips) {
            Some(fixed) => {
                service::save_conf(&pdns, &fixed)?;
                println!("  {}: local-address={}", pdns.display(), ips.join(", "));
                if live {
                    let ok = if Path::new("/scripts/restartsrv_pdns").exists() {
                        run_logged(&mut Command::new("/scripts/restartsrv_pdns"))?
                    } else {
                        run_logged(Command::new("systemctl").args(["restart", "pdns"]))?
                    };
                    println!("  PowerDNS restarted: {}", if ok { "ok" } else { "FAILED" });
                }
            }
            None => println!("  already bound to {}", ips.join(", ")),
        }
    } else {
        println!("  no PowerDNS here — skipped");
    }

    step(3, "configure unbound on loopback");
    let local = at(UNBOUND_LOCAL);
    std::fs::create_dir_all(local.parent().unwrap())?;
    service::save_conf(&local, &unbound_local_conf(s.has_v6_loopback))?;
    println!("  {}", local.display());
    let dropin = at(UNBOUND_DROPIN);
    std::fs::create_dir_all(dropin.parent().unwrap())?;
    service::save_conf(&dropin, "[Service]\nRestart=on-failure\nRestartSec=5\n")?;
    println!("  {} (Restart=on-failure)", dropin.display());
    if live {
        let _ = Command::new("systemctl").arg("daemon-reload").status();
        if !run_logged(Command::new("systemctl").args(["enable", "--now", "unbound"]))? {
            return Err(io::Error::other(
                "unbound did not start — journalctl -u unbound",
            ));
        }
        let _ = Command::new("systemctl")
            .args(["restart", "unbound"])
            .status();
    }

    step(4, "verify: a blocklist query through 127.0.0.1");
    if live {
        std::thread::sleep(Duration::from_secs(1));
        let answers = query_a("127.0.0.1", TEST_NAME)?;
        if !answers.iter().any(|a| a.starts_with("127.0.0.")) {
            return Err(io::Error::other(format!(
                "unbound on 127.0.0.1 did not answer {TEST_NAME} with 127.0.0.x (got {answers:?}) — resolv.conf left untouched"
            )));
        }
        println!("  {TEST_NAME} → {} — the list answers", answers.join(", "));
    } else {
        println!("  (fixture root: skipped)");
    }

    step(5, "point the system at it");
    match s.manager.as_str() {
        "networkmanager" if live => {
            let out = Command::new("nmcli")
                .args(["-t", "-f", "NAME,DEVICE", "connection", "show", "--active"])
                .output()?;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let (name, dev) = line.split_once(':').unwrap_or((line, ""));
                if dev.is_empty() || dev == "lo" {
                    continue;
                }
                let mut args = vec![
                    "connection",
                    "modify",
                    name,
                    "ipv4.dns",
                    "127.0.0.1",
                    "ipv4.ignore-auto-dns",
                    "yes",
                ];
                if s.has_v6_loopback {
                    args.extend(["ipv6.dns", "::1", "ipv6.ignore-auto-dns", "yes"]);
                }
                let ok = run_logged(Command::new("nmcli").args(&args))?;
                let _ = Command::new("nmcli")
                    .args(["device", "reapply", dev])
                    .status();
                println!("  NetworkManager connection '{name}' ({dev}): dns 127.0.0.1, ignore-auto-dns — {}", if ok { "ok" } else { "FAILED" });
            }
        }
        "network-scripts" => {
            let dir = at("/etc/sysconfig/network-scripts");
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().into_owned();
                    if !n.starts_with("ifcfg-") || n == "ifcfg-lo" {
                        continue;
                    }
                    let text = std::fs::read_to_string(e.path()).unwrap_or_default();
                    if let Some(fixed) = ifcfg_with_local_dns(&text, s.has_v6_loopback) {
                        service::save_conf(&e.path(), &fixed)?;
                        println!("  {}: PEERDNS=no DNS1=127.0.0.1", e.path().display());
                    }
                }
            }
        }
        _ => {}
    }
    let resolv = at(RESOLV_CONF);
    let existing = std::fs::read_to_string(&resolv).unwrap_or_default();
    service::save_conf(
        &resolv,
        &resolv_conf_for_loopback(&existing, s.has_v6_loopback),
    )?;
    println!(
        "  {}: nameserver 127.0.0.1{}",
        resolv.display(),
        if s.has_v6_loopback { ", ::1" } else { "" }
    );

    step(6, "done");
    println!("  the doctor's 'DNS blocklists answering' re-probes within ten minutes (msfe-ng doctor now forces it)");
    Ok(())
}

pub fn start_job() -> io::Result<()> {
    crate::jobs::start(JOB, "msfe-ng resolver install", &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdns_local_address_is_set_once() {
        let ips = vec!["203.0.113.5".to_string(), "2001:db8::1".to_string()];
        let fresh = "launch=bind\nsetuid=pdns\n";
        let out = pdns_conf_with_local_address(fresh, &ips).unwrap();
        assert!(
            out.ends_with("local-address=203.0.113.5, 2001:db8::1\n"),
            "{out}"
        );
        assert_eq!(pdns_conf_with_local_address(&out, &ips), None, "idempotent");
        let stale = "# local-address=0.0.0.0\nlocal-address=0.0.0.0\nsetuid=pdns\n";
        let out = pdns_conf_with_local_address(stale, &ips).unwrap();
        assert_eq!(
            out,
            "local-address=203.0.113.5, 2001:db8::1\n# local-address=0.0.0.0\nsetuid=pdns\n"
        );
    }

    #[test]
    fn resolv_conf_keeps_search_and_drops_the_provider() {
        let old = "# Generated by NetworkManager\nsearch example.net\nnameserver 213.186.33.99\nnameserver 8.8.8.8\noptions timeout:2\n";
        let out = resolv_conf_for_loopback(old, true);
        assert_eq!(nameservers_of(&out), vec!["127.0.0.1", "::1"]);
        assert!(out.contains("search example.net\n") && out.contains("options timeout:2\n"));
        assert!(!out.contains("213.186"));
        assert_eq!(
            nameservers_of(&resolv_conf_for_loopback("", false)),
            vec!["127.0.0.1"]
        );
    }

    #[test]
    fn ifcfg_gets_local_dns_and_no_peerdns() {
        let text = "DEVICE=eth0\nBOOTPROTO=static\nPEERDNS=yes\nDNS1=213.186.33.99\nDNS2=8.8.8.8\n";
        let out = ifcfg_with_local_dns(text, false).unwrap();
        assert_eq!(
            out,
            "DEVICE=eth0\nBOOTPROTO=static\nPEERDNS=no\nDNS1=127.0.0.1\n"
        );
        assert_eq!(ifcfg_with_local_dns(&out, false), None);
    }

    #[test]
    fn unbound_conf_never_filters_private_answers() {
        let c = unbound_local_conf(true);
        assert!(c.contains("interface: 127.0.0.1\n") && c.contains("interface: ::1\n"));
        assert!(
            !c.contains("private-address:"),
            "blocklists answer 127.0.0.x"
        );
        assert!(!unbound_local_conf(false).contains("interface: ::1"));
    }

    #[test]
    fn parses_ip_addr_and_dns_answers() {
        let out = "2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\n3: eth1    inet 10.0.0.2/8 scope global eth1\n";
        assert_eq!(parse_ip_addr(out), vec!["203.0.113.5", "10.0.0.2"]);
        // a minimal response: header, question, one A answer with a compressed name
        let mut m = vec![0x4d, 0x53, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]); // question a. A IN
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 2]);
        assert_eq!(parse_a_answers(&m), vec!["127.0.0.2"]);
        assert!(parse_a_answers(&[0; 5]).is_empty());
    }

    /// Needs network: `cargo test -p msfe-core resolver -- --ignored`.
    #[test]
    #[ignore]
    fn query_a_reaches_the_system_resolver() {
        let ns = nameservers_of(&std::fs::read_to_string("/etc/resolv.conf").unwrap());
        let answers = query_a(&ns[0], "a.root-servers.net").unwrap();
        assert!(answers.contains(&"198.41.0.4".to_string()), "{answers:?}");
    }

    #[test]
    fn state_under_a_fixture_root_finds_pdns_and_the_manager() {
        let root = std::env::temp_dir().join(format!("msfe-resolver-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc/pdns")).unwrap();
        std::fs::create_dir_all(root.join("etc/sysconfig/network-scripts")).unwrap();
        std::fs::write(root.join("etc/pdns/pdns.conf"), "launch=bind\n").unwrap();
        std::fs::write(root.join("etc/resolv.conf"), "nameserver 213.186.33.99\n").unwrap();
        std::env::set_var("MSFE_NG_RESOLVER_ROOT", &root);
        let s = state();
        assert_eq!(s.nameservers, vec!["213.186.33.99"]);
        assert!(!s.on_loopback && !s.done());
        assert_eq!(s.port53, vec!["pdns"]);
        assert_eq!(s.manager, "network-scripts");
        assert!(s.ok(), "{:?}", s.blockers);
        std::env::remove_var("MSFE_NG_RESOLVER_ROOT");
        let _ = std::fs::remove_dir_all(&root);
    }
}
