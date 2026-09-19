//! Two things the plain DNS client cannot tell on its own: whether a name
//! validates under DNSSEC (a ladder of system tools — `delv`,
//! `unbound-host`, `dig` — each with its own trust anchor, falling back to
//! the resolver's AD flag and the DS record at the parent), and whether the
//! domain's authoritative servers agree with one another.

use crate::dns::{Client, DnsError, RType, Rr};
use crate::service::run_with_timeout;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnssecState {
    /// Signed and the chain of trust verifies.
    Secure,
    /// Not signed (no DS at the parent): nothing to verify.
    Insecure,
    /// Signed but the chain does not verify: validating resolvers refuse it.
    Bogus,
    /// No tool could tell; the string says why.
    Unknown(String),
}

impl DnssecState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnssecState::Secure => "secure",
            DnssecState::Insecure => "insecure",
            DnssecState::Bogus => "bogus",
            DnssecState::Unknown(_) => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DnssecResult {
    pub state: DnssecState,
    /// Which tool decided.
    pub via: String,
    pub evidence: String,
}

fn tool_present(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
        .unwrap_or(false)
}

/// `delv +cd name type` output → state. `+cd` makes the upstream resolver
/// hand over bogus data so delv validates it with its own trust anchor.
pub fn parse_delv(out: &str) -> Option<DnssecState> {
    for line in out.lines() {
        let l = line.trim();
        if l == "; fully validated" || l.starts_with("; negative response, fully validated") {
            return Some(DnssecState::Secure);
        }
        if l == "; unsigned answer" || l.starts_with("; negative response, unsigned") {
            return Some(DnssecState::Insecure);
        }
        if l.contains("broken trust chain")
            || l.contains("no valid signature")
            || l.contains("no valid RRSIG")
            || l.contains("verify failed")
        {
            return Some(DnssecState::Bogus);
        }
    }
    None
}

/// `unbound-host -v -D -t type name` output → state.
pub fn parse_unbound_host(out: &str) -> Option<DnssecState> {
    let mut seen = None;
    for line in out.lines() {
        let l = line.trim();
        if l.contains("(BOGUS") || l.starts_with("validation failure") {
            return Some(DnssecState::Bogus);
        }
        if l.ends_with("(secure)") {
            seen = Some(DnssecState::Secure);
        } else if l.ends_with("(insecure)") && seen.is_none() {
            seen = Some(DnssecState::Insecure);
        }
    }
    seen
}

/// `dig +dnssec +noall +comments` → (rcode, ad flag).
pub fn parse_dig_flags(out: &str) -> Option<(String, bool)> {
    let mut status = None;
    let mut ad = None;
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix(";; ->>HEADER<<-") {
            status = rest.split(',').find_map(|p| {
                p.trim()
                    .strip_prefix("status: ")
                    .map(|s| s.trim().to_string())
            });
        } else if let Some(rest) = line.strip_prefix(";; flags:") {
            let flags = rest.split(';').next().unwrap_or("");
            ad = Some(flags.split_whitespace().any(|f| f == "ad"));
        }
    }
    Some((status?, ad?))
}

/// The DNSSEC state of `name`/`rtype`, decided by the first tool that can.
pub fn dnssec_state(client: &Client, name: &str, rtype: RType) -> DnssecResult {
    let timeout = Duration::from_secs(8);
    let server = client.servers.first().map(|s| s.to_string());
    let at = |cmd: &mut Command| {
        // delv/dig take @server; unbound-host has no such switch (uses resolv.conf)
        if let Some(s) = &server {
            if let Ok(sa) = s.parse::<SocketAddr>() {
                if sa.port() == 53 {
                    cmd.arg(format!("@{}", sa.ip()));
                }
            }
        }
    };
    if tool_present("delv") {
        let mut cmd = Command::new("delv");
        at(&mut cmd);
        cmd.args(["+cd", name, rtype.as_str()]); // no +time in delv 9.11: run_with_timeout bounds it
        if let Ok(out) = run_with_timeout(&mut cmd, timeout) {
            let all = format!("{}\n{}", out.stdout, out.stderr);
            if let Some(state) = parse_delv(&all) {
                return DnssecResult {
                    state,
                    via: "delv".into(),
                    evidence: all.lines().take(6).collect::<Vec<_>>().join("\n"),
                };
            }
        }
    }
    if tool_present("unbound-host") {
        let mut cmd = Command::new("unbound-host");
        cmd.args(["-v", "-D", "-t", rtype.as_str(), name]);
        if let Ok(out) = run_with_timeout(&mut cmd, timeout) {
            let all = format!("{}\n{}", out.stdout, out.stderr);
            if let Some(state) = parse_unbound_host(&all) {
                return DnssecResult {
                    state,
                    via: "unbound-host".into(),
                    evidence: all.lines().take(6).collect::<Vec<_>>().join("\n"),
                };
            }
        }
    }
    // no independent validator: the resolver's AD flag (only meaningful when
    // it validates), then whether the name sits in a signed zone at all — a
    // DS at the name or any ancestor below the TLD, or RRSIGs in the answer
    let ans = client.query(name, rtype);
    if let Ok(r) = &ans {
        if r.ad {
            return DnssecResult {
                state: DnssecState::Secure,
                via: "resolver AD flag".into(),
                evidence: format!(
                    "{} answered with the AD (authenticated data) flag set",
                    r.server
                ),
            };
        }
    }
    let (signed, ds_evidence) = match signed_zone(client, name) {
        Ok(Some(at)) => (true, format!("DS record found at {at}")),
        Ok(None) => {
            let rrsig = ans
                .as_ref()
                .map(|r| {
                    r.answers
                        .iter()
                        .chain(r.authority.iter())
                        .any(|rr| rr.rtype == 46)
                })
                .unwrap_or(false);
            if rrsig {
                (true, "the answer carries RRSIG records".to_string())
            } else {
                (
                    false,
                    "no DS record at the name or its parent zones, no RRSIG in the answer"
                        .to_string(),
                )
            }
        }
        Err(e) => {
            return DnssecResult {
                state: DnssecState::Unknown(format!("the DS lookup failed: {e}")),
                via: "DS lookup".into(),
                evidence: String::new(),
            }
        }
    };
    match (signed, &ans) {
        (false, _) => DnssecResult {
            state: DnssecState::Insecure,
            via: "DS lookup".into(),
            evidence: ds_evidence,
        },
        (true, Err(DnsError::ServFail)) => DnssecResult {
            state: DnssecState::Bogus,
            via: "DS + SERVFAIL".into(),
            evidence: format!("{ds_evidence}, and the resolver answers SERVFAIL for the name — the signature chain is most likely broken (a validating tool such as delv would confirm)"),
        },
        (true, _) => DnssecResult {
            state: DnssecState::Unknown(format!("{ds_evidence}, but no validating resolver or tool (delv, unbound-host) is available here to verify the chain")),
            via: "DS lookup".into(),
            evidence: ds_evidence,
        },
    }
}

/// The closest name at or above `name` (below the TLD) that has a DS record,
/// i.e. is a signed zone apex.
fn signed_zone(client: &Client, name: &str) -> Result<Option<String>, DnsError> {
    let labels: Vec<&str> = name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
        .collect();
    let mut last_err = None;
    for i in 0..labels.len().saturating_sub(1) {
        let cand = labels[i..].join(".");
        match client.query(&cand, RType::Ds) {
            Ok(r) if !r.of(RType::Ds).is_empty() => return Ok(Some(cand)),
            Ok(_) => {}
            Err(e) => last_err = Some(e),
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// What each authoritative server answers for `name`/`rtype`.
#[derive(Debug, Clone, PartialEq)]
pub struct Consistency {
    /// Per name server: its answer (sorted presentation lines) or the failure.
    pub per_ns: Vec<(String, Result<Vec<String>, String>)>,
    /// Every reachable server gave the same answer.
    pub agree: bool,
    pub reachable: usize,
}

fn present_sorted(rrs: &[&Rr], rtype: RType) -> Vec<String> {
    let mut v: Vec<String> = rrs
        .iter()
        .map(|r| match (&r.data, rtype) {
            // the serial is what matters for SOA agreement
            (crate::dns::RData::Soa { serial, .. }, RType::Soa) => format!("serial {serial}"),
            (d, _) => d.present(),
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Ask every NS host directly (RD=0) and compare. `guard` refuses
/// non-public server addresses (off only in tests against fake servers).
pub fn compare_across_ns(
    client: &Client,
    ns_hosts: &[String],
    name: &str,
    rtype: RType,
    guard: bool,
) -> Consistency {
    compare_across_ns_with(client, ns_hosts, name, rtype, guard, &|_, ip| {
        SocketAddr::new(ip, 53)
    })
}

/// `compare_across_ns` with the server socket chosen by `server_of` (tests
/// point fake servers at ephemeral ports).
pub fn compare_across_ns_with(
    client: &Client,
    ns_hosts: &[String],
    name: &str,
    rtype: RType,
    guard: bool,
    server_of: &dyn Fn(&str, IpAddr) -> SocketAddr,
) -> Consistency {
    let mut per_ns = Vec::new();
    for ns in ns_hosts {
        let ip: Option<IpAddr> = match client.addrs(ns) {
            Ok((v4, v6)) => v4
                .first()
                .map(|a| IpAddr::V4(*a))
                .or_else(|| v6.first().map(|a| IpAddr::V6(*a))),
            Err(_) => None,
        };
        let Some(ip) = ip else {
            per_ns.push((
                ns.clone(),
                Err("the name server does not resolve".to_string()),
            ));
            continue;
        };
        if guard {
            if let Err(why) = crate::netguard::outbound_allowed(ip, false) {
                per_ns.push((ns.clone(), Err(why)));
                continue;
            }
        }
        match client.query_authoritative(server_of(ns, ip), name, rtype) {
            Ok(r) if r.rcode == 0 || r.rcode == 3 => {
                if !r.aa {
                    per_ns.push((ns.clone(), Err("answers without the AA flag: not authoritative for the zone (lame delegation)".into())));
                } else {
                    per_ns.push((ns.clone(), Ok(present_sorted(&r.of(rtype), rtype))));
                }
            }
            Ok(r) => per_ns.push((ns.clone(), Err(format!("rcode {}", r.rcode)))),
            Err(e) => per_ns.push((ns.clone(), Err(e.to_string()))),
        }
    }
    let answers: Vec<&Vec<String>> = per_ns.iter().filter_map(|(_, r)| r.as_ref().ok()).collect();
    let agree = answers.windows(2).all(|w| w[0] == w[1]);
    Consistency {
        reachable: answers.len(),
        per_ns,
        agree,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_tools() {
        assert_eq!(
            parse_delv("; fully validated\nisc.org.\t300\tIN\tA\t151.101.131.42\n"),
            Some(DnssecState::Secure)
        );
        assert_eq!(
            parse_delv("; unsigned answer\ngmail.com.\t300\tIN\tA\t1.2.3.4\n"),
            Some(DnssecState::Insecure)
        );
        assert_eq!(parse_delv(";; validating dnssec-failed.org/DNSKEY: no valid signature found (DS)\n;; no valid RRSIG resolving 'dnssec-failed.org/DNSKEY/IN': 127.0.0.1#53\n;; broken trust chain resolving 'dnssec-failed.org/A/IN': 127.0.0.1#53\n;; resolution failed: broken trust chain\n"), Some(DnssecState::Bogus));
        assert_eq!(
            parse_delv(
                ";; resolution failed: ncache nxdomain\n; negative response, fully validated\n"
            ),
            Some(DnssecState::Secure)
        );
        assert_eq!(parse_delv(";; resolution failed: SERVFAIL\n"), None);
        assert_eq!(parse_unbound_host("isc.org has address 151.101.195.42 (secure)\nisc.org has address 151.101.131.42 (secure)\n"), Some(DnssecState::Secure));
        assert_eq!(
            parse_unbound_host("gmail.com has address 142.251.14.18 (insecure)\n"),
            Some(DnssecState::Insecure)
        );
        assert_eq!(parse_unbound_host("dnssec-failed.org has no mail handler record (BOGUS (security failure))\nvalidation failure <dnssec-failed.org. MX IN>: no keys have a DS\n"), Some(DnssecState::Bogus));
        assert_eq!(
            parse_unbound_host("Host nonexistent.isc.org not found: 3(NXDOMAIN). (secure)\n"),
            Some(DnssecState::Secure)
        );
        assert_eq!(parse_unbound_host(""), None);
        assert_eq!(parse_dig_flags(";; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 43556\n;; flags: qr rd ra ad; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 1\n"), Some(("NOERROR".into(), true)));
        assert_eq!(parse_dig_flags(";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 58017\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"), Some(("SERVFAIL".into(), false)));
    }

    #[test]
    fn consistency_over_fake_servers() {
        use crate::dns::testsupport::start as fake;
        use crate::dns::RData;
        let rr = |name: &str, rtype: u16, data: RData| Rr {
            name: name.into(),
            rtype,
            ttl: 60,
            data,
        };
        let soa = |serial: u32| RData::Soa {
            mname: "ns1".into(),
            rname: "h".into(),
            serial,
            refresh: 1,
            retry: 1,
            expire: 1,
            minimum: 1,
        };
        let mx = |pref: u16, host: &str| RData::Mx {
            pref,
            host: host.into(),
        };
        let (s1, m1, s2, m2) = (
            soa(2026),
            mx(10, "mx.z.example"),
            soa(2026),
            mx(10, "mx.z.example"),
        );
        let a1 = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("z.example", 15) => Some((0, vec![rr(name, 15, m1.clone())], false)),
                ("z.example", 6) => Some((0, vec![rr(name, 6, s1.clone())], false)),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        // the second server still has an old backup MX
        let old = mx(20, "old.z.example");
        let a2 = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("z.example", 15) => Some((
                    0,
                    vec![rr(name, 15, m2.clone()), rr(name, 15, old.clone())],
                    false,
                )),
                ("z.example", 6) => Some((0, vec![rr(name, 6, s2.clone())], false)),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        let v4 = |a: SocketAddr| match a.ip() {
            IpAddr::V4(v) => v,
            _ => unreachable!(),
        };
        let (ip1, ip2) = (v4(a1.addr), v4(a2.addr));
        let rec = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("ns1.z.example", 1) => Some((0, vec![rr(name, 1, RData::A(ip1))], false)),
                ("ns2.z.example", 1) => Some((0, vec![rr(name, 1, RData::A(ip2))], false)),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        // the fakes answer on 127.0.0.1:<port>; the client always asks port 53,
        // so point each NS name at a client whose "authoritative" call goes
        // to the fake's port instead
        let mut client = Client::at(rec.addr);
        client.timeout = Duration::from_millis(500);
        let ns = [
            "ns1.z.example".to_string(),
            "ns2.z.example".to_string(),
            "ns3.z.example".to_string(),
        ];
        // both fakes live on 127.0.0.1, so the mapping goes by NS name
        let pick = |ns: &str, ip: IpAddr| match ns {
            "ns1.z.example" => a1.addr,
            "ns2.z.example" => a2.addr,
            _ => SocketAddr::new(ip, 53),
        };
        let c = compare_across_ns_with(&client, &ns, "z.example", RType::Mx, false, &pick);
        assert_eq!(c.reachable, 2);
        assert!(!c.agree, "ns2 still serves the old MX: {:?}", c.per_ns);
        assert!(c.per_ns[2]
            .1
            .as_ref()
            .unwrap_err()
            .contains("does not resolve"));
        let c = compare_across_ns_with(&client, &ns[..2], "z.example", RType::Soa, false, &pick);
        assert!(c.agree);
        assert_eq!(c.per_ns[0].1, Ok(vec!["serial 2026".to_string()]));
        // with the guard on, loopback servers are refused rather than probed
        let c = compare_across_ns(&client, &ns[..1], "z.example", RType::Soa, true);
        assert_eq!(c.reachable, 0);
    }
}
