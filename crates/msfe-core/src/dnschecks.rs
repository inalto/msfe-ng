//! The DNS checks of the delivery test: does the domain exist, who serves
//! it, where does its mail go, and do those hosts resolve to public
//! addresses with matching reverse names. They are the first tasks of a run
//! and record what later tasks build on as facts (`mx`, `mx_ips`, `ns`,
//! `null_mx`).

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::dns::{DnsError, RData, RType};
use crate::json::Json;
use crate::netguard;
use std::net::IpAddr;

const CAT: Category = Category::Dns;

fn unknown(id: &str, scope: Scope, title: &str, e: &DnsError) -> Check {
    Check::new(
        id,
        scope,
        CAT,
        Verdict::Unknown,
        Severity::Info,
        title,
        format!("could not look up: {e}"),
    )
}

/// Present a whole answer section as evidence.
fn rrs_evidence(rrs: &[&crate::dns::Rr]) -> String {
    rrs.iter()
        .map(|r| r.present())
        .collect::<Vec<_>>()
        .join("\n")
}

/// PTR names that look like a provider's generic label rather than a mail host.
pub fn generic_ptr(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "static",
        "dynamic",
        "dyn",
        "pool",
        "dhcp",
        "customer",
        "cust",
        "ip-",
        "unassigned",
        "no-rdns",
        "broadband",
        "dsl",
        "cable",
    ]
    .iter()
    .any(|w| n.contains(w))
        || n.split('.')
            .next()
            .is_some_and(|l| l.matches(|c: char| c.is_ascii_digit()).count() >= 6)
}

/// SOA timers outside what RFC 1912 / common practice expect.
pub fn soa_problems(refresh: u32, retry: u32, expire: u32, minimum: u32) -> Vec<String> {
    let mut p = Vec::new();
    if retry > refresh {
        p.push(format!(
            "retry ({retry}) is larger than refresh ({refresh})"
        ));
    }
    if expire < refresh {
        p.push(format!("expire ({expire}) is shorter than refresh ({refresh}) — a secondary would drop the zone before it even retries"));
    }
    if minimum > 86_400 {
        p.push(format!("negative-caching TTL ({minimum}) is above one day — NXDOMAIN answers stick for a long time"));
    }
    p
}

/// The tasks of the DNS category. Facts written: `domain_exists` (bool),
/// `mx` (["pref host", …]), `null_mx` (bool), `mx_hosts` ([host]),
/// `mx_ips` ({host: [ip]}), `ns` ([host]), `a_fallback` ([ip]).
pub fn tasks() -> Vec<Task> {
    vec![
        Task::new("dns.domain", &[], domain_task),
        Task::new("dns.ns", &["dns.domain"], ns_task),
        Task::new("dns.soa", &["dns.domain"], soa_task),
        Task::new("dns.mx", &["dns.domain"], mx_task),
        Task::new("dns.apex", &["dns.domain"], apex_task),
    ]
}

fn domain_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    let mut checks = Vec::new();
    let mut exists = false;
    let mut errors = Vec::new();
    let mut ev = Vec::new();
    for rt in [RType::Mx, RType::A, RType::Aaaa, RType::Txt, RType::Ns] {
        match ctx.dns.query(d, rt) {
            Ok(r) => {
                if !r.nxdomain() {
                    exists = true;
                }
                if !r.answers.is_empty() {
                    ev.push(format!("{}: {} record(s)", rt.as_str(), r.of(rt).len()));
                }
            }
            Err(e) => errors.push(format!("{}: {e}", rt.as_str())),
        }
    }
    res.set_fact("domain_exists", Json::Bool(exists));
    // all SERVFAIL: let the DNSSEC check say whether a broken chain is why
    res.set_fact(
        "domain_servfail",
        Json::Bool(!exists && errors.len() == 5 && errors.iter().all(|e| e.contains("SERVFAIL"))),
    );
    let c = if exists {
        Check::new(
            "dns.domain",
            Scope::Sending,
            CAT,
            Verdict::Pass,
            Severity::Info,
            format!("{d} exists in DNS"),
            "the domain has records; the checks below look at each of them",
        )
        .evidence("records", ev.join("\n"))
    } else if errors.len() == 5 {
        Check::new("dns.domain", Scope::Sending, CAT, Verdict::Unknown, Severity::Info, format!("{d}: DNS did not answer"), format!("every lookup failed — the resolver or the zone's nameservers are not answering:\n{}", errors.join("\n")))
    } else {
        Check::new(
            "dns.domain",
            Scope::Sending,
            CAT,
            Verdict::Fail,
            Severity::Critical,
            format!("{d} does not exist in DNS"),
            "the nameservers answer NXDOMAIN for the domain: no mail can be sent from it (receivers reject unknown sender domains) or delivered to it",
        )
        .fix(Fix {
            summary: format!("Register {d}, or repair its zone at the DNS host so that the domain answers"),
            ..Default::default()
        })
    };
    checks.push(c);
    (checks, Vec::new())
}

fn ns_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let r = match ctx.dns.query(d, RType::Ns) {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![unknown("dns.ns", Scope::Sending, "nameservers", &e)],
                vec![],
            )
        }
    };
    let ns: Vec<String> = r
        .of(RType::Ns)
        .iter()
        .filter_map(|rr| match &rr.data {
            RData::Ns(n) => Some(n.clone()),
            _ => None,
        })
        .collect();
    if ns.is_empty() {
        // a subdomain: the zone cut is above; find the authority
        let auth: Vec<String> = r
            .authority
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::Soa { mname, .. } => Some(format!("SOA at {} (primary {mname})", rr.name)),
                RData::Ns(n) => Some(format!("NS {n} for {}", rr.name)),
                _ => None,
            })
            .collect();
        return (
            vec![Check::new("dns.ns", Scope::Sending, CAT, Verdict::Pass, Severity::Info, "served from a parent zone", format!("{d} has no NS records of its own — it is part of a larger zone, which is normal for a subdomain"))
                .evidence("authority", auth.join("\n"))],
            vec![],
        );
    }
    res.set_fact("ns", Json::Array(ns.iter().map(Json::str).collect()));
    let mut resolving = Vec::new();
    let mut dead = Vec::new();
    let mut ev = Vec::new();
    for host in &ns {
        match ctx.dns.addrs(host) {
            Ok((v4, v6)) if !v4.is_empty() || !v6.is_empty() => {
                let ips: Vec<String> = v4
                    .iter()
                    .map(|a| a.to_string())
                    .chain(v6.iter().map(|a| a.to_string()))
                    .collect();
                ev.push(format!("{host} → {}", ips.join(", ")));
                resolving.push(host.clone());
            }
            Ok(_) => {
                ev.push(format!("{host} → no address"));
                dead.push(host.clone());
            }
            Err(e) => {
                ev.push(format!("{host} → lookup failed: {e}"));
                dead.push(host.clone());
            }
        }
    }
    let (verdict, sev, title, expl) = if resolving.is_empty() {
        (Verdict::Fail, Severity::Critical, "no nameserver resolves".to_string(), "none of the domain's nameservers has an address — resolvers cannot reach the zone (lame delegation)".to_string())
    } else if resolving.len() == 1 {
        (Verdict::Warn, Severity::Medium, "a single working nameserver".to_string(), "only one nameserver answers; if it is down, mail for and from the domain fails — RFC 2182 asks for at least two in different networks".to_string())
    } else if !dead.is_empty() {
        (
            Verdict::Warn,
            Severity::Low,
            format!("{} of {} nameservers resolve", resolving.len(), ns.len()),
            format!("{} do not resolve: {}", dead.len(), dead.join(", ")),
        )
    } else {
        (
            Verdict::Pass,
            Severity::Info,
            format!("{} nameservers, all resolving", ns.len()),
            "resolvers can reach the zone through several servers".to_string(),
        )
    };
    let mut c = Check::new("dns.ns", Scope::Sending, CAT, verdict, sev, title, expl)
        .evidence("NS", ev.join("\n"));
    if verdict != Verdict::Pass {
        c = c.fix_summary(
            "Add or repair nameservers at the registrar so at least two answer for the domain",
        );
    }
    (vec![c], vec![])
}

fn soa_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let r = match ctx.dns.query(d, RType::Soa) {
        Ok(r) => r,
        Err(e) => return (vec![unknown("dns.soa", Scope::Sending, "SOA", &e)], vec![]),
    };
    let soa = r
        .of(RType::Soa)
        .first()
        .map(|rr| (rr.present(), rr.data.clone()));
    let Some((
        present,
        RData::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        },
    )) = soa
    else {
        return (
            vec![Check::new(
                "dns.soa",
                Scope::Sending,
                CAT,
                Verdict::Pass,
                Severity::Info,
                "no SOA of its own",
                "the name is inside a parent zone (normal for a subdomain)",
            )],
            vec![],
        );
    };
    res.set_fact("soa_serial", Json::Int(serial as i64));
    let problems = soa_problems(refresh, retry, expire, minimum);
    let c = if problems.is_empty() {
        Check::new("dns.soa", Scope::Sending, CAT, Verdict::Pass, Severity::Info, "zone SOA is sane", format!("serial {serial}; refresh {refresh}, retry {retry}, expire {expire}, negative TTL {minimum}"))
    } else {
        Check::new("dns.soa", Scope::Sending, CAT, Verdict::Warn, Severity::Low, "unusual SOA timers", problems.join("; "))
            .fix_summary("Adjust the SOA timers at the DNS host (typical: refresh 3600–86400, retry ≤ refresh, expire 1209600–2419200, minimum 300–86400)")
    };
    (vec![c.evidence("SOA", present)], vec![])
}

fn mx_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = ctx.inputs.domain.clone();
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let r = match ctx.dns.query(&d, RType::Mx) {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![unknown("dns.mx", Scope::Receiving, "MX records", &e)],
                vec![],
            )
        }
    };
    let mut mx: Vec<(u16, String, u32)> = r
        .of(RType::Mx)
        .iter()
        .filter_map(|rr| match &rr.data {
            RData::Mx { pref, host } => Some((*pref, host.clone(), rr.ttl)),
            _ => None,
        })
        .collect();
    mx.sort();
    let evidence = rrs_evidence(&r.of(RType::Mx));
    let mut checks = Vec::new();
    let mut more = Vec::new();

    // null MX (RFC 7505)
    if mx.len() == 1 && mx[0].1.is_empty() {
        res.set_fact("null_mx", Json::Bool(true));
        res.set_fact("mx", Json::Array(vec![]));
        checks.push(
            Check::new("dns.mx", Scope::Receiving, CAT, Verdict::Pass, Severity::Info, "null MX: the domain accepts no mail", format!("{d} publishes `0 .` (RFC 7505): senders reject mail to it immediately instead of retrying — this is deliberate; receiving checks do not apply"))
                .evidence("MX", evidence),
        );
        return (checks, more);
    }
    res.set_fact("null_mx", Json::Bool(false));

    if mx.is_empty() {
        // RFC 5321 §5.1: fall back to the A/AAAA of the domain
        match ctx.dns.addrs(&d) {
            Ok((v4, v6)) if !v4.is_empty() || !v6.is_empty() => {
                let ips: Vec<String> = v4.iter().map(|a| a.to_string()).chain(v6.iter().map(|a| a.to_string())).collect();
                res.set_fact("a_fallback", Json::Array(ips.iter().map(Json::str).collect()));
                res.set_fact("mx", Json::Array(vec![Json::str(format!("0 {d}"))]));
                res.set_fact("mx_hosts", Json::Array(vec![Json::str(&d)]));
                checks.push(
                    Check::new("dns.mx", Scope::Receiving, CAT, Verdict::Warn, Severity::Medium, "no MX record — mail falls back to the domain's address", format!("senders deliver to {} (the A/AAAA of {d}, RFC 5321 §5.1). That works only if a mail server listens there; usually it is the web server, and mail is lost or bounced", ips.join(", ")))
                        .evidence("A/AAAA", ips.join("\n"))
                        .fix(Fix {
                            summary: "Publish an MX record pointing at the mail server".into(),
                            dns_record: Some(format!("{d}. 3600 IN MX 10 mail.{d}.")),
                            ..Default::default()
                        }),
                );
                more.push(mx_host_task(d.clone(), 0, d.clone()));
            }
            Ok(_) => checks.push(
                Check::new("dns.mx", Scope::Receiving, CAT, Verdict::Fail, Severity::Critical, "no MX and no address: the domain cannot receive mail", "there is neither an MX record nor an A/AAAA record to fall back to — every message to this domain bounces")
                    .fix(Fix {
                        summary: "Publish an MX record pointing at the mail server".into(),
                        dns_record: Some(format!("{d}. 3600 IN MX 10 mail.{d}.")),
                        ..Default::default()
                    }),
            ),
            Err(e) => checks.push(unknown("dns.mx", Scope::Receiving, "MX records", &e)),
        }
        return (checks, more);
    }

    let hosts: Vec<String> = mx.iter().map(|(_, h, _)| h.clone()).collect();
    res.set_fact(
        "mx",
        Json::Array(
            mx.iter()
                .map(|(p, h, _)| Json::str(format!("{p} {h}")))
                .collect(),
        ),
    );
    res.set_fact(
        "mx_hosts",
        Json::Array(hosts.iter().map(Json::str).collect()),
    );
    checks.push(
        Check::new(
            "dns.mx",
            Scope::Receiving,
            CAT,
            Verdict::Pass,
            Severity::Info,
            format!("{} MX record(s)", mx.len()),
            format!(
                "mail for {d} goes to {}",
                mx.iter()
                    .map(|(p, h, _)| format!("{h} (priority {p})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .evidence("MX", evidence),
    );

    // priorities / duplicates / count
    let mut dup = Vec::new();
    for (i, (_, h, _)) in mx.iter().enumerate() {
        if mx[..i].iter().any(|(_, x, _)| x == h) && !dup.contains(h) {
            dup.push(h.clone());
        }
    }
    let mut pr = Vec::new();
    if !dup.is_empty() {
        pr.push(format!("duplicate MX host(s): {}", dup.join(", ")));
    }
    if mx.len() > 10 {
        pr.push(format!(
            "{} MX records is unusually many — senders try them all",
            mx.len()
        ));
    }
    if mx.iter().any(|(_, h, _)| h.parse::<IpAddr>().is_ok()) {
        pr.push("an MX points at an IP address instead of a hostname — invalid per RFC 5321, refused by many senders".into());
    }
    checks.push(if pr.is_empty() {
        Check::new(
            "dns.mx.priorities",
            Scope::Receiving,
            CAT,
            Verdict::Pass,
            Severity::Info,
            "MX priorities are sane",
            format!("lowest priority {} is tried first", mx[0].0),
        )
    } else {
        Check::new(
            "dns.mx.priorities",
            Scope::Receiving,
            CAT,
            Verdict::Warn,
            Severity::Low,
            "MX set has oddities",
            pr.join("; "),
        )
        .fix_summary("Tidy the MX records at the DNS host")
    });

    // TTLs
    let low: Vec<String> = mx
        .iter()
        .filter(|(_, _, ttl)| *ttl < 300)
        .map(|(_, h, ttl)| format!("{h} ({ttl}s)"))
        .collect();
    let high: Vec<String> = mx
        .iter()
        .filter(|(_, _, ttl)| *ttl > 604_800)
        .map(|(_, h, ttl)| format!("{h} ({ttl}s)"))
        .collect();
    checks.push(if low.is_empty() && high.is_empty() {
        Check::new(
            "dns.ttl",
            Scope::Receiving,
            CAT,
            Verdict::Pass,
            Severity::Info,
            "MX TTLs are reasonable",
            format!("{}s", mx[0].2),
        )
    } else if !low.is_empty() {
        Check::new(
            "dns.ttl",
            Scope::Receiving,
            CAT,
            Verdict::Warn,
            Severity::Low,
            "very short MX TTL",
            format!(
                "{} — fine during a migration, otherwise it just multiplies lookups",
                low.join(", ")
            ),
        )
    } else {
        Check::new(
            "dns.ttl",
            Scope::Receiving,
            CAT,
            Verdict::Warn,
            Severity::Low,
            "very long MX TTL",
            format!(
                "{} — a change to the mail servers takes that long to propagate",
                high.join(", ")
            ),
        )
    });

    for (pref, host, _) in &mx {
        if host.parse::<IpAddr>().is_err() {
            more.push(mx_host_task(d.clone(), *pref, host.clone()));
        }
    }
    more.push(Task::new(
        "dns.ipv6",
        &hosts.iter().map(|h| format!("dns.mx.host.{h}")).collect::<Vec<_>>().iter().map(String::as_str).collect::<Vec<_>>(),
        |_, res| {
            let any6 = res.fact("mx_ips").and_then(|v| match v {
                Json::Object(f) => Some(f.iter().any(|(_, ips)| ips.as_array().is_some_and(|a| a.iter().any(|i| i.as_str().is_some_and(|s| s.contains(':')))))),
                _ => None,
            });
            (
                vec![match any6 {
                    Some(true) => Check::new("dns.ipv6", Scope::Receiving, CAT, Verdict::Pass, Severity::Info, "IPv6 delivery path available", "at least one MX has an AAAA record"),
                    Some(false) => Check::new("dns.ipv6", Scope::Receiving, CAT, Verdict::Warn, Severity::Low, "IPv4 only", "no MX has an AAAA record — fine today, but IPv6-only senders (rare) cannot deliver"),
                    None => Check::new("dns.ipv6", Scope::Receiving, CAT, Verdict::Unknown, Severity::Info, "IPv6", "MX addresses were not resolved"),
                }],
                vec![],
            )
        },
    ));
    (checks, more)
}

/// Per-MX task: the target resolves, is not a CNAME, has public addresses,
/// and its addresses have confirming reverse names. Records `mx_ips`.
fn mx_host_task(domain: String, pref: u16, host: String) -> Task {
    let id = format!("dns.mx.host.{host}");
    Task::new(&id, &["dns.mx"], move |ctx, res| {
        let mut checks = Vec::new();
        let a = ctx.dns.query(&host, RType::A);
        let aaaa = ctx.dns.query(&host, RType::Aaaa);
        let cname = a.as_ref().ok().and_then(|r| r.cname_of(&host));
        let mut v4: Vec<IpAddr> = a
            .as_ref()
            .map(|r| {
                r.of(RType::A)
                    .iter()
                    .filter_map(|rr| match rr.data {
                        RData::A(x) => Some(IpAddr::V4(x)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let v6: Vec<IpAddr> = aaaa
            .as_ref()
            .map(|r| {
                r.of(RType::Aaaa)
                    .iter()
                    .filter_map(|rr| match rr.data {
                        RData::Aaaa(x) => Some(IpAddr::V6(x)),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        v4.extend(v6);
        let ips = v4;
        let tgt = format!("{host} (priority {pref})");
        match (&a, ips.is_empty()) {
            (Err(e), _) => {
                checks.push(
                    unknown("dns.mx.target", Scope::Receiving, &format!("MX {host}"), e)
                        .target(&tgt),
                );
                return (checks, vec![]);
            }
            (Ok(r), true) => {
                checks.push(
                    Check::new(
                        "dns.mx.target",
                        Scope::Receiving,
                        CAT,
                        Verdict::Fail,
                        Severity::High,
                        format!("MX {host} does not resolve"),
                        if r.nxdomain() { "the MX host does not exist — senders cannot deliver through it" } else { "the MX host has no A or AAAA record — senders cannot deliver through it" },
                    )
                    .target(&tgt)
                    .fix(Fix {
                        summary: format!("Give {host} an address, or point the MX at an existing mail host"),
                        dns_record: Some(format!("{host}. 3600 IN A <mail server IP>")),
                        ..Default::default()
                    }),
                );
                return (checks, vec![]);
            }
            _ => {}
        }
        res.insert_fact_entry(
            "mx_ips",
            &host,
            Json::Array(ips.iter().map(|i| Json::str(i.to_string())).collect()),
        );
        let ip_list = ips
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        checks.push(match &cname {
            Some(c) => Check::new("dns.mx.target", Scope::Receiving, CAT, Verdict::Warn, Severity::Medium, format!("MX {host} is a CNAME"), format!("it aliases {c}; RFC 2181 §10.3 forbids MX targets that are CNAMEs and some senders refuse them"))
                .target(&tgt)
                .evidence("addresses", ip_list.clone())
                .fix(Fix {
                    summary: format!("Point the MX at {c} directly, or give {host} its own A/AAAA records"),
                    dns_record: Some(format!("{domain}. 3600 IN MX {pref} {c}.")),
                    ..Default::default()
                }),
            None => Check::new("dns.mx.target", Scope::Receiving, CAT, Verdict::Pass, Severity::Info, format!("MX {host} resolves"), ip_list.to_string()).target(&tgt),
        });
        let private: Vec<String> = ips
            .iter()
            .filter(|i| !netguard::is_public(**i))
            .map(|i| i.to_string())
            .collect();
        if !private.is_empty() {
            checks.push(
                Check::new("dns.mx.addr_public", Scope::Receiving, CAT, Verdict::Fail, Severity::High, format!("MX {host} has a non-public address"), format!("{} is not reachable from the internet; senders outside the network cannot deliver (the host is not probed)", private.join(", ")))
                    .target(&tgt)
                    .fix_summary("Publish the mail server's public address in DNS (split-horizon zones must not leak private addresses)"),
            );
        }
        // reverse DNS per public address
        for ip in ips.iter().filter(|i| netguard::is_public(**i)) {
            let t = format!("{ip} ({host})");
            match ctx.dns.ptr(*ip) {
                Ok(names) if names.is_empty() => checks.push(
                    Check::new("dns.mx.ptr", Scope::Receiving, CAT, Verdict::Warn, Severity::Low, format!("no reverse DNS for {ip}"), "the MX address has no PTR record. For receiving mail this is cosmetic; if the same host also sends, most receivers reject or penalise it")
                        .target(&t)
                        .fix_summary(format!("Ask the IP owner (hosting provider) to set the PTR of {ip} to {host}")),
                ),
                Ok(names) => {
                    res.set_fact(&format!("ptr.{ip}"), Json::Array(names.iter().map(Json::str).collect()));
                    let confirmed = names.iter().any(|n| {
                        ctx.dns.addrs(n).map(|(v4, v6)| v4.iter().any(|a| IpAddr::V4(*a) == *ip) || v6.iter().any(|a| IpAddr::V6(*a) == *ip)).unwrap_or(false)
                    });
                    let generic = names.iter().all(|n| generic_ptr(n));
                    let ev = names.join(", ");
                    checks.push(if confirmed && !generic {
                        Check::new("dns.mx.ptr", Scope::Receiving, CAT, Verdict::Pass, Severity::Info, format!("reverse DNS of {ip} confirms"), format!("PTR {ev} resolves back to {ip} (forward-confirmed)")).target(&t).evidence("PTR", ev)
                    } else if confirmed {
                        Check::new("dns.mx.ptr", Scope::Receiving, CAT, Verdict::Warn, Severity::Low, format!("generic reverse DNS for {ip}"), format!("PTR {ev} looks like a provider's default name; receivers treat mail from such hosts with suspicion if it also sends")).target(&t).evidence("PTR", ev).fix_summary(format!("Set the PTR of {ip} to {host}"))
                    } else {
                        Check::new("dns.mx.ptr", Scope::Receiving, CAT, Verdict::Warn, Severity::Medium, format!("reverse DNS of {ip} does not confirm"), format!("PTR {ev} does not resolve back to {ip} — not forward-confirmed (FCrDNS); receivers reject mail from such hosts if it also sends")).target(&t).evidence("PTR", ev).fix_summary(format!("Set the PTR of {ip} to {host} and make sure {host} resolves to {ip}"))
                    });
                }
                Err(e) => checks.push(unknown("dns.mx.ptr", Scope::Receiving, &format!("reverse DNS of {ip}"), &e).target(&t)),
            }
        }
        (checks, vec![])
    })
}

fn apex_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let r = match ctx.dns.query(d, RType::A) {
        Ok(r) => r,
        Err(e) => {
            return (
                vec![unknown("dns.apex_cname", Scope::Sending, "apex", &e)],
                vec![],
            )
        }
    };
    (
        vec![match r.cname_of(d) {
            Some(t) => Check::new("dns.apex_cname", Scope::Sending, CAT, Verdict::Fail, Severity::High, format!("{d} is a CNAME"), format!("the domain itself aliases {t}. A CNAME cannot coexist with MX, TXT (SPF/DMARC) or NS records (RFC 1034 §3.6.2) — resolvers ignore them, so mail for the domain is undefined"))
                .evidence("CNAME", format!("{d}. IN CNAME {t}."))
                .fix_summary(format!("Replace the CNAME at {d} with A/AAAA records (or an ALIAS/ANAME at the DNS host) so MX and TXT records can exist")),
            None => Check::new("dns.apex_cname", Scope::Sending, CAT, Verdict::Pass, Severity::Info, "no CNAME at the domain apex", "MX and TXT records can coexist with the domain's address records"),
        }],
        vec![],
    )
}

/// The always-present note that an address alone proves nothing about the mailbox.
pub fn meta_task() -> Task {
    Task::new("meta.mailbox", &[], |ctx, _| {
        (
            vec![Check::new(
                "meta.mailbox",
                Scope::Receiving,
                Category::Meta,
                Verdict::Unknown,
                Severity::Info,
                format!("does {} exist?", ctx.inputs.address),
                "an address alone cannot prove that the mailbox exists, that its mail authenticates, or that it lands in the inbox. Use the server audit for a locally hosted address, or the diagnostic inbox / a test message to see real results",
            )],
            vec![],
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_and_soa_heuristics() {
        assert!(generic_ptr("static.88-198-1-2.clients.your-server.de"));
        assert!(generic_ptr("ip-10-1-2-3.eu-west-1.compute.internal"));
        assert!(generic_ptr("78-47-94-167.dynamic.example.net"));
        assert!(!generic_ptr("mail.example.com"));
        assert!(!generic_ptr("ncc.transfervda.com"));
        assert!(soa_problems(3600, 900, 1209600, 3600).is_empty());
        let p = soa_problems(3600, 7200, 1800, 172800);
        assert_eq!(p.len(), 3);
        assert!(
            soa_problems(900, 900, 1800, 60).is_empty(),
            "google-style short timers are a choice, not a fault"
        );
    }
}
