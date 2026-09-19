//! SPF (RFC 7208): parse a record, walk its includes and redirects counting
//! the DNS lookups receivers count, and evaluate a sending address against
//! it. The walker keeps going past the ten-lookup limit (to a bound) so the
//! report can name what to drop; the evaluator treats `exists` and `ptr`
//! conservatively (no match, noted) rather than emulating them.

use crate::dns::{Client, DnsError};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

impl Qualifier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Qualifier::Pass => "+",
            Qualifier::Fail => "-",
            Qualifier::SoftFail => "~",
            Qualifier::Neutral => "?",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mech {
    All,
    Include(String),
    A {
        domain: Option<String>,
        cidr4: u8,
        cidr6: u8,
    },
    Mx {
        domain: Option<String>,
        cidr4: u8,
        cidr6: u8,
    },
    Ptr(Option<String>),
    Ip4(Ipv4Addr, u8),
    Ip6(Ipv6Addr, u8),
    Exists(String),
}

impl Mech {
    /// Mechanisms that cost a DNS lookup per RFC 7208 §4.6.4.
    pub fn costs_lookup(&self) -> bool {
        matches!(
            self,
            Mech::Include(_) | Mech::A { .. } | Mech::Mx { .. } | Mech::Ptr(_) | Mech::Exists(_)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    pub q: Qualifier,
    pub m: Mech,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub raw: String,
    pub terms: Vec<Term>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    /// Modifiers other than redirect/exp (kept, ignored).
    pub other_modifiers: Vec<String>,
    pub uses_macros: bool,
}

impl SpfRecord {
    pub fn all_qualifier(&self) -> Option<Qualifier> {
        self.terms.iter().find(|t| t.m == Mech::All).map(|t| t.q)
    }
    pub fn lookup_terms(&self) -> usize {
        self.terms.iter().filter(|t| t.m.costs_lookup()).count()
            + usize::from(self.redirect.is_some())
    }
}

fn split_domain_cidr(spec: &str) -> Result<(Option<String>, u8, u8), String> {
    // spec: [domain][/cidr4][//cidr6]
    let (rest, cidr6) = match spec.split_once("//") {
        Some((r, c)) => (
            r,
            c.parse::<u8>()
                .map_err(|_| format!("bad IPv6 prefix length '{c}'"))?,
        ),
        None => (spec, 128),
    };
    let (dom, cidr4) = match rest.split_once('/') {
        Some((d, c)) => (
            d,
            c.parse::<u8>()
                .map_err(|_| format!("bad IPv4 prefix length '{c}'"))?,
        ),
        None => (rest, 32),
    };
    if cidr4 > 32 || cidr6 > 128 {
        return Err("prefix length out of range".into());
    }
    let dom = if dom.is_empty() {
        None
    } else {
        Some(dom.to_string())
    };
    Ok((dom, cidr4, cidr6))
}

/// Parse one `v=spf1 …` record.
pub fn parse(txt: &str) -> Result<SpfRecord, String> {
    let raw = txt.trim().to_string();
    let mut toks = raw.split_whitespace();
    match toks.next() {
        Some(v) if v.eq_ignore_ascii_case("v=spf1") => {}
        _ => return Err("does not start with v=spf1".into()),
    }
    let mut rec = SpfRecord {
        raw: raw.clone(),
        terms: Vec::new(),
        redirect: None,
        exp: None,
        other_modifiers: Vec::new(),
        uses_macros: raw.contains("%{"),
    };
    let mut seen_all = false;
    for tok in toks {
        if seen_all {
            return Err(format!(
                "'{tok}' comes after 'all' and is ignored by receivers — remove it"
            ));
        }
        let lower = tok.to_ascii_lowercase();
        if let Some((name, val)) = lower.split_once('=') {
            // modifier
            if name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
                && !name.is_empty()
            {
                match name {
                    "redirect" => {
                        if rec.redirect.is_some() {
                            return Err("two redirect= modifiers".into());
                        }
                        rec.redirect = Some(val.to_string());
                    }
                    "exp" => rec.exp = Some(val.to_string()),
                    _ => rec.other_modifiers.push(tok.to_string()),
                }
                continue;
            }
        }
        let (q, body) = match lower.chars().next() {
            Some('+') => (Qualifier::Pass, &lower[1..]),
            Some('-') => (Qualifier::Fail, &lower[1..]),
            Some('~') => (Qualifier::SoftFail, &lower[1..]),
            Some('?') => (Qualifier::Neutral, &lower[1..]),
            _ => (Qualifier::Pass, lower.as_str()),
        };
        let (name, arg) = match body.split_once(':') {
            Some((n, a)) => (n, Some(a)),
            None => match body.split_once('/') {
                Some((n, _)) if !matches!(n, "ip4" | "ip6") => (n, Some(&body[n.len()..])),
                _ => (body, None),
            },
        };
        let m = match name {
            "all" => {
                if arg.is_some() {
                    return Err("'all' takes no argument".into());
                }
                seen_all = true;
                Mech::All
            }
            "include" => Mech::Include(
                arg.filter(|a| !a.is_empty())
                    .ok_or("include needs a domain")?
                    .to_string(),
            ),
            "exists" => Mech::Exists(
                arg.filter(|a| !a.is_empty())
                    .ok_or("exists needs a domain")?
                    .to_string(),
            ),
            "a" | "mx" => {
                let (domain, cidr4, cidr6) =
                    split_domain_cidr(arg.unwrap_or("").trim_start_matches(':'))?;
                if name == "a" {
                    Mech::A {
                        domain,
                        cidr4,
                        cidr6,
                    }
                } else {
                    Mech::Mx {
                        domain,
                        cidr4,
                        cidr6,
                    }
                }
            }
            "ptr" => Mech::Ptr(arg.filter(|a| !a.is_empty()).map(str::to_string)),
            "ip4" => {
                let a = arg.ok_or("ip4 needs an address")?;
                let (ip, cidr) = match a.split_once('/') {
                    Some((i, c)) => (
                        i,
                        c.parse::<u8>()
                            .map_err(|_| format!("bad prefix length in ip4:{a}"))?,
                    ),
                    None => (a, 32),
                };
                let ip: Ipv4Addr = ip
                    .parse()
                    .map_err(|_| format!("'{a}' is not an IPv4 address"))?;
                if cidr > 32 {
                    return Err(format!("prefix length out of range in ip4:{a}"));
                }
                Mech::Ip4(ip, cidr)
            }
            "ip6" => {
                let a = arg.ok_or("ip6 needs an address")?;
                let (ip, cidr) = match a.rsplit_once('/') {
                    Some((i, c)) if !i.contains("//") => (
                        i,
                        c.parse::<u8>()
                            .map_err(|_| format!("bad prefix length in ip6:{a}"))?,
                    ),
                    _ => (a, 128),
                };
                let ip: Ipv6Addr = ip
                    .parse()
                    .map_err(|_| format!("'{a}' is not an IPv6 address"))?;
                if cidr > 128 {
                    return Err(format!("prefix length out of range in ip6:{a}"));
                }
                Mech::Ip6(ip, cidr)
            }
            _ => return Err(format!("unknown mechanism '{tok}'")),
        };
        rec.terms.push(Term {
            q,
            m,
            raw: tok.to_string(),
        });
    }
    if seen_all && rec.redirect.is_some() {
        return Err("redirect= together with 'all' — the redirect is never used".into());
    }
    Ok(rec)
}

/// Split a long record into ≤255-byte strings at spaces, for a fix text.
pub fn split_txt_strings(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for tok in raw.split_whitespace() {
        let add = if cur.is_empty() {
            tok.len()
        } else {
            tok.len() + 1
        };
        if cur.len() + add > 255 && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(tok);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// What the SPF records at `domain` look like: `(records, lookup error)`.
pub fn records_at(client: &Client, domain: &str) -> Result<Vec<String>, DnsError> {
    Ok(client
        .txt(domain)?
        .into_iter()
        .filter(|t| t.trim_start().to_ascii_lowercase().starts_with("v=spf1"))
        .collect())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Walk {
    /// DNS-lookup terms encountered (RFC 7208 counts these against 10).
    pub lookups: u32,
    /// Lookups that returned no records (limit 2).
    pub void_lookups: u32,
    pub loops: Vec<String>,
    pub missing_includes: Vec<String>,
    pub errors: Vec<String>,
    /// (domain, raw record) in walk order.
    pub records: Vec<(String, String)>,
    pub all_qualifier: Option<Qualifier>,
    pub uses_ptr: bool,
    pub uses_macros: bool,
    /// Addresses authorised through ip4/ip6 terms: (v4 count, v6 /64 count).
    pub ip_count: (u64, u64),
    pub depth_exceeded: bool,
    /// The lookup terms in order, for the "drop these" advice.
    pub lookup_terms: Vec<String>,
}

const MAX_DEPTH: usize = 10;
const MAX_TOTAL_LOOKUPS: u32 = 30;

/// Walk `domain`'s SPF record and everything it pulls in.
pub fn walk(client: &Client, domain: &str) -> Walk {
    let mut w = Walk::default();
    let mut visited: HashSet<String> = HashSet::new();
    walk_into(client, domain, 0, &mut visited, &mut w, true);
    w
}

fn walk_into(
    client: &Client,
    domain: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    w: &mut Walk,
    top: bool,
) {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if depth > MAX_DEPTH {
        w.depth_exceeded = true;
        return;
    }
    if !visited.insert(d.clone()) {
        w.loops.push(d);
        return;
    }
    let recs = match records_at(client, &d) {
        Ok(r) => r,
        Err(e) => {
            w.errors.push(format!("{d}: {e}"));
            return;
        }
    };
    if recs.is_empty() {
        if !top {
            w.missing_includes.push(d.clone());
            w.void_lookups += 1;
        }
        return;
    }
    let rec = match parse(&recs[0]) {
        Ok(r) => r,
        Err(e) => {
            w.errors.push(format!("{d}: {e}"));
            w.records.push((d.clone(), recs[0].clone()));
            return;
        }
    };
    w.records.push((d.clone(), rec.raw.clone()));
    if top {
        w.all_qualifier = rec.all_qualifier();
        w.uses_macros = rec.uses_macros;
    } else if rec.uses_macros {
        w.uses_macros = true;
    }
    for t in &rec.terms {
        match &t.m {
            Mech::Ip4(_, c) => w.ip_count.0 += 1u64 << (32 - *c as u32).min(63),
            Mech::Ip6(_, c) => w.ip_count.1 += 1u64 << (64u32.saturating_sub(*c as u32)).min(63),
            _ => {}
        }
        if t.m.costs_lookup() {
            w.lookups += 1;
            w.lookup_terms.push(format!("{d}: {}", t.raw));
            if w.lookups > MAX_TOTAL_LOOKUPS {
                w.depth_exceeded = true;
                return;
            }
        }
        match &t.m {
            Mech::Include(inc) => walk_into(client, inc, depth + 1, visited, w, false),
            Mech::A { domain: dom, .. } => {
                let target = dom.clone().unwrap_or_else(|| d.clone());
                if let Ok((v4, v6)) = client.addrs(&target) {
                    if v4.is_empty() && v6.is_empty() {
                        w.void_lookups += 1;
                    }
                }
            }
            Mech::Mx { domain: dom, .. } => {
                let target = dom.clone().unwrap_or_else(|| d.clone());
                match client.mx(&target) {
                    Ok(mx) if mx.is_empty() => w.void_lookups += 1,
                    Ok(mx) => {
                        // each MX host's A/AAAA counts too (max 10 per RFC)
                        for (_, h) in mx.iter().take(10) {
                            let _ = client.addrs(h);
                        }
                    }
                    Err(_) => {}
                }
            }
            Mech::Ptr(_) => w.uses_ptr = true,
            Mech::Exists(_) => {}
            _ => {}
        }
    }
    if let Some(r) = &rec.redirect {
        w.lookups += 1;
        w.lookup_terms.push(format!("{d}: redirect={r}"));
        walk_into(client, r, depth + 1, visited, w, false);
        // the redirected record's `all` is what applies
        if top {
            let target = r.trim_end_matches('.').to_ascii_lowercase();
            if let Some((_, raw)) = w.records.iter().find(|(dom, _)| *dom == target) {
                if let Ok(rr) = parse(raw) {
                    w.all_qualifier = rr.all_qualifier();
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    PermError,
    TempError,
}

impl SpfResult {
    pub fn as_str(&self) -> &'static str {
        match self {
            SpfResult::Pass => "pass",
            SpfResult::Fail => "fail",
            SpfResult::SoftFail => "softfail",
            SpfResult::Neutral => "neutral",
            SpfResult::None => "none",
            SpfResult::PermError => "permerror",
            SpfResult::TempError => "temperror",
        }
    }
}

fn v4_in(ip: Ipv4Addr, net: Ipv4Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - cidr as u32);
    u32::from(ip) & mask == u32::from(net) & mask
}

fn v6_in(ip: Ipv6Addr, net: Ipv6Addr, cidr: u8) -> bool {
    if cidr == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - cidr as u32);
    u128::from(ip) & mask == u128::from(net) & mask
}

fn ip_in(ip: IpAddr, v4: &[Ipv4Addr], v6: &[Ipv6Addr], cidr4: u8, cidr6: u8) -> bool {
    match ip {
        IpAddr::V4(a) => v4.iter().any(|n| v4_in(a, *n, cidr4)),
        IpAddr::V6(a) => v6.iter().any(|n| v6_in(a, *n, cidr6)),
    }
}

/// Evaluate `ip` as the connecting address for MAIL FROM at `domain`.
/// Returns the result and a trace of what matched.
pub fn evaluate(client: &Client, domain: &str, ip: IpAddr) -> (SpfResult, Vec<String>) {
    let mut trace = Vec::new();
    let mut lookups = 0u32;
    let mut visited = HashSet::new();
    let r = eval_domain(
        client,
        domain,
        ip,
        &mut lookups,
        &mut visited,
        &mut trace,
        0,
    );
    (r, trace)
}

fn eval_domain(
    client: &Client,
    domain: &str,
    ip: IpAddr,
    lookups: &mut u32,
    visited: &mut HashSet<String>,
    trace: &mut Vec<String>,
    depth: usize,
) -> SpfResult {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if depth > MAX_DEPTH || !visited.insert(d.clone()) {
        trace.push(format!("{d}: include loop or too deep → permerror"));
        return SpfResult::PermError;
    }
    let recs = match records_at(client, &d) {
        Ok(r) => r,
        Err(DnsError::Timeout) | Err(DnsError::ServFail) => {
            trace.push(format!("{d}: DNS did not answer → temperror"));
            return SpfResult::TempError;
        }
        Err(e) => {
            trace.push(format!("{d}: {e} → temperror"));
            return SpfResult::TempError;
        }
    };
    if recs.is_empty() {
        trace.push(format!("{d}: no SPF record → none"));
        return SpfResult::None;
    }
    if recs.len() > 1 {
        trace.push(format!("{d}: {} SPF records → permerror", recs.len()));
        return SpfResult::PermError;
    }
    let rec = match parse(&recs[0]) {
        Ok(r) => r,
        Err(e) => {
            trace.push(format!("{d}: {e} → permerror"));
            return SpfResult::PermError;
        }
    };
    for t in &rec.terms {
        if t.m.costs_lookup() {
            *lookups += 1;
            if *lookups > 10 {
                trace.push(format!("{d}: more than 10 DNS lookups → permerror"));
                return SpfResult::PermError;
            }
        }
        let matched = match &t.m {
            Mech::All => true,
            Mech::Ip4(n, c) => matches!(ip, IpAddr::V4(a) if v4_in(a, *n, *c)),
            Mech::Ip6(n, c) => matches!(ip, IpAddr::V6(a) if v6_in(a, *n, *c)),
            Mech::A {
                domain: dom,
                cidr4,
                cidr6,
            } => {
                let target = dom.clone().unwrap_or_else(|| d.clone());
                match client.addrs(&target) {
                    Ok((v4, v6)) => ip_in(ip, &v4, &v6, *cidr4, *cidr6),
                    Err(_) => false,
                }
            }
            Mech::Mx {
                domain: dom,
                cidr4,
                cidr6,
            } => {
                let target = dom.clone().unwrap_or_else(|| d.clone());
                match client.mx(&target) {
                    Ok(mx) => mx.iter().take(10).any(|(_, h)| {
                        client
                            .addrs(h)
                            .map(|(v4, v6)| ip_in(ip, &v4, &v6, *cidr4, *cidr6))
                            .unwrap_or(false)
                    }),
                    Err(_) => false,
                }
            }
            Mech::Include(inc) => {
                match eval_domain(client, inc, ip, lookups, visited, trace, depth + 1) {
                    SpfResult::Pass => true,
                    SpfResult::PermError => {
                        trace.push(format!("{d}: include:{inc} → permerror"));
                        return SpfResult::PermError;
                    }
                    SpfResult::TempError => return SpfResult::TempError,
                    _ => false,
                }
            }
            Mech::Ptr(_) => {
                trace.push(format!(
                    "{d}: ptr mechanism not evaluated (deprecated) — treated as no match"
                ));
                false
            }
            Mech::Exists(_) => {
                trace.push(format!("{d}: exists mechanism not evaluated (needs macro expansion) — treated as no match"));
                false
            }
        };
        if matched {
            let r = match t.q {
                Qualifier::Pass => SpfResult::Pass,
                Qualifier::Fail => SpfResult::Fail,
                Qualifier::SoftFail => SpfResult::SoftFail,
                Qualifier::Neutral => SpfResult::Neutral,
            };
            trace.push(format!("{d}: matched {} → {}", t.raw, r.as_str()));
            return r;
        }
    }
    if let Some(r) = &rec.redirect {
        *lookups += 1;
        trace.push(format!("{d}: redirect={r}"));
        return match eval_domain(client, r, ip, lookups, visited, trace, depth + 1) {
            SpfResult::None => SpfResult::PermError,
            other => other,
        };
    }
    trace.push(format!("{d}: no mechanism matched → neutral"));
    SpfResult::Neutral
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::testsupport::start as fake;
    use crate::dns::{RData, Rr};

    #[test]
    fn parses_records_and_rejects_bad_ones() {
        let r = parse("v=spf1 mx a:mail.example.com ip4:192.0.2.0/24 ip6:2001:db8::/32 include:_spf.google.com ~all").unwrap();
        assert_eq!(r.terms.len(), 6);
        assert_eq!(r.all_qualifier(), Some(Qualifier::SoftFail));
        assert_eq!(r.lookup_terms(), 3);
        assert_eq!(
            r.terms[1].m,
            Mech::A {
                domain: Some("mail.example.com".into()),
                cidr4: 32,
                cidr6: 128
            }
        );
        assert_eq!(r.terms[2].m, Mech::Ip4("192.0.2.0".parse().unwrap(), 24));
        assert_eq!(r.terms[3].m, Mech::Ip6("2001:db8::".parse().unwrap(), 32));
        let r = parse("V=SPF1 a/24//64 mx:other.example/28 -all").unwrap();
        assert_eq!(
            r.terms[0].m,
            Mech::A {
                domain: None,
                cidr4: 24,
                cidr6: 64
            }
        );
        assert_eq!(
            r.terms[1].m,
            Mech::Mx {
                domain: Some("other.example".into()),
                cidr4: 28,
                cidr6: 128
            }
        );
        let r = parse("v=spf1 redirect=_spf.example.com").unwrap();
        assert_eq!(r.redirect.as_deref(), Some("_spf.example.com"));
        assert_eq!(r.all_qualifier(), None);
        let r = parse("v=spf1 exists:%{i}._spf.example.com ?all").unwrap();
        assert!(r.uses_macros);
        assert_eq!(r.all_qualifier(), Some(Qualifier::Neutral));
        assert!(parse("v=spf1 +all").unwrap().all_qualifier() == Some(Qualifier::Pass));
        for bad in [
            "v=spf2 -all",
            "v=spf1 ip4:300.1.1.1 -all",
            "v=spf1 ip4:1.2.3.4/33 -all",
            "v=spf1 frob:x -all",
            "v=spf1 -all ip4:1.2.3.4",
            "v=spf1 include: -all",
            "v=spf1 redirect=x -all",
            "v=spf1 all:x",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn splits_long_records_at_spaces() {
        let raw = format!(
            "v=spf1 {} -all",
            (0..30)
                .map(|i| format!("ip4:192.0.2.{i}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let parts = split_txt_strings(&raw);
        assert!(parts.len() >= 2);
        assert!(parts.iter().all(|p| p.len() <= 255));
        assert_eq!(parts.join(" "), raw);
    }

    fn txt(name: &str, v: &str) -> Rr {
        Rr {
            name: name.into(),
            rtype: 16,
            ttl: 300,
            data: RData::Txt(vec![v.into()]),
        }
    }

    #[test]
    fn walk_and_evaluate_over_a_fake_zone() {
        let srv = fake(
            Box::new(|name, rtype| {
                match (name, rtype) {
                ("example.com", 16) => Some((0, vec![txt("example.com", "v=spf1 mx ip4:203.0.113.0/24 include:vendor.example include:missing.example include:loop.example ~all")], false)),
                ("example.com", 15) => Some((0, vec![Rr { name: "example.com".into(), rtype: 15, ttl: 1, data: RData::Mx { pref: 10, host: "mail.example.com".into() } }], false)),
                ("mail.example.com", 1) => Some((0, vec![Rr { name: name.into(), rtype: 1, ttl: 1, data: RData::A("198.51.100.5".parse().unwrap()) }], false)),
                ("vendor.example", 16) => Some((0, vec![txt("vendor.example", "v=spf1 ip4:192.0.2.0/24 a:relay.vendor.example ptr -all")], false)),
                ("relay.vendor.example", 1) => Some((0, vec![], false)),
                ("missing.example", 16) => Some((0, vec![], false)),
                ("loop.example", 16) => Some((0, vec![txt("loop.example", "v=spf1 include:example.com -all")], false)),
                ("redir.example", 16) => Some((0, vec![txt("redir.example", "v=spf1 redirect=example.com")], false)),
                ("clean.example", 16) => Some((0, vec![txt("clean.example", "v=spf1 ip4:203.0.113.0/24 ~all")], false)),
                ("redir2.example", 16) => Some((0, vec![txt("redir2.example", "v=spf1 redirect=clean.example")], false)),
                ("many.example", 16) => Some((0, vec![txt("many.example", &format!("v=spf1 {} -all", (0..12).map(|i| format!("include:i{i}.example")).collect::<Vec<_>>().join(" ")))], false)),
                (n, 16) if n.starts_with('i') && n.ends_with(".example") => Some((0, vec![txt(n, "v=spf1 -all")], false)),
                ("two.example", 16) => Some((0, vec![txt("two.example", "v=spf1 -all"), txt("two.example", "v=spf1 +all")], false)),
                _ => Some((0, vec![], false)),
            }
            }),
            false,
        );
        let mut c = Client::at(srv.addr);
        c.timeout = std::time::Duration::from_millis(500);
        let w = walk(&c, "example.com");
        assert_eq!(w.records.len(), 3, "{w:?}");
        assert_eq!(w.all_qualifier, Some(Qualifier::SoftFail));
        assert_eq!(
            w.lookups, 7,
            "mx, 3 includes, a:relay, ptr, and the include inside loop.example"
        );
        assert_eq!(
            w.void_lookups, 2,
            "missing.example and relay.vendor.example"
        );
        assert_eq!(w.missing_includes, vec!["missing.example"]);
        assert_eq!(w.loops, vec!["example.com"]);
        assert!(w.uses_ptr);
        assert_eq!(w.ip_count.0, 512);
        assert!(!w.depth_exceeded);
        let w = walk(&c, "many.example");
        assert_eq!(w.lookups, 12);
        let w = walk(&c, "redir.example");
        assert_eq!(
            w.all_qualifier,
            Some(Qualifier::SoftFail),
            "the redirect target's all applies"
        );

        let (r, trace) = evaluate(&c, "example.com", "198.51.100.5".parse().unwrap());
        assert_eq!(r, SpfResult::Pass, "{trace:?}");
        assert!(trace.iter().any(|t| t.contains("matched mx")));
        assert_eq!(
            evaluate(&c, "example.com", "203.0.113.77".parse().unwrap()).0,
            SpfResult::Pass
        );
        assert_eq!(
            evaluate(&c, "example.com", "192.0.2.9".parse().unwrap()).0,
            SpfResult::Pass,
            "via include:vendor"
        );
        assert_eq!(
            evaluate(&c, "example.com", "8.8.8.8".parse().unwrap()).0,
            SpfResult::PermError,
            "nothing matched before the include loop, which is a permerror"
        );
        assert_eq!(
            evaluate(&c, "clean.example", "8.8.8.8".parse().unwrap()).0,
            SpfResult::SoftFail
        );
        assert_eq!(
            evaluate(&c, "redir2.example", "8.8.8.8".parse().unwrap()).0,
            SpfResult::SoftFail
        );
        assert_eq!(
            evaluate(&c, "nospf.example", "8.8.8.8".parse().unwrap()).0,
            SpfResult::None
        );
        assert_eq!(
            evaluate(&c, "two.example", "8.8.8.8".parse().unwrap()).0,
            SpfResult::PermError
        );
        assert_eq!(
            evaluate(&c, "many.example", "8.8.8.8".parse().unwrap()).0,
            SpfResult::PermError,
            "over 10 lookups"
        );
        assert!(v6_in(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
        assert!(!v6_in(
            "2001:db9::1".parse().unwrap(),
            "2001:db8::".parse().unwrap(),
            32
        ));
    }
}
