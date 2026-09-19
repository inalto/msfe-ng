//! DNS blocklists (and one allowlist) the delivery test consults: a curated
//! table with each list's return codes, its "not serving you" answers and
//! the removal page, a query function that tells a listing from a refusal
//! or an outage, and a short cache so a run does not ask twice.

use crate::delivery::Severity;
use crate::dns::{Client, DnsError, RData, RType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// IPv4 addresses (reversed octets).
    Ip4,
    /// IPv6 addresses (reversed nibbles).
    Ip6,
    /// Domain names.
    Domain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    Block,
    Allow,
}

/// What a return code means: `prefix` matches the first three octets
/// (255 = any), `last` the fourth (`None` = any).
#[derive(Debug, Clone, Copy)]
pub struct Code {
    pub prefix: [u8; 3],
    pub last: Option<u8>,
    pub meaning: &'static str,
    pub severity: Severity,
}

impl Code {
    fn prefix_matches(&self, o: [u8; 4]) -> bool {
        self.prefix
            .iter()
            .zip(o.iter())
            .all(|(p, x)| *p == 255 || p == x)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Dnsbl {
    pub zone: &'static str,
    pub name: &'static str,
    pub kinds: &'static [Kind],
    pub polarity: Polarity,
    pub codes: &'static [Code],
    /// Answers that mean "this resolver is not served", not "listed".
    pub refusals: &'static [(Ipv4Addr, &'static str)],
    pub removal_url: &'static str,
    /// How much a listing here matters for a sender.
    pub note: &'static str,
}

const fn code(prefix: [u8; 3], last: u8, meaning: &'static str, severity: Severity) -> Code {
    Code {
        prefix,
        last: if last == 0 { None } else { Some(last) },
        meaning,
        severity,
    }
}

/// A code whose last octet is significant even when it is 0.
const fn exact(prefix: [u8; 3], last: u8, meaning: &'static str, severity: Severity) -> Code {
    Code {
        prefix,
        last: Some(last),
        meaning,
        severity,
    }
}

const SPAMHAUS_REFUSALS: &[(Ipv4Addr, &str)] = &[
    (
        Ipv4Addr::new(127, 255, 255, 252),
        "typing error in the query",
    ),
    (
        Ipv4Addr::new(127, 255, 255, 254),
        "Spamhaus refuses queries from public/shared resolvers",
    ),
    (
        Ipv4Addr::new(127, 255, 255, 255),
        "Spamhaus query limit exceeded for this resolver",
    ),
];

pub const LISTS: &[Dnsbl] = &[
    Dnsbl {
        zone: "zen.spamhaus.org",
        name: "Spamhaus ZEN",
        kinds: &[Kind::Ip4, Kind::Ip6],
        polarity: Polarity::Block,
        codes: &[
            code([127, 0, 0], 2, "SBL — a known spam source or spam-supporting network", Severity::High),
            code([127, 0, 0], 3, "CSS — snowshoe spam / compromised host", Severity::High),
            code([127, 0, 0], 4, "XBL — infected or hijacked host (CBL)", Severity::High),
            code([127, 0, 0], 5, "XBL — infected or hijacked host", Severity::High),
            code([127, 0, 0], 6, "XBL — infected or hijacked host", Severity::High),
            code([127, 0, 0], 7, "XBL — infected or hijacked host", Severity::High),
            code([127, 0, 0], 9, "SBL DROP — hijacked or criminal network", Severity::Critical),
            code([127, 0, 0], 10, "PBL — ISP-declared end-user/dynamic range: should not send mail directly", Severity::Medium),
            code([127, 0, 0], 11, "PBL — Spamhaus-declared end-user/dynamic range: should not send mail directly", Severity::Medium),
        ],
        refusals: SPAMHAUS_REFUSALS,
        removal_url: "https://check.spamhaus.org/",
        note: "the most widely used blocklist; Gmail, Microsoft and most MTAs reject or penalise listed senders",
    },
    Dnsbl {
        zone: "dbl.spamhaus.org",
        name: "Spamhaus DBL",
        kinds: &[Kind::Domain],
        polarity: Polarity::Block,
        codes: &[
            code([127, 0, 1], 2, "spam domain", Severity::High),
            code([127, 0, 1], 4, "phishing domain", Severity::High),
            code([127, 0, 1], 5, "malware domain", Severity::High),
            code([127, 0, 1], 6, "botnet C&C domain", Severity::High),
            code([127, 0, 1], 102, "abused legitimate domain (spam)", Severity::Medium),
            code([127, 0, 1], 103, "abused legitimate redirector", Severity::Medium),
            code([127, 0, 1], 104, "abused legitimate domain (phishing)", Severity::Medium),
            code([127, 0, 1], 105, "abused legitimate domain (malware)", Severity::Medium),
            code([127, 0, 1], 106, "abused legitimate domain (botnet)", Severity::Medium),
        ],
        refusals: &[
            (Ipv4Addr::new(127, 0, 1, 255), "the query was an IP address, not a domain"),
            (Ipv4Addr::new(127, 255, 255, 252), "typing error in the query"),
            (Ipv4Addr::new(127, 255, 255, 254), "Spamhaus refuses queries from public/shared resolvers"),
            (Ipv4Addr::new(127, 255, 255, 255), "Spamhaus query limit exceeded for this resolver"),
        ],
        removal_url: "https://check.spamhaus.org/",
        note: "a domain listing means mail mentioning or sent from the domain is blocked or filtered by most receivers",
    },
    Dnsbl {
        zone: "bl.spamcop.net",
        name: "SpamCop",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "reported as a spam source by SpamCop users", Severity::High)],
        refusals: &[],
        removal_url: "https://www.spamcop.net/bl.shtml",
        note: "listings expire automatically (about 24 h after the last report) — recurring listings point at a real problem",
    },
    Dnsbl {
        zone: "b.barracudacentral.org",
        name: "Barracuda",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "poor reputation at Barracuda", Severity::High)],
        refusals: &[],
        removal_url: "https://www.barracudacentral.org/rbl/removal-request",
        note: "used by Barracuda appliances and many corporate gateways",
    },
    Dnsbl {
        zone: "dnsbl-1.uceprotect.net",
        name: "UCEPROTECT level 1",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "this address sent spam to UCEPROTECT traps in the last 7 days", Severity::Medium)],
        refusals: &[],
        removal_url: "https://www.uceprotect.net/en/rblcheck.php",
        note: "expires 7 days after the last incident; paid express removal is not worth it",
    },
    Dnsbl {
        zone: "dnsbl-2.uceprotect.net",
        name: "UCEPROTECT level 2",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "the whole allocation (network) is listed because of other senders in it", Severity::Low)],
        refusals: &[],
        removal_url: "https://www.uceprotect.net/en/rblcheck.php",
        note: "a network-wide listing, not about this address; few receivers use level 2/3 for rejection",
    },
    Dnsbl {
        zone: "dnsbl-3.uceprotect.net",
        name: "UCEPROTECT level 3",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "the whole ASN is listed because of other senders in it", Severity::Low)],
        refusals: &[],
        removal_url: "https://www.uceprotect.net/en/rblcheck.php",
        note: "an ASN-wide listing (the hosting provider), not about this address",
    },
    Dnsbl {
        zone: "psbl.surriel.com",
        name: "PSBL",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "sent spam to PSBL traps", Severity::Medium)],
        refusals: &[],
        removal_url: "https://psbl.org/remove",
        note: "self-service removal; used by SpamAssassin",
    },
    Dnsbl {
        zone: "bl.mailspike.net",
        name: "Mailspike",
        kinds: &[Kind::Ip4],
        polarity: Polarity::Block,
        codes: &[
            code([127, 0, 0], 2, "worst possible reputation", Severity::High),
            code([127, 0, 0], 10, "very bad reputation", Severity::Medium),
            code([127, 0, 0], 11, "bad reputation", Severity::Medium),
            code([127, 0, 0], 12, "poor reputation", Severity::Low),
            code([127, 0, 0], 0, "listed", Severity::Medium),
        ],
        refusals: &[],
        removal_url: "https://mailspike.org/iplookup.html",
        note: "reputation list used by SpamAssassin",
    },
    Dnsbl {
        zone: "all.s5h.net",
        name: "s5h.net",
        kinds: &[Kind::Ip4, Kind::Ip6],
        polarity: Polarity::Block,
        codes: &[code([127, 0, 0], 0, "listed at s5h.net", Severity::Medium)],
        refusals: &[],
        removal_url: "https://www.usenix.org.uk/content/rbl.html",
        note: "a smaller list with automatic expiry",
    },
    Dnsbl {
        zone: "multi.surbl.org",
        name: "SURBL",
        kinds: &[Kind::Domain],
        polarity: Polarity::Block,
        codes: &[
            code([127, 0, 0], 8, "phishing", Severity::High),
            code([127, 0, 0], 16, "malware", Severity::High),
            code([127, 0, 0], 64, "abuse (spam)", Severity::High),
            code([127, 0, 0], 128, "cracked site", Severity::High),
            code([127, 0, 0], 0, "listed (combined flags)", Severity::High),
        ],
        refusals: &[(Ipv4Addr::new(127, 0, 0, 1), "SURBL refuses this resolver (public, or over its query limit)")],
        removal_url: "https://surbl.org/surbl-analysis",
        note: "URI blocklist: mail containing links to a listed domain is filtered",
    },
    Dnsbl {
        zone: "multi.uribl.com",
        name: "URIBL",
        kinds: &[Kind::Domain],
        polarity: Polarity::Block,
        codes: &[
            code([127, 0, 0], 2, "black — spam domain", Severity::High),
            code([127, 0, 0], 4, "grey — mixed use", Severity::Medium),
            code([127, 0, 0], 8, "red — very recent spam", Severity::High),
            code([127, 0, 0], 14, "black + grey + red", Severity::High),
            code([127, 0, 0], 0, "listed (combined flags)", Severity::High),
        ],
        refusals: &[(Ipv4Addr::new(127, 0, 0, 1), "URIBL refuses this resolver (public, or over its query limit)")],
        removal_url: "https://admin.uribl.com/",
        note: "URI blocklist used by SpamAssassin",
    },
    Dnsbl {
        zone: "list.dnswl.org",
        name: "DNSWL",
        kinds: &[Kind::Ip4, Kind::Ip6],
        polarity: Polarity::Allow,
        codes: &[
            exact([127, 0, 255], 0, "trust none (listed, no reputation yet)", Severity::Info),
            exact([127, 0, 255], 1, "trust low", Severity::Info),
            exact([127, 0, 255], 2, "trust medium", Severity::Info),
            exact([127, 0, 255], 3, "trust high", Severity::Info),
        ],
        refusals: &[(Ipv4Addr::new(127, 0, 0, 255), "DNSWL query limit exceeded for this resolver")],
        removal_url: "https://www.dnswl.org/?page_id=15",
        note: "an allowlist: being listed lowers spam scores at receivers that use it",
    },
];

/// Lists that cover `kind`.
pub fn lists_for(kind: Kind) -> Vec<&'static Dnsbl> {
    LISTS.iter().filter(|l| l.kinds.contains(&kind)).collect()
}

pub fn by_zone(zone: &str) -> Option<&'static Dnsbl> {
    LISTS.iter().find(|l| l.zone == zone)
}

/// One listing code with its meaning.
#[derive(Debug, Clone, PartialEq)]
pub struct Listing {
    pub code: Ipv4Addr,
    pub meaning: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ListVerdict {
    NotListed,
    Listed(Vec<Listing>),
    /// The list answered with a "not serving you" code.
    Refused(String),
    /// No reply (timeout) — not the same as "not listed".
    NoAnswer,
    Error(String),
}

/// The query name for `ip` under `zone`.
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(64);
            for b in v6.octets().iter().rev() {
                s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
                s.push('.');
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push('.');
            }
            s.pop();
            s
        }
    }
}

/// Interpret the A answers of a list query.
pub fn classify(list: &Dnsbl, answers: &[Ipv4Addr]) -> ListVerdict {
    if answers.is_empty() {
        return ListVerdict::NotListed;
    }
    for a in answers {
        if let Some((_, why)) = list.refusals.iter().find(|(r, _)| r == a) {
            return ListVerdict::Refused((*why).to_string());
        }
    }
    let mut listings = Vec::new();
    for a in answers {
        let o = a.octets();
        if o[0] != 127 {
            // not a DNSBL answer at all (a wildcard, a hijacked zone)
            return ListVerdict::Error(format!(
                "unexpected answer {a} — the list may be defunct or the zone hijacked"
            ));
        }
        let exact = list
            .codes
            .iter()
            .find(|c| c.prefix_matches(o) && c.last == Some(o[3]));
        let generic = list
            .codes
            .iter()
            .find(|c| c.prefix_matches(o) && c.last.is_none());
        // SURBL/URIBL combine flags: every set bit that has a meaning
        let bits: Vec<&Code> =
            if exact.is_none() && (list.zone.contains("surbl") || list.zone.contains("uribl")) {
                list.codes
                    .iter()
                    .filter(|c| c.last.is_some_and(|l| l.count_ones() == 1 && o[3] & l != 0))
                    .collect()
            } else {
                Vec::new()
            };
        match (exact, bits.is_empty(), generic) {
            (Some(c), _, _) => listings.push(Listing {
                code: *a,
                meaning: c.meaning.to_string(),
                severity: c.severity,
            }),
            (None, false, _) => {
                for c in bits {
                    listings.push(Listing {
                        code: *a,
                        meaning: c.meaning.to_string(),
                        severity: c.severity,
                    });
                }
            }
            (None, true, Some(c)) => listings.push(Listing {
                code: *a,
                meaning: c.meaning.to_string(),
                severity: c.severity,
            }),
            (None, true, None) => listings.push(Listing {
                code: *a,
                meaning: format!("listed (code {a})"),
                severity: Severity::Medium,
            }),
        }
    }
    ListVerdict::Listed(listings)
}

const CACHE_TTL: Duration = Duration::from_secs(600);
static CACHE: Mutex<Option<HashMap<String, (Instant, ListVerdict)>>> = Mutex::new(None);

/// Query `key` (a reversed IP or a domain) under the list, cached 10 min.
pub fn query(client: &Client, list: &Dnsbl, key: &str) -> ListVerdict {
    let name = format!("{key}.{}", list.zone);
    {
        let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        let c = g.get_or_insert_with(HashMap::new);
        if let Some((at, v)) = c.get(&name) {
            if at.elapsed() < CACHE_TTL {
                return v.clone();
            }
        }
    }
    let v = match client.query(&name, RType::A) {
        Ok(r) => {
            let answers: Vec<Ipv4Addr> = r
                .of(RType::A)
                .iter()
                .filter_map(|rr| match rr.data {
                    RData::A(a) => Some(a),
                    _ => None,
                })
                .collect();
            classify(list, &answers)
        }
        Err(DnsError::Timeout) => ListVerdict::NoAnswer,
        Err(e) => ListVerdict::Error(e.to_string()),
    };
    // outages are not cached: the next run may get through
    if !matches!(v, ListVerdict::NoAnswer | ListVerdict::Error(_)) {
        let mut g = CACHE.lock().unwrap_or_else(|e| e.into_inner());
        g.get_or_insert_with(HashMap::new)
            .insert(name, (Instant::now(), v.clone()));
    }
    v
}

pub fn query_ip(client: &Client, list: &Dnsbl, ip: IpAddr) -> ListVerdict {
    query(client, list, &ip_key(ip))
}

pub fn query_domain(client: &Client, list: &Dnsbl, domain: &str) -> ListVerdict {
    query(client, list, domain.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_codes() {
        assert_eq!(ip_key("78.47.94.167".parse().unwrap()), "167.94.47.78");
        assert_eq!(
            ip_key("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
        );
        let zen = by_zone("zen.spamhaus.org").unwrap();
        assert_eq!(classify(zen, &[]), ListVerdict::NotListed);
        match classify(
            zen,
            &["127.0.0.2".parse().unwrap(), "127.0.0.11".parse().unwrap()],
        ) {
            ListVerdict::Listed(l) => {
                assert_eq!(l.len(), 2);
                assert!(l[0].meaning.starts_with("SBL"));
                assert_eq!(l[1].severity, Severity::Medium);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            classify(zen, &["127.255.255.254".parse().unwrap()]),
            ListVerdict::Refused(_)
        ));
        assert!(matches!(
            classify(zen, &["10.0.0.1".parse().unwrap()]),
            ListVerdict::Error(_)
        ));
        let dbl = by_zone("dbl.spamhaus.org").unwrap();
        assert!(matches!(
            classify(dbl, &["127.0.1.255".parse().unwrap()]),
            ListVerdict::Refused(_)
        ));
        match classify(dbl, &["127.0.1.4".parse().unwrap()]) {
            ListVerdict::Listed(l) => assert_eq!(l[0].meaning, "phishing domain"),
            other => panic!("{other:?}"),
        }
        let uribl = by_zone("multi.uribl.com").unwrap();
        assert!(matches!(
            classify(uribl, &["127.0.0.1".parse().unwrap()]),
            ListVerdict::Refused(_)
        ));
        match classify(uribl, &["127.0.0.6".parse().unwrap()]) {
            ListVerdict::Listed(l) => assert_eq!(
                l.iter().map(|x| x.meaning.as_str()).collect::<Vec<_>>(),
                vec!["black — spam domain", "grey — mixed use"]
            ),
            other => panic!("{other:?}"),
        }
        let spamcop = by_zone("bl.spamcop.net").unwrap();
        match classify(spamcop, &["127.0.0.2".parse().unwrap()]) {
            ListVerdict::Listed(l) => assert_eq!(l[0].severity, Severity::High),
            other => panic!("{other:?}"),
        }
        let dnswl = by_zone("list.dnswl.org").unwrap();
        match classify(dnswl, &["127.0.10.3".parse().unwrap()]) {
            ListVerdict::Listed(l) => assert_eq!(l[0].meaning, "trust high"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            classify(dnswl, &["127.0.0.255".parse().unwrap()]),
            ListVerdict::Refused(_)
        ));
        assert_eq!(lists_for(Kind::Domain).len(), 3);
        assert!(lists_for(Kind::Ip6)
            .iter()
            .any(|l| l.zone == "zen.spamhaus.org"));
    }

    #[test]
    fn queries_and_caches_through_a_fake_list() {
        use crate::dns::testsupport::start as fake;
        use crate::dns::Rr;
        let srv = fake(
            Box::new(|name, rtype| match (name, rtype) {
                ("2.0.0.127.zen.spamhaus.org", 1) => Some((
                    0,
                    vec![Rr {
                        name: name.into(),
                        rtype: 1,
                        ttl: 60,
                        data: RData::A("127.0.0.4".parse().unwrap()),
                    }],
                    false,
                )),
                ("1.0.0.127.zen.spamhaus.org", 1) => Some((3, vec![], false)),
                ("bad.example.dbl.spamhaus.org", 1) => Some((
                    0,
                    vec![Rr {
                        name: name.into(),
                        rtype: 1,
                        ttl: 60,
                        data: RData::A("127.255.255.254".parse().unwrap()),
                    }],
                    false,
                )),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        let client = Client::at(srv.addr);
        let zen = by_zone("zen.spamhaus.org").unwrap();
        assert!(matches!(
            query_ip(&client, zen, "127.0.0.2".parse().unwrap()),
            ListVerdict::Listed(_)
        ));
        assert_eq!(
            query_ip(&client, zen, "127.0.0.1".parse().unwrap()),
            ListVerdict::NotListed
        );
        let dbl = by_zone("dbl.spamhaus.org").unwrap();
        assert!(matches!(
            query_domain(&client, dbl, "bad.example"),
            ListVerdict::Refused(_)
        ));
        let hits = srv.hits.lock().unwrap().len();
        // the second round is served from the cache
        assert!(matches!(
            query_ip(&client, zen, "127.0.0.2".parse().unwrap()),
            ListVerdict::Listed(_)
        ));
        assert_eq!(srv.hits.lock().unwrap().len(), hits);
    }
}
