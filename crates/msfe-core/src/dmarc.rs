//! DMARC (RFC 7489): the record at `_dmarc.<domain>`, inherited from the
//! organizational domain when the name has none of its own, its tags, and
//! whether an external report receiver has authorised the domain.

use crate::dns::{Client, DnsError};
use crate::psl;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub raw: String,
    pub p: Option<String>,
    pub sp: Option<String>,
    pub pct: u8,
    pub adkim: char,
    pub aspf: char,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub fo: Option<String>,
    pub ri: Option<u32>,
    pub rf: Option<String>,
    pub problems: Vec<String>,
}

fn mailto_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.split('!').next().unwrap_or(s).to_string()) // strip size limits
        .collect()
}

/// Parse `v=DMARC1; p=…`.
pub fn parse(txt: &str) -> Result<DmarcRecord, String> {
    let raw = txt.trim().to_string();
    let mut tags: Vec<(String, String)> = Vec::new();
    for t in raw.split(';') {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            return Err(format!("'{t}' is not a tag=value pair"));
        };
        tags.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    match tags.first() {
        Some((k, v)) if k == "v" && v.eq_ignore_ascii_case("DMARC1") => {}
        Some((k, v)) if k == "v" => return Err(format!("v={v} is not DMARC1")),
        _ => return Err("the record must start with v=DMARC1".into()),
    }
    let mut r = DmarcRecord {
        raw: raw.clone(),
        p: None,
        sp: None,
        pct: 100,
        adkim: 'r',
        aspf: 'r',
        rua: Vec::new(),
        ruf: Vec::new(),
        fo: None,
        ri: None,
        rf: None,
        problems: Vec::new(),
    };
    let policy = |v: &str| {
        matches!(
            v.to_ascii_lowercase().as_str(),
            "none" | "quarantine" | "reject"
        )
    };
    for (k, v) in &tags[1..] {
        match k.as_str() {
            "p" => {
                if !policy(v) {
                    r.problems
                        .push(format!("p={v} is not none, quarantine or reject"));
                }
                r.p = Some(v.to_ascii_lowercase());
            }
            "sp" => {
                if !policy(v) {
                    r.problems
                        .push(format!("sp={v} is not none, quarantine or reject"));
                }
                r.sp = Some(v.to_ascii_lowercase());
            }
            "pct" => match v.parse::<u8>() {
                Ok(n) if n <= 100 => r.pct = n,
                _ => r.problems.push(format!("pct={v} is not 0–100")),
            },
            "adkim" | "aspf" => {
                let c = v.to_ascii_lowercase().chars().next().unwrap_or('r');
                if !matches!(c, 'r' | 's') || v.len() != 1 {
                    r.problems.push(format!("{k}={v} is not r or s"));
                }
                if k == "adkim" {
                    r.adkim = c;
                } else {
                    r.aspf = c;
                }
            }
            "rua" => r.rua = mailto_list(v),
            "ruf" => r.ruf = mailto_list(v),
            "fo" => r.fo = Some(v.clone()),
            "ri" => match v.parse::<u32>() {
                Ok(n) => r.ri = Some(n),
                Err(_) => r.problems.push(format!("ri={v} is not a number")),
            },
            "rf" => r.rf = Some(v.clone()),
            "v" => r.problems.push("v= appears twice".into()),
            other => r
                .problems
                .push(format!("unknown tag {other}= (ignored by receivers)")),
        }
    }
    if r.p.is_none() {
        // RFC 7489 §6.3: p is required; receivers treat a missing p as p=none only when rua is present
        r.problems.push(if r.rua.is_empty() {
            "no p= tag: the record is invalid".into()
        } else {
            "no p= tag: receivers treat it as p=none".into()
        });
    }
    for u in r.rua.iter().chain(r.ruf.iter()) {
        if !u.to_ascii_lowercase().starts_with("mailto:") {
            r.problems
                .push(format!("report address '{u}' is not a mailto: URI"));
        }
    }
    Ok(r)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    /// The name the record was found at.
    pub at: String,
    pub inherited: bool,
    pub org_uncertain: bool,
    /// Every `v=DMARC1` TXT found at `at` (should be exactly one).
    pub records: Vec<String>,
    pub record: Option<DmarcRecord>,
    pub parse_error: Option<String>,
}

fn dmarc_txts(client: &Client, name: &str) -> Result<Vec<String>, DnsError> {
    Ok(client
        .txt(&format!("_dmarc.{name}"))?
        .into_iter()
        .filter(|t| t.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect())
}

/// The DMARC record that applies to `domain`: its own, else the
/// organizational domain's.
pub fn lookup(client: &Client, domain: &str) -> Result<Lookup, DnsError> {
    let own = dmarc_txts(client, domain)?;
    let (org, uncertain) = psl::organizational_domain(domain);
    let (at, inherited, records) = if !own.is_empty() || org == domain {
        (domain.to_string(), false, own)
    } else {
        (org.clone(), true, dmarc_txts(client, &org)?)
    };
    let (record, parse_error) = match records.first() {
        Some(t) => match parse(t) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e)),
        },
        None => (None, None),
    };
    Ok(Lookup {
        at,
        inherited,
        org_uncertain: inherited && uncertain,
        records,
        record,
        parse_error,
    })
}

/// The domain part of a `mailto:` report URI.
pub fn mailto_domain(uri: &str) -> Option<String> {
    let addr = uri
        .strip_prefix("mailto:")
        .or_else(|| uri.strip_prefix("MAILTO:"))?;
    addr.rsplit_once('@')
        .map(|(_, d)| d.trim().to_ascii_lowercase())
}

/// RFC 7489 §7.1: a report receiver in another organizational domain must
/// publish `<domain>._report._dmarc.<receiver>` with `v=DMARC1`.
/// `None` when the lookup failed.
pub fn external_report_authorized(client: &Client, domain: &str, rua_domain: &str) -> Option<bool> {
    let name = format!("{domain}._report._dmarc.{rua_domain}");
    client.txt(&name).ok().map(|txts| {
        txts.iter()
            .any(|t| t.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
    })
}

/// Whether `rua_domain` needs the external authorization (different org).
pub fn is_external(domain: &str, rua_domain: &str) -> bool {
    psl::organizational_domain(domain).0 != psl::organizational_domain(rua_domain).0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tags() {
        let r = parse("v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=r; rua=mailto:a@r.example!10m, mailto:b@example.com; ruf=mailto:f@example.com; fo=1; ri=3600").unwrap();
        assert_eq!(r.p.as_deref(), Some("reject"));
        assert_eq!(r.sp.as_deref(), Some("quarantine"));
        assert_eq!(r.pct, 50);
        assert_eq!(r.adkim, 's');
        assert_eq!(r.rua, vec!["mailto:a@r.example", "mailto:b@example.com"]);
        assert_eq!(r.ri, Some(3600));
        assert!(r.problems.is_empty(), "{:?}", r.problems);
        let r = parse("v=DMARC1;p=none;").unwrap();
        assert_eq!(r.pct, 100);
        assert!(r.problems.is_empty());
        let r = parse("v=DMARC1; p=bogus; pct=200; adkim=x; rua=a@b; ri=z; zz=1").unwrap();
        assert_eq!(r.problems.len(), 6, "{:?}", r.problems);
        let r = parse("v=DMARC1; rua=mailto:x@example.com").unwrap();
        assert!(r.problems.iter().any(|p| p.contains("treat it as p=none")));
        assert!(parse("v=DMARC2; p=none").is_err());
        assert!(parse("p=none; v=DMARC1").is_err());
        assert!(parse("v=DMARC1; nonsense").is_err());
        assert_eq!(
            mailto_domain("mailto:dmarc@Reports.Example"),
            Some("reports.example".into())
        );
        assert_eq!(mailto_domain("https://x"), None);
        assert!(is_external("example.com", "dmarcian.com"));
        assert!(!is_external("mail.example.com", "example.com"));
    }

    #[test]
    fn lookup_inherits_from_the_organizational_domain() {
        use crate::dns::testsupport::start as fake;
        use crate::dns::{RData, Rr};
        let txt = |n: &str, v: &str| Rr {
            name: n.into(),
            rtype: 16,
            ttl: 1,
            data: RData::Txt(vec![v.into()]),
        };
        let srv = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("_dmarc.example.com", 16) => Some((
                    0,
                    vec![txt(
                        "_dmarc.example.com",
                        "v=DMARC1; p=quarantine; rua=mailto:r@dmarcian.com",
                    )],
                    false,
                )),
                ("_dmarc.sub.example.com", 16) => Some((3, vec![], false)),
                ("example.com._report._dmarc.dmarcian.com", 16) => {
                    Some((0, vec![txt(name, "v=DMARC1")], false))
                }
                ("_dmarc.two.example", 16) => Some((
                    0,
                    vec![
                        txt(name, "v=DMARC1; p=none"),
                        txt(name, "v=DMARC1; p=reject"),
                    ],
                    false,
                )),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        let c = Client::at(srv.addr);
        let l = lookup(&c, "sub.example.com").unwrap();
        assert!(l.inherited);
        assert_eq!(l.at, "example.com");
        assert_eq!(l.record.unwrap().p.as_deref(), Some("quarantine"));
        let l = lookup(&c, "example.com").unwrap();
        assert!(!l.inherited);
        let l = lookup(&c, "two.example").unwrap();
        assert_eq!(l.records.len(), 2);
        let l = lookup(&c, "none.example").unwrap();
        assert!(l.record.is_none() && l.records.is_empty());
        assert_eq!(
            external_report_authorized(&c, "example.com", "dmarcian.com"),
            Some(true)
        );
        assert_eq!(
            external_report_authorized(&c, "other.example", "dmarcian.com"),
            Some(false)
        );
    }
}
