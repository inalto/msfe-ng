//! What the Delivery → DMARC reports view shows, from the stored reports.
//!
//! One grouped query (per day, source, header_from domain, verdicts and
//! reporter) plus the sources' triage feed [`aggregate`], which classifies in
//! Rust (`dmarcrep::classify`): re-triaging a source changes its whole
//! history at once, and the arithmetic is testable without a database.

use crate::config::Config;
use crate::db::{self, quote};
use crate::dmarcrep::{self, Class, DomainStats};
use crate::json::Json;
use std::collections::{BTreeMap, BTreeSet};

/// One grouped row of `dmarc_records` joined with its report.
#[derive(Debug, Clone, Default)]
pub struct Row {
    pub day: String,
    pub ip: String,
    pub domain: String,
    pub dkim: String,
    pub spf: String,
    pub forwarded: bool,
    pub org: String,
    pub count: u64,
}

impl Row {
    fn passed(&self) -> bool {
        self.dkim == "pass" || self.spf == "pass"
    }
}

/// A source's triage row from `dmarc_sources`.
#[derive(Debug, Clone, Default)]
pub struct Source {
    pub status: String,
    pub note: String,
    pub rdns: String,
    pub first_seen: String,
    pub last_seen: String,
}

/// Published policy of a domain, from its latest report.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub p: String,
    pub pct: Option<u32>,
}

pub struct Filter {
    pub days: u32,
    pub domain: Option<String>,
    /// restrict the lists (not the chart) to one day
    pub day: Option<String>,
}

pub fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

pub fn valid_day(d: &str) -> bool {
    crate::civil::Date::parse(d).is_some()
}

fn today() -> crate::civil::Date {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    crate::civil::Date::from_unix(secs)
}

fn days_ago(n: u32) -> String {
    crate::civil::Date::from_days(today().to_days() - n as i64).to_string()
}

fn class_counts(m: &BTreeMap<&'static str, u64>) -> Json {
    Json::Object(
        Class::ALL
            .iter()
            .map(|c| {
                (
                    c.key().to_string(),
                    Json::Int(*m.get(c.key()).unwrap_or(&0) as i64),
                )
            })
            .collect(),
    )
}

fn pct(n: u64, d: u64) -> Json {
    if d == 0 {
        Json::Null
    } else {
        Json::Num(format!("{:.1}", n as f64 * 100.0 / d as f64))
    }
}

#[derive(Default)]
struct SrcAgg {
    classes: BTreeMap<&'static str, u64>,
    messages: u64,
    dkim: BTreeMap<String, u64>,
    spf: BTreeMap<String, u64>,
    orgs: BTreeSet<String>,
    first: String,
    last: String,
}

#[derive(Default)]
struct DomAgg {
    classes: BTreeMap<&'static str, u64>,
    messages: u64,
    days: BTreeSet<String>,
    legit: u64,
    legit_pass: u64,
    own_fail_recent: u64,
    suspects: BTreeSet<String>,
}

/// Everything the view needs, from rows already filtered by period and domain.
/// `today` is `YYYY-MM-DD` (the 7-day windows count back from it).
pub fn aggregate(
    rows: &[Row],
    sources: &BTreeMap<(String, String), Source>,
    policies: &BTreeMap<String, Policy>,
    own: &BTreeSet<String>,
    day: Option<&str>,
    today: &str,
) -> Json {
    let week_ago = crate::civil::Date::parse(today)
        .map(|d| crate::civil::Date::from_days(d.to_days() - 7).to_string())
        .unwrap_or_default();
    let unknown = Source {
        status: "unknown".into(),
        ..Default::default()
    };
    let class_of = |r: &Row| -> Class {
        let st = sources
            .get(&(r.ip.clone(), r.domain.clone()))
            .unwrap_or(&unknown);
        dmarcrep::classify(r.passed(), r.forwarded, own.contains(&r.ip), &st.status)
    };

    // the chart covers the whole period; everything else honours `day`
    let mut series: BTreeMap<&str, BTreeMap<&'static str, u64>> = BTreeMap::new();
    for r in rows {
        *series
            .entry(&r.day)
            .or_default()
            .entry(class_of(r).key())
            .or_default() += r.count;
    }

    let mut total: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut messages = 0u64;
    let mut orgs: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    let mut srcs: BTreeMap<(String, String), SrcAgg> = BTreeMap::new();
    let mut doms: BTreeMap<&str, DomAgg> = BTreeMap::new();
    for r in rows.iter().filter(|r| day.map_or(true, |d| r.day == d)) {
        let c = class_of(r);
        *total.entry(c.key()).or_default() += r.count;
        messages += r.count;
        let o = orgs.entry(&r.org).or_default();
        o.0 += r.count;
        if c == Class::Pass {
            o.1 += r.count;
        }
        let s = srcs.entry((r.ip.clone(), r.domain.clone())).or_default();
        *s.classes.entry(c.key()).or_default() += r.count;
        s.messages += r.count;
        *s.dkim.entry(r.dkim.clone()).or_default() += r.count;
        *s.spf.entry(r.spf.clone()).or_default() += r.count;
        s.orgs.insert(r.org.clone());
        if s.first.is_empty() || r.day < s.first {
            s.first = r.day.clone();
        }
        if r.day > s.last {
            s.last = r.day.clone();
        }
        let d = doms.entry(&r.domain).or_default();
        *d.classes.entry(c.key()).or_default() += r.count;
        d.messages += r.count;
        d.days.insert(r.day.clone());
        // legitimate traffic for readiness: this server, triaged-legit sources,
        // and anything passing (a passing third party is authorised by definition)
        if c != Class::Forwarded && c != Class::Suspect {
            d.legit += r.count;
            if c == Class::Pass {
                d.legit_pass += r.count;
            }
        }
        if c == Class::OwnFail && r.day.as_str() >= week_ago.as_str() {
            d.own_fail_recent += r.count;
        }
        if c == Class::Suspect {
            d.suspects.insert(r.ip.clone());
        }
    }

    let pass = *total.get("pass").unwrap_or(&0);
    let mut new_suspects = 0;
    let mut sources_json: Vec<(u8, u64, Json)> = Vec::new();
    for ((ip, dom), a) in &srcs {
        let st = sources.get(&(ip.clone(), dom.clone())).unwrap_or(&unknown);
        // the worst failing class it has, by severity
        let failing = [
            Class::Suspect,
            Class::OwnFail,
            Class::LegitFail,
            Class::Forwarded,
        ]
        .into_iter()
        .find(|c| a.classes.contains_key(c.key()));
        let class = failing.unwrap_or(Class::Pass);
        if class == Class::Suspect && st.first_seen.as_str() >= week_ago.as_str() {
            new_suspects += 1;
        }
        let rank = match class {
            Class::Suspect => 0,
            Class::OwnFail => 1,
            Class::LegitFail => 2,
            Class::Forwarded => 3,
            Class::Pass => 4,
        };
        let mix = |m: &BTreeMap<String, u64>| {
            Json::Object(
                m.iter()
                    .map(|(k, v)| {
                        (
                            if k.is_empty() {
                                "none".into()
                            } else {
                                k.clone()
                            },
                            Json::Int(*v as i64),
                        )
                    })
                    .collect(),
            )
        };
        let failed = a.messages - a.classes.get("pass").copied().unwrap_or(0);
        sources_json.push((
            rank,
            u64::MAX - failed,
            Json::Object(vec![
                ("ip".into(), Json::str(ip)),
                ("domain".into(), Json::str(dom)),
                ("rdns".into(), Json::str(&st.rdns)),
                ("status".into(), Json::str(&st.status)),
                ("note".into(), Json::str(&st.note)),
                ("own".into(), Json::Bool(own.contains(ip))),
                ("class".into(), Json::str(class.key())),
                ("messages".into(), Json::Int(a.messages as i64)),
                ("failed".into(), Json::Int(failed as i64)),
                ("classes".into(), class_counts(&a.classes)),
                ("dkim".into(), mix(&a.dkim)),
                ("spf".into(), mix(&a.spf)),
                (
                    "reporters".into(),
                    Json::Array(a.orgs.iter().map(Json::str).collect()),
                ),
                (
                    "first_seen".into(),
                    Json::str(if st.first_seen.is_empty() {
                        &a.first
                    } else {
                        &st.first_seen
                    }),
                ),
                ("last_seen".into(), Json::str(&a.last)),
            ]),
        ));
    }
    sources_json.sort_by_key(|s| (s.0, s.1));

    let domains: Vec<Json> = doms
        .iter()
        .map(|(dom, a)| {
            let pol = policies.get(*dom).cloned().unwrap_or_default();
            let rd = dmarcrep::readiness(&DomainStats {
                p: pol.p.clone(),
                pct: pol.pct,
                days: a.days.len() as u32,
                legit: a.legit,
                legit_pass: a.legit_pass,
                own_fail_recent: a.own_fail_recent,
                suspect_sources: a.suspects.len() as u64,
            });
            Json::Object(vec![
                ("domain".into(), Json::str(*dom)),
                ("messages".into(), Json::Int(a.messages as i64)),
                (
                    "pass_pct".into(),
                    pct(*a.classes.get("pass").unwrap_or(&0), a.messages),
                ),
                ("classes".into(), class_counts(&a.classes)),
                ("days".into(), Json::Int(a.days.len() as i64)),
                ("suspect_sources".into(), Json::Int(a.suspects.len() as i64)),
                ("p".into(), Json::str(&pol.p)),
                (
                    "pct".into(),
                    pol.pct.map(|p| Json::Int(p as i64)).unwrap_or(Json::Null),
                ),
                (
                    "readiness".into(),
                    Json::Object(vec![
                        ("ready".into(), Json::Bool(rd.ready)),
                        ("next_p".into(), Json::str(&rd.next_p)),
                        ("next_pct".into(), Json::Int(rd.next_pct as i64)),
                        ("text".into(), Json::str(&rd.text)),
                    ]),
                ),
            ])
        })
        .collect();

    let mut reporters: Vec<(&str, (u64, u64))> = orgs.into_iter().collect();
    reporters.sort_by_key(|r| std::cmp::Reverse(r.1 .0));
    Json::Object(vec![
        (
            "summary".into(),
            Json::Object(vec![
                ("messages".into(), Json::Int(messages as i64)),
                ("pass_pct".into(), pct(pass, messages)),
                ("classes".into(), class_counts(&total)),
                ("sources".into(), Json::Int(srcs.len() as i64)),
                (
                    "suspect_sources".into(),
                    Json::Int(sources_json.iter().filter(|s| s.0 == 0).count() as i64),
                ),
                ("new_suspects_7d".into(), Json::Int(new_suspects as i64)),
                ("reporters".into(), Json::Int(reporters.len() as i64)),
            ]),
        ),
        (
            "series".into(),
            Json::Array(
                series
                    .iter()
                    .map(|(d, m)| {
                        let mut o = vec![("day".to_string(), Json::str(*d))];
                        if let Json::Object(c) = class_counts(m) {
                            o.extend(c);
                        }
                        Json::Object(o)
                    })
                    .collect(),
            ),
        ),
        (
            "reporters".into(),
            Json::Array(
                reporters
                    .iter()
                    .map(|(o, (n, p))| {
                        Json::Object(vec![
                            ("org".into(), Json::str(*o)),
                            ("messages".into(), Json::Int(*n as i64)),
                            ("pass_pct".into(), pct(*p, *n)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("domains".into(), Json::Array(domains)),
        (
            "sources".into(),
            Json::Array(sources_json.into_iter().map(|s| s.2).collect()),
        ),
    ])
}

fn where_clause(f: &Filter, day_col: &str, dom_col: &str) -> String {
    let mut w = format!("{day_col} >= {}", quote(&days_ago(f.days)));
    if let Some(d) = &f.domain {
        w.push_str(&format!(" AND {dom_col} = {}", quote(d)));
    }
    w
}

/// The whole overview for the UI.
pub fn overview(cfg: &Config, f: &Filter) -> Result<Json, String> {
    let e = |e: std::io::Error| e.to_string();
    let rows: Vec<Row> = db::query(
        cfg,
        &format!(
            "SELECT r.day, r.source_ip, r.header_from, r.dmarc_dkim, r.dmarc_spf, r.forwarded, p.org_name, SUM(r.count) \
             FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report WHERE {} \
             GROUP BY r.day, r.source_ip, r.header_from, r.dmarc_dkim, r.dmarc_spf, r.forwarded, p.org_name",
            where_clause(f, "r.day", "r.header_from")
        ),
    )
    .map_err(e)?
    .into_iter()
    .filter(|c| c.len() >= 8)
    .map(|c| Row {
        day: c[0].clone(),
        ip: c[1].clone(),
        domain: c[2].clone(),
        dkim: c[3].clone(),
        spf: c[4].clone(),
        forwarded: c[5] == "1",
        org: c[6].clone(),
        count: c[7].parse().unwrap_or(0),
    })
    .collect();
    let sources: BTreeMap<(String, String), Source> = db::query(
        cfg,
        "SELECT ip, domain, status, note, IFNULL(rdns,''), first_seen, last_seen FROM dmarc_sources",
    )
    .map_err(e)?
    .into_iter()
    .filter(|c| c.len() >= 7)
    .map(|c| {
        (
            (c[0].clone(), c[1].clone()),
            Source {
                status: c[2].clone(),
                note: c[3].clone(),
                rdns: c[4].clone(),
                first_seen: c[5].clone(),
                last_seen: c[6].clone(),
            },
        )
    })
    .collect();
    // latest published policy per domain (ordered oldest first: later rows win)
    let mut policies = BTreeMap::new();
    for c in db::query(
        cfg,
        "SELECT domain, p, IFNULL(pct,''), day FROM dmarc_reports ORDER BY day, id",
    )
    .map_err(e)?
    {
        if c.len() >= 3 {
            policies.insert(
                c[0].clone(),
                Policy {
                    p: c[1].clone(),
                    pct: c[2].parse().ok(),
                },
            );
        }
    }
    // a subdomain reported under its organisational domain's policy
    let lookup: BTreeMap<String, Policy> = rows
        .iter()
        .map(|r| r.domain.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|d| {
            let pol = policies.get(&d).cloned().or_else(|| {
                policies
                    .get(&crate::psl::organizational_domain(&d).0)
                    .cloned()
            })?;
            Some((d, pol))
        })
        .collect();
    let own = crate::dmarcjob::own_ips(std::path::Path::new("/"));
    let mut out = aggregate(
        &rows,
        &sources,
        &lookup,
        &own,
        f.day.as_deref(),
        &today().to_string(),
    );
    let counts = db::query(
        cfg,
        &format!(
            "SELECT COUNT(*), COUNT(DISTINCT org_name) FROM dmarc_reports WHERE {}",
            where_clause(f, "day", "domain")
        ),
    )
    .map_err(e)?;
    let all_domains: Vec<Json> = db::query(
        cfg,
        "SELECT DISTINCT header_from FROM dmarc_records ORDER BY header_from",
    )
    .map_err(e)?
    .into_iter()
    .filter_map(|c| c.into_iter().next())
    .map(Json::Str)
    .collect();
    if let Json::Object(o) = &mut out {
        let first = counts.first().cloned().unwrap_or_default();
        o.push((
            "reports".into(),
            Json::Int(first.first().and_then(|n| n.parse().ok()).unwrap_or(0)),
        ));
        o.push(("domain_list".into(), Json::Array(all_domains)));
        o.push((
            "own_ips".into(),
            Json::Array(own.iter().map(Json::str).collect()),
        ));
    }
    Ok(out)
}

fn record_json(c: &[String], with_org: bool) -> Json {
    let mut o = vec![
        ("day".to_string(), Json::str(&c[0])),
        ("ip".into(), Json::str(&c[1])),
        ("header_from".into(), Json::str(&c[2])),
        ("count".into(), Json::Int(c[3].parse().unwrap_or(0))),
        ("disposition".into(), Json::str(&c[4])),
        ("dkim".into(), Json::str(&c[5])),
        ("spf".into(), Json::str(&c[6])),
        ("dkim_auth".into(), Json::str(&c[7])),
        ("spf_auth".into(), Json::str(&c[8])),
        ("envelope_from".into(), Json::str(&c[9])),
        ("envelope_to".into(), Json::str(&c[10])),
        ("reasons".into(), Json::str(&c[11])),
    ];
    if with_org {
        o.push((
            "org".into(),
            Json::str(c.get(12).map(String::as_str).unwrap_or("")),
        ));
    }
    Json::Object(o)
}

const RECORD_COLS: &str = "r.day, r.source_ip, r.header_from, r.count, r.disposition, r.dmarc_dkim, r.dmarc_spf, r.dkim_auth, r.spf_auth, r.envelope_from, r.envelope_to, r.reasons";

/// The individual records of one source for one domain (newest first).
pub fn source_records(cfg: &Config, ip: &str, domain: &str, days: u32) -> Result<Json, String> {
    let rows = db::query(
        cfg,
        &format!(
            "SELECT {RECORD_COLS}, p.org_name FROM dmarc_records r JOIN dmarc_reports p ON p.id = r.report \
             WHERE r.source_ip = {} AND r.header_from = {} AND r.day >= {} ORDER BY r.day DESC, r.id DESC LIMIT 500",
            quote(ip),
            quote(domain),
            quote(&days_ago(days))
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(Json::Array(
        rows.iter()
            .filter(|c| c.len() >= 13)
            .map(|c| record_json(c, true))
            .collect(),
    ))
}

/// The stored reports, newest first.
pub fn reports(cfg: &Config, f: &Filter) -> Result<Json, String> {
    let rows = db::query(
        cfg,
        &format!(
            "SELECT id, org_name, org_email, report_id, domain, day, date_begin, date_end, p, IFNULL(pct,''), records, messages, imported_at, origin \
             FROM dmarc_reports WHERE {} ORDER BY day DESC, id DESC LIMIT 1000",
            where_clause(f, "day", "domain")
        ),
    )
    .map_err(|e| e.to_string())?;
    Ok(Json::Array(
        rows.iter()
            .filter(|c| c.len() >= 14)
            .map(|c| {
                Json::Object(vec![
                    ("id".into(), Json::Int(c[0].parse().unwrap_or(0))),
                    ("org".into(), Json::str(&c[1])),
                    ("email".into(), Json::str(&c[2])),
                    ("report_id".into(), Json::str(&c[3])),
                    ("domain".into(), Json::str(&c[4])),
                    ("day".into(), Json::str(&c[5])),
                    ("begin".into(), Json::Int(c[6].parse().unwrap_or(0))),
                    ("end".into(), Json::Int(c[7].parse().unwrap_or(0))),
                    ("p".into(), Json::str(&c[8])),
                    (
                        "pct".into(),
                        c[9].parse::<i64>().map(Json::Int).unwrap_or(Json::Null),
                    ),
                    ("records".into(), Json::Int(c[10].parse().unwrap_or(0))),
                    ("messages".into(), Json::Int(c[11].parse().unwrap_or(0))),
                    ("imported_at".into(), Json::str(&c[12])),
                    ("origin".into(), Json::str(&c[13])),
                ])
            })
            .collect(),
    ))
}

/// One report's records.
pub fn report_records(cfg: &Config, id: u64) -> Result<Json, String> {
    let rows = db::query(
        cfg,
        &format!("SELECT {RECORD_COLS} FROM dmarc_records r WHERE r.report = {id} ORDER BY r.count DESC, r.id LIMIT 2000"),
    )
    .map_err(|e| e.to_string())?;
    Ok(Json::Array(
        rows.iter()
            .filter(|c| c.len() >= 12)
            .map(|c| record_json(c, false))
            .collect(),
    ))
}

pub const STATUSES: [&str; 4] = ["unknown", "legit", "forwarder", "abuse"];

/// Triage a source: for one domain, or for every domain it sent as.
pub fn set_status(
    cfg: &Config,
    ip: &str,
    domain: Option<&str>,
    status: &str,
    note: &str,
) -> Result<(), String> {
    if !STATUSES.contains(&status) {
        return Err(format!("status must be one of {}", STATUSES.join(", ")));
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err("bad ip".into());
    }
    let mut sql = format!(
        "UPDATE dmarc_sources SET status={}, note={} WHERE ip={}",
        quote(status),
        quote(&note.chars().take(255).collect::<String>()),
        quote(ip)
    );
    if let Some(d) = domain {
        sql.push_str(&format!(" AND domain={}", quote(d)));
    }
    sql.push_str(";\n");
    db::exec_stdin(cfg, &sql).map_err(|e| e.to_string())
}

/// Suspect sources (unknown triage, not this server) failing on at least
/// `min` messages in the last `days` — the doctor's notice.
pub fn suspect_count(cfg: &Config, days: u32, min: u64) -> Option<(u64, u64)> {
    let own = crate::dmarcjob::own_ips(std::path::Path::new("/"));
    let rows = db::query(
        cfg,
        &format!(
            "SELECT r.source_ip, SUM(r.count) FROM dmarc_records r \
             LEFT JOIN dmarc_sources s ON s.ip = r.source_ip AND s.domain = r.header_from \
             WHERE r.day >= {} AND r.passed = 0 AND r.forwarded = 0 \
             AND IFNULL(s.status,'unknown') IN ('unknown','abuse') GROUP BY r.source_ip",
            quote(&days_ago(days))
        ),
    )
    .ok()?;
    let (mut n, mut msgs) = (0, 0);
    for c in rows {
        let m: u64 = c.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
        if c.first().is_some_and(|ip| !own.contains(ip)) && m >= min {
            n += 1;
            msgs += m;
        }
    }
    Some((n, msgs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(day: &str, ip: &str, dkim: &str, spf: &str, fwd: bool, org: &str, n: u64) -> Row {
        Row {
            day: day.into(),
            ip: ip.into(),
            domain: "example.com".into(),
            dkim: dkim.into(),
            spf: spf.into(),
            forwarded: fwd,
            org: org.into(),
            count: n,
        }
    }

    #[test]
    fn aggregates_classes_sources_and_domains() {
        let rows = vec![
            row(
                "2026-09-20",
                "198.51.100.1",
                "pass",
                "pass",
                false,
                "google.com",
                90,
            ),
            row(
                "2026-09-20",
                "198.51.100.1",
                "fail",
                "pass",
                false,
                "Outlook.com",
                5,
            ),
            row(
                "2026-09-21",
                "198.51.100.1",
                "fail",
                "fail",
                false,
                "google.com",
                2,
            ),
            row(
                "2026-09-21",
                "203.0.113.9",
                "fail",
                "fail",
                false,
                "google.com",
                40,
            ),
            row(
                "2026-09-21",
                "192.0.2.8",
                "fail",
                "fail",
                true,
                "google.com",
                3,
            ),
            row(
                "2026-09-21",
                "192.0.2.50",
                "fail",
                "fail",
                false,
                "Outlook.com",
                6,
            ),
        ];
        let mut sources = BTreeMap::new();
        sources.insert(
            ("192.0.2.50".to_string(), "example.com".to_string()),
            Source {
                status: "legit".into(),
                first_seen: "2026-09-01".into(),
                ..Default::default()
            },
        );
        sources.insert(
            ("203.0.113.9".to_string(), "example.com".to_string()),
            Source {
                status: "unknown".into(),
                rdns: "bad.example".into(),
                first_seen: "2026-09-21".into(),
                ..Default::default()
            },
        );
        let mut pol = BTreeMap::new();
        pol.insert(
            "example.com".to_string(),
            Policy {
                p: "none".into(),
                pct: None,
            },
        );
        let own: BTreeSet<String> = ["198.51.100.1".to_string()].into();
        let j = aggregate(&rows, &sources, &pol, &own, None, "2026-09-22");
        let s = j.get("summary").unwrap();
        assert_eq!(s.get("messages").unwrap().as_i64(), Some(146));
        let c = s.get("classes").unwrap();
        assert_eq!(c.get("pass").unwrap().as_i64(), Some(95));
        assert_eq!(c.get("own_fail").unwrap().as_i64(), Some(2));
        assert_eq!(c.get("suspect").unwrap().as_i64(), Some(40));
        assert_eq!(c.get("forwarded").unwrap().as_i64(), Some(3));
        assert_eq!(c.get("legit_fail").unwrap().as_i64(), Some(6));
        assert_eq!(s.get("new_suspects_7d").unwrap().as_i64(), Some(1));
        assert_eq!(s.get("reporters").unwrap().as_i64(), Some(2));
        let src = j.get("sources").unwrap().as_array().unwrap();
        assert_eq!(src[0].str_field("ip"), "203.0.113.9"); // suspects first
        assert_eq!(src[0].str_field("rdns"), "bad.example");
        assert_eq!(src[1].str_field("class"), "own_fail");
        let series = j.get("series").unwrap().as_array().unwrap();
        assert_eq!(series.len(), 2);
        assert_eq!(series[0].get("pass").unwrap().as_i64(), Some(95));
        let d = &j.get("domains").unwrap().as_array().unwrap()[0];
        let rd = d.get("readiness").unwrap();
        // 2 days of reports only, and this server failing: not ready
        assert!(matches!(rd.get("ready"), Some(Json::Bool(false))));
        assert!(rd.str_field("text").contains("this server failed"));
        // one day only: the chart keeps both days
        let one = aggregate(
            &rows,
            &sources,
            &pol,
            &own,
            Some("2026-09-20"),
            "2026-09-22",
        );
        assert_eq!(
            one.get("summary")
                .unwrap()
                .get("messages")
                .unwrap()
                .as_i64(),
            Some(95)
        );
        assert_eq!(one.get("series").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn input_checks() {
        assert!(valid_domain("mail.example.com"));
        assert!(!valid_domain("x' OR 1"));
        assert!(valid_day("2026-09-21"));
        assert!(!valid_day("2026-13-40"));
    }
}
