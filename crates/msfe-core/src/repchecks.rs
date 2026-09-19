//! Reputation checks of the delivery test: the sending address (when one
//! was given) and the MX addresses against the blocklists in `dnsbl`, the
//! domain against the domain lists, and the DNSWL allowlist. Refusals and
//! outages are reported once per list as unknown, never as listings.

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::dnsbl::{self, Dnsbl, Kind, ListVerdict, Polarity};
use crate::json::Json;
use std::net::IpAddr;

const CAT: Category = Category::Reputation;

pub fn tasks() -> Vec<Task> {
    vec![
        Task::new("rbl.sender", &["dns.domain"], sender_task),
        Task::new("rbl.domain", &["dns.domain"], domain_task),
        Task::new("rbl.mx", &["dns.mx"], mx_task),
    ]
}

fn resolver_fix() -> Fix {
    Fix {
        summary: "Give this server its own validating resolver so the lists answer (Settings → Resolver → Install, or `msfe-ng resolver install`)".into(),
        command: Some("msfe-ng resolver install".into()),
        ..Default::default()
    }
}

/// Record a refusal/outage once per list (the summary reports them).
fn note_problem(res: &Results, list: &Dnsbl, what: &str) {
    res.insert_fact_entry("rbl_problems", list.zone, Json::str(what));
}

/// Checks for one address against every list that covers its family.
fn ip_checks(ctx: &Ctx, res: &Results, ip: IpAddr, scope: Scope, role: &str) -> Vec<Check> {
    let kind = if ip.is_ipv4() { Kind::Ip4 } else { Kind::Ip6 };
    let mut out = Vec::new();
    let tgt = ip.to_string();
    let mut listed_on: Vec<String> = Vec::new();
    for list in dnsbl::lists_for(kind) {
        if ctx.cancelled() {
            break;
        }
        let id = format!(
            "rbl.{}.{}",
            if list.polarity == Polarity::Allow {
                "dnswl"
            } else {
                "ip"
            },
            list.zone
        );
        match dnsbl::query_ip(&ctx.dns, list, ip) {
            ListVerdict::NotListed => {
                if list.polarity == Polarity::Allow {
                    out.push(
                        Check::new(
                            &id,
                            scope,
                            CAT,
                            Verdict::NotApplicable,
                            Severity::Info,
                            format!("{ip} not on {}", list.name),
                            list.note,
                        )
                        .target(&tgt),
                    );
                }
                // silence for blocklists: the summary counts them
            }
            ListVerdict::Listed(listings) => {
                let meanings: Vec<String> = listings
                    .iter()
                    .map(|l| format!("{} ({})", l.meaning, l.code))
                    .collect();
                if list.polarity == Polarity::Allow {
                    out.push(
                        Check::new(
                            &id,
                            scope,
                            CAT,
                            Verdict::Pass,
                            Severity::Info,
                            format!("{ip} is on {} — {}", list.name, listings[0].meaning),
                            list.note,
                        )
                        .target(&tgt)
                        .evidence("answer", meanings.join("\n")),
                    );
                    continue;
                }
                listed_on.push(list.name.to_string());
                let worst = listings
                    .iter()
                    .map(|l| l.severity)
                    .min()
                    .unwrap_or(Severity::Medium);
                let (verdict, sev, why) = match scope {
                    Scope::Sending => (
                        if worst <= Severity::High { Verdict::Fail } else { Verdict::Warn },
                        worst,
                        format!("{} — {}. Receivers that use this list reject or junk mail from {ip}", meanings.join("; "), list.note),
                    ),
                    _ => (
                        Verdict::Warn,
                        Severity::Low,
                        format!("{} — {}. This is an inbound (MX) address: a listing only matters if the same host also sends mail, which this test does not assume", meanings.join("; "), list.note),
                    ),
                };
                let mut c = Check::new(&id, scope, CAT, verdict, sev, format!("{ip} ({role}) is listed on {}", list.name), why)
                    .target(&tgt)
                    .evidence("answer", meanings.join("\n"))
                    .fix(Fix {
                        summary: format!("Find and stop the cause (a compromised account or script, an open relay, a bad list of recipients), then request delisting at {}", list.name),
                        url: Some(list.removal_url.to_string()),
                        ..Default::default()
                    });
                if listings.iter().any(|l| l.meaning.starts_with("PBL")) {
                    c = c.fix(Fix {
                        summary: "This is a dynamic/end-user range by policy: send through the provider's or a dedicated mail server (smarthost on port 587), or ask the ISP to remove the range from the PBL".into(),
                        url: Some(list.removal_url.to_string()),
                        ..Default::default()
                    });
                }
                out.push(c);
            }
            ListVerdict::Refused(why) => note_problem(res, list, &why),
            ListVerdict::NoAnswer => note_problem(res, list, "no reply (timeout)"),
            ListVerdict::Error(e) => note_problem(res, list, &e),
        }
    }
    res.insert_fact_entry(
        "rbl_listed",
        &tgt,
        Json::Array(listed_on.iter().map(Json::str).collect()),
    );
    out
}

fn sender_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let Some(ip) = ctx.inputs.ip else {
        return (vec![], vec![]);
    };
    let mut out = ip_checks(ctx, res, ip, Scope::Sending, "sending address");
    out.push(summary_for(
        res,
        &[ip],
        Scope::Sending,
        "rbl.sender.summary",
        &format!("sending address {ip}"),
    ));
    (out, vec![])
}

fn domain_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let mut out = Vec::new();
    let mut listed = Vec::new();
    let mut asked = 0;
    for list in dnsbl::lists_for(Kind::Domain) {
        let id = format!("rbl.domain.{}", list.zone);
        match dnsbl::query_domain(&ctx.dns, list, d) {
            ListVerdict::NotListed => asked += 1,
            ListVerdict::Listed(listings) => {
                asked += 1;
                listed.push(list.name);
                let meanings: Vec<String> = listings
                    .iter()
                    .map(|l| format!("{} ({})", l.meaning, l.code))
                    .collect();
                out.push(
                    Check::new(&id, Scope::Sending, CAT, Verdict::Fail, Severity::High, format!("{d} is listed on {}", list.name), format!("{} — {}", meanings.join("; "), list.note))
                        .target(d)
                        .evidence("answer", meanings.join("\n"))
                        .fix(Fix {
                            summary: format!("Clean up whatever got the domain listed (phishing pages, spam campaigns, a hacked site), then request removal at {}", list.name),
                            url: Some(list.removal_url.to_string()),
                            ..Default::default()
                        }),
                );
            }
            ListVerdict::Refused(why) => note_problem(res, list, &why),
            ListVerdict::NoAnswer => note_problem(res, list, "no reply (timeout)"),
            ListVerdict::Error(e) => note_problem(res, list, &e),
        }
    }
    if listed.is_empty() && asked > 0 {
        out.push(Check::new(
            "rbl.domain",
            Scope::Sending,
            CAT,
            Verdict::Pass,
            Severity::Info,
            format!("{d} is on no domain blocklist"),
            format!("{asked} list(s) answered: not listed"),
        ));
    } else if asked == 0 {
        out.push(
            Check::new(
                "rbl.domain",
                Scope::Sending,
                CAT,
                Verdict::Unknown,
                Severity::Info,
                "domain blocklists",
                "no domain list answered this resolver (see the reputation summary)",
            )
            .fix(resolver_fix()),
        );
    }
    (out, vec![])
}

fn mx_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    if res.fact_bool("domain_exists") == Some(false) || res.fact_bool("null_mx") == Some(true) {
        return (vec![], vec![]);
    }
    let hosts: Vec<String> = res
        .fact_strs("mx_hosts")
        .into_iter()
        .filter(|h| h.parse::<IpAddr>().is_err())
        .collect();
    if hosts.is_empty() {
        return (vec![], vec![]);
    }
    let _ = ctx;
    // one task per MX host after its addresses are known, then a summary
    let mut more = Vec::new();
    let mut deps: Vec<String> = Vec::new();
    for host in &hosts {
        let dep = format!("dns.mx.host.{host}");
        let id = format!("rbl.mx.{host}");
        deps.push(id.clone());
        let h = host.clone();
        more.push(Task::new(&id, &[&dep], move |ctx, res| {
            let mut out = Vec::new();
            for ip in crate::mxchecks::host_ips(res, &h)
                .into_iter()
                .filter(|i| crate::netguard::is_public(*i))
            {
                out.extend(ip_checks(
                    ctx,
                    res,
                    ip,
                    Scope::Receiving,
                    &format!("MX {h}"),
                ));
            }
            (out, vec![])
        }));
    }
    let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
    more.push(Task::new("rbl.mx.summary", &dep_refs, move |_, res| {
        let ips: Vec<IpAddr> = hosts
            .iter()
            .flat_map(|h| crate::mxchecks::host_ips(res, h))
            .filter(|i| crate::netguard::is_public(*i))
            .collect();
        (
            vec![summary_for(
                res,
                &ips,
                Scope::Receiving,
                "rbl.mx.summary",
                "the MX addresses",
            )],
            vec![],
        )
    }));
    (vec![], more)
}

/// One line per scope: what was checked, what was listed, which lists did
/// not answer.
fn summary_for(res: &Results, ips: &[IpAddr], scope: Scope, id: &str, what: &str) -> Check {
    let problems = match res.fact("rbl_problems") {
        Some(Json::Object(f)) => f,
        _ => Vec::new(),
    };
    let listed: Vec<(String, Vec<String>)> = ips
        .iter()
        .filter_map(|ip| {
            let l: Vec<String> = res
                .fact_entry("rbl_listed", &ip.to_string())
                .and_then(|v| {
                    v.as_array().map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                })
                .unwrap_or_default();
            (!l.is_empty()).then(|| (ip.to_string(), l))
        })
        .collect();
    let n_lists = dnsbl::LISTS
        .iter()
        .filter(|l| l.polarity == Polarity::Block && l.kinds.contains(&Kind::Ip4))
        .count();
    let refused: Vec<String> = problems
        .iter()
        .map(|(zone, why)| {
            format!(
                "{}: {}",
                dnsbl::by_zone(zone).map(|l| l.name).unwrap_or(zone),
                why.as_str().unwrap_or("")
            )
        })
        .collect();
    let mut c = if ips.is_empty() {
        Check::new(
            id,
            scope,
            CAT,
            Verdict::Unknown,
            Severity::Info,
            format!("blocklists: nothing to check for {what}"),
            "no public address to look up",
        )
    } else if !listed.is_empty() {
        let (v, sev) = if scope == Scope::Sending {
            (Verdict::Fail, Severity::High)
        } else {
            (Verdict::Warn, Severity::Low)
        };
        Check::new(
            id,
            scope,
            CAT,
            v,
            sev,
            format!("blocklist listings for {what}"),
            listed
                .iter()
                .map(|(ip, l)| format!("{ip}: {}", l.join(", ")))
                .collect::<Vec<_>>()
                .join("; "),
        )
    } else if refused.len() >= n_lists / 2 {
        Check::new(id, scope, CAT, Verdict::Unknown, Severity::Info, format!("blocklists mostly unanswered for {what}"), format!("{} of the lists refused or did not answer this resolver — a listing cannot be ruled out", refused.len())).fix(resolver_fix())
    } else {
        Check::new(
            id,
            scope,
            CAT,
            Verdict::Pass,
            Severity::Info,
            format!("{what}: no blocklist listing"),
            format!(
                "{} address(es) checked against {} IP list(s){}",
                ips.len(),
                n_lists,
                if refused.is_empty() {
                    String::new()
                } else {
                    format!(" ({} did not answer)", refused.len())
                }
            ),
        )
    };
    if !refused.is_empty() {
        c = c.evidence("lists that did not answer", refused.join("\n"));
        if c.fix.is_none() && c.verdict == Verdict::Pass {
            c = c.fix(resolver_fix());
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_list() {
        let ids: Vec<String> = tasks().into_iter().map(|t| t.id).collect();
        assert_eq!(ids, ["rbl.sender", "rbl.domain", "rbl.mx"]);
    }
}
