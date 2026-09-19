//! Transport-security checks of the delivery test: MTA-STS, TLS-RPT, DANE
//! and BIMI, plus the two DNS checks that need more than one resolver's
//! word — DNSSEC validation and agreement between the authoritative servers.

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::dns::{DnsError, RData, RType};
use crate::dnsx::{self, DnssecState};
use crate::httpclient::{self, Pin};
use crate::json::Json;
use crate::mtasts::{self, StsMode};
use crate::netguard;
use crate::tlsprobe::{self, Dane};
use std::net::IpAddr;
use std::time::Duration;

const TS: Category = Category::TransportSecurity;
const DNS: Category = Category::Dns;
/// The largest MTA-STS policy fetched (RFC 8461 gives no cap; 64 KiB is generous).
const POLICY_MAX_BYTES: u64 = 65_536;
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
const DANE_TIMEOUT: Duration = Duration::from_secs(50);

pub fn tasks() -> Vec<Task> {
    vec![
        Task::new("dns.dnssec", &["dns.domain"], dnssec_task),
        Task::new("dns.auth_consistency", &["dns.ns"], consistency_task),
        Task::new("mtasts", &["dns.mx"], mtasts_task),
        Task::new("tlsrpt", &["dns.domain"], tlsrpt_task),
        Task::new("dane", &["dns.mx"], dane_task),
        Task::new("bimi", &["dmarc"], bimi_task),
    ]
}

fn no_net() -> bool {
    std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_some()
}

fn unknown(id: &str, scope: Scope, cat: Category, title: &str, why: impl Into<String>) -> Check {
    Check::new(id, scope, cat, Verdict::Unknown, Severity::Info, title, why)
}

fn dns_unknown(id: &str, scope: Scope, cat: Category, title: &str, e: &DnsError) -> Check {
    unknown(id, scope, cat, title, format!("could not look up: {e}"))
}

// ---- DNSSEC ------------------------------------------------------------------

fn dnssec_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false)
        && res.fact_bool("domain_servfail") != Some(true)
    {
        return (vec![], vec![]);
    }
    let both = Scope::Sending; // it affects both sides; sending sorts first
    if no_net() {
        return (
            vec![unknown(
                "dns.dnssec",
                both,
                DNS,
                "DNSSEC",
                "network probes are disabled",
            )],
            vec![],
        );
    }
    let r = dnsx::dnssec_state(&ctx.dns, d, RType::Mx);
    res.set_fact("dnssec", Json::str(r.state.as_str()));
    let via = format!("checked with {}", r.via);
    let check = match r.state {
        DnssecState::Secure => Check::new("dns.dnssec", both, DNS, Verdict::Pass, Severity::Info, "DNSSEC validates", format!("{d} is signed and the chain of trust verifies ({via}); DANE is possible"))
            .evidence(&r.via, r.evidence),
        DnssecState::Insecure => Check::new("dns.dnssec", both, DNS, Verdict::Pass, Severity::Info, "not signed with DNSSEC", format!("{d} has no DS record at its parent ({via}). Signing is optional; without it DANE cannot be used and MTA-STS is the way to protect delivery"))
            .evidence(&r.via, r.evidence),
        DnssecState::Bogus => Check::new("dns.dnssec", both, DNS, Verdict::Fail, Severity::Critical, "DNSSEC is broken", format!("{d} publishes a DS record but the signatures do not validate ({via}). Every validating resolver — Google, Cloudflare, Quad9, most ISPs and this server's unbound — answers SERVFAIL for the domain: mail to it bounces and mail from it fails SPF/DKIM/DMARC lookups"))
            .evidence(&r.via, r.evidence)
            .fix(Fix {
                summary: "Make the DS record at the registrar match the zone's KSK, or remove the DS if the zone is no longer signed".into(),
                location: Some("cPanel: WHM → DNS Functions → Zone Editor → DNSSEC (copy the DS to the registrar); other hosts: the DNS provider's DNSSEC page".into()),
                command: Some(format!("delv +cd {d} MX")),
                ..Default::default()
            }),
        DnssecState::Unknown(why) => Check::new("dns.dnssec", both, DNS, Verdict::Unknown, Severity::Info, "DNSSEC not verified", why)
            .fix_summary("Install bind-utils (delv) or the private validating resolver (Settings → Resolver → Install) so the chain can be verified here"),
    };
    (vec![check], vec![])
}

// ---- authoritative consistency ----------------------------------------------

fn consistency_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = ctx.inputs.domain.clone();
    let ns = res.fact_strs("ns");
    let both = Scope::Sending;
    if ns.is_empty() {
        return (vec![], vec![]); // dns.ns already failed
    }
    if no_net() {
        return (
            vec![unknown(
                "dns.auth_consistency",
                both,
                DNS,
                "name servers agree",
                "network probes are disabled",
            )],
            vec![],
        );
    }
    let mut checks = Vec::new();
    let mut disagreements = Vec::new();
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut evidence = Vec::new();
    let mut reachable_min = usize::MAX;
    for (label, rtype) in [
        ("SOA serial", RType::Soa),
        ("MX", RType::Mx),
        ("SPF", RType::Txt),
    ] {
        let c = dnsx::compare_across_ns(&ctx.dns, &ns, &d, rtype, true);
        let mut answers: Vec<(String, Vec<String>)> = Vec::new();
        for (server, r) in &c.per_ns {
            match r {
                Ok(lines) => {
                    let lines: Vec<String> = if rtype == RType::Txt {
                        lines
                            .iter()
                            .filter(|l| l.contains("v=spf1"))
                            .cloned()
                            .collect()
                    } else {
                        lines.clone()
                    };
                    answers.push((server.clone(), lines));
                }
                Err(e) => {
                    if !failures.iter().any(|(s, _)| s == server) {
                        failures.push((server.clone(), e.clone()));
                    }
                }
            }
        }
        reachable_min = reachable_min.min(answers.len());
        let agree = answers.windows(2).all(|w| w[0].1 == w[1].1);
        if !agree {
            disagreements.push(label);
        }
        for (server, lines) in &answers {
            evidence.push(format!(
                "{label} @ {server}: {}",
                if lines.is_empty() {
                    "(none)".to_string()
                } else {
                    lines.join(" | ")
                }
            ));
        }
    }
    for (server, e) in &failures {
        evidence.push(format!("{server}: {e}"));
    }
    let ev = evidence.join("\n");
    if reachable_min == 0 || reachable_min == usize::MAX {
        checks.push(unknown("dns.auth_consistency", both, DNS, "name servers agree", "none of the authoritative servers could be queried directly (firewalled outbound DNS?)").evidence("queries", ev));
        return (checks, vec![]);
    }
    if disagreements == ["SOA serial"] {
        // the data agrees; only the serial differs — a lagging secondary, or
        // a provider that generates serials per server (Google does)
        checks.push(
            Check::new("dns.auth_consistency", both, DNS, Verdict::Warn, Severity::Low, "name servers report different SOA serials", format!("the MX and SPF records of {d} agree on every server, but the serials differ: either a secondary has not refreshed yet, or the DNS provider generates serials per server (large providers do). Worth a look if the zone was just changed"))
                .evidence("per server", ev.clone())
                .fix_summary("If you just edited the zone, wait for the secondaries to refresh (SOA refresh interval) or trigger a NOTIFY; otherwise nothing to do"),
        );
    } else if !disagreements.is_empty() {
        checks.push(
            Check::new("dns.auth_consistency", both, DNS, Verdict::Fail, Severity::High, format!("name servers disagree on {}", disagreements.join(", ")), format!("the authoritative servers of {d} return different data. Which answer a sender gets depends on which server its resolver happens to ask — mail and SPF results become unpredictable. A serial mismatch means a secondary has not picked up the latest zone"))
                .evidence("per server", ev.clone())
                .fix_summary("Re-sync the zone: bump the SOA serial on the primary, check NOTIFY/AXFR to the secondaries (or the DNS host's replication), and make sure every listed NS actually hosts the zone"),
        );
    } else {
        checks.push(
            Check::new(
                "dns.auth_consistency",
                both,
                DNS,
                Verdict::Pass,
                Severity::Info,
                "name servers agree",
                format!(
                    "{} server(s) return the same SOA serial, MX and SPF records",
                    reachable_min
                ),
            )
            .evidence("per server", ev.clone()),
        );
    }
    for (server, e) in failures {
        checks.push(
            Check::new("dns.ns.reachable", both, DNS, Verdict::Warn, Severity::Medium, format!("name server {server} does not answer authoritatively"), format!("{e}. Resolvers that pick this server get no answer and retry another — slower lookups, and outright failures if the others are down too"))
                .target(&server)
                .fix_summary(format!("Make sure {server} is reachable on port 53 (UDP and TCP) and serves the zone, or drop it from the NS set at the registrar")),
        );
    }
    (checks, vec![])
}

// ---- MTA-STS ---------------------------------------------------------------

fn mtasts_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = ctx.inputs.domain.clone();
    let r = Scope::Receiving;
    if res.fact_bool("domain_exists") == Some(false) || res.fact_bool("null_mx") == Some(true) {
        return (vec![], vec![]);
    }
    let name = format!("_mta-sts.{d}");
    let recs: Vec<String> = match ctx.dns.txt(&name) {
        Ok(v) => v
            .into_iter()
            .filter(|t| t.trim_start().to_ascii_lowercase().starts_with("v=stsv1"))
            .collect(),
        Err(e) => {
            return (
                vec![dns_unknown("mtasts.txt", r, TS, "MTA-STS record", &e)],
                vec![],
            )
        }
    };
    let mut out = Vec::new();
    if recs.is_empty() {
        let stamp = crate::civil::Date::from_unix(crate::delivery::now_secs())
            .to_string()
            .replace('-', "");
        out.push(
            Check::new("mtasts.txt", r, TS, Verdict::Warn, Severity::Low, "no MTA-STS policy", format!("{name} has no v=STSv1 record. Without MTA-STS (or DANE) senders use opportunistic TLS only: an attacker on the path can strip STARTTLS and read the mail. Gmail, Microsoft and others honour MTA-STS"))
                .fix(Fix {
                    summary: "Publish an MTA-STS policy (start in testing mode, switch to enforce once the MX certificates are right)".into(),
                    dns_record: Some(format!("_mta-sts.{d}. 3600 IN TXT \"v=STSv1; id={stamp}01\"")),
                    location: Some(format!("serve https://mta-sts.{d}/.well-known/mta-sts.txt (text/plain) from a site with a valid certificate for mta-sts.{d} — cPanel: a subdomain with AutoSSL and the file under .well-known/")),
                    ..Default::default()
                }),
        );
        return (out, vec![]);
    }
    if recs.len() > 1 {
        out.push(Check::new("mtasts.txt", r, TS, Verdict::Fail, Severity::High, "several MTA-STS records", format!("{name} has {} v=STSv1 records; RFC 8461 §3.1 says senders must treat that as no policy", recs.len())).evidence("TXT", recs.join("\n")).fix_summary("Keep exactly one _mta-sts TXT record"));
        return (out, vec![]);
    }
    let txt = match mtasts::parse_sts_txt(&recs[0]) {
        Ok(t) => t,
        Err(e) => {
            out.push(Check::new("mtasts.txt", r, TS, Verdict::Fail, Severity::High, "invalid MTA-STS record", format!("{e} — senders ignore the policy")).evidence("TXT", recs[0].clone()).fix(Fix {
                summary: "Fix the record".into(),
                dns_record: Some(format!("_mta-sts.{d}. 3600 IN TXT \"v=STSv1; id=<letters and digits, change it whenever the policy changes>\"")),
                ..Default::default()
            }));
            return (out, vec![]);
        }
    };
    out.push(
        Check::new(
            "mtasts.txt",
            r,
            TS,
            Verdict::Pass,
            Severity::Info,
            "MTA-STS record present",
            format!("policy id {}", txt.id),
        )
        .evidence("TXT", recs[0].clone()),
    );

    // the policy file
    let host = format!("mta-sts.{d}");
    let url = format!("https://{host}/.well-known/mta-sts.txt");
    let ip: Option<IpAddr> = match ctx.dns.addrs(&host) {
        Ok((v4, v6)) => v4
            .first()
            .map(|a| IpAddr::V4(*a))
            .or_else(|| v6.first().map(|a| IpAddr::V6(*a))),
        Err(e) => {
            out.push(dns_unknown("mtasts.policy", r, TS, "MTA-STS policy", &e).target(&url));
            return (out, vec![]);
        }
    };
    let Some(ip) = ip else {
        out.push(
            Check::new("mtasts.policy", r, TS, Verdict::Fail, Severity::High, format!("{host} does not resolve"), "the TXT record announces a policy but the host that must serve it has no address; senders cannot fetch it and fall back to opportunistic TLS")
                .target(&url)
                .fix(Fix {
                    summary: format!("Give {host} an address (A/AAAA or CNAME) and serve the policy over HTTPS"),
                    dns_record: Some(format!("{host}. 3600 IN A <web server IP>")),
                    ..Default::default()
                }),
        );
        return (out, vec![]);
    };
    if no_net() {
        out.push(
            unknown(
                "mtasts.policy",
                r,
                TS,
                "MTA-STS policy",
                "network probes are disabled",
            )
            .target(&url),
        );
        return (out, vec![]);
    }
    if let Err(why) = netguard::outbound_allowed(ip, ctx.inputs.audit) {
        out.push(
            unknown(
                "mtasts.policy",
                r,
                TS,
                "MTA-STS policy",
                format!("{why}; the policy was not fetched"),
            )
            .target(&url),
        );
        return (out, vec![]);
    }
    let pin = Pin {
        host: host.clone(),
        port: 443,
        ip,
    };
    let fetched = match httpclient::get(&url, FETCH_TIMEOUT, Some(&pin), POLICY_MAX_BYTES) {
        Ok(f) => f,
        Err(e) => {
            out.push(
                Check::new("mtasts.policy", r, TS, Verdict::Fail, Severity::High, "MTA-STS policy cannot be fetched", format!("{e}. Senders that support MTA-STS fetch this file after seeing the TXT record; failing that they fall back to opportunistic TLS and retry on every delivery — the TXT record promises a policy that is not there"))
                    .target(&url)
                    .fix_summary(format!("Serve {url} over HTTPS with a certificate valid for {host} (no redirects), content type text/plain")),
            );
            return (out, vec![]);
        }
    };
    if fetched.status != 200 {
        out.push(
            Check::new(
                "mtasts.policy",
                r,
                TS,
                Verdict::Fail,
                Severity::High,
                format!("MTA-STS policy answers HTTP {}", fetched.status),
                "the policy must be served with status 200; anything else counts as no policy",
            )
            .target(&url)
            .evidence("body", fetched.body.chars().take(500).collect::<String>())
            .fix_summary(format!("Put the policy file at {url}")),
        );
        return (out, vec![]);
    }
    let policy = match mtasts::parse_policy(&fetched.body) {
        Ok(p) => p,
        Err(e) => {
            out.push(Check::new("mtasts.policy", r, TS, Verdict::Fail, Severity::High, "invalid MTA-STS policy", format!("{e} — senders ignore it")).target(&url).evidence("policy", fetched.body.chars().take(1000).collect::<String>()).fix_summary("The file needs `version: STSv1`, `mode:`, one `mx:` line per MX pattern and `max_age:` (seconds), one key per line"));
            return (out, vec![]);
        }
    };
    let mut notes = policy.problems.clone();
    if !fetched
        .content_type
        .as_deref()
        .unwrap_or("")
        .starts_with("text/plain")
    {
        notes.push(format!(
            "served as `{}` instead of text/plain (RFC 8461 §3.3)",
            fetched
                .content_type
                .clone()
                .unwrap_or_else(|| "no content type".into())
        ));
    }
    out.push(if notes.is_empty() {
        Check::new(
            "mtasts.policy",
            r,
            TS,
            Verdict::Pass,
            Severity::Info,
            "MTA-STS policy served",
            format!("{url} answers 200 with a valid policy"),
        )
        .target(&url)
        .evidence("policy", fetched.body.clone())
    } else {
        Check::new(
            "mtasts.policy",
            r,
            TS,
            Verdict::Warn,
            Severity::Low,
            "MTA-STS policy served with remarks",
            notes.join("; "),
        )
        .target(&url)
        .evidence("policy", fetched.body.clone())
    });
    res.set_fact("mtasts_mode", Json::str(policy.mode.as_str()));
    out.push(match policy.mode {
        StsMode::Enforce => Check::new("mtasts.mode", r, TS, Verdict::Pass, Severity::Info, "MTA-STS mode: enforce", "senders refuse to deliver to an MX whose certificate does not validate or that lacks STARTTLS — the protection is active"),
        StsMode::Testing => Check::new("mtasts.mode", r, TS, Verdict::Warn, Severity::Low, "MTA-STS mode: testing", "senders report failures (via TLS-RPT) but still deliver over weaker connections; switch to enforce once the reports are clean").fix_summary("Change `mode: testing` to `mode: enforce` in the policy and bump the TXT record's id"),
        StsMode::None => Check::new("mtasts.mode", r, TS, Verdict::Warn, Severity::Low, "MTA-STS mode: none", "the policy is published but disabled — it protects nothing").fix_summary("Set `mode: enforce` (or `testing` while checking) and bump the TXT record's id"),
    });
    // every MX must be covered
    let hosts = res.fact_strs("mx_hosts");
    if policy.mode != StsMode::None {
        let uncovered: Vec<&String> = hosts
            .iter()
            .filter(|h| !policy.mx.iter().any(|p| mtasts::mx_matches(p, h)))
            .collect();
        out.push(if uncovered.is_empty() {
            Check::new("mtasts.mx_match", r, TS, Verdict::Pass, Severity::Info, "policy covers every MX", format!("patterns: {}", policy.mx.join(", ")))
        } else {
            let (v, sev) = if policy.mode == StsMode::Enforce { (Verdict::Fail, Severity::Critical) } else { (Verdict::Warn, Severity::High) };
            Check::new("mtasts.mx_match", r, TS, v, sev, format!("MX not covered by the policy: {}", uncovered.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), format!("the policy lists {} but DNS publishes {}. In enforce mode senders skip the uncovered hosts entirely — if every MX is uncovered, mail is not delivered at all", policy.mx.join(", "), hosts.join(", ")))
                .evidence("policy mx", policy.mx.join("\n"))
                .fix_summary(format!("Add `mx: {}` lines to the policy (a `*.` wildcard matches one label), then change the id in the TXT record", uncovered.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("`, `mx: ")))
        });
    }
    out.push(if policy.max_age < 86_400 {
        Check::new("mtasts.max_age", r, TS, Verdict::Warn, Severity::Low, format!("max_age is only {} s", policy.max_age), "senders cache the policy that long; a day or more is usual (RFC 8461 suggests weeks) so that a temporary outage of the policy site does not drop the protection").fix_summary("Raise `max_age:` to 604800 (a week) or more")
    } else if policy.max_age > 31_557_600 {
        Check::new("mtasts.max_age", r, TS, Verdict::Warn, Severity::Low, format!("max_age is {} s (over a year)", policy.max_age), "changes to the MX set take that long to reach senders that cached the policy — RFC 8461 caps it at a year").fix_summary("Lower `max_age:` to 31557600 or less")
    } else {
        Check::new("mtasts.max_age", r, TS, Verdict::Pass, Severity::Info, format!("max_age {} s", policy.max_age), format!("senders cache the policy for {} day(s)", policy.max_age / 86_400))
    });
    // the MX certificates must satisfy the policy: after the TLS probes
    if policy.mode != StsMode::None && !hosts.is_empty() {
        let mode = policy.mode;
        let mut deps: Vec<String> = vec!["mx.servers".into()];
        deps.extend(
            hosts
                .iter()
                .filter(|h| h.parse::<IpAddr>().is_err())
                .map(|h| format!("mx.host.{h}")),
        );
        let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
        let child = Task::new("mtasts.tls", &dep_refs, move |_, res| {
            let mut out = Vec::new();
            let tls = match res.fact("mx_tls") {
                Some(Json::Object(f)) => f,
                _ => Vec::new(),
            };
            for (host, v) in tls {
                let ok = matches!(v.get("ok"), Some(Json::Bool(true)));
                let names: Vec<String> = v
                    .get("names")
                    .and_then(|n| {
                        n.as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_string))
                                .collect()
                        })
                    })
                    .unwrap_or_default();
                let covers = tlsprobe::hostname_matches(&names, None, &host);
                let (v, sev) = if mode == StsMode::Enforce {
                    (Verdict::Fail, Severity::Critical)
                } else {
                    (Verdict::Warn, Severity::High)
                };
                out.push(if ok && covers {
                    Check::new("mtasts.tls", Scope::Receiving, TS, Verdict::Pass, Severity::Info, format!("{host} satisfies the MTA-STS policy"), "STARTTLS with a trusted certificate that names the MX").target(&host)
                } else if !ok {
                    Check::new("mtasts.tls", Scope::Receiving, TS, v, sev, format!("{host} fails the MTA-STS policy: certificate not trusted"), format!("with `mode: {}` senders that honour MTA-STS {} deliver to this MX until its certificate chain validates", mode.as_str(), if mode == StsMode::Enforce { "do not" } else { "will not, once enforced," })).target(&host).fix_summary(format!("Install a publicly trusted certificate (with its intermediates) for {host} on the MX"))
                } else {
                    Check::new("mtasts.tls", Scope::Receiving, TS, v, sev, format!("{host} fails the MTA-STS policy: certificate names do not include the MX"), format!("the certificate is for {}; MTA-STS requires the MX host name itself to be covered", if names.is_empty() { "no names".to_string() } else { names.join(", ") })).target(&host).fix_summary(format!("Issue a certificate that includes {host} (a wildcard for its parent domain also works)"))
                });
            }
            (out, vec![])
        });
        return (out, vec![child]);
    }
    (out, vec![])
}

// ---- TLS-RPT ---------------------------------------------------------------

fn tlsrpt_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    let r = Scope::Receiving;
    if res.fact_bool("domain_exists") == Some(false) || res.fact_bool("null_mx") == Some(true) {
        return (vec![], vec![]);
    }
    let name = format!("_smtp._tls.{d}");
    let recs: Vec<String> = match ctx.dns.txt(&name) {
        Ok(v) => v
            .into_iter()
            .filter(|t| {
                t.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("v=tlsrptv1")
            })
            .collect(),
        Err(e) => {
            return (
                vec![dns_unknown("tlsrpt.record", r, TS, "TLS-RPT record", &e)],
                vec![],
            )
        }
    };
    let c = if recs.is_empty() {
        Check::new("tlsrpt.record", r, TS, Verdict::Warn, Severity::Low, "no TLS-RPT record", format!("{name} is empty. TLS-RPT is optional: senders that support it mail you a daily report of TLS failures towards your MX — the only way to see MTA-STS/DANE problems from the sender's side"))
            .fix(Fix {
                summary: "Publish a TLS-RPT record with a mailbox that receives the reports".into(),
                dns_record: Some(format!("_smtp._tls.{d}. 3600 IN TXT \"v=TLSRPTv1; rua=mailto:tls-reports@{d}\"")),
                ..Default::default()
            })
    } else if recs.len() > 1 {
        Check::new(
            "tlsrpt.record",
            r,
            TS,
            Verdict::Fail,
            Severity::Low,
            "several TLS-RPT records",
            "senders ignore the record set when more than one exists",
        )
        .evidence("TXT", recs.join("\n"))
        .fix_summary("Keep one _smtp._tls TXT record")
    } else {
        match mtasts::parse_tlsrpt(&recs[0]) {
            Ok(t) => Check::new(
                "tlsrpt.record",
                r,
                TS,
                Verdict::Pass,
                Severity::Info,
                "TLS-RPT record present",
                format!("reports go to {}", t.rua.join(", ")),
            )
            .evidence("TXT", recs[0].clone()),
            Err(e) => Check::new(
                "tlsrpt.record",
                r,
                TS,
                Verdict::Fail,
                Severity::Low,
                "invalid TLS-RPT record",
                e,
            )
            .evidence("TXT", recs[0].clone())
            .fix(Fix {
                summary: "Fix the record".into(),
                dns_record: Some(format!(
                    "_smtp._tls.{d}. 3600 IN TXT \"v=TLSRPTv1; rua=mailto:tls-reports@{d}\""
                )),
                ..Default::default()
            }),
        }
    };
    (vec![c], vec![])
}

// ---- DANE ------------------------------------------------------------------

fn dane_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    if res.fact_bool("domain_exists") == Some(false) || res.fact_bool("null_mx") == Some(true) {
        return (vec![], vec![]);
    }
    let audit = ctx.inputs.audit;
    let mut more = Vec::new();
    for host in res.fact_strs("mx_hosts") {
        if host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let dep = format!("dns.mx.host.{host}");
        more.push(Task::new(
            &format!("dane.host.{host}"),
            &[&dep],
            move |ctx, res| (dane_host(ctx, res, &host, audit), vec![]),
        ));
    }
    (vec![], more)
}

fn dane_host(ctx: &Ctx, res: &Results, host: &str, audit: bool) -> Vec<Check> {
    let r = Scope::Receiving;
    let name = format!("_25._tcp.{host}");
    let mut out = Vec::new();
    let tlsa: Vec<(u8, u8, u8, Vec<u8>)> = match ctx.dns.query(&name, RType::Tlsa) {
        Ok(resp) => resp
            .of(RType::Tlsa)
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::Tlsa {
                    usage,
                    selector,
                    matching,
                    data,
                } => Some((*usage, *selector, *matching, data.clone())),
                _ => None,
            })
            .collect(),
        Err(e) => {
            out.push(dns_unknown("dane.tlsa", r, TS, &format!("DANE for {host}"), &e).target(host));
            return out;
        }
    };
    if tlsa.is_empty() {
        out.push(Check::new("dane.tlsa", r, TS, Verdict::NotApplicable, Severity::Info, format!("no DANE for {host}"), format!("{name} has no TLSA record. DANE is optional and needs a DNSSEC-signed zone; MTA-STS covers the same ground for most senders")).target(host));
        return out;
    }
    let presented: Vec<String> = tlsa
        .iter()
        .map(|(u, s, m, d)| format!("{u} {s} {m} {}", crate::dns::hex(d)))
        .collect();
    out.push(
        Check::new(
            "dane.tlsa",
            r,
            TS,
            Verdict::Pass,
            Severity::Info,
            format!("TLSA records for {host}"),
            format!("{} record(s)", tlsa.len()),
        )
        .target(host)
        .evidence("TLSA", presented.join("\n")),
    );
    let odd: Vec<String> = tlsa
        .iter()
        .filter(|(u, s, m, _)| !matches!(u, 2 | 3) || *s > 1 || *m > 2)
        .map(|(u, s, m, _)| format!("{u} {s} {m}"))
        .collect();
    if !odd.is_empty() {
        out.push(Check::new("dane.tlsa.params", r, TS, Verdict::Warn, Severity::Medium, format!("unusual TLSA parameters on {host}"), format!("{} — RFC 7672 says SMTP DANE uses usage 3 (DANE-EE) or 2 (DANE-TA); usages 0/1 are ignored by senders", odd.join(", "))).target(host).fix_summary("Publish `3 1 1 <SHA-256 of the SPKI>` (and `2 1 1` of the issuing CA if you rotate certificates)"));
    }
    // TLSA without DNSSEC is worthless
    if no_net() {
        out.push(
            unknown(
                "dane.dnssec",
                r,
                TS,
                &format!("DNSSEC of {name}"),
                "network probes are disabled",
            )
            .target(host),
        );
        return out;
    }
    let sec = dnsx::dnssec_state(&ctx.dns, &name, RType::Tlsa);
    out.push(match sec.state {
        DnssecState::Secure => Check::new("dane.dnssec", r, TS, Verdict::Pass, Severity::Info, format!("TLSA of {host} is DNSSEC-signed"), format!("validated with {}", sec.via)).target(host).evidence(&sec.via, sec.evidence),
        DnssecState::Insecure => Check::new("dane.dnssec", r, TS, Verdict::Fail, Severity::High, format!("TLSA of {host} is not DNSSEC-signed"), "DANE senders only trust TLSA records that validate; unsigned ones are ignored, so the records achieve nothing").target(host).evidence(&sec.via, sec.evidence).fix_summary(format!("Sign the zone that holds {name} with DNSSEC and publish its DS at the registrar")),
        DnssecState::Bogus => Check::new("dane.dnssec", r, TS, Verdict::Fail, Severity::Critical, format!("TLSA of {host} fails DNSSEC validation"), "validating senders get SERVFAIL for the MX host — with DANE that means they refuse to deliver").target(host).evidence(&sec.via, sec.evidence).fix_summary("Fix the DNSSEC chain of the MX host's zone"),
        DnssecState::Unknown(why) => unknown("dane.dnssec", r, TS, &format!("DNSSEC of {name}"), why).target(host),
    });
    // does the certificate match?
    let ips = crate::mxchecks::host_ips(res, host);
    let Some(ip) = ips.iter().find(|i| i.is_ipv4()).or(ips.first()).copied() else {
        out.push(
            unknown(
                "dane.match",
                r,
                TS,
                &format!("DANE match on {host}"),
                "the MX has no address to connect to",
            )
            .target(host),
        );
        return out;
    };
    if let Err(why) = netguard::outbound_allowed(ip, audit) {
        out.push(unknown("dane.match", r, TS, &format!("DANE match on {host}"), why).target(host));
        return out;
    }
    if ctx.time_left() < Duration::from_secs(5) {
        out.push(
            unknown(
                "dane.match",
                r,
                TS,
                &format!("DANE match on {host}"),
                "the run's time limit was reached",
            )
            .target(host),
        );
        return out;
    }
    let t = tlsprobe::starttls(ip, 25, host, &tlsa, DANE_TIMEOUT.min(ctx.time_left()));
    let tgt = format!("{host} ({ip})");
    out.push(match t.dane {
        Some(Dane::Matched(line)) => Check::new("dane.match", r, TS, Verdict::Pass, Severity::Info, format!("DANE matches on {host}"), "the certificate presented over STARTTLS matches a TLSA record").target(&tgt).evidence("openssl", line),
        Some(Dane::NoMatch) => Check::new("dane.match", r, TS, Verdict::Fail, Severity::Critical, format!("DANE mismatch on {host}"), "no TLSA record matches the certificate the MX presents — DANE senders (Posteo, Comcast, many .nl/.de providers, Exim/Postfix with DANE on) refuse to deliver. This is what happens after a certificate renewal when the TLSA record is not updated")
            .target(&tgt)
            .evidence("openssl", t.transcript.clone())
            .fix(Fix {
                summary: "Publish a TLSA record for the current certificate's public key (3 1 1), or pin the issuing CA (2 1 1) so renewals need no DNS change".into(),
                dns_record: Some(format!("_25._tcp.{host}. 3600 IN TLSA 3 1 1 <sha256 of the SPKI>")),
                command: Some(format!("openssl s_client -starttls smtp -connect {ip}:25 -servername {host} </dev/null 2>/dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256")),
                ..Default::default()
            }),
        None => unknown("dane.match", r, TS, &format!("DANE match on {host}"), format!("openssl reported no DANE result: {}", t.error.clone().unwrap_or_else(|| "no TLS session".into()))).target(&tgt).evidence("openssl", t.transcript.clone()),
    });
    out
}

// ---- BIMI ------------------------------------------------------------------

fn bimi_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    let s = Scope::Sending;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let name = format!("default._bimi.{d}");
    let recs: Vec<String> = match ctx.dns.txt(&name) {
        Ok(v) => v
            .into_iter()
            .filter(|t| t.trim_start().to_ascii_lowercase().starts_with("v=bimi1"))
            .collect(),
        Err(e) => return (vec![dns_unknown("bimi.record", s, TS, "BIMI", &e)], vec![]),
    };
    if recs.is_empty() {
        return (vec![Check::new("bimi.record", s, TS, Verdict::NotApplicable, Severity::Info, "no BIMI record", "BIMI (a brand logo next to messages in Gmail, Yahoo, Apple Mail) is optional; it needs DMARC at quarantine/reject and, for most mailbox providers, a Verified Mark Certificate")], vec![]);
    }
    let c = match mtasts::parse_bimi(&recs[0]) {
        Err(e) => Check::new(
            "bimi.record",
            s,
            TS,
            Verdict::Fail,
            Severity::Low,
            "invalid BIMI record",
            e,
        )
        .evidence("TXT", recs[0].clone()),
        Ok(b) => {
            let policy = res.fact_str("dmarc_policy").unwrap_or_default();
            if b.logo.is_none() {
                Check::new(
                    "bimi.record",
                    s,
                    TS,
                    Verdict::Pass,
                    Severity::Info,
                    "BIMI declined",
                    "an empty `l=` tells mailbox providers not to show a logo",
                )
                .evidence("TXT", recs[0].clone())
            } else if policy != "quarantine" && policy != "reject" {
                Check::new("bimi.record", s, TS, Verdict::Warn, Severity::Medium, "BIMI record without an enforcing DMARC policy", format!("mailbox providers show the logo only when DMARC is at p=quarantine (pct=100) or p=reject; the domain has p={}", if policy.is_empty() { "none / no record".to_string() } else { policy }))
                    .evidence("TXT", recs[0].clone())
                    .fix_summary("Move DMARC to p=quarantine or p=reject (after checking the aggregate reports)")
            } else {
                Check::new(
                    "bimi.record",
                    s,
                    TS,
                    Verdict::Pass,
                    Severity::Info,
                    "BIMI record present",
                    format!(
                        "logo {}{}",
                        b.logo.clone().unwrap_or_default(),
                        if b.vmc.is_some() {
                            ", with a VMC"
                        } else {
                            " — no VMC (a=), so Gmail and Apple will not show it"
                        }
                    ),
                )
                .evidence("TXT", recs[0].clone())
            }
        }
    };
    (vec![c], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_ids_and_deps() {
        let t = tasks();
        let ids: Vec<&str> = t.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "dns.dnssec",
                "dns.auth_consistency",
                "mtasts",
                "tlsrpt",
                "dane",
                "bimi"
            ]
        );
        assert_eq!(t[5].deps, vec!["dmarc"]);
    }
}
