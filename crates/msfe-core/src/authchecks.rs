//! The sender-authentication checks of the delivery test: SPF, DKIM and
//! DMARC as receivers evaluate them. All on the sending side. Facts written:
//! `spf_record`, `dkim_selectors` ([selector]), `dmarc_policy`.

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::json::Json;
use crate::spf::{Qualifier, SpfResult};
use crate::{dkim, dmarc, spf};

const S: Scope = Scope::Sending;

pub fn tasks() -> Vec<Task> {
    vec![
        Task::new("spf", &["dns.domain"], spf_task),
        Task::new("dkim", &["dns.domain"], dkim_task),
        Task::new("dmarc", &["spf", "dkim"], dmarc_task),
    ]
}

fn spf_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let cat = Category::Spf;
    let mut out = Vec::new();
    let recs = match spf::records_at(&ctx.dns, d) {
        Ok(r) => r,
        Err(e) => {
            out.push(Check::new(
                "spf.record",
                S,
                cat,
                Verdict::Unknown,
                Severity::Info,
                "SPF record",
                format!("could not look up TXT records: {e}"),
            ));
            return (out, vec![]);
        }
    };
    let mailhost = res
        .fact_strs("mx_hosts")
        .first()
        .cloned()
        .unwrap_or_else(|| format!("mail.{d}"));
    let suggested = Fix {
        summary: "Publish one SPF record naming every host that sends mail for the domain, ending with -all".into(),
        dns_record: Some(format!("{d}. 3600 IN TXT \"v=spf1 mx a:{mailhost} -all\"")),
        location: Some("cPanel → Email Deliverability → Manage (or the zone editor at the DNS host)".into()),
        ..Default::default()
    };
    match recs.len() {
        0 => {
            out.push(
                Check::new("spf.record", S, cat, Verdict::Fail, Severity::High, "no SPF record", "receivers cannot tell which servers may send for the domain: mail is more likely to be marked as spam, DMARC cannot pass through SPF, and forged mail from the domain is not rejected")
                    .fix(suggested),
            );
            return (out, vec![]);
        }
        1 => {}
        n => {
            out.push(
                Check::new("spf.record", S, cat, Verdict::Fail, Severity::Critical, format!("{n} SPF records"), "more than one v=spf1 record is a permanent error (RFC 7208 §4.5): receivers treat the domain as having a broken policy and may reject its mail")
                    .evidence("TXT", recs.join("\n"))
                    .fix_summary("Merge the records into a single v=spf1 TXT record"),
            );
            return (out, vec![]);
        }
    }
    let raw = &recs[0];
    res.set_fact("spf_record", Json::str(raw));
    let rec = match spf::parse(raw) {
        Ok(r) => r,
        Err(e) => {
            out.push(
                Check::new(
                    "spf.syntax",
                    S,
                    cat,
                    Verdict::Fail,
                    Severity::Critical,
                    "SPF record does not parse",
                    format!("{e} — receivers treat a malformed record as a permanent error"),
                )
                .evidence("TXT", raw.clone())
                .fix(suggested),
            );
            return (out, vec![]);
        }
    };
    out.push(
        Check::new(
            "spf.record",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "one SPF record",
            format!("{} mechanism(s)", rec.terms.len()),
        )
        .evidence("TXT", raw.clone()),
    );

    // the `all` qualifier
    out.push(match rec.all_qualifier() {
        Some(Qualifier::Fail) => Check::new("spf.all", S, cat, Verdict::Pass, Severity::Info, "ends with -all", "unlisted senders fail SPF"),
        Some(Qualifier::SoftFail) => Check::new("spf.all", S, cat, Verdict::Pass, Severity::Info, "ends with ~all", "unlisted senders soft-fail — accepted by most receivers but marked; fine, and what DMARC-aligned domains usually use"),
        Some(Qualifier::Neutral) => Check::new("spf.all", S, cat, Verdict::Warn, Severity::Medium, "ends with ?all", "neutral: the record says nothing about unlisted senders, so it protects nothing").fix_summary("End the record with -all (or ~all)"),
        Some(Qualifier::Pass) => Check::new("spf.all", S, cat, Verdict::Fail, Severity::Critical, "ends with +all", "the record authorises every host on the internet to send as the domain — receivers treat this as no policy at all, and some as a spam signal").fix_summary("Replace +all with -all"),
        None if rec.redirect.is_some() => Check::new("spf.all", S, cat, Verdict::Pass, Severity::Info, "redirect= record", format!("the policy of {} applies", rec.redirect.as_deref().unwrap_or(""))),
        None => Check::new("spf.all", S, cat, Verdict::Warn, Severity::Medium, "no all mechanism", "without an all term the default result is neutral: unlisted senders are not rejected").fix_summary("Append -all to the record"),
    });

    // walk: lookups, void, includes, loops
    let w = spf::walk(&ctx.dns, d);
    let lookups_ev = w.lookup_terms.join("\n");
    out.push(match w.lookups {
        0..=8 => Check::new("spf.lookups", S, cat, Verdict::Pass, Severity::Info, format!("{} DNS lookups", w.lookups), "within the limit of 10 (RFC 7208 §4.6.4)").evidence("lookup terms", lookups_ev.clone()),
        9 | 10 => Check::new("spf.lookups", S, cat, Verdict::Warn, Severity::Medium, format!("{} DNS lookups", w.lookups), "at the limit of 10 — one more include and every receiver returns a permanent error").evidence("lookup terms", lookups_ev.clone()).fix_summary("Remove unused includes or replace a/mx terms with ip4/ip6"),
        n => Check::new("spf.lookups", S, cat, Verdict::Fail, Severity::Critical, format!("{n} DNS lookups"), "more than 10 lookups is a permanent error (RFC 7208 §4.6.4): receivers reject or ignore the record and mail is not authenticated").evidence("lookup terms", lookups_ev.clone()).fix_summary("Drop vendors no longer used, flatten includes into ip4/ip6 terms, or split sending across subdomains"),
    });
    out.push(match w.void_lookups {
        0 | 1 => Check::new("spf.void", S, cat, Verdict::Pass, Severity::Info, "void lookups within limit", format!("{} lookup(s) returned nothing (limit 2)", w.void_lookups)),
        2 => Check::new("spf.void", S, cat, Verdict::Warn, Severity::Low, "2 void lookups", "at the limit: a term that resolves to nothing (RFC 7208 §4.6.4)").fix_summary("Remove mechanisms whose names no longer resolve"),
        n => Check::new("spf.void", S, cat, Verdict::Fail, Severity::High, format!("{n} void lookups"), "more than 2 lookups returning nothing is a permanent error for receivers that enforce it").fix_summary("Remove mechanisms whose names no longer resolve"),
    });
    if !w.missing_includes.is_empty() || !w.loops.is_empty() || w.depth_exceeded {
        let mut msg = Vec::new();
        if !w.missing_includes.is_empty() {
            msg.push(format!(
                "include targets without an SPF record: {}",
                w.missing_includes.join(", ")
            ));
        }
        if !w.loops.is_empty() {
            msg.push(format!("include loop through: {}", w.loops.join(", ")));
        }
        if w.depth_exceeded {
            msg.push("includes nested more than 10 deep".into());
        }
        out.push(
            Check::new(
                "spf.includes",
                S,
                cat,
                Verdict::Fail,
                Severity::High,
                "broken include chain",
                format!("{} — a permanent error for receivers", msg.join("; ")),
            )
            .evidence(
                "records",
                w.records
                    .iter()
                    .map(|(d, r)| format!("{d}: {r}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .fix_summary("Remove or correct the failing include: terms"),
        );
    } else {
        out.push(
            Check::new(
                "spf.includes",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                format!("{} record(s) in the include chain", w.records.len()),
                "every include resolves to a record",
            )
            .evidence(
                "records",
                w.records
                    .iter()
                    .map(|(d, r)| format!("{d}: {r}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        );
    }
    if !w.errors.is_empty() {
        out.push(Check::new(
            "spf.includes.lookup",
            S,
            cat,
            Verdict::Unknown,
            Severity::Info,
            "part of the chain could not be looked up",
            w.errors.join("; "),
        ));
    }
    if w.uses_ptr {
        out.push(
            Check::new(
                "spf.ptr",
                S,
                cat,
                Verdict::Warn,
                Severity::Low,
                "uses the ptr mechanism",
                "ptr is deprecated (RFC 7208 §5.5): slow, unreliable and skipped by some receivers",
            )
            .fix_summary("Replace ptr with ip4/ip6 or a: terms"),
        );
    }
    if w.uses_macros {
        out.push(Check::new("spf.macros", S, cat, Verdict::Warn, Severity::Low, "uses macros", "valid, but hard to audit and mishandled by some checkers — make sure the macro targets really answer"));
    }
    // record length
    let strings = ctx
        .dns
        .query(d, crate::dns::RType::Txt)
        .ok()
        .and_then(|r| {
            r.of(crate::dns::RType::Txt)
                .iter()
                .find_map(|rr| match &rr.data {
                    crate::dns::RData::Txt(parts)
                        if parts
                            .concat()
                            .trim_start()
                            .to_ascii_lowercase()
                            .starts_with("v=spf1") =>
                    {
                        Some(parts.clone())
                    }
                    _ => None,
                })
        })
        .unwrap_or_default();
    if strings.iter().any(|s| s.len() > 255) {
        out.push(Check::new("spf.length", S, cat, Verdict::Fail, Severity::High, "a TXT string longer than 255 bytes", "DNS character-strings are limited to 255 bytes; a longer one cannot be published correctly — split it").evidence("split as", spf::split_txt_strings(raw).iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(" ")));
    } else if raw.len() > 450 {
        out.push(Check::new("spf.length", S, cat, Verdict::Warn, Severity::Low, format!("long record ({} bytes)", raw.len()), "answers above ~450 bytes may not fit a plain UDP reply; some resolvers then retry over TCP — fine, but a sign the record could be simpler"));
    }
    if w.ip_count.0 > 65_536 {
        out.push(Check::new("spf.ip_scope", S, cat, Verdict::Warn, Severity::Low, "authorises a very large address space", format!("{} IPv4 addresses are allowed to send as the domain — a compromised host anywhere in that range can spoof it", w.ip_count.0)));
    }
    // evaluation for the supplied sending IP
    if let Some(ip) = ctx.inputs.ip {
        let (r, trace) = spf::evaluate(&ctx.dns, d, ip);
        let tr = trace.join("\n");
        let fix = Fix {
            summary: format!(
                "Authorise {ip} in the SPF record (an ip4/ip6 term, or the vendor's include)"
            ),
            dns_record: Some(format!("{d}. 3600 IN TXT \"{}\"", insert_ip(raw, ip))),
            ..Default::default()
        };
        out.push(
            match r {
                SpfResult::Pass => Check::new("spf.eval", S, cat, Verdict::Pass, Severity::Info, format!("{ip} passes SPF"), "the address is authorised to send for the domain"),
                SpfResult::SoftFail => Check::new("spf.eval", S, cat, Verdict::Warn, Severity::Medium, format!("{ip} soft-fails SPF"), "the address is not listed; ~all lets receivers accept but mark such mail, and DMARC cannot pass through SPF").fix(fix),
                SpfResult::Fail => Check::new("spf.eval", S, cat, Verdict::Fail, Severity::High, format!("{ip} fails SPF"), "the address is not authorised and the record says -all: receivers reject or junk its mail").fix(fix),
                SpfResult::Neutral | SpfResult::None => Check::new("spf.eval", S, cat, Verdict::Warn, Severity::Medium, format!("{ip}: SPF says nothing"), "no mechanism matched and the record does not fail unlisted senders — no authentication either way").fix(fix),
                SpfResult::PermError => Check::new("spf.eval", S, cat, Verdict::Fail, Severity::Critical, "SPF evaluation is a permanent error", "receivers cannot evaluate the record at all (see the other SPF findings)"),
                SpfResult::TempError => Check::new("spf.eval", S, cat, Verdict::Unknown, Severity::Info, "SPF evaluation hit a DNS error", "a lookup in the chain did not answer"),
            }
            .target(ip.to_string())
            .evidence("trace", tr),
        );
    }
    (out, vec![])
}

/// A copy of the record with an ip4/ip6 term for `ip` before `all`.
fn insert_ip(raw: &str, ip: std::net::IpAddr) -> String {
    let term = match ip {
        std::net::IpAddr::V4(a) => format!("ip4:{a}"),
        std::net::IpAddr::V6(a) => format!("ip6:{a}"),
    };
    let mut toks: Vec<&str> = raw.split_whitespace().collect();
    let pos = toks
        .iter()
        .position(|t| {
            t.trim_start_matches(['+', '-', '~', '?'])
                .eq_ignore_ascii_case("all")
        })
        .unwrap_or(toks.len());
    toks.insert(pos, &term);
    toks.join(" ")
}

fn dkim_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let cat = Category::Dkim;
    let mut out = Vec::new();
    let found = dkim::discover(&ctx.dns, d, ctx.inputs.selector.as_deref());
    let keys: Vec<&dkim::DkimKey> = found.iter().filter_map(|(_, k, _)| k.as_ref()).collect();
    res.set_fact(
        "dkim_selectors",
        Json::Array(keys.iter().map(|k| Json::str(&k.selector)).collect()),
    );
    if keys.is_empty() {
        let (verdict, sev, title, expl) = match found.first() {
            Some((sel, None, Some(e))) => (Verdict::Unknown, Severity::Info, format!("selector {sel}: lookup failed"), format!("{e}")),
            Some((sel, None, None)) => (Verdict::Fail, Severity::High, format!("no DKIM key at selector {sel}"), format!("{sel}._domainkey.{d} has no key record: messages signed with this selector fail DKIM at every receiver")),
            _ => (
                Verdict::Unknown,
                Severity::Info,
                "no DKIM selector found".into(),
                format!("none of the {} common selector names has a key at {d}. That does not prove DKIM is absent — selectors can be anything. Find yours in a sent message's DKIM-Signature header (the s= tag) and enter it under Advanced", dkim::COMMON_SELECTORS.len().min(40)),
            ),
        };
        out.push(Check::new("dkim.discovery", S, cat, verdict, sev, title, expl).fix(Fix {
            summary: "If the domain sends from this server: cPanel → Email Deliverability → Manage → Install the suggested DKIM record (selector default)".into(),
            dns_record: Some(format!("default._domainkey.{d}. 3600 IN TXT \"v=DKIM1; k=rsa; p=<public key>\"")),
            ..Default::default()
        }));
        return (out, vec![]);
    }
    let user_sel = ctx.inputs.selector.as_deref();
    let live: Vec<&str> = keys
        .iter()
        .filter(|k| !k.revoked)
        .map(|k| k.selector.as_str())
        .collect();
    let retired: Vec<&str> = keys
        .iter()
        .filter(|k| k.revoked)
        .map(|k| k.selector.as_str())
        .collect();
    res.set_fact(
        "dkim_selectors",
        Json::Array(live.iter().map(|s| Json::str(*s)).collect()),
    );
    out.push(if live.is_empty() {
        Check::new("dkim.discovery", S, cat, Verdict::Unknown, Severity::Info, "only retired DKIM selectors found", format!("{} selector(s) publish revoked keys ({}); the selector in use was not among the common names — find it in a sent message's DKIM-Signature s= tag and enter it under Advanced", retired.len(), retired.join(", ")))
    } else {
        Check::new("dkim.discovery", S, cat, Verdict::Pass, Severity::Info, format!("{} DKIM selector(s) found", live.len()), format!("selectors: {}{}. Discovery is best effort — other selectors may exist", live.join(", "), if retired.is_empty() { String::new() } else { format!(" (retired: {})", retired.join(", ")) }))
    });
    for k in keys {
        let t = format!("{}._domainkey.{d}", k.selector);
        if k.revoked {
            out.push(if user_sel == Some(k.selector.as_str()) {
                Check::new("dkim.record", S, cat, Verdict::Fail, Severity::High, format!("selector {} is revoked", k.selector), "the record has an empty p= tag: the key was retired. Messages still signed with this selector fail DKIM at every receiver").target(&t).evidence("TXT", k.raw.clone()).fix_summary("Sign with a current selector, or re-publish the key if it is still in use")
            } else {
                Check::new("dkim.record", S, cat, Verdict::NotApplicable, Severity::Info, format!("selector {} is retired", k.selector), "an empty p= tag marks a key that is no longer in use — normal after a key rotation").target(&t).evidence("TXT", k.raw.clone())
            });
            continue;
        }
        if !k.problems.is_empty() {
            out.push(Check::new("dkim.record", S, cat, if k.problems.iter().any(|p| p.contains("base64") || p.contains("no p=") || p.contains("does not parse")) { Verdict::Fail } else { Verdict::Warn }, Severity::High, format!("selector {}: record problems", k.selector), k.problems.join("; ")).target(&t).evidence("TXT", k.raw.clone()).fix_summary("Re-publish the key exactly as the signer generated it (cPanel: Email Deliverability → Repair)"));
        } else {
            out.push(
                Check::new(
                    "dkim.record",
                    S,
                    cat,
                    Verdict::Pass,
                    Severity::Info,
                    format!("selector {}: valid record", k.selector),
                    format!(
                        "k={}{}",
                        k.k,
                        k.n.as_ref()
                            .map(|n| format!(", note: {n}"))
                            .unwrap_or_default()
                    ),
                )
                .target(&t)
                .evidence("TXT", k.raw.clone()),
            );
        }
        let fix = Fix {
            summary: format!("Rotate selector {} to a 2048-bit RSA key", k.selector),
            location: Some("cPanel → Email Deliverability → Manage → DKIM → Generate a new key (2048), then re-publish".into()),
            ..Default::default()
        };
        out.push(match (k.k.as_str(), k.bits) {
            ("rsa", Some(b)) if b >= 2048 => Check::new("dkim.key", S, cat, Verdict::Pass, Severity::Info, format!("{b}-bit RSA key"), "meets current receiver requirements").target(&t),
            ("rsa", Some(b)) if b >= 1024 => Check::new("dkim.key", S, cat, Verdict::Warn, Severity::Medium, format!("{b}-bit RSA key"), "1024-bit keys are the minimum receivers accept (Gmail/Yahoo) and are considered weak; 2048 is the norm").target(&t).fix(fix),
            ("rsa", Some(b)) => Check::new("dkim.key", S, cat, Verdict::Fail, Severity::High, format!("{b}-bit RSA key"), "keys under 1024 bits are rejected by major receivers (RFC 8301): signatures with this key do not count").target(&t).fix(fix),
            ("ed25519", _) => Check::new("dkim.key", S, cat, Verdict::Pass, Severity::Info, "ed25519 key", "modern and strong; not every receiver verifies ed25519 yet, so most senders publish an RSA key alongside").target(&t),
            (_, None) => Check::new("dkim.key", S, cat, Verdict::Unknown, Severity::Info, "key size unknown", "the key material did not parse as RSA").target(&t),
            (other, _) => Check::new("dkim.key", S, cat, Verdict::Warn, Severity::Medium, format!("unknown key type {other}"), "receivers ignore key types they do not know").target(&t),
        });
        if k.t_testing {
            out.push(Check::new("dkim.testing", S, cat, Verdict::Warn, Severity::Medium, format!("selector {} is in testing mode", k.selector), "t=y tells receivers to treat signatures as unsigned — remove the flag once signing works").target(&t).fix_summary("Remove t=y from the record"));
        }
        if !k.h.is_empty() && !k.h.iter().any(|h| h == "sha256") {
            out.push(Check::new("dkim.hash", S, cat, Verdict::Fail, Severity::High, format!("selector {} allows only {}", k.selector, k.h.join("/")), "sha1 signatures are rejected by receivers (RFC 8301); the record must allow sha256").target(&t).fix_summary("Remove the h= tag or set h=sha256"));
        }
    }
    (out, vec![])
}

fn dmarc_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let d = &ctx.inputs.domain;
    if res.fact_bool("domain_exists") == Some(false) {
        return (vec![], vec![]);
    }
    let cat = Category::Dmarc;
    let mut out = Vec::new();
    let l = match dmarc::lookup(&ctx.dns, d) {
        Ok(l) => l,
        Err(e) => {
            out.push(Check::new(
                "dmarc.record",
                S,
                cat,
                Verdict::Unknown,
                Severity::Info,
                "DMARC record",
                format!("could not look up _dmarc.{d}: {e}"),
            ));
            return (out, vec![]);
        }
    };
    let suggested = Fix {
        summary: "Publish a DMARC record; start with p=none to receive reports, move to quarantine/reject once SPF and DKIM align".into(),
        dns_record: Some(format!("_dmarc.{d}. 3600 IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@{d}\"")),
        location: Some("cPanel → Email Deliverability → Manage, or the zone editor at the DNS host".into()),
        ..Default::default()
    };
    let at = format!("_dmarc.{}", l.at);
    match l.records.len() {
        0 => {
            out.push(Check::new("dmarc.record", S, cat, Verdict::Fail, Severity::High, "no DMARC record", format!("neither _dmarc.{d}{} publishes a policy. Gmail and Yahoo require DMARC from bulk senders since 2024; without it forged mail from the domain is not rejected and you get no reports", if l.inherited { format!(" nor _dmarc.{}", l.at) } else { String::new() })).fix(suggested));
            return (out, vec![]);
        }
        1 => {}
        n => {
            out.push(Check::new("dmarc.record", S, cat, Verdict::Fail, Severity::Critical, format!("{n} DMARC records"), "more than one v=DMARC1 record: receivers discard the policy entirely (RFC 7489 §6.6.3)").target(&at).evidence("TXT", l.records.join("\n")).fix_summary("Keep exactly one record"));
            return (out, vec![]);
        }
    }
    let raw = &l.records[0];
    let Some(rec) = l.record.as_ref() else {
        out.push(
            Check::new(
                "dmarc.syntax",
                S,
                cat,
                Verdict::Fail,
                Severity::Critical,
                "DMARC record does not parse",
                l.parse_error.clone().unwrap_or_default(),
            )
            .target(&at)
            .evidence("TXT", raw.clone())
            .fix(suggested),
        );
        return (out, vec![]);
    };
    res.set_fact(
        "dmarc_policy",
        Json::str(rec.p.clone().unwrap_or_else(|| "none".into())),
    );
    out.push(
        Check::new(
            "dmarc.record",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            if l.inherited {
                format!("DMARC inherited from {}", l.at)
            } else {
                "one DMARC record".into()
            },
            if l.inherited {
                format!(
                    "{d} has no record of its own; the organizational domain's applies{}",
                    if l.org_uncertain {
                        " (the organizational domain was guessed — no public-suffix list here)"
                    } else {
                        ""
                    }
                )
            } else {
                "the record applies to this domain".into()
            },
        )
        .target(&at)
        .evidence("TXT", raw.clone()),
    );
    if !rec.problems.is_empty() {
        out.push(
            Check::new(
                "dmarc.syntax",
                S,
                cat,
                if rec
                    .problems
                    .iter()
                    .any(|p| p.contains("invalid") || p.contains("not none"))
                {
                    Verdict::Fail
                } else {
                    Verdict::Warn
                },
                Severity::Medium,
                "DMARC record has problems",
                rec.problems.join("; "),
            )
            .target(&at)
            .fix_summary("Correct the tags (v=DMARC1 first, then p=, then the rest)"),
        );
    }
    out.push(match rec.p.as_deref() {
        Some("reject") => Check::new("dmarc.policy", S, cat, Verdict::Pass, Severity::Info, "p=reject", "forged mail from the domain is rejected by receivers that honour DMARC"),
        Some("quarantine") => Check::new("dmarc.policy", S, cat, Verdict::Pass, Severity::Info, "p=quarantine", "forged mail goes to spam; consider p=reject once reports show only legitimate mail aligning"),
        _ => Check::new("dmarc.policy", S, cat, Verdict::Warn, Severity::Medium, "p=none", "monitoring only: receivers report but do not act, so the domain is still spoofable").fix_summary("Move to p=quarantine, then p=reject, once the reports show your legitimate mail passing"),
    });
    if rec.pct < 100 {
        out.push(Check::new("dmarc.pct", S, cat, Verdict::Warn, Severity::Low, format!("pct={}", rec.pct), "only part of the failing mail gets the policy applied — a rollout setting, not a final state"));
    }
    if let (Some(sp), Some(p)) = (&rec.sp, &rec.p) {
        let rank = |v: &str| match v {
            "reject" => 2,
            "quarantine" => 1,
            _ => 0,
        };
        if rank(sp) < rank(p) {
            out.push(
                Check::new(
                    "dmarc.sp",
                    S,
                    cat,
                    Verdict::Warn,
                    Severity::Medium,
                    format!("sp={sp} is weaker than p={p}"),
                    "subdomains can be forged more easily than the domain itself",
                )
                .fix_summary(format!("Set sp={p} or remove sp=")),
            );
        }
    }
    if rec.rua.is_empty() {
        out.push(Check::new("dmarc.rua", S, cat, Verdict::Warn, Severity::Low, "no rua= report address", "you receive no aggregate reports, so you cannot see who sends as the domain or what fails").fix_summary(format!("Add rua=mailto:dmarc@{d} (or a report service)")));
    } else {
        out.push(Check::new(
            "dmarc.rua",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "aggregate reports requested",
            rec.rua.join(", "),
        ));
        for u in &rec.rua {
            if let Some(rd) = dmarc::mailto_domain(u) {
                if dmarc::is_external(d, &rd) {
                    let t = format!("{d}._report._dmarc.{rd}");
                    out.push(match dmarc::external_report_authorized(&ctx.dns, d, &rd) {
                        Some(true) => Check::new("dmarc.rua_external", S, cat, Verdict::Pass, Severity::Info, format!("{rd} accepts reports for {d}"), "the external receiver publishes the authorization record").target(&t),
                        Some(false) => Check::new("dmarc.rua_external", S, cat, Verdict::Warn, Severity::Medium, format!("{rd} has not authorised reports for {d}"), "reports to another organization's domain need <domain>._report._dmarc.<receiver> (RFC 7489 §7.1) — receivers silently drop them otherwise. Report services usually publish it; a plain mailbox does not").target(&t).fix(Fix {
                            summary: format!("Publish the authorization at the receiving domain {rd}"),
                            dns_record: Some(format!("{d}._report._dmarc.{rd}. 3600 IN TXT \"v=DMARC1\"")),
                            ..Default::default()
                        }),
                        None => Check::new("dmarc.rua_external", S, cat, Verdict::Unknown, Severity::Info, format!("could not check {rd}'s authorization"), "DNS did not answer").target(&t),
                    });
                }
            }
        }
    }
    // alignment hint
    let dkim_sel = res.fact_strs("dkim_selectors");
    let spf_ok = res.fact_str("spf_record").is_some();
    let mut hints = Vec::new();
    hints.push(format!(
        "SPF alignment ({}): the MAIL FROM domain must be {d}{}",
        if rec.aspf == 's' { "strict" } else { "relaxed" },
        if rec.aspf == 's' {
            " exactly"
        } else {
            " or a subdomain"
        }
    ));
    hints.push(format!(
        "DKIM alignment ({}): the signature's d= must be {d}{}",
        if rec.adkim == 's' {
            "strict"
        } else {
            "relaxed"
        },
        if rec.adkim == 's' {
            " exactly"
        } else {
            " or a subdomain"
        }
    ));
    if !spf_ok && dkim_sel.is_empty() {
        out.push(Check::new("dmarc.alignment", S, cat, Verdict::Warn, Severity::High, "nothing found that could align", "no SPF record and no DKIM key were found: mail from the domain cannot pass DMARC, and the policy above then applies to your own mail").evidence("alignment rules", hints.join("\n")));
    } else {
        out.push(
            Check::new(
                "dmarc.alignment",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                "alignment requirements",
                format!(
                    "{}{}",
                    if spf_ok { "SPF present" } else { "no SPF" },
                    if dkim_sel.is_empty() {
                        ", no DKIM selector found"
                    } else {
                        ", DKIM present"
                    }
                ),
            )
            .evidence("alignment rules", hints.join("\n")),
        );
    }
    (out, vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_the_ip_before_all() {
        assert_eq!(
            insert_ip("v=spf1 mx -all", "1.2.3.4".parse().unwrap()),
            "v=spf1 mx ip4:1.2.3.4 -all"
        );
        assert_eq!(
            insert_ip("v=spf1 mx", "2001:db8::1".parse().unwrap()),
            "v=spf1 mx ip6:2001:db8::1"
        );
        assert_eq!(
            insert_ip("v=spf1 ~ALL", "1.2.3.4".parse().unwrap()),
            "v=spf1 ip4:1.2.3.4 ~ALL"
        );
    }
}
