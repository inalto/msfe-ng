//! The mail-server checks of the delivery test: one SMTP courtesy call and
//! one STARTTLS handshake per MX host and address family. They run after the
//! DNS tasks resolved the MX hosts (`mx_ips` fact) and never go beyond
//! EHLO/QUIT.

use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::json::Json;
use crate::netguard;
use crate::smtpprobe::{self, SmtpProbe};
use crate::tlsprobe::{self, TlsProbe};
use std::net::IpAddr;
use std::time::Duration;

const MX: Category = Category::MailServers;
const TLS: Category = Category::TransportSecurity;
const SC: Scope = Scope::Receiving;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Greet-pause of 20–30 s is a common anti-spam measure: wait it out.
const BANNER_TIMEOUT: Duration = Duration::from_secs(40);
const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
/// openssl sits through the greet-pause again, then handshakes.
const TLS_TIMEOUT: Duration = Duration::from_secs(50);
/// A certificate this close to its end is worth a warning.
const EXPIRY_WARN_DAYS: u64 = 14;

pub fn tasks() -> Vec<Task> {
    vec![Task::new("mx.servers", &["dns.mx"], servers_task)]
}

/// Well-known MX suffixes → the mail provider behind them.
pub fn provider_of(mx_hosts: &[String]) -> Option<&'static str> {
    const TABLE: &[(&str, &str)] = &[
        (".google.com", "Google Workspace / Gmail"),
        (".googlemail.com", "Google Workspace / Gmail"),
        (".protection.outlook.com", "Microsoft 365"),
        (".olc.protection.outlook.com", "Outlook.com"),
        (".pphosted.com", "Proofpoint"),
        (".ppe-hosted.com", "Proofpoint Essentials"),
        (".mimecast.com", "Mimecast"),
        (".mimecast.co.za", "Mimecast"),
        (".mimecast-offshore.com", "Mimecast"),
        (".zoho.com", "Zoho Mail"),
        (".zoho.eu", "Zoho Mail"),
        (".mail.icloud.com", "iCloud Mail"),
        (".yahoodns.net", "Yahoo Mail"),
        (".secureserver.net", "GoDaddy"),
        (".messagelabs.com", "Symantec / Broadcom Email Security"),
        (".barracudanetworks.com", "Barracuda"),
        (".kundenserver.de", "IONOS"),
        (".ionos.com", "IONOS"),
        (".ovh.net", "OVH"),
        (".mailgun.org", "Mailgun"),
        (".emailsrvr.com", "Rackspace"),
        (".protonmail.ch", "Proton Mail"),
        (".fastmail.com", "Fastmail"),
        (".messagingengine.com", "Fastmail"),
        (".hostedemail.com", "OpenSRS"),
        (".mxrouting.net", "MXroute"),
        (".mail.aruba.it", "Aruba"),
        (".register.it", "Register.it"),
        (".hornetsecurity.com", "Hornetsecurity"),
        (".sophos.com", "Sophos Email"),
        (".trendmicro.com", "Trend Micro Email Security"),
        (".mailcontrol.com", "Forcepoint"),
        (".cisco.com", "Cisco Secure Email"),
        (".iphmx.com", "Cisco Secure Email"),
        (".spamexperts.", "SpamExperts / N-able"),
        (".antispamcloud.com", "SpamExperts / N-able"),
        (".mailprotect.", "SpamExperts / N-able"),
    ];
    for h in mx_hosts {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        for (suffix, name) in TABLE {
            if h.ends_with(suffix) || h.contains(&format!("{suffix}.")) {
                return Some(name);
            }
        }
    }
    None
}

/// Does this host have a public IPv6 address of its own?
fn have_public_v6() -> bool {
    netguard::own_addresses()
        .iter()
        .any(|a| a.is_ipv6() && netguard::is_public(*a))
}

fn servers_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let mut checks = Vec::new();
    if res.fact_bool("null_mx") == Some(true) || res.fact_bool("domain_exists") == Some(false) {
        return (checks, vec![]);
    }
    let hosts = res.fact_strs("mx_hosts");
    if hosts.is_empty() {
        return (checks, vec![]);
    }
    // "pref host" strings → priority per host
    let prefs: Vec<(u16, String)> = res
        .fact_strs("mx")
        .iter()
        .filter_map(|s| {
            let (p, h) = s.split_once(' ')?;
            Some((p.parse().ok()?, h.to_string()))
        })
        .collect();
    let best = prefs.iter().map(|(p, _)| *p).min().unwrap_or(0);

    // the provider behind the MX hosts
    let own = netguard::own_addresses();
    let served_here = match res.fact("mx_ips") {
        Some(Json::Object(f)) => f.iter().any(|(_, ips)| {
            ips.as_array().is_some_and(|a| {
                a.iter().any(|i| {
                    i.as_str()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .is_some_and(|ip| own.contains(&ip))
                })
            })
        }),
        _ => false,
    };
    let provider = match provider_of(&hosts) {
        Some(p) => p.to_string(),
        None if served_here => "this server (cPanel / Exim)".to_string(),
        None => "self-hosted or unrecognised provider".to_string(),
    };
    res.set_fact("provider", Json::str(&provider));
    checks.push(
        Check::new("meta.provider", SC, Category::Meta, Verdict::Pass, Severity::Info, format!("mail provider: {provider}"), format!("inferred from the MX hosts ({}); provider-specific advice in this report follows it", hosts.join(", ")))
            .evidence("MX hosts", hosts.join("\n")),
    );

    let v6_here = have_public_v6();
    let mut more = Vec::new();
    for host in hosts {
        if host.parse::<IpAddr>().is_ok() {
            continue; // IP-literal MX: already failed by dns.mx.target
        }
        let pref = prefs
            .iter()
            .find(|(_, h)| *h == host)
            .map(|(p, _)| *p)
            .unwrap_or(0);
        let primary = pref == best;
        let dep = format!("dns.mx.host.{host}");
        let id = format!("mx.host.{host}");
        let audit = ctx.inputs.audit;
        more.push(Task::new(&id, &[&dep], move |ctx, res| {
            (
                host_checks(ctx, res, &host, primary, v6_here, audit),
                vec![],
            )
        }));
    }
    (checks, more)
}

/// The addresses `dns.mx.host.<host>` recorded for an MX.
pub fn host_ips(res: &Results, host: &str) -> Vec<IpAddr> {
    match res.fact("mx_ips") {
        Some(Json::Object(f)) => f
            .iter()
            .find(|(h, _)| h == host)
            .and_then(|(_, v)| {
                v.as_array().map(|a| {
                    a.iter()
                        .filter_map(|i| i.as_str().and_then(|s| s.parse().ok()))
                        .collect()
                })
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn host_checks(
    ctx: &Ctx,
    res: &Results,
    host: &str,
    primary: bool,
    v6_here: bool,
    audit: bool,
) -> Vec<Check> {
    let ips = host_ips(res, host);
    let mut checks = Vec::new();
    if ips.is_empty() {
        return checks; // dns.mx.target already reported it
    }
    let v4 = ips.iter().find(|i| i.is_ipv4()).copied();
    let v6 = ips.iter().find(|i| i.is_ipv6()).copied();
    for (fam, ip) in [("IPv4", v4), ("IPv6", v6)] {
        let Some(ip) = ip else { continue };
        let tgt = format!("{host} ({ip})");
        if fam == "IPv6" && !v6_here {
            checks.push(
                Check::new(
                    "mx.connect",
                    SC,
                    MX,
                    Verdict::NotApplicable,
                    Severity::Info,
                    format!("{host} over IPv6"),
                    "this server has no public IPv6 address, so the IPv6 path was not probed",
                )
                .target(&tgt),
            );
            continue;
        }
        if std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_some() {
            // dev/test knob: no connections leave the box
            checks.push(
                Check::new(
                    "mx.connect",
                    SC,
                    MX,
                    Verdict::Unknown,
                    Severity::Info,
                    format!("{host} over {fam} not probed"),
                    "network probes are disabled (MSFE_NG_DELIVERY_NO_NET)",
                )
                .target(&tgt),
            );
            continue;
        }
        if let Err(why) = netguard::outbound_allowed(ip, audit) {
            checks.push(
                Check::new(
                    "mx.connect",
                    SC,
                    MX,
                    Verdict::Unknown,
                    Severity::Info,
                    format!("{host} over {fam} not probed"),
                    why,
                )
                .target(&tgt),
            );
            continue;
        }
        if ctx.cancelled() || ctx.time_left() < CONNECT_TIMEOUT {
            checks.push(
                Check::new(
                    "mx.connect",
                    SC,
                    MX,
                    Verdict::Unknown,
                    Severity::Info,
                    format!("{host} over {fam} not probed"),
                    "the run's time limit was reached",
                )
                .target(&tgt),
            );
            continue;
        }
        // the SMTP call and the openssl handshake run side by side so a
        // greet-pause is waited out once, not twice
        let tls_timeout = TLS_TIMEOUT.min(ctx.time_left());
        let tls_host = host.to_string();
        let tls_thread =
            std::thread::spawn(move || tlsprobe::starttls(ip, 25, &tls_host, &[], tls_timeout));
        let p = smtpprobe::probe(
            ip,
            25,
            host,
            &ctx.helo,
            CONNECT_TIMEOUT,
            BANNER_TIMEOUT.min(ctx.time_left()),
            SESSION_TIMEOUT,
        );
        let ptr_names = res.fact_strs(&format!("ptr.{ip}"));
        checks.extend(smtp_checks(&p, host, &tgt, fam, primary, &ptr_names));
        let t = tls_thread.join().unwrap_or_else(|_| TlsProbe {
            error: Some("the TLS probe crashed".into()),
            ..Default::default()
        });
        if p.starttls {
            checks.extend(tls_checks(&t, host, &tgt));
            record_tls_fact(res, host, &t);
        } else if t.protocol.is_some() {
            // EHLO did not list STARTTLS for us, yet openssl negotiated it
            checks.push(
                Check::new(
                    "tls.handshake",
                    SC,
                    TLS,
                    Verdict::Warn,
                    Severity::Low,
                    format!("{host} negotiates TLS although it did not advertise STARTTLS"),
                    "inconsistent: the EHLO reply to this probe lacked STARTTLS while a second connection could start TLS — check the MTA's `tls_advertise_hosts` (or equivalent) for host-dependent rules",
                )
                .target(&tgt)
                .evidence("openssl", t.transcript.clone()),
            );
        }
    }
    checks
}

/// Which names the MX presents in its certificate (for MTA-STS later).
fn record_tls_fact(res: &Results, host: &str, t: &TlsProbe) {
    let names: Vec<Json> = t
        .leaf
        .as_ref()
        .map(|c| c.sans.iter().map(Json::str).collect())
        .unwrap_or_default();
    res.insert_fact_entry(
        "mx_tls",
        host,
        Json::Object(vec![
            (
                "ok".into(),
                Json::Bool(t.protocol.is_some() && t.verify_code == Some(0)),
            ),
            ("names".into(), Json::Array(names)),
        ]),
    );
}

fn smtp_checks(
    p: &SmtpProbe,
    host: &str,
    tgt: &str,
    fam: &str,
    primary: bool,
    ptr_names: &[String],
) -> Vec<Check> {
    let mut out = Vec::new();
    let sev = if primary {
        Severity::High
    } else {
        Severity::Medium
    };
    let role = if primary { "primary" } else { "backup" };
    if p.banner.is_empty() {
        // never got a greeting: connect failure or a silent server
        let err = p.error.clone().unwrap_or_default();
        let connect_failed = err.starts_with("connection") || err.starts_with("cannot connect");
        let (id, title, why) = if connect_failed {
            (
                "mx.connect",
                format!("cannot connect to {host} over {fam}"),
                format!("{err}. Senders using {fam} cannot deliver through this {role} MX"),
            )
        } else {
            (
                "mx.banner",
                format!("{host} accepts the connection but sends no greeting"),
                format!("{err} — a firewall or a stuck MTA; senders time out"),
            )
        };
        out.push(
            Check::new(id, SC, MX, Verdict::Fail, sev, title, why)
                .target(tgt)
                .evidence("transcript", if p.transcript.is_empty() { err.clone() } else { p.transcript.clone() })
                .fix_summary(if connect_failed {
                    format!("Make sure the mail server listens on port 25 at {} and that the firewall allows it (WHM → Service Manager, csf TCP_IN)", p.ip.map(|i| i.to_string()).unwrap_or_default())
                } else {
                    "Check the MTA's logs for why the SMTP greeting is delayed (DNS lookups of the client, a full queue, a paniclog)".into()
                }),
        );
        return out;
    }
    out.push(
        Check::new(
            "mx.connect",
            SC,
            MX,
            Verdict::Pass,
            Severity::Info,
            format!("{host} answers on port 25 over {fam}"),
            format!("connected in {} ms", p.connect_ms),
        )
        .target(tgt),
    );
    let code: u16 = p.banner.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
    if code != 220 {
        out.push(
            Check::new("mx.banner", SC, MX, Verdict::Fail, sev, format!("{host} greets with {code}"), format!("the server refuses sessions at the greeting ({}). Senders are told to go away before they can deliver", p.banner))
                .target(tgt)
                .evidence("transcript", p.transcript.clone())
                .fix_summary("A 4xx greeting is temporary (load, connection limits, greylisting by source); a 5xx greeting means the server blocks this client — check the MTA's connection ACLs and blocklist lookups on the client address"),
        );
        return out;
    }
    if p.banner_ms > 5_000 {
        out.push(
            Check::new("mx.banner", SC, MX, Verdict::Warn, Severity::Low, format!("{host} delays its greeting"), format!("the 220 greeting arrived after {:.1} s. A deliberate greet-pause is a common anti-spam measure (cPanel: \"Introduce a delay into the SMTP transaction for unknown hosts\") — real senders wait, spam bots give up — but it slows every delivery and some senders time out", p.banner_ms as f64 / 1000.0))
                .target(tgt)
                .evidence("greeting", p.banner.clone()),
        );
    } else {
        out.push(
            Check::new(
                "mx.banner",
                SC,
                MX,
                Verdict::Pass,
                Severity::Info,
                format!("{host} greets promptly"),
                format!("220 after {} ms", p.banner_ms),
            )
            .target(tgt)
            .evidence("greeting", p.banner.clone()),
        );
    }
    if let Some(err) = &p.error {
        out.push(
            Check::new(
                "mx.ehlo",
                SC,
                MX,
                Verdict::Fail,
                sev,
                format!("{host} rejects EHLO and HELO"),
                format!("{err} — no session can be opened"),
            )
            .target(tgt)
            .evidence("transcript", p.transcript.clone()),
        );
        return out;
    }
    let helo_only = p.caps.iter().any(|c| c.starts_with("(HELO only"));
    let same_org = |a: &str, b: &str| {
        crate::psl::organizational_domain(a).0 == crate::psl::organizational_domain(b).0
    };
    match &p.ehlo_name {
        Some(name)
            if name.eq_ignore_ascii_case(host)
                || ptr_names.iter().any(|n| n.eq_ignore_ascii_case(name)) =>
        {
            out.push(
                Check::new(
                    "mx.ehlo",
                    SC,
                    MX,
                    Verdict::Pass,
                    Severity::Info,
                    format!("{host} identifies itself as {name}"),
                    "the EHLO name matches the MX host or its reverse name",
                )
                .target(tgt),
            );
        }
        Some(name)
            if name.contains('.')
                && (same_org(name, host) || ptr_names.iter().any(|n| same_org(name, n))) =>
        {
            // Google's MXs say "mx.google.com": same organisation, fine
            out.push(
                Check::new(
                    "mx.ehlo",
                    SC,
                    MX,
                    Verdict::Pass,
                    Severity::Info,
                    format!("{host} identifies itself as {name}"),
                    "the EHLO name belongs to the same organisation as the MX host",
                )
                .target(tgt),
            );
        }
        Some(name) => {
            out.push(
                Check::new("mx.ehlo", SC, MX, Verdict::Warn, Severity::Low, format!("{host} identifies itself as {name}"), format!("the EHLO name differs from the MX name and from its reverse DNS{} — harmless for receiving, but if the host also sends, receivers compare it with the PTR", if ptr_names.is_empty() { String::new() } else { format!(" ({})", ptr_names.join(", ")) }))
                    .target(tgt)
                    .fix_summary(format!("Set the MTA's primary hostname to {host} (Exim: `primary_hostname`, cPanel: WHM → Basic WebHost Manager Setup → hostname)")),
            );
        }
        None => out.push(
            Check::new(
                "mx.ehlo",
                SC,
                MX,
                Verdict::Unknown,
                Severity::Info,
                format!("{host}: no EHLO name"),
                "the server's EHLO reply carried no host name",
            )
            .target(tgt),
        ),
    }
    if helo_only {
        out.push(
            Check::new("mx.caps", SC, MX, Verdict::Warn, Severity::Medium, format!("{host} speaks only HELO"), "the server rejected EHLO: no SMTP extensions, so no STARTTLS, SIZE or 8BITMIME — an ancient or misconfigured MTA")
                .target(tgt)
                .evidence("transcript", p.transcript.clone()),
        );
        out.push(
            Check::new(
                "mx.starttls",
                SC,
                TLS,
                Verdict::Fail,
                sev,
                format!("{host} cannot negotiate TLS"),
                "without ESMTP there is no STARTTLS; mail to this host travels in clear text",
            )
            .target(tgt),
        );
        return out;
    }
    let mut missing = Vec::new();
    if !p.eightbit {
        missing.push("8BITMIME");
    }
    if p.size.is_none() {
        missing.push("SIZE");
    }
    if !p.pipelining {
        missing.push("PIPELINING");
    }
    let caps_ev = p.caps.join("\n");
    let auth_on_25 = !p.auth.is_empty();
    if auth_on_25 {
        out.push(
            Check::new("mx.caps", SC, MX, Verdict::Warn, Severity::Medium, format!("{host} offers AUTH before TLS on port 25"), format!("AUTH {} is advertised on the clear-text connection; credentials of clients that fall for it travel unencrypted, and port 25 should be for server-to-server mail only", p.auth.join(" ")))
                .target(tgt)
                .evidence("EHLO", caps_ev.clone())
                .fix_summary("Advertise AUTH only after STARTTLS and on the submission ports 465/587 (Exim: `auth_advertise_hosts = ${if eq{$tls_in_cipher}{}{}{*}}`; cPanel: WHM → Exim Configuration Manager → Require SSL/TLS for authentication)"),
        );
    } else if missing.is_empty() {
        out.push(
            Check::new(
                "mx.caps",
                SC,
                MX,
                Verdict::Pass,
                Severity::Info,
                format!("{host} advertises the usual extensions"),
                format!(
                    "SIZE {}{}",
                    p.size
                        .map(|s| format!("{} MB", s / 1_048_576))
                        .unwrap_or_default(),
                    if p.smtputf8 { ", SMTPUTF8" } else { "" }
                ),
            )
            .target(tgt)
            .evidence("EHLO", caps_ev.clone()),
        );
    } else {
        out.push(
            Check::new("mx.caps", SC, MX, Verdict::Warn, Severity::Low, format!("{host} lacks {}", missing.join(", ")), "senders fall back to 7-bit encoding or cannot size-check messages before sending; modern MTAs advertise these by default")
                .target(tgt)
                .evidence("EHLO", caps_ev.clone()),
        );
    }
    if p.starttls {
        out.push(
            Check::new(
                "mx.starttls",
                SC,
                TLS,
                Verdict::Pass,
                Severity::Info,
                format!("{host} offers STARTTLS"),
                "senders can encrypt the delivery",
            )
            .target(tgt),
        );
    } else {
        out.push(
            Check::new("mx.starttls", SC, TLS, Verdict::Fail, sev, format!("{host} does not offer STARTTLS"), "mail to this host travels in clear text; Gmail and Microsoft flag it, MTA-STS/DANE senders refuse to deliver")
                .target(tgt)
                .evidence("EHLO", caps_ev)
                .fix(Fix {
                    summary: "Enable STARTTLS with a valid certificate on the MX".into(),
                    location: Some("cPanel: WHM → Service Manager and AutoSSL cover Exim; other MTAs: `tls_advertise_hosts = *` (Exim), `smtpd_tls_security_level = may` (Postfix)".into()),
                    ..Default::default()
                }),
        );
    }
    out
}

fn tls_checks(t: &TlsProbe, host: &str, tgt: &str) -> Vec<Check> {
    let mut out = Vec::new();
    let Some(proto) = &t.protocol else {
        out.push(
            Check::new("tls.handshake", SC, TLS, Verdict::Fail, Severity::High, format!("TLS handshake with {host} failed"), format!("{} — senders that insist on TLS cannot deliver, others fall back to clear text", t.error.clone().unwrap_or_else(|| "no session".into())))
                .target(tgt)
                .evidence("openssl", t.transcript.clone()),
        );
        return out;
    };
    let cipher = t.cipher.clone().unwrap_or_default();
    match proto.as_str() {
        "TLSv1.3" | "TLSv1.2" => out.push(Check::new("tls.handshake", SC, TLS, Verdict::Pass, Severity::Info, format!("{host} negotiates {proto}"), format!("cipher {cipher}")).target(tgt)),
        _ => out.push(
            Check::new("tls.handshake", SC, TLS, Verdict::Fail, Severity::Medium, format!("{host} negotiates only {proto}"), format!("cipher {cipher}; TLS 1.0/1.1 are deprecated (RFC 8996) and modern senders refuse them"))
                .target(tgt)
                .fix_summary("Enable TLS 1.2 and 1.3 on the MTA (Exim: `openssl_options`/`tls_require_ciphers`; cPanel: WHM → Exim Configuration Manager → SSL/TLS Cipher Suite List)"),
        ),
    }
    // the chain
    match t.verify_code {
        Some(0) => out.push(Check::new("tls.cert.valid", SC, TLS, Verdict::Pass, Severity::Info, format!("{host} presents a trusted certificate"), format!("{} certificate(s) sent, chain verifies", t.chain_len)).target(tgt)),
        Some(10) => out.push(
            Check::new("tls.cert.valid", SC, TLS, Verdict::Fail, Severity::High, format!("{host}'s certificate has expired"), "senders that verify certificates (MTA-STS, DANE-TA, strict policies) refuse to deliver")
                .target(tgt)
                .fix_summary("Renew the certificate (cPanel: WHM → Manage AutoSSL → run, or install a valid certificate for the mail service)"),
        ),
        Some(c @ 18..=21) => out.push(
            Check::new("tls.cert.valid", SC, TLS, Verdict::Warn, Severity::Medium, format!("{host}'s certificate is not trusted"), format!("{} (openssl code {c}). Opportunistic TLS still works, but MTA-STS in enforce mode and strict senders refuse it", t.verify_text))
                .target(tgt)
                .evidence("openssl", t.transcript.clone())
                .fix_summary(if c == 21 || c == 20 { "Install the intermediate certificate(s) with the server certificate, or obtain a publicly trusted certificate" } else { "Replace the self-signed certificate with a publicly trusted one (cPanel: AutoSSL covers mail.{domain} and the hostname)" }),
        ),
        Some(c) => out.push(
            Check::new("tls.cert.valid", SC, TLS, Verdict::Warn, Severity::Medium, format!("{host}'s certificate does not verify"), format!("{} (openssl code {c})", t.verify_text))
                .target(tgt)
                .evidence("openssl", t.transcript.clone()),
        ),
        None => out.push(Check::new("tls.cert.valid", SC, TLS, Verdict::Unknown, Severity::Info, format!("{host}'s certificate"), "openssl did not report a verification result").target(tgt).evidence("openssl", t.transcript.clone())),
    }
    if t.chain_len == 1 && matches!(t.verify_code, Some(20 | 21)) {
        out.push(
            Check::new("tls.chain", SC, TLS, Verdict::Warn, Severity::Medium, format!("{host} sends no intermediate certificate"), "only the server certificate is sent and its issuer is unknown: the chain is incomplete. Clients without the intermediate in their store cannot verify it")
                .target(tgt)
                .fix_summary("Concatenate the CA bundle (intermediate certificates) after the server certificate in the MTA's certificate file"),
        );
    }
    let Some(leaf) = &t.leaf else {
        out.push(
            Check::new(
                "tls.cert.name",
                SC,
                TLS,
                Verdict::Unknown,
                Severity::Info,
                format!("{host}'s certificate names"),
                "the certificate could not be read",
            )
            .target(tgt),
        );
        return out;
    };
    let ev = format!(
        "subject: {}\nissuer: {}\nvalid: {} → {}\nnames: {}",
        leaf.subject,
        leaf.issuer,
        leaf.not_before,
        leaf.not_after,
        leaf.sans.join(", ")
    );
    if tlsprobe::hostname_matches(&leaf.sans, leaf.subject_cn.as_deref(), host) {
        out.push(
            Check::new(
                "tls.cert.name",
                SC,
                TLS,
                Verdict::Pass,
                Severity::Info,
                format!("certificate covers {host}"),
                "the MX name is among the certificate's names",
            )
            .target(tgt)
            .evidence("certificate", ev.clone()),
        );
    } else {
        out.push(
            Check::new("tls.cert.name", SC, TLS, Verdict::Warn, Severity::Medium, format!("certificate does not cover {host}"), format!("it is issued for {}; opportunistic TLS ignores this, MTA-STS (enforce) and strict senders refuse to deliver", if leaf.sans.is_empty() { leaf.subject_cn.clone().unwrap_or_else(|| "no name".into()) } else { leaf.sans.join(", ") }))
                .target(tgt)
                .evidence("certificate", ev.clone())
                .fix_summary(format!("Issue a certificate that includes {host} (cPanel: the hostname certificate via WHM → Manage Service SSL Certificates, or AutoSSL for mail.<domain>)")),
        );
    }
    match leaf.not_after_epoch {
        Some(exp) => {
            let now = crate::delivery::now_secs();
            if exp <= now {
                out.push(
                    Check::new(
                        "tls.cert.expiry",
                        SC,
                        TLS,
                        Verdict::Fail,
                        Severity::High,
                        format!("{host}'s certificate expired {}", leaf.not_after),
                        "expired certificates are refused by verifying senders",
                    )
                    .target(tgt)
                    .fix_summary("Renew the certificate"),
                );
            } else {
                let days = (exp - now) / 86_400;
                if days <= EXPIRY_WARN_DAYS {
                    out.push(
                        Check::new("tls.cert.expiry", SC, TLS, Verdict::Warn, Severity::Medium, format!("{host}'s certificate expires in {days} day(s)"), format!("valid until {}; make sure renewal is automated", leaf.not_after))
                            .target(tgt)
                            .fix_summary("Renew now (cPanel: WHM → Manage AutoSSL → Run AutoSSL) and check why the automatic renewal has not happened"),
                    );
                } else {
                    out.push(
                        Check::new(
                            "tls.cert.expiry",
                            SC,
                            TLS,
                            Verdict::Pass,
                            Severity::Info,
                            format!("{host}'s certificate is valid for {days} more days"),
                            format!("until {}", leaf.not_after),
                        )
                        .target(tgt),
                    );
                }
            }
        }
        None => out.push(
            Check::new(
                "tls.cert.expiry",
                SC,
                TLS,
                Verdict::Unknown,
                Severity::Info,
                format!("{host}'s certificate expiry"),
                format!("could not parse the validity end `{}`", leaf.not_after),
            )
            .target(tgt),
        ),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlsprobe::Cert;

    fn probe_ok() -> SmtpProbe {
        SmtpProbe {
            host: "mx.example".into(),
            ip: Some("203.0.113.1".parse().unwrap()),
            port: 25,
            connect_ms: 30,
            banner_ms: 120,
            banner: "220 mx.example ESMTP".into(),
            ehlo_name: Some("mx.example".into()),
            caps: vec![
                "SIZE 1000".into(),
                "8BITMIME".into(),
                "PIPELINING".into(),
                "STARTTLS".into(),
            ],
            starttls: true,
            size: Some(1000),
            pipelining: true,
            eightbit: true,
            ..Default::default()
        }
    }

    fn verdict_of(checks: &[Check], id: &str) -> Verdict {
        checks
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.verdict)
            .unwrap_or_else(|| panic!("no {id}"))
    }

    #[test]
    fn provider_table() {
        assert_eq!(
            provider_of(&["aspmx.l.google.com".into()]),
            Some("Google Workspace / Gmail")
        );
        assert_eq!(
            provider_of(&["example-com.mail.protection.outlook.com".into()]),
            Some("Microsoft 365")
        );
        assert_eq!(
            provider_of(&[
                "mx1.example-com.mail.protection.outlook.com".into(),
                "mail.example".into()
            ]),
            Some("Microsoft 365")
        );
        assert_eq!(provider_of(&["ncc.transfervda.com".into()]), None);
    }

    #[test]
    fn smtp_verdicts() {
        let p = probe_ok();
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &[]);
        assert_eq!(verdict_of(&c, "mx.connect"), Verdict::Pass);
        assert_eq!(verdict_of(&c, "mx.banner"), Verdict::Pass);
        assert_eq!(verdict_of(&c, "mx.ehlo"), Verdict::Pass);
        assert_eq!(verdict_of(&c, "mx.caps"), Verdict::Pass);
        assert_eq!(verdict_of(&c, "mx.starttls"), Verdict::Pass);

        let mut p = probe_ok();
        p.banner.clear();
        p.error = Some("connection refused".into());
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", false, &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(
            (c[0].id.as_str(), c[0].verdict, c[0].severity),
            ("mx.connect", Verdict::Fail, Severity::Medium),
            "backup MX → medium"
        );

        let mut p = probe_ok();
        p.banner.clear();
        p.error = Some("no greeting: reply timeout".into());
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &[]);
        assert_eq!(
            (c[0].id.as_str(), c[0].verdict),
            ("mx.banner", Verdict::Fail)
        );

        let mut p = probe_ok();
        p.banner = "554 go away".into();
        p.error = Some("greeting was 554".into());
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &[]);
        assert_eq!(verdict_of(&c, "mx.banner"), Verdict::Fail);
        assert!(c.iter().all(|c| c.id != "mx.ehlo"));

        let mut p = probe_ok();
        p.ehlo_name = Some("other.name".into());
        p.starttls = false;
        p.auth = vec!["PLAIN".into()];
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &["ptr.example".into()]);
        assert_eq!(verdict_of(&c, "mx.ehlo"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "mx.caps"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "mx.starttls"), Verdict::Fail);
        p.ehlo_name = Some("mx7.corp.example".into());
        let c = smtp_checks(&p, "mx.corp.example", "t", "IPv4", true, &[]);
        assert_eq!(
            verdict_of(&c, "mx.ehlo"),
            Verdict::Pass,
            "same organisation as the MX host"
        );
        let c = smtp_checks(
            &p,
            "mx.example",
            "t",
            "IPv4",
            true,
            &["ptr.corp.example".into()],
        );
        assert_eq!(
            verdict_of(&c, "mx.ehlo"),
            Verdict::Pass,
            "same organisation as the reverse name"
        );
        p.ehlo_name = Some("PTR.example".into());
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &["ptr.example".into()]);
        assert_eq!(
            verdict_of(&c, "mx.ehlo"),
            Verdict::Pass,
            "EHLO name equal to the PTR is fine"
        );

        let mut p = probe_ok();
        p.caps = vec!["(HELO only — no extensions)".into()];
        p.starttls = false;
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &[]);
        assert_eq!(verdict_of(&c, "mx.caps"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "mx.starttls"), Verdict::Fail);

        let mut p = probe_ok();
        p.banner_ms = 7000;
        p.eightbit = false;
        let c = smtp_checks(&p, "mx.example", "t", "IPv4", true, &[]);
        assert_eq!(verdict_of(&c, "mx.banner"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "mx.caps"), Verdict::Warn);
    }

    #[test]
    fn tls_verdicts() {
        let now = crate::delivery::now_secs();
        let leaf = Cert {
            subject: "CN = mx.example".into(),
            subject_cn: Some("mx.example".into()),
            issuer: "C = US, O = Let's Encrypt, CN = R11".into(),
            not_after: "later".into(),
            not_after_epoch: Some(now + 90 * 86_400),
            sans: vec!["mx.example".into(), "*.mail.example".into()],
            ..Default::default()
        };
        let t = TlsProbe {
            protocol: Some("TLSv1.3".into()),
            cipher: Some("TLS_AES_256_GCM_SHA384".into()),
            verify_code: Some(0),
            verify_text: "ok".into(),
            chain_len: 2,
            leaf: Some(leaf.clone()),
            ..Default::default()
        };
        let c = tls_checks(&t, "mx.example", "t");
        for id in [
            "tls.handshake",
            "tls.cert.valid",
            "tls.cert.name",
            "tls.cert.expiry",
        ] {
            assert_eq!(verdict_of(&c, id), Verdict::Pass, "{id}");
        }
        assert!(c.iter().all(|c| c.id != "tls.chain"));

        // self-signed, wrong name, about to expire, old protocol, leaf only
        let mut t2 = t.clone();
        t2.protocol = Some("TLSv1".into());
        t2.verify_code = Some(18);
        t2.verify_text = "self signed certificate".into();
        t2.chain_len = 1;
        let mut l2 = leaf.clone();
        l2.sans = vec!["www.example".into()];
        l2.not_after_epoch = Some(now + 3 * 86_400);
        t2.leaf = Some(l2);
        let c = tls_checks(&t2, "mx.example", "t");
        assert_eq!(verdict_of(&c, "tls.handshake"), Verdict::Fail);
        assert_eq!(verdict_of(&c, "tls.cert.valid"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "tls.cert.name"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "tls.cert.expiry"), Verdict::Warn);
        assert!(
            c.iter().all(|c| c.id != "tls.chain"),
            "self-signed is not a missing intermediate"
        );

        let mut t3 = t.clone();
        t3.verify_code = Some(21);
        t3.verify_text = "unable to verify the first certificate".into();
        t3.chain_len = 1;
        let c = tls_checks(&t3, "mx.example", "t");
        assert_eq!(verdict_of(&c, "tls.cert.valid"), Verdict::Warn);
        assert_eq!(verdict_of(&c, "tls.chain"), Verdict::Warn);

        let mut t4 = t.clone();
        t4.verify_code = Some(10);
        t4.leaf.as_mut().unwrap().not_after_epoch = Some(now - 10);
        let c = tls_checks(&t4, "mx.example", "t");
        assert_eq!(verdict_of(&c, "tls.cert.valid"), Verdict::Fail);
        assert_eq!(verdict_of(&c, "tls.cert.expiry"), Verdict::Fail);

        let failed = TlsProbe {
            error: Some("the server did not offer STARTTLS".into()),
            ..Default::default()
        };
        let c = tls_checks(&failed, "mx.example", "t");
        assert_eq!(c.len(), 1);
        assert_eq!(verdict_of(&c, "tls.handshake"), Verdict::Fail);
    }
}
