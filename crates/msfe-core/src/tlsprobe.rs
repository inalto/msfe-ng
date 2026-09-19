//! STARTTLS and certificate inspection through the system `openssl`
//! (`s_client -starttls smtp`, `x509`) — the same tool on every EL host,
//! 1.1.1 or 3.x, whose output the parsers here read. DANE is checked by
//! handing `s_client` the TLSA records.

use crate::service::{run_with_stdin, run_with_timeout};
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Cert {
    pub subject: String,
    pub subject_cn: Option<String>,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub not_after_epoch: Option<u64>,
    pub sans: Vec<String>,
    pub self_signed: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Dane {
    Matched(String),
    NoMatch,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TlsProbe {
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    /// OpenSSL's verify return code (0 = chain verifies).
    pub verify_code: Option<i32>,
    pub verify_text: String,
    pub chain_len: usize,
    pub leaf: Option<Cert>,
    pub dane: Option<Dane>,
    pub transcript: String,
    pub error: Option<String>,
}

pub fn openssl_version() -> Option<String> {
    Command::new("openssl")
        .arg("version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// The parts of an `s_client` transcript the checks care about.
pub fn parse_s_client(out: &str) -> TlsProbe {
    let mut p = TlsProbe::default();
    let mut pems: Vec<String> = Vec::new();
    let mut cur: Option<String> = None;
    for line in out.lines() {
        let t = line.trim();
        if t == "-----BEGIN CERTIFICATE-----" {
            cur = Some(String::new());
        }
        if let Some(c) = cur.as_mut() {
            c.push_str(t);
            c.push('\n');
            if t == "-----END CERTIFICATE-----" {
                pems.push(cur.take().unwrap());
            }
            continue;
        }
        // "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" (both versions)
        if let Some(rest) = t.strip_prefix("New, ") {
            if let Some((proto, cipher)) = rest.split_once(", Cipher is ") {
                p.protocol = Some(proto.trim().to_string());
                p.cipher = Some(cipher.trim().to_string());
            }
        } else if let Some(rest) = t.strip_prefix("Protocol") {
            // "Protocol  : TLSv1.2" (session block)
            if let Some((_, v)) = rest.split_once(':') {
                if p.protocol.is_none() {
                    p.protocol = Some(v.trim().to_string());
                }
            }
        } else if let Some(rest) = t.strip_prefix("Cipher") {
            if let Some((_, v)) = rest.split_once(':') {
                if p.cipher.is_none() && !v.trim().is_empty() {
                    p.cipher = Some(v.trim().to_string());
                }
            }
        } else if let Some(rest) = t.strip_prefix("Verify return code:") {
            let rest = rest.trim();
            let code = rest
                .split_whitespace()
                .next()
                .and_then(|c| c.parse::<i32>().ok());
            p.verify_code = code;
            p.verify_text = rest
                .split_once('(')
                .map(|(_, x)| x.trim_end_matches(')').to_string())
                .unwrap_or_else(|| rest.to_string());
        } else if let Some(rest) = t.strip_prefix("DANE TLSA ") {
            if rest.contains("matched") {
                p.dane = Some(Dane::Matched(rest.to_string()));
            }
        } else if t.contains("No matching DANE TLSA records") {
            if p.dane.is_none() {
                p.dane = Some(Dane::NoMatch);
            }
        } else if t.starts_with("connect:")
            || t.starts_with("connect: ")
            || t.contains(":error:") && p.protocol.is_none()
        {
            // "connect:errno=111", "…:error:…:ssl/tls alert handshake failure…"
            if p.error.is_none() {
                p.error = Some(t.to_string());
            }
        } else if t.starts_with("Didn't find STARTTLS in server response") {
            p.error = Some("the server did not offer STARTTLS".into());
        }
    }
    p.chain_len = pems.len();
    if let Some(leaf) = pems.first() {
        p.leaf = x509_info(leaf);
    }
    // the transcript keeps the readable lines, not the PEM blocks
    let mut in_pem = false;
    let mut transcript = Vec::new();
    for l in out.lines() {
        let t = l.trim();
        if t == "-----BEGIN CERTIFICATE-----" {
            in_pem = true;
            transcript.push("[certificate]");
            continue;
        }
        if t == "-----END CERTIFICATE-----" {
            in_pem = false;
            continue;
        }
        if !in_pem {
            transcript.push(l);
        }
    }
    p.transcript = transcript.join("\n");
    p
}

/// `openssl x509 -noout -subject -issuer -dates -ext subjectAltName` output.
pub fn parse_x509(out: &str) -> Cert {
    let mut c = Cert::default();
    let mut in_san = false;
    for line in out.lines() {
        let t = line.trim();
        if in_san {
            if !t.is_empty() && !t.starts_with("X509v3") {
                for e in t.split(',') {
                    let e = e.trim();
                    if let Some(d) = e.strip_prefix("DNS:") {
                        c.sans.push(d.to_ascii_lowercase());
                    } else if let Some(ip) = e.strip_prefix("IP Address:") {
                        c.sans.push(ip.to_string());
                    }
                }
                continue;
            }
            in_san = false;
        }
        if let Some(v) = t.strip_prefix("subject=") {
            c.subject = v.trim().to_string();
            c.subject_cn = cn_of(v);
        } else if let Some(v) = t.strip_prefix("issuer=") {
            c.issuer = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("notBefore=") {
            c.not_before = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("notAfter=") {
            c.not_after = v.trim().to_string();
            c.not_after_epoch = parse_openssl_date(v.trim());
        } else if t.starts_with("X509v3 Subject Alternative Name") {
            in_san = true;
        }
    }
    c.self_signed = !c.subject.is_empty() && c.subject == c.issuer;
    c
}

fn cn_of(dn: &str) -> Option<String> {
    dn.split(',').map(str::trim).find_map(|part| {
        let (k, v) = part.split_once('=')?;
        (k.trim() == "CN").then(|| v.trim().to_ascii_lowercase())
    })
}

/// `Nov 27 08:06:11 2026 GMT` → epoch seconds.
pub fn parse_openssl_date(s: &str) -> Option<u64> {
    let mut it = s.split_whitespace();
    let mon = match it.next()? {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let day: u32 = it.next()?.parse().ok()?;
    let hms = it.next()?;
    let year: i32 = it.next()?.parse().ok()?;
    let mut t = hms.split(':');
    let (h, m, sec): (u64, u64, u64) = (
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
        t.next()?.parse().ok()?,
    );
    let date = crate::civil::Date {
        y: year,
        m: mon,
        d: day,
    };
    if mon < 1 || day < 1 || crate::civil::Date::from_days(date.to_days()) != date {
        return None;
    }
    let days = date.to_days();
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400 + h * 3600 + m * 60 + sec)
}

/// Does a certificate name (SAN or CN) cover `host`? One-label wildcard only.
pub fn hostname_matches(sans: &[String], subject_cn: Option<&str>, host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let names: Vec<&str> = sans
        .iter()
        .map(String::as_str)
        .chain(subject_cn.filter(|_| sans.is_empty()))
        .collect();
    names.iter().any(|n| {
        let n = n.trim_end_matches('.');
        if let Some(suffix) = n.strip_prefix("*.") {
            match h.split_once('.') {
                Some((first, rest)) => !first.is_empty() && rest == suffix,
                None => false,
            }
        } else {
            n == h
        }
    })
}

/// Certificate details from PEM text.
pub fn x509_info(pem: &str) -> Option<Cert> {
    let mut cmd = Command::new("openssl");
    cmd.args([
        "x509",
        "-noout",
        "-subject",
        "-issuer",
        "-dates",
        "-ext",
        "subjectAltName",
    ]);
    let out = run_with_stdin(&mut cmd, pem.as_bytes(), Duration::from_secs(5)).ok()?;
    if !out.ok && out.stdout.trim().is_empty() {
        // 1.1.1 without -ext support? fall back without it
        let mut cmd = Command::new("openssl");
        cmd.args(["x509", "-noout", "-subject", "-issuer", "-dates"]);
        let out2 = run_with_stdin(&mut cmd, pem.as_bytes(), Duration::from_secs(5)).ok()?;
        return Some(parse_x509(&out2.stdout));
    }
    Some(parse_x509(&out.stdout))
}

/// STARTTLS handshake against `ip:port` (SNI/verification for `servername`),
/// with DANE matching when `tlsa` records are given.
pub fn starttls(
    ip: IpAddr,
    port: u16,
    servername: &str,
    tlsa: &[(u8, u8, u8, Vec<u8>)],
    timeout: Duration,
) -> TlsProbe {
    let mut cmd = Command::new("openssl");
    let connect = match ip {
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
        IpAddr::V4(v4) => format!("{v4}:{port}"),
    };
    // no -verify_hostname: the name check is done here from the SANs so the
    // verify code keeps describing the chain alone
    cmd.args([
        "s_client",
        "-starttls",
        "smtp",
        "-connect",
        &connect,
        "-servername",
        servername,
        "-showcerts",
    ]);
    if !tlsa.is_empty() {
        cmd.args(["-dane_tlsa_domain", servername]);
        for (u, s, m, data) in tlsa {
            cmd.arg("-dane_tlsa_rrdata");
            cmd.arg(format!("{u} {s} {m} {}", crate::dns::hex(data)));
        }
    }
    let out = match run_with_timeout(&mut cmd, timeout) {
        Ok(o) => o,
        Err(e) => {
            return TlsProbe {
                error: Some(format!("cannot run openssl: {e}")),
                ..Default::default()
            }
        }
    };
    let mut p = parse_s_client(&format!("{}\n{}", out.stdout, out.stderr));
    if out.timed_out {
        p.error = Some(format!(
            "openssl did not finish within {} s",
            timeout.as_secs()
        ));
    } else if p.protocol.is_none() && p.error.is_none() {
        p.error = Some(if out.stderr.trim().is_empty() {
            "no TLS session was established".into()
        } else {
            out.stderr.lines().last().unwrap_or("").trim().to_string()
        });
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    const S_CLIENT_35: &str = "CONNECTED(00000003)\ndepth=2 C = US, O = Google Trust Services LLC, CN = GTS Root R4\nverify return:1\ndepth=0 CN = mx.google.com\nverify return:1\n---\nCertificate chain\n 0 s:CN = mx.google.com\n   i:C = US, O = Google Trust Services, CN = WE2\n-----BEGIN CERTIFICATE-----\nMIIDxxxx\n-----END CERTIFICATE-----\n 1 s:C = US, O = Google Trust Services, CN = WE2\n-----BEGIN CERTIFICATE-----\nMIIDyyyy\n-----END CERTIFICATE-----\n---\nServer certificate\nsubject=CN = mx.google.com\nissuer=C = US, O = Google Trust Services, CN = WE2\n---\nSSL handshake has read 3698 bytes and written 475 bytes\nVerification: OK\n---\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nServer public key is 256 bit\nVerify return code: 0 (ok)\n---\n250 SMTPUTF8\nDONE\n";
    const S_CLIENT_111_SELFSIGNED: &str = "CONNECTED(00000003)\ndepth=0 CN = mail.example\nverify error:num=18:self signed certificate\nverify return:1\n---\nSSL-Session:\n    Protocol  : TLSv1.2\n    Cipher    : ECDHE-RSA-AES256-GCM-SHA384\n    Verify return code: 18 (self signed certificate)\n---\nNew, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384\nVerification error: self signed certificate\n";
    const S_CLIENT_DANE: &str = "Verification: OK\nDANE TLSA 3 1 1 ...fa1c3feda4594098841139c9 matched EE certificate at depth 0\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerify return code: 0 (ok)\n";
    const S_CLIENT_DANE_FAIL: &str = "verify error:num=65:No matching DANE TLSA records\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nVerification error: No matching DANE TLSA records\nVerify return code: 65 (No matching DANE TLSA records)\n";
    const S_CLIENT_NOTLS: &str = "CONNECTED(00000003)\nDidn't find STARTTLS in server response, trying anyway...\n140:error:1408F10B:SSL routines:ssl3_get_record:wrong version number:ssl/record/ssl3_record.c:332:\n";

    #[test]
    fn parses_s_client_from_both_versions() {
        let p = parse_s_client(S_CLIENT_35);
        assert_eq!(p.protocol.as_deref(), Some("TLSv1.3"));
        assert_eq!(p.cipher.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(p.verify_code, Some(0));
        assert_eq!(p.verify_text, "ok");
        assert_eq!(p.chain_len, 2);
        assert!(p.error.is_none());
        assert!(!p.transcript.contains("MIIDxxxx"));
        let p = parse_s_client(S_CLIENT_111_SELFSIGNED);
        assert_eq!(p.protocol.as_deref(), Some("TLSv1.2"));
        assert_eq!(p.verify_code, Some(18));
        assert_eq!(p.verify_text, "self signed certificate");
        let p = parse_s_client(S_CLIENT_DANE);
        assert!(matches!(p.dane, Some(Dane::Matched(_))));
        let p = parse_s_client(S_CLIENT_DANE_FAIL);
        assert_eq!(p.dane, Some(Dane::NoMatch));
        assert_eq!(p.verify_code, Some(65));
        let p = parse_s_client(S_CLIENT_NOTLS);
        assert!(p.protocol.is_none());
        assert_eq!(
            p.error.as_deref(),
            Some("the server did not offer STARTTLS")
        );
    }

    #[test]
    fn parses_x509_and_dates_and_names() {
        let out = "subject=CN = mx.google.com\nissuer=C = US, O = Google Trust Services, CN = WE2\nnotBefore=Sep  4 08:06:12 2026 GMT\nnotAfter=Nov 27 08:06:11 2026 GMT\nX509v3 Subject Alternative Name: \n    DNS:mx.google.com, DNS:*.example.org, IP Address:192.0.2.1\n";
        let c = parse_x509(out);
        assert_eq!(c.subject_cn.as_deref(), Some("mx.google.com"));
        assert_eq!(c.sans, vec!["mx.google.com", "*.example.org", "192.0.2.1"]);
        assert_eq!(
            c.not_after_epoch,
            parse_openssl_date("Nov 27 08:06:11 2026 GMT")
        );
        assert!(!c.self_signed);
        assert_eq!(parse_openssl_date("Jan  1 00:00:00 1970 GMT"), Some(0));
        assert_eq!(
            parse_openssl_date("Nov 14 22:13:20 2023 GMT"),
            Some(1_700_000_000)
        );
        assert!(parse_openssl_date("nonsense").is_none());
        let self_signed = parse_x509("subject=CN = mail.example\nissuer=CN = mail.example\n");
        assert!(self_signed.self_signed);
        assert!(hostname_matches(&c.sans, None, "MX.google.com"));
        assert!(hostname_matches(&c.sans, None, "a.example.org"));
        assert!(!hostname_matches(&c.sans, None, "a.b.example.org"));
        assert!(!hostname_matches(&c.sans, None, "example.org"));
        assert!(
            hostname_matches(&[], Some("mail.example"), "mail.example"),
            "CN only when no SANs"
        );
        assert!(
            !hostname_matches(&c.sans, Some("other.example"), "other.example"),
            "CN ignored when SANs exist"
        );
    }

    #[test]
    fn x509_info_runs_openssl_when_present() {
        if openssl_version().is_none() {
            return;
        }
        // a throwaway self-signed certificate
        let out = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "/dev/null",
                "-subj",
                "/CN=mail.test.example",
                "-addext",
                "subjectAltName=DNS:mail.test.example,DNS:*.test.example",
                "-days",
                "2",
            ])
            .output()
            .unwrap();
        let pem = String::from_utf8_lossy(&out.stdout).into_owned();
        if !pem.contains("BEGIN CERTIFICATE") {
            return; // old openssl without -addext
        }
        let c = x509_info(&pem).unwrap();
        assert_eq!(c.subject_cn.as_deref(), Some("mail.test.example"));
        assert!(c.sans.contains(&"*.test.example".to_string()));
        assert!(c.self_signed);
        assert!(c.not_after_epoch.unwrap() > crate::delivery::now_secs());
    }
}
