//! Transport-security policies a domain can publish: MTA-STS (RFC 8461),
//! TLS-RPT (RFC 8460), DANE TLSA (RFC 7672) and BIMI. Parsers here, the
//! checks in `tschecks`.

#[derive(Debug, Clone, PartialEq)]
pub struct StsTxt {
    pub id: String,
}

/// `v=STSv1; id=20190429T010101;`
pub fn parse_sts_txt(txt: &str) -> Result<StsTxt, String> {
    let mut version = false;
    let mut id = None;
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("`{part}` is not tag=value"))?;
        match k.trim() {
            "v" => {
                if v.trim() != "STSv1" {
                    return Err(format!("version `{}` is not STSv1", v.trim()));
                }
                version = true;
            }
            "id" => {
                let v = v.trim();
                if v.is_empty() || v.len() > 32 || !v.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(format!("id `{v}` must be 1–32 letters or digits"));
                }
                id = Some(v.to_string());
            }
            _ => {} // unknown tags are ignored (RFC 8461 §3.1)
        }
    }
    if !version {
        return Err("no v=STSv1 tag".into());
    }
    Ok(StsTxt {
        id: id.ok_or("no id= tag")?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StsMode {
    Enforce,
    Testing,
    None,
}

impl StsMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StsMode::Enforce => "enforce",
            StsMode::Testing => "testing",
            StsMode::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StsPolicy {
    pub mode: StsMode,
    pub mx: Vec<String>,
    pub max_age: u64,
    pub problems: Vec<String>,
}

/// The policy file at `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
pub fn parse_policy(text: &str) -> Result<StsPolicy, String> {
    let mut version = false;
    let mut mode = None;
    let mut mx = Vec::new();
    let mut max_age = None;
    let mut problems = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let (k, v) = match line.split_once(':') {
            Some(x) => x,
            None => {
                problems.push(format!("line {}: `{line}` is not key: value", n + 1));
                continue;
            }
        };
        let v = v.trim();
        match k.trim() {
            "version" => {
                if v != "STSv1" {
                    return Err(format!("version `{v}` is not STSv1"));
                }
                version = true;
            }
            "mode" => {
                mode = Some(match v {
                    "enforce" => StsMode::Enforce,
                    "testing" => StsMode::Testing,
                    "none" => StsMode::None,
                    other => return Err(format!("mode `{other}` is not enforce, testing or none")),
                })
            }
            "mx" => {
                let v = v.to_ascii_lowercase();
                let bare = v.strip_prefix("*.").unwrap_or(&v);
                if bare.is_empty()
                    || !bare.split('.').all(|l| {
                        !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    })
                {
                    problems.push(format!("mx `{v}` is not a host name pattern"));
                } else {
                    mx.push(v);
                }
            }
            "max_age" => match v.parse::<u64>() {
                Ok(n) => max_age = Some(n),
                Err(_) => return Err(format!("max_age `{v}` is not a number")),
            },
            other => problems.push(format!("unknown key `{other}` (ignored)")),
        }
    }
    if !version {
        return Err("no `version: STSv1` line".into());
    }
    let mode = mode.ok_or("no `mode:` line")?;
    let max_age = max_age.ok_or("no `max_age:` line")?;
    if mode != StsMode::None && mx.is_empty() {
        return Err("no `mx:` line — an enforce/testing policy needs at least one".into());
    }
    Ok(StsPolicy {
        mode,
        mx,
        max_age,
        problems,
    })
}

/// Does an MTA-STS `mx` pattern cover `host`? (`*.example.com` matches one
/// label, never the apex; RFC 8461 §4.1)
pub fn mx_matches(pattern: &str, host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let p = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = p.strip_prefix("*.") {
        match h.split_once('.') {
            Some((first, rest)) => !first.is_empty() && rest == suffix,
            None => false,
        }
    } else {
        p == h
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlsRpt {
    pub rua: Vec<String>,
}

/// `v=TLSRPTv1; rua=mailto:a@x, https://y/`
pub fn parse_tlsrpt(txt: &str) -> Result<TlsRpt, String> {
    let mut version = false;
    let mut rua = Vec::new();
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("`{part}` is not tag=value"))?;
        match k.trim() {
            "v" => {
                if v.trim() != "TLSRPTv1" {
                    return Err(format!("version `{}` is not TLSRPTv1", v.trim()));
                }
                version = true;
            }
            "rua" => {
                for u in v.split(',') {
                    let u = u.trim();
                    if !(u.starts_with("mailto:") || u.starts_with("https://")) {
                        return Err(format!("rua `{u}` must be mailto: or https:"));
                    }
                    rua.push(u.to_string());
                }
            }
            _ => {}
        }
    }
    if !version {
        return Err("no v=TLSRPTv1 tag".into());
    }
    if rua.is_empty() {
        return Err("no rua= destination".into());
    }
    Ok(TlsRpt { rua })
}

#[derive(Debug, Clone, PartialEq)]
pub struct Bimi {
    pub logo: Option<String>,
    pub vmc: Option<String>,
}

/// `v=BIMI1; l=https://…/logo.svg; a=https://…/cert.pem`
pub fn parse_bimi(txt: &str) -> Result<Bimi, String> {
    let mut version = false;
    let mut b = Bimi {
        logo: None,
        vmc: None,
    };
    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| format!("`{part}` is not tag=value"))?;
        let v = v.trim();
        match k.trim() {
            "v" => {
                if v != "BIMI1" {
                    return Err(format!("version `{v}` is not BIMI1"));
                }
                version = true;
            }
            "l" => {
                if !v.is_empty() && !v.starts_with("https://") {
                    return Err(format!("l `{v}` must be an https URL"));
                }
                b.logo = Some(v.to_string()).filter(|s| !s.is_empty());
            }
            "a" => {
                if !v.is_empty() && !v.starts_with("https://") {
                    return Err(format!("a `{v}` must be an https URL"));
                }
                b.vmc = Some(v.to_string()).filter(|s| !s.is_empty());
            }
            _ => {}
        }
    }
    if !version {
        return Err("no v=BIMI1 tag".into());
    }
    Ok(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sts_txt_and_policy() {
        assert_eq!(
            parse_sts_txt("v=STSv1; id=20190429T010101;").unwrap().id,
            "20190429T010101"
        );
        assert!(parse_sts_txt("v=STSv1").is_err());
        assert!(parse_sts_txt("v=STSv2; id=1").is_err());
        assert!(parse_sts_txt("v=STSv1; id=has space").is_err());
        let p = parse_policy("version: STSv1\r\nmode: enforce\r\nmx: smtp.google.com\r\nmx: gmail-smtp-in.l.google.com\r\nmx: *.gmail-smtp-in.l.google.com\r\nmax_age: 86400\r\n").unwrap();
        assert_eq!(p.mode, StsMode::Enforce);
        assert_eq!(p.mx.len(), 3);
        assert_eq!(p.max_age, 86400);
        assert!(p.problems.is_empty());
        let p = parse_policy(
            "version: STSv1\nmode: testing\nmx: mail.example\nmax_age: 604800\nfoo: bar\n",
        )
        .unwrap();
        assert_eq!(p.mode, StsMode::Testing);
        assert_eq!(p.problems, vec!["unknown key `foo` (ignored)"]);
        assert!(
            parse_policy("version: STSv1\nmode: enforce\nmax_age: 1\n").is_err(),
            "no mx"
        );
        assert!(
            parse_policy("mode: enforce\nmx: a.b\nmax_age: 1\n").is_err(),
            "no version"
        );
        assert!(parse_policy("version: STSv1\nmode: strict\nmx: a.b\nmax_age: 1\n").is_err());
        assert!(
            parse_policy("version: STSv1\nmode: none\nmax_age: 1\n").is_ok(),
            "none needs no mx"
        );
        assert!(mx_matches(
            "*.gmail-smtp-in.l.google.com",
            "alt1.gmail-smtp-in.l.google.com"
        ));
        assert!(!mx_matches(
            "*.gmail-smtp-in.l.google.com",
            "gmail-smtp-in.l.google.com"
        ));
        assert!(!mx_matches(
            "*.l.google.com",
            "alt1.gmail-smtp-in.l.google.com"
        ));
        assert!(mx_matches("MX.Example.com", "mx.example.com."));
    }

    #[test]
    fn tlsrpt_and_bimi() {
        assert_eq!(
            parse_tlsrpt("v=TLSRPTv1;rua=mailto:sts-reports@google.com")
                .unwrap()
                .rua,
            vec!["mailto:sts-reports@google.com"]
        );
        assert_eq!(
            parse_tlsrpt("v=TLSRPTv1; rua=mailto:a@x.test, https://r.test/v1")
                .unwrap()
                .rua
                .len(),
            2
        );
        assert!(parse_tlsrpt("v=TLSRPTv1; rua=ftp://x").is_err());
        assert!(parse_tlsrpt("v=TLSRPTv1").is_err());
        let b = parse_bimi("v=BIMI1; l=https://x.test/logo.svg; a=https://x.test/vmc.pem").unwrap();
        assert_eq!(b.logo.as_deref(), Some("https://x.test/logo.svg"));
        assert_eq!(b.vmc.as_deref(), Some("https://x.test/vmc.pem"));
        let b = parse_bimi("v=BIMI1; l=;").unwrap();
        assert!(b.logo.is_none(), "declined BIMI");
        assert!(parse_bimi("v=BIMI1; l=http://x/logo.svg").is_err());
    }
}
