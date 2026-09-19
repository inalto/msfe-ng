//! DKIM public-key records (RFC 6376): find selectors (best effort — the
//! user's, cPanel's `default`, then the usual provider names), parse the
//! record, and read the RSA modulus size out of the DER key so the report
//! can say 1024 vs 2048 bits without a crypto library.

use crate::b64;
use crate::dns::{Client, DnsError};

/// Selectors worth trying when none is known, in order.
pub const COMMON_SELECTORS: &[&str] = &[
    "default",
    "google",
    "20230601",
    "20221208",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "k3",
    "s1",
    "s2",
    "s3",
    "mail",
    "dkim",
    "smtp",
    "email",
    "mx",
    "key1",
    "key2",
    "mandrill",
    "everlytickey1",
    "everlytickey2",
    "mxvault",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "zoho",
    "zmail",
    "sendgrid",
    "sig1",
    "cm",
    "mailjet",
    "mailgun",
    "mg",
    "krs",
    "pm",
    "hs1",
    "hs2",
    "turbo-smtp",
    "sm",
    "fm1",
    "fm2",
    "fm3",
    "dkim1",
    "dkim2",
    "s1024",
    "s2048",
    "amazonses",
    "ses",
    "sparkpost",
    "scph0123",
    "mte1",
    "mte2",
    "sendinblue",
    "brevo",
    "mailchimp",
    "postmark",
    "pic",
    "ovh",
    "ionos",
    "strato",
    "1and1",
];

/// How many selectors a discovery may query.
pub const MAX_QUERIES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkimKey {
    pub selector: String,
    pub raw: String,
    pub v: Option<String>,
    /// `rsa` (default) or `ed25519`.
    pub k: String,
    pub p: Vec<u8>,
    /// `p=` empty: the key is revoked.
    pub revoked: bool,
    pub t_testing: bool,
    pub t_strict: bool,
    /// `h=` acceptable hash algorithms (empty = all).
    pub h: Vec<String>,
    pub s: Vec<String>,
    pub n: Option<String>,
    /// RSA modulus bits, when the key parsed.
    pub bits: Option<u32>,
    pub problems: Vec<String>,
}

/// Parse a `v=DKIM1; k=rsa; p=…` TXT record.
pub fn parse_record(selector: &str, txt: &str) -> DkimKey {
    let mut key = DkimKey {
        selector: selector.to_string(),
        raw: txt.to_string(),
        v: None,
        k: "rsa".into(),
        p: Vec::new(),
        revoked: false,
        t_testing: false,
        t_strict: false,
        h: Vec::new(),
        s: Vec::new(),
        n: None,
        bits: None,
        problems: Vec::new(),
    };
    let mut seen_p = false;
    for (i, tag) in txt.split(';').enumerate() {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        let Some((name, val)) = tag.split_once('=') else {
            key.problems
                .push(format!("'{tag}' is not a tag=value pair"));
            continue;
        };
        let (name, val) = (name.trim(), val.trim());
        match name {
            "v" => {
                if i != 0 {
                    key.problems.push("v= must be the first tag".into());
                }
                if val != "DKIM1" {
                    key.problems.push(format!("v={val} is not DKIM1"));
                }
                key.v = Some(val.to_string());
            }
            "k" => key.k = val.to_ascii_lowercase(),
            "p" => {
                seen_p = true;
                let compact: String = val.chars().filter(|c| !c.is_whitespace()).collect();
                if compact.is_empty() {
                    key.revoked = true;
                } else {
                    match b64::decode(&compact) {
                        Some(b) => key.p = b,
                        None => key.problems.push("p= is not valid base64".into()),
                    }
                }
            }
            "t" => {
                for f in val.split(':') {
                    match f.trim() {
                        "y" => key.t_testing = true,
                        "s" => key.t_strict = true,
                        "" => {}
                        other => key.problems.push(format!("unknown t= flag '{other}'")),
                    }
                }
            }
            "h" => {
                key.h = val
                    .split(':')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .collect()
            }
            "s" => {
                key.s = val
                    .split(':')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .collect()
            }
            "n" => key.n = Some(val.to_string()),
            "g" => {} // RFC 4871 granularity: obsolete, ignored
            _ => {}   // unknown tags are ignored per the RFC
        }
    }
    if !seen_p {
        key.problems.push("no p= tag: not a DKIM key record".into());
    }
    if key.k == "rsa" && !key.p.is_empty() {
        match rsa_modulus_bits(&key.p) {
            Some(b) => key.bits = Some(b),
            None => key.problems.push(
                "the RSA key does not parse (not a SubjectPublicKeyInfo or PKCS#1 key)".into(),
            ),
        }
    } else if key.k == "ed25519" && !key.p.is_empty() && key.p.len() != 32 {
        key.problems.push(format!(
            "an ed25519 key is 32 bytes, this one is {}",
            key.p.len()
        ));
    }
    key
}

/// Minimal DER: returns `(tag, content start, content len)` at `off`.
fn tlv(der: &[u8], off: usize) -> Option<(u8, usize, usize)> {
    let tag = *der.get(off)?;
    let first = *der.get(off + 1)? as usize;
    if first < 0x80 {
        return Some((tag, off + 2, first));
    }
    let n = first & 0x7f;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | *der.get(off + 2 + i)? as usize;
    }
    Some((tag, off + 2 + n, len))
}

/// Bits of the modulus of an RSA public key given as SubjectPublicKeyInfo
/// (the usual DKIM form) or bare PKCS#1 `RSAPublicKey`.
pub fn rsa_modulus_bits(der: &[u8]) -> Option<u32> {
    let (tag, start, len) = tlv(der, 0)?;
    if tag != 0x30 {
        return None;
    }
    let body = der.get(start..start + len)?;
    // PKCS#1: SEQUENCE { INTEGER modulus, INTEGER exponent }
    if let Some((0x02, s, l)) = tlv(body, 0) {
        return integer_bits(body.get(s..s + l)?);
    }
    // SPKI: SEQUENCE { SEQUENCE algid, BIT STRING key }
    let (t1, s1, l1) = tlv(body, 0)?;
    if t1 != 0x30 {
        return None;
    }
    let (t2, s2, l2) = tlv(body, s1 + l1)?;
    if t2 != 0x03 {
        return None;
    }
    let bits = body.get(s2..s2 + l2)?;
    let inner = bits.get(1..)?; // skip the unused-bits byte
    let (t3, s3, l3) = tlv(inner, 0)?;
    if t3 != 0x30 {
        return None;
    }
    let seq = inner.get(s3..s3 + l3)?;
    let (t4, s4, l4) = tlv(seq, 0)?;
    if t4 != 0x02 {
        return None;
    }
    integer_bits(seq.get(s4..s4 + l4)?)
}

fn integer_bits(mut v: &[u8]) -> Option<u32> {
    while v.first() == Some(&0) {
        v = &v[1..];
    }
    let first = *v.first()?;
    Some((v.len() as u32 - 1) * 8 + (8 - first.leading_zeros()))
}

/// The DKIM records found for `domain`: every selector tried, with the key
/// when a record exists, or the lookup error.
pub fn discover(
    client: &Client,
    domain: &str,
    user_selector: Option<&str>,
) -> Vec<(String, Option<DkimKey>, Option<DnsError>)> {
    let mut selectors: Vec<String> = Vec::new();
    if let Some(s) = user_selector {
        selectors.push(s.to_string());
    }
    for s in COMMON_SELECTORS {
        if !selectors.iter().any(|x| x == s) {
            selectors.push(s.to_string());
        }
    }
    let mut out = Vec::new();
    for sel in selectors.iter().take(MAX_QUERIES) {
        let name = format!("{sel}._domainkey.{domain}");
        match client.txt(&name) {
            Ok(txts) => {
                let recs: Vec<&String> = txts
                    .iter()
                    .filter(|t| t.contains("p=") || t.contains("v=DKIM1"))
                    .collect();
                if let Some(t) = recs.first() {
                    let mut k = parse_record(sel, t);
                    if recs.len() > 1 {
                        k.problems.push(format!(
                            "{} TXT records at the selector — verifiers pick one at random",
                            recs.len()
                        ));
                    }
                    out.push((sel.clone(), Some(k), None));
                } else if user_selector == Some(sel.as_str()) {
                    out.push((sel.clone(), None, None));
                }
            }
            Err(e) => {
                if user_selector == Some(sel.as_str())
                    || matches!(e, DnsError::Timeout | DnsError::ServFail)
                {
                    out.push((sel.clone(), None, Some(e)));
                }
                if matches!(out.last(), Some((_, None, Some(DnsError::Timeout)))) && out.len() > 2 {
                    break; // the resolver is not answering; stop hammering it
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // openssl genrsa 1024 | openssl rsa -pubout -outform DER | base64
    const RSA1024: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDc4L9Y1DKjv0dxZCAeJ9zQ/9Sp+hI3zj4Gogh81W+meulRLOnzpUKmWOea7b2D24CFxpRg/LjWkkbSwgf/yZXqIMlulrT2OCDse/Po3dD3OWgauAkNECICN6kZ218EBnxtuLQhy9V0v10+SkoIz232ztN664KOVYC5/rJ7+EZsDQIDAQAB";
    // openssl genrsa 2048 | openssl rsa -pubout -outform DER | base64
    const RSA2048: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7BQjQ/1d9Rj+RMNJt32Nk5bYJoCRjq2XuMFwcWD3/dbzIGm5k2JNp8zGtZPbWPFwDSHhNH7CGLMfKtyqwy7Gt9i4SNVeWftfX30vsjGQhCf9dMbthVhuhT6Pd96esILhJNvAJJfg0A4WXGN8sdMM4njiqCEkZq9BT9LR9Xh+n696t2gTjuAjPxgymG5Ten7IlJkraNzKeAy0hjOsra8qWh29weXnAXWc3Jex1zSpL7WhroAIecdH6ydi3O6atO9T7G3PUWpTuX2Fzb7gKAqzZ71L1vDGmx8sOY7FEYqDih5GvaG3sgO0R1O5IGzqoIHbEQTJNMsz1oprvIH2FhcQhwIDAQAB";

    #[test]
    fn modulus_bits_from_spki_and_pkcs1() {
        assert_eq!(rsa_modulus_bits(&b64::decode(RSA1024).unwrap()), Some(1024));
        assert_eq!(rsa_modulus_bits(&b64::decode(RSA2048).unwrap()), Some(2048));
        // PKCS#1: SEQUENCE { INTEGER (3 bytes, top bit set → 24 bits), INTEGER 65537 }
        let pkcs1 = [
            0x30, 0x0a, 0x02, 0x03, 0x80, 0x00, 0x01, 0x02, 0x03, 0x01, 0x00, 0x01,
        ];
        assert_eq!(rsa_modulus_bits(&pkcs1), Some(24));
        assert_eq!(rsa_modulus_bits(b"garbage"), None);
        assert_eq!(
            rsa_modulus_bits(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]),
            None
        );
        assert_eq!(integer_bits(&[0x00, 0x01]), Some(1));
        assert_eq!(integer_bits(&[0xff]), Some(8));
    }

    #[test]
    fn parses_records_with_flags_and_problems() {
        let k = parse_record(
            "default",
            &format!("v=DKIM1; k=rsa; t=y:s; h=sha256; p={RSA2048}"),
        );
        assert_eq!(k.bits, Some(2048));
        assert!(k.t_testing && k.t_strict);
        assert_eq!(k.h, vec!["sha256"]);
        assert!(k.problems.is_empty(), "{:?}", k.problems);
        let k = parse_record("s", "k=rsa; p=");
        assert!(k.revoked);
        assert!(k.problems.is_empty());
        let k = parse_record(
            "s",
            "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
        );
        assert_eq!(k.k, "ed25519");
        assert!(k.problems.is_empty());
        assert_eq!(k.bits, None);
        let k = parse_record("s", "k=rsa; v=DKIM1; p=!!!");
        assert!(k.problems.iter().any(|p| p.contains("first tag")));
        assert!(k.problems.iter().any(|p| p.contains("base64")));
        let k = parse_record("s", "v=DKIM1; k=rsa");
        assert!(k.problems.iter().any(|p| p.contains("no p=")));
        let k = parse_record("s", &format!("v=DKIM1; p={RSA1024}; t=q"));
        assert_eq!(k.bits, Some(1024));
        assert!(k.problems.iter().any(|p| p.contains("unknown t= flag")));
    }

    #[test]
    fn discovery_tries_user_then_common_selectors() {
        use crate::dns::testsupport::start as fake;
        use crate::dns::{RData, Rr};
        let rec = format!("v=DKIM1; k=rsa; p={RSA1024}");
        let srv = fake(
            Box::new(move |name, rtype| match (name, rtype) {
                ("mine._domainkey.example.com", 16) | ("google._domainkey.example.com", 16) => {
                    Some((
                        0,
                        vec![Rr {
                            name: name.into(),
                            rtype: 16,
                            ttl: 1,
                            data: RData::Txt(vec![rec.clone()]),
                        }],
                        false,
                    ))
                }
                ("gone._domainkey.example.com", 16) => Some((3, vec![], false)),
                _ => Some((0, vec![], false)),
            }),
            false,
        );
        let c = Client::at(srv.addr);
        let found = discover(&c, "example.com", Some("mine"));
        let names: Vec<&str> = found.iter().map(|(s, _, _)| s.as_str()).collect();
        assert_eq!(names, vec!["mine", "google"]);
        assert_eq!(found[0].1.as_ref().unwrap().bits, Some(1024));
        let found = discover(&c, "example.com", Some("gone"));
        assert_eq!(found[0].0, "gone");
        assert!(
            found[0].1.is_none(),
            "user selector reported even when empty"
        );
        let found = discover(&c, "nodkim.example", None);
        assert!(found.is_empty());
    }
}
