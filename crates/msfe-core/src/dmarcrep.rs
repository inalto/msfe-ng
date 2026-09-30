//! DMARC aggregate reports (RFC 7489 appendix C): unpack, parse, classify.
//!
//! Receivers mail one report per domain per day to the `rua=` address,
//! usually as `receiver!domain!begin!end[!id].xml`, gzip'd or zipped. This
//! module turns such a mail (or a bare file) into [`Report`]s, builds the SQL
//! that stores one, and holds the pure verdicts the UI shows: which class a
//! reported source falls in, and whether a domain is ready for a stricter
//! policy. Fetching and scheduling live in `dmarcjob`, queries in `dmarcq`.

use crate::db::quote;
use crate::xml::{self, Element};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::process::{Command, Stdio};

/// Decompressed report size cap: a year of a busy domain is a few MB.
pub const MAX_XML: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub org_name: String,
    pub org_email: String,
    pub report_id: String,
    pub begin: i64,
    pub end: i64,
    pub domain: String,
    pub adkim: String,
    pub aspf: String,
    pub p: String,
    pub sp: String,
    pub pct: Option<u32>,
    pub fo: String,
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Record {
    pub source_ip: String,
    pub count: u64,
    pub disposition: String,
    /// `policy_evaluated`: the aligned verdicts DMARC decided on
    pub dkim: String,
    pub spf: String,
    /// `(type, comment)` overrides the receiver applied (forwarded, local_policy…)
    pub reasons: Vec<(String, String)>,
    pub header_from: String,
    pub envelope_from: String,
    pub envelope_to: String,
    /// `auth_results`: raw, unaligned results as `(domain, selector, result)`
    pub dkim_auth: Vec<(String, String, String)>,
    /// `(domain, scope, result)`
    pub spf_auth: Vec<(String, String, String)>,
}

impl Record {
    /// DMARC passed: at least one aligned mechanism passed.
    pub fn passed(&self) -> bool {
        self.dkim == "pass" || self.spf == "pass"
    }
    /// The receiver says the failure comes from forwarding or a mailing list
    /// (or an ARC chain it trusted), not from someone forging the domain.
    pub fn forwarded(&self) -> bool {
        self.reasons.iter().any(|(t, c)| {
            matches!(
                t.as_str(),
                "forwarded" | "mailing_list" | "trusted_forwarder"
            ) || (t == "local_policy" && c.to_ascii_lowercase().contains("arc"))
        })
    }
}

fn lower(e: &Element, path: &[&str]) -> String {
    e.text_at(path).to_ascii_lowercase()
}

/// Parse one aggregate report document.
pub fn parse(text: &str) -> Result<Report, String> {
    let root = xml::parse(text)?;
    if root.name != "feedback" {
        return Err(format!(
            "<{}> is not a DMARC report (<feedback>)",
            root.name
        ));
    }
    let meta = root
        .child("report_metadata")
        .ok_or("no <report_metadata>")?;
    let pol = root
        .child("policy_published")
        .ok_or("no <policy_published>")?;
    let num = |p: &[&str]| -> Result<i64, String> {
        let t = meta.text_at(p);
        t.parse().map_err(|_| format!("bad {}: {t:?}", p.join("/")))
    };
    let mut r = Report {
        org_name: meta.text_at(&["org_name"]),
        org_email: meta.text_at(&["email"]),
        report_id: meta.text_at(&["report_id"]),
        begin: num(&["date_range", "begin"])?,
        end: num(&["date_range", "end"])?,
        domain: lower(pol, &["domain"]).trim_end_matches('.').to_string(),
        adkim: lower(pol, &["adkim"]),
        aspf: lower(pol, &["aspf"]),
        p: lower(pol, &["p"]),
        sp: lower(pol, &["sp"]),
        pct: pol.text_at(&["pct"]).parse().ok(),
        fo: pol.text_at(&["fo"]),
        records: Vec::new(),
    };
    if r.org_name.is_empty() || r.report_id.is_empty() {
        return Err("report without org_name or report_id".into());
    }
    if r.domain.is_empty() {
        return Err("report without a published domain".into());
    }
    for rec in root.all("record") {
        let row = rec.child("row").ok_or("record without <row>")?;
        let ip = row.text_at(&["source_ip"]);
        let ip = ip
            .parse::<IpAddr>()
            .map_err(|_| format!("bad source_ip {ip:?}"))?
            .to_string();
        let pe = row.child("policy_evaluated");
        let ev = |f: &str| pe.map(|p| lower(p, &[f])).unwrap_or_default();
        let reasons = pe
            .map(|p| {
                p.all("reason")
                    .map(|x| (lower(x, &["type"]), x.text_at(&["comment"])))
                    .collect()
            })
            .unwrap_or_default();
        let auth = rec.child("auth_results");
        let triples = |kind: &str, second: &str| -> Vec<(String, String, String)> {
            auth.map(|a| {
                a.all(kind)
                    .map(|x| {
                        (
                            lower(x, &["domain"]),
                            x.text_at(&[second]),
                            lower(x, &["result"]),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
        };
        r.records.push(Record {
            source_ip: ip,
            count: row.text_at(&["count"]).parse().unwrap_or(0),
            disposition: ev("disposition"),
            dkim: ev("dkim"),
            spf: ev("spf"),
            reasons,
            header_from: lower(rec, &["identifiers", "header_from"]),
            envelope_from: lower(rec, &["identifiers", "envelope_from"]),
            envelope_to: lower(rec, &["identifiers", "envelope_to"]),
            dkim_auth: triples("dkim", "selector"),
            spf_auth: triples("spf", "scope"),
        });
    }
    Ok(r)
}

/// Run a decompressor over `data`, keeping at most [`MAX_XML`] bytes of output.
fn pipe(cmd: &mut Command, data: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let mut child = cmd
        .stdin(if data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if let Some(d) = data {
        let mut stdin = child.stdin.take().expect("stdin piped");
        let d = d.to_vec();
        // feed from a thread: the child blocks on a full stdout pipe otherwise
        std::thread::spawn(move || {
            let _ = stdin.write_all(&d);
        });
    }
    let mut out = Vec::new();
    let mut stdout = child.stdout.take().expect("stdout piped");
    let n = (&mut stdout)
        .take(MAX_XML as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if n > MAX_XML {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!(
            "report decompresses to more than {} MB",
            MAX_XML >> 20
        ));
    }
    let ok = child.wait().map(|s| s.success()).unwrap_or(false);
    if !ok {
        return Err(format!(
            "{:?} could not decompress the attachment",
            cmd.get_program()
        ));
    }
    Ok(out)
}

fn unzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let path = std::env::temp_dir().join(format!(
        "msfe-ng-dmarc-{}-{:?}.zip",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::write(&path, data).map_err(|e| format!("cannot write temp zip: {e}"))?;
    let r = pipe(Command::new("unzip").arg("-p").arg(&path), None)
        // no unzip: gzip reads a single-member deflate zip, which is what receivers send
        .or_else(|_| pipe(Command::new("gzip").arg("-dc"), Some(data)));
    let _ = std::fs::remove_file(&path);
    r
}

/// Turn an attachment's bytes into report XML, by content (magic bytes), not name.
pub fn unpack(data: &[u8]) -> Result<Vec<u8>, String> {
    let d = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    let start = d.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0);
    if d.starts_with(b"\x1f\x8b") {
        pipe(Command::new("gzip").arg("-dc"), Some(d))
    } else if d.starts_with(b"PK\x03\x04") {
        unzip(d)
    } else if d[start..].starts_with(b"<") {
        if d.len() > MAX_XML {
            return Err("report larger than the size cap".into());
        }
        Ok(d[start..].to_vec())
    } else {
        Err("not XML, gzip or zip".into())
    }
}

/// True when a mail part may hold a report: by name or by media type.
fn candidate(ctype: &str, name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.ends_with(".xml")
        || n.ends_with(".gz")
        || n.ends_with(".zip")
        || n.ends_with(".xml.gz")
        || matches!(
            ctype,
            "text/xml"
                | "application/xml"
                | "application/gzip"
                | "application/x-gzip"
                | "application/zip"
                | "application/x-zip-compressed"
        )
}

/// The reports in one mail, each `(attachment name, parse result)`. An empty
/// list means the mail carries nothing that looks like a report.
pub fn extract(raw_mail: &[u8]) -> Vec<(String, Result<Report, String>)> {
    crate::mime::leaf_parts(raw_mail)
        .into_iter()
        .filter(|(ct, name, _)| candidate(ct, name))
        .map(|(_, name, body)| {
            let r = unpack(&body).and_then(|x| parse(&String::from_utf8_lossy(&x)));
            (name, r)
        })
        .collect()
}

/// A file given on the command line: a report (xml, gz, zip) or a whole mail.
pub fn from_file(bytes: &[u8]) -> Vec<(String, Result<Report, String>)> {
    match unpack(bytes) {
        Ok(x) if String::from_utf8_lossy(&x).contains("<feedback") => {
            vec![(String::new(), parse(&String::from_utf8_lossy(&x)))]
        }
        _ => extract(bytes),
    }
}

/// `receiver!domain!begin!end[!id].xml[.gz|.zip]` → (receiver, domain, begin, end).
/// A hint only — the XML is authoritative.
pub fn filename_hint(name: &str) -> Option<(String, String, i64, i64)> {
    let base = name.rsplit('/').next()?;
    let stem = base
        .split(".xml")
        .next()?
        .trim_end_matches(".zip")
        .trim_end_matches(".gz");
    let f: Vec<&str> = stem.split('!').collect();
    if f.len() < 4 {
        return None;
    }
    Some((
        f[0].to_ascii_lowercase(),
        f[1].to_ascii_lowercase(),
        f[2].parse().ok()?,
        f[3].parse().ok()?,
    ))
}

/// What a reported source is, from the domain owner's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// DMARC passed
    Pass,
    /// failed, but forwarded or via a list (or triaged as a forwarder)
    Forwarded,
    /// failed while sent from this server: something here needs fixing
    OwnFail,
    /// failed from a source the admin marked as legitimate
    LegitFail,
    /// failed from an unknown or abusive source: spoofing
    Suspect,
}

impl Class {
    pub fn key(self) -> &'static str {
        match self {
            Class::Pass => "pass",
            Class::Forwarded => "forwarded",
            Class::OwnFail => "own_fail",
            Class::LegitFail => "legit_fail",
            Class::Suspect => "suspect",
        }
    }
    pub const ALL: [Class; 5] = [
        Class::Pass,
        Class::Forwarded,
        Class::OwnFail,
        Class::LegitFail,
        Class::Suspect,
    ];
}

/// Classify a (group of) record(s). `status` is the source's triage
/// (`unknown|legit|abuse|forwarder`), `own` whether the IP is this server's.
pub fn classify(passed: bool, forwarded: bool, own: bool, status: &str) -> Class {
    if passed {
        Class::Pass
    } else if own {
        Class::OwnFail
    } else if forwarded || status == "forwarder" {
        Class::Forwarded
    } else if status == "legit" {
        Class::LegitFail
    } else {
        Class::Suspect
    }
}

/// What the numbers say about tightening a domain's policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Readiness {
    pub ready: bool,
    /// suggested policy and pct when ready (or when already at the end)
    pub next_p: String,
    pub next_pct: u32,
    pub text: String,
}

/// Inputs for [`readiness`]: counts over the period for one domain.
#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    pub p: String,
    pub pct: Option<u32>,
    /// distinct report days seen
    pub days: u32,
    /// messages from this server and triaged legitimate sources
    pub legit: u64,
    pub legit_pass: u64,
    /// failing messages from this server in the last 7 days
    pub own_fail_recent: u64,
    /// distinct unknown sources failing
    pub suspect_sources: u64,
}

pub const READY_DAYS: u32 = 14;
pub const READY_PASS_PCT: f64 = 98.0;

/// Whether a domain can move p=none → quarantine (in pct steps) → reject.
pub fn readiness(s: &DomainStats) -> Readiness {
    let pct = s.pct.unwrap_or(100);
    let (np, npct) = match (s.p.as_str(), pct) {
        ("reject", 100) => {
            return Readiness {
                ready: false,
                next_p: "reject".into(),
                next_pct: 100,
                text: "Already at p=reject — spoofed mail is refused.".into(),
            }
        }
        ("reject", _) => ("reject", 100),
        ("quarantine", p) if p < 25 => ("quarantine", 25),
        ("quarantine", p) if p < 50 => ("quarantine", 50),
        ("quarantine", p) if p < 100 => ("quarantine", 100),
        ("quarantine", _) => ("reject", 100),
        _ => ("quarantine", 25),
    };
    let rate = if s.legit == 0 {
        0.0
    } else {
        s.legit_pass as f64 * 100.0 / s.legit as f64
    };
    let mut blockers = Vec::new();
    if s.days < READY_DAYS {
        blockers.push(format!(
            "only {} day(s) of reports (need {READY_DAYS})",
            s.days
        ));
    }
    if s.legit == 0 {
        blockers.push("no legitimate traffic reported yet".into());
    } else if rate < READY_PASS_PCT {
        blockers.push(format!(
            "legitimate mail passes DMARC {rate:.1}% (need {READY_PASS_PCT}%) — fix SPF/DKIM for the failing senders first"
        ));
    }
    if s.own_fail_recent > 0 {
        blockers.push(format!(
            "this server failed DMARC on {} message(s) in the last 7 days — check the DKIM key and SPF in Account DNS",
            s.own_fail_recent
        ));
    }
    if blockers.is_empty() {
        let step = if np == "quarantine" && npct < 100 {
            format!("p=quarantine; pct={npct}")
        } else if np == s.p {
            format!("p={np} on all mail (pct=100)")
        } else {
            format!("p={np}")
        };
        let spoof = if s.suspect_sources > 0 {
            format!(
                " {} unknown source(s) failing would be {} — triage them first, in case one is a service of yours.",
                s.suspect_sources,
                if np == "reject" { "refused" } else { "sent to spam" }
            )
        } else {
            String::new()
        };
        Readiness {
            ready: true,
            next_p: np.into(),
            next_pct: npct,
            text: format!(
                "Ready for {step}: legitimate mail passes {rate:.1}% over {} days.{spoof}",
                s.days
            ),
        }
    } else {
        Readiness {
            ready: false,
            next_p: np.into(),
            next_pct: npct,
            text: format!("Not yet: {}.", blockers.join("; ")),
        }
    }
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// SQL that stores one report and its records and folds the sources into
/// `dmarc_sources`, as one transaction. `origin` is `imap` or `file`.
/// The caller checks for a duplicate (org_name, report_id) first.
pub fn insert_sql(r: &Report, origin: &str) -> String {
    let day = crate::civil::Date::from_unix(r.begin.max(0) as u64).to_string();
    let messages: u64 = r.records.iter().map(|x| x.count).sum();
    let q = |s: &str, n: usize| quote(&clip(s, n));
    let mut sql = String::from("START TRANSACTION;\n");
    sql.push_str(&format!(
        "INSERT INTO dmarc_reports (org_name,org_email,report_id,domain,date_begin,date_end,day,p,sp,pct,adkim,aspf,fo,records,messages,imported_at,origin) VALUES ({},{},{},{},{},{},'{day}',{},{},{},{},{},{},{},{messages},UTC_TIMESTAMP(),{});\n",
        q(&r.org_name, 128),
        q(&r.org_email, 255),
        q(&r.report_id, 255),
        q(&r.domain, 253),
        r.begin,
        r.end,
        q(&r.p, 16),
        q(&r.sp, 16),
        r.pct.map(|p| p.to_string()).unwrap_or_else(|| "NULL".into()),
        q(&r.adkim, 4),
        q(&r.aspf, 4),
        q(&r.fo, 16),
        r.records.len(),
        quote(origin),
    ));
    sql.push_str("SET @rep=LAST_INSERT_ID();\n");
    for chunk in r.records.chunks(500) {
        let rows: Vec<String> = chunk
            .iter()
            .map(|x| {
                let dk: Vec<String> = x
                    .dkim_auth
                    .iter()
                    .map(|(d, s, v)| format!("{d}:{s}:{v}"))
                    .collect();
                let sp: Vec<String> = x
                    .spf_auth
                    .iter()
                    .map(|(d, s, v)| format!("{d}:{s}:{v}"))
                    .collect();
                let rs: Vec<String> = x
                    .reasons
                    .iter()
                    .map(|(t, c)| {
                        if c.is_empty() {
                            t.clone()
                        } else {
                            format!("{t}: {c}")
                        }
                    })
                    .collect();
                let hf = if x.header_from.is_empty() {
                    &r.domain
                } else {
                    &x.header_from
                };
                format!(
                    "(@rep,'{day}',{},{},{},{},{},{},{},{},{},{},{},{},{})",
                    q(&x.source_ip, 45),
                    x.count,
                    q(&x.disposition, 16),
                    q(&x.dkim, 16),
                    q(&x.spf, 16),
                    x.passed() as u8,
                    x.forwarded() as u8,
                    q(hf, 253),
                    q(&x.envelope_from, 253),
                    q(&x.envelope_to, 253),
                    q(&dk.join(";"), 1024),
                    q(&sp.join(";"), 1024),
                    q(&rs.join("; "), 512),
                )
            })
            .collect();
        sql.push_str(&format!(
            "INSERT INTO dmarc_records (report,day,source_ip,count,disposition,dmarc_dkim,dmarc_spf,passed,forwarded,header_from,envelope_from,envelope_to,dkim_auth,spf_auth,reasons) VALUES\n{};\n",
            rows.join(",\n")
        ));
    }
    // one source row per (ip, header_from domain)
    let mut seen = std::collections::BTreeSet::new();
    for x in &r.records {
        let hf = if x.header_from.is_empty() {
            r.domain.clone()
        } else {
            x.header_from.clone()
        };
        seen.insert((x.source_ip.clone(), hf));
    }
    if !seen.is_empty() {
        let rows: Vec<String> = seen
            .iter()
            .map(|(ip, d)| format!("({},{},'{day}','{day}')", q(ip, 45), q(d, 253)))
            .collect();
        sql.push_str(&format!(
            "INSERT INTO dmarc_sources (ip,domain,first_seen,last_seen) VALUES\n{}\nON DUPLICATE KEY UPDATE first_seen=LEAST(first_seen,VALUES(first_seen)),last_seen=GREATEST(last_seen,VALUES(last_seen));\n",
            rows.join(",\n")
        ));
    }
    sql.push_str("COMMIT;\n");
    sql
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTLOOK: &str = include_str!("../tests/fixtures/dmarc/outlook-example.org.xml");

    #[test]
    fn parses_the_outlook_sample() {
        let r = parse(OUTLOOK).unwrap();
        assert_eq!(r.org_name, "Outlook.com");
        assert_eq!(r.org_email, "dmarcreport@microsoft.com");
        assert_eq!(r.report_id, "0411cec2b3734480b47549b2da4cf7aa");
        assert_eq!((r.begin, r.end), (1789171200, 1789257600));
        assert_eq!(r.domain, "example.org");
        assert_eq!((r.adkim.as_str(), r.aspf.as_str()), ("r", "r"));
        assert_eq!(
            (r.p.as_str(), r.sp.as_str(), r.pct),
            ("quarantine", "quarantine", Some(100))
        );
        assert_eq!(r.fo, "1");
        assert_eq!(r.records.len(), 1);
        let x = &r.records[0];
        assert_eq!(x.source_ip, "192.0.2.10");
        assert_eq!(x.count, 1);
        assert_eq!(
            (x.disposition.as_str(), x.dkim.as_str(), x.spf.as_str()),
            ("none", "pass", "pass")
        );
        assert!(x.reasons.is_empty());
        assert_eq!(x.envelope_to, "hotmail.example");
        assert_eq!(x.envelope_from, "example.org");
        assert_eq!(x.header_from, "example.org");
        assert_eq!(
            x.dkim_auth,
            vec![("example.org".into(), "default".into(), "pass".into())]
        );
        assert_eq!(
            x.spf_auth,
            vec![("example.org".into(), "mfrom".into(), "pass".into())]
        );
        assert!(x.passed() && !x.forwarded());
    }

    const GOOGLE: &str = r#"<?xml version="1.0" encoding="UTF-8" ?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range><begin>1789257600</begin><end>1789343999</end></date_range>
  </report_metadata>
  <policy_published><domain>formed.info</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><sp>none</sp><pct>100</pct><np>none</np></policy_published>
  <record>
    <row><source_ip>203.0.113.7</source_ip><count>12</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>formed.info</header_from></identifiers>
    <auth_results><spf><domain>spoof.example</domain><result>softfail</result></spf></auth_results>
  </record>
  <record>
    <row><source_ip>2001:db8::1</source_ip><count>3</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
        <reason><type>local_policy</type><comment>arc=pass</comment></reason></policy_evaluated></row>
    <identifiers><header_from>Formed.Info</header_from></identifiers>
    <auth_results>
      <dkim><domain>lists.example</domain><selector>s1</selector><result>pass</result></dkim>
      <dkim><domain>formed.info</domain><selector>default</selector><result>fail</result></dkim>
    </auth_results>
  </record>
</feedback>"#;

    #[test]
    fn parses_google_style_with_default_namespace_and_reasons() {
        let r = parse(GOOGLE).unwrap();
        assert_eq!(r.domain, "formed.info");
        assert_eq!(r.fo, "");
        assert_eq!(r.records.len(), 2);
        let (a, b) = (&r.records[0], &r.records[1]);
        assert!(!a.passed() && !a.forwarded());
        assert_eq!(
            a.spf_auth,
            vec![("spoof.example".into(), "".into(), "softfail".into())]
        );
        assert_eq!(b.source_ip, "2001:db8::1");
        assert_eq!(b.header_from, "formed.info");
        assert!(b.forwarded());
        assert_eq!(b.dkim_auth.len(), 2);
    }

    #[test]
    fn rejects_non_reports() {
        assert!(parse("<html><body/></html>").is_err());
        assert!(parse("<feedback><report_metadata/></feedback>").is_err());
        let bad_ip = OUTLOOK.replace("192.0.2.10", "not-an-ip");
        assert!(parse(&bad_ip).is_err());
    }

    #[test]
    fn unpacks_gzip_zip_and_plain() {
        assert_eq!(unpack(b"  <feedback/>").unwrap(), b"<feedback/>");
        assert!(unpack(b"hello").is_err());
        let dir = std::env::temp_dir().join(format!("msfe-dmarc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let xml = dir.join("r.xml");
        std::fs::write(&xml, OUTLOOK).unwrap();
        let gz = Command::new("gzip")
            .arg("-c")
            .arg(&xml)
            .output()
            .unwrap()
            .stdout;
        assert_eq!(
            parse(&String::from_utf8(unpack(&gz).unwrap()).unwrap())
                .unwrap()
                .report_id,
            "0411cec2b3734480b47549b2da4cf7aa"
        );
        let zip = dir.join("r.zip");
        if Command::new("zip")
            .arg("-qj")
            .arg(&zip)
            .arg(&xml)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            let z = std::fs::read(&zip).unwrap();
            assert_eq!(unpack(&z).unwrap(), OUTLOOK.as_bytes());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extracts_reports_from_a_mail() {
        let b64 = crate::b64::encode(OUTLOOK.as_bytes());
        let mail = format!(
            "From: dmarcreport@microsoft.com\r\nSubject: Report Domain: example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nThis is a DMARC report.\r\n--b\r\nContent-Type: application/octet-stream; name=\"outlook.com!example.org!1789171200!1789257600.xml\"\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--b--\r\n"
        );
        let got = extract(mail.as_bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].0,
            "outlook.com!example.org!1789171200!1789257600.xml"
        );
        assert_eq!(got[0].1.as_ref().unwrap().domain, "example.org");
        assert!(extract(b"From: x\r\nSubject: hi\r\n\r\nplain mail\r\n").is_empty());
        assert_eq!(from_file(OUTLOOK.as_bytes()).len(), 1);
        assert_eq!(from_file(mail.as_bytes()).len(), 1);
    }

    #[test]
    fn filename_hints() {
        assert_eq!(
            filename_hint("google.com!formed.info!1789257600!1789343999.xml"),
            Some((
                "google.com".into(),
                "formed.info".into(),
                1789257600,
                1789343999
            ))
        );
        assert_eq!(
            filename_hint("Yahoo!formed.info!1!2!abc.xml.gz"),
            Some(("yahoo".into(), "formed.info".into(), 1, 2))
        );
        assert_eq!(filename_hint("report.xml"), None);
    }

    #[test]
    fn classes() {
        assert_eq!(classify(true, false, false, "unknown"), Class::Pass);
        assert_eq!(classify(true, false, false, "abuse"), Class::Pass);
        assert_eq!(classify(false, false, true, "unknown"), Class::OwnFail);
        assert_eq!(classify(false, true, false, "unknown"), Class::Forwarded);
        assert_eq!(classify(false, false, false, "forwarder"), Class::Forwarded);
        assert_eq!(classify(false, false, false, "legit"), Class::LegitFail);
        assert_eq!(classify(false, false, false, "unknown"), Class::Suspect);
        assert_eq!(classify(false, false, false, "abuse"), Class::Suspect);
    }

    fn st(p: &str, pct: Option<u32>, days: u32, legit: u64, pass: u64, own: u64) -> DomainStats {
        DomainStats {
            p: p.into(),
            pct,
            days,
            legit,
            legit_pass: pass,
            own_fail_recent: own,
            suspect_sources: 2,
        }
    }

    #[test]
    fn readiness_steps() {
        let r = readiness(&st("none", None, 20, 1000, 995, 0));
        assert!(r.ready);
        assert_eq!((r.next_p.as_str(), r.next_pct), ("quarantine", 25));
        assert!(r.text.contains("2 unknown source(s)"));
        let r = readiness(&st("quarantine", Some(25), 20, 1000, 995, 0));
        assert_eq!((r.next_p.as_str(), r.next_pct), ("quarantine", 50));
        let r = readiness(&st("quarantine", Some(50), 20, 1000, 995, 0));
        assert_eq!((r.next_p.as_str(), r.next_pct), ("quarantine", 100));
        assert!(
            r.text
                .starts_with("Ready for p=quarantine on all mail (pct=100)"),
            "{}",
            r.text
        );
        let r = readiness(&st("quarantine", Some(100), 20, 1000, 995, 0));
        assert_eq!((r.next_p.as_str(), r.next_pct), ("reject", 100));
        assert!(r.text.contains("refused"));
        let r = readiness(&st("reject", Some(100), 20, 1000, 995, 0));
        assert!(!r.ready);
        assert!(r.text.contains("Already"));
    }

    #[test]
    fn readiness_blockers() {
        let r = readiness(&st("none", None, 5, 1000, 995, 0));
        assert!(!r.ready && r.text.contains("5 day(s)"));
        let r = readiness(&st("none", None, 20, 1000, 900, 0));
        assert!(!r.ready && r.text.contains("90.0%"));
        let r = readiness(&st("none", None, 20, 1000, 1000, 3));
        assert!(!r.ready && r.text.contains("this server failed"));
        let r = readiness(&st("none", None, 20, 0, 0, 0));
        assert!(!r.ready && r.text.contains("no legitimate traffic"));
    }

    #[test]
    fn insert_sql_is_one_transaction_and_quotes() {
        let mut r = parse(OUTLOOK).unwrap();
        r.org_name = "O'Brien Mail".into();
        let sql = insert_sql(&r, "imap");
        assert!(sql.starts_with("START TRANSACTION;"));
        assert!(sql.trim_end().ends_with("COMMIT;"));
        assert!(sql.contains("'O''Brien Mail'"));
        assert!(sql.contains("'2026-09-12'"));
        assert!(sql.contains("'example.org:default:pass'"));
        assert!(sql.contains("ON DUPLICATE KEY UPDATE"));
        assert_eq!(sql.matches("INSERT INTO dmarc_records").count(), 1);
    }
}
