//! Self-contained HTML export of an OSINT report. Every value is escaped; only
//! http(s) URLs become links.

use crate::deliveryhtml::escape;
use crate::osint::OsintReport;

pub fn safe_url(u: &str) -> bool {
    u.starts_with("https://") || u.starts_with("http://")
}

pub fn render(r: &OsintReport) -> String {
    let mut h = String::new();
    h.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>OSINT report — ");
    h.push_str(&escape(&r.address));
    h.push_str("</title><style>body{font:14px system-ui,sans-serif;max-width:60rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ccc;padding:.3rem .5rem;text-align:left;vertical-align:top}.muted{color:#666}</style></head><body>");
    h.push_str(&format!(
        "<h1>OSINT report — {}</h1><p class=\"muted\">run {} · state {} · started {} (unix)</p>",
        escape(&r.address),
        escape(&r.run_id),
        escape(r.state.as_str()),
        r.started
    ));
    h.push_str(
        "<h2>Source coverage</h2><table><tr><th>Source</th><th>State</th><th>Detail</th></tr>",
    );
    for s in &r.sources {
        h.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape(&s.id),
            escape(s.state.as_str()),
            escape(&s.detail)
        ));
    }
    h.push_str("</table><h2>Findings</h2>");
    if r.findings.is_empty() {
        h.push_str(
            "<p class=\"muted\">No findings. This does not mean the address is unexposed.</p>",
        );
    }
    for f in &r.findings {
        h.push_str(&format!(
            "<h3>{}</h3><p class=\"muted\">{} · confidence {} ({}) · observed {} (unix)</p><p>{}</p>",
            escape(&f.title),
            escape(f.group.as_str()),
            escape(f.confidence.as_str()),
            escape(&f.confidence_reason),
            f.observed_at,
            escape(&f.evidence)
        ));
        if let Some(u) = &f.source_url {
            if safe_url(u) {
                h.push_str(&format!(
                    "<p><a href=\"{0}\" rel=\"noreferrer noopener\">{0}</a></p>",
                    escape(u)
                ));
            } else {
                h.push_str(&format!("<p class=\"muted\">{}</p>", escape(u)));
            }
        }
        for l in &f.limitations {
            h.push_str(&format!("<p class=\"muted\">Limit: {}</p>", escape(l)));
        }
    }
    h.push_str("<h2>Limitations</h2><ul>");
    for l in &r.limitations {
        h.push_str(&format!("<li>{}</li>", escape(l)));
    }
    h.push_str("</ul></body></html>");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint::*;

    fn rep(evidence: &str, url: Option<&str>) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: "a<b>@example.org".into(),
            started: 1,
            finished: Some(2),
            state: RunState::Complete,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![SourceStatus {
                id: "fixture".into(),
                state: SourceState::NoMatch,
                retry_after: None,
                detail: "d".into(),
            }],
            findings: vec![Finding {
                group: Group::Exposure,
                confidence: Confidence::Low,
                confidence_reason: "r".into(),
                severity: Severity::Info,
                observed_at: 1,
                event_at: None,
                source_id: "fixture".into(),
                source_url: url.map(String::from),
                title: "T".into(),
                evidence: evidence.into(),
                limitations: vec![],
            }],
            delivery_run_id: None,
            limitations: vec!["l".into()],
        }
    }

    #[test]
    fn evidence_and_address_are_escaped() {
        let h = render(&rep("<script>alert(1)</script>\"'", None));
        assert!(!h.contains("<script>alert"));
        assert!(h.contains("&lt;script&gt;"));
        assert!(h.contains("a&lt;b&gt;@example.org"));
    }

    #[test]
    fn only_http_urls_become_links() {
        assert!(safe_url("https://example.org/x"));
        assert!(safe_url("http://example.org"));
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "//evil",
            "",
            "ftp://x",
            " https://x",
        ] {
            assert!(!safe_url(bad), "{bad}");
        }
        let h = render(&rep("e", Some("javascript:alert(1)")));
        assert!(!h.contains("href=\"javascript:"));
    }

    #[test]
    fn non_matching_sources_stay_visible() {
        let h = render(&rep("e", None));
        assert!(h.contains("no_match"));
        assert!(h.contains("<li>l</li>"), "limitations are printed");
    }

    #[test]
    fn empty_findings_state_the_limit() {
        let mut report = rep("e", None);
        report.findings = vec![];
        let h = render(&report);
        assert!(h.contains("does not mean the address is unexposed"));
    }
}
