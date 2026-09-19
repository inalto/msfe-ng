//! A delivery report as one self-contained HTML page (inline CSS, no
//! scripts): what "Download HTML" hands out and what a monitoring alert can
//! attach. Same grouping as the tab — by side of the conversation, then by
//! category, attention order within.

use crate::delivery::{Category, Report, Scope};

pub fn escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn when(secs: u64) -> String {
    if secs == 0 {
        return String::new();
    }
    let d = crate::civil::Date::from_unix(secs);
    let sod = secs % 86_400;
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        d.y,
        d.m,
        d.d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

const CSS: &str = "body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a;background:#fff;margin:0;padding:1.5rem;max-width:64rem}\
h1{font-size:1.3rem;margin:0 0 .2rem}h2{font-size:1.05rem;margin:1.6rem 0 .4rem;border-bottom:1px solid #dde2e8;padding-bottom:.2rem}h3{font-size:.9rem;margin:1rem 0 .3rem;color:#475569}\
.meta{color:#64748b;font-size:.85rem}.chips span{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.78rem;font-weight:600;border:1px solid #cbd5e1;margin-right:.3rem}\
.chips .fail{color:#b91c1c;border-color:#b91c1c}.chips .warn{color:#b45309;border-color:#b45309}.chips .pass{color:#15803d;border-color:#15803d}.chips .unknown{color:#64748b}\
table{width:100%;border-collapse:collapse;font-size:.85rem}td{padding:.4rem .5rem;border-bottom:1px solid #e2e8f0;vertical-align:top}\
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#94a3b8;margin-right:.4rem;vertical-align:middle}.dot.fail{background:#dc2626}.dot.warn{background:#d97706}.dot.pass{background:#16a34a}.dot.na{background:#cbd5e1}\
.sev{font-size:.7rem;color:#64748b;text-transform:uppercase;letter-spacing:.03em}.target{font-family:ui-monospace,Menlo,monospace;font-size:.8rem;color:#475569}\
pre{background:#f1f5f9;border:1px solid #e2e8f0;border-radius:6px;padding:.5rem .7rem;font:.78rem/1.45 ui-monospace,Menlo,monospace;white-space:pre-wrap;word-break:break-all;margin:.3rem 0}\
.fix{border-left:3px solid #0e7490;padding:.3rem .7rem;margin:.4rem 0;background:#f0fdfa}.fix b{color:#0e7490}details summary{cursor:pointer;color:#475569;font-size:.8rem}\
@media print{body{padding:0}}";

/// Render the whole report.
pub fn render(r: &Report) -> String {
    let mut h = String::with_capacity(16 * 1024);
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Delivery test — ");
    h.push_str(&escape(&r.inputs.address));
    h.push_str("</title><style>");
    h.push_str(CSS);
    h.push_str("</style></head><body>");
    h.push_str(&format!(
        "<h1>Delivery test: {}</h1><div class=\"meta\">run {} · started {}{}{}{}</div>",
        escape(&r.inputs.address),
        escape(&r.id),
        when(r.started),
        r.finished
            .map(|f| format!(" · finished {}", when(f)))
            .unwrap_or_default(),
        r.inputs
            .ip
            .map(|ip| format!(" · sending IP {ip}"))
            .unwrap_or_default(),
        r.inputs
            .selector
            .as_ref()
            .map(|s| format!(" · DKIM selector {}", escape(s)))
            .unwrap_or_default(),
    ));
    let summary = r.summary();
    h.push_str("<p class=\"chips\">");
    for (scope, n) in &summary {
        h.push_str(&format!(
            "<b>{}:</b> <span class=\"fail\">{} fail</span><span class=\"warn\">{} warn</span><span class=\"unknown\">{} unknown</span><span class=\"pass\">{} pass</span> &nbsp; ",
            scope_title(*scope),
            n[0],
            n[1],
            n[2],
            n[3]
        ));
    }
    h.push_str("</p>");
    if !r.done {
        h.push_str(
            "<p class=\"meta\"><b>This run had not finished when the report was exported.</b></p>",
        );
    }
    let sorted = r.sorted();
    for scope in [Scope::Sending, Scope::Receiving, Scope::Server] {
        let in_scope: Vec<_> = sorted.iter().filter(|c| c.scope == scope).collect();
        if in_scope.is_empty() {
            continue;
        }
        h.push_str(&format!("<h2>{}</h2>", scope_title(scope)));
        let mut cats: Vec<Category> = in_scope.iter().map(|c| c.category).collect();
        cats.sort();
        cats.dedup();
        for cat in cats {
            h.push_str(&format!("<h3>{}</h3><table>", escape(cat.title())));
            for c in in_scope.iter().filter(|c| c.category == cat) {
                h.push_str(&format!(
                    "<tr><td style=\"width:1%;white-space:nowrap\"><span class=\"dot {}\"></span><span class=\"sev\">{}</span></td><td><b>{}</b>{}<div>{}</div>",
                    c.verdict.as_str(),
                    escape(c.severity.as_str()),
                    escape(&c.title),
                    c.target.as_ref().map(|t| format!(" <span class=\"target\">{}</span>", escape(t))).unwrap_or_default(),
                    escape(&c.explanation)
                ));
                if let Some(f) = &c.fix {
                    h.push_str(&format!(
                        "<div class=\"fix\"><b>Fix:</b> {}",
                        escape(&f.summary)
                    ));
                    if let Some(d) = &f.dns_record {
                        h.push_str(&format!("<pre>{}</pre>", escape(d)));
                    }
                    if let Some(l) = &f.location {
                        h.push_str(&format!("<div>Where: {}</div>", escape(l)));
                    }
                    if let Some(cmd) = &f.command {
                        h.push_str(&format!("<pre>{}</pre>", escape(cmd)));
                    }
                    if let Some(u) = &f.url {
                        h.push_str(&format!("<div><a href=\"{0}\">{0}</a></div>", escape(u)));
                    }
                    h.push_str("</div>");
                }
                if !c.evidence.is_empty() {
                    h.push_str("<details><summary>evidence</summary>");
                    for e in &c.evidence {
                        h.push_str(&format!(
                            "<div class=\"meta\">{}</div><pre>{}</pre>",
                            escape(&e.label),
                            escape(&e.text)
                        ));
                    }
                    h.push_str("</details>");
                }
                h.push_str(&format!(
                    "<div class=\"meta\">{} · {} · {} ms</div></td></tr>",
                    escape(&c.id),
                    when(c.at),
                    c.duration_ms
                ));
            }
            h.push_str("</table>");
        }
    }
    if !r.tool_notes.is_empty() {
        h.push_str("<h2>Notes</h2><ul>");
        for n in &r.tool_notes {
            h.push_str(&format!("<li>{}</li>", escape(n)));
        }
        h.push_str("</ul>");
    }
    h.push_str("<p class=\"meta\">Verdicts: pass / warn / fail are evidence-based; <i>unknown</i> means a lookup or tool did not answer, never a finding; <i>n/a</i> means the check does not apply. Generated by MSFE-NG.</p></body></html>");
    h
}

fn scope_title(s: Scope) -> &'static str {
    match s {
        Scope::Sending => "Sending (mail from this address)",
        Scope::Receiving => "Receiving (mail to this address)",
        Scope::Server => "This server",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::{Check, Fix, Inputs, Severity, Verdict};

    #[test]
    fn renders_every_check_escaped() {
        let r = Report {
            id: "id1".into(),
            inputs: Inputs {
                address: "a@example.com".into(),
                domain: "example.com".into(),
                local_part: "a".into(),
                ip: None,
                selector: Some("<s>".into()),
                days: 2,
                audit: false,
                force: false,
                user_scope: None,
                eml: None,
            },
            started: 1_700_000_000,
            finished: Some(1_700_000_010),
            done: true,
            planned: vec![],
            checks: vec![
                Check::new(
                    "spf.record",
                    Scope::Sending,
                    Category::Spf,
                    Verdict::Fail,
                    Severity::High,
                    "no SPF <script>",
                    "x",
                )
                .fix(Fix {
                    summary: "add".into(),
                    dns_record: Some("example.com. IN TXT \"v=spf1 -all\"".into()),
                    ..Default::default()
                }),
                Check::new(
                    "dns.mx",
                    Scope::Receiving,
                    Category::Dns,
                    Verdict::Pass,
                    Severity::Info,
                    "mx",
                    "ok",
                )
                .evidence("MX", "<b>bold</b>"),
            ],
            tool_notes: vec!["note & more".into()],
            cached: false,
        };
        let h = render(&r);
        assert!(h.contains("&lt;script&gt;"));
        assert!(!h.contains("<script>"));
        assert!(h.contains("&lt;b&gt;bold&lt;/b&gt;"));
        assert!(h.contains("spf.record") && h.contains("dns.mx"));
        assert!(h.contains("v=spf1 -all"));
        assert!(h.contains("note &amp; more"));
        assert!(h.contains("2023-11-14 22:13:20 UTC"));
        assert!(h.contains("&lt;s&gt;"));
    }
}
