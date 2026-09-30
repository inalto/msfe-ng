//! `/api/dmarc/*`: the DMARC reports view of the Delivery tab.
//!
//! Reads are plain queries over the stored reports (`dmarcq`). `POST fetch`
//! starts the same run cron does in a background thread and returns at once
//! (the run holds its own lock file, so it never overlaps cron's); the view
//! polls `GET status` until `running` drops. `POST test` logs in to the
//! mailbox for the Config tab. `POST source` records the admin's triage.

use crate::http::{Request, Response};
use msfe_core::dmarcjob;
use msfe_core::dmarcq::{self, Filter};
use msfe_core::json::Json;
use msfe_core::Config;
use std::path::Path;

pub fn handle(
    method: &str,
    path: &str,
    req: &Request,
    cfg: &Config,
    config_file: &Path,
) -> Response {
    let _ = config_file;
    match (method, path) {
        ("GET", "/api/dmarc/status") => status(cfg),
        ("POST", "/api/dmarc/fetch") => fetch(cfg),
        ("POST", "/api/dmarc/test") => test(req, cfg),
        ("GET", "/api/dmarc/overview") => with_filter(req, |f| dmarcq::overview(cfg, &f)),
        ("GET", "/api/dmarc/reports") => with_filter(req, |f| dmarcq::reports(cfg, &f)),
        ("GET", "/api/dmarc/report") => report(req, cfg),
        ("GET", "/api/dmarc/source") => source_get(req, cfg),
        ("POST", "/api/dmarc/source") => source_set(req, cfg),
        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn ok(j: Json) -> Response {
    Response::json(200, &j.to_string())
}

fn days(req: &Request) -> u32 {
    req.query_param("days")
        .and_then(|d| d.parse().ok())
        .unwrap_or(30)
        .clamp(1, 3650)
}

/// `?days=&domain=&day=`, checked before anything reaches SQL.
fn filter(req: &Request) -> Result<Filter, Response> {
    let domain = req
        .query_param("domain")
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty());
    if let Some(d) = &domain {
        if !dmarcq::valid_domain(d) {
            return Err(err(400, "bad domain"));
        }
    }
    let day = req.query_param("day").filter(|d| !d.is_empty());
    if let Some(d) = &day {
        if !dmarcq::valid_day(d) {
            return Err(err(400, "bad day (YYYY-MM-DD)"));
        }
    }
    Ok(Filter {
        days: days(req),
        domain,
        day,
    })
}

fn with_filter(req: &Request, f: impl FnOnce(Filter) -> Result<Json, String>) -> Response {
    match filter(req) {
        Ok(flt) => match f(flt) {
            Ok(j) => ok(j),
            Err(e) => err(500, &e),
        },
        Err(r) => r,
    }
}

fn status(cfg: &Config) -> Response {
    let counts = msfe_core::db::query(
        cfg,
        "SELECT (SELECT COUNT(*) FROM dmarc_reports), (SELECT IFNULL(SUM(count),0) FROM dmarc_records), (SELECT IFNULL(MAX(day),'') FROM dmarc_reports)",
    );
    let (db_ok, c) = match counts {
        Ok(r) => (true, r.into_iter().next().unwrap_or_default()),
        Err(_) => (false, Vec::new()),
    };
    let num = |i: usize| Json::Int(c.get(i).and_then(|v| v.parse().ok()).unwrap_or(0));
    ok(Json::Object(vec![
        ("configured".into(), Json::Bool(cfg.dmarc_configured())),
        (
            "mailbox".into(),
            Json::str(if cfg.dmarc_configured() {
                format!("{} ({})", cfg.dmarc_imap_user, cfg.dmarc_imap_folder)
            } else {
                String::new()
            }),
        ),
        (
            "running".into(),
            Json::Bool(dmarcjob::running(&dmarcjob::lock_path())),
        ),
        (
            "last_run".into(),
            dmarcjob::last_run(cfg).unwrap_or(Json::Null),
        ),
        ("db".into(), Json::Bool(db_ok)),
        ("reports".into(), num(0)),
        ("messages".into(), num(1)),
        (
            "latest_day".into(),
            Json::str(c.get(2).cloned().unwrap_or_default()),
        ),
        (
            "retention_days".into(),
            Json::Int(cfg.dmarc_retention_days as i64),
        ),
    ]))
}

fn fetch(cfg: &Config) -> Response {
    if !cfg.dmarc_configured() {
        return err(400, "no DMARC report mailbox configured (Config tab)");
    }
    if dmarcjob::running(&dmarcjob::lock_path()) {
        return err(409, "a fetch is already running");
    }
    let cfg = cfg.clone();
    std::thread::spawn(move || {
        let _ = dmarcjob::run(&cfg, &dmarcjob::Options::default());
    });
    ok(Json::Object(vec![("started".into(), Json::Bool(true))]))
}

/// Log in with the saved settings, or with the ones in the form (a body of
/// `dmarc_imap_*` fields) before they are saved; an empty password keeps the
/// saved one, but only for the saved host and user.
fn test(req: &Request, cfg: &Config) -> Response {
    let mut c = cfg.clone();
    if let Ok(Json::Object(fields)) = Json::parse(&req.body) {
        for (k, v) in fields {
            let s = match &v {
                Json::Str(s) => s.trim().to_string(),
                Json::Bool(b) => b.to_string(),
                Json::Int(n) => n.to_string(),
                _ => continue,
            };
            match k.as_str() {
                "dmarc_imap_host" => c.dmarc_imap_host = s,
                "dmarc_imap_port" => c.dmarc_imap_port = s.parse().unwrap_or(c.dmarc_imap_port),
                "dmarc_imap_tls" => c.dmarc_imap_tls = s == "true",
                "dmarc_imap_verify" => c.dmarc_imap_verify = s == "true",
                "dmarc_imap_user" => c.dmarc_imap_user = s,
                "dmarc_imap_pass" if !s.is_empty() => c.dmarc_imap_pass = s,
                "dmarc_imap_folder" if !s.is_empty() => c.dmarc_imap_folder = s,
                _ => {}
            }
        }
    }
    // the saved password only ever goes to the saved server and account
    let typed_pass = matches!(
        Json::parse(&req.body).ok().and_then(|v| v
            .get("dmarc_imap_pass")
            .and_then(|p| p.as_str().map(|s| !s.trim().is_empty()))),
        Some(true)
    );
    if !typed_pass
        && (c.dmarc_imap_host != cfg.dmarc_imap_host || c.dmarc_imap_user != cfg.dmarc_imap_user)
    {
        c.dmarc_imap_pass.clear();
    }
    let (good, lines) = msfe_core::imap::test(&c);
    ok(Json::Object(vec![
        ("ok".into(), Json::Bool(good)),
        (
            "transcript".into(),
            Json::Array(lines.into_iter().map(Json::Str).collect()),
        ),
    ]))
}

fn report(req: &Request, cfg: &Config) -> Response {
    let Some(id) = req.query_param("id").and_then(|i| i.parse::<u64>().ok()) else {
        return err(400, "id required");
    };
    match dmarcq::report_records(cfg, id) {
        Ok(j) => ok(j),
        Err(e) => err(500, &e),
    }
}

fn ip_param(v: Option<String>) -> Option<String> {
    let ip = v?.trim().parse::<std::net::IpAddr>().ok()?;
    Some(ip.to_string())
}

fn source_get(req: &Request, cfg: &Config) -> Response {
    let Some(ip) = ip_param(req.query_param("ip")) else {
        return err(400, "bad ip");
    };
    let domain = req
        .query_param("domain")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !dmarcq::valid_domain(&domain) {
        return err(400, "bad domain");
    }
    match dmarcq::source_records(cfg, &ip, &domain, days(req)) {
        Ok(j) => ok(j),
        Err(e) => err(500, &e),
    }
}

fn source_set(req: &Request, cfg: &Config) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    let Some(ip) = ip_param(v.get("ip").and_then(Json::as_str).map(str::to_string)) else {
        return err(400, "bad ip");
    };
    let all = matches!(v.get("all_domains"), Some(Json::Bool(true)));
    let domain = v.str_field("domain").trim().to_ascii_lowercase();
    if !all && !dmarcq::valid_domain(&domain) {
        return err(400, "bad domain");
    }
    match dmarcq::set_status(
        cfg,
        &ip,
        (!all).then_some(domain.as_str()),
        &v.str_field("status"),
        &v.str_field("note"),
    ) {
        Ok(()) => ok(Json::Object(vec![("ok".into(), Json::Bool(true))])),
        Err(e) => err(400, &e),
    }
}
