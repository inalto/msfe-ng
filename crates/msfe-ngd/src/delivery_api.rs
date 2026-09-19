//! `/api/delivery/*`: start a delivery test, poll its progressive report,
//! cancel it, fetch a finished report (JSON or HTML), list recent runs, and
//! answer the two cheap questions the tab asks before a run (is the domain
//! hosted here, which tools are available).
//!
//! Starting a run registers it and returns at once, so the write lock every
//! non-GET holds is released in milliseconds; the run continues on its own
//! thread and polling is a lock-free GET.

use crate::http::{Request, Response};
use msfe_core::delivery::Report;
use msfe_core::deliveryrun::{self, StartError};
use msfe_core::json::Json;
use msfe_core::{users, Config};
use std::path::Path;

pub fn handle(
    method: &str,
    path: &str,
    req: &Request,
    cfg: &Config,
    config_file: &Path,
) -> Response {
    match (method, path) {
        ("POST", "/api/delivery/run") => start(req, cfg),
        ("GET", "/api/delivery/run") => poll(req),
        ("POST", "/api/delivery/run/cancel") => cancel(req),
        ("GET", "/api/delivery/report") => report(req),
        ("GET", "/api/delivery/recent") => recent(),
        ("GET", "/api/delivery/local") => local(req, cfg, config_file),
        ("GET", "/api/delivery/tools") => tools(),
        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn report_json(r: &Report) -> Json {
    let mut f = match r.to_json() {
        Json::Object(f) => f,
        _ => Vec::new(),
    };
    let elapsed = r
        .finished
        .unwrap_or_else(msfe_core::delivery::now_secs)
        .saturating_sub(r.started);
    f.push(("elapsed_ms".into(), Json::Int(elapsed as i64 * 1000)));
    Json::Object(f)
}

fn start(req: &Request, cfg: &Config) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    let inputs = match deliveryrun::parse_inputs(
        &v.str_field("address"),
        v.get("ip").and_then(Json::as_str),
        v.get("selector").and_then(Json::as_str),
        v.get("days").and_then(Json::as_i64),
        matches!(v.get("audit"), Some(Json::Bool(true))),
        matches!(v.get("force"), Some(Json::Bool(true))),
        None,
    ) {
        Ok(i) => i,
        Err(e) => return err(400, &e),
    };
    if !inputs.force {
        if let Some(r) = deliveryrun::cached_report(&inputs, cfg.delivery_cache_secs) {
            return Response::json(
                200,
                &Json::Object(vec![
                    ("run_id".into(), Json::str(&r.id)),
                    ("cached".into(), Json::Bool(true)),
                    (
                        "finished".into(),
                        r.finished
                            .map(|f| Json::Int(f as i64))
                            .unwrap_or(Json::Null),
                    ),
                ])
                .to_string(),
            );
        }
    }
    match deliveryrun::start(cfg, inputs, deliveryrun::plan) {
        Ok(id) => Response::json(
            201,
            &Json::Object(vec![
                ("run_id".into(), Json::str(id)),
                ("cached".into(), Json::Bool(false)),
            ])
            .to_string(),
        ),
        Err(StartError::Invalid(e)) => err(400, &e),
        Err(StartError::Busy(id)) => Response::json(
            409,
            &Json::Object(vec![
                (
                    "error".into(),
                    Json::str("a test of this address is already running"),
                ),
                ("run_id".into(), Json::str(id)),
            ])
            .to_string(),
        ),
        Err(StartError::RateLimited(secs)) => Response::json(
            429,
            &Json::Object(vec![
                (
                    "error".into(),
                    Json::str(format!("too many tests started — try again in {secs} s")),
                ),
                ("retry_secs".into(), Json::Int(secs as i64)),
            ])
            .to_string(),
        ),
    }
}

fn poll(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    match deliveryrun::snapshot(&id) {
        Some(r) => Response::json(200, &report_json(&r).to_string()),
        None => err(
            404,
            "no such run (the daemon may have restarted — start the test again)",
        ),
    }
}

fn cancel(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    if deliveryrun::cancel(&v.str_field("id")) {
        Response::json(200, r#"{"ok":true}"#)
    } else {
        err(404, "no such run")
    }
}

fn report(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    let Some(r) = deliveryrun::snapshot(&id) else {
        return err(404, "no such run");
    };
    match req.query_param("format").as_deref() {
        Some("html") => Response::html(200, &msfe_core::deliveryhtml::render(&r)),
        _ => Response::json(200, &report_json(&r).to_string()),
    }
}

fn recent() -> Response {
    let items: Vec<Json> = deliveryrun::recent(20)
        .iter()
        .map(|r| {
            let s = r.summary();
            let n = |scope: msfe_core::delivery::Scope| {
                s.get(&scope)
                    .map(|c| {
                        Json::Object(vec![
                            ("fail".into(), Json::Int(c[0] as i64)),
                            ("warn".into(), Json::Int(c[1] as i64)),
                            ("unknown".into(), Json::Int(c[2] as i64)),
                            ("pass".into(), Json::Int(c[3] as i64)),
                            ("na".into(), Json::Int(c[4] as i64)),
                        ])
                    })
                    .unwrap_or(Json::Null)
            };
            Json::Object(vec![
                ("id".into(), Json::str(&r.id)),
                ("address".into(), Json::str(&r.inputs.address)),
                ("audit".into(), Json::Bool(r.inputs.audit)),
                ("started".into(), Json::Int(r.started as i64)),
                ("done".into(), Json::Bool(r.done)),
                ("sending".into(), n(msfe_core::delivery::Scope::Sending)),
                ("receiving".into(), n(msfe_core::delivery::Scope::Receiving)),
                ("server".into(), n(msfe_core::delivery::Scope::Server)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![("runs".into(), Json::Array(items))]).to_string(),
    )
}

/// Is `domain` hosted on this server (and by which account)?
fn local(req: &Request, cfg: &Config, _config_file: &Path) -> Response {
    let domain = req
        .query_param("domain")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !msfe_core::netguard::valid_hostname(&domain) {
        return err(400, "domain required");
    }
    let owner = users::owner_of_domain(&domain);
    let hosted = owner.is_some();
    Response::json(
        200,
        &Json::Object(vec![
            ("domain".into(), Json::str(&domain)),
            ("hosted".into(), Json::Bool(hosted)),
            ("user".into(), owner.map(Json::Str).unwrap_or(Json::Null)),
            ("panel".into(), Json::str(&cfg.panel)),
        ])
        .to_string(),
    )
}

fn which(bin: &str) -> Option<String> {
    let extra = [
        "/usr/local/cpanel/3rdparty/bin",
        "/usr/local/bin",
        "/usr/local/sbin",
    ];
    for d in std::env::var_os("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .map(|x| x.display().to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .chain(extra)
    {
        let p = Path::new(d).join(bin);
        if p.is_file() {
            return Some(p.display().to_string());
        }
    }
    None
}

fn tools() -> Response {
    let present = |b: &str| match which(b) {
        Some(p) => Json::Object(vec![
            ("present".into(), Json::Bool(true)),
            ("path".into(), Json::str(p)),
        ]),
        None => Json::Object(vec![("present".into(), Json::Bool(false))]),
    };
    let openssl_version = std::process::Command::new("openssl")
        .arg("version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let rs = msfe_core::resolver::state();
    Response::json(
        200,
        &Json::Object(vec![
            (
                "openssl".into(),
                Json::Object(vec![
                    ("present".into(), Json::Bool(which("openssl").is_some())),
                    ("version".into(), Json::str(openssl_version)),
                ]),
            ),
            ("dig".into(), present("dig")),
            ("delv".into(), present("delv")),
            ("unbound_host".into(), present("unbound-host")),
            ("curl".into(), present("curl")),
            ("exim".into(), present("exim")),
            ("uapi".into(), present("uapi")),
            ("whmapi1".into(), present("whmapi1")),
            (
                "resolver".into(),
                Json::Object(vec![
                    (
                        "nameservers".into(),
                        Json::Array(rs.nameservers.iter().map(Json::str).collect()),
                    ),
                    ("on_loopback".into(), Json::Bool(rs.on_loopback)),
                    ("validating".into(), Json::Bool(rs.done())),
                    ("ipv6".into(), Json::Bool(!rs.public_v6.is_empty())),
                ]),
            ),
        ])
        .to_string(),
    )
}
