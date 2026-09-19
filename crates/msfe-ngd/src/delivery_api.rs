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
        ("POST", "/api/delivery/eml") => start_eml(req, cfg),
        ("GET", "/api/delivery/run") => poll(req),
        ("POST", "/api/delivery/run/cancel") => cancel(req),
        ("GET", "/api/delivery/report") => report(req),
        ("GET", "/api/delivery/recent") => recent(),
        ("GET", "/api/delivery/local") => local(req, cfg, config_file),
        ("GET", "/api/delivery/tools") => tools(),
        ("POST", "/api/delivery/inbox") => inbox_create(cfg),
        ("GET", "/api/delivery/inbox") => inbox_poll(req, cfg),
        ("DELETE", "/api/delivery/inbox") | ("POST", "/api/delivery/inbox/remove") => {
            inbox_remove(req)
        }
        ("POST", "/api/delivery/inbox/install") => inbox_install(req, cfg, true),
        ("POST", "/api/delivery/inbox/uninstall") => inbox_install(req, cfg, false),
        ("POST", "/api/delivery/testmail") => testmail_start(req),
        ("GET", "/api/delivery/testmail/last") => testmail_last(),
        ("GET", "/api/delivery/monitors") => monitors_list(cfg),
        ("POST", "/api/delivery/monitors") => monitors_add(req, cfg),
        ("DELETE", "/api/delivery/monitors") | ("POST", "/api/delivery/monitors/remove") => {
            monitors_remove(req, cfg)
        }
        ("POST", "/api/delivery/monitors/enable") => monitors_enable(req, cfg),
        ("POST", "/api/delivery/monitors/run") => monitors_run(req, cfg),
        ("GET", "/api/delivery/monitors/runs") => monitors_runs(req, cfg),
        ("GET", "/api/delivery/monitors/report") => monitors_report(req, cfg),
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

/// `{b64, kind: message|bounce, address?, ip?, selector?, name?}`: store the
/// upload, derive what the message itself says (From, DKIM selector, the
/// sending IP) for anything not given, and start the usual run plus the
/// message/bounce checks.
fn start_eml(req: &Request, cfg: &Config) -> Response {
    use msfe_core::delivery::EmlKind;
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    let kind = match EmlKind::parse(&v.str_field("kind")) {
        Some(k) => k,
        None => return err(400, "kind must be message or bounce"),
    };
    let raw = match msfe_core::b64::decode(&v.str_field("b64")) {
        Some(r) => r,
        None => return err(400, "b64 is not valid base64"),
    };
    let derived = msfe_core::emlcheck::derive_inputs(&raw, kind);
    let address = match v
        .get("address")
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        Some(a) => a.to_string(),
        None => match derived.address {
            Some(a) => a,
            None => {
                return err(
                    400,
                    "the message has no usable From address — give the address to test",
                )
            }
        },
    };
    let ip = v
        .get("ip")
        .and_then(Json::as_str)
        .map(str::to_string)
        .or_else(|| derived.ip.map(|i| i.to_string()));
    let selector = v
        .get("selector")
        .and_then(Json::as_str)
        .map(str::to_string)
        .or(derived.selector);
    let mut inputs = match deliveryrun::parse_inputs(
        &address,
        ip.as_deref(),
        selector.as_deref(),
        v.get("days").and_then(Json::as_i64),
        matches!(v.get("audit"), Some(Json::Bool(true))),
        true,
        None,
    ) {
        Ok(i) => i,
        Err(e) => return err(400, &e),
    };
    inputs.eml = match deliveryrun::store_eml(kind, &v.str_field("name"), &raw) {
        Ok(e) => Some(e),
        Err(e) => return err(400, &e),
    };
    match deliveryrun::start(cfg, inputs.clone(), deliveryrun::plan) {
        Ok(id) => Response::json(
            201,
            &Json::Object(vec![
                ("run_id".into(), Json::str(id)),
                ("cached".into(), Json::Bool(false)),
                ("address".into(), Json::str(&inputs.address)),
                (
                    "ip".into(),
                    inputs
                        .ip
                        .map(|i| Json::str(i.to_string()))
                        .unwrap_or(Json::Null),
                ),
                (
                    "selector".into(),
                    inputs.selector.clone().map(Json::Str).unwrap_or(Json::Null),
                ),
            ])
            .to_string(),
        ),
        Err(e) => {
            if let Some(x) = &inputs.eml {
                let _ = std::fs::remove_file(&x.path);
            }
            match e {
                StartError::Invalid(e) => err(400, &e),
                StartError::Busy(id) => Response::json(
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
                StartError::RateLimited(secs) => Response::json(
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
    }
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
                "diag_inbox".into(),
                Json::Bool(msfe_core::diaginbox::installed()),
            ),
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

// ---- the diagnostic inbox ------------------------------------------------------

fn inbox_create(cfg: &Config) -> Response {
    use msfe_core::diaginbox;
    if !diaginbox::installed() {
        return Response::json(
            503,
            &Json::Object(vec![
                ("error".into(), Json::str("the diagnostic inbox is not installed on this server")),
                ("fix".into(), Json::str("Install it below (or `msfe-ng delivery inbox install`): two Exim fragments included from /etc/exim.conf.local, then buildeximconf + restart")),
            ])
            .to_string(),
        );
    }
    match diaginbox::create(cfg) {
        Ok(i) => Response::json(
            201,
            &Json::Object(vec![
                ("token".into(), Json::str(&i.token)),
                ("address".into(), Json::str(&i.address)),
                ("expires".into(), Json::Int(i.expires as i64)),
                ("ttl_secs".into(), Json::Int(diaginbox::TTL_SECS as i64)),
            ])
            .to_string(),
        ),
        Err(e) => err(500, &format!("cannot create the inbox: {e}")),
    }
}

fn inbox_poll(req: &Request, cfg: &Config) -> Response {
    let token = req.query_param("token").unwrap_or_default();
    if !msfe_core::diaginbox::valid_token(&token) {
        return err(400, "token required");
    }
    match msfe_core::diaginbox::poll(cfg, &token) {
        Some(st) => Response::json(200, &st.to_json().to_string()),
        None => err(404, "no such inbox (expired or removed)"),
    }
}

fn inbox_remove(req: &Request) -> Response {
    let token = req
        .query_param("token")
        .or_else(|| Json::parse(&req.body).ok().map(|v| v.str_field("token")))
        .unwrap_or_default();
    if !msfe_core::diaginbox::valid_token(&token) {
        return err(400, "token required");
    }
    msfe_core::diaginbox::remove(&token);
    Response::json(200, r#"{"ok":true}"#)
}

fn inbox_install(req: &Request, cfg: &Config, install: bool) -> Response {
    let dry = Json::parse(&req.body)
        .ok()
        .is_some_and(|v| matches!(v.get("dry_run"), Some(Json::Bool(true))));
    let r = if install {
        msfe_core::diaginbox::wire(cfg, dry)
    } else {
        msfe_core::diaginbox::unwire(dry)
    };
    match r {
        Ok(w) => Response::json(
            200,
            &Json::Object(vec![
                ("ok".into(), Json::Bool(true)),
                ("dry_run".into(), Json::Bool(w.dry_run)),
                (
                    "installed".into(),
                    Json::Bool(msfe_core::diaginbox::installed()),
                ),
                (
                    "actions".into(),
                    Json::Array(w.actions.iter().map(Json::str).collect()),
                ),
            ])
            .to_string(),
        ),
        Err(e) => err(500, &e.to_string()),
    }
}

// ---- the outbound test message -------------------------------------------------

fn testmail_start(req: &Request) -> Response {
    use msfe_core::testmail;
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    if !matches!(v.get("confirm"), Some(Json::Bool(true))) {
        return err(400, "confirm:true required — this sends a real message");
    }
    let (from, to) = match testmail::validate(&v.str_field("from"), &v.str_field("to")) {
        Ok(x) => x,
        Err(e) => return err(400, &e),
    };
    if msfe_core::jobs::status(testmail::JOB).running {
        return Response::json(
            409,
            r#"{"error":"a test message is already being followed"}"#,
        );
    }
    let tag = testmail::new_tag();
    match testmail::start(&from, &to, &tag) {
        Ok(()) => Response::json(
            202,
            &Json::Object(vec![
                ("ok".into(), Json::Bool(true)),
                ("job".into(), Json::str(testmail::JOB)),
                ("tag".into(), Json::str(&tag)),
                ("from".into(), Json::str(&from)),
                ("to".into(), Json::str(&to)),
            ])
            .to_string(),
        ),
        Err(e) => err(500, &e.to_string()),
    }
}

fn testmail_last() -> Response {
    match msfe_core::testmail::last() {
        Some(v) => Response::json(200, &v.to_string()),
        None => err(404, "no test message sent yet"),
    }
}

// ---- monitors --------------------------------------------------------------

fn db_error(e: std::io::Error) -> Response {
    let msg = e.to_string();
    if msg.contains("doesn't exist") {
        return err(503, "the delivery monitors table is missing — apply the pending migration: msfe-ng db-migrate");
    }
    err(
        503,
        &format!("database: {}", msg.lines().last().unwrap_or("error")),
    )
}

fn monitors_list(cfg: &Config) -> Response {
    match msfe_core::deliverymon::list(cfg, None) {
        Ok(ms) => Response::json(
            200,
            &Json::Object(vec![
                (
                    "monitors".into(),
                    Json::Array(ms.iter().map(|m| m.to_json()).collect()),
                ),
                ("max".into(), Json::Int(cfg.delivery_max_monitors as i64)),
                (
                    "telegram".into(),
                    Json::Bool(msfe_core::telegram::configured(cfg)),
                ),
            ])
            .to_string(),
        ),
        Err(e) => db_error(e),
    }
}

fn body_json(req: &Request) -> Result<Json, Response> {
    Json::parse(&req.body).map_err(|e| err(400, &format!("bad json: {e}")))
}

fn monitors_add(req: &Request, cfg: &Config) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let inputs = match deliveryrun::parse_inputs(
        &v.str_field("address"),
        v.get("ip").and_then(Json::as_str),
        v.get("selector").and_then(Json::as_str),
        v.get("days").and_then(Json::as_i64),
        matches!(v.get("audit"), Some(Json::Bool(true))),
        true,
        None,
    ) {
        Ok(i) => i,
        Err(e) => return err(400, &e),
    };
    let interval = v
        .get("interval_mins")
        .and_then(Json::as_i64)
        .unwrap_or(msfe_core::deliverymon::DEFAULT_INTERVAL_MINS as i64)
        .clamp(1, 100_000) as u32;
    match msfe_core::deliverymon::add(cfg, &inputs, interval, "") {
        Ok(m) => Response::json(201, &m.to_json().to_string()),
        Err(e) if e.contains("doesn't exist") => err(503, "the delivery monitors table is missing — apply the pending migration: msfe-ng db-migrate"),
        Err(e) => err(400, &e),
    }
}

fn id_of(req: &Request) -> Option<u32> {
    req.query_param("id")
        .or_else(|| {
            Json::parse(&req.body)
                .ok()
                .and_then(|v| v.get("id").and_then(Json::as_i64).map(|i| i.to_string()))
        })
        .and_then(|s| s.parse().ok())
}

fn monitors_remove(req: &Request, cfg: &Config) -> Response {
    let Some(id) = id_of(req) else {
        return err(400, "id required");
    };
    match msfe_core::deliverymon::remove(cfg, id, None) {
        Ok(true) => Response::json(200, r#"{"ok":true}"#),
        Ok(false) => err(404, "no such monitor"),
        Err(e) => db_error(e),
    }
}

fn monitors_enable(req: &Request, cfg: &Config) -> Response {
    let Some(id) = id_of(req) else {
        return err(400, "id required");
    };
    let on = Json::parse(&req.body)
        .ok()
        .is_some_and(|v| matches!(v.get("enabled"), Some(Json::Bool(true))));
    match msfe_core::deliverymon::set_enabled(cfg, id, on) {
        Ok(()) => Response::json(200, r#"{"ok":true}"#),
        Err(e) => db_error(e),
    }
}

/// Run one monitor now: the same as a scheduled pass, on a thread; the
/// caller polls the runs list.
fn monitors_run(req: &Request, cfg: &Config) -> Response {
    let Some(id) = id_of(req) else {
        return err(400, "id required");
    };
    let m = match msfe_core::deliverymon::get(cfg, id) {
        Ok(Some(m)) => m,
        Ok(None) => return err(404, "no such monitor"),
        Err(e) => return db_error(e),
    };
    if let Err(e) = msfe_core::db::exec_stdin(
        cfg,
        &format!(
            "UPDATE delivery_monitors SET last_run_at = 0 WHERE id = {};\n",
            m.id
        ),
    ) {
        return db_error(e);
    }
    let cfg2 = cfg.clone();
    std::thread::spawn(move || {
        let _ = msfe_core::deliverymon::run_due(&cfg2, false);
    });
    Response::json(
        202,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(true)),
            ("id".into(), Json::Int(m.id as i64)),
        ])
        .to_string(),
    )
}

fn monitors_runs(req: &Request, cfg: &Config) -> Response {
    let Some(id) = id_of(req) else {
        return err(400, "id required");
    };
    let limit = req
        .query_param("limit")
        .and_then(|l| l.parse().ok())
        .unwrap_or(50);
    match msfe_core::deliverymon::runs(cfg, id, limit) {
        Ok(rows) => {
            if req.query_param("format").as_deref() == Some("csv") {
                Response::text(200, &msfe_core::deliverymon::history_csv(&rows))
            } else {
                Response::json(
                    200,
                    &Json::Object(vec![(
                        "runs".into(),
                        Json::Array(rows.iter().map(|r| r.to_json()).collect()),
                    )])
                    .to_string(),
                )
            }
        }
        Err(e) => db_error(e),
    }
}

fn monitors_report(req: &Request, cfg: &Config) -> Response {
    let Some(run) = req.query_param("run").and_then(|s| s.parse::<u32>().ok()) else {
        return err(400, "run required");
    };
    match msfe_core::deliverymon::run_report(cfg, run) {
        Ok(Some(r)) => {
            if req.query_param("format").as_deref() == Some("html") {
                Response::html(200, &msfe_core::deliveryhtml::render(&r))
            } else {
                Response::json(200, &report_json(&r).to_string())
            }
        }
        Ok(None) => err(404, "no such run"),
        Err(e) => db_error(e),
    }
}
