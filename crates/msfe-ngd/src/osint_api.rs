//! `/api/delivery/osint/*` (admin only, via the existing peer check): start an
//! OSINT run, poll it, cancel it, export, list, remove. Starting returns at
//! once; the run continues on its own thread and polling is a lock-free GET.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::osintmon::{self, Store};
use msfe_core::osintrun::{self, StartError, StartOk};
use msfe_core::Config;

pub fn handle(method: &str, path: &str, req: &Request, cfg: &Config) -> Response {
    if path == MON || path.starts_with("/api/delivery/osint/monitors/") {
        return handle_with_store(method, path, req, cfg, &osintmon::MysqlStore::new(cfg));
    }
    match (method, path) {
        ("GET", "/api/delivery/osint/providers") => providers(cfg),
        ("POST", "/api/delivery/osint/run") => start(req, cfg),
        ("GET", "/api/delivery/osint/run") => poll(req),
        ("POST", "/api/delivery/osint/run/cancel") => cancel(req),
        ("GET", "/api/delivery/osint/report") => report(req),
        ("GET", "/api/delivery/osint/recent") => recent(),
        ("GET", "/api/delivery/osint/asset") => asset(req),
        ("POST", "/api/delivery/osint/remove") => remove(req),
        _ => err(404, "not found"),
    }
}

/// The monitor routes, with the store injected (the real one in `handle`, an
/// in-memory one in the tests).
pub fn handle_with_store(
    method: &str,
    path: &str,
    req: &Request,
    cfg: &Config,
    store: &dyn Store,
) -> Response {
    match (method, path) {
        ("GET", MON) => monitors_list(cfg, store),
        ("POST", MON) => monitors_add(req, cfg, store),
        ("DELETE", MON) | ("POST", "/api/delivery/osint/monitors/remove") => {
            monitors_remove(req, store)
        }
        ("POST", "/api/delivery/osint/monitors/enable") => monitors_enable(req, store),
        ("POST", "/api/delivery/osint/monitors/run") => monitors_run(req, cfg, store),
        ("GET", "/api/delivery/osint/monitors/runs") => monitors_runs(req, store),
        ("GET", "/api/delivery/osint/monitors/report") => monitors_report(req, store),
        _ => err(404, "not found"),
    }
}

const MON: &str = "/api/delivery/osint/monitors";
/// Largest request body a monitor route reads.
const MAX_BODY: usize = 4096;
const MIGRATE_HINT: &str = "apply the pending migration: msfe-ng db-migrate";

enum DbFault {
    /// The table is not there: the migration has not been applied.
    Missing,
    /// The database cannot be reached or refused the login.
    Unavailable,
    /// The server answered with an SQL error (constraint, data, statement).
    Other,
}

fn classify(e: &str) -> DbFault {
    if e.contains("doesn't exist") {
        return DbFault::Missing;
    }
    let access = [
        "ERROR 1040",
        "ERROR 1044",
        "ERROR 1045",
        "ERROR 1049",
        "ERROR 1129",
        "ERROR 1130",
    ];
    if e.contains("ERROR 1") && !access.iter().any(|a| e.contains(a)) {
        DbFault::Other
    } else {
        DbFault::Unavailable
    }
}

/// A store error as a short fixed message: the raw database text (which can
/// name users, hosts or paths) never reaches the client.
fn db_error(e: &str) -> Response {
    match classify(e) {
        DbFault::Missing => err(
            503,
            &format!("the OSINT monitors tables are missing — {MIGRATE_HINT}"),
        ),
        DbFault::Unavailable | DbFault::Other => err(
            503,
            &format!("the database is not available — check it, then {MIGRATE_HINT} if it is new"),
        ),
    }
}

/// Like `db_error`, but an SQL error from a reachable database is a 500.
fn db_error_write(e: &str) -> Response {
    match classify(e) {
        DbFault::Other => err(500, "could not save the monitor"),
        _ => db_error(e),
    }
}

fn body_json(req: &Request) -> Result<Json, Response> {
    if req.body.len() > MAX_BODY {
        return Err(err(400, "request body too large"));
    }
    Json::parse(&req.body).map_err(|_| err(400, "bad json"))
}

/// A positive integer id: from the query when given there, else from the
/// JSON body (an integer, never a string).
fn positive_id(raw: Option<&str>, body: Option<&Json>, key: &str) -> Result<u32, Response> {
    let bad = || err(400, &format!("{key} must be a positive integer"));
    let n = match raw {
        Some(s) => {
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            s.parse::<i64>().map_err(|_| bad())?
        }
        None => match body.and_then(|b| b.get(key)) {
            Some(Json::Int(n)) => *n,
            _ => return Err(bad()),
        },
    };
    u32::try_from(n).ok().filter(|n| *n > 0).ok_or_else(bad)
}

fn id_of(req: &Request) -> Result<u32, Response> {
    let q = req.query_param("id");
    if q.is_some() {
        return positive_id(q.as_deref(), None, "id");
    }
    let body = body_json(req)?;
    positive_id(None, Some(&body), "id")
}

fn monitors_list(cfg: &Config, store: &dyn Store) -> Response {
    let ms = match store.list(None) {
        Ok(m) => m,
        Err(e) => return db_error(&e),
    };
    let period = osintmon::period_for(msfe_core::osint::now_secs());
    let used = match store.usage_month(&period) {
        Ok(u) => u,
        Err(e) => return db_error(&e),
    };
    Response::json(
        200,
        &Json::Object(vec![
            (
                "monitors".into(),
                Json::Array(ms.iter().map(|m| m.to_json()).collect()),
            ),
            ("max".into(), Json::Int(cfg.osint_max_monitors as i64)),
            (
                "budget".into(),
                Json::Object(vec![
                    ("cap".into(), Json::Int(cfg.osint_monitor_budget as i64)),
                    ("used".into(), Json::Int(used as i64)),
                    ("period".into(), Json::str(period)),
                ]),
            ),
            (
                "telegram".into(),
                Json::Bool(msfe_core::telegram::configured(cfg)),
            ),
            ("enabled".into(), Json::Bool(cfg.osint_enabled)),
            (
                "history_days".into(),
                Json::Int(cfg.osint_history_days as i64),
            ),
        ])
        .to_string(),
    )
}

fn monitors_add(req: &Request, cfg: &Config, store: &dyn Store) -> Response {
    if !cfg.osint_enabled {
        return err(403, "OSINT is switched off — enable it in Config first");
    }
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(addr) = v.get("address").and_then(Json::as_str) else {
        return err(400, "address required");
    };
    let (local, domain) = match msfe_core::netguard::parse_address(addr) {
        Ok(p) => p,
        Err(e) => return err(400, &e),
    };
    let address = format!("{local}@{domain}");
    let Some(list) = v.get("sources").and_then(Json::as_array) else {
        return err(400, "sources must be a list");
    };
    let mut named: Vec<String> = Vec::new();
    for s in list {
        match s.as_str() {
            Some(s) => named.push(s.to_string()),
            None => return err(400, "sources must be a list of ids"),
        }
    }
    let sources = match osintmon::validate_sources(&named, cfg) {
        Ok(s) => s,
        Err(e) => return err(400, &e),
    };
    let interval = match v.get("interval_mins") {
        None | Some(Json::Null) => osintmon::DEFAULT_INTERVAL_MINS,
        Some(Json::Int(n)) => osintmon::clamp_interval((*n).clamp(0, u32::MAX as i64) as u32),
        Some(_) => return err(400, "interval_mins must be a number"),
    };
    // The owner is always the admin's (empty): nothing in the request sets it.
    match store.add(&address, "", &sources, interval, cfg.osint_max_monitors) {
        Ok(m) => Response::json(201, &m.to_json().to_string()),
        Err(e) if e.starts_with("the limit of ") => err(400, &e),
        Err(e) => db_error_write(&e),
    }
}

fn monitors_remove(req: &Request, store: &dyn Store) -> Response {
    let id = match id_of(req) {
        Ok(i) => i,
        Err(r) => return r,
    };
    match store.remove(id) {
        Ok(true) => Response::json(200, r#"{"ok":true}"#),
        Ok(false) => err(404, "no such monitor"),
        Err(e) => db_error(&e),
    }
}

fn monitors_enable(req: &Request, store: &dyn Store) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let id = match positive_id(req.query_param("id").as_deref(), Some(&v), "id") {
        Ok(i) => i,
        Err(r) => return r,
    };
    let on = match v.get("enabled") {
        Some(Json::Bool(b)) => *b,
        _ => return err(400, "enabled must be true or false"),
    };
    match store.get(id) {
        Ok(Some(_)) => {}
        Ok(None) => return err(404, "no such monitor"),
        Err(e) => return db_error(&e),
    }
    match store.set_enabled(id, on) {
        Ok(()) => Response::json(200, r#"{"ok":true}"#),
        Err(e) => db_error(&e),
    }
}

/// Start a scheduled pass on a thread. It runs every monitor that is due, at
/// most `MAX_PER_PASS`, not only the one asked for: "run now" makes that one
/// due (last run 0) and the pass picks it up. Under test no pass is started
/// (it would call the real providers and database).
#[cfg(not(test))]
fn spawn_pass(cfg: &Config) {
    let cfg2 = cfg.clone();
    std::thread::spawn(move || {
        let _ = osintmon::run_due(&cfg2, false);
    });
}

#[cfg(test)]
fn spawn_pass(_cfg: &Config) {}

fn monitors_run(req: &Request, cfg: &Config, store: &dyn Store) -> Response {
    if !cfg.osint_enabled {
        return err(403, "OSINT is switched off — enable it in Config first");
    }
    let id = match id_of(req) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let m = match store.get(id) {
        Ok(Some(m)) => m,
        Ok(None) => return err(404, "no such monitor"),
        Err(e) => return db_error(&e),
    };
    if !m.enabled {
        return err(409, "the monitor is paused — resume it first");
    }
    // A pass in flight would return at once without running anything.
    if osintmon::pass_running(store, msfe_core::osint::now_secs()) {
        return err(
            409,
            "a monitoring pass is already running — it will pick this monitor up on its next pass",
        );
    }
    if let Err(e) = store.touch_last_run(m.id, 0) {
        return db_error(&e);
    }
    spawn_pass(cfg);
    Response::json(
        202,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(true)),
            ("id".into(), Json::Int(m.id as i64)),
        ])
        .to_string(),
    )
}

fn monitors_runs(req: &Request, store: &dyn Store) -> Response {
    let id = match positive_id(req.query_param("id").as_deref(), None, "id") {
        Ok(i) => i,
        Err(r) => return r,
    };
    let limit = match req.query_param("limit") {
        None => 50,
        Some(l) => match l.parse::<usize>() {
            Ok(n) => n.clamp(1, 200),
            Err(_) => return err(400, "limit must be a number"),
        },
    };
    match store.runs(id, limit) {
        Ok(rows) => Response::json(
            200,
            &Json::Object(vec![(
                "runs".into(),
                Json::Array(rows.iter().map(|r| r.to_json()).collect()),
            )])
            .to_string(),
        ),
        Err(e) => db_error(&e),
    }
}

fn monitors_report(req: &Request, store: &dyn Store) -> Response {
    let run = match positive_id(req.query_param("run").as_deref(), None, "run") {
        Ok(i) => i,
        Err(r) => return r,
    };
    match store.run_report(run) {
        Ok(Some(r)) => {
            if req.query_param("format").as_deref() == Some("html") {
                Response::html(200, &msfe_core::osinthtml::render(&r))
            } else {
                Response::json(200, &r.to_json().to_string())
            }
        }
        Ok(None) => err(404, "no such run"),
        Err(e) => db_error(&e),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn providers(cfg: &Config) -> Response {
    let list: Vec<Json> = osintrun::providers(cfg)
        .iter()
        .map(|p| {
            Json::Object(vec![
                ("id".into(), Json::str(p.id)),
                ("name".into(), Json::str(p.name)),
                ("disclosure".into(), Json::str(p.disclosure.as_str())),
                ("configured".into(), Json::Bool(p.configured)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("enabled".into(), Json::Bool(cfg.osint_enabled)),
            ("providers".into(), Json::Array(list)),
            (
                "limits".into(),
                Json::Object(vec![
                    (
                        "runs_per_min".into(),
                        Json::Int(cfg.osint_runs_per_min as i64),
                    ),
                    (
                        "max_concurrent".into(),
                        Json::Int(cfg.osint_max_concurrent as i64),
                    ),
                    (
                        "deadline_secs".into(),
                        Json::Int(cfg.osint_deadline_secs as i64),
                    ),
                    (
                        "max_external_queries".into(),
                        Json::Int(cfg.osint_max_external_queries as i64),
                    ),
                ]),
            ),
        ])
        .to_string(),
    )
}

fn start(req: &Request, cfg: &Config) -> Response {
    if !cfg.osint_enabled {
        return err(403, "OSINT is switched off — enable it in Config first");
    }
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return err(400, &format!("bad json: {e}")),
    };
    let provs: Vec<String> = v
        .get("providers")
        .and_then(Json::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let ctx = v.get("context");
    let delivery_id = ctx
        .and_then(|c| c.get("delivery_run_id"))
        .and_then(Json::as_str);
    let limit = v
        .get("external_query_limit")
        .and_then(Json::as_i64)
        .filter(|n| *n >= 1)
        .map(|n| n.min(u32::MAX as i64) as u32);
    let inputs = match osintrun::parse_inputs(
        &v.str_field("address"),
        &provs,
        matches!(v.get("force"), Some(Json::Bool(true))),
        delivery_id,
    ) {
        Ok(i) => i,
        Err(e) => return err(400, &e),
    }
    .with_query_limit(limit);
    match osintrun::start(cfg, inputs) {
        Ok(StartOk::Started(id)) => Response::json(
            201,
            &Json::Object(vec![
                ("run_id".into(), Json::str(id)),
                ("cached".into(), Json::Bool(false)),
            ])
            .to_string(),
        ),
        Ok(StartOk::Cached(id)) => Response::json(
            200,
            &Json::Object(vec![
                ("run_id".into(), Json::str(id)),
                ("cached".into(), Json::Bool(true)),
            ])
            .to_string(),
        ),
        Err(StartError::Disabled) => err(403, "OSINT is switched off"),
        Err(StartError::Invalid(e)) => err(400, &e),
        Err(StartError::Busy(id)) => Response::json(
            409,
            &Json::Object(vec![
                (
                    "error".into(),
                    Json::str("a lookup of this address is already running"),
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
                    Json::str(format!("too many lookups started — try again in {secs} s")),
                ),
                ("retry_secs".into(), Json::Int(secs as i64)),
            ])
            .to_string(),
        ),
        Err(StartError::TooManyRuns) => {
            err(429, "too many lookups are running — wait for one to finish")
        }
    }
}

fn poll(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    match osintrun::snapshot(&id) {
        Some(r) => Response::json(200, &r.to_json().to_string()),
        None => err(
            404,
            "no such run (the daemon may have restarted — start the lookup again)",
        ),
    }
}

fn cancel(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    if osintrun::cancel(&v.str_field("id")) {
        Response::json(200, r#"{"ok":true}"#)
    } else {
        err(404, "no such running lookup")
    }
}

fn report(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    let Some(r) = osintrun::snapshot(&id) else {
        return err(404, "no such run");
    };
    match req.query_param("format").as_deref() {
        Some("html") => Response::html(200, &msfe_core::osinthtml::render(&r)),
        _ => Response::json(200, &r.to_json().to_string()),
    }
}

fn asset(req: &Request) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    match osintrun::asset(&id) {
        Some((mime, bytes)) => Response::json(
            200,
            &Json::Object(vec![
                ("mime".into(), Json::str(&mime)),
                ("data".into(), Json::str(msfe_core::b64::encode(&bytes))),
            ])
            .to_string(),
        ),
        None => err(404, "no such image"),
    }
}

fn recent() -> Response {
    let items: Vec<Json> = osintrun::recent(20)
        .iter()
        .map(|r| {
            Json::Object(vec![
                ("run_id".into(), Json::str(&r.run_id)),
                ("address".into(), Json::str(&r.address)),
                ("state".into(), Json::str(r.state.as_str())),
                ("started".into(), Json::Int(r.started as i64)),
                ("findings".into(), Json::Int(r.findings.len() as i64)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![("runs".into(), Json::Array(items))]).to_string(),
    )
}

fn remove(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    if osintrun::remove(&v.str_field("id")) {
        Response::json(200, r#"{"ok":true}"#)
    } else {
        err(404, "no such run")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Config {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            std::env::set_var("MSFE_NG_OSINT_FIXTURE", "1");
            std::env::set_var(
                "MSFE_NG_OSINT_DIR",
                std::env::temp_dir().join(format!("msfe-osint-api-{}", std::process::id())),
            );
        });
        Config {
            osint_enabled: true,
            osint_runs_per_min: 30,
            osint_max_concurrent: 8,
            ..Config::default()
        }
    }

    #[test]
    fn providers_answers_even_when_disabled() {
        let mut c = setup();
        c.osint_enabled = false;
        let r = handle(
            "GET",
            "/api/delivery/osint/providers",
            &crate::http::Request::test("GET", "/api/delivery/osint/providers", ""),
            &c,
        );
        assert_eq!(r.status, 200);
        assert!(r.body_str().contains("\"enabled\":false"));
        assert!(r.body_str().contains("fixture"));
    }

    #[test]
    fn run_is_forbidden_when_disabled() {
        let mut c = setup();
        c.osint_enabled = false;
        let body = r#"{"address":"a@example.org","providers":["fixture"]}"#;
        let r = handle(
            "POST",
            "/api/delivery/osint/run",
            &crate::http::Request::test("POST", "/api/delivery/osint/run", body),
            &c,
        );
        assert_eq!(r.status, 403);
    }

    #[test]
    fn invalid_input_is_400_and_unknown_route_is_404() {
        let c = setup();
        let bad = r#"{"address":"nope","providers":["fixture"]}"#;
        let r = handle(
            "POST",
            "/api/delivery/osint/run",
            &crate::http::Request::test("POST", "/api/delivery/osint/run", bad),
            &c,
        );
        assert_eq!(r.status, 400);
        let r = handle(
            "GET",
            "/api/delivery/osint/nothing",
            &crate::http::Request::test("GET", "/api/delivery/osint/nothing", ""),
            &c,
        );
        assert_eq!(r.status, 404);
    }

    #[test]
    fn run_poll_report_and_remove() {
        let c = setup();
        let body = r#"{"address":"breach.api@example.org","providers":["fixture"],"force":true}"#;
        let r = handle(
            "POST",
            "/api/delivery/osint/run",
            &crate::http::Request::test("POST", "/api/delivery/osint/run", body),
            &c,
        );
        assert_eq!(r.status, 201);
        let id = Json::parse(r.body_str()).unwrap().str_field("run_id");
        let mut done = false;
        for _ in 0..200 {
            let p = handle(
                "GET",
                "/api/delivery/osint/run",
                &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={id}"), ""),
                &c,
            );
            assert_eq!(p.status, 200);
            if Json::parse(p.body_str()).unwrap().str_field("state") == "complete" {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(done);
        let h = handle(
            "GET",
            "/api/delivery/osint/report",
            &crate::http::Request::test(
                "GET",
                &format!("/api/delivery/osint/report?id={id}&format=html"),
                "",
            ),
            &c,
        );
        assert_eq!(h.status, 200);
        let rm = handle(
            "POST",
            "/api/delivery/osint/remove",
            &crate::http::Request::test(
                "POST",
                "/api/delivery/osint/remove",
                &format!(r#"{{"id":"{id}"}}"#),
            ),
            &c,
        );
        assert_eq!(rm.status, 200);
        let gone = handle(
            "GET",
            "/api/delivery/osint/run",
            &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={id}"), ""),
            &c,
        );
        assert_eq!(gone.status, 404);
    }

    #[test]
    fn poll_with_a_traversal_id_is_404() {
        let c = setup();
        let r = handle(
            "GET",
            "/api/delivery/osint/run",
            &crate::http::Request::test("GET", "/api/delivery/osint/run?id=..%2Fetc%2Fpasswd", ""),
            &c,
        );
        assert_eq!(r.status, 404);
    }

    fn post(path: &str, body: &str, c: &Config) -> Response {
        handle(
            "POST",
            path,
            &crate::http::Request::test("POST", path, body),
            c,
        )
    }

    #[test]
    fn busy_cached_and_rate_limited_map_to_409_200_429() {
        let c = Config {
            osint_runs_per_min: 1000,
            osint_max_concurrent: 8,
            ..setup()
        };
        let run = "/api/delivery/osint/run";
        let slow = r#"{"address":"slow.route@example.org","providers":["fixture"],"force":true}"#;
        let a = post(run, slow, &c);
        assert_eq!(a.status, 201);
        let id = Json::parse(a.body_str()).unwrap().str_field("run_id");
        let b = post(run, slow, &c);
        assert_eq!(b.status, 409);
        assert_eq!(Json::parse(b.body_str()).unwrap().str_field("run_id"), id);
        let _ = post(
            "/api/delivery/osint/run/cancel",
            &format!(r#"{{"id":"{id}"}}"#),
            &c,
        );

        let quiet = r#"{"address":"quiet.route@example.org","providers":["fixture"],"force":true}"#;
        let q = post(run, quiet, &c);
        let qid = Json::parse(q.body_str()).unwrap().str_field("run_id");
        for _ in 0..200 {
            let p = handle(
                "GET",
                run,
                &crate::http::Request::test("GET", &format!("{run}?id={qid}"), ""),
                &c,
            );
            if Json::parse(p.body_str()).unwrap().str_field("state") == "complete" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let cached = r#"{"address":"quiet.route@example.org","providers":["fixture"]}"#;
        let r = post(run, cached, &c);
        assert_eq!(r.status, 200);
        assert!(r.body_str().contains("\"cached\":true"));

        let tight = Config {
            osint_runs_per_min: 1,
            ..c.clone()
        };
        let one = r#"{"address":"quiet.route2@example.org","providers":["fixture"],"force":true}"#;
        let two = r#"{"address":"quiet.route3@example.org","providers":["fixture"],"force":true}"#;
        let _ = post(run, one, &tight);
        let t = post(run, two, &tight);
        assert_eq!(t.status, 429);
    }

    #[test]
    fn non_hex_ids_are_404_on_report_cancel_and_remove() {
        let c = setup();
        for (m, p, b) in [
            ("GET", "/api/delivery/osint/report?id=..%2Fx", ""),
            ("POST", "/api/delivery/osint/run/cancel", r#"{"id":"../x"}"#),
            ("POST", "/api/delivery/osint/remove", r#"{"id":"../x"}"#),
        ] {
            let r = handle(
                m,
                p.split('?').next().unwrap(),
                &crate::http::Request::test(m, p, b),
                &c,
            );
            assert_eq!(r.status, 404, "{p}");
        }
    }

    #[test]
    fn client_supplied_urls_paths_and_keys_are_ignored() {
        let c = setup();
        let body = r#"{"address":"quiet.ign@example.org","providers":["fixture"],"force":true,"url":"https://evil.example/x","path":"/etc/passwd","key":"k","ip":"127.0.0.1"}"#;
        let r = post("/api/delivery/osint/run", body, &c);
        assert!(r.status == 201 || r.status == 200 || r.status == 429);
        assert!(!r.body_str().contains("evil"));
    }

    #[test]
    fn asset_endpoint_serves_a_run_avatar_and_404s_otherwise() {
        let c = setup();
        let get = |q: &str| {
            let u = format!("/api/delivery/osint/asset?id={q}");
            handle(
                "GET",
                "/api/delivery/osint/asset",
                &crate::http::Request::test("GET", &u, ""),
                &c,
            )
        };
        assert_eq!(get("0123456789abcdef").status, 404);
        assert_eq!(get("..%2Fx").status, 404);
        assert_eq!(get("").status, 404);
        let body = r#"{"address":"avatar.api@example.org","providers":["fixture"],"force":true}"#;
        let r = handle(
            "POST",
            "/api/delivery/osint/run",
            &crate::http::Request::test("POST", "/api/delivery/osint/run", body),
            &c,
        );
        assert_eq!(r.status, 201);
        let id = Json::parse(r.body_str()).unwrap().str_field("run_id");
        let mut aid = String::new();
        for _ in 0..200 {
            let p = handle(
                "GET",
                "/api/delivery/osint/run",
                &crate::http::Request::test("GET", &format!("/api/delivery/osint/run?id={id}"), ""),
                &c,
            );
            let j = Json::parse(p.body_str()).unwrap();
            if j.str_field("state") == "complete" {
                aid = j.get("findings").and_then(Json::as_array).unwrap()[0].str_field("asset_id");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(aid.len(), 16);
        let a = get(&aid);
        assert_eq!(a.status, 200);
        let j = Json::parse(a.body_str()).unwrap();
        assert_eq!(j.str_field("mime"), "image/png");
        assert!(!j.str_field("data").is_empty());
        let _ = handle(
            "POST",
            "/api/delivery/osint/remove",
            &crate::http::Request::test(
                "POST",
                "/api/delivery/osint/remove",
                &format!(r#"{{"id":"{id}"}}"#),
            ),
            &c,
        );
        assert_eq!(get(&aid).status, 404);
    }

    // ---- monitors ---------------------------------------------------------

    use msfe_core::osint::{OsintReport, RunState};
    use msfe_core::osintmon::{FakeStore, Store};

    const MON: &str = "/api/delivery/osint/monitors";

    fn call(m: &str, pq: &str, body: &str, c: &Config, st: &dyn Store) -> Response {
        let path = pq.split('?').next().unwrap();
        handle_with_store(m, path, &crate::http::Request::test(m, pq, body), c, st)
    }

    fn sample_report(addr: &str) -> OsintReport {
        OsintReport {
            run_id: "0123456789abcdef".into(),
            address: addr.into(),
            started: 1_700_000_000,
            finished: Some(1_700_000_003),
            state: RunState::Complete,
            cached: false,
            planned: vec!["fixture".into()],
            sources: vec![],
            findings: vec![],
            delivery_run_id: None,
            limitations: vec![],
        }
    }

    #[test]
    fn monitor_routes_without_a_database_are_503_with_a_hint() {
        let c = setup();
        for (m, pq, b) in [
            ("GET", MON, ""),
            (
                "POST",
                MON,
                r#"{"address":"a@example.org","sources":["fixture"]}"#,
            ),
            ("POST", "/api/delivery/osint/monitors/remove", r#"{"id":1}"#),
            ("DELETE", "/api/delivery/osint/monitors?id=1", ""),
            (
                "POST",
                "/api/delivery/osint/monitors/enable",
                r#"{"id":1,"enabled":false}"#,
            ),
            ("POST", "/api/delivery/osint/monitors/run", r#"{"id":1}"#),
            ("GET", "/api/delivery/osint/monitors/runs?id=1", ""),
            ("GET", "/api/delivery/osint/monitors/report?run=1", ""),
        ] {
            let path = pq.split('?').next().unwrap();
            let r = handle(m, path, &crate::http::Request::test(m, pq, b), &c);
            assert_eq!(r.status, 503, "{m} {pq}");
            assert!(r.body_str().contains("msfe-ng db-migrate"), "{m} {pq}");
            assert!(!r.body_str().contains("mysql"), "{m} {pq}");
        }
    }

    #[test]
    fn database_errors_map_to_fixed_messages() {
        let missing =
            db_error("mysql query failed: ERROR 1146: Table 'x.osint_monitors' doesn't exist");
        assert_eq!(missing.status, 503);
        assert!(missing
            .body_str()
            .contains("apply the pending migration: msfe-ng db-migrate"));
        let other =
            db_error("mysql query failed: Access denied for user 'secret'@'h' (password: YES)");
        assert_eq!(other.status, 503);
        assert!(!other.body_str().contains("secret"));
        assert!(!other.body_str().contains("Access"));
    }

    #[test]
    fn add_is_forbidden_when_osint_is_off() {
        let mut c = setup();
        c.osint_enabled = false;
        let st = FakeStore::default();
        let r = call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        assert_eq!(r.status, 403);
        assert!(st.list(None).unwrap().is_empty());
    }

    #[test]
    fn add_validates_address_sources_interval_and_body() {
        let c = setup();
        let st = FakeStore::default();
        for b in [
            r#"{"address":"nope","sources":["fixture"]}"#,
            r#"{"address":"a@example.org","sources":["nonesuch"]}"#,
            r#"{"address":"a@example.org","sources":["delivery"]}"#,
            r#"{"address":"a@example.org","sources":[]}"#,
            r#"{"address":"a@example.org"}"#,
            r#"{"address":"a@example.org","sources":"fixture"}"#,
            r#"{"address":"a@example.org","sources":[7]}"#,
            r#"{"address":"a@example.org","sources":["fixture"],"interval_mins":"x"}"#,
            r#"{"address":5,"sources":["fixture"]}"#,
            "not json",
            "",
        ] {
            assert_eq!(call("POST", MON, b, &c, &st).status, 400, "{b}");
        }
        let big = format!(
            r#"{{"address":"a@example.org","sources":["fixture"],"pad":"{}"}}"#,
            "x".repeat(10_000)
        );
        assert_eq!(call("POST", MON, &big, &c, &st).status, 400);
        assert!(st.list(None).unwrap().is_empty());
    }

    #[test]
    fn add_clamps_interval_keeps_case_and_ignores_owner_and_extras() {
        let c = setup();
        let st = FakeStore::default();
        let b = r#"{"address":"Mixed.Case@Example.ORG","sources":["fixture"],"interval_mins":5,"owner":"bob","path":"/etc/passwd","url":"http://evil","key":"k","command":"id"}"#;
        let r = call("POST", MON, b, &c, &st);
        assert_eq!(r.status, 201, "{}", r.body_str());
        let j = Json::parse(r.body_str()).unwrap();
        assert_eq!(j.str_field("address"), "Mixed.Case@example.org");
        assert_eq!(j.str_field("owner"), "");
        assert_eq!(j.get("interval_mins").and_then(Json::as_i64), Some(1440));
        let r = call(
            "POST",
            MON,
            r#"{"address":"b@example.org","sources":["fixture"],"interval_mins":999999}"#,
            &c,
            &st,
        );
        assert_eq!(
            Json::parse(r.body_str())
                .unwrap()
                .get("interval_mins")
                .and_then(Json::as_i64),
            Some(10080)
        );
        let r = call(
            "POST",
            MON,
            r#"{"address":"c@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        assert_eq!(
            Json::parse(r.body_str())
                .unwrap()
                .get("interval_mins")
                .and_then(Json::as_i64),
            Some(1440)
        );
    }

    #[test]
    fn hunter_is_stored_only_when_named() {
        let c = setup();
        let st = FakeStore::default();
        let r = call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["gravatar"]}"#,
            &c,
            &st,
        );
        assert!(!r.body_str().contains("hunter"));
        let r = call(
            "POST",
            MON,
            r#"{"address":"b@example.org","sources":["gravatar","hunter"]}"#,
            &c,
            &st,
        );
        assert_eq!(r.status, 201);
        assert!(r.body_str().contains("hunter"));
    }

    #[test]
    fn duplicate_add_updates_and_the_cap_is_400() {
        let c = Config {
            osint_max_monitors: 2,
            ..setup()
        };
        let st = FakeStore::default();
        let add = |a: &str, s: &str| {
            call(
                "POST",
                MON,
                &format!(r#"{{"address":"{a}","sources":["{s}"]}}"#),
                &c,
                &st,
            )
        };
        assert_eq!(add("a@example.org", "fixture").status, 201);
        assert_eq!(add("a@example.org", "gravatar").status, 201);
        assert_eq!(st.list(None).unwrap().len(), 1);
        assert_eq!(
            st.list(None).unwrap()[0].sources,
            vec!["gravatar".to_string()]
        );
        assert_eq!(add("b@example.org", "fixture").status, 201);
        let r = add("c@example.org", "fixture");
        assert_eq!(r.status, 400);
        assert!(r.body_str().contains("osint_max_monitors"));
        // an existing address may still be updated at the cap
        assert_eq!(add("b@example.org", "gravatar").status, 201);
    }

    #[test]
    fn list_reports_max_budget_telegram_and_enabled() {
        let c = Config {
            osint_max_monitors: 7,
            osint_monitor_budget: 42,
            osint_history_days: 30,
            ..setup()
        };
        let st = FakeStore::default();
        call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        let used = msfe_core::osintmon::period_for(msfe_core::osint::now_secs());
        st.usage_reserve(1, &used, 5, "r1").unwrap();
        let r = call("GET", MON, "", &c, &st);
        assert_eq!(r.status, 200);
        let j = Json::parse(r.body_str()).unwrap();
        assert_eq!(j.get("monitors").and_then(Json::as_array).unwrap().len(), 1);
        assert_eq!(j.get("max").and_then(Json::as_i64), Some(7));
        assert_eq!(j.get("history_days").and_then(Json::as_i64), Some(30));
        assert!(matches!(j.get("telegram"), Some(Json::Bool(false))));
        assert!(matches!(j.get("enabled"), Some(Json::Bool(true))));
        let b = j.get("budget").unwrap();
        assert_eq!(b.get("cap").and_then(Json::as_i64), Some(42));
        assert_eq!(b.get("used").and_then(Json::as_i64), Some(5));
        assert_eq!(b.str_field("period"), used);
    }

    #[test]
    fn remove_enable_and_run_now() {
        let c = setup();
        let st = FakeStore::default();
        call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        st.touch_last_run(1, 12345).unwrap();
        let r = call(
            "POST",
            &format!("{MON}/enable"),
            r#"{"id":1,"enabled":false}"#,
            &c,
            &st,
        );
        assert_eq!(r.status, 200);
        assert!(!st.get(1).unwrap().unwrap().enabled);
        assert_eq!(
            call("POST", &format!("{MON}/enable"), r#"{"id":1}"#, &c, &st).status,
            400
        );
        assert_eq!(
            call(
                "POST",
                &format!("{MON}/enable"),
                r#"{"id":9,"enabled":true}"#,
                &c,
                &st
            )
            .status,
            404
        );
        // a paused monitor is not run
        assert_eq!(
            call("POST", &format!("{MON}/run"), r#"{"id":1}"#, &c, &st).status,
            409
        );
        call(
            "POST",
            &format!("{MON}/enable"),
            r#"{"id":1,"enabled":true}"#,
            &c,
            &st,
        );
        let r = call("POST", &format!("{MON}/run"), r#"{"id":1}"#, &c, &st);
        assert_eq!(r.status, 202);
        assert_eq!(st.get(1).unwrap().unwrap().last_run_at, 0);
        assert_eq!(
            call("POST", &format!("{MON}/run"), r#"{"id":9}"#, &c, &st).status,
            404
        );
        assert_eq!(
            call("POST", &format!("{MON}/remove"), r#"{"id":9}"#, &c, &st).status,
            404
        );
        assert_eq!(
            call("DELETE", &format!("{MON}?id=1"), "", &c, &st).status,
            200
        );
        assert!(st.list(None).unwrap().is_empty());
    }

    #[test]
    fn ids_must_be_positive_integers() {
        let c = setup();
        let st = FakeStore::default();
        for (m, pq, b) in [
            ("POST", "remove", r#"{"id":0}"#),
            ("POST", "remove", r#"{"id":-3}"#),
            ("POST", "remove", r#"{"id":"1; DROP"}"#),
            ("POST", "remove", r#"{"id":1.5}"#),
            ("POST", "remove", "{}"),
            ("POST", "enable", r#"{"id":0,"enabled":true}"#),
            ("POST", "run", r#"{"id":99999999999}"#),
            ("DELETE", "?id=abc", ""),
            ("DELETE", "?id=-1", ""),
            ("GET", "runs", ""),
            ("GET", "runs?id=0", ""),
            ("GET", "runs?id=x", ""),
            ("GET", "report", ""),
            ("GET", "report?run=0", ""),
            ("GET", "report?run=1x", ""),
        ] {
            let p = if pq.starts_with('?') {
                MON.to_string() + pq
            } else {
                format!("{MON}/{pq}")
            };
            assert_eq!(call(m, &p, b, &c, &st).status, 400, "{m} {p} {b}");
        }
    }

    #[test]
    fn runs_and_report_success_and_404() {
        let c = setup();
        let st = FakeStore::default();
        call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        let rid = st
            .store_run(1, &sample_report("a@example.org"), 1500, "baseline")
            .unwrap();
        let r = call("GET", &format!("{MON}/runs?id=1&limit=5"), "", &c, &st);
        assert_eq!(r.status, 200);
        let j = Json::parse(r.body_str()).unwrap();
        let runs = j.get("runs").and_then(Json::as_array).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(
            runs[0].get("duration_ms").and_then(Json::as_i64),
            Some(1500)
        );
        assert_eq!(
            call("GET", &format!("{MON}/runs?id=1&limit=9999"), "", &c, &st).status,
            200
        );
        let r = call("GET", &format!("{MON}/report?run={rid}"), "", &c, &st);
        assert_eq!(r.status, 200);
        assert_eq!(
            Json::parse(r.body_str()).unwrap().str_field("address"),
            "a@example.org"
        );
        let h = call(
            "GET",
            &format!("{MON}/report?run={rid}&format=html"),
            "",
            &c,
            &st,
        );
        assert_eq!(h.status, 200);
        assert!(h.body_str().contains("<html") || h.body_str().contains("<!DOCTYPE"));
        assert_eq!(
            call("GET", &format!("{MON}/report?run=999"), "", &c, &st).status,
            404
        );
    }

    #[test]
    fn unknown_monitor_route_is_404() {
        let c = setup();
        let st = FakeStore::default();
        assert_eq!(
            call("GET", &format!("{MON}/nothing"), "", &c, &st).status,
            404
        );
        assert_eq!(call("PUT", MON, "", &c, &st).status, 404);
    }

    #[test]
    fn run_now_is_403_when_off_and_409_while_a_pass_runs() {
        let mut c = setup();
        let st = FakeStore::default();
        call(
            "POST",
            MON,
            r#"{"address":"a@example.org","sources":["fixture"]}"#,
            &c,
            &st,
        );
        st.touch_last_run(1, 777).unwrap();
        st.kv_set(
            "osintmon_running",
            &msfe_core::osint::now_secs().to_string(),
        )
        .unwrap();
        let r = call("POST", &format!("{MON}/run"), r#"{"id":1}"#, &c, &st);
        assert_eq!(r.status, 409);
        assert!(r.body_str().contains("already running"));
        assert_eq!(st.get(1).unwrap().unwrap().last_run_at, 777);
        // a stale guard does not block
        st.kv_set(
            "osintmon_running",
            &(msfe_core::osint::now_secs() - 700).to_string(),
        )
        .unwrap();
        assert_eq!(
            call("POST", &format!("{MON}/run"), r#"{"id":1}"#, &c, &st).status,
            202
        );
        c.osint_enabled = false;
        st.touch_last_run(1, 777).unwrap();
        assert_eq!(
            call("POST", &format!("{MON}/run"), r#"{"id":1}"#, &c, &st).status,
            403
        );
        assert_eq!(st.get(1).unwrap().unwrap().last_run_at, 777);
    }

    #[test]
    fn database_faults_are_classified() {
        let missing =
            "mysql query failed: ERROR 1146 (42S02): Table 'x.osint_monitors' doesn't exist";
        let down = "mysql query failed: ERROR 2002 (HY000): Can't connect to local server";
        let denied = "mysql query failed: ERROR 1045 (28000): Access denied for user 'u'";
        let nobin = "No such file or directory (os error 2)";
        let sql = "mysql query failed: ERROR 1366 (22007): Incorrect string value 'secret'";
        for e in [missing, down, denied, nobin] {
            assert_eq!(db_error_write(e).status, 503, "{e}");
        }
        assert!(db_error_write(missing).body_str().contains("db-migrate"));
        assert!(db_error_write(down).body_str().contains("db-migrate"));
        let r = db_error_write(sql);
        assert_eq!(r.status, 500);
        assert_eq!(r.body_str(), r#"{"error":"could not save the monitor"}"#);
        assert_eq!(db_error(sql).status, 503);
    }
}
