//! `/api/delivery/osint/*` (admin only, via the existing peer check): start an
//! OSINT run, poll it, cancel it, export, list, remove. Starting returns at
//! once; the run continues on its own thread and polling is a lock-free GET.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::osintrun::{self, StartError, StartOk};
use msfe_core::Config;

pub fn handle(method: &str, path: &str, req: &Request, cfg: &Config) -> Response {
    match (method, path) {
        ("GET", "/api/delivery/osint/providers") => providers(cfg),
        ("POST", "/api/delivery/osint/run") => start(req, cfg),
        ("GET", "/api/delivery/osint/run") => poll(req),
        ("POST", "/api/delivery/osint/run/cancel") => cancel(req),
        ("GET", "/api/delivery/osint/report") => report(req),
        ("GET", "/api/delivery/osint/recent") => recent(),
        ("POST", "/api/delivery/osint/remove") => remove(req),
        _ => err(404, "not found"),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn providers(cfg: &Config) -> Response {
    let list: Vec<Json> = osintrun::providers()
        .iter()
        .map(|p| {
            Json::Object(vec![
                ("id".into(), Json::str(p.id)),
                ("name".into(), Json::str(p.name)),
                ("disclosure".into(), Json::str(p.disclosure)),
                ("configured".into(), Json::Bool(true)),
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
}
