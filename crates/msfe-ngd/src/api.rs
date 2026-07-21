//! JSON API served over the Unix socket, consumed by the admin/user SPAs
//! (through the panel proxy shims). All handlers return a `Response`.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::{stats, sync, Config};
use std::path::Path;

/// Route `/api/*` requests. `config_file` is the daemon's config path (used to
/// locate the policy dir); `cfg` is the loaded config.
pub fn handle(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/config") => Response::json(200, &cfg.to_public_json().to_string()),

        ("GET", "/api/policy") => {
            let pdir = sync::policy_dir(config_file);
            let (settings, wl, bl) = sync::load_policy(&pdir);
            Response::json(200, &policy_json(&settings, &wl, &bl).to_string())
        }
        ("PUT", "/api/policy") | ("POST", "/api/policy") => save_policy(req, cfg, config_file),

        ("GET", "/api/stats/summary") => {
            let days = stats::clamp_int(req.query_param("days").as_deref(), 7, 1, 365);
            stat_response(stats::summary(cfg, days))
        }
        ("GET", "/api/stats/series") => {
            let days = stats::clamp_int(req.query_param("days").as_deref(), 30, 1, 365);
            stat_response(stats::series(cfg, days))
        }
        ("GET", "/api/stats/top") => {
            let days = stats::clamp_int(req.query_param("days").as_deref(), 7, 1, 365);
            let limit = stats::clamp_int(req.query_param("limit").as_deref(), 10, 1, 100);
            let field = req
                .query_param("field")
                .unwrap_or_else(|| "from_domain".into());
            stat_response(stats::top(cfg, days, &field, limit))
        }
        ("GET", "/api/messages") => {
            let limit = stats::clamp_int(req.query_param("limit").as_deref(), 50, 1, 500);
            stat_response(stats::messages(cfg, limit))
        }

        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

fn policy_json(settings: &[(String, String)], wl: &[String], bl: &[String]) -> Json {
    Json::Object(vec![
        (
            "settings".into(),
            Json::Object(
                settings
                    .iter()
                    .map(|(k, v)| (k.clone(), Json::str(v)))
                    .collect(),
            ),
        ),
        (
            "whitelist".into(),
            Json::Array(wl.iter().map(Json::str).collect()),
        ),
        (
            "blacklist".into(),
            Json::Array(bl.iter().map(Json::str).collect()),
        ),
    ])
}

/// Persist a policy sent as `{settings:{..}, whitelist:[..], blacklist:[..]}`,
/// then regenerate the rule files and reload MailScanner.
fn save_policy(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
    };
    let settings: Vec<(String, String)> = match v.get("settings") {
        Some(Json::Object(f)) => f
            .iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        _ => Vec::new(),
    };
    let strs = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(Json::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|j| j.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let (wl, bl) = (strs("whitelist"), strs("blacklist"));

    let pdir = sync::policy_dir(config_file);
    if let Err(e) = sync::save_policy(&pdir, &settings, &wl, &bl) {
        return Response::json(500, &format!("{{\"error\":\"cannot save policy: {e}\"}}"));
    }
    match sync::run(cfg, config_file, None) {
        Ok(n) => {
            let reloaded = sync::reload_mailscanner();
            Response::json(
                200,
                &format!("{{\"ok\":true,\"files\":{n},\"reloaded\":{reloaded}}}"),
            )
        }
        Err(e) => Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}")),
    }
}

/// Turn a stats result into a response; a DB error becomes a graceful
/// `{"available":false}` so the dashboard can show "no data yet".
fn stat_response(r: std::io::Result<Json>) -> Response {
    match r {
        Ok(j) => Response::json(200, &j.to_string()),
        Err(_) => Response::json(200, r#"{"available":false}"#),
    }
}
