//! JSON API served over the Unix socket, consumed by the admin/user SPAs
//! (through the panel proxy shims). All handlers return a `Response`.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::rules::DomainPolicy;
use msfe_core::{quarantine, stats, sync, users, Config};
use std::path::Path;

/// Route `/api/*` requests. `config_file` is the daemon's config path (used to
/// locate the policy dir); `cfg` is the loaded config.
pub fn handle(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    if req.path.starts_with("/api/user/") {
        return user_handle(req, cfg, config_file);
    }
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

fn forbidden() -> Response {
    Response::json(403, r#"{"error":"not authorized for this domain"}"#)
}

/// End-user (`/api/user/*`) routes. The authenticated user comes from the
/// `X-MSFE-User` header set by the panel-authenticated user proxy; every route
/// is scoped to the domains that user owns, and quarantine actions re-check
/// ownership via the message's recipient domain.
fn user_handle(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let user = req.user.trim();
    if !users::valid_username(user) {
        return Response::json(403, r#"{"error":"no user context"}"#);
    }
    let domains = users::user_domains(user);
    let pdir = sync::policy_dir(config_file);
    let owns = |d: &str| domains.iter().any(|x| x == d);

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/api/user/domains") => Response::json(
            200,
            &Json::Object(vec![
                ("available".into(), Json::Bool(true)),
                (
                    "domains".into(),
                    Json::Array(domains.iter().map(Json::str).collect()),
                ),
            ])
            .to_string(),
        ),

        ("GET", "/api/user/policy") => {
            let domain = req.query_param("domain").unwrap_or_default();
            if !owns(&domain) {
                return forbidden();
            }
            let ov = sync::load_override(&pdir, &domain);
            let (global, _, _) = sync::load_policy(&pdir);
            let g = |k: &str, d: &str| {
                global
                    .iter()
                    .find(|(kk, _)| kk == k)
                    .map(|(_, v)| v.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| d.into())
            };
            let opt = |o: &Option<String>| o.clone().map(Json::Str).unwrap_or(Json::Null);
            Response::json(
                200,
                &Json::Object(vec![
                    ("available".into(), Json::Bool(true)),
                    ("domain".into(), Json::str(&domain)),
                    (
                        "override".into(),
                        Json::Object(vec![
                            ("spam_scan".into(), opt(&ov.spam_scan)),
                            ("virus_scan".into(), opt(&ov.virus_scan)),
                            ("spam_action".into(), opt(&ov.spam_action)),
                            ("spamhigh_action".into(), opt(&ov.spamhigh_action)),
                            ("lowscore".into(), opt(&ov.lowscore)),
                            ("highscore".into(), opt(&ov.highscore)),
                        ]),
                    ),
                    (
                        "global".into(),
                        Json::Object(vec![
                            ("spam_scan".into(), Json::str(g("def_spam", "yes"))),
                            ("virus_scan".into(), Json::str(g("def_virus", "yes"))),
                            ("spam_action".into(), Json::str(g("def_lspam", "deliver"))),
                            (
                                "spamhigh_action".into(),
                                Json::str(g("def_hspam", "deliver")),
                            ),
                            ("lowscore".into(), Json::str(g("lowscore", "5"))),
                            ("highscore".into(), Json::str(g("highscore", "20"))),
                        ]),
                    ),
                ])
                .to_string(),
            )
        }
        ("PUT", "/api/user/policy") => {
            let v = match Json::parse(&req.body) {
                Ok(v) => v,
                Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
            };
            let domain = v.str_field("domain");
            if !owns(&domain) {
                return forbidden();
            }
            // Keep any existing per-domain lists; only replace scan/action/score.
            let mut ov = sync::load_override(&pdir, &domain);
            let field = |k: &str| -> Option<String> {
                match v.get("override").and_then(|o| o.get(k)) {
                    Some(Json::Str(s)) if !s.is_empty() => Some(s.clone()),
                    _ => None,
                }
            };
            ov.spam_scan = field("spam_scan");
            ov.virus_scan = field("virus_scan");
            ov.spam_action = field("spam_action");
            ov.spamhigh_action = field("spamhigh_action");
            ov.lowscore = field("lowscore");
            ov.highscore = field("highscore");
            apply_override(cfg, config_file, &pdir, &domain, ov)
        }

        ("GET", "/api/user/lists") => {
            let domain = req.query_param("domain").unwrap_or_default();
            if !owns(&domain) {
                return forbidden();
            }
            let ov = sync::load_override(&pdir, &domain);
            Response::json(
                200,
                &Json::Object(vec![
                    ("available".into(), Json::Bool(true)),
                    ("domain".into(), Json::str(&domain)),
                    (
                        "whitelist".into(),
                        Json::Array(ov.whitelist.iter().map(Json::str).collect()),
                    ),
                    (
                        "blacklist".into(),
                        Json::Array(ov.blacklist.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        ("PUT", "/api/user/lists") => {
            let v = match Json::parse(&req.body) {
                Ok(v) => v,
                Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
            };
            let domain = v.str_field("domain");
            if !owns(&domain) {
                return forbidden();
            }
            let arr = |k: &str| -> Vec<String> {
                v.get(k)
                    .and_then(Json::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(|j| j.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let mut ov = sync::load_override(&pdir, &domain);
            ov.whitelist = arr("whitelist");
            ov.blacklist = arr("blacklist");
            apply_override(cfg, config_file, &pdir, &domain, ov)
        }

        ("GET", "/api/user/quarantine") => {
            stat_response(stats::quarantine_list(cfg, &domains, 200))
        }
        ("GET", "/api/user/quarantine/message") => {
            let id = req.query_param("id").unwrap_or_default();
            if !quarantine::valid_message_id(&id) || !quarantine_owned(cfg, &id, &domains) {
                return forbidden();
            }
            match quarantine::find_message(Path::new(&cfg.quarantine_dir), &id)
                .and_then(|p| quarantine::read_message(&p).ok())
            {
                Some(bytes) => Response::text(200, &String::from_utf8_lossy(&bytes)),
                None => Response::json(404, r#"{"error":"message not found"}"#),
            }
        }
        ("POST", "/api/user/quarantine/release") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let id = v.str_field("id");
            if !quarantine::valid_message_id(&id) || !quarantine_owned(cfg, &id, &domains) {
                return forbidden();
            }
            match quarantine::find_message(Path::new(&cfg.quarantine_dir), &id) {
                Some(p) => match quarantine::release(&p) {
                    Ok(()) => Response::json(200, r#"{"ok":true}"#),
                    Err(e) => {
                        Response::json(500, &format!("{{\"error\":\"release failed: {e}\"}}"))
                    }
                },
                None => Response::json(404, r#"{"error":"message not found"}"#),
            }
        }

        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

/// True if the message's recipient domain is one the user owns.
fn quarantine_owned(cfg: &Config, message_id: &str, domains: &[String]) -> bool {
    match stats::to_domain_of(cfg, message_id) {
        Ok(Some(d)) => domains.iter().any(|x| x == &d),
        _ => false,
    }
}

/// Persist a per-domain override, regenerate rules and reload.
fn apply_override(
    cfg: &Config,
    config_file: &Path,
    pdir: &Path,
    domain: &str,
    ov: DomainPolicy,
) -> Response {
    if let Err(e) = sync::save_override(pdir, domain, &ov) {
        return Response::json(500, &format!("{{\"error\":\"cannot save: {e}\"}}"));
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
