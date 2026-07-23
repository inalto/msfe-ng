//! JSON API served over the Unix socket, consumed by the admin/user SPAs
//! (through the panel proxy shims). All handlers return a `Response`.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::rules::DomainPolicy;
use msfe_core::{mailflow, quarantine, rulefile, rules, service, stats, sync, users, Config};
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

        // ---- MailScanner service operations (root-only admin surface) -------
        ("GET", "/api/service/status") => service_status(cfg),
        ("POST", "/api/service/control") => service_control(req),
        ("POST", "/api/service/mailflow") => service_mailflow(req),
        ("POST", "/api/service/sync") => service_sync(cfg, config_file),
        ("GET", "/api/service/maillog") => service_maillog(req, cfg),
        ("GET", "/api/service/journal") => {
            let lines = stats::clamp_int(req.query_param("lines").as_deref(), 80, 10, 500);
            let j = service::journal(lines as usize);
            Response::text(
                200,
                if j.is_empty() {
                    "(no journal entries)"
                } else {
                    &j
                },
            )
        }
        ("GET", "/api/service/queue") => service_queue(cfg),
        ("POST", "/api/service/queue/fix") => service_queue_fix(cfg),
        ("GET", "/api/service/rules") => service_rules(cfg),
        ("GET", "/api/service/rules/view") => service_rules_view(req, cfg),
        ("GET", "/api/service/conf") => service_conf_read(req, cfg, config_file),
        ("PUT", "/api/service/conf") => service_conf_write(req, cfg, config_file),
        ("GET", "/api/service/update") => service_update(),

        // ---- structured rule management (root-only admin surface) -----------
        ("GET", "/api/rules/files") => rules_files(config_file),
        ("GET", "/api/rules/custom") => rules_custom_get(req, config_file),
        ("PUT", "/api/rules/custom") => rules_custom_put(req, cfg, config_file),
        ("GET", "/api/rules/live") => rules_live(req, cfg, config_file),
        ("POST", "/api/rules/adopt") => rules_adopt(req, cfg, config_file),

        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

// ---- structured rule handlers ------------------------------------------------

fn rule_to_json(r: &rulefile::Rule) -> Json {
    let opt = |o: &Option<String>| o.clone().map(Json::Str).unwrap_or(Json::Null);
    Json::Object(vec![
        ("direction".into(), Json::str(r.direction.as_str())),
        ("pattern".into(), Json::str(&r.pattern)),
        (
            "and_direction".into(),
            r.and_direction
                .map(|d| Json::str(d.as_str()))
                .unwrap_or(Json::Null),
        ),
        ("and_pattern".into(), opt(&r.and_pattern)),
        ("value".into(), Json::str(&r.value)),
    ])
}

fn json_to_rule(v: &Json) -> Result<rulefile::Rule, String> {
    let dir = rulefile::Direction::parse(&v.str_field("direction"))
        .ok_or_else(|| format!("bad direction '{}'", v.str_field("direction")))?;
    let and_dir_s = v.str_field("and_direction");
    let and_pat_s = v.str_field("and_pattern");
    let (and_direction, and_pattern) = if and_dir_s.is_empty() && and_pat_s.is_empty() {
        (None, None)
    } else {
        (
            Some(
                rulefile::Direction::parse(&and_dir_s)
                    .ok_or_else(|| format!("bad direction '{and_dir_s}'"))?,
            ),
            Some(and_pat_s),
        )
    };
    let r = rulefile::Rule {
        direction: dir,
        pattern: v.str_field("pattern"),
        and_direction,
        and_pattern,
        value: v.str_field("value").trim().to_string(),
    };
    r.validate()?;
    Ok(r)
}

fn valid_managed(name: &str) -> bool {
    rules::managed_files().iter().any(|f| f == name)
}

fn rules_files(config_file: &Path) -> Response {
    let pdir = sync::policy_dir(config_file);
    let items: Vec<Json> = rules::managed_files()
        .into_iter()
        .map(|name| {
            let n = rulefile::load_custom(&pdir, &name).len();
            Json::Object(vec![
                ("name".into(), Json::str(name)),
                ("custom".into(), Json::Int(n as i64)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![("files".into(), Json::Array(items))]).to_string(),
    )
}

fn rules_custom_get(req: &Request, config_file: &Path) -> Response {
    let file = req.query_param("file").unwrap_or_default();
    if !valid_managed(&file) {
        return Response::json(400, r#"{"error":"not a managed rules file"}"#);
    }
    let rules = rulefile::load_custom(&sync::policy_dir(config_file), &file);
    Response::json(
        200,
        &Json::Object(vec![
            ("file".into(), Json::str(&file)),
            (
                "rules".into(),
                Json::Array(rules.iter().map(rule_to_json).collect()),
            ),
        ])
        .to_string(),
    )
}

fn rules_custom_put(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
    };
    let file = v.str_field("file");
    if !valid_managed(&file) {
        return Response::json(400, r#"{"error":"not a managed rules file"}"#);
    }
    let mut parsed = Vec::new();
    for (i, rj) in v
        .get("rules")
        .and_then(Json::as_array)
        .unwrap_or(&[])
        .iter()
        .enumerate()
    {
        match json_to_rule(rj) {
            Ok(r) => parsed.push(r),
            Err(e) => {
                return Response::json(
                    400,
                    &Json::Object(vec![(
                        "error".into(),
                        Json::str(format!("rule {}: {e}", i + 1)),
                    )])
                    .to_string(),
                )
            }
        }
    }
    let pdir = sync::policy_dir(config_file);
    if let Err(e) = rulefile::save_custom(&pdir, &file, &parsed) {
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

/// Parse the live on-disk rules file and annotate each line: rules not in the
/// regenerated baseline are strays (hand edits about to be lost), unparsable
/// lines are flagged for manual attention.
fn rules_live(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let file = req.query_param("file").unwrap_or_default();
    if !valid_managed(&file) {
        return Response::json(400, r#"{"error":"not a managed rules file"}"#);
    }
    let path = Path::new(&cfg.mailscanner_rules_dir).join(&file);
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let expected = sync::expected_rule_lines(config_file, &file);
    let mut rows = Vec::new();
    let mut strays = 0;
    let mut unparsed = 0;
    for line in rulefile::parse(&text) {
        match line {
            rulefile::Line::Blank => {}
            rulefile::Line::Comment(c) => rows.push(Json::Object(vec![
                ("kind".into(), Json::str("comment")),
                ("text".into(), Json::str(c)),
            ])),
            rulefile::Line::Unparsed(u) => {
                unparsed += 1;
                rows.push(Json::Object(vec![
                    ("kind".into(), Json::str("unparsed")),
                    ("text".into(), Json::str(u)),
                ]));
            }
            rulefile::Line::Rule(r) => {
                let stray = !expected.contains(&r.to_line());
                if stray {
                    strays += 1;
                }
                let mut o = match rule_to_json(&r) {
                    Json::Object(f) => f,
                    _ => vec![],
                };
                o.insert(0, ("kind".into(), Json::str("rule")));
                o.push(("stray".into(), Json::Bool(stray)));
                rows.push(Json::Object(o));
            }
        }
    }
    Response::json(
        200,
        &Json::Object(vec![
            ("file".into(), Json::str(&file)),
            ("path".into(), Json::str(path.display().to_string())),
            ("strays".into(), Json::Int(strays)),
            ("unparsed".into(), Json::Int(unparsed)),
            ("lines".into(), Json::Array(rows)),
        ])
        .to_string(),
    )
}

/// Rescue stray on-disk rules (hand edits, in any whitespace style) into the
/// custom store — normalized to canonical form — then resync. With a `file`
/// in the body, only that ruleset; without, all managed rulesets ("borrow all
/// current rules"). `default` rules are never adopted (they belong to policy).
fn rules_adopt(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    let file = v.str_field("file");
    if !file.is_empty() && !valid_managed(&file) {
        return Response::json(400, r#"{"error":"not a managed rules file"}"#);
    }
    let only = if file.is_empty() {
        None
    } else {
        Some(file.as_str())
    };
    let report = match sync::adopt_rules(cfg, config_file, None, only) {
        Ok(r) => r,
        Err(e) => return Response::json(500, &format!("{{\"error\":\"cannot save: {e}\"}}")),
    };
    if report.adopted > 0 {
        if let Err(e) = sync::run(cfg, config_file, None) {
            return Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}"));
        }
        sync::reload_mailscanner();
    }
    Response::json(
        200,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(true)),
            ("adopted".into(), Json::Int(report.adopted as i64)),
            (
                "skipped_defaults".into(),
                Json::Int(report.skipped_defaults as i64),
            ),
            ("unparsed".into(), Json::Int(report.unparsed as i64)),
            (
                "per_file".into(),
                Json::Array(
                    report
                        .per_file
                        .iter()
                        .map(|(f, n)| {
                            Json::Object(vec![
                                ("file".into(), Json::str(f)),
                                ("adopted".into(), Json::Int(*n as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
        .to_string(),
    )
}

// ---- service handlers --------------------------------------------------------

fn service_status(cfg: &Config) -> Response {
    let st = service::status();
    let (inc_dir, out_dir) = service::queue_dirs(cfg);
    Response::json(
        200,
        &Json::Object(vec![
            ("engine".into(), Json::Bool(service::engine_installed())),
            (
                "engine_configured".into(),
                Json::Bool(service::engine_configured()),
            ),
            (
                "engine_run_enabled".into(),
                service::engine_run_enabled()
                    .map(Json::Bool)
                    .unwrap_or(Json::Null),
            ),
            ("active".into(), Json::Bool(st.active)),
            ("procs".into(), Json::Int(st.procs as i64)),
            ("scanning".into(), Json::Bool(mailflow::scanning_enabled())),
            (
                "queues".into(),
                Json::Object(vec![
                    (
                        "incoming".into(),
                        Json::Int(service::count_queue(&inc_dir) as i64),
                    ),
                    (
                        "outgoing".into(),
                        Json::Int(service::count_queue(&out_dir) as i64),
                    ),
                ]),
            ),
            ("version".into(), Json::str(msfe_api::VERSION)),
        ])
        .to_string(),
    )
}

fn service_control(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    let action = v.str_field("action");
    let outcome = service::control(&action);
    let st = service::status();
    Response::json(
        200,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(outcome.ok)),
            ("action".into(), Json::str(&action)),
            ("active".into(), Json::Bool(st.active)),
            ("procs".into(), Json::Int(st.procs as i64)),
            (
                "transcript".into(),
                Json::Array(outcome.transcript.iter().map(Json::str).collect()),
            ),
        ])
        .to_string(),
    )
}

/// Enable/disable scanning via the exiscandisable mailflow flag.
fn service_mailflow(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    let enabled = matches!(v.get("enabled"), Some(Json::Bool(true)));
    match mailflow::set_scanning(enabled) {
        Ok(()) => Response::json(
            200,
            &format!(
                "{{\"ok\":true,\"scanning\":{}}}",
                mailflow::scanning_enabled()
            ),
        ),
        Err(e) => Response::json(500, &format!("{{\"error\":\"mailflow: {e}\"}}")),
    }
}

/// Regenerate rule files from policy (incl. end-user overrides) and reload.
fn service_sync(cfg: &Config, config_file: &Path) -> Response {
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

fn service_maillog(req: &Request, cfg: &Config) -> Response {
    let lines = stats::clamp_int(req.query_param("lines").as_deref(), 200, 10, 2000);
    match service::tail_file(Path::new(&cfg.maillog_path), lines as usize) {
        Ok(text) => Response::text(200, &text),
        Err(e) => Response::text(200, &format!("(cannot read {}: {e})", cfg.maillog_path)),
    }
}

fn service_queue(cfg: &Config) -> Response {
    let (inc_dir, out_dir) = service::queue_dirs(cfg);
    let orphans: Vec<Json> = [&inc_dir, &out_dir]
        .iter()
        .flat_map(|d| service::find_orphans(d, 600))
        .map(|p| Json::str(p.display().to_string()))
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            (
                "incoming_dir".into(),
                Json::str(inc_dir.display().to_string()),
            ),
            (
                "outgoing_dir".into(),
                Json::str(out_dir.display().to_string()),
            ),
            (
                "incoming".into(),
                Json::Int(service::count_queue(&inc_dir) as i64),
            ),
            (
                "outgoing".into(),
                Json::Int(service::count_queue(&out_dir) as i64),
            ),
            ("orphans".into(), Json::Array(orphans)),
        ])
        .to_string(),
    )
}

fn service_queue_fix(cfg: &Config) -> Response {
    match service::queue_fix(cfg) {
        Ok(r) => Response::json(
            200,
            &Json::Object(vec![
                ("ok".into(), Json::Bool(true)),
                ("moved".into(), Json::Int(r.moved as i64)),
                (
                    "badqueue_dir".into(),
                    Json::str(r.badqueue_dir.display().to_string()),
                ),
                ("flush_started".into(), Json::Bool(r.flush_started)),
            ])
            .to_string(),
        ),
        Err(e) => Response::json(500, &format!("{{\"error\":\"queue fix: {e}\"}}")),
    }
}

fn service_rules(cfg: &Config) -> Response {
    let items: Vec<Json> = service::list_rules(cfg)
        .into_iter()
        .map(|(name, size)| {
            Json::Object(vec![
                ("name".into(), Json::str(name)),
                ("size".into(), Json::Int(size as i64)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("dir".into(), Json::str(&cfg.mailscanner_rules_dir)),
            ("files".into(), Json::Array(items)),
        ])
        .to_string(),
    )
}

fn service_rules_view(req: &Request, cfg: &Config) -> Response {
    let name = req.query_param("name").unwrap_or_default();
    match service::read_rule(cfg, &name) {
        Ok(text) => Response::text(200, &text),
        Err(_) => Response::json(404, r#"{"error":"no such ruleset"}"#),
    }
}

/// Resolve the editable-file selector to a path. Only these two files are ever
/// exposed for editing.
fn conf_target(which: &str, cfg: &Config, config_file: &Path) -> Option<std::path::PathBuf> {
    match which {
        "mailscanner" => Some(cfg.mailscanner_conf.clone().into()),
        "msfe" => Some(config_file.to_path_buf()),
        _ => None,
    }
}

fn service_conf_read(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let which = req.query_param("which").unwrap_or_default();
    let Some(path) = conf_target(&which, cfg, config_file) else {
        return Response::json(400, r#"{"error":"which must be mailscanner|msfe"}"#);
    };
    match std::fs::read_to_string(&path) {
        Ok(text) => Response::json(
            200,
            &Json::Object(vec![
                ("path".into(), Json::str(path.display().to_string())),
                ("content".into(), Json::str(text)),
            ])
            .to_string(),
        ),
        Err(e) => Response::json(500, &format!("{{\"error\":\"cannot read: {e}\"}}")),
    }
}

fn service_conf_write(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
    };
    let which = v.str_field("which");
    let Some(path) = conf_target(&which, cfg, config_file) else {
        return Response::json(400, r#"{"error":"which must be mailscanner|msfe"}"#);
    };
    let Some(content) = v.get("content").and_then(Json::as_str) else {
        return Response::json(400, r#"{"error":"missing content"}"#);
    };
    match service::save_conf(&path, content) {
        Ok(()) => Response::json(200, r#"{"ok":true}"#),
        Err(e) => Response::json(500, &format!("{{\"error\":\"cannot save: {e}\"}}")),
    }
}

fn service_update() -> Response {
    let latest = service::latest_version();
    Response::json(
        200,
        &Json::Object(vec![
            ("current".into(), Json::str(msfe_api::VERSION)),
            ("latest".into(), latest.map(Json::Str).unwrap_or(Json::Null)),
        ])
        .to_string(),
    )
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
