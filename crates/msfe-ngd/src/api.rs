//! JSON API served over the Unix socket, consumed by the admin/user SPAs
//! (through the panel proxy shims). All handlers return a `Response`.

use crate::http::{Request, Response};
use msfe_core::json::Json;
use msfe_core::rules::DomainPolicy;
use msfe_core::{
    civil, confcatalog, confsave, logindex, mailflow, quarantine, rulefile, rules, service, stats,
    sync, users, Config,
};
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
        ("GET", "/api/stats/daily") => {
            let days = stats::clamp_int(req.query_param("days").as_deref(), 14, 1, 365);
            stat_response(stats::daily_summary(cfg, days))
        }
        ("GET", "/api/storage") => {
            let (settings, _, _) = sync::load_policy(&sync::policy_dir(config_file));
            let bodydays = msfe_core::housekeeping::body_retention_days(&settings);
            let mut obj = match stats::storage(cfg, bodydays) {
                Ok(Json::Object(f)) => f,
                _ => vec![("available".into(), Json::Bool(false))],
            };
            let archive_on = settings
                .iter()
                .find(|(k, _)| k == "archive")
                .map(|(_, v)| v != "no")
                .unwrap_or(true);
            obj.push(("archive_enabled".into(), Json::Bool(archive_on)));
            obj.push(("archive_dir".into(), Json::str(&cfg.archive_dir)));
            obj.push(("quarantine_dir".into(), Json::str(&cfg.quarantine_dir)));
            if let Some((total, avail)) = msfe_core::housekeeping::disk_free(&cfg.archive_dir) {
                obj.push(("disk_total".into(), Json::Int(total as i64)));
                obj.push(("disk_avail".into(), Json::Int(avail as i64)));
            }
            Response::json(200, &Json::Object(obj).to_string())
        }
        ("GET", "/api/sa/bayes") => {
            let rows: Vec<Json> = msfe_core::sa::bayes_status(cfg)
                .into_iter()
                .map(|(k, v)| {
                    Json::Object(vec![
                        ("key".into(), Json::str(k)),
                        ("value".into(), Json::str(v)),
                    ])
                })
                .collect();
            Response::json(
                200,
                &Json::Object(vec![("rows".into(), Json::Array(rows))]).to_string(),
            )
        }
        ("POST", "/api/sa/lint") => {
            let (ok, output) = msfe_core::sa::lint();
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(ok)),
                    ("output".into(), Json::str(output)),
                ])
                .to_string(),
            )
        }
        ("GET", "/api/messages") => {
            let f = stats::MessageFilter {
                status: req.query_param("status").unwrap_or_else(|| "all".into()),
                field: req.query_param("field").unwrap_or_else(|| "from".into()),
                text: req.query_param("text").unwrap_or_default(),
                days: stats::clamp_int(req.query_param("days").as_deref(), 0, 0, 3650) as u32,
                offset: stats::clamp_int(req.query_param("offset").as_deref(), 0, 0, 10_000_000)
                    as u32,
                limit: stats::clamp_int(req.query_param("limit").as_deref(), 50, 1, 500) as u32,
            };
            stat_response(stats::messages(cfg, &f))
        }
        ("GET", "/api/messages/detail") => {
            let id = req.query_param("id").unwrap_or_default();
            let mut detail = match stats::message_detail(cfg, &id) {
                Ok(d) => d,
                Err(_) => return Response::json(200, r#"{"available":false}"#),
            };
            if let Json::Object(fields) = &mut detail {
                // read everything we need before mutating `fields`
                let (report, headers, stored) = {
                    let get = |k: &str| {
                        fields
                            .iter()
                            .find(|(kk, _)| kk == k)
                            .and_then(|(_, v)| v.as_str())
                            .unwrap_or("")
                            .to_string()
                    };
                    (
                        format!("{} {}", get("spamreport"), get("report")),
                        get("headers"),
                        get("body_path"),
                    )
                };
                // spam-report component rows (rule / score / description)
                let comps: Vec<Json> = msfe_core::sa::parse_report(&report)
                    .iter()
                    .map(|c| {
                        Json::Object(vec![
                            ("rule".into(), Json::str(&c.rule)),
                            ("score".into(), Json::Num(format!("{:.2}", c.score))),
                            ("desc".into(), c.desc.map(Json::str).unwrap_or(Json::Null)),
                        ])
                    })
                    .collect();
                // header IP hops (no geolocation)
                let ips: Vec<Json> = msfe_core::sa::header_ips(&headers)
                    .iter()
                    .map(|h| {
                        Json::Object(vec![
                            ("ip".into(), Json::str(&h.ip)),
                            ("host".into(), Json::str(&h.host)),
                        ])
                    })
                    .collect();
                fields.push(("components".into(), Json::Array(comps)));
                fields.push(("header_ips".into(), Json::Array(ips)));
                // Body availability is decided by the filesystem, not by the
                // stored `quarantined` flag: after pruning the flag stays 1.
                let body = quarantine::resolve_body(cfg, &id, &stored);
                fields.push(("has_body".into(), Json::Bool(body.is_some())));
                if let Some(p) = &body {
                    fields.push(("body_kind".into(), Json::str(quarantine::body_kind(cfg, p))));
                    if let Ok(bytes) = quarantine::read_rfc822(p, &headers) {
                        let preview =
                            String::from_utf8_lossy(&bytes[..bytes.len().min(10240)]).into_owned();
                        fields.push(("content".into(), Json::str(preview)));
                    }
                }
                let (settings, _, _) = sync::load_policy(&sync::policy_dir(config_file));
                let archive_on = settings
                    .iter()
                    .find(|(k, _)| k == "archive")
                    .map(|(_, v)| v != "no")
                    .unwrap_or(true);
                fields.push(("archive_enabled".into(), Json::Bool(archive_on)));
                fields.push((
                    "bodydays".into(),
                    Json::Int(msfe_core::housekeeping::body_retention_days(&settings) as i64),
                ));
            }
            Response::json(200, &detail.to_string())
        }
        // ---- sender: history + current list membership -----------------------
        ("GET", "/api/sender/info") => {
            let addr = req.query_param("addr").unwrap_or_default();
            let addr_l = addr.trim().to_lowercase();
            let domain = addr_l.rsplit_once('@').map(|(_, d)| d.to_string());
            let days = stats::clamp_int(req.query_param("days").as_deref(), 30, 0, 3650) as u32;
            let activity = stats::sender_activity(cfg, &addr_l, days)
                .unwrap_or(Json::Object(vec![("available".into(), Json::Bool(false))]));
            let domain_activity = domain
                .as_ref()
                .and_then(|d| stats::sender_activity(cfg, &format!("@{d}"), days).ok())
                .unwrap_or(Json::Object(vec![("available".into(), Json::Bool(false))]));
            // membership in the global lists (the Lists tab's data)
            let (_, wl, bl) = sync::load_policy(&sync::policy_dir(config_file));
            let listed = |list: &[String], pat: &str| list.iter().any(|e| e.trim() == pat);
            let dom_pat = domain
                .as_ref()
                .map(|d| format!("*@{d}"))
                .unwrap_or_default();
            Response::json(
                200,
                &Json::Object(vec![
                    ("addr".into(), Json::str(&addr_l)),
                    (
                        "domain".into(),
                        domain.clone().map(Json::Str).unwrap_or(Json::Null),
                    ),
                    ("activity".into(), activity),
                    ("domain_activity".into(), domain_activity),
                    ("addr_blacklisted".into(), Json::Bool(listed(&bl, &addr_l))),
                    ("addr_whitelisted".into(), Json::Bool(listed(&wl, &addr_l))),
                    (
                        "domain_blacklisted".into(),
                        Json::Bool(!dom_pat.is_empty() && listed(&bl, &dom_pat)),
                    ),
                    (
                        "domain_whitelisted".into(),
                        Json::Bool(!dom_pat.is_empty() && listed(&wl, &dom_pat)),
                    ),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/sender/list") => sender_list(req, cfg, config_file),

        // ---- client IP: intel + firewall (csf) ------------------------------
        ("GET", "/api/ip/geo") => {
            let ip = msfe_core::csf::normalize_ip(&req.query_param("ip").unwrap_or_default());
            let rows: Vec<Json> = msfe_core::geoip::lookup(cfg, config_file, &ip)
                .into_iter()
                .map(|(k, v)| {
                    Json::Object(vec![
                        ("key".into(), Json::str(k)),
                        ("value".into(), Json::str(v)),
                    ])
                })
                .collect();
            Response::json(
                200,
                &Json::Object(vec![
                    ("ip".into(), Json::str(&ip)),
                    (
                        "enabled".into(),
                        Json::Bool(!cfg.geoip_url.trim().is_empty()),
                    ),
                    ("rows".into(), Json::Array(rows)),
                ])
                .to_string(),
            )
        }
        ("GET", "/api/ip/info") => {
            let ip = msfe_core::csf::normalize_ip(&req.query_param("ip").unwrap_or_default());
            let days = stats::clamp_int(req.query_param("days").as_deref(), 30, 0, 3650) as u32;
            let activity = stats::ip_activity(cfg, &ip, days)
                .unwrap_or(Json::Object(vec![("available".into(), Json::Bool(false))]));
            Response::json(
                200,
                &Json::Object(vec![
                    ("ip".into(), Json::str(&ip)),
                    ("rdns".into(), Json::str(msfe_core::csf::reverse_dns(&ip))),
                    ("activity".into(), activity),
                    (
                        "csf_available".into(),
                        Json::Bool(msfe_core::csf::available()),
                    ),
                    ("csf".into(), Json::str(msfe_core::csf::lookup(&ip))),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/ip/ban") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let target = msfe_core::csf::normalize_ip(&v.str_field("target"));
            let comment = v.str_field("comment");
            let force = matches!(v.get("force"), Some(Json::Bool(true)));
            let restart = matches!(v.get("restart"), Some(Json::Bool(true)));
            let hours = match v.get("hours") {
                Some(Json::Int(h)) if *h > 0 => Some(*h as u32),
                _ => None,
            };
            let o = msfe_core::csf::ban(&target, &comment, hours, restart, force);
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/ip/unban") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let o = msfe_core::csf::unban(&msfe_core::csf::normalize_ip(&v.str_field("target")));
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        ("GET", "/api/messages/raw") => {
            let id = req.query_param("id").unwrap_or_default();
            if !service::valid_exim_id(&id) {
                return Response::text(200, "bad message id");
            }
            match read_full_message(cfg, &id) {
                Some(bytes) => Response::text(200, &String::from_utf8_lossy(&bytes)),
                // 404, so the caller never renders this text as the message
                None => Response::text(404, "the message body is no longer available"),
            }
        }
        // MIME-decoded HTML fragment for the "rendered" preview: the browser
        // wraps it in a no-network CSP document, so inline images come as data:
        // URIs and the plain-text fallback is pre-escaped.
        ("GET", "/api/messages/preview") => {
            let id = req.query_param("id").unwrap_or_default();
            if !service::valid_exim_id(&id) {
                return Response::text(200, "bad message id");
            }
            match read_full_message(cfg, &id) {
                Some(bytes) => Response::html(200, &msfe_core::mime::preview(&bytes).html),
                None => Response::text(404, "the message body is no longer available"),
            }
        }
        ("POST", "/api/messages/learn") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let id = v.str_field("id");
            let action = v.str_field("action");
            if !service::valid_exim_id(&id) {
                return Response::json(400, r#"{"error":"bad message id"}"#);
            }
            let Some(bytes) = body_of(cfg, &id).and_then(|p| quarantine::read_message(&p).ok())
            else {
                return Response::json(
                    404,
                    r#"{"error":"Bayes training needs the message body, which is no longer available (see the body retention setting)"}"#,
                );
            };
            let o = msfe_core::sa::learn(cfg, &bytes, &action);
            // reflect the correction in the database when enabled
            if o.ok && cfg.learn_updates_db {
                match action.as_str() {
                    "spam" | "report" => {
                        let _ = stats::reclassify(cfg, &id, true);
                    }
                    "ham" => {
                        let _ = stats::reclassify(cfg, &id, false);
                    }
                    _ => {}
                }
            }
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/messages/release-bulk") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let to = v.str_field("to");
            let ids: Vec<String> = v
                .get("ids")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|j| j.as_str().map(str::to_string))
                        .take(200)
                        .collect()
                })
                .unwrap_or_default();
            if ids.is_empty() {
                return Response::json(400, r#"{"error":"no messages selected"}"#);
            }
            if !to.is_empty() && !quarantine::valid_recipient(&to) {
                return Response::json(400, r#"{"error":"invalid forward recipient"}"#);
            }
            let mut released = 0usize;
            let mut results = Vec::new();
            for id in &ids {
                let outcome = if !service::valid_exim_id(id) {
                    "invalid id".to_string()
                } else {
                    match read_full_message(cfg, id) {
                        None => "body no longer available (past the retention window)".into(),
                        Some(bytes) => {
                            let r = quarantine::send_message(
                                &bytes,
                                if to.is_empty() {
                                    None
                                } else {
                                    Some(to.as_str())
                                },
                            );
                            match r {
                                Ok(()) => {
                                    released += 1;
                                    "released".into()
                                }
                                Err(e) => format!("failed: {e}"),
                            }
                        }
                    }
                };
                results.push(Json::Object(vec![
                    ("id".into(), Json::str(id)),
                    ("result".into(), Json::str(outcome)),
                ]));
            }
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(released > 0)),
                    ("released".into(), Json::Int(released as i64)),
                    ("total".into(), Json::Int(ids.len() as i64)),
                    ("results".into(), Json::Array(results)),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/messages/release") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let id = v.str_field("id");
            let to = v.str_field("to");
            // mode: "resend" (default) | "forward" | "inbox"
            let mode = v.str_field("mode");
            if !service::valid_exim_id(&id) {
                return Response::json(400, r#"{"error":"bad message id"}"#);
            }
            let Some(bytes) = read_full_message(cfg, &id) else {
                return Response::json(
                    404,
                    r#"{"error":"the message body is no longer available, so it cannot be re-sent"}"#,
                );
            };
            let result = match mode.as_str() {
                "inbox" => quarantine::deliver_inbox(&bytes, &cfg.dovecot_lda, &to),
                "forward" => {
                    let msg = quarantine::rewrite_for_forward(
                        &bytes,
                        &cfg.forward_subject,
                        &cfg.release_from,
                        &cfg.forward_body,
                    );
                    quarantine::send_message(&msg, Some(&to))
                }
                _ => quarantine::send_message(
                    &bytes,
                    if to.is_empty() {
                        None
                    } else {
                        Some(to.as_str())
                    },
                ),
            };
            match result {
                Ok(()) => Response::json(200, r#"{"ok":true}"#),
                Err(e) => Response::json(500, &format!("{{\"error\":\"release failed: {e}\"}}")),
            }
        }
        ("POST", "/api/messages/spamcop") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let id = v.str_field("id");
            if !service::valid_exim_id(&id) {
                return Response::json(400, r#"{"error":"bad message id"}"#);
            }
            if cfg.spamcop_address.trim().is_empty() {
                return Response::json(
                    400,
                    r#"{"error":"no SpamCop address configured (Settings → Interface & release)"}"#,
                );
            }
            let Some(bytes) = read_full_message(cfg, &id) else {
                return Response::json(
                    404,
                    r#"{"error":"the message body is no longer available"}"#,
                );
            };
            match quarantine::send_message(&bytes, Some(cfg.spamcop_address.trim())) {
                Ok(()) => Response::json(200, r#"{"ok":true}"#),
                Err(e) => Response::json(500, &format!("{{\"error\":\"report failed: {e}\"}}")),
            }
        }

        // ---- database maintenance (root-only admin surface) ----------------
        ("POST", "/api/db/backup") => match msfe_core::dbtools::backup(cfg) {
            Ok(path) => Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(true)),
                    ("path".into(), Json::str(path.display().to_string())),
                ])
                .to_string(),
            ),
            Err(e) => Response::json(500, &format!("{{\"error\":\"backup failed: {e}\"}}")),
        },
        ("POST", "/api/db/fix") => {
            let r = msfe_core::dbtools::fix(cfg, &migrations_dir());
            let log: Vec<Json> = r.log.iter().map(Json::str).collect();
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(r.ok)),
                    ("log".into(), Json::Array(log)),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/db/bayes-repair") => outcome_json(msfe_core::sa::bayes_repair(cfg)),
        ("POST", "/api/db/bayes-reset") => {
            // destructive: snapshot the SQL side first (Bayes lives outside the
            // DB, but a backup gives a recovery point for the whole operation)
            let backup = msfe_core::dbtools::backup(cfg)
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let mut out = msfe_core::sa::bayes_reset(cfg);
            if !backup.is_empty() {
                out.transcript
                    .insert(0, format!("backed up database to {backup}"));
            }
            outcome_json(out)
        }

        ("POST", "/api/engine/spam-checks-all") => {
            let mut transcript = Vec::new();
            let mut ok = true;
            match msfe_core::engine::enable_spam_checks_all(cfg) {
                Ok((changed, prev)) => {
                    if changed {
                        transcript
                            .push(format!("MailScanner.conf: Spam Checks = yes (was: {prev})"));
                        transcript.push("restarting MailScanner to apply…".into());
                        let r = service::control("restart");
                        ok = r.ok;
                        transcript.extend(r.transcript);
                    } else {
                        transcript.push(
                            "Spam Checks is already 'yes' — every domain is scanned; no restart needed."
                                .into(),
                        );
                    }
                }
                Err(e) => {
                    ok = false;
                    transcript.push(format!("could not update MailScanner.conf: {e}"));
                }
            }
            outcome_json(service::ControlOutcome { ok, transcript })
        }

        // ---- MailScanner service operations (root-only admin surface) -------
        ("GET", "/api/service/status") => service_status(cfg),
        ("POST", "/api/service/control") => service_control(req),
        ("POST", "/api/service/mailflow") => service_mailflow(req),
        ("POST", "/api/service/cpanel-spamassassin") => service_cpanel_sa(req),
        ("POST", "/api/service/engine-latch") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let enabled = matches!(v.get("enabled"), Some(Json::Bool(true)));
            match service::set_engine_run(cfg, enabled) {
                Ok(()) => Response::json(
                    200,
                    &Json::Object(vec![
                        ("ok".into(), Json::Bool(true)),
                        (
                            "run_enabled".into(),
                            service::engine_run_enabled(cfg)
                                .map(Json::Bool)
                                .unwrap_or(Json::Null),
                        ),
                    ])
                    .to_string(),
                ),
                Err(e) => Response::json(
                    500,
                    &format!("{{\"error\":\"cannot update defaults: {e}\"}}"),
                ),
            }
        }
        ("POST", "/api/service/engine-wire") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let enable = !matches!(v.get("enable"), Some(Json::Bool(false)));
            let dry = matches!(v.get("dry_run"), Some(Json::Bool(true)));
            let result = if enable {
                msfe_core::engine::wire(cfg, dry)
            } else {
                msfe_core::engine::unwire(cfg, dry)
            };
            match result {
                Ok(r) => Response::json(
                    200,
                    &Json::Object(vec![
                        ("ok".into(), Json::Bool(true)),
                        ("dry_run".into(), Json::Bool(r.dry_run)),
                        (
                            "actions".into(),
                            Json::Array(r.actions.iter().map(Json::str).collect()),
                        ),
                        ("wired".into(), Json::Bool(msfe_core::engine::is_wired(cfg))),
                    ])
                    .to_string(),
                ),
                Err(e) => Response::json(500, &format!("{{\"error\":\"wiring: {e}\"}}")),
            }
        }
        ("GET", "/api/service/conf/parsed") => conf_parsed(req, cfg, config_file),
        ("POST", "/api/service/conf/apply") => conf_apply(req, cfg, config_file),
        ("POST", "/api/service/engine-configure") => match msfe_core::engine::configure(cfg) {
            Ok(r) => {
                let arr = |v: &[String]| Json::Array(v.iter().map(Json::str).collect());
                Response::json(
                    200,
                    &Json::Object(vec![
                        ("ok".into(), Json::Bool(true)),
                        ("set".into(), arr(&r.set)),
                        ("created".into(), arr(&r.created)),
                        ("chown_failed".into(), arr(&r.chown_failed)),
                        ("restarted".into(), Json::Bool(r.restarted)),
                        ("repaired".into(), arr(&r.repaired)),
                        ("warnings".into(), arr(&r.warnings)),
                    ])
                    .to_string(),
                )
            }
            Err(e) => Response::json(500, &format!("{{\"error\":\"configure: {e}\"}}")),
        },
        ("POST", "/api/doctor/fix") => {
            let done = msfe_core::doctor::fix(cfg, config_file);
            let checks = msfe_core::doctor::run(cfg, config_file);
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(true)),
                    (
                        "done".into(),
                        Json::Array(done.iter().map(Json::str).collect()),
                    ),
                    (
                        "healthy".into(),
                        Json::Bool(msfe_core::doctor::healthy(&checks)),
                    ),
                ])
                .to_string(),
            )
        }
        ("GET", "/api/doctor") => {
            let checks = msfe_core::doctor::run(cfg, config_file);
            let items: Vec<Json> = checks
                .iter()
                .map(|c| {
                    Json::Object(vec![
                        ("name".into(), Json::str(c.name)),
                        ("level".into(), Json::str(c.level.as_str())),
                        ("detail".into(), Json::str(&c.detail)),
                        (
                            "fix".into(),
                            c.fix.clone().map(Json::Str).unwrap_or(Json::Null),
                        ),
                    ])
                })
                .collect();
            Response::json(
                200,
                &Json::Object(vec![
                    (
                        "healthy".into(),
                        Json::Bool(msfe_core::doctor::healthy(&checks)),
                    ),
                    ("checks".into(), Json::Array(items)),
                ])
                .to_string(),
            )
        }
        // ---- first-run setup (dashboard) ------------------------------------
        ("GET", "/api/setup") => {
            let s = msfe_core::setup::status(cfg);
            Response::json(
                200,
                &Json::Object(vec![
                    ("db_configured".into(), Json::Bool(s.db_configured)),
                    ("db_ready".into(), Json::Bool(s.db_ready)),
                    ("logging_enabled".into(), Json::Bool(s.logging_enabled)),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/setup/db") => match msfe_core::setup::setup_database(cfg, config_file) {
            Ok(log) => Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(true)),
                    (
                        "log".into(),
                        Json::Array(log.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            ),
            Err(e) => Response::json(
                500,
                &Json::Object(vec![("error".into(), Json::str(e.to_string()))]).to_string(),
            ),
        },
        ("POST", "/api/setup/logging") => match msfe_core::setup::enable_logging(cfg) {
            Ok(log) => Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(true)),
                    (
                        "log".into(),
                        Json::Array(log.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            ),
            Err(e) => Response::json(
                500,
                &Json::Object(vec![("error".into(), Json::str(e.to_string()))]).to_string(),
            ),
        },
        ("POST", "/api/service/lint") => {
            let r = service::lint(cfg);
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(r.ok)),
                    ("output".into(), Json::str(r.output)),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/service/sync") => service_sync(cfg, config_file),
        ("GET", "/api/service/maillog") => service_maillog(req, cfg),
        ("GET", "/api/service/maillog/days") => service_maillog_days(req, cfg),
        ("GET", "/api/service/maillog/search") => service_maillog_search(req, cfg),
        ("GET", "/api/service/maillog/window") => service_maillog_window(req, cfg),
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
        ("GET", "/api/service/queue/listing") => {
            let named = match req.query_param("which").as_deref() {
                Some("main") => None,
                _ => Some("mailscanner"),
            };
            Response::text(200, &service::queue_listing(named))
        }
        ("GET", "/api/service/queue/msg") => {
            let named = match req.query_param("which").as_deref() {
                Some("main") => None,
                _ => Some("mailscanner"),
            };
            let id = req.query_param("id").unwrap_or_default();
            let what = req.query_param("what").unwrap_or_else(|| "headers".into());
            Response::text(200, &service::queue_msg_view(cfg, named, &id, &what))
        }
        // Structured queue listing parsed from the spool -H files: sender,
        // recipients, subject, spam score, frozen state per message.
        ("GET", "/api/service/queue/detail") => {
            let (inq, outq) = service::queue_dirs(cfg);
            let dir = match req.query_param("which").as_deref() {
                Some("main") => outq,
                _ => inq,
            };
            let limit =
                stats::clamp_int(req.query_param("limit").as_deref(), 500, 1, 2000) as usize;
            let l = msfe_core::queueview::list_queue(&dir, limit);
            let msgs: Vec<Json> = l
                .msgs
                .iter()
                .map(|m| {
                    Json::Object(vec![
                        ("id".into(), Json::str(&m.id)),
                        ("age_secs".into(), Json::Int(m.age_secs as i64)),
                        ("size".into(), Json::Int(m.size as i64)),
                        ("sender".into(), Json::str(&m.sender)),
                        ("bounce".into(), Json::Bool(m.bounce)),
                        (
                            "recipients".into(),
                            Json::Array(m.recipients.iter().map(Json::str).collect()),
                        ),
                        ("subject".into(), Json::str(&m.subject)),
                        (
                            "spam_score".into(),
                            m.spam_score
                                .map(|s| Json::Num(format!("{s:.1}")))
                                .unwrap_or(Json::Null),
                        ),
                        ("frozen".into(), Json::Bool(m.frozen)),
                        ("parsed".into(), Json::Bool(m.parsed)),
                    ])
                })
                .collect();
            Response::json(
                200,
                &Json::Object(vec![
                    ("total".into(), Json::Int(l.total as i64)),
                    ("truncated".into(), Json::Bool(l.truncated)),
                    ("msgs".into(), Json::Array(msgs)),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/service/queue/action") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let named = match v.str_field("which").as_str() {
                "main" => None,
                _ => Some("mailscanner"),
            };
            let o = service::queue_msg_action(named, &v.str_field("id"), &v.str_field("action"));
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        ("POST", "/api/service/queue/bulk") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let named = match v.str_field("which").as_str() {
                "main" => None,
                _ => Some("mailscanner"),
            };
            let ids: Vec<String> = v
                .get("ids")
                .and_then(|j| match j {
                    Json::Array(a) => Some(
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default();
            let dry = matches!(v.get("dry"), Some(Json::Bool(true)));
            let o = service::queue_bulk_action(named, &ids, &v.str_field("action"), dry);
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    ("count".into(), Json::Int(ids.len() as i64)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        // Criteria-based cleanup of the DELIVERY queue (frozen/bounce/high-spam
        // per the queue_clean_* config; optional per-request overrides for the
        // preview). The scanning queue is deliberately out of reach here.
        ("POST", "/api/service/queue/clean") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let dry = matches!(v.get("dry"), Some(Json::Bool(true)));
            let num = |k: &str| -> Option<f64> {
                v.get(k).and_then(|j| match j {
                    Json::Int(n) => Some(*n as f64),
                    Json::Num(s) => s.parse().ok(),
                    _ => None,
                })
            };
            let mut criteria = msfe_core::queueview::CleanCriteria::from_config(cfg);
            // overrides let the UI preview thresholds before saving them
            if let Some(h) = num("frozen_hours") {
                criteria.frozen_older_hours = if h > 0.0 { Some(h as u32) } else { None };
            }
            if let Some(h) = num("bounce_hours") {
                criteria.bounce_older_hours = if h > 0.0 { Some(h as u32) } else { None };
            }
            if let Some(s) = num("spam_score") {
                criteria.spam_score_min = if s > 0.0 { Some(s) } else { None };
            }
            if !criteria.any_enabled() {
                return Response::json(
                    200,
                    r#"{"ok":true,"count":0,"transcript":["no cleanup rule is enabled — set a threshold first"]}"#,
                );
            }
            let (_, out_dir) = service::queue_dirs(cfg);
            let listing = msfe_core::queueview::list_queue(&out_dir, 100_000);
            let ids = msfe_core::queueview::select_removals(&listing.msgs, &criteria);
            let o = service::queue_bulk_action(None, &ids, "delete", dry);
            Response::json(
                200,
                &Json::Object(vec![
                    ("ok".into(), Json::Bool(o.ok)),
                    ("count".into(), Json::Int(ids.len() as i64)),
                    ("dry".into(), Json::Bool(dry)),
                    (
                        "transcript".into(),
                        Json::Array(o.transcript.iter().map(Json::str).collect()),
                    ),
                ])
                .to_string(),
            )
        }
        // ---- admin quarantine browser + purge (disk is the source of truth) --
        ("GET", "/api/quarantine") => {
            let limit =
                stats::clamp_int(req.query_param("limit").as_deref(), 1000, 1, 5000) as usize;
            quarantine_listing(cfg, limit)
        }
        ("GET", "/api/quarantine/message") => {
            let date = req.query_param("date").unwrap_or_default();
            let id = req.query_param("id").unwrap_or_default();
            Response::text(200, &quarantine_preview(cfg, &date, &id))
        }
        ("POST", "/api/quarantine/purge") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let dry = matches!(v.get("dry"), Some(Json::Bool(true)));
            let items: Vec<(String, String)> = v
                .get("items")
                .and_then(|j| match j {
                    Json::Array(a) => Some(
                        a.iter()
                            .map(|it| (it.str_field("date"), it.str_field("id")))
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default();
            let r = quarantine::purge_items(Path::new(&cfg.quarantine_dir), &items, dry);
            purge_json(r, dry)
        }
        ("POST", "/api/quarantine/purge-older") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let dry = matches!(v.get("dry"), Some(Json::Bool(true)));
            let days = v
                .get("days")
                .and_then(|j| match j {
                    Json::Int(n) => Some(*n),
                    Json::Num(s) => s.parse().ok(),
                    _ => None,
                })
                .filter(|d| (1..=3650).contains(d));
            let Some(days) = days else {
                return Response::json(400, r#"{"error":"days must be 1-3650"}"#);
            };
            let Some(cutoff) = quarantine::cutoff_days_ago(days as u32) else {
                return Response::json(500, r#"{"error":"cannot compute cutoff date"}"#);
            };
            let r = quarantine::purge_older_than(Path::new(&cfg.quarantine_dir), &cutoff, dry);
            purge_json(r, dry)
        }
        ("POST", "/api/telegram/test") => {
            let mut transcript = Vec::new();
            let ok = match msfe_core::telegram::send(
                cfg,
                "✅ MSFE-NG test message — Telegram alerts are working.",
            ) {
                Ok(()) => {
                    transcript.push("test message sent — check your Telegram chat".into());
                    true
                }
                Err(e) => {
                    transcript.push(e);
                    false
                }
            };
            outcome_json(service::ControlOutcome { ok, transcript })
        }
        ("POST", "/api/service/queue/fix") => service_queue_fix(cfg),
        ("POST", "/api/service/queue/repair-spool") => {
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let dry = matches!(v.get("dry_run"), Some(Json::Bool(true)));
            let (_, outq) = service::queue_dirs(cfg);
            match service::repair_spool(&outq, dry) {
                Ok(r) => Response::json(
                    200,
                    &Json::Object(vec![
                        ("ok".into(), Json::Bool(true)),
                        ("dry_run".into(), Json::Bool(r.dry_run)),
                        ("moved".into(), Json::Int(r.moved as i64)),
                        ("flush_started".into(), Json::Bool(r.flush_started)),
                        (
                            "actions".into(),
                            Json::Array(r.actions.iter().map(Json::str).collect()),
                        ),
                    ])
                    .to_string(),
                ),
                Err(e) => Response::json(500, &format!("{{\"error\":\"spool repair: {e}\"}}")),
            }
        }
        ("GET", "/api/service/rules") => service_rules(cfg),
        ("GET", "/api/service/rules/view") => service_rules_view(req, cfg),
        ("GET", "/api/service/conf") => service_conf_read(req, cfg, config_file),
        ("PUT", "/api/service/conf") => service_conf_write(req, cfg, config_file),
        ("GET", "/api/service/update") => service_update(cfg),
        (m, p) if p.starts_with("/api/jobs/") => {
            jobs_route(m, &p["/api/jobs/".len()..], req, cfg, config_file)
        }
        (m, p) if p.starts_with("/api/conf/") => {
            crate::conf_api::handle(m, p, req, cfg, config_file)
        }
        ("GET", "/api/engine/migrate") => engine_migrate_preflight(cfg, config_file),
        ("GET", "/api/resolver") => resolver_state(),

        // ---- structured rule management (root-only admin surface) -----------
        ("GET", "/api/rules/files") => rules_files(config_file),
        ("GET", "/api/rules/custom") => rules_custom_get(req, config_file),
        ("PUT", "/api/rules/custom") => rules_custom_put(req, cfg, config_file),
        ("GET", "/api/rules/live") => rules_live(req, cfg, config_file),
        ("POST", "/api/rules/adopt") => rules_adopt(req, cfg, config_file),

        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

/// A pattern accepted into the white/black lists: `user@domain` or `*@domain`.
/// Rejects whitespace and anything that could break the TAB-separated rule
/// files these end up in.
fn valid_list_pattern(p: &str) -> bool {
    let p = p.trim();
    !p.is_empty()
        && p.len() <= 254
        && p.contains('@')
        && !p.contains(char::is_whitespace)
        && p.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'@' | b'.' | b'_' | b'-' | b'+' | b'*')
        })
}

/// Add or remove a sender pattern from the global white/black lists, then
/// regenerate the rules — the same path the Lists tab uses, so one code path
/// owns list changes.
fn sender_list(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
    };
    let pattern = v.str_field("pattern").trim().to_lowercase();
    let list = v.str_field("list"); // "black" | "white"
    let remove = matches!(v.get("remove"), Some(Json::Bool(true)));
    if !valid_list_pattern(&pattern) {
        return Response::json(
            400,
            r#"{"error":"pattern must be an address or *@domain, without spaces"}"#,
        );
    }
    if list != "black" && list != "white" {
        return Response::json(400, r#"{"error":"list must be black or white"}"#);
    }
    let pdir = sync::policy_dir(config_file);
    let (settings, mut wl, mut bl) = sync::load_policy(&pdir);
    let target = if list == "black" { &mut bl } else { &mut wl };
    let existed = target
        .iter()
        .any(|e| e.trim().eq_ignore_ascii_case(&pattern));
    if remove {
        target.retain(|e| !e.trim().eq_ignore_ascii_case(&pattern));
    } else if !existed {
        target.push(pattern.clone());
    }
    if let Err(e) = sync::save_policy(&pdir, &settings, &wl, &bl) {
        return Response::json(500, &format!("{{\"error\":\"cannot save lists: {e}\"}}"));
    }
    match sync::run(cfg, config_file, None) {
        Ok(r) => {
            let reloaded = r.changed > 0 && sync::reload_mailscanner();
            Response::json(
                200,
                &format!(
                    "{{\"ok\":true,\"pattern\":\"{pattern}\",\"list\":\"{list}\",\"removed\":{remove},\"files\":{},\"changed\":{},\"reloaded\":{reloaded}}}",
                    r.files, r.changed
                ),
            )
        }
        Err(e) => Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}")),
    }
}

/// Resolve a message body: the path MailScanner recorded, else the legacy scan.
/// Single source of truth for every body-dependent endpoint.
fn body_of(cfg: &Config, id: &str) -> Option<std::path::PathBuf> {
    let (stored, _) = stats::body_ref_of(cfg, id).unwrap_or_default();
    quarantine::resolve_body(cfg, id, &stored)
}

/// Resolve the body and read it as a complete RFC822 message (headers + body),
/// reconstructing from the logged headers when the store is an Exim `-D` file.
fn read_full_message(cfg: &Config, id: &str) -> Option<Vec<u8>> {
    let (stored, headers) = stats::body_ref_of(cfg, id).unwrap_or_default();
    let p = quarantine::resolve_body(cfg, id, &stored)?;
    quarantine::read_rfc822(&p, &headers).ok()
}

// ---- structured rule handlers ------------------------------------------------

pub(crate) fn rule_to_json(r: &rulefile::Rule) -> Json {
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

pub(crate) fn json_to_rule(v: &Json) -> Result<rulefile::Rule, String> {
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
        Ok(r) => {
            let reloaded = r.changed > 0 && sync::reload_mailscanner();
            Response::json(
                200,
                &format!(
                    "{{\"ok\":true,\"files\":{},\"changed\":{},\"reloaded\":{reloaded}}}",
                    r.files, r.changed
                ),
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
        match sync::run(cfg, config_file, None) {
            Ok(r) => {
                if r.changed > 0 {
                    sync::reload_mailscanner();
                }
            }
            Err(e) => return Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}")),
        }
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

// ---- admin quarantine handlers ------------------------------------------------

/// Disk listing of the quarantine, enriched from `maillog` where a row
/// exists. Ids are inlined into the IN clause only when their charset is
/// SQL-safe (they are filesystem names, not trusted input).
fn quarantine_listing(cfg: &Config, limit: usize) -> Response {
    let l = quarantine::list_quarantine(Path::new(&cfg.quarantine_dir), limit);
    let sql_safe = |id: &str| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'%'))
    };
    let quoted: Vec<String> = l
        .entries
        .iter()
        .filter(|e| sql_safe(&e.id))
        .map(|e| format!("'{}'", e.id))
        .collect();
    let mut info: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    if !quoted.is_empty() {
        if let Ok(rows) = msfe_core::db::query(
            cfg,
            &format!(
                "SELECT message_id, from_address, to_address, subject, sascore \
                 FROM maillog WHERE message_id IN ({})",
                quoted.join(",")
            ),
        ) {
            for r in rows {
                if r.len() >= 5 {
                    info.insert(r[0].clone(), r[1..].to_vec());
                }
            }
        }
    }
    let entries: Vec<Json> = l
        .entries
        .iter()
        .map(|e| {
            let mut o = vec![
                ("date".into(), Json::str(&e.date)),
                ("id".into(), Json::str(&e.id)),
                ("kind".into(), Json::str(e.kind)),
                ("size".into(), Json::Int(e.size as i64)),
                ("mtime".into(), Json::Int(e.mtime as i64)),
            ];
            if let Some(m) = info.get(&e.id) {
                o.push(("from".into(), Json::str(&m[0])));
                o.push(("to".into(), Json::str(&m[1])));
                o.push(("subject".into(), Json::str(&m[2])));
                o.push(("sascore".into(), Json::str(&m[3])));
            }
            Json::Object(o)
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("total".into(), Json::Int(l.total as i64)),
            ("bytes".into(), Json::Int(l.bytes as i64)),
            ("truncated".into(), Json::Bool(l.truncated)),
            ("entries".into(), Json::Array(entries)),
        ])
        .to_string(),
    )
}

/// Headers preview for a quarantine item without a DB row: the message's
/// header block, size-capped, via the same validated resolver purge uses.
fn quarantine_preview(cfg: &Config, date: &str, id: &str) -> String {
    let Some(path) = quarantine::item_path(Path::new(&cfg.quarantine_dir), date, id) else {
        return "not found".into();
    };
    // a held message is a directory: prefer its `message` file
    let file = if path.is_dir() {
        let named = path.join("message");
        if named.exists() {
            named
        } else {
            match std::fs::read_dir(&path)
                .ok()
                .and_then(|mut rd| rd.next())
                .and_then(|e| e.ok())
            {
                Some(e) => e.path(),
                None => return "(empty)".into(),
            }
        }
    } else {
        path
    };
    match quarantine::read_message(&file) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes[..bytes.len().min(16 * 1024)]).into_owned();
            let headers: String = text
                .lines()
                .take_while(|l| !l.trim().is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            if headers.is_empty() {
                "(no headers)".into()
            } else {
                headers
            }
        }
        Err(e) => format!("cannot read message: {e}"),
    }
}

fn purge_json(r: msfe_core::quarantine::PurgeReport, dry: bool) -> Response {
    Response::json(
        200,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(r.errors.is_empty())),
            ("dry".into(), Json::Bool(dry)),
            ("removed".into(), Json::Int(r.removed as i64)),
            ("bytes".into(), Json::Int(r.bytes as i64)),
            (
                "errors".into(),
                Json::Array(r.errors.iter().map(Json::str).collect()),
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
            ("engine".into(), Json::Bool(service::engine_installed(cfg))),
            (
                "engine_configured".into(),
                Json::Bool(service::engine_configured(cfg)),
            ),
            (
                "engine_run_enabled".into(),
                service::engine_run_enabled(cfg)
                    .map(Json::Bool)
                    .unwrap_or(Json::Null),
            ),
            ("wired".into(), Json::Bool(msfe_core::engine::is_wired(cfg))),
            ("active".into(), Json::Bool(st.active)),
            ("procs".into(), Json::Int(st.procs as i64)),
            ("scanning".into(), Json::Bool(mailflow::scanning_enabled())),
            (
                "cpanel_sa".into(),
                if cfg.panel == "cpanel" {
                    let s = mailflow::cpanel_sa_state();
                    Json::Object(vec![
                        ("forced_on".into(), Json::Bool(s.forced_on)),
                        ("accounts_on".into(), Json::Int(s.accounts_on.len() as i64)),
                        ("restorable".into(), Json::Int(s.restorable.len() as i64)),
                        ("would_scan".into(), Json::Bool(s.would_scan())),
                    ])
                } else {
                    Json::Null
                },
            ),
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

/// cPanel's Apache SpamAssassin: off for every account (`enabled:false`) or
/// back on for the accounts that were turned off here (`enabled:true`).
fn service_cpanel_sa(req: &Request) -> Response {
    let v = Json::parse(&req.body).unwrap_or(Json::Null);
    let enabled = matches!(v.get("enabled"), Some(Json::Bool(true)));
    match mailflow::set_cpanel_sa(enabled) {
        Ok(changed) => Response::json(
            200,
            &Json::Object(vec![
                ("ok".into(), Json::Bool(true)),
                ("changed".into(), Json::Int(changed.len() as i64)),
                (
                    "would_scan".into(),
                    Json::Bool(mailflow::cpanel_sa_state().would_scan()),
                ),
            ])
            .to_string(),
        ),
        Err(e) => Response::json(500, &format!("{{\"error\":\"cPanel SpamAssassin: {e}\"}}")),
    }
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
        Ok(r) => {
            // reload = restart for the LSB service; skip it when the ruleset
            // on disk already matches (the 10-minute sync cron hits this path)
            let reloaded = r.changed > 0 && sync::reload_mailscanner();
            Response::json(
                200,
                &format!(
                    "{{\"ok\":true,\"files\":{},\"changed\":{},\"reloaded\":{reloaded}}}",
                    r.files, r.changed
                ),
            )
        }
        Err(e) => Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}")),
    }
}

/// Which log the `which=` query parameter selects.
fn log_path<'a>(req: &Request, cfg: &'a Config) -> &'a str {
    match req.query_param("which").as_deref() {
        Some("exim") => &cfg.exim_mainlog_path,
        _ => &cfg.maillog_path,
    }
}

fn service_maillog(req: &Request, cfg: &Config) -> Response {
    let lines = stats::clamp_int(req.query_param("lines").as_deref(), 200, 10, 2000);
    let path = log_path(req, cfg);
    match service::tail_file(Path::new(path), lines as usize) {
        Ok(text) => Response::text(200, &text),
        Err(e) => Response::text(200, &format!("(cannot read {path}: {e})")),
    }
}

/// Longest search pattern accepted by `/api/service/maillog/search`.
const MAX_SEARCH_PATTERN: usize = 200;
/// Most hits returned per search (the newest survive).
const MAX_SEARCH_HITS: usize = 5000;

fn cannot_read(path: &str, e: std::io::Error) -> Response {
    Response::json(
        200,
        &Json::Object(vec![(
            "error".into(),
            Json::str(format!("cannot read {path}: {e}")),
        )])
        .to_string(),
    )
}

fn bad_request(msg: &str) -> Response {
    Response::json(
        400,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

/// The log set (live file + rotated siblings) `which=` selects, indexed by day.
fn log_index(req: &Request, cfg: &Config) -> Result<logindex::LogIndex, Response> {
    let path = log_path(req, cfg);
    // A missing live log is an error, not an empty set of rotated files.
    std::fs::metadata(path).map_err(|e| cannot_read(path, e))?;
    logindex::index(Path::new(path)).map_err(|e| cannot_read(path, e))
}

/// `GET /api/service/maillog/days[?which=exim]` — the days present across the
/// live log and its rotated siblings, each with the file and offset where it
/// begins, plus the files themselves.
fn service_maillog_days(req: &Request, cfg: &Config) -> Response {
    let idx = match log_index(req, cfg) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let days = idx
        .days()
        .into_iter()
        .map(|(date, span)| {
            Json::Object(vec![
                ("date".into(), Json::str(date.to_string())),
                ("file".into(), Json::str(&span.file)),
                ("start".into(), Json::Int(span.start as i64)),
            ])
        })
        .collect();
    let files = idx
        .files
        .iter()
        .map(|f| {
            Json::Object(vec![
                ("name".into(), Json::str(&f.name)),
                ("gz".into(), Json::Bool(f.gz)),
                ("size".into(), Json::Int(f.len as i64)),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("days".into(), Json::Array(days)),
            ("files".into(), Json::Array(files)),
        ])
        .to_string(),
    )
}

/// `GET /api/service/maillog/search?q=text[&day=YYYY-MM-DD][&which=exim]` —
/// every line containing `q` (case-insensitive) across the whole log set,
/// oldest file first, or only within `day`. Hits are `[file, offset]`.
fn service_maillog_search(req: &Request, cfg: &Config) -> Response {
    let q = req.query_param("q").unwrap_or_default();
    let q = q.trim();
    if q.is_empty() || q.len() > MAX_SEARCH_PATTERN {
        return bad_request(&format!(
            "pattern must be 1 to {MAX_SEARCH_PATTERN} characters"
        ));
    }
    let day = match req.query_param("day").filter(|d| !d.is_empty()) {
        None => None,
        Some(d) => match civil::Date::parse(&d) {
            Some(date) => Some(date),
            None => return bad_request("day must be YYYY-MM-DD"),
        },
    };
    let idx = match log_index(req, cfg) {
        Ok(i) => i,
        Err(r) => return r,
    };
    match service::search_logs(&idx, q, day, MAX_SEARCH_HITS) {
        Ok(r) => Response::json(
            200,
            &Json::Object(vec![
                ("total".into(), Json::Int(r.total as i64)),
                ("truncated".into(), Json::Bool(r.truncated)),
                (
                    "hits".into(),
                    Json::Array(
                        r.hits
                            .iter()
                            .map(|h| Json::Array(vec![Json::str(&h.file), Json::Int(h.off as i64)]))
                            .collect(),
                    ),
                ),
            ])
            .to_string(),
        ),
        Err(e) => cannot_read(log_path(req, cfg), e),
    }
}

/// `GET /api/service/maillog/window?at=offset[&file=name&before=N&after=N&which=exim]`
/// — the lines around the line starting at byte `at` of `file` (default: the
/// live log). `file` must be a name from the index, never a path.
fn service_maillog_window(req: &Request, cfg: &Config) -> Response {
    let at: u64 = req
        .query_param("at")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let before = stats::clamp_int(req.query_param("before").as_deref(), 200, 0, 1000);
    let after = stats::clamp_int(req.query_param("after").as_deref(), 200, 0, 1000);
    let idx = match log_index(req, cfg) {
        Ok(i) => i,
        Err(r) => return r,
    };
    let live = Path::new(log_path(req, cfg))
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    let name = req.query_param("file").unwrap_or(live);
    let Some(file) = idx.file(&name) else {
        return bad_request("unknown log file");
    };
    let plain = match logindex::plain_path(file, &logindex::cache_dir()) {
        Ok(p) => p,
        Err(e) => return cannot_read(&file.name, e),
    };
    match service::window_file(&plain, at, before as usize, after as usize) {
        Ok(w) => Response::json(
            200,
            &Json::Object(vec![
                ("file".into(), Json::str(&file.name)),
                ("text".into(), Json::str(w.text)),
                ("anchor".into(), Json::Int(w.anchor as i64)),
                ("start".into(), Json::Int(w.start as i64)),
                ("end".into(), Json::Int(w.end as i64)),
            ])
            .to_string(),
        ),
        Err(e) => cannot_read(&file.name, e),
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
            (
                "oldest_incoming_secs".into(),
                service::oldest_queue_age(&inc_dir)
                    .map(|a| Json::Int(a as i64))
                    .unwrap_or(Json::Null),
            ),
            (
                "oldest_outgoing_secs".into(),
                service::oldest_queue_age(&out_dir)
                    .map(|a| Json::Int(a as i64))
                    .unwrap_or(Json::Null),
            ),
            // last auto-clean run summary: {"at":epoch,"removed":n}
            (
                "clean_last".into(),
                msfe_core::db::kv_get(cfg, "queueclean_last")
                    .and_then(|v| Json::parse(&v).ok())
                    .unwrap_or(Json::Null),
            ),
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

/// Parsed view of an editable conf file for the visual editor: ordered lines,
/// comments preserved, entries addressable by key.
fn conf_parsed(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let which = req.query_param("which").unwrap_or_default();
    let Some(path) = conf_target(&which, cfg, config_file) else {
        return Response::json(400, r#"{"error":"which must be mailscanner|msfe"}"#);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return Response::json(500, &format!("{{\"error\":\"cannot read: {e}\"}}")),
    };
    use msfe_core::conffile::{parse, ConfLine};
    let lines: Vec<Json> = parse(&text)
        .into_iter()
        .map(|l| match l {
            ConfLine::Blank => Json::Object(vec![("t".into(), Json::str("blank"))]),
            ConfLine::Comment(c) => Json::Object(vec![
                ("t".into(), Json::str("comment")),
                ("text".into(), Json::str(c)),
            ]),
            ConfLine::Other(o) => Json::Object(vec![
                ("t".into(), Json::str("other")),
                ("text".into(), Json::str(o)),
            ]),
            ConfLine::Entry { key, value } => Json::Object(vec![
                ("t".into(), Json::str("entry")),
                ("key".into(), Json::str(key)),
                ("value".into(), Json::str(value)),
            ]),
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            ("path".into(), Json::str(path.display().to_string())),
            ("which".into(), Json::str(&which)),
            ("lines".into(), Json::Array(lines)),
        ])
        .to_string(),
    )
}

/// Apply key→value changes from the visual editor onto the original file text
/// (comments and untouched lines survive byte-for-byte), with backup.
fn conf_apply(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match Json::parse(&req.body) {
        Ok(v) => v,
        Err(e) => return Response::json(400, &format!("{{\"error\":\"bad json: {e}\"}}")),
    };
    let which = v.str_field("which");
    let Some(path) = conf_target(&which, cfg, config_file) else {
        return Response::json(400, r#"{"error":"which must be mailscanner|msfe"}"#);
    };
    let changes: Vec<(String, String)> = match v.get("changes") {
        Some(Json::Object(f)) => f
            .iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect(),
        _ => Vec::new(),
    };
    if changes.is_empty() {
        return Response::json(200, r#"{"ok":true,"applied":0}"#);
    }
    let Some(entry) = confcatalog::resolve(cfg, config_file, &conf_id(&which)) else {
        return Response::json(404, r#"{"error":"file not found"}"#);
    };
    let _ = path;
    let text = std::fs::read_to_string(&entry.path).unwrap_or_default();
    let Some(new_text) = confsave::render_changes(&entry, &text, &changes) else {
        return Response::json(400, r#"{"error":"not a key/value file"}"#);
    };
    let applied = changes.len();
    match confsave::save(
        cfg,
        confsave::SaveRequest {
            entry: &entry,
            new_text,
            lint: lint_mode(v.get("lint")),
            reload: reload_mode(v.get("reload")),
            reason: "save",
            expect_mtime: v
                .get("expect_mtime")
                .and_then(Json::as_i64)
                .map(|m| m as u64),
        },
    ) {
        Ok(r) => {
            let mut obj = save_report_json(&r);
            obj.insert(1, ("applied".into(), Json::Int(applied as i64)));
            Response::json(200, &Json::Object(obj).to_string())
        }
        Err(e) => Response::json(500, &format!("{{\"error\":\"cannot save: {e}\"}}")),
    }
}

pub(crate) fn strs(v: &[String]) -> Json {
    Json::Array(v.iter().map(Json::str).collect())
}

/// The catalog id behind the legacy `which` selector.
fn conf_id(which: &str) -> String {
    match which {
        "msfe" => "msfe:config.toml".into(),
        _ => "ms:MailScanner.conf".into(),
    }
}

pub(crate) fn lint_mode(v: Option<&Json>) -> confsave::LintMode {
    match v.and_then(Json::as_str) {
        Some("skip") => confsave::LintMode::Skip,
        _ => confsave::LintMode::Auto,
    }
}

pub(crate) fn reload_mode(v: Option<&Json>) -> confsave::ReloadMode {
    match v.and_then(Json::as_str) {
        Some("skip") => confsave::ReloadMode::Skip,
        _ => confsave::ReloadMode::Auto,
    }
}

/// A `SaveReport` as the fields every save-like route answers with.
pub(crate) fn save_report_json(r: &confsave::SaveReport) -> Vec<(String, Json)> {
    let validation = match &r.validation {
        Some(v) => Json::Object(vec![
            ("tool".into(), Json::str(v.tool)),
            ("ok".into(), Json::Bool(v.ok)),
            ("timed_out".into(), Json::Bool(v.timed_out)),
            ("output".into(), Json::str(&v.output)),
            ("problems".into(), strs(&v.problems)),
        ]),
        None => Json::Null,
    };
    vec![
        ("ok".into(), Json::Bool(r.error.is_none())),
        ("changed".into(), Json::Bool(r.changed)),
        (
            "backup_id".into(),
            r.backup_id.clone().map(Json::Str).unwrap_or(Json::Null),
        ),
        ("validation".into(), validation),
        (
            "reloaded".into(),
            Json::Object(vec![
                ("action".into(), Json::str(r.reloaded.action)),
                ("ok".into(), Json::Bool(r.reloaded.ok)),
                ("transcript".into(), strs(&r.reloaded.transcript)),
            ]),
        ),
        ("rolled_back".into(), Json::Bool(r.rolled_back)),
        (
            "error".into(),
            r.error.clone().map(Json::Str).unwrap_or(Json::Null),
        ),
    ]
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
    let Some(entry) = confcatalog::resolve(cfg, config_file, &conf_id(&which)) else {
        return Response::json(404, r#"{"error":"file not found"}"#);
    };
    let _ = path;
    match confsave::save(
        cfg,
        confsave::SaveRequest {
            entry: &entry,
            new_text: content.to_string(),
            lint: lint_mode(v.get("lint")),
            reload: reload_mode(v.get("reload")),
            reason: "save",
            expect_mtime: v
                .get("expect_mtime")
                .and_then(Json::as_i64)
                .map(|m| m as u64),
        },
    ) {
        Ok(r) => Response::json(200, &Json::Object(save_report_json(&r)).to_string()),
        Err(e) => Response::json(500, &format!("{{\"error\":\"cannot save: {e}\"}}")),
    }
}

fn service_update(cfg: &Config) -> Response {
    let latest = service::latest_version();
    let upgradable = latest
        .as_deref()
        .is_some_and(|l| service::version_newer(l, msfe_api::VERSION));
    let e = msfe_core::upgrade::engine_update(cfg);
    let opt = |v: Option<String>| v.map(Json::Str).unwrap_or(Json::Null);
    Response::json(
        200,
        &Json::Object(vec![
            ("current".into(), Json::str(msfe_api::VERSION)),
            ("latest".into(), opt(latest)),
            ("upgradable".into(), Json::Bool(upgradable)),
            (
                "engine".into(),
                Json::Object(vec![
                    ("version".into(), opt(e.version)),
                    ("latest".into(), opt(e.latest)),
                    ("rpm".into(), Json::Bool(e.rpm)),
                    ("upgradable".into(), Json::Bool(e.upgradable)),
                ]),
            ),
        ])
        .to_string(),
    )
}

/// The DNS resolver situation (Service tab card).
fn resolver_state() -> Response {
    let s = msfe_core::resolver::state();
    let strs = |v: &[String]| Json::Array(v.iter().map(Json::str).collect());
    Response::json(
        200,
        &Json::Object(vec![
            ("nameservers".into(), strs(&s.nameservers)),
            ("on_loopback".into(), Json::Bool(s.on_loopback)),
            ("unbound_installed".into(), Json::Bool(s.unbound_installed)),
            ("unbound_active".into(), Json::Bool(s.unbound_active)),
            (
                "unbound_answers".into(),
                s.unbound_answers.map(Json::Bool).unwrap_or(Json::Null),
            ),
            ("port53".into(), strs(&s.port53)),
            ("public_v4".into(), strs(&s.public_v4)),
            ("public_v6".into(), strs(&s.public_v6)),
            ("manager".into(), Json::str(&s.manager)),
            ("done".into(), Json::Bool(s.done())),
            ("ok".into(), Json::Bool(s.ok())),
            ("blockers".into(), strs(&s.blockers)),
            ("notes".into(), strs(&s.notes)),
        ])
        .to_string(),
    )
}

/// What the ConfigServer → RPM migration would do on this host.
fn engine_migrate_preflight(cfg: &Config, config_file: &Path) -> Response {
    let pf = msfe_core::engine_migration::preflight(cfg, config_file);
    let strs = |v: &[String]| Json::Array(v.iter().map(Json::str).collect());
    Response::json(
        200,
        &Json::Object(vec![
            ("legacy_engine".into(), Json::Bool(pf.legacy_engine)),
            ("engine".into(), Json::str(&pf.engine)),
            ("uninstaller".into(), Json::Bool(pf.uninstaller)),
            ("remnants".into(), strs(&pf.remnants)),
            ("policy_imported".into(), Json::Bool(pf.policy_imported)),
            ("db_configured".into(), Json::Bool(pf.db_configured)),
            ("queue_incoming".into(), Json::Int(pf.queue_incoming as i64)),
            (
                "wiring".into(),
                pf.wiring.clone().map(Json::Str).unwrap_or(Json::Null),
            ),
            ("ok".into(), Json::Bool(pf.ok())),
            ("blockers".into(), strs(&pf.blockers)),
            ("warnings".into(), strs(&pf.warnings)),
        ])
        .to_string(),
    )
}

/// Background jobs (`msfe_core::jobs`): GET status + log tail, POST start.
/// Only the named upgrade jobs exist; a job is never a command from the API.
fn jobs_route(
    method: &str,
    name: &str,
    req: &Request,
    cfg: &Config,
    config_file: &Path,
) -> Response {
    use msfe_core::{engine_migration, jobs, msgtest, resolver, upgrade};
    if name != upgrade::SELF_JOB
        && name != upgrade::ENGINE_JOB
        && name != engine_migration::JOB
        && name != resolver::JOB
        && name != msgtest::JOB
        && name != msgtest::SELFTEST_JOB
    {
        return Response::json(404, r#"{"error":"no such job"}"#);
    }
    match method {
        "GET" => {
            let s = jobs::status(name);
            Response::json(
                200,
                &Json::Object(vec![
                    ("name".into(), Json::str(name)),
                    ("known".into(), Json::Bool(s.known)),
                    ("running".into(), Json::Bool(s.running)),
                    (
                        "exit".into(),
                        s.exit.map(|c| Json::Int(c as i64)).unwrap_or(Json::Null),
                    ),
                    ("log".into(), Json::str(&s.log_tail)),
                    (
                        "log_path".into(),
                        Json::Str(
                            jobs::dir()
                                .join(format!("{name}.log"))
                                .display()
                                .to_string(),
                        ),
                    ),
                ])
                .to_string(),
            )
        }
        "POST" => {
            if jobs::status(name).running {
                return Response::json(409, r#"{"error":"already running"}"#);
            }
            let v = Json::parse(&req.body).unwrap_or(Json::Null);
            let res = if name == upgrade::SELF_JOB {
                upgrade::start_self(v.get("version").and_then(Json::as_str))
            } else if name == msgtest::JOB {
                crate::conf_api::start_message_test(cfg, &v)
            } else if name == msgtest::SELFTEST_JOB {
                msgtest::start_selftest()
            } else if name == resolver::JOB {
                let s = resolver::state();
                match s.blockers.first() {
                    Some(b) => Err(std::io::Error::other(b.clone())),
                    None => resolver::start_job(),
                }
            } else if name == engine_migration::JOB {
                let pf = engine_migration::preflight(cfg, config_file);
                match pf.blockers.first() {
                    Some(b) => Err(std::io::Error::other(b.clone())),
                    None => engine_migration::start_job(),
                }
            } else {
                let e = upgrade::engine_update(cfg);
                match (e.upgradable, e.latest) {
                    (true, Some(latest)) => upgrade::start_engine(&latest),
                    _ => Err(std::io::Error::other(
                        "the engine is not upgradable in place (not the RPM engine, or no newer release)",
                    )),
                }
            };
            match res {
                Ok(()) => Response::json(200, r#"{"ok":true}"#),
                Err(e) => Response::json(500, &format!("{{\"error\":\"{e}\"}}")),
            }
        }
        _ => Response::json(405, r#"{"error":"method not allowed"}"#),
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
        Ok(r) => {
            let reloaded = r.changed > 0 && sync::reload_mailscanner();
            Response::json(
                200,
                &format!(
                    "{{\"ok\":true,\"files\":{},\"changed\":{},\"reloaded\":{reloaded}}}",
                    r.files, r.changed
                ),
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

/// Render a `ControlOutcome` (ok flag + transcript lines) as JSON — the shape the
/// SPA's action-output panels expect from learn / service / db endpoints.
fn outcome_json(o: msfe_core::service::ControlOutcome) -> Response {
    Response::json(
        200,
        &Json::Object(vec![
            ("ok".into(), Json::Bool(o.ok)),
            (
                "transcript".into(),
                Json::Array(o.transcript.iter().map(Json::str).collect()),
            ),
        ])
        .to_string(),
    )
}

/// The migrations directory the daemon applies from (env override, else the
/// packaged default), mirroring the CLI's resolution.
fn migrations_dir() -> std::path::PathBuf {
    std::env::var("MSFE_NG_MIGRATIONS")
        .unwrap_or_else(|_| msfe_api::DEFAULT_MIGRATIONS_DIR.to_string())
        .into()
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
                            ("archive".into(), opt(&ov.archive)),
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
                            ("archive".into(), Json::str(g("archive", "yes"))),
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
            ov.archive = field("archive");
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
            match read_full_message(cfg, &id) {
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
            match read_full_message(cfg, &id) {
                Some(bytes) => match quarantine::send_message(&bytes, None) {
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
        Ok(r) => {
            let reloaded = r.changed > 0 && sync::reload_mailscanner();
            Response::json(
                200,
                &format!(
                    "{{\"ok\":true,\"files\":{},\"changed\":{},\"reloaded\":{reloaded}}}",
                    r.files, r.changed
                ),
            )
        }
        Err(e) => Response::json(500, &format!("{{\"error\":\"sync failed: {e}\"}}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(path: &str, query: &str) -> Request {
        Request {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            body: String::new(),
            user: String::new(),
        }
    }

    /// Serialise a response and split it into (status, body).
    fn send(r: Response) -> (u16, String) {
        let mut out = Vec::new();
        r.write(&mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        let (_, body) = s.split_once("\r\n\r\n").unwrap();
        (r.status, body.to_string())
    }

    fn log_fixture(name: &str, body: &str) -> (std::path::PathBuf, Config) {
        let d = std::env::temp_dir().join(format!("msfe-api-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("maillog");
        std::fs::write(&f, body).unwrap();
        let cfg = Config {
            maillog_path: f.display().to_string(),
            exim_mainlog_path: d.join("missing").display().to_string(),
            ..Default::default()
        };
        (d, cfg)
    }

    #[test]
    fn jobs_api_knows_only_the_upgrade_jobs() {
        let d = std::env::temp_dir().join(format!("msfe-api-jobs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::env::set_var("MSFE_NG_JOBS_DIR", &d);
        let cfg = Config::default();
        let (st, _) = send(handle(&get("/api/jobs/rm-rf", ""), &cfg, &d));
        assert_eq!(st, 404);
        let (st, body) = send(handle(&get("/api/jobs/upgrade", ""), &cfg, &d));
        assert_eq!(st, 200);
        assert!(
            body.contains(r#""known":false"#) && body.contains(r#""running":false"#),
            "{body}"
        );
        assert!(body.contains(r#""exit":null"#), "{body}");
        std::env::remove_var("MSFE_NG_JOBS_DIR");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn maillog_search_returns_offsets_json() {
        let (d, cfg) = log_fixture("search", "alpha\nBETA one\ngamma\nbeta two\n");
        let (st, body) = send(handle(
            &get("/api/service/maillog/search", "q=beta"),
            &cfg,
            &d,
        ));
        assert_eq!(st, 200);
        assert_eq!(
            body,
            r#"{"total":2,"truncated":false,"hits":[["maillog",6],["maillog",21]]}"#
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn rotated_fixture(name: &str) -> (std::path::PathBuf, Config) {
        let (d, cfg) = log_fixture(
            name,
            "Sep 13 04:00:00 h hit c\nSep 14 10:00:00 h miss\nSep 14 11:00:00 h hit d\n",
        );
        let old = d.join("maillog-20260913");
        std::fs::write(&old, "Sep 12 10:00:00 h hit a\nSep 13 01:00:00 h hit b\n").unwrap();
        let t = std::time::SystemTime::now() - std::time::Duration::from_secs(5 * 86_400);
        std::fs::File::open(&old).unwrap().set_modified(t).unwrap();
        (d, cfg)
    }

    #[test]
    fn maillog_days_lists_each_date_with_where_it_starts() {
        let (d, cfg) = rotated_fixture("days");
        let (st, body) = send(handle(&get("/api/service/maillog/days", ""), &cfg, &d));
        assert_eq!(st, 200);
        assert_eq!(
            body,
            r#"{"days":[{"date":"2026-09-12","file":"maillog-20260913","start":0},{"date":"2026-09-13","file":"maillog-20260913","start":24},{"date":"2026-09-14","file":"maillog","start":24}],"files":[{"name":"maillog-20260913","gz":false,"size":48},{"name":"maillog","gz":false,"size":71}]}"#
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn maillog_search_spans_rotated_files_and_takes_a_day() {
        let (d, cfg) = rotated_fixture("searchday");
        let (_, body) = send(handle(
            &get("/api/service/maillog/search", "q=hit"),
            &cfg,
            &d,
        ));
        assert_eq!(
            body,
            r#"{"total":4,"truncated":false,"hits":[["maillog-20260913",0],["maillog-20260913",24],["maillog",0],["maillog",47]]}"#
        );
        let (_, body) = send(handle(
            &get("/api/service/maillog/search", "q=hit&day=2026-09-13"),
            &cfg,
            &d,
        ));
        assert_eq!(
            body,
            r#"{"total":2,"truncated":false,"hits":[["maillog-20260913",24],["maillog",0]]}"#
        );
        let (st, _) = send(handle(
            &get("/api/service/maillog/search", "q=hit&day=13/09/2026"),
            &cfg,
            &d,
        ));
        assert_eq!(st, 400);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn maillog_window_takes_a_file_name_from_the_index_only() {
        let (d, cfg) = rotated_fixture("windowfile");
        let (st, body) = send(handle(
            &get(
                "/api/service/maillog/window",
                "file=maillog-20260913&at=24&before=1&after=0",
            ),
            &cfg,
            &d,
        ));
        assert_eq!(st, 200);
        assert_eq!(
            body,
            r#"{"file":"maillog-20260913","text":"Sep 12 10:00:00 h hit a\nSep 13 01:00:00 h hit b","anchor":1,"start":0,"end":48}"#
        );
        // defaults to the live file
        let (_, body) = send(handle(
            &get("/api/service/maillog/window", "at=0&before=0&after=0"),
            &cfg,
            &d,
        ));
        assert!(
            body.starts_with(r#"{"file":"maillog","text":"Sep 13 04:00:00 h hit c""#),
            "{body}"
        );
        for bad in [
            "file=../../etc/passwd&at=0",
            "file=maillog-19990101&at=0",
            "file=/etc/passwd&at=0",
        ] {
            let (st, _) = send(handle(&get("/api/service/maillog/window", bad), &cfg, &d));
            assert_eq!(st, 400, "{bad}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn maillog_search_rejects_an_empty_or_huge_pattern() {
        let (d, cfg) = log_fixture("searchbad", "x\n");
        for q in ["", "q=", "q=%20%20", &format!("q={}", "a".repeat(201))] {
            let (st, body) = send(handle(&get("/api/service/maillog/search", q), &cfg, &d));
            assert_eq!(st, 400, "{q}");
            assert!(body.contains("error"), "{body}");
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn maillog_search_reports_unreadable_files() {
        let (d, cfg) = log_fixture("searchmissing", "x\n");
        let (st, body) = send(handle(
            &get("/api/service/maillog/search", "q=x&which=exim"),
            &cfg,
            &d,
        ));
        assert_eq!(st, 200);
        assert!(body.starts_with(r#"{"error":"cannot read"#), "{body}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn maillog_window_returns_lines_around_the_offset() {
        let (d, cfg) = log_fixture("window", "l0\nl1\nl2\nl3\nl4\n");
        let (st, body) = send(handle(
            &get("/api/service/maillog/window", "at=6&before=1&after=1"),
            &cfg,
            &d,
        ));
        assert_eq!(st, 200);
        assert_eq!(
            body,
            r#"{"file":"maillog","text":"l1\nl2\nl3","anchor":1,"start":3,"end":12}"#
        );
        std::fs::remove_dir_all(&d).unwrap();
    }
}
