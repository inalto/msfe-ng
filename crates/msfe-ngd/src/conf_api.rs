//! `/api/conf/*`: the Config tab's file tree, per-file read (raw text plus the
//! kind's parsed view), saves through `confsave`, new files, and history.
//!
//! A file is only ever named by its catalog id; the parsed views and the
//! row→text rendering are the server's so every save — key/value changes,
//! table rows or raw text — ends as one `new_text` through the same pipeline.

use crate::api::{json_to_rule, lint_mode, reload_mode, rule_to_json, save_report_json, strs};
use crate::http::{Request, Response};
use msfe_core::confcatalog::{self, Entry, Kind, Root};
use msfe_core::json::Json;
use msfe_core::msgrammar::{self, Line, Table};
use msfe_core::{conffile, confsave, rulefile, service, Config};
use std::path::Path;

pub fn handle(
    method: &str,
    path: &str,
    req: &Request,
    cfg: &Config,
    config_file: &Path,
) -> Response {
    match (method, path) {
        ("GET", "/api/conf/tree") => tree(cfg, config_file),
        ("GET", "/api/conf/file") => file(req, cfg, config_file),
        ("PUT", "/api/conf/file") => save(req, cfg, config_file),
        ("POST", "/api/conf/create") => create(req, cfg, config_file),
        ("GET", "/api/conf/history") => history(req, cfg, config_file),
        ("GET", "/api/conf/history/view") => history_view(req, cfg, config_file),
        ("POST", "/api/conf/restore") => restore(req, cfg, config_file),
        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

fn body(req: &Request) -> Result<Json, Response> {
    Json::parse(&req.body).map_err(|e| err(400, &format!("bad json: {e}")))
}

fn entry_json(e: &Entry) -> Vec<(String, Json)> {
    vec![
        ("id".into(), Json::str(&e.id)),
        ("root".into(), Json::str(e.root.prefix())),
        ("rel".into(), Json::str(&e.rel)),
        ("path".into(), Json::str(e.path.display().to_string())),
        ("kind".into(), Json::str(e.kind.as_str())),
        ("reload".into(), Json::str(e.reload.as_str())),
        ("validator".into(), Json::str(e.validator.as_str())),
        ("editable".into(), Json::Bool(e.kind.editable())),
        (
            "readonly_reason".into(),
            match e.kind {
                Kind::ReadOnly(r) => Json::str(r.as_str()),
                _ => Json::Null,
            },
        ),
        ("size".into(), Json::Int(e.size as i64)),
        ("mtime".into(), Json::Int(e.mtime as i64)),
        (
            "symlink".into(),
            e.symlink_target
                .as_ref()
                .map(|p| Json::str(p.display().to_string()))
                .unwrap_or(Json::Null),
        ),
    ]
}

fn tree(cfg: &Config, config_file: &Path) -> Response {
    let cat = confcatalog::scan(cfg, config_file);
    let pending = confcatalog::pending_restart(&cat.entries, service::active_since());
    Response::json(
        200,
        &Json::Object(vec![
            (
                "roots".into(),
                Json::Array(vec![
                    Json::Object(vec![
                        ("id".into(), Json::str("ms")),
                        ("path".into(), Json::str(cat.ms_etc.display().to_string())),
                        ("label".into(), Json::str("MailScanner")),
                    ]),
                    Json::Object(vec![
                        ("id".into(), Json::str("msfe")),
                        ("path".into(), Json::str(cat.msfe_dir.display().to_string())),
                        ("label".into(), Json::str("MSFE-NG")),
                    ]),
                ]),
            ),
            (
                "files".into(),
                Json::Array(
                    cat.entries
                        .iter()
                        .map(|e| Json::Object(entry_json(e)))
                        .collect(),
                ),
            ),
            ("pending_restart".into(), strs(&pending)),
        ])
        .to_string(),
    )
}

fn line_obj(line: usize, fields: Vec<(String, Json)>) -> Json {
    let mut f = vec![("line".into(), Json::Int(line as i64))];
    f.extend(fields);
    Json::Object(f)
}

fn unparsed_json<T>(t: &Table<T>) -> Json {
    Json::Array(
        t.unparsed()
            .into_iter()
            .map(|(n, s)| line_obj(n, vec![("text".into(), Json::str(s))]))
            .collect(),
    )
}

fn rows_json<T>(t: &Table<T>, f: impl Fn(&T) -> Vec<(String, Json)>) -> Json {
    Json::Array(
        t.lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match l {
                Line::Row(r) => Some(line_obj(i + 1, f(r))),
                _ => None,
            })
            .collect(),
    )
}

fn table_json<T>(t: &Table<T>, f: impl Fn(&T) -> Vec<(String, Json)>) -> Json {
    Json::Object(vec![
        ("rows".into(), rows_json(t, f)),
        ("unparsed".into(), unparsed_json(t)),
        ("normalized".into(), Json::Bool(t.normalized)),
    ])
}

/// A ruleset file as a `msgrammar` table so the shared rebuild applies.
fn rule_table(text: &str) -> Table<rulefile::Rule> {
    Table {
        lines: text
            .lines()
            .map(|l| match rulefile::parse_line(l) {
                rulefile::Line::Blank => Line::Blank,
                rulefile::Line::Comment(c) => Line::Comment(c),
                rulefile::Line::Rule(r) => Line::Row(r),
                rulefile::Line::Unparsed(u) => Line::Unparsed(u),
            })
            .collect(),
        normalized: false,
    }
}

fn s(k: &str, v: &str) -> (String, Json) {
    (k.into(), Json::str(v))
}

/// The kind-specific structured view of a file, or `Null` for raw-only kinds.
fn parsed_json(kind: Kind, text: &str) -> Json {
    match kind {
        Kind::KeyValue(_) => Json::Array(
            conffile::parse(text)
                .into_iter()
                .map(|l| match l {
                    conffile::ConfLine::Blank => Json::Object(vec![s("t", "blank")]),
                    conffile::ConfLine::Comment(c) => {
                        Json::Object(vec![s("t", "comment"), s("text", &c)])
                    }
                    conffile::ConfLine::Other(o) => {
                        Json::Object(vec![s("t", "other"), s("text", &o)])
                    }
                    conffile::ConfLine::Entry { key, value } => {
                        Json::Object(vec![s("t", "entry"), s("key", &key), s("value", &value)])
                    }
                })
                .collect(),
        ),
        Kind::RuleTable => table_json(&rule_table(text), |r| match rule_to_json(r) {
            Json::Object(f) => f,
            _ => Vec::new(),
        }),
        Kind::FilenameRules => table_json(&msgrammar::parse_filename_rules(text), |r| {
            vec![
                s("action", &r.action.as_string()),
                s("pattern", &r.pattern),
                s("log_text", &r.log_text),
                s("user_text", &r.user_text),
            ]
        }),
        Kind::SpamLists => table_json(&msgrammar::parse_spam_lists(text), |r| {
            vec![s("name", &r.name), s("domain", &r.domain)]
        }),
        Kind::VirusScanners => table_json(&msgrammar::parse_virus_scanners(text), |r| {
            vec![
                s("name", &r.name),
                s("wrapper", &r.wrapper),
                s("dir", &r.dir),
            ]
        }),
        Kind::HostList => table_json(&msgrammar::parse_host_list(text), |h| vec![s("host", h)]),
        Kind::PlainText | Kind::ReadOnly(_) => Json::Null,
    }
}

/// Per-key typing from the engine's ConfigDefs.pl for the keys present in
/// `text`: `{key: {type, default, ruleset, options}}`; `Null` without a
/// readable schema (the editor then stays untyped).
fn schema_json(cfg: &Config, text: &str) -> Json {
    let lay = msfe_core::layout::resolve(cfg);
    let Some(schema) = msfe_core::msdefs::load(&lay) else {
        return Json::Null;
    };
    let mut out = Vec::new();
    for l in conffile::parse(text) {
        if let conffile::ConfLine::Entry { key, .. } = l {
            if out.iter().any(|(k, _)| *k == key) {
                continue;
            }
            let v = match schema.lookup(&key) {
                // `%org-name% = …` lines define variables, not directives
                _ if key.starts_with('%') => Json::Object(vec![s("type", "variable")]),
                Some(d) => Json::Object(vec![
                    s("type", d.ty.as_str()),
                    s("default", &d.default),
                    ("ruleset".into(), Json::Bool(d.ruleset_ok())),
                    ("options".into(), strs(&d.words)),
                ]),
                None => Json::Null, // unknown to the engine: a typo, or a newer directive
            };
            out.push((key, v));
        }
    }
    Json::Object(out)
}

/// Keys that a `conf.d` fragment sets again: `{key: "conf.d/x.conf"}` — the
/// fragment wins, since the engine reads them after the main file.
fn overrides_json(cat: &confcatalog::Catalog) -> Json {
    let mut out: Vec<(String, Json)> = Vec::new();
    for e in cat
        .entries
        .iter()
        .filter(|e| e.rel.starts_with("conf.d/") && e.rel.ends_with(".conf"))
    {
        let Ok(t) = std::fs::read_to_string(&e.path) else {
            continue;
        };
        for l in conffile::parse(&t) {
            if let conffile::ConfLine::Entry { key, .. } = l {
                out.retain(|(k, _)| *k != key);
                out.push((key, Json::str(&e.rel)));
            }
        }
    }
    Json::Object(out)
}

fn resolve(req_id: &str, cfg: &Config, config_file: &Path) -> Result<Entry, Response> {
    confcatalog::resolve(cfg, config_file, req_id).ok_or_else(|| err(404, "no such file"))
}

fn file(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let id = req.query_param("id").unwrap_or_default();
    let e = match resolve(&id, cfg, config_file) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let text = match std::fs::read(&e.path) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(er) => return err(500, &format!("cannot read: {er}")),
    };
    let mut obj = entry_json(&e);
    obj.push(("content".into(), Json::str(&text)));
    obj.push(("parsed".into(), parsed_json(e.kind, &text)));
    if e.root == Root::Ms && matches!(e.kind, Kind::KeyValue(conffile::Style::Plain)) {
        let cat = confcatalog::scan(cfg, config_file);
        obj.push(("schema".into(), schema_json(cfg, &text)));
        obj.push((
            "rulesets".into(),
            Json::Array(
                cat.entries
                    .iter()
                    .filter(|x| x.rel.starts_with("rules/") && x.rel.ends_with(".rules"))
                    .map(|x| Json::str(x.rel.trim_start_matches("rules/")))
                    .collect(),
            ),
        ));
        if e.rel == "MailScanner.conf" {
            obj.push(("overrides".into(), overrides_json(&cat)));
        }
    }
    obj.push((
        "history".into(),
        Json::Int(confsave::history(cfg, &e).len() as i64),
    ));
    Response::json(200, &Json::Object(obj).to_string())
}

/// `rows` → file text for the table kinds, comments kept through `rebuild`.
fn rows_to_text(kind: Kind, current: &str, rows: &[Json]) -> Result<String, String> {
    let at = |v: &Json| v.get("line").and_then(Json::as_i64).map(|n| n as usize);
    macro_rules! table {
        ($parse:expr, $render:expr, $mk:expr) => {{
            let mut out = Vec::with_capacity(rows.len());
            for (i, v) in rows.iter().enumerate() {
                let row = $mk(v).map_err(|e: String| format!("row {}: {e}", i + 1))?;
                out.push((at(v), row));
            }
            Ok($render(&msgrammar::rebuild(&$parse(current), out)))
        }};
    }
    match kind {
        Kind::RuleTable => table!(
            rule_table,
            |t: &Table<rulefile::Rule>| {
                let mut o = String::new();
                for l in &t.lines {
                    match l {
                        Line::Blank => {}
                        Line::Comment(c) | Line::Unparsed(c) => o.push_str(c),
                        Line::Row(r) => o.push_str(&r.to_line()),
                    }
                    o.push('\n');
                }
                o
            },
            json_to_rule
        ),
        Kind::FilenameRules => table!(
            msgrammar::parse_filename_rules,
            msgrammar::render_filename_rules,
            |v: &Json| {
                let action = msgrammar::Action::parse(&v.str_field("action"))
                    .ok_or_else(|| format!("bad action '{}'", v.str_field("action")))?;
                let dash = |k: &str| {
                    let t = v.str_field(k).trim().to_string();
                    if t.is_empty() {
                        "-".to_string()
                    } else {
                        t
                    }
                };
                let r = msgrammar::FilenameRule {
                    action,
                    pattern: v.str_field("pattern").trim().to_string(),
                    log_text: dash("log_text"),
                    user_text: dash("user_text"),
                };
                r.validate()?;
                Ok(r)
            }
        ),
        Kind::SpamLists => table!(
            msgrammar::parse_spam_lists,
            msgrammar::render_spam_lists,
            |v: &Json| {
                let r = msgrammar::SpamList {
                    name: v.str_field("name").trim().to_string(),
                    domain: v.str_field("domain").trim().to_string(),
                };
                r.validate()?;
                Ok(r)
            }
        ),
        Kind::VirusScanners => table!(
            msgrammar::parse_virus_scanners,
            msgrammar::render_virus_scanners,
            |v: &Json| {
                let r = msgrammar::VirusScanner {
                    name: v.str_field("name").trim().to_string(),
                    wrapper: v.str_field("wrapper").trim().to_string(),
                    dir: v.str_field("dir").trim().to_string(),
                };
                r.validate()?;
                Ok(r)
            }
        ),
        Kind::HostList => table!(
            msgrammar::parse_host_list,
            msgrammar::render_host_list,
            |v: &Json| {
                let h = v.str_field("host").trim().to_string();
                if !msgrammar::is_hostname(&h) {
                    return Err(format!("'{h}' is not a hostname"));
                }
                Ok(h)
            }
        ),
        Kind::KeyValue(_) | Kind::PlainText | Kind::ReadOnly(_) => {
            Err("this file has no row editor".into())
        }
    }
}

fn save(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let e = match resolve(&v.str_field("id"), cfg, config_file) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let current = std::fs::read_to_string(&e.path).unwrap_or_default();
    let new_text = if let Some(c) = v.get("content").and_then(Json::as_str) {
        c.to_string()
    } else if let Some(Json::Object(f)) = v.get("changes") {
        let changes: Vec<(String, String)> = f
            .iter()
            .filter_map(|(k, val)| val.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        match confsave::render_changes(&e, &current, &changes) {
            Some(t) => t,
            None => return err(400, "not a key/value file"),
        }
    } else if let Some(rows) = v.get("rows").and_then(Json::as_array) {
        match rows_to_text(e.kind, &current, rows) {
            Ok(t) => t,
            Err(m) => return err(400, &m),
        }
    } else {
        return err(400, "content, changes or rows required");
    };
    match confsave::save(
        cfg,
        confsave::SaveRequest {
            entry: &e,
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
            let status = if r.error.as_deref() == Some("stale") {
                409
            } else {
                200
            };
            let mut obj = save_report_json(&r);
            if let Ok(m) = std::fs::metadata(&e.path) {
                use std::os::unix::fs::MetadataExt;
                obj.push(("mtime".into(), Json::Int(m.mtime().max(0))));
            }
            Response::json(status, &Json::Object(obj).to_string())
        }
        Err(er) => err(500, &format!("cannot save: {er}")),
    }
}

fn create(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let (dir, name) = (v.str_field("dir"), v.str_field("name"));
    let Some((kind, reload, validator)) = confcatalog::creatable(&dir, &name) else {
        return err(
            400,
            "only conf.d/<name>.conf and rules/<name>.rules can be created",
        );
    };
    let cat = confcatalog::scan(cfg, config_file);
    let rel = format!("{dir}/{name}");
    let path = cat.ms_etc.join(&rel);
    if path.exists() {
        return err(409, "already exists");
    }
    let e = Entry {
        id: format!("ms:{rel}"),
        root: Root::Ms,
        rel,
        path,
        kind,
        reload,
        validator,
        size: 0,
        mtime: 0,
        symlink_target: None,
    };
    match confsave::save(
        cfg,
        confsave::SaveRequest {
            entry: &e,
            new_text: "# created by MSFE-NG\n".into(),
            lint: confsave::LintMode::Skip,
            reload: confsave::ReloadMode::Skip,
            reason: "save",
            expect_mtime: None,
        },
    ) {
        Ok(r) => {
            let mut obj = save_report_json(&r);
            obj.insert(0, ("id".into(), Json::str(&e.id)));
            Response::json(200, &Json::Object(obj).to_string())
        }
        Err(er) => err(500, &format!("cannot create: {er}")),
    }
}

fn history(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let e = match resolve(&req.query_param("id").unwrap_or_default(), cfg, config_file) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let backups: Vec<Json> = confsave::history(cfg, &e)
        .into_iter()
        .map(|b| {
            Json::Object(vec![
                s("stamp", &b.stamp),
                ("size".into(), Json::Int(b.size as i64)),
                s("reason", &b.reason),
            ])
        })
        .collect();
    Response::json(
        200,
        &Json::Object(vec![
            s("id", &e.id),
            ("backups".into(), Json::Array(backups)),
        ])
        .to_string(),
    )
}

fn history_view(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let e = match resolve(&req.query_param("id").unwrap_or_default(), cfg, config_file) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let stamp = req.query_param("stamp").unwrap_or_default();
    match confsave::read_backup(cfg, &e, &stamp) {
        Ok(t) => Response::json(
            200,
            &Json::Object(vec![s("stamp", &stamp), s("content", &t)]).to_string(),
        ),
        Err(_) => err(404, "no such backup"),
    }
}

fn restore(req: &Request, cfg: &Config, config_file: &Path) -> Response {
    let v = match body(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let e = match resolve(&v.str_field("id"), cfg, config_file) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match confsave::restore(
        cfg,
        &e,
        &v.str_field("stamp"),
        lint_mode(v.get("lint")),
        reload_mode(v.get("reload")),
    ) {
        Ok(r) => Response::json(200, &Json::Object(save_report_json(&r)).to_string()),
        Err(er) => err(404, &format!("cannot restore: {er}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_rebuild_each_table_kind_keeping_comments() {
        let cur = "# rules\nFromOrTo:\tdefault\tno\n# tail\n";
        let rows = vec![
            Json::Object(vec![
                ("line".into(), Json::Int(2)),
                s("direction", "FromOrTo:"),
                s("pattern", "default"),
                s("value", "yes"),
            ]),
            Json::Object(vec![
                s("direction", "To:"),
                s("pattern", "*@x.example"),
                s("value", "no"),
            ]),
        ];
        assert_eq!(
            rows_to_text(Kind::RuleTable, cur, &rows).unwrap(),
            "# rules\nFromOrTo:\tdefault\tyes\nTo:\t*@x.example\tno\n# tail\n"
        );
        let cur = "# f\ndeny\t\\.exe$\tExe\tNo exe\n";
        let rows = vec![Json::Object(vec![
            s("action", "rename to .txt"),
            s("pattern", "\\.vbs$"),
            s("log_text", ""),
            s("user_text", "VBS"),
        ])];
        assert_eq!(
            rows_to_text(Kind::FilenameRules, cur, &rows).unwrap(),
            "# f\nrename to .txt\t\\.vbs$\t-\tVBS\n"
        );
        assert!(rows_to_text(
            Kind::FilenameRules,
            cur,
            &[Json::Object(vec![s("action", "nuke"), s("pattern", "x")])]
        )
        .unwrap_err()
        .contains("bad action"));
        let rows = vec![Json::Object(vec![s("host", "bad host")])];
        assert!(rows_to_text(Kind::HostList, "", &rows).is_err());
        let rows = vec![Json::Object(vec![
            s("name", "X"),
            s("domain", "zen.spamhaus.org."),
        ])];
        assert_eq!(
            rows_to_text(Kind::SpamLists, "", &rows).unwrap(),
            "X\tzen.spamhaus.org.\n"
        );
        let rows = vec![Json::Object(vec![
            s("name", "clamd"),
            s("wrapper", "/bin/false"),
            s("dir", "/usr"),
        ])];
        assert_eq!(
            rows_to_text(Kind::VirusScanners, "", &rows).unwrap(),
            "clamd\t/bin/false\t/usr\n"
        );
        assert!(rows_to_text(Kind::PlainText, "", &[]).is_err());
    }

    #[test]
    fn parsed_views_carry_line_numbers() {
        let p = parsed_json(Kind::HostList, "# c\na.example\nbad host\n");
        let rows = p.get("rows").and_then(Json::as_array).unwrap();
        assert_eq!(rows[0].get("line").and_then(Json::as_i64), Some(2));
        assert_eq!(rows[0].str_field("host"), "a.example");
        let un = p.get("unparsed").and_then(Json::as_array).unwrap();
        assert_eq!(un[0].get("line").and_then(Json::as_i64), Some(3));
        let p = parsed_json(Kind::RuleTable, "To:\tdefault\tyes\n");
        assert_eq!(
            p.get("rows").and_then(Json::as_array).unwrap()[0].str_field("direction"),
            "To:"
        );
        assert!(matches!(parsed_json(Kind::PlainText, "x"), Json::Null));
        let p = parsed_json(Kind::KeyValue(conffile::Style::Plain), "# c\nA = 1\n");
        assert_eq!(p.as_array().unwrap()[1].str_field("key"), "A");
    }
}
