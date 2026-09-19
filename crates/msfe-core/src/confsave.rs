//! The one way a configuration file changes: validate → backup → apply →
//! reload, with rollback.
//!
//! A save, a restore from history and a snapshot import all build a
//! `SaveRequest` and come through `save`. The candidate is checked by its
//! kind's parser, then — for the kinds MailScanner or SpamAssassin can judge —
//! linted on a staged copy of the etc tree (`confstage`), so a bad edit never
//! reaches the live file. What passes is promoted: the live file is copied
//! into a timestamped history under `backup_dir/conf/`, written atomically
//! (mode and owner kept), and the engine is restarted or reloaded as the kind
//! requires. `conf.d` fragments, which the engine reads live whatever conf it
//! is given, are linted after apply and written back from the backup when
//! that fails.

use crate::confcatalog::{Entry, Kind, Reload, Root, Validator};
use crate::confstage::Stage;
use crate::{conffile, dbtools, layout, msgrammar, rulefile, sa, service, sync, Config};
use std::io;
use std::path::{Path, PathBuf};

/// How many history copies to keep per file.
pub const KEEP: usize = 50;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintMode {
    Auto,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadMode {
    Auto,
    Skip,
}

pub struct SaveRequest<'a> {
    pub entry: &'a Entry,
    pub new_text: String,
    pub lint: LintMode,
    pub reload: ReloadMode,
    /// `save` | `restore` | `import` — recorded with the backup.
    pub reason: &'static str,
    /// The mtime the editor loaded; a different one on disk means someone
    /// else changed the file since.
    pub expect_mtime: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Validation {
    pub tool: &'static str,
    pub ok: bool,
    pub output: String,
    pub timed_out: bool,
    /// Problem lines picked out of the transcript.
    pub problems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reloaded {
    /// `restart` | `reload` | `none`
    pub action: &'static str,
    pub ok: bool,
    pub transcript: Vec<String>,
}

impl Reloaded {
    fn none(why: &str) -> Reloaded {
        Reloaded {
            action: "none",
            ok: true,
            transcript: if why.is_empty() {
                Vec::new()
            } else {
                vec![why.to_string()]
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SaveReport {
    pub changed: bool,
    pub backup_id: Option<String>,
    pub validation: Option<Validation>,
    pub reloaded: Reloaded,
    pub rolled_back: bool,
    /// Why nothing (or nothing lasting) was written: `stale`, a syntax
    /// message, a failed lint.
    pub error: Option<String>,
}

impl SaveReport {
    fn refused(error: String, validation: Option<Validation>) -> SaveReport {
        SaveReport {
            changed: false,
            backup_id: None,
            validation,
            reloaded: Reloaded::none(""),
            rolled_back: false,
            error: Some(error),
        }
    }
}

// ---- syntax -----------------------------------------------------------------------

/// The kind's own parser: a table file may not carry lines MailScanner would
/// misread, a ruleset no unparsable rule.
pub fn syntax_check(kind: Kind, text: &str) -> Result<(), String> {
    if text.contains('\0') {
        return Err("binary content".into());
    }
    let bad = |lines: Vec<(usize, &str)>, what: &str| -> Result<(), String> {
        match lines.first() {
            None => Ok(()),
            Some((n, l)) => Err(format!(
                "line {n} is not a {what}: {}{}",
                l.chars().take(60).collect::<String>(),
                if lines.len() > 1 {
                    format!(" (+{} more)", lines.len() - 1)
                } else {
                    String::new()
                }
            )),
        }
    };
    match kind {
        Kind::FilenameRules => bad(
            msgrammar::parse_filename_rules(text).unparsed(),
            "filename rule",
        ),
        Kind::SpamLists => bad(
            msgrammar::parse_spam_lists(text).unparsed(),
            "spam list definition",
        ),
        Kind::VirusScanners => bad(
            msgrammar::parse_virus_scanners(text).unparsed(),
            "virus scanner definition",
        ),
        Kind::HostList => bad(msgrammar::parse_host_list(text).unparsed(), "hostname"),
        Kind::RuleTable => {
            let lines: Vec<(usize, &str)> = text
                .lines()
                .enumerate()
                .filter(|(_, l)| matches!(rulefile::parse_line(l), rulefile::Line::Unparsed(_)))
                .map(|(i, l)| (i + 1, l))
                .collect();
            bad(lines, "rule")
        }
        Kind::ReadOnly(r) => Err(format!("read-only: {}", r.as_str())),
        Kind::KeyValue(_) | Kind::PlainText => Ok(()),
    }
}

/// Lines of a `MailScanner --lint` transcript that report a configuration
/// problem. The engine keeps going after most of them and may still exit 0,
/// so the exit status alone is not the verdict.
pub fn ms_lint_problems(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            low.starts_with("cannot ")
                || low.starts_with("can't ")
                || low.starts_with("could not ")
                || low.starts_with("error")
                || low.starts_with("fatal")
                || low.starts_with("syntax error")
                || low.starts_with("died")
                || low.contains(" cannot be a ruleset")
                || low.contains("value of ") && low.contains(" must be ")
        })
        .map(|l| {
            // drop perl's "at …/Config.pm line N." suffix: the file and line
            // that matter are the conf's, not the engine's
            match l.find(" at /") {
                Some(i) if l[i..].contains(".pm line ") => l[..i].trim_end_matches('.').to_string(),
                _ => l.to_string(),
            }
        })
        .collect()
}

/// Lines of a `spamassassin --lint` transcript that report a problem.
pub fn sa_lint_problems(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|l| {
            let t = l.trim();
            // "Sep 19 10:00:00 [123] warn: config: …" → "config: …"
            match t.find(": ") {
                Some(i)
                    if t[..i].ends_with("warn")
                        || t[..i].ends_with("info")
                        || t[..i].ends_with("error") =>
                {
                    t[i + 2..].trim()
                }
                _ => t,
            }
        })
        .filter(|l| {
            let low = l.to_ascii_lowercase();
            low.starts_with("config:")
                || low.starts_with("plugin:")
                || low.starts_with("lint:")
                || low.starts_with("warning")
        })
        .map(str::to_string)
        .collect()
}

// ---- history ----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Backup {
    pub stamp: String,
    pub size: u64,
    pub reason: String,
    pub path: PathBuf,
}

fn history_dir(cfg: &Config, entry: &Entry) -> PathBuf {
    Path::new(&cfg.backup_dir)
        .join("conf")
        .join(entry.root.prefix())
        .join(&entry.rel)
}

/// The legacy one-time copy `service::save_conf` kept next to the file.
fn original_bak(entry: &Entry) -> PathBuf {
    PathBuf::from(format!("{}.msfe-ng.bak", entry.path.display()))
}

/// History of `entry`, newest first; the legacy `.msfe-ng.bak` (the file as
/// it was before MSFE-NG first touched it) is listed last as `original`.
pub fn history(cfg: &Config, entry: &Entry) -> Vec<Backup> {
    let dir = history_dir(cfg, entry);
    let mut out: Vec<Backup> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| {
                    let name = e.file_name().to_str()?.to_string();
                    if name.ends_with(".meta") {
                        return None;
                    }
                    let size = e.metadata().ok()?.len();
                    let reason = std::fs::read_to_string(dir.join(format!("{name}.meta")))
                        .ok()
                        .and_then(|m| {
                            m.lines()
                                .find_map(|l| l.strip_prefix("reason=").map(str::to_string))
                        })
                        .unwrap_or_default();
                    Some(Backup {
                        stamp: name,
                        size,
                        reason,
                        path: e.path(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    let orig = original_bak(entry);
    if let Ok(m) = std::fs::metadata(&orig) {
        out.push(Backup {
            stamp: "original".into(),
            size: m.len(),
            reason: "original".into(),
            path: orig,
        });
    }
    out
}

pub fn read_backup(cfg: &Config, entry: &Entry, stamp: &str) -> io::Result<String> {
    if stamp == "original" {
        return std::fs::read_to_string(original_bak(entry));
    }
    if !service::safe_name(stamp) || stamp.ends_with(".meta") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad stamp"));
    }
    std::fs::read_to_string(history_dir(cfg, entry).join(stamp))
}

/// Copy the live file into the history; `None` when there is no live file
/// yet (a created file).
fn backup(cfg: &Config, entry: &Entry, reason: &str) -> io::Result<Option<String>> {
    if !entry.path.exists() {
        return Ok(None);
    }
    let dir = history_dir(cfg, entry);
    std::fs::create_dir_all(&dir)?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            Path::new(&cfg.backup_dir),
            std::fs::Permissions::from_mode(0o700),
        );
    }
    let base = dbtools::stamp(dbtools::now_secs());
    // same-second copies get a zero-padded suffix continuing from the highest
    // one present, so they keep sorting by age even after older ones were pruned
    let next = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| !n.ends_with(".meta") && n.starts_with(&base))
                .map(|n| {
                    n[base.len()..]
                        .strip_prefix('-')
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(0)
                        + 1
                })
                .max()
        })
        .ok()
        .flatten();
    let stamp = match next {
        None => base,
        Some(n) => format!("{base}-{n:03}"),
    };
    std::fs::copy(&entry.path, dir.join(&stamp))?;
    std::fs::write(
        dir.join(format!("{stamp}.meta")),
        format!("reason={reason}\nsize={}\n", entry.size),
    )?;
    prune(&dir);
    Ok(Some(stamp))
}

fn prune(dir: &Path) {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| !n.ends_with(".meta"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    while names.len() > KEEP {
        let old = names.remove(0);
        let _ = std::fs::remove_file(dir.join(&old));
        let _ = std::fs::remove_file(dir.join(format!("{old}.meta")));
    }
}

// ---- the pipeline ------------------------------------------------------------------------

fn mtime_of(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.mtime().max(0) as u64)
}

/// Validate, back up, apply and reload. Logical refusals (stale file, syntax,
/// a failed lint) come back as a report with `error`; only I/O trouble is an
/// `Err`.
pub fn save(cfg: &Config, req: SaveRequest) -> io::Result<SaveReport> {
    save_with(cfg, req, &layout::resolve(cfg).bin)
}

/// `save` with an explicit engine binary (tests point it at a script).
pub fn save_with(cfg: &Config, req: SaveRequest, bin: &Path) -> io::Result<SaveReport> {
    let entry = req.entry;
    if !entry.kind.editable() {
        return Ok(SaveReport::refused(
            format!("read-only: {}", entry.kind.as_str()),
            None,
        ));
    }
    if let (Some(want), Some(have)) = (req.expect_mtime, mtime_of(&entry.path)) {
        if want != have {
            return Ok(SaveReport::refused("stale".into(), None));
        }
    }
    let current = std::fs::read_to_string(&entry.path).unwrap_or_default();
    if entry.path.exists() && current == req.new_text {
        return Ok(SaveReport {
            changed: false,
            backup_id: None,
            validation: None,
            reloaded: Reloaded::none(""),
            rolled_back: false,
            error: None,
        });
    }
    if let Err(e) = syntax_check(entry.kind, &req.new_text) {
        return Ok(SaveReport::refused(e, None));
    }

    // ---- validate on a stage --------------------------------------------------
    let mut validation: Option<Validation> = None;
    let mut lint_after = false;
    if req.lint == LintMode::Auto && entry.root == Root::Ms {
        match entry.validator {
            Validator::MsLint => {
                let mut st = Stage::new(cfg)?;
                match st.apply(&entry.rel, &req.new_text) {
                    Ok(()) => {
                        let r = service::lint_conf(bin, Some(&st.conf()));
                        let staged = st.conf().display().to_string();
                        if !r.timed_out && !r.output.contains(&staged) {
                            // the engine read the live conf instead: judge
                            // after apply, with rollback
                            lint_after = true;
                        } else {
                            let v = ms_validation(&r);
                            let ok = v.ok;
                            validation = Some(v);
                            if !ok {
                                return Ok(SaveReport::refused(
                                    "MailScanner --lint rejected the change".into(),
                                    validation,
                                ));
                            }
                        }
                    }
                    Err(_) => lint_after = true, // behind a symlink: validated in place
                }
            }
            Validator::SaLint => {
                let mut st = Stage::new(cfg)?;
                st.apply(&entry.rel, &req.new_text)?;
                let (ok, output) = sa::lint_prefs(Some(&st.etc.join(&entry.rel)));
                let problems = sa_lint_problems(&output);
                let ok = ok && problems.is_empty();
                validation = Some(Validation {
                    tool: "spamassassin --lint",
                    ok,
                    output,
                    timed_out: false,
                    problems,
                });
                if !ok {
                    return Ok(SaveReport::refused(
                        "spamassassin --lint rejected the change".into(),
                        validation,
                    ));
                }
            }
            Validator::MsLintAfter => lint_after = true,
            Validator::Syntax | Validator::TomlLoad => {}
        }
    }

    // ---- promote -------------------------------------------------------------
    let backup_id = backup(cfg, entry, req.reason)?;
    let existed = entry.path.exists();
    sync::atomic_write(&entry.path, req.new_text.as_bytes())?;

    // ---- lint after apply (conf.d, or an engine that ignored the stage) --------
    let mut rolled_back = false;
    if lint_after {
        let r = service::lint_conf(bin, None);
        let v = ms_validation(&r);
        let ok = v.ok || v.timed_out;
        validation = Some(v);
        if !ok {
            if existed {
                sync::atomic_write(&entry.path, current.as_bytes())?;
            } else {
                let _ = std::fs::remove_file(&entry.path);
            }
            rolled_back = true;
            return Ok(SaveReport {
                changed: false,
                backup_id,
                validation,
                reloaded: Reloaded::none(""),
                rolled_back,
                error: Some(
                    "MailScanner --lint rejected the change; the previous file is back".into(),
                ),
            });
        }
    }

    // ---- reload --------------------------------------------------------------
    let reloaded = if req.reload == ReloadMode::Skip {
        Reloaded::none("reload skipped")
    } else {
        match entry.reload {
            Reload::Restart => {
                if service::status().active {
                    let o = service::control("restart");
                    Reloaded {
                        action: "restart",
                        ok: o.ok,
                        transcript: o.transcript,
                    }
                } else {
                    Reloaded::none(
                        "MailScanner is not running; the change applies at its next start",
                    )
                }
            }
            Reload::Reload => {
                let ok = sync::reload_mailscanner();
                Reloaded {
                    action: "reload",
                    ok,
                    transcript: vec![if ok {
                        "MailScanner reloaded".into()
                    } else {
                        "MailScanner reload failed (is it running?)".into()
                    }],
                }
            }
            Reload::None => Reloaded::none(""),
        }
    };

    Ok(SaveReport {
        changed: true,
        backup_id,
        validation,
        reloaded,
        rolled_back,
        error: None,
    })
}

/// Save several files as one change: every candidate syntax-checked, all of
/// them staged together and linted once, then promoted with one backup each
/// and one restart/reload for the set. Any refusal refuses the whole set —
/// an import is all or nothing. `conf.d` fragments (validated only after
/// apply) are linted once more on the live tree and the whole set is put
/// back if that fails.
pub fn save_many(cfg: &Config, reqs: Vec<SaveRequest>) -> io::Result<Vec<SaveReport>> {
    save_many_with(cfg, reqs, &layout::resolve(cfg).bin)
}

pub fn save_many_with(
    cfg: &Config,
    reqs: Vec<SaveRequest>,
    bin: &Path,
) -> io::Result<Vec<SaveReport>> {
    let refuse_all = |n: usize, error: String, validation: Option<Validation>| -> Vec<SaveReport> {
        (0..n)
            .map(|_| SaveReport::refused(error.clone(), validation.clone()))
            .collect()
    };
    let n = reqs.len();
    // cheap refusals first
    for r in &reqs {
        if !r.entry.kind.editable() {
            return Ok(refuse_all(n, format!("{}: read-only", r.entry.rel), None));
        }
        if let Err(e) = syntax_check(r.entry.kind, &r.new_text) {
            return Ok(refuse_all(n, format!("{}: {e}", r.entry.rel), None));
        }
    }
    let changed: Vec<bool> = reqs
        .iter()
        .map(|r| {
            std::fs::read_to_string(&r.entry.path)
                .map(|c| c != r.new_text)
                .unwrap_or(true)
        })
        .collect();
    if !changed.iter().any(|c| *c) {
        return Ok((0..n)
            .map(|_| SaveReport {
                changed: false,
                backup_id: None,
                validation: None,
                reloaded: Reloaded::none(""),
                rolled_back: false,
                error: None,
            })
            .collect());
    }
    let lint = reqs.first().map(|r| r.lint).unwrap_or(LintMode::Auto);
    let reload = reqs.first().map(|r| r.reload).unwrap_or(ReloadMode::Auto);
    let reason = reqs.first().map(|r| r.reason).unwrap_or("import");
    let ms: Vec<&SaveRequest> = reqs
        .iter()
        .zip(&changed)
        .filter(|(r, c)| **c && r.entry.root == Root::Ms)
        .map(|(r, _)| r)
        .collect();
    let mut validation: Option<Validation> = None;
    let mut lint_after = false;
    if lint == LintMode::Auto && !ms.is_empty() {
        let mut st = Stage::new(cfg)?;
        let mut need_ms = false;
        let mut need_sa = false;
        for r in &ms {
            match r.entry.validator {
                Validator::MsLint | Validator::MsLintAfter => {
                    if st.apply(&r.entry.rel, &r.new_text).is_err() {
                        lint_after = true;
                    } else {
                        need_ms = true;
                        if r.entry.validator == Validator::MsLintAfter {
                            lint_after = true;
                        }
                    }
                }
                Validator::SaLint => {
                    let _ = st.apply(&r.entry.rel, &r.new_text);
                    need_sa = true;
                }
                _ => {}
            }
        }
        if need_ms {
            let lr = service::lint_conf(bin, Some(&st.conf()));
            if !lr.timed_out && !lr.output.contains(&st.conf().display().to_string()) {
                lint_after = true;
            } else {
                let v = ms_validation(&lr);
                if !v.ok {
                    return Ok(refuse_all(
                        n,
                        "MailScanner --lint rejected the change".into(),
                        Some(v),
                    ));
                }
                validation = Some(v);
            }
        }
        if need_sa {
            let (ok, output) = sa::lint_prefs(Some(&st.etc.join("spamassassin.conf")));
            let problems = sa_lint_problems(&output);
            if !ok || !problems.is_empty() {
                return Ok(refuse_all(
                    n,
                    "spamassassin --lint rejected the change".into(),
                    Some(Validation {
                        tool: "spamassassin --lint",
                        ok: false,
                        output,
                        timed_out: false,
                        problems,
                    }),
                ));
            }
        }
    }

    // promote every changed file
    let mut reports: Vec<SaveReport> = Vec::with_capacity(n);
    let mut written: Vec<(usize, Option<String>, bool)> = Vec::new(); // (index, previous text, existed)
    for (i, (r, c)) in reqs.iter().zip(&changed).enumerate() {
        if !*c {
            reports.push(SaveReport {
                changed: false,
                backup_id: None,
                validation: None,
                reloaded: Reloaded::none(""),
                rolled_back: false,
                error: None,
            });
            continue;
        }
        let existed = r.entry.path.exists();
        let prev = std::fs::read_to_string(&r.entry.path).ok();
        let backup_id = backup(cfg, r.entry, reason)?;
        if let Some(dir) = r.entry.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        sync::atomic_write(&r.entry.path, r.new_text.as_bytes())?;
        written.push((i, prev, existed));
        reports.push(SaveReport {
            changed: true,
            backup_id,
            validation: validation.clone(),
            reloaded: Reloaded::none(""),
            rolled_back: false,
            error: None,
        });
    }

    if lint_after && lint == LintMode::Auto {
        let lr = service::lint_conf(bin, None);
        let v = ms_validation(&lr);
        if !v.ok && !v.timed_out {
            for (i, prev, existed) in &written {
                let r = &reqs[*i];
                match (existed, prev) {
                    (true, Some(p)) => sync::atomic_write(&r.entry.path, p.as_bytes())?,
                    _ => {
                        let _ = std::fs::remove_file(&r.entry.path);
                    }
                }
                reports[*i].changed = false;
                reports[*i].rolled_back = true;
                reports[*i].error = Some(
                    "MailScanner --lint rejected the set; every file is back as it was".into(),
                );
            }
            for rep in &mut reports {
                rep.validation = Some(v.clone());
            }
            return Ok(reports);
        }
        for rep in &mut reports {
            if rep.changed {
                rep.validation = Some(v.clone());
            }
        }
    }

    // one reload for the set
    let want_restart = reqs
        .iter()
        .zip(&changed)
        .any(|(r, c)| *c && r.entry.reload == Reload::Restart);
    let want_reload = reqs
        .iter()
        .zip(&changed)
        .any(|(r, c)| *c && r.entry.reload == Reload::Reload);
    let reloaded = if reload == ReloadMode::Skip {
        Reloaded::none("reload skipped")
    } else if want_restart {
        if service::status().active {
            let o = service::control("restart");
            Reloaded {
                action: "restart",
                ok: o.ok,
                transcript: o.transcript,
            }
        } else {
            Reloaded::none("MailScanner is not running; the change applies at its next start")
        }
    } else if want_reload {
        let ok = sync::reload_mailscanner();
        Reloaded {
            action: "reload",
            ok,
            transcript: vec![if ok {
                "MailScanner reloaded".into()
            } else {
                "MailScanner reload failed (is it running?)".into()
            }],
        }
    } else {
        Reloaded::none("")
    };
    for rep in &mut reports {
        if rep.changed {
            rep.reloaded = reloaded.clone();
        }
    }
    Ok(reports)
}

fn ms_validation(r: &service::LintReport) -> Validation {
    let problems = ms_lint_problems(&r.output);
    Validation {
        tool: "MailScanner --lint",
        ok: r.ok && problems.is_empty() && !r.timed_out,
        output: r.output.clone(),
        timed_out: r.timed_out,
        problems,
    }
}

/// Put a history copy back, through the same pipeline (the current file is
/// itself backed up first).
pub fn restore(
    cfg: &Config,
    entry: &Entry,
    stamp: &str,
    lint: LintMode,
    reload: ReloadMode,
) -> io::Result<SaveReport> {
    let text = read_backup(cfg, entry, stamp)?;
    save(
        cfg,
        SaveRequest {
            entry,
            new_text: text,
            lint,
            reload,
            reason: "restore",
            expect_mtime: None,
        },
    )
}

/// Render a kind's structured rows to the file text `save` takes; `changes`
/// for key/value files go through `conffile::apply` on the current text.
pub fn render_changes(
    entry: &Entry,
    current: &str,
    changes: &[(String, String)],
) -> Option<String> {
    match entry.kind {
        Kind::KeyValue(style) => Some(conffile::apply(current, changes, style).0),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confcatalog;

    /// A tree plus a fake engine whose `--lint` fails when any file under the
    /// conf's dir (the staged one when a path is given) contains BREAKME.
    fn fixture(tag: &str) -> (PathBuf, Config, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("msfe-save-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("rules")).unwrap();
        std::fs::create_dir_all(etc.join("conf.d")).unwrap();
        std::fs::write(
            etc.join("MailScanner.conf"),
            format!("%etc-dir% = {}\nMax Children = 5\n", etc.display()),
        )
        .unwrap();
        std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
        std::fs::write(etc.join("conf.d/10-x.conf"), "Max Children = 6\n").unwrap();
        std::fs::write(etc.join("spam.lists.conf"), "SPAMCOP\tbl.spamcop.net.\n").unwrap();
        std::fs::write(etc.join("phishing.bad.sites.custom"), "bad.example\n").unwrap();
        let msfe = base.join("etc/msfe-ng");
        std::fs::create_dir_all(&msfe).unwrap();
        let conf = msfe.join("config.toml");
        std::fs::write(&conf, "panel = \"x\"\n").unwrap();
        let bin = base.join("fake-mailscanner");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nif [ -n \"$2\" ]; then d=$(dirname \"$2\"); else d={etc}; fi\n\
                 echo \"Reading configuration file $d/MailScanner.conf\"\n\
                 if grep -rq BREAKME \"$d\"; then echo \"Cannot open ruleset file BREAKME, No such file or directory at /usr/share/MailScanner/perl/MailScanner/Config.pm line 2633.\"; exit 1; fi\n\
                 echo \"SpamAssassin reported no errors.\"\n",
                etc = etc.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        (base, cfg, conf, bin)
    }

    fn req<'a>(entry: &'a Entry, text: &str) -> SaveRequest<'a> {
        SaveRequest {
            entry,
            new_text: text.into(),
            lint: LintMode::Auto,
            reload: ReloadMode::Skip,
            reason: "save",
            expect_mtime: None,
        }
    }

    #[test]
    fn good_edit_is_backed_up_and_written() {
        let (base, cfg, conf, bin) = fixture("good");
        let e = confcatalog::resolve(&cfg, &conf, "ms:MailScanner.conf").unwrap();
        let text = std::fs::read_to_string(&e.path)
            .unwrap()
            .replace("= 5", "= 9");
        let r = save_with(&cfg, req(&e, &text), &bin).unwrap();
        assert!(r.changed, "{r:?}");
        assert!(r.error.is_none());
        let v = r.validation.unwrap();
        assert!(v.ok);
        assert!(v.output.contains("Reading configuration file"));
        assert!(
            v.output.contains("/.stage/"),
            "linted the stage: {}",
            v.output
        );
        assert_eq!(r.reloaded.action, "none");
        assert_eq!(std::fs::read_to_string(&e.path).unwrap(), text);
        let h = history(&cfg, &e);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].reason, "save");
        assert_eq!(h[0].stamp, r.backup_id.unwrap());
        assert!(read_backup(&cfg, &e, &h[0].stamp).unwrap().contains("= 5"));
        // stage cleaned
        assert!(
            std::fs::read_dir(base.join("backups/.stage"))
                .map(|d| d.count())
                .unwrap_or(0)
                == 0
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lint_failure_on_the_stage_leaves_live_untouched() {
        let (base, cfg, conf, bin) = fixture("bad");
        let e = confcatalog::resolve(&cfg, &conf, "ms:rules/bounce.rules").unwrap();
        let r = save_with(&cfg, req(&e, "FromOrTo: default BREAKME\n"), &bin).unwrap();
        assert!(!r.changed);
        assert!(r.error.as_deref().unwrap().contains("rejected"));
        let v = r.validation.unwrap();
        assert!(!v.ok);
        assert_eq!(
            v.problems,
            vec!["Cannot open ruleset file BREAKME, No such file or directory"]
        );
        assert_eq!(
            std::fs::read_to_string(&e.path).unwrap(),
            "FromOrTo: default no\n"
        );
        assert!(r.backup_id.is_none());
        assert!(history(&cfg, &e).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn confd_is_linted_after_apply_and_rolled_back() {
        let (base, cfg, conf, bin) = fixture("confd");
        let e = confcatalog::resolve(&cfg, &conf, "ms:conf.d/10-x.conf").unwrap();
        assert_eq!(e.validator, Validator::MsLintAfter);
        let r = save_with(&cfg, req(&e, "Max Children = BREAKME\n"), &bin).unwrap();
        assert!(!r.changed);
        assert!(r.rolled_back);
        assert!(r.backup_id.is_some(), "the pre-edit copy is kept");
        assert_eq!(
            std::fs::read_to_string(&e.path).unwrap(),
            "Max Children = 6\n"
        );
        // and a good one lands
        let r = save_with(&cfg, req(&e, "Max Children = 7\n"), &bin).unwrap();
        assert!(r.changed && !r.rolled_back);
        assert_eq!(
            std::fs::read_to_string(&e.path).unwrap(),
            "Max Children = 7\n"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn syntax_stale_unchanged_and_readonly_are_refused_cheaply() {
        let (base, cfg, conf, bin) = fixture("refuse");
        let e = confcatalog::resolve(&cfg, &conf, "ms:spam.lists.conf").unwrap();
        let r = save_with(&cfg, req(&e, "SPAMCOP bl.spamcop.net. extra\n"), &bin).unwrap();
        assert!(r
            .error
            .as_deref()
            .unwrap()
            .starts_with("line 1 is not a spam list definition"));
        let r = save_with(&cfg, req(&e, "SPAMCOP\tbl.spamcop.net.\n"), &bin).unwrap();
        assert!(!r.changed && r.error.is_none() && r.validation.is_none());
        let mut s = req(&e, "X\ty.z.\n");
        s.expect_mtime = Some(1);
        let r = save_with(&cfg, s, &bin).unwrap();
        assert_eq!(r.error.as_deref(), Some("stale"));
        let h = confcatalog::resolve(&cfg, &conf, "ms:phishing.bad.sites.custom").unwrap();
        let r = save_with(&cfg, req(&h, "not a host name\n"), &bin).unwrap();
        assert!(r.error.as_deref().unwrap().contains("not a hostname"));
        let r = save_with(&cfg, req(&h, "good.example\n"), &bin).unwrap();
        assert!(
            r.changed && r.validation.is_none(),
            "syntax-only kinds never lint"
        );
        let ro = Entry {
            kind: Kind::ReadOnly(confcatalog::ReadOnlyReason::Defaults),
            ..h.clone()
        };
        assert!(save_with(&cfg, req(&ro, "x\n"), &bin)
            .unwrap()
            .error
            .unwrap()
            .starts_with("read-only"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn msfe_config_is_saved_without_the_engine() {
        let (base, cfg, conf, bin) = fixture("msfe");
        let e = confcatalog::resolve(&cfg, &conf, "msfe:config.toml").unwrap();
        let r = save_with(&cfg, req(&e, "panel = \"y\"\n"), &bin).unwrap();
        assert!(r.changed && r.validation.is_none());
        assert_eq!(std::fs::read_to_string(&conf).unwrap(), "panel = \"y\"\n");
        assert_eq!(history(&cfg, &e).len(), 1);
        assert!(base.join("backups/conf/msfe/config.toml").is_dir());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn history_is_newest_first_pruned_and_restorable() {
        let (base, cfg, conf, bin) = fixture("history");
        let e = confcatalog::resolve(&cfg, &conf, "ms:phishing.bad.sites.custom").unwrap();
        for i in 0..(KEEP + 3) {
            let r = save_with(&cfg, req(&e, &format!("h{i}.example\n")), &bin).unwrap();
            assert!(r.changed);
        }
        let h = history(&cfg, &e);
        assert_eq!(h.len(), KEEP);
        assert!(h[0].stamp > h[1].stamp);
        // legacy one-time copy shows as "original"
        std::fs::write(
            format!("{}.msfe-ng.bak", e.path.display()),
            "orig.example\n",
        )
        .unwrap();
        let h = history(&cfg, &e);
        assert_eq!(h.last().unwrap().stamp, "original");
        assert_eq!(read_backup(&cfg, &e, "original").unwrap(), "orig.example\n");
        assert!(read_backup(&cfg, &e, "../x").is_err());
        let newest = h[0].stamp.clone();
        let r = restore(&cfg, &e, &newest, LintMode::Skip, ReloadMode::Skip).unwrap();
        assert!(r.changed);
        assert_eq!(history(&cfg, &e)[0].reason, "restore");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn save_many_stages_everything_once_and_is_all_or_nothing() {
        let (base, cfg, conf, bin) = fixture("many");
        let a = confcatalog::resolve(&cfg, &conf, "ms:rules/bounce.rules").unwrap();
        let b = confcatalog::resolve(&cfg, &conf, "ms:phishing.bad.sites.custom").unwrap();
        fn mk<'a>(e: &'a Entry, text: &str) -> SaveRequest<'a> {
            SaveRequest {
                entry: e,
                new_text: text.into(),
                lint: LintMode::Auto,
                reload: ReloadMode::Skip,
                reason: "import",
                expect_mtime: None,
            }
        }
        // one bad file refuses the whole set, nothing written
        let rs = save_many_with(
            &cfg,
            vec![
                mk(
                    &a,
                    "FromOrTo: default BREAKME
",
                ),
                mk(
                    &b,
                    "good.example
",
                ),
            ],
            &bin,
        )
        .unwrap();
        assert!(rs.iter().all(|r| !r.changed && r.error.is_some()));
        assert_eq!(
            std::fs::read_to_string(&b.path).unwrap(),
            "bad.example
"
        );
        assert!(history(&cfg, &a).is_empty() && history(&cfg, &b).is_empty());
        // a good set lands with one backup each and one lint
        let rs = save_many_with(
            &cfg,
            vec![
                mk(
                    &a,
                    "FromOrTo: default yes
",
                ),
                mk(
                    &b,
                    "good.example
",
                ),
            ],
            &bin,
        )
        .unwrap();
        assert!(rs.iter().all(|r| r.changed && r.error.is_none()), "{rs:?}");
        assert!(rs[0].backup_id.is_some() && rs[1].backup_id.is_some());
        assert!(rs[0]
            .validation
            .as_ref()
            .unwrap()
            .output
            .contains("/.stage/"));
        assert_eq!(
            std::fs::read_to_string(&a.path).unwrap(),
            "FromOrTo: default yes
"
        );
        assert_eq!(
            std::fs::read_to_string(&b.path).unwrap(),
            "good.example
"
        );
        // an unchanged file in the set is left alone
        let rs = save_many_with(
            &cfg,
            vec![
                mk(
                    &a,
                    "FromOrTo: default yes
",
                ),
                mk(
                    &b,
                    "other.example
",
                ),
            ],
            &bin,
        )
        .unwrap();
        assert!(!rs[0].changed && rs[1].changed);
        assert_eq!(history(&cfg, &a).len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn problem_lines_are_picked_out_of_transcripts() {
        let ms = "Trying to setlogsock(unix)\n\nReading configuration file /x/MailScanner.conf\n\
                  Value of children cannot be a ruleset, only a simple value at /usr/share/MailScanner/perl/MailScanner/Config.pm line 3298.\n\
                  Cannot open ruleset file notanumber, No such file or directory at /usr/share/MailScanner/perl/MailScanner/Config.pm line 2633.\n\
                  Read 1492 hostnames from the phishing whitelist\nSpamAssassin reported no errors.\n\
                  MailScanner.conf says \"Virus Scanners = clamd\"\nFound these virus scanners installed: clamd\n";
        assert_eq!(
            ms_lint_problems(ms),
            vec![
                "Value of children cannot be a ruleset, only a simple value",
                "Cannot open ruleset file notanumber, No such file or directory"
            ]
        );
        let sa = "Sep 19 10:00:00 [123] warn: config: failed to parse line, skipping, in \"/etc/MailScanner/spamassassin.conf\": bogus line\n\
                  Sep 19 10:00:00 [123] warn: lint: 1 issues detected, please rerun with debug enabled for more information\n";
        assert_eq!(
            sa_lint_problems(sa),
            vec![
                "config: failed to parse line, skipping, in \"/etc/MailScanner/spamassassin.conf\": bogus line",
                "lint: 1 issues detected, please rerun with debug enabled for more information"
            ]
        );
        assert!(sa_lint_problems("").is_empty());
    }
}
