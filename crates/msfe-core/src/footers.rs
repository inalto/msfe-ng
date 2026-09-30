//! Settings → What MailScanner changes in mail: one switch per setting,
//! and every change reversible to the exact bytes.
//!
//! [`CATALOGUE`] lists what MailScanner adds to or changes in delivered mail
//! — body text (the "scanned … believed to be clean" footer and friends),
//! attachments, subject tags, headers, content rewriting and the notices it
//! sends — each with the value that switches it off. A switch is written on
//! the line where the setting takes effect (MailScanner reads
//! MailScanner.conf, then conf.d/*.conf; the last occurrence wins; names
//! match case- and space-insensitively), or appended. Before any change, a
//! backup under `<msfe dir>/footers/<stamp>/` keeps the lines replaced (or
//! that there were none) and a copy of the footer templates; switching a
//! setting back, or "Put back", restores those exact lines — rulesets and
//! comments included. Every write goes through `confsave::save_many`:
//! staged, linted once, history kept, one restart.

use crate::confcatalog::{self, Entry};
use crate::config::Config;
use crate::confsave::{self, LintMode, ReloadMode, SaveReport, SaveRequest};
use crate::json::Json;
use crate::msdefs;
use std::path::{Path, PathBuf};

/// One MailScanner setting that changes delivered mail, as a switch.
#[derive(Debug, Clone, Copy)]
pub struct Item {
    pub key: &'static str,
    pub group: &'static str,
    pub what: &'static str,
    /// the value that stops the change (`no`; `yes` for "Allow WebBugs")
    pub off: &'static str,
    /// written to switch it on when no earlier line can be restored and the
    /// engine default is the off value
    pub on_fallback: &'static str,
    /// MailScanner 5's own default (ConfigDefs.pl), used when the engine's
    /// ConfigDefs cannot be read
    pub stock_default: &'static str,
    pub caution: &'static str,
}

const fn it(
    group: &'static str,
    key: &'static str,
    what: &'static str,
    off: &'static str,
    on_fallback: &'static str,
    stock_default: &'static str,
    caution: &'static str,
) -> Item {
    Item {
        key,
        group,
        what,
        off,
        on_fallback,
        stock_default,
        caution,
    }
}

/// Group ids and titles, in display order.
pub const GROUPS: [(&str, &str); 6] = [
    ("body", "Text added to the message body"),
    ("attachments", "Attachments"),
    ("subject", "Subject tags"),
    ("headers", "Headers added"),
    ("rewriting", "Content rewriting"),
    ("notices", "Notices MailScanner sends"),
];

/// Everything MailScanner changes in delivered mail that is safe to switch.
/// Protections (script/form/iframe/object disarming, dangerous-HTML
/// conversion, scanning, quarantine) are deliberately not here.
pub const CATALOGUE: [Item; 37] = [
    it("body", "Sign Clean Messages", "the “This message has been scanned … and is believed to be clean” footer on clean mail", "no", "yes", "yes", ""),
    it("body", "Mark Unscanned Messages", "a note on mail that was not scanned (too big, too many messages at once)", "no", "yes", "yes", ""),
    it("body", "Mark Infected Messages", "the inline warning inserted where an attachment was removed", "no", "yes", "yes", ""),
    it("body", "Highlight Phishing Fraud", "“MailScanner has detected a possible fraud attempt” in front of links that pretend to go elsewhere", "no", "yes", "yes", "recipients lose the warning on real phishing links"),
    it("body", "Highlight Hidden URLs", "marks links whose visible text hides where they go", "no", "yes", "no", ""),
    it("body", "Highlight Mailto Phishing", "the same warning for mailto: links", "no", "yes", "yes", ""),
    it("body", "External Message Warning", "a “this message came from outside” banner", "no", "yes", "no", ""),
    it("body", "Attach Image To Signature", "an image inside the footer", "no", "yes", "no", ""),
    it("body", "Sign Messages Already Processed", "the footer again on mail another MailScanner already signed", "no", "yes", "no", ""),
    it("attachments", "Warning Is Attachment", "a VirusWarning.txt attachment saying what was removed", "no", "yes", "yes", "without it (and without the inline warning) a removed attachment just disappears"),
    it("attachments", "Zip Attachments", "attachments packed into one zip file", "no", "yes", "no", ""),
    it("subject", "Spam Modify Subject", "{Spam?} in the subject of spam", "no", "start", "start", ""),
    it("subject", "High Scoring Spam Modify Subject", "{Spam?} in the subject of high-scoring spam", "no", "start", "start", ""),
    it("subject", "Virus Modify Subject", "{Virus?} in the subject of infected mail", "no", "start", "start", ""),
    it("subject", "Filename Modify Subject", "{Filename?} when an attachment was blocked by name or type", "no", "start", "start", ""),
    it("subject", "Content Modify Subject", "{Dangerous Content?} when content was blocked", "no", "start", "start", ""),
    it("subject", "Size Modify Subject", "{Size} when an attachment was too big", "no", "start", "start", ""),
    it("subject", "Disarmed Modify Subject", "{Disarmed} when HTML was disarmed", "no", "start", "start", ""),
    it("subject", "Phishing Modify Subject", "{Fraud?} on suspected phishing", "no", "start", "no", ""),
    it("subject", "Scanned Modify Subject", "{Scanned} on every scanned message", "no", "start", "no", ""),
    it("headers", "Add Envelope From Header", "X-…-MailScanner-Envelope-From with the envelope sender", "no", "yes", "yes", "msfe-ng's spam checks read the envelope sender from it"),
    it("headers", "Add Envelope To Header", "X-…-MailScanner-Envelope-To with the recipients", "no", "yes", "no", "exposes every recipient's address to the others"),
    it("headers", "Add Watermark", "a watermark header on outgoing mail", "no", "yes", "yes", "bounce-backscatter protection recognises your own bounces by it"),
    it("headers", "Spam Score", "the score as stars (sss…) in a header", "no", "yes", "yes", ""),
    it("headers", "Detailed Spam Report", "the SpamAssassin rules that fired, in the spam-check header", "no", "yes", "yes", ""),
    it("headers", "Include Scores In SpamAssassin Report", "each rule's score in that report", "no", "yes", "yes", ""),
    it("headers", "Always Include SpamAssassin Report", "the report on clean mail too", "no", "yes", "no", ""),
    it("rewriting", "Allow WebBugs", "tracking images (web bugs) replaced by a blank one", "yes", "disarm", "convert", ""),
    it("rewriting", "Use TNEF Contents", "winmail.dat (Outlook TNEF) replaced by the files inside it", "no", "replace", "replace", ""),
    it("rewriting", "Convert HTML To Text", "HTML parts turned into plain text", "no", "yes", "no", "every HTML message arrives as text"),
    it("notices", "Notify Senders", "notices back to the sender when something is blocked (the switch for the four below)", "no", "yes", "yes", ""),
    it("notices", "Notify Senders Of Viruses", "…when the message carried a virus (usually a forged sender)", "no", "yes", "no", "virus senders are almost always forged: this mails innocent people"),
    it("notices", "Notify Senders Of Blocked Filenames Or Filetypes", "…when an attachment is blocked by name or type", "no", "yes", "yes", ""),
    it("notices", "Notify Senders Of Blocked Size Attachments", "…when an attachment is too big", "no", "yes", "no", ""),
    it("notices", "Notify Senders Of Other Blocked Content", "…when other content is blocked", "no", "yes", "yes", ""),
    it("notices", "Send Notices", "notices to the postmaster about blocked mail", "no", "yes", "yes", ""),
    it("notices", "Notices Include Full Headers", "the message's full headers in those notices", "no", "yes", "yes", ""),
];

/// The catalogue entry for a key (spelling- and case-insensitive).
pub fn item(key: &str) -> Option<&'static Item> {
    let n = norm(key);
    CATALOGUE.iter().find(|i| norm(i.key) == n)
}

/// A value's first word, lower-cased, without an inline `# …` comment.
pub fn first_word(v: &str) -> String {
    v.split('#')
        .next()
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// A value that names a ruleset file rather than a plain setting.
pub fn is_ruleset(v: &str) -> bool {
    let w = first_word(v);
    w.starts_with('/') || w.contains("%rules-dir%") || w.ends_with(".rules")
}

const KEEP_BACKUPS: usize = 10;

/// `Sign Clean Messages` → `signcleanmessages` (MailScanner's own matching).
fn norm(key: &str) -> String {
    msdefs::internal_name(key)
}

/// `(key as written, value)` of a live directive line.
fn live_kv(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    if t.starts_with('#') || t.starts_with('%') {
        return None;
    }
    let (k, v) = t.split_once('=')?;
    Some((k.trim(), v.trim()))
}

/// Where a directive takes effect: the file and its exact line.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub file: String,
    pub line: String,
    pub value: String,
}

/// The last live line of `key` across the files, read in order.
pub fn effective(files: &[(String, String)], key: &str) -> Option<Found> {
    let want = norm(key);
    let mut found = None;
    for (id, text) in files {
        for line in text.lines() {
            if let Some((k, v)) = live_kv(line) {
                if norm(k) == want {
                    found = Some(Found {
                        file: id.clone(),
                        line: line.to_string(),
                        value: v.to_string(),
                    });
                }
            }
        }
    }
    found
}

#[derive(Debug, Clone)]
pub struct DirState {
    pub key: &'static str,
    pub what: &'static str,
    pub item: Item,
    /// the engine's ConfigDefs knows it (true when ConfigDefs is unreadable)
    pub known: bool,
    pub found: Option<Found>,
    pub default: String,
    /// the value in effect: the line's, else the engine default
    pub effective: String,
}

impl DirState {
    pub fn on(&self) -> bool {
        self.known && first_word(&self.effective) != self.item.off
    }
    pub fn rules(&self) -> bool {
        is_ruleset(&self.effective)
    }
    /// What "on" writes when no earlier line can be restored: the engine
    /// default, unless that default is the off value.
    pub fn on_value(&self) -> String {
        let d = first_word(&self.default);
        if d.is_empty() || d == self.item.off {
            self.item.on_fallback.to_string()
        } else {
            d
        }
    }
}

/// One line change in one file: `before` → `after` (None: append / delete).
#[derive(Debug, Clone, PartialEq)]
pub struct Edit {
    pub file: String,
    pub key: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// Apply an edit to a file's text: replace the last exact `before` line (or
/// append `after` when there was none; delete when `after` is None).
/// `None` when the `before` line is not there any more.
pub fn apply_edit(text: &str, before: Option<&str>, after: Option<&str>) -> Option<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    match before {
        Some(b) => {
            let i = lines.iter().rposition(|l| l == b)?;
            match after {
                Some(a) => lines[i] = a.to_string(),
                None => {
                    lines.remove(i);
                }
            }
        }
        None => lines.push(after?.to_string()),
    }
    let mut s = lines.join("\n");
    if text.ends_with('\n') || before.is_none() {
        s.push('\n');
    }
    Some(s)
}

/// The edit that writes `value` for `d`: on its effective line, else appended
/// to the main file.
fn set_edit(d: &DirState, value: &str, main_file: &str) -> Edit {
    match &d.found {
        Some(f) => {
            let (k, _) = live_kv(&f.line).unwrap_or((d.key, ""));
            let indent: String = f.line.chars().take_while(|c| c.is_whitespace()).collect();
            Edit {
                file: f.file.clone(),
                key: d.key.into(),
                before: Some(f.line.clone()),
                after: Some(format!("{indent}{k} = {value}")),
            }
        }
        None => Edit {
            file: main_file.into(),
            key: d.key.into(),
            before: None,
            after: Some(format!("{} = {value}", d.key)),
        },
    }
}

/// The edits for a set of switches (`key`, on?). Off writes the item's off
/// value on the line in effect. On restores the line the newest applied
/// backup replaced, when that backup's line is still the one in effect;
/// otherwise it writes `on_value()`. Unchanged switches give no edit.
pub fn plan_set(
    dirs: &[DirState],
    backups: &[BackupInfo],
    changes: &[(String, bool)],
    main_file: &str,
) -> Result<Vec<Edit>, String> {
    let mut out = Vec::new();
    for (key, want) in changes {
        let Some(d) = dirs.iter().find(|d| norm(d.key) == norm(key)) else {
            return Err(format!("{key}: not a setting this card switches"));
        };
        if !d.known {
            return Err(format!("{}: not known to this MailScanner version", d.key));
        }
        if d.on() == *want {
            continue;
        }
        // The line an earlier switch replaced, when that switch's line is
        // still the one in effect and what it replaced is in the state
        // asked for: going back gives the exact bytes (rulesets, comments).
        // A line that was absent counts as the engine default.
        let current = d.found.as_ref().map(|f| f.line.clone());
        let default_on = first_word(&d.default) != d.item.off;
        let state_of = |l: &Option<String>| match l.as_deref() {
            Some(l) => first_word(live_kv(l).map(|kv| kv.1).unwrap_or("")) != d.item.off,
            None => default_on,
        };
        let earlier = backups.iter().filter(|b| b.applied).find_map(|b| {
            b.edits.iter().find(|e| {
                norm(&e.key) == norm(d.key)
                    && e.after == current
                    && e.before != e.after
                    && state_of(&e.before) == *want
            })
        });
        match earlier {
            Some(e) => out.push(Edit {
                file: e.file.clone(),
                key: d.key.into(),
                before: e.after.clone(),
                after: e.before.clone(),
            }),
            None if *want => out.push(set_edit(d, &d.on_value(), main_file)),
            None => out.push(set_edit(d, d.item.off, main_file)),
        }
    }
    Ok(out)
}

/// The edits that switch every active insertion off. Pure.
pub fn plan_off(dirs: &[DirState], main_file: &str) -> Vec<Edit> {
    dirs.iter()
        .filter(|d| d.on())
        .map(|d| match &d.found {
            Some(f) => {
                let (k, _) = live_kv(&f.line).unwrap_or((d.key, ""));
                let indent: String = f.line.chars().take_while(|c| c.is_whitespace()).collect();
                Edit {
                    file: f.file.clone(),
                    key: d.key.into(),
                    before: Some(f.line.clone()),
                    after: Some(format!("{indent}{k} = {}", d.item.off)),
                }
            }
            None => Edit {
                file: main_file.into(),
                key: d.key.into(),
                before: None,
                after: Some(format!("{} = {}", d.key, d.item.off)),
            },
        })
        .collect()
}

/// The edits that undo `edits` (restore: after → before).
pub fn plan_restore(edits: &[Edit]) -> Vec<Edit> {
    edits
        .iter()
        .map(|e| Edit {
            file: e.file.clone(),
            key: e.key.clone(),
            before: e.after.clone(),
            after: e.before.clone(),
        })
        .collect()
}

/// A footer template file, and its text now.
#[derive(Debug, Clone)]
pub struct Template {
    pub path: PathBuf,
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub struct State {
    pub dirs: Vec<DirState>,
    pub templates: Vec<Template>,
    pub backups: Vec<BackupInfo>,
    pub main_file: String,
    pub error: Option<String>,
}

impl State {
    /// MailScanner writes text into message bodies (the "footers" group).
    pub fn on(&self) -> bool {
        self.dirs.iter().any(|d| d.item.group == "body" && d.on())
    }
}

/// MailScanner.conf, then conf.d/*.conf in name order: `(catalog id, text)`.
fn conf_files(cat: &confcatalog::Catalog) -> Vec<(Entry, String)> {
    let mut out: Vec<(Entry, String)> = Vec::new();
    let mut confd: Vec<&Entry> = Vec::new();
    for e in &cat.entries {
        if e.id == "ms:MailScanner.conf" {
            if let Ok(t) = std::fs::read_to_string(&e.path) {
                out.insert(0, (e.clone(), t));
            }
        } else if e.rel.starts_with("conf.d/") && e.rel.ends_with(".conf") {
            confd.push(e);
        }
    }
    confd.sort_by(|a, b| a.rel.cmp(&b.rel));
    for e in confd {
        if let Ok(t) = std::fs::read_to_string(&e.path) {
            out.push((e.clone(), t));
        }
    }
    out
}

/// Every template the `Inline …` directives point at, and the same file name
/// in each sibling language directory of the reports tree.
pub fn template_paths(files: &[(String, String)], main_text: &str) -> Vec<PathBuf> {
    let mut keys: Vec<String> = Vec::new();
    for (_, t) in files {
        for l in t.lines() {
            if let Some((k, _)) = live_kv(l) {
                let n = norm(k);
                if n.starts_with("inline")
                    && (n.ends_with("signature") || n.ends_with("warning"))
                    && !keys.contains(&n)
                {
                    keys.push(n);
                }
            }
        }
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for k in keys {
        let Some(f) = effective(files, &k) else {
            continue;
        };
        let p = PathBuf::from(crate::mailscanner::expand_variables(main_text, &f.value));
        if !p.is_absolute() {
            continue;
        }
        let mut cands = vec![p.clone()];
        if let (Some(name), Some(root)) = (p.file_name(), p.parent().and_then(Path::parent)) {
            if let Ok(rd) = std::fs::read_dir(root) {
                let mut langs: Vec<PathBuf> = rd
                    .flatten()
                    .map(|d| d.path().join(name))
                    .filter(|q| q.is_file())
                    .collect();
                langs.sort();
                cands.extend(langs);
            }
        }
        for c in cands {
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

pub fn backup_root(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .join("footers")
}

#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub stamp: String,
    pub at: i64,
    pub was_on: Vec<String>,
    pub edits: Vec<Edit>,
    /// (original path, file name inside the backup)
    pub templates: Vec<(PathBuf, String)>,
    pub applied: bool,
}

impl BackupInfo {
    pub fn to_json(&self) -> Json {
        let opt = |s: &Option<String>| s.clone().map(Json::Str).unwrap_or(Json::Null);
        Json::Object(vec![
            ("stamp".into(), Json::str(&self.stamp)),
            ("at".into(), Json::Int(self.at)),
            (
                "was_on".into(),
                Json::Array(self.was_on.iter().map(Json::str).collect()),
            ),
            ("applied".into(), Json::Bool(self.applied)),
            (
                "edits".into(),
                Json::Array(
                    self.edits
                        .iter()
                        .map(|e| {
                            Json::Object(vec![
                                ("file".into(), Json::str(&e.file)),
                                ("key".into(), Json::str(&e.key)),
                                ("before".into(), opt(&e.before)),
                                ("after".into(), opt(&e.after)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "templates".into(),
                Json::Array(
                    self.templates
                        .iter()
                        .map(|(p, n)| {
                            Json::Object(vec![
                                ("path".into(), Json::str(p.display().to_string())),
                                ("copy".into(), Json::str(n)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_json(j: &Json) -> Option<BackupInfo> {
        let s = |v: Option<&Json>| v.and_then(Json::as_str).map(str::to_string);
        Some(BackupInfo {
            stamp: s(j.get("stamp"))?,
            at: j.get("at").and_then(Json::as_i64).unwrap_or(0),
            was_on: j
                .get("was_on")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            applied: matches!(j.get("applied"), Some(Json::Bool(true))),
            edits: j
                .get("edits")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|e| Edit {
                    file: e.str_field("file"),
                    key: e.str_field("key"),
                    before: s(e.get("before")),
                    after: s(e.get("after")),
                })
                .collect(),
            templates: j
                .get("templates")
                .and_then(Json::as_array)
                .unwrap_or(&[])
                .iter()
                .map(|t| (PathBuf::from(t.str_field("path")), t.str_field("copy")))
                .collect(),
        })
    }
}

fn valid_stamp(s: &str) -> bool {
    !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// The backups, newest first.
pub fn backups(config_file: &Path) -> Vec<BackupInfo> {
    let root = backup_root(config_file);
    let mut out: Vec<BackupInfo> = std::fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|d| {
            let name = d.file_name().to_string_lossy().to_string();
            if !valid_stamp(&name) {
                return None;
            }
            let t = std::fs::read_to_string(d.path().join("state.json")).ok()?;
            BackupInfo::from_json(&Json::parse(&t).ok()?)
        })
        .collect();
    out.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    out
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn stamp_of(at: i64) -> String {
    let d = crate::civil::Date::from_unix(at as u64);
    let s = at.rem_euclid(86_400);
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        d.y,
        d.m,
        d.d,
        s / 3600,
        s / 60 % 60,
        s % 60
    )
}

/// Everything the Settings card shows.
pub fn state(cfg: &Config, config_file: &Path) -> State {
    let cat = confcatalog::scan(cfg, config_file);
    let files = conf_files(&cat);
    let schema = msdefs::load(&crate::layout::resolve(cfg));
    let texts: Vec<(String, String)> = files
        .iter()
        .map(|(e, t)| (e.id.clone(), t.clone()))
        .collect();
    let main_text = texts.first().map(|(_, t)| t.clone()).unwrap_or_default();
    let error = files
        .is_empty()
        .then(|| format!("{} cannot be read", cfg.mailscanner_conf));
    let dirs = CATALOGUE
        .iter()
        .map(|item| {
            let (key, what) = (item.key, item.what);
            let def = schema.as_ref().and_then(|s| s.lookup(key));
            let known = schema.is_none() || def.is_some();
            let default = def
                .map(|d| d.default.clone())
                .unwrap_or_else(|| item.stock_default.into());
            let found = effective(&texts, key);
            let effective = found
                .as_ref()
                .map(|f| f.value.clone())
                .unwrap_or_else(|| default.clone());
            DirState {
                key,
                what,
                item: *item,
                known,
                found,
                default,
                effective,
            }
        })
        .collect();
    let templates = template_paths(&texts, &main_text)
        .into_iter()
        .map(|p| Template {
            text: std::fs::read_to_string(&p).ok(),
            path: p,
        })
        .collect();
    State {
        dirs,
        templates,
        backups: backups(config_file),
        main_file: "ms:MailScanner.conf".into(),
        error,
    }
}

/// What an off/restore did.
#[derive(Debug, Default)]
pub struct Report {
    pub ok: bool,
    pub lines: Vec<String>,
    pub saves: Vec<SaveReport>,
    pub stamp: Option<String>,
}

/// Group edits per file and turn them into save requests.
fn requests<'a>(
    entries: &'a [Entry],
    edits: &[Edit],
    reason: &'static str,
    reload: ReloadMode,
    lines: &mut Vec<String>,
) -> Vec<SaveRequest<'a>> {
    let mut reqs = Vec::new();
    for e in entries {
        let mine: Vec<&Edit> = edits.iter().filter(|x| x.file == e.id).collect();
        if mine.is_empty() {
            continue;
        }
        let Ok(mut text) = std::fs::read_to_string(&e.path) else {
            lines.push(format!("{}: cannot be read — skipped", e.rel));
            continue;
        };
        for x in mine {
            match apply_edit(&text, x.before.as_deref(), x.after.as_deref()) {
                Some(t) => {
                    lines.push(format!(
                        "{}: {} → {}",
                        e.rel,
                        x.before.as_deref().map(str::trim).unwrap_or("(not set)"),
                        x.after
                            .as_deref()
                            .map(str::trim)
                            .unwrap_or("(removed — the engine default applies)")
                    ));
                    text = t;
                }
                None => lines.push(format!("{}: {} changed since — left alone", e.rel, x.key)),
            }
        }
        reqs.push(SaveRequest {
            entry: e,
            new_text: text,
            lint: LintMode::Auto,
            reload,
            reason,
            expect_mtime: None,
        });
    }
    reqs
}

fn describe(saves: &[SaveReport], lines: &mut Vec<String>) -> bool {
    let mut ok = true;
    for r in saves {
        if let Some(e) = &r.error {
            ok = false;
            // save_many refuses the whole set with one reason per file
            let l = format!("✗ not saved — {e}");
            if !lines.contains(&l) {
                lines.push(l);
            }
        }
        if let Some(v) = &r.validation {
            if !v.ok {
                lines.extend(v.problems.iter().map(|p| format!("  {p}")));
            }
        }
    }
    if let Some(r) = saves.iter().find(|r| r.reloaded.action != "none") {
        lines.push(format!(
            "MailScanner {}: {}",
            r.reloaded.action,
            if r.reloaded.ok { "ok" } else { "FAILED" }
        ));
    }
    ok
}

pub fn switch_off(cfg: &Config, config_file: &Path, dry: bool) -> Report {
    switch_off_with(
        cfg,
        config_file,
        &crate::layout::resolve(cfg).bin,
        ReloadMode::Auto,
        dry,
    )
}

/// "Remove footers": every active setting of the body group off.
pub fn switch_off_with(
    cfg: &Config,
    config_file: &Path,
    bin: &Path,
    reload: ReloadMode,
    dry: bool,
) -> Report {
    let st = state(cfg, config_file);
    let changes: Vec<(String, bool)> = st
        .dirs
        .iter()
        .filter(|d| d.item.group == "body" && d.on())
        .map(|d| (d.key.to_string(), false))
        .collect();
    if changes.is_empty() && st.error.is_none() {
        return Report {
            ok: true,
            lines: vec![
                "MailScanner adds nothing to message bodies already — nothing to change".into(),
            ],
            ..Default::default()
        };
    }
    apply_with(cfg, config_file, bin, reload, &changes, dry)
}

/// Switch settings on or off: backup, then one checked save of every file.
pub fn apply(cfg: &Config, config_file: &Path, changes: &[(String, bool)], dry: bool) -> Report {
    apply_with(
        cfg,
        config_file,
        &crate::layout::resolve(cfg).bin,
        ReloadMode::Auto,
        changes,
        dry,
    )
}

pub fn apply_with(
    cfg: &Config,
    config_file: &Path,
    bin: &Path,
    reload: ReloadMode,
    changes: &[(String, bool)],
    dry: bool,
) -> Report {
    let st = state(cfg, config_file);
    let mut rep = Report::default();
    if let Some(e) = st.error {
        rep.lines.push(e);
        return rep;
    }
    let edits = match plan_set(&st.dirs, &st.backups, changes, &st.main_file) {
        Ok(e) => e,
        Err(e) => {
            rep.lines.push(e);
            return rep;
        }
    };
    if edits.is_empty() {
        rep.ok = true;
        rep.lines
            .push("every switch is already as asked — nothing to change".into());
        return rep;
    }
    let summary: Vec<String> = changes
        .iter()
        .filter(|(k, _)| edits.iter().any(|e| norm(&e.key) == norm(k)))
        .map(|(k, on)| {
            format!(
                "{} {}",
                item(k).map(|i| i.key).unwrap_or(k),
                if *on { "on" } else { "off" }
            )
        })
        .collect();
    let cat = confcatalog::scan(cfg, config_file);
    if dry {
        let _ = requests(&cat.entries, &edits, "switches", reload, &mut rep.lines);
        rep.lines.push("dry run: nothing written".into());
        rep.ok = true;
        return rep;
    }
    // the backup first: settings as they are, and every template
    let at = now();
    let stamp = unique_stamp(&backup_root(config_file), at);
    let dir = backup_root(config_file).join(&stamp);
    let mut info = BackupInfo {
        stamp: stamp.clone(),
        at,
        was_on: summary,
        edits: edits.clone(),
        templates: Vec::new(),
        applied: false,
    };
    let write_backup = |info: &BackupInfo| -> std::io::Result<()> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        let _ = std::fs::set_permissions(
            backup_root(config_file),
            std::fs::Permissions::from_mode(0o700),
        );
        std::fs::write(dir.join("state.json"), info.to_json().to_string())
    };
    for (i, t) in st.templates.iter().enumerate() {
        if let Some(text) = &t.text {
            let name = format!("template-{i}");
            if write_backup(&info)
                .and_then(|_| std::fs::write(dir.join(&name), text))
                .is_ok()
            {
                info.templates.push((t.path.clone(), name));
            }
        }
    }
    if let Err(e) = write_backup(&info) {
        rep.lines.push(format!(
            "cannot write the backup in {}: {e} — nothing changed",
            dir.display()
        ));
        return rep;
    }
    rep.lines.push(format!(
        "backup {stamp}: {} setting(s), {} footer template(s)",
        info.edits.len(),
        info.templates.len()
    ));
    let reqs = requests(&cat.entries, &edits, "switches", reload, &mut rep.lines);
    match confsave::save_many_with(cfg, reqs, bin) {
        Ok(saves) => {
            rep.ok = describe(&saves, &mut rep.lines);
            rep.saves = saves;
        }
        Err(e) => rep.lines.push(format!("✗ {e}")),
    }
    if rep.ok {
        info.applied = true;
        let _ = write_backup(&info);
        prune(config_file);
    } else {
        rep.lines.push(format!("backup {stamp} kept, unused"));
    }
    rep.stamp = Some(stamp);
    rep
}

/// A backup name not taken yet: two changes in the same second get `-2`, `-3`…
/// (names still sort by time: `…-101500` < `…-101500-2`).
fn unique_stamp(root: &Path, at: i64) -> String {
    let base = stamp_of(at);
    (1..)
        .map(|n| {
            if n == 1 {
                base.clone()
            } else {
                format!("{base}-{n}")
            }
        })
        .find(|s| !root.join(s).exists())
        .unwrap_or(base)
}

fn prune(config_file: &Path) {
    for b in backups(config_file).into_iter().skip(KEEP_BACKUPS) {
        let _ = std::fs::remove_dir_all(backup_root(config_file).join(&b.stamp));
    }
}

pub fn restore(cfg: &Config, config_file: &Path, stamp: &str, dry: bool) -> Report {
    restore_with(
        cfg,
        config_file,
        stamp,
        &crate::layout::resolve(cfg).bin,
        ReloadMode::Auto,
        dry,
    )
}

pub fn restore_with(
    cfg: &Config,
    config_file: &Path,
    stamp: &str,
    bin: &Path,
    reload: ReloadMode,
    dry: bool,
) -> Report {
    let mut rep = Report {
        stamp: Some(stamp.to_string()),
        ..Default::default()
    };
    if !valid_stamp(stamp) {
        rep.lines.push("bad backup name".into());
        return rep;
    }
    let dir = backup_root(config_file).join(stamp);
    let Some(info) = std::fs::read_to_string(dir.join("state.json"))
        .ok()
        .and_then(|t| Json::parse(&t).ok())
        .and_then(|j| BackupInfo::from_json(&j))
    else {
        rep.lines.push(format!("backup {stamp} not found"));
        return rep;
    };
    let cat = confcatalog::scan(cfg, config_file);
    let mut reqs = requests(
        &cat.entries,
        &plan_restore(&info.edits),
        "footers restored",
        reload,
        &mut rep.lines,
    );
    // templates that differ from the backup copy go back too
    let mut direct: Vec<(PathBuf, String)> = Vec::new();
    for (path, name) in &info.templates {
        let Ok(saved) = std::fs::read_to_string(dir.join(name)) else {
            continue;
        };
        if std::fs::read_to_string(path).ok().as_deref() == Some(saved.as_str()) {
            continue;
        }
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        match cat
            .entries
            .iter()
            .find(|e| std::fs::canonicalize(&e.path).ok().as_ref() == Some(&canon))
        {
            Some(e) => {
                rep.lines.push(format!("{}: footer text restored", e.rel));
                reqs.push(SaveRequest {
                    entry: e,
                    new_text: saved,
                    lint: LintMode::Auto,
                    reload,
                    reason: "footers restored",
                    expect_mtime: None,
                });
            }
            None => {
                rep.lines
                    .push(format!("{}: footer text restored", path.display()));
                direct.push((path.clone(), saved));
            }
        }
    }
    if dry {
        rep.lines.push("dry run: nothing written".into());
        rep.ok = true;
        return rep;
    }
    if reqs.is_empty() && direct.is_empty() {
        rep.ok = true;
        rep.lines.push(
            "nothing to restore — the settings and texts are already as in the backup".into(),
        );
        return rep;
    }
    for (p, t) in &direct {
        let tmp = p.with_extension("msfe-ng.tmp");
        if let Err(e) = std::fs::write(&tmp, t).and_then(|_| std::fs::rename(&tmp, p)) {
            rep.lines.push(format!("✗ {}: {e}", p.display()));
        }
    }
    match confsave::save_many_with(cfg, reqs, bin) {
        Ok(saves) => {
            rep.ok = describe(&saves, &mut rep.lines);
            rep.saves = saves;
        }
        Err(e) => rep.lines.push(format!("✗ {e}")),
    }
    rep
}

/// The state as the Settings card reads it.
pub fn state_json(st: &State) -> Json {
    let opt = |s: Option<&str>| s.map(Json::str).unwrap_or(Json::Null);
    Json::Object(vec![
        (
            "on".into(),
            Json::Bool(st.dirs.iter().any(|d| d.item.group == "body" && d.on())),
        ),
        ("error".into(), opt(st.error.as_deref())),
        (
            "groups".into(),
            Json::Array(
                GROUPS
                    .iter()
                    .map(|(id, title)| {
                        Json::Object(vec![
                            ("id".into(), Json::str(*id)),
                            ("title".into(), Json::str(*title)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "directives".into(),
            Json::Array(
                st.dirs
                    .iter()
                    .map(|d| {
                        Json::Object(vec![
                            ("key".into(), Json::str(d.key)),
                            ("group".into(), Json::str(d.item.group)),
                            ("what".into(), Json::str(d.what)),
                            ("caution".into(), Json::str(d.item.caution)),
                            ("known".into(), Json::Bool(d.known)),
                            ("on".into(), Json::Bool(d.on())),
                            ("rules".into(), Json::Bool(d.rules())),
                            ("off_value".into(), Json::str(d.item.off)),
                            ("value".into(), Json::str(&d.effective)),
                            ("default".into(), Json::str(&d.default)),
                            (
                                "file".into(),
                                opt(d.found.as_ref().map(|f| f.file.as_str())),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "templates".into(),
            Json::Array(
                st.templates
                    .iter()
                    .map(|t| {
                        Json::Object(vec![
                            ("path".into(), Json::str(t.path.display().to_string())),
                            (
                                "text".into(),
                                opt(t.text.as_deref().map(|x| {
                                    if x.len() > 4000 {
                                        &x[..x
                                            .char_indices()
                                            .nth(4000)
                                            .map(|(i, _)| i)
                                            .unwrap_or(x.len())]
                                    } else {
                                        x
                                    }
                                })),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "backups".into(),
            Json::Array(st.backups.iter().map(BackupInfo::to_json).collect()),
        ),
    ])
}

pub fn report_json(r: &Report) -> Json {
    Json::Object(vec![
        ("ok".into(), Json::Bool(r.ok)),
        (
            "stamp".into(),
            r.stamp.clone().map(Json::Str).unwrap_or(Json::Null),
        ),
        (
            "transcript".into(),
            Json::Array(r.lines.iter().map(Json::str).collect()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(main: &str, confd: &str) -> Vec<(String, String)> {
        vec![
            ("ms:MailScanner.conf".into(), main.into()),
            ("ms:conf.d/20-site.conf".into(), confd.into()),
        ]
    }

    #[test]
    fn effective_value_is_the_last_live_line_in_read_order() {
        let f = files("#Sign Clean Messages = no\nSign Clean Messages = yes\nsign clean messages=%rules-dir%/sign.rules\n", "");
        let e = effective(&f, "Sign Clean Messages").unwrap();
        assert_eq!(e.file, "ms:MailScanner.conf");
        assert_eq!(e.value, "%rules-dir%/sign.rules");
        let f = files("Sign Clean Messages = yes\n", "SignCleanMessages = no\n");
        assert_eq!(
            effective(&f, "Sign Clean Messages").unwrap().file,
            "ms:conf.d/20-site.conf"
        );
        assert!(effective(&f, "Mark Unscanned Messages").is_none());
    }

    fn dir(key: &'static str, found: Option<Found>, known: bool) -> DirState {
        let effective = found
            .as_ref()
            .map(|f| f.value.clone())
            .unwrap_or_else(|| "yes".into());
        DirState {
            key,
            what: "",
            item: *item(key).unwrap(),
            known,
            found,
            default: "yes".into(),
            effective,
        }
    }

    #[test]
    fn plan_off_edits_the_effective_line_or_appends() {
        let dirs = vec![
            dir(
                "Sign Clean Messages",
                Some(Found {
                    file: "ms:conf.d/x.conf".into(),
                    line: "  sign clean messages = %rules-dir%/s.rules".into(),
                    value: "%rules-dir%/s.rules".into(),
                }),
                true,
            ),
            dir("Mark Unscanned Messages", None, true),
            dir(
                "Mark Infected Messages",
                Some(Found {
                    file: "ms:MailScanner.conf".into(),
                    line: "Mark Infected Messages = no".into(),
                    value: "no".into(),
                }),
                true,
            ),
        ];
        let mut unknown = dir("Mark Unscanned Messages", None, false);
        unknown.key = "Mark Unscanned Messages";
        let e = plan_off(&dirs, "ms:MailScanner.conf");
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].after.as_deref(), Some("  sign clean messages = no"));
        assert_eq!(
            e[1],
            Edit {
                file: "ms:MailScanner.conf".into(),
                key: "Mark Unscanned Messages".into(),
                before: None,
                after: Some("Mark Unscanned Messages = no".into())
            }
        );
        assert!(plan_off(&[unknown], "ms:MailScanner.conf").is_empty());
    }

    #[test]
    fn edits_and_their_inverse_give_back_the_original_bytes() {
        let orig =
            "%report-dir% = /r/en\nSign Clean Messages = %rules-dir%/s.rules\nMax Children = 5\n";
        let edits = vec![
            Edit {
                file: "f".into(),
                key: "Sign Clean Messages".into(),
                before: Some("Sign Clean Messages = %rules-dir%/s.rules".into()),
                after: Some("Sign Clean Messages = no".into()),
            },
            Edit {
                file: "f".into(),
                key: "Mark Unscanned Messages".into(),
                before: None,
                after: Some("Mark Unscanned Messages = no".into()),
            },
        ];
        let mut t = orig.to_string();
        for e in &edits {
            t = apply_edit(&t, e.before.as_deref(), e.after.as_deref()).unwrap();
        }
        assert_eq!(t, "%report-dir% = /r/en\nSign Clean Messages = no\nMax Children = 5\nMark Unscanned Messages = no\n");
        for e in plan_restore(&edits).iter().rev() {
            t = apply_edit(&t, e.before.as_deref(), e.after.as_deref()).unwrap();
        }
        assert_eq!(t, orig);
        // a line edited by hand since: left alone
        assert!(apply_edit(
            "Sign Clean Messages = maybe\n",
            Some("Sign Clean Messages = no"),
            Some("x")
        )
        .is_none());
    }

    #[test]
    fn backup_state_round_trips() {
        let b = BackupInfo {
            stamp: "20260930-101500".into(),
            at: 1_790_763_300,
            was_on: vec!["Sign Clean Messages".into()],
            edits: vec![Edit {
                file: "ms:MailScanner.conf".into(),
                key: "Sign Clean Messages".into(),
                before: None,
                after: Some("Sign Clean Messages = no".into()),
            }],
            templates: vec![(PathBuf::from("/r/en/inline.sig.txt"), "template-0".into())],
            applied: true,
        };
        let back = BackupInfo::from_json(&Json::parse(&b.to_json().to_string()).unwrap()).unwrap();
        assert_eq!(back.edits, b.edits);
        assert_eq!(back.templates, b.templates);
        assert!(back.applied && back.stamp == b.stamp && back.was_on == b.was_on);
        assert_eq!(stamp_of(1_790_763_300), "20260930-101500");
        assert!(valid_stamp("20260930-101500") && !valid_stamp("../x"));
    }

    /// The whole cycle on a tree like the engine's: off, then restore gives
    /// back every file byte for byte, templates included.
    #[test]
    fn off_then_restore_round_trip() {
        let base = std::env::temp_dir().join(format!("msfe-footers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        let rep = base.join("reports");
        for d in ["conf.d", "rules"] {
            std::fs::create_dir_all(etc.join(d)).unwrap();
        }
        for l in ["en", "it"] {
            std::fs::create_dir_all(rep.join(l)).unwrap();
            std::fs::write(
                rep.join(l).join("inline.sig.txt"),
                format!("scanned ({l})\n"),
            )
            .unwrap();
        }
        let main = format!(
            "%report-dir% = {}/en\n%etc-dir% = {}\nMax Children = 5\nSign Clean Messages = yes\nInline Text Signature = %report-dir%/inline.sig.txt\n",
            rep.display(),
            etc.display()
        );
        let confd = "# site\nMark Infected Messages = %rules-dir%/mark.rules\n";
        std::fs::write(etc.join("MailScanner.conf"), &main).unwrap();
        std::fs::write(etc.join("conf.d/20-site.conf"), confd).unwrap();
        let msfe = base.join("etc/msfe-ng");
        std::fs::create_dir_all(&msfe).unwrap();
        let conf = msfe.join("config.toml");
        std::fs::write(&conf, "").unwrap();
        let bin = base.join("fake-mailscanner");
        std::fs::write(&bin, "#!/bin/sh\necho \"Reading configuration file\"\necho \"SpamAssassin reported no errors.\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };

        let st = state(&cfg, &conf);
        assert!(st.on());
        assert_eq!(st.templates.len(), 2, "{:?}", st.templates);
        let dry = switch_off_with(&cfg, &conf, &bin, ReloadMode::Skip, true);
        assert!(dry.ok);
        assert_eq!(
            std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap(),
            main
        );

        let r = switch_off_with(&cfg, &conf, &bin, ReloadMode::Skip, false);
        assert!(r.ok, "{:?}", r.lines);
        let now = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
        // every body insertion that was on, by line or by stock default
        for l in [
            "Sign Clean Messages = no\n",
            "Mark Unscanned Messages = no\n",
            "Highlight Phishing Fraud = no\n",
            "Highlight Mailto Phishing = no\n",
        ] {
            assert!(now.contains(l), "{l} missing in {now}");
        }
        assert!(
            !now.contains("Highlight Hidden URLs"),
            "stock default is already no: {now}"
        );
        assert!(std::fs::read_to_string(etc.join("conf.d/20-site.conf"))
            .unwrap()
            .contains("Mark Infected Messages = no"));
        assert!(!state(&cfg, &conf).on());
        let b = backups(&conf);
        assert_eq!(b.len(), 1);
        assert!(b[0].applied && b[0].templates.len() == 2);

        // someone rewords a footer meanwhile; restore brings back the original too
        std::fs::write(rep.join("it/inline.sig.txt"), "changed\n").unwrap();
        let r = restore_with(&cfg, &conf, &b[0].stamp, &bin, ReloadMode::Skip, false);
        assert!(r.ok, "{:?}", r.lines);
        assert_eq!(
            std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap(),
            main
        );
        assert_eq!(
            std::fs::read_to_string(etc.join("conf.d/20-site.conf")).unwrap(),
            confd
        );
        assert_eq!(
            std::fs::read_to_string(rep.join("it/inline.sig.txt")).unwrap(),
            "scanned (it)\n"
        );
        let again = switch_off_with(&cfg, &conf, &bin, ReloadMode::Skip, false);
        assert!(again.ok);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn values_read_as_their_first_word() {
        assert_eq!(first_word("no # end"), "no");
        assert_eq!(first_word(" Start "), "start");
        assert!(is_ruleset("%rules-dir%/external.message.rules"));
        assert!(is_ruleset("/etc/MailScanner/rules/sign.rules # per domain"));
        assert!(!is_ruleset("yes"));
        let mut d = dir(
            "Scanned Modify Subject",
            Some(Found {
                file: "ms:MailScanner.conf".into(),
                line: "Scanned Modify Subject = no # end".into(),
                value: "no # end".into(),
            }),
            true,
        );
        assert!(!d.on());
        d.effective = "end".into();
        assert!(d.on());
    }

    #[test]
    fn web_bugs_switch_is_inverted() {
        let mut d = dir(
            "Allow WebBugs",
            Some(Found {
                file: "ms:MailScanner.conf".into(),
                line: "Allow WebBugs = disarm".into(),
                value: "disarm".into(),
            }),
            true,
        );
        assert!(d.on(), "disarm replaces web bugs: the change is on");
        let e = plan_set(
            std::slice::from_ref(&d),
            &[],
            &[("Allow WebBugs".into(), false)],
            "ms:MailScanner.conf",
        )
        .unwrap();
        assert_eq!(e[0].after.as_deref(), Some("Allow WebBugs = yes"));
        d.effective = "yes".into();
        d.found = Some(Found {
            file: "ms:MailScanner.conf".into(),
            line: "Allow WebBugs = yes".into(),
            value: "yes".into(),
        });
        d.default = "convert".into();
        let e = plan_set(
            &[d],
            &[],
            &[("allow webbugs".into(), true)],
            "ms:MailScanner.conf",
        )
        .unwrap();
        assert_eq!(
            e[0].after.as_deref(),
            Some("Allow WebBugs = convert"),
            "the engine default"
        );
    }

    #[test]
    fn plan_set_restores_the_earlier_line_or_writes_the_default() {
        let main = "ms:MailScanner.conf";
        let rules = Found {
            file: main.into(),
            line: "External Message Warning = %rules-dir%/external.message.rules".into(),
            value: "%rules-dir%/external.message.rules".into(),
        };
        let d = dir("External Message Warning", Some(rules.clone()), true);
        assert!(d.on() && d.rules());
        let off = plan_set(
            std::slice::from_ref(&d),
            &[],
            &[("External Message Warning".into(), false)],
            main,
        )
        .unwrap();
        assert_eq!(
            off[0].after.as_deref(),
            Some("External Message Warning = no")
        );
        // now off; the backup of that switch-off brings the ruleset line back
        let b = BackupInfo {
            stamp: "1".into(),
            at: 0,
            was_on: vec![],
            edits: off.clone(),
            templates: vec![],
            applied: true,
        };
        let now_off = dir(
            "External Message Warning",
            Some(Found {
                file: main.into(),
                line: "External Message Warning = no".into(),
                value: "no".into(),
            }),
            true,
        );
        let on = plan_set(
            std::slice::from_ref(&now_off),
            std::slice::from_ref(&b),
            &[("External Message Warning".into(), true)],
            main,
        )
        .unwrap();
        assert_eq!(on[0].after.as_deref(), Some(rules.line.as_str()));
        // no backup: the default, or the fallback when the default is off
        let mut plain = now_off.clone();
        plain.default = "no".into();
        let on = plan_set(
            &[plain],
            &[],
            &[("External Message Warning".into(), true)],
            main,
        )
        .unwrap();
        assert_eq!(
            on[0].after.as_deref(),
            Some("External Message Warning = yes")
        );
        let mut subj = dir(
            "Spam Modify Subject",
            Some(Found {
                file: "ms:conf.d/x.conf".into(),
                line: "Spam Modify Subject = no".into(),
                value: "no".into(),
            }),
            true,
        );
        subj.default = "no".into();
        let on = plan_set(&[subj], &[], &[("Spam Modify Subject".into(), true)], main).unwrap();
        assert_eq!(
            (on[0].file.as_str(), on[0].after.as_deref()),
            ("ms:conf.d/x.conf", Some("Spam Modify Subject = start"))
        );
        // unchanged switches give nothing; unknown keys and versions are refused
        assert!(plan_set(
            std::slice::from_ref(&d),
            &[],
            &[("External Message Warning".into(), true)],
            main
        )
        .unwrap()
        .is_empty());
        assert!(plan_set(&[d], &[], &[("Allow Script Tags".into(), true)], main).is_err());
        let gone = dir("Zip Attachments", None, false);
        assert!(plan_set(&[gone], &[], &[("Zip Attachments".into(), true)], main).is_err());
    }

    #[test]
    fn switches_round_trip_across_files() {
        let base = std::env::temp_dir().join(format!("msfe-switches-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("conf.d")).unwrap();
        let main = "Max Children = 5\nSpam Modify Subject = start\nScanned Modify Subject = no # end\nExternal Message Warning = %rules-dir%/external.message.rules\nAllow WebBugs = disarm\nUse TNEF Contents = replace\n";
        let confd = "Add Envelope From Header = yes\n";
        std::fs::write(etc.join("MailScanner.conf"), main).unwrap();
        std::fs::write(etc.join("conf.d/10-site.conf"), confd).unwrap();
        let msfe = base.join("etc/msfe-ng");
        std::fs::create_dir_all(&msfe).unwrap();
        let conf = msfe.join("config.toml");
        std::fs::write(&conf, "").unwrap();
        let bin = base.join("fake-mailscanner");
        std::fs::write(&bin, "#!/bin/sh\necho \"Reading configuration file\"\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        let flip = |on: bool| -> Vec<(String, bool)> {
            [
                "Spam Modify Subject",
                "External Message Warning",
                "Allow WebBugs",
                "Add Envelope From Header",
            ]
            .iter()
            .map(|k| (k.to_string(), on))
            .chain(std::iter::once(("Scanned Modify Subject".to_string(), !on)))
            .collect()
        };
        let dry = apply_with(&cfg, &conf, &bin, ReloadMode::Skip, &flip(false), true);
        assert!(dry.ok, "{:?}", dry.lines);
        assert_eq!(
            std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap(),
            main
        );
        let r = apply_with(&cfg, &conf, &bin, ReloadMode::Skip, &flip(false), false);
        assert!(r.ok, "{:?}", r.lines);
        let now = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
        for l in [
            "Spam Modify Subject = no",
            "External Message Warning = no",
            "Allow WebBugs = yes",
            "Scanned Modify Subject = start",
        ] {
            assert!(now.contains(l), "{l} in {now}");
        }
        assert_eq!(
            std::fs::read_to_string(etc.join("conf.d/10-site.conf")).unwrap(),
            "Add Envelope From Header = no\n"
        );
        // back on (and Scanned back off): the earlier lines return
        let r = apply_with(&cfg, &conf, &bin, ReloadMode::Skip, &flip(true), false);
        assert!(r.ok, "{:?}", r.lines);
        let now = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
        assert!(
            now.contains("External Message Warning = %rules-dir%/external.message.rules"),
            "{now}"
        );
        assert!(
            now.contains("Allow WebBugs = disarm") && now.contains("Spam Modify Subject = start"),
            "{now}"
        );
        // every line as it was, the "# end" comment included
        assert_eq!(now, main);
        assert_eq!(
            std::fs::read_to_string(etc.join("conf.d/10-site.conf")).unwrap(),
            confd
        );
        // two changes in the same second keep two backups
        assert_eq!(backups(&conf).iter().filter(|b| b.applied).count(), 2);
        let bad = apply_with(
            &cfg,
            &conf,
            &bin,
            ReloadMode::Skip,
            &[("Allow Script Tags".into(), true)],
            false,
        );
        assert!(!bad.ok);
        let _ = std::fs::remove_dir_all(&base);
    }
}
