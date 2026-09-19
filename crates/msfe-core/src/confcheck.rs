//! Cross-file consistency of a MailScanner etc tree — the things `--lint`
//! does not say: every path a directive names exists, every ruleset parses
//! and fits its directive, the virus scanners and spam lists named are
//! defined, filename patterns compile, `conf.d` fragments and phishing lists
//! parse, unknown directives (typos) and files the scanning user cannot
//! read. Works on the live tree or a staged copy; findings always name
//! catalog ids.

use crate::conftest::{Finding, Level, Source};
use crate::{conffile, engine, mailscanner, msdefs, msgrammar, rulefile, Config};
use std::path::{Path, PathBuf};

pub struct Tree<'a> {
    pub etc: &'a Path,
    /// The text of `MailScanner.conf` in that tree.
    pub conf: &'a str,
}

const FILENAME_RULE_KEYS: [&str; 4] = [
    "Filename Rules",
    "Filetype Rules",
    "Archives: Filename Rules",
    "Archives: Filetype Rules",
];

fn id_of(etc: &Path, p: &Path) -> Option<String> {
    p.strip_prefix(etc)
        .ok()
        .map(|r| format!("ms:{}", r.display()))
}

fn finding(level: Level, msg: impl Into<String>) -> Finding {
    Finding::new(level, Source::Msfe, msg)
}

fn is_ruleset(expanded: &str, etc: &Path) -> bool {
    expanded.ends_with(".rules")
        || (Path::new(expanded).starts_with(etc.join("rules")) && Path::new(expanded).is_file())
}

fn executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Every `key = value` of the conf (variables excluded), value expanded.
fn entries(conf: &str) -> Vec<(String, String, String)> {
    conffile::parse(conf)
        .into_iter()
        .filter_map(|l| match l {
            conffile::ConfLine::Entry { key, value } if !key.starts_with('%') => {
                let exp = mailscanner::expand_variables(conf, &value);
                Some((key, value, exp))
            }
            _ => None,
        })
        .collect()
}

/// The value(s) a directive resolves to: the value itself, or every rule's
/// value when it names a ruleset.
fn values_of(expanded: &str, etc: &Path) -> Vec<String> {
    if is_ruleset(expanded, etc) {
        std::fs::read_to_string(expanded)
            .map(|t| {
                rulefile::rules_of(&rulefile::parse(&t))
                    .into_iter()
                    .map(|r| r.value)
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![expanded.to_string()]
    }
}

fn yes_no_ok(v: &str, words: &[String]) -> bool {
    let l = v.trim().to_ascii_lowercase();
    words.contains(&l)
        || ["yes", "no", "1", "0", "on", "off", "true", "false"].contains(&l.as_str())
}

fn number_ok(v: &str) -> bool {
    let t = v.trim().trim_end_matches(['k', 'K', 'm', 'M', 'g', 'G']);
    t.parse::<f64>().is_ok()
}

fn check_rulesets(tree: &Tree, schema: Option<&msdefs::Schema>, out: &mut Vec<Finding>) {
    for (key, _, exp) in entries(tree.conf) {
        if !is_ruleset(&exp, tree.etc) {
            continue;
        }
        let path = Path::new(&exp);
        let id = id_of(tree.etc, path).unwrap_or_else(|| exp.clone());
        let Ok(text) = std::fs::read_to_string(path) else {
            out.push(
                finding(Level::Fail, format!("{key}: ruleset {exp} does not exist"))
                    .key(key)
                    .file(id),
            );
            continue;
        };
        let def = schema.and_then(|s| s.lookup(&key));
        if let Some(d) = def {
            if !d.ruleset_ok() {
                out.push(
                    finding(
                        Level::Fail,
                        format!("{key} cannot take a ruleset, only a single value"),
                    )
                    .key(key.clone())
                    .file("ms:MailScanner.conf"),
                );
            }
        }
        let mut has_default = false;
        for (i, line) in text.lines().enumerate() {
            match rulefile::parse_line(line) {
                rulefile::Line::Unparsed(u) => out.push(
                    finding(
                        Level::Fail,
                        format!(
                            "line {} is not a rule: {}",
                            i + 1,
                            u.chars().take(60).collect::<String>()
                        ),
                    )
                    .file(id.clone())
                    .line(i as u32 + 1),
                ),
                rulefile::Line::Rule(r) => {
                    if r.pattern.eq_ignore_ascii_case("default") {
                        has_default = true;
                    }
                    if let Some(d) = def {
                        let bad = match d.ty {
                            msdefs::Ty::YesNo => !yes_no_ok(&r.value, &d.words),
                            msdefs::Ty::Number => !number_ok(&r.value),
                            _ => false,
                        };
                        if bad {
                            out.push(
                                finding(
                                    Level::Fail,
                                    format!(
                                        "line {}: '{}' is not a {} value for {key}",
                                        i + 1,
                                        r.value,
                                        d.ty.as_str()
                                    ),
                                )
                                .file(id.clone())
                                .line(i as u32 + 1)
                                .key(key.clone()),
                            );
                        }
                    }
                }
                _ => {}
            }
        }
        if !has_default {
            out.push(finding(Level::Warn, format!("{key}: ruleset has no 'default' rule — mail matching no rule gets the engine default")).file(id).key(key));
        }
    }
}

fn check_paths(tree: &Tree, schema: Option<&msdefs::Schema>, out: &mut Vec<Finding>) {
    for (key, _, exp) in entries(tree.conf) {
        if exp.is_empty() || is_ruleset(&exp, tree.etc) {
            continue;
        }
        let Some(d) = schema.and_then(|s| s.lookup(&key)) else {
            // no schema: only bare absolute paths are judged, softly
            if schema.is_none()
                && exp.starts_with('/')
                && !exp.contains(' ')
                && !Path::new(&exp).exists()
            {
                out.push(
                    finding(Level::Warn, format!("{key}: {exp} does not exist"))
                        .key(key)
                        .file("ms:MailScanner.conf"),
                );
            }
            continue;
        };
        let p = Path::new(&exp);
        match d.ty {
            msdefs::Ty::File => {
                if !p.exists() {
                    out.push(
                        finding(Level::Fail, format!("{key}: file {exp} does not exist"))
                            .key(key)
                            .file("ms:MailScanner.conf"),
                    );
                }
            }
            msdefs::Ty::Dir => {
                if !p.is_dir() {
                    out.push(
                        finding(
                            Level::Warn,
                            format!(
                                "{key}: directory {exp} does not exist (the engine may create it)"
                            ),
                        )
                        .key(key)
                        .file("ms:MailScanner.conf"),
                    );
                }
            }
            msdefs::Ty::Command => {
                let first = exp.split_whitespace().next().unwrap_or("");
                if first.starts_with('/') && !executable(Path::new(first)) {
                    out.push(
                        finding(Level::Fail, format!("{key}: {first} is not an executable"))
                            .key(key)
                            .file("ms:MailScanner.conf"),
                    );
                }
            }
            _ => {}
        }
    }
}

fn check_virus_scanners(tree: &Tree, out: &mut Vec<Finding>) {
    let Some(v) = mailscanner::get_directive(tree.conf, "Virus Scanners") else {
        return;
    };
    let exp = mailscanner::expand_variables(tree.conf, v);
    let defs = std::fs::read_to_string(tree.etc.join("virus.scanners.conf"))
        .map(|t| msgrammar::parse_virus_scanners(&t))
        .ok();
    for name in values_of(&exp, tree.etc)
        .iter()
        .flat_map(|v| v.split_whitespace().map(str::to_string).collect::<Vec<_>>())
    {
        if ["none", "auto"].contains(&name.as_str()) {
            continue;
        }
        let Some(t) = &defs else {
            out.push(
                finding(
                    Level::Fail,
                    "Virus Scanners is set but virus.scanners.conf is missing",
                )
                .key("Virus Scanners")
                .file("ms:virus.scanners.conf"),
            );
            return;
        };
        match t.rows().into_iter().find(|r| r.name == name) {
            None => out.push(
                finding(
                    Level::Fail,
                    format!(
                        "Virus Scanners names '{name}', which virus.scanners.conf does not define"
                    ),
                )
                .key("Virus Scanners")
                .file("ms:virus.scanners.conf"),
            ),
            Some(r) => {
                if !executable(Path::new(&r.wrapper)) {
                    out.push(
                        finding(
                            Level::Fail,
                            format!(
                                "scanner '{name}': wrapper {} is not an executable",
                                r.wrapper
                            ),
                        )
                        .file("ms:virus.scanners.conf"),
                    );
                } else if !Path::new(&r.dir).exists() {
                    out.push(
                        finding(
                            Level::Warn,
                            format!("scanner '{name}': install dir {} does not exist", r.dir),
                        )
                        .file("ms:virus.scanners.conf"),
                    );
                } else {
                    out.push(
                        finding(
                            Level::Ok,
                            format!("scanner '{name}' defined ({})", r.wrapper),
                        )
                        .file("ms:virus.scanners.conf"),
                    );
                }
            }
        }
    }
}

fn check_spam_lists(tree: &Tree, out: &mut Vec<Finding>) {
    let defs_path = engine::spam_list_definitions(tree.conf, &tree.etc.join("MailScanner.conf"));
    let defs = std::fs::read_to_string(&defs_path)
        .map(|t| engine::parse_rbl_definitions(&t))
        .unwrap_or_default();
    let defs_id = id_of(tree.etc, &defs_path).unwrap_or_else(|| "ms:spam.lists.conf".into());
    for key in ["Spam List", "Spam Domain List"] {
        let Some(v) = mailscanner::get_directive(tree.conf, key) else {
            continue;
        };
        let exp = mailscanner::expand_variables(tree.conf, v);
        let mut n = 0;
        for name in values_of(&exp, tree.etc)
            .iter()
            .flat_map(|v| v.split_whitespace().map(str::to_string).collect::<Vec<_>>())
        {
            n += 1;
            match defs.iter().find(|(d, _)| *d == name) {
                None => out.push(finding(Level::Fail, format!("{key} names '{name}', which is not defined in spam.lists.conf")).key(key).file(defs_id.clone())),
                Some((_, zone)) if engine::rbl_defunct(zone.trim_end_matches('.')) => out.push(finding(Level::Warn, format!("{key}: '{name}' ({zone}) is a defunct blocklist — every lookup fails or times out")).key(key).file(defs_id.clone())),
                Some(_) => {}
            }
        }
        if n > 0
            && !out
                .iter()
                .any(|f| f.key.as_deref() == Some(key) && f.level != Level::Ok)
        {
            out.push(finding(Level::Ok, format!("{key}: {n} list(s), all defined")).key(key));
        }
    }
}

fn check_filename_rules(tree: &Tree, perl: &[String], out: &mut Vec<Finding>) {
    let mut files: Vec<PathBuf> = Vec::new();
    for key in FILENAME_RULE_KEYS {
        let Some(v) = mailscanner::get_directive(tree.conf, key) else {
            continue;
        };
        let exp = mailscanner::expand_variables(tree.conf, v);
        for val in values_of(&exp, tree.etc) {
            let p = PathBuf::from(&val);
            if val.is_empty() || files.contains(&p) {
                continue;
            }
            if !p.is_file() {
                out.push(
                    finding(Level::Fail, format!("{key}: {val} does not exist"))
                        .key(key)
                        .file("ms:MailScanner.conf"),
                );
                continue;
            }
            files.push(p);
        }
    }
    let mut perl_missing = false;
    for p in files {
        let id = id_of(tree.etc, &p).unwrap_or_else(|| p.display().to_string());
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let t = msgrammar::parse_filename_rules(&text);
        for (n, l) in t.unparsed() {
            out.push(
                finding(
                    Level::Fail,
                    format!(
                        "line {n} is not a filename rule: {}",
                        l.chars().take(60).collect::<String>()
                    ),
                )
                .file(id.clone())
                .line(n as u32),
            );
        }
        if t.normalized {
            out.push(finding(Level::Warn, "some rules use spaces where MailScanner expects tabs — save the file from the table editor to fix").file(id.clone()));
        }
        let rows: Vec<(usize, &msgrammar::FilenameRule)> = t
            .lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match l {
                msgrammar::Line::Row(r) => Some((i + 1, r)),
                _ => None,
            })
            .collect();
        let patterns: Vec<String> = rows.iter().map(|(_, r)| r.pattern.clone()).collect();
        match msgrammar::perl_regex_check(perl, &patterns) {
            Some(bad) => {
                for (i, msg) in bad {
                    let (line, r) = rows[i];
                    out.push(
                        finding(
                            Level::Fail,
                            format!("pattern '{}' does not compile: {msg}", r.pattern),
                        )
                        .file(id.clone())
                        .line(line as u32),
                    );
                }
                if !rows.is_empty()
                    && !out
                        .iter()
                        .any(|f| f.file.as_deref() == Some(&id) && f.level == Level::Fail)
                {
                    out.push(
                        finding(Level::Ok, format!("{} patterns compile", rows.len()))
                            .file(id.clone()),
                    );
                }
            }
            None => perl_missing = true,
        }
    }
    if perl_missing {
        out.push(finding(
            Level::Warn,
            "filename patterns were not compile-checked (the engine's perl is not available)",
        ));
    }
}

fn check_phishing_custom(tree: &Tree, out: &mut Vec<Finding>) {
    for name in ["phishing.bad.sites.custom", "phishing.safe.sites.custom"] {
        let Ok(t) = std::fs::read_to_string(tree.etc.join(name)) else {
            continue;
        };
        for (n, l) in msgrammar::parse_host_list(&t).unparsed() {
            out.push(
                finding(
                    Level::Fail,
                    format!(
                        "line {n} is not a hostname: {}",
                        l.chars().take(60).collect::<String>()
                    ),
                )
                .file(format!("ms:{name}"))
                .line(n as u32),
            );
        }
    }
}

fn check_confd(tree: &Tree, schema: Option<&msdefs::Schema>, out: &mut Vec<Finding>) {
    let main_keys: Vec<String> = entries(tree.conf).into_iter().map(|(k, _, _)| k).collect();
    let dir = tree.etc.join("conf.d");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| n.ends_with(".conf"))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        let Ok(t) = std::fs::read_to_string(dir.join(&name)) else {
            continue;
        };
        let id = format!("ms:conf.d/{name}");
        for (i, l) in conffile::parse(&t).into_iter().enumerate() {
            match l {
                conffile::ConfLine::Other(o) => out.push(
                    finding(
                        Level::Warn,
                        format!(
                            "line {}: not a directive: {}",
                            i + 1,
                            o.chars().take(60).collect::<String>()
                        ),
                    )
                    .file(id.clone())
                    .line(i as u32 + 1),
                ),
                conffile::ConfLine::Entry { key, .. } if !key.starts_with('%') => {
                    if let Some(s) = schema {
                        if s.lookup(&key).is_none() {
                            out.push(finding(Level::Warn, format!("'{key}' is not a directive the engine knows (typo?) — it is ignored silently")).file(id.clone()).key(key.clone()).line(i as u32 + 1));
                            continue;
                        }
                    }
                    if main_keys.contains(&key) {
                        out.push(
                            finding(Level::Ok, format!("'{key}' overrides MailScanner.conf"))
                                .file(id.clone())
                                .key(key),
                        );
                    }
                }
                _ => {}
            }
        }
    }
}

fn check_unknown_keys(tree: &Tree, schema: Option<&msdefs::Schema>, out: &mut Vec<Finding>) {
    let Some(s) = schema else {
        return;
    };
    for (key, _, _) in entries(tree.conf) {
        if s.lookup(&key).is_none() {
            out.push(finding(Level::Warn, format!("'{key}' is not a directive the engine knows (typo, or newer than the engine) — it is ignored silently")).file("ms:MailScanner.conf").key(key));
        }
    }
}

/// `(uid, gid)` of a user from `/etc/passwd`.
pub fn uid_gid_of(name: &str) -> Option<(u32, u32)> {
    let t = std::fs::read_to_string("/etc/passwd").ok()?;
    t.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[0] == name).then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
    })
}

fn readable_by(p: &Path, uid: u32, gid: u32, write: bool) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p).ok()?;
    let mode = m.mode();
    let bit = if write { 0o2 } else { 0o4 };
    Some(
        uid == 0
            || (m.uid() == uid && mode & (bit << 6) != 0)
            || (m.gid() == gid && mode & (bit << 3) != 0)
            || mode & bit != 0,
    )
}

fn check_permissions(cfg: &Config, tree: &Tree, out: &mut Vec<Finding>) {
    let user = engine::run_user_for(cfg);
    let Some((uid, gid)) = uid_gid_of(user) else {
        return;
    };
    let mut unreadable = Vec::new();
    let mut walk = |dir: &Path, depth: u8| {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.filter_map(Result::ok) {
                let p = e.path();
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with('.') || name.ends_with(".msfe-ng.bak") {
                    continue;
                }
                if p.is_file() && readable_by(&p, uid, gid, false) == Some(false) {
                    unreadable.push(id_of(tree.etc, &p).unwrap_or(name));
                }
            }
        }
        let _ = depth;
    };
    walk(tree.etc, 0);
    for sub in ["conf.d", "mcp", "rules"] {
        walk(&tree.etc.join(sub), 1);
    }
    for id in unreadable {
        out.push(
            finding(
                Level::Warn,
                format!("not readable by the scanning user '{user}'"),
            )
            .file(id),
        );
    }
    for key in ["Incoming Work Dir", "Quarantine Dir", "Lockfile Dir"] {
        let Some(v) = mailscanner::get_directive(tree.conf, key) else {
            continue;
        };
        let p = mailscanner::expand_variables(tree.conf, v);
        if readable_by(Path::new(&p), uid, gid, true) == Some(false) {
            out.push(finding(Level::Warn, format!("{key}: {p} is not writable by the scanning user '{user}' — every batch touching it fails")).key(key).file("ms:MailScanner.conf"));
        }
    }
}

/// All checks over `tree`.
pub fn run(
    cfg: &Config,
    tree: &Tree,
    schema: Option<&msdefs::Schema>,
    perl: &[String],
) -> Vec<Finding> {
    let mut out = Vec::new();
    check_paths(tree, schema, &mut out);
    check_rulesets(tree, schema, &mut out);
    check_virus_scanners(tree, &mut out);
    check_spam_lists(tree, &mut out);
    check_filename_rules(tree, perl, &mut out);
    check_phishing_custom(tree, &mut out);
    check_confd(tree, schema, &mut out);
    check_unknown_keys(tree, schema, &mut out);
    check_permissions(cfg, tree, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFS: &str = "[Translation,Translation]\nchildren = maxchildren\nspamlist = spamlist\n[Simple,Number]\nChildren 5\n[Simple,File]\nSpamListDefinitions /etc/MailScanner/spam.lists.conf\n[Simple,Other]\nVirusScanners auto\nSpamList\n[First,YesNo]\nSpamChecks 1 no 0 yes 1\n[First,Number]\nRequiredSpamAssassinScore 6\n[All,File]\nFilenameRules\n[First,Command]\nSendmail /usr/sbin/sendmail\n";

    fn tree(tag: &str, conf_extra: &str) -> (PathBuf, Config) {
        let base =
            std::env::temp_dir().join(format!("msfe-confcheck-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let etc = base.join("etc/MailScanner");
        std::fs::create_dir_all(etc.join("rules")).unwrap();
        std::fs::create_dir_all(etc.join("conf.d")).unwrap();
        let conf = format!(
            "%etc-dir% = {e}\n%rules-dir% = {e}/rules\nMax Children = 5\nSpam Checks = %rules-dir%/spam.rules\nRequired SpamAssassin Score = %rules-dir%/score.rules\n\
             Virus Scanners = clamd bogus\nSpam List Definitions = %etc-dir%/spam.lists.conf\nSpam List = SPAMCOP UNDEFINED SORBS\nFilename Rules = %etc-dir%/filename.rules.conf\nSendmail = /nonexistent/sendmail\n{conf_extra}",
            e = etc.display()
        );
        std::fs::write(etc.join("MailScanner.conf"), conf).unwrap();
        std::fs::write(
            etc.join("rules/spam.rules"),
            "From: *@a.example yes\ngarbage here\nFromOrTo: default maybe\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("rules/score.rules"),
            "To: *@b.example 4.5\nTo: *@c.example high\n",
        )
        .unwrap();
        std::fs::write(etc.join("virus.scanners.conf"), "clamd\t/bin/false\t/usr\n").unwrap();
        std::fs::write(
            etc.join("spam.lists.conf"),
            "SPAMCOP\tbl.spamcop.net.\nSORBS\tdnsbl.sorbs.net.\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("filename.rules.conf"),
            "deny\t\\.exe$\ta\tb\ndeny\t(unclosed\tc\td\nnot a rule at all\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("phishing.bad.sites.custom"),
            "bad.example\nnot a host\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("conf.d/10-x.conf"),
            "Max Children = 9\nMax Chlidren = 3\nstray line\n",
        )
        .unwrap();
        let cfg = Config {
            mailscanner_conf: etc.join("MailScanner.conf").display().to_string(),
            backup_dir: base.join("backups").display().to_string(),
            ..Config::default()
        };
        (base, cfg)
    }

    fn perl() -> Vec<String> {
        ["/usr/bin/perl", "/usr/local/bin/perl"]
            .iter()
            .find(|p| Path::new(p).exists())
            .map(|p| vec![p.to_string()])
            .unwrap_or_default()
    }

    #[test]
    fn every_check_finds_its_defect() {
        let (base, cfg) = tree("defects", "Max Chidlren = 4\n");
        let etc = base.join("etc/MailScanner");
        let conf = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
        let schema = msdefs::parse(DEFS);
        let out = run(
            &cfg,
            &Tree {
                etc: &etc,
                conf: &conf,
            },
            Some(&schema),
            &perl(),
        );
        let has = |level: Level, needle: &str| {
            out.iter()
                .any(|f| f.level == level && f.message.contains(needle))
        };
        assert!(
            has(
                Level::Fail,
                "Sendmail: /nonexistent/sendmail is not an executable"
            ),
            "{out:#?}"
        );
        assert!(has(Level::Fail, "line 2 is not a rule: garbage here"));
        assert!(has(
            Level::Fail,
            "'maybe' is not a yesno value for Spam Checks"
        ));
        assert!(has(
            Level::Fail,
            "'high' is not a number value for Required SpamAssassin Score"
        ));
        assert!(has(
            Level::Warn,
            "Required SpamAssassin Score: ruleset has no 'default' rule"
        ));
        assert!(has(Level::Fail, "Virus Scanners names 'bogus'"));
        assert!(has(Level::Ok, "scanner 'clamd' defined"));
        assert!(has(Level::Fail, "Spam List names 'UNDEFINED'"));
        assert!(has(
            Level::Warn,
            "'SORBS' (dnsbl.sorbs.net.) is a defunct blocklist"
        ));
        assert!(has(
            Level::Fail,
            "line 3 is not a filename rule: not a rule at all"
        ));
        if !perl().is_empty() {
            assert!(
                has(Level::Fail, "pattern '(unclosed' does not compile"),
                "{out:#?}"
            );
        }
        assert!(has(Level::Fail, "line 2 is not a hostname: not a host"));
        assert!(has(Level::Warn, "line 3: not a directive: stray line"));
        assert!(has(
            Level::Warn,
            "'Max Chlidren' is not a directive the engine knows (typo?)"
        ));
        assert!(has(Level::Ok, "'Max Children' overrides MailScanner.conf"));
        assert!(has(
            Level::Warn,
            "'Max Chidlren' is not a directive the engine knows (typo, or newer"
        ));
        // ids point at the files
        let f = out
            .iter()
            .find(|f| f.message.contains("garbage here"))
            .unwrap();
        assert_eq!(f.file.as_deref(), Some("ms:rules/spam.rules"));
        assert_eq!(f.line, Some(2));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_clean_tree_has_no_failures() {
        let (base, cfg) = tree("clean", "");
        let etc = base.join("etc/MailScanner");
        std::fs::write(
            etc.join("rules/spam.rules"),
            "From: *@a.example yes\nFromOrTo: default no\n",
        )
        .unwrap();
        std::fs::write(
            etc.join("rules/score.rules"),
            "To: *@b.example 4.5\nFromOrTo: default 6\n",
        )
        .unwrap();
        std::fs::write(etc.join("filename.rules.conf"), "deny\t\\.exe$\ta\tb\n").unwrap();
        std::fs::write(etc.join("phishing.bad.sites.custom"), "bad.example\n").unwrap();
        std::fs::write(etc.join("conf.d/10-x.conf"), "Max Children = 9\n").unwrap();
        let mut conf = std::fs::read_to_string(etc.join("MailScanner.conf")).unwrap();
        conf = conf
            .replace("clamd bogus", "clamd")
            .replace("SPAMCOP UNDEFINED SORBS", "SPAMCOP")
            .replace("/nonexistent/sendmail", "/bin/sh");
        std::fs::write(etc.join("MailScanner.conf"), &conf).unwrap();
        let schema = msdefs::parse(DEFS);
        let out = run(
            &cfg,
            &Tree {
                etc: &etc,
                conf: &conf,
            },
            Some(&schema),
            &perl(),
        );
        let fails: Vec<&Finding> = out.iter().filter(|f| f.level == Level::Fail).collect();
        assert!(fails.is_empty(), "{fails:#?}");
        assert!(out.iter().any(
            |f| f.level == Level::Ok && f.message.contains("Spam List: 1 list(s), all defined")
        ));
        // no schema: paths judged softly, nothing about unknown keys
        let out = run(
            &cfg,
            &Tree {
                etc: &etc,
                conf: &conf,
            },
            None,
            &[],
        );
        assert!(!out.iter().any(|f| f.message.contains("engine knows")));
        assert!(out
            .iter()
            .any(|f| f.level == Level::Warn && f.message.contains("not compile-checked")));
        let _ = std::fs::remove_dir_all(&base);
    }
}
