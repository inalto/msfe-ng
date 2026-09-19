//! Comment-preserving parsers for the MailScanner conf files that are tables
//! rather than `key = value` lists: filename/filetype rules, spam list
//! definitions, virus scanner definitions and the phishing custom host lists.
//!
//! Same discipline as `rulefile`: every line is kept (`Blank`, `Comment`,
//! `Row`, or `Unparsed` verbatim), rows re-serialize to MailScanner's canonical
//! TAB-separated form, and a file whose rows did not change round-trips
//! byte-for-byte — the editor never rewrites what it did not touch.

#[derive(Debug, Clone, PartialEq)]
pub enum Line<T> {
    Blank,
    Comment(String),
    Row(T),
    /// Kept verbatim so nothing is silently dropped.
    Unparsed(String),
}

/// A parsed table file; `normalized` is set when any row had to be split on
/// runs of spaces instead of tabs (a hand edit MailScanner itself would
/// misread — saving rewrites it canonically).
#[derive(Debug, Clone, PartialEq)]
pub struct Table<T> {
    pub lines: Vec<Line<T>>,
    pub normalized: bool,
}

impl<T> Table<T> {
    pub fn rows(&self) -> Vec<&T> {
        self.lines
            .iter()
            .filter_map(|l| match l {
                Line::Row(r) => Some(r),
                _ => None,
            })
            .collect()
    }
    pub fn unparsed(&self) -> Vec<(usize, &str)> {
        self.lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| match l {
                Line::Unparsed(s) => Some((i + 1, s.as_str())),
                _ => None,
            })
            .collect()
    }
}

/// Split a raw line the way MailScanner's table readers do (`\t+`), falling
/// back to runs of two or more spaces when tabs do not yield `min` fields.
/// Returns the fields and whether the fallback was needed.
fn split_fields(line: &str, min: usize) -> (Vec<String>, bool) {
    let tabs: Vec<String> = line
        .split('\t')
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_string)
        .collect();
    if tabs.len() >= min {
        return (tabs, false);
    }
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut spaces = 0;
    for c in line.trim().chars() {
        if c == ' ' || c == '\t' {
            spaces += 1;
            if c == '\t' {
                spaces = 2;
            }
            continue;
        }
        if spaces >= 2 && !cur.is_empty() {
            fields.push(cur.trim().to_string());
            cur.clear();
        } else if spaces == 1 && !cur.is_empty() {
            cur.push(' ');
        }
        spaces = 0;
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        fields.push(cur.trim().to_string());
    }
    (fields, true)
}

fn classify(raw: &str) -> Option<Line<()>> {
    let t = raw.trim();
    if t.is_empty() {
        Some(Line::Blank)
    } else if t.starts_with('#') {
        Some(Line::Comment(raw.trim_end().to_string()))
    } else {
        None
    }
}

fn parse_with<T>(text: &str, mut row: impl FnMut(&str) -> Option<(T, bool)>) -> Table<T> {
    let mut normalized = false;
    let lines = text
        .lines()
        .map(|raw| match classify(raw) {
            Some(Line::Blank) => Line::Blank,
            Some(Line::Comment(c)) => Line::Comment(c),
            _ => match row(raw) {
                Some((r, norm)) => {
                    normalized |= norm;
                    Line::Row(r)
                }
                None => Line::Unparsed(raw.trim_end().to_string()),
            },
        })
        .collect();
    Table { lines, normalized }
}

fn render_with<T>(t: &Table<T>, mut row: impl FnMut(&T) -> String) -> String {
    let mut out = String::new();
    for l in &t.lines {
        match l {
            Line::Blank => {}
            Line::Comment(c) | Line::Unparsed(c) => out.push_str(c),
            Line::Row(r) => out.push_str(&row(r)),
        }
        out.push('\n');
    }
    out
}

// ---- filename / filetype rules ------------------------------------------------

/// What MailScanner does with an attachment whose name (or type) matches.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny,
    DenyDelete,
    Rename,
    /// `rename to .ext`
    RenameTo(String),
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        let l = s.trim().to_ascii_lowercase();
        match l.as_str() {
            "allow" => Some(Action::Allow),
            "deny" => Some(Action::Deny),
            "deny+delete" => Some(Action::DenyDelete),
            "rename" => Some(Action::Rename),
            _ => l
                .strip_prefix("rename to ")
                .map(|ext| Action::RenameTo(ext.trim().to_string())),
        }
    }
    pub fn as_string(&self) -> String {
        match self {
            Action::Allow => "allow".into(),
            Action::Deny => "deny".into(),
            Action::DenyDelete => "deny+delete".into(),
            Action::Rename => "rename".into(),
            Action::RenameTo(e) => format!("rename to {e}"),
        }
    }
}

/// One line of `filename.rules.conf` / `filetype.rules.conf` and their
/// `archives.` twins: `action TAB pattern TAB log text TAB user text`.
#[derive(Debug, Clone, PartialEq)]
pub struct FilenameRule {
    pub action: Action,
    pub pattern: String,
    pub log_text: String,
    pub user_text: String,
}

impl FilenameRule {
    pub fn to_line(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            self.action.as_string(),
            self.pattern,
            self.log_text,
            self.user_text
        )
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.pattern.is_empty() || self.pattern.chars().any(char::is_control) {
            return Err("empty or invalid pattern".into());
        }
        for (what, v) in [("log text", &self.log_text), ("user text", &self.user_text)] {
            if v.chars().any(|c| c == '\t' || c.is_control()) {
                return Err(format!("{what} may not contain tabs or control characters"));
            }
        }
        Ok(())
    }
}

pub fn parse_filename_rules(text: &str) -> Table<FilenameRule> {
    parse_with(text, |raw| {
        let (f, norm) = split_fields(raw, 4);
        if f.len() < 2 {
            return None;
        }
        let action = Action::parse(&f[0])?;
        Some((
            FilenameRule {
                action,
                pattern: f[1].clone(),
                log_text: f.get(2).cloned().unwrap_or_else(|| "-".into()),
                user_text: f.get(3).cloned().unwrap_or_else(|| "-".into()),
            },
            norm || f.len() < 4,
        ))
    })
}

pub fn render_filename_rules(t: &Table<FilenameRule>) -> String {
    render_with(t, FilenameRule::to_line)
}

// ---- spam.lists.conf ---------------------------------------------------------------

/// `NAME  zone.example.` — an RBL definition.
#[derive(Debug, Clone, PartialEq)]
pub struct SpamList {
    pub name: String,
    pub domain: String,
}

impl SpamList {
    pub fn to_line(&self) -> String {
        format!("{}\t{}", self.name, self.domain)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty()
            || self
                .name
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(format!("bad list name '{}'", self.name));
        }
        // RBL zones are conventionally written fully qualified (trailing dot)
        if !is_hostname(self.domain.strip_suffix('.').unwrap_or(&self.domain)) {
            return Err(format!("bad zone '{}'", self.domain));
        }
        Ok(())
    }
}

pub fn parse_spam_lists(text: &str) -> Table<SpamList> {
    parse_with(text, |raw| {
        let mut it = raw.split_whitespace();
        let name = it.next()?.to_string();
        let domain = it.next()?.to_string();
        if it.next().is_some() {
            return None;
        }
        Some((SpamList { name, domain }, false))
    })
}

pub fn render_spam_lists(t: &Table<SpamList>) -> String {
    render_with(t, SpamList::to_line)
}

// ---- virus.scanners.conf ----------------------------------------------------------

/// `name  wrapper  dir`
#[derive(Debug, Clone, PartialEq)]
pub struct VirusScanner {
    pub name: String,
    pub wrapper: String,
    pub dir: String,
}

impl VirusScanner {
    pub fn to_line(&self) -> String {
        format!("{}\t{}\t{}", self.name, self.wrapper, self.dir)
    }
    pub fn validate(&self) -> Result<(), String> {
        for (what, v) in [
            ("name", &self.name),
            ("wrapper", &self.wrapper),
            ("dir", &self.dir),
        ] {
            if v.is_empty() || v.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return Err(format!("bad {what} '{v}'"));
            }
        }
        Ok(())
    }
}

pub fn parse_virus_scanners(text: &str) -> Table<VirusScanner> {
    parse_with(text, |raw| {
        let f: Vec<&str> = raw.split_whitespace().collect();
        if f.len() != 3 {
            return None;
        }
        Some((
            VirusScanner {
                name: f[0].into(),
                wrapper: f[1].into(),
                dir: f[2].into(),
            },
            false,
        ))
    })
}

pub fn render_virus_scanners(t: &Table<VirusScanner>) -> String {
    render_with(t, VirusScanner::to_line)
}

// ---- phishing custom lists ----------------------------------------------------------

/// A hostname as the phishing lists accept it: labels of letters, digits and
/// hyphens joined by dots (a leading `*.` wildcard is fine).
pub fn is_hostname(s: &str) -> bool {
    let s = s.strip_prefix("*.").unwrap_or(s);
    !s.is_empty()
        && s.len() <= 253
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

/// One host per line.
pub fn parse_host_list(text: &str) -> Table<String> {
    parse_with(text, |raw| {
        let t = raw.trim();
        if t.split_whitespace().count() != 1 || !is_hostname(t) {
            return None;
        }
        Some((t.to_string(), false))
    })
}

pub fn render_host_list(t: &Table<String>) -> String {
    render_with(t, |h| h.clone())
}

// ---- pattern check ----------------------------------------------------------------

/// Compile each pattern with the engine's own perl (`qr/…/`), returning the
/// 0-based indexes that fail and perl's message. Filename rules are compiled
/// by MailScanner at scan time, after `--lint` — this is the only place they
/// are checked. `None` when no perl can be run.
pub fn perl_regex_check(perl: &[String], patterns: &[String]) -> Option<Vec<(usize, String)>> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let exe = perl.first()?;
    let mut child = Command::new(exe)
        .args(perl.iter().skip(1))
        .arg("-e")
        .arg(
            r#"while (<STDIN>) { chomp; my $p = $_; eval { qr/$p/ }; if ($@) { my $m = $@; $m =~ s/\s+at -e line \d+.*//s; $m =~ s/\n/ /g; print "BAD $m\n" } else { print "OK\n" } }"#,
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        for p in patterns {
            let one = p.replace(['\n', '\r'], " ");
            let _ = writeln!(stdin, "{one}");
        }
    }
    let out = child.wait_with_output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(msg) = line.strip_prefix("BAD ") {
            bad.push((i, msg.trim().to_string()));
        }
    }
    Some(bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILENAME: &str = "# Filename rules\n\
\n\
deny\t.{150,}\t\t\tVery long filename, possible OE attack\t\t\t\t\t\tVery long filenames are good signs of attacks\n\
rename\t\\.fdf$\t\t\tDangerous Adobe Acrobat data-file\t\t\t\t\t\tOpening this file can cause auto-loading\n\
allow\t\\.txt$\t-\t-\n\
rename to .txt\t\\.vbs$\tVBS\tVisual Basic script\n\
deny+delete\t\\.pif$\tPIF\tPIF\n\
garbage line without tabs\n";

    #[test]
    fn filename_rules_parse_tabs_and_keep_everything() {
        let t = parse_filename_rules(FILENAME);
        assert!(!t.normalized);
        let rows = t.rows();
        assert_eq!(rows.len(), 5);
        assert_eq!(rows[0].action, Action::Deny);
        assert_eq!(rows[0].pattern, ".{150,}");
        assert_eq!(rows[0].log_text, "Very long filename, possible OE attack");
        assert_eq!(rows[1].action, Action::Rename);
        assert_eq!(rows[2].log_text, "-");
        assert_eq!(rows[3].action, Action::RenameTo(".txt".into()));
        assert_eq!(rows[4].action, Action::DenyDelete);
        assert_eq!(t.unparsed(), vec![(8, "garbage line without tabs")]);
        assert!(matches!(t.lines[0], Line::Comment(_)));
        assert!(matches!(t.lines[1], Line::Blank));
    }

    #[test]
    fn filename_rules_render_canonical_tabs_and_round_trip() {
        let t = parse_filename_rules(FILENAME);
        let out = render_filename_rules(&t);
        assert!(out.contains("deny\t.{150,}\tVery long filename, possible OE attack\tVery long filenames are good signs of attacks\n"));
        assert!(out.contains("rename to .txt\t\\.vbs$\tVBS\tVisual Basic script\n"));
        assert!(out.contains("garbage line without tabs\n"));
        // canonical text is a fixed point
        assert_eq!(render_filename_rules(&parse_filename_rules(&out)), out);
    }

    #[test]
    fn filename_rules_fall_back_to_spaces_and_flag_it() {
        let t = parse_filename_rules(
            "deny   \\.exe$   Windows executable   Executables are not allowed\n",
        );
        assert!(t.normalized);
        let r = t.rows()[0];
        assert_eq!(r.pattern, "\\.exe$");
        assert_eq!(r.log_text, "Windows executable");
        assert_eq!(r.user_text, "Executables are not allowed");
        // a real deny line with just two fields is a row too (texts default to -)
        let t = parse_filename_rules("deny\t\\.scr$\n");
        assert_eq!(t.rows()[0].user_text, "-");
        assert!(t.normalized);
    }

    #[test]
    fn filename_rule_validation() {
        let ok = FilenameRule {
            action: Action::Deny,
            pattern: "\\.exe$".into(),
            log_text: "x".into(),
            user_text: "y".into(),
        };
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.pattern.clear();
        assert!(bad.validate().is_err());
        let mut bad = ok;
        bad.log_text = "a\tb".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn spam_lists_parse_and_render() {
        let t = parse_spam_lists("# lists\nSPAMCOP\t\tbl.spamcop.net.\nBARRACUDA b.barracudacentral.org.\nbroken line here\n");
        let rows = t.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "SPAMCOP");
        assert_eq!(rows[1].domain, "b.barracudacentral.org.");
        assert_eq!(t.unparsed().len(), 1);
        let out = render_spam_lists(&t);
        assert_eq!(out, "# lists\nSPAMCOP\tbl.spamcop.net.\nBARRACUDA\tb.barracudacentral.org.\nbroken line here\n");
        assert!(SpamList {
            name: "X Y".into(),
            domain: "a.b".into()
        }
        .validate()
        .is_err());
        assert!(SpamList {
            name: "X".into(),
            domain: "not a host".into()
        }
        .validate()
        .is_err());
        assert!(SpamList {
            name: "X".into(),
            domain: "zen.spamhaus.org.".into()
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn virus_scanners_parse_and_render() {
        let t = parse_virus_scanners("clamd\t\t\t/bin/false\t\t\t/usr\nbitdefender\t/usr/lib/MailScanner/wrapper/bitdefender-wrapper \t/opt/BitDefender\nonly two\n");
        let rows = t.rows();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].wrapper, "/bin/false");
        assert_eq!(rows[1].dir, "/opt/BitDefender");
        assert_eq!(t.unparsed().len(), 1);
        assert_eq!(
            render_virus_scanners(&t),
            "clamd\t/bin/false\t/usr\nbitdefender\t/usr/lib/MailScanner/wrapper/bitdefender-wrapper\t/opt/BitDefender\nonly two\n"
        );
    }

    #[test]
    fn host_lists() {
        let t = parse_host_list(
            "# custom\nexample.com\n*.bad.example\nnot a host\nhas_underscore.com\n",
        );
        assert_eq!(
            t.rows(),
            vec![&"example.com".to_string(), &"*.bad.example".to_string()]
        );
        assert_eq!(t.unparsed().len(), 2);
        assert_eq!(
            render_host_list(&t),
            "# custom\nexample.com\n*.bad.example\nnot a host\nhas_underscore.com\n"
        );
        assert!(is_hostname("a-b.c"));
        assert!(!is_hostname(".a.b"));
        assert!(!is_hostname("a..b"));
    }

    #[test]
    fn perl_regex_check_reports_bad_patterns() {
        let Some(perl) = ["/usr/bin/perl", "/usr/local/bin/perl"]
            .iter()
            .find(|p| std::path::Path::new(p).exists())
        else {
            return;
        };
        let bad = perl_regex_check(
            &[perl.to_string()],
            &["\\.exe$".into(), "(unclosed".into(), ".{150,}".into()],
        )
        .expect("perl runs");
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].0, 1);
        assert!(bad[0].1.to_lowercase().contains("unmatched") || !bad[0].1.is_empty());
        assert_eq!(perl_regex_check(&[], &["x".into()]), None);
    }
}
