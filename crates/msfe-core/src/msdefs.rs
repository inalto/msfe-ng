//! The engine's own description of its directives: `MailScanner/ConfigDefs.pl`.
//!
//! The file is perl only by its first line; after `__DATA__` it is a plain
//! table. `[Translation,Translation]` maps the short internal name to the
//! external one (`children = maxchildren`); the `[Category,Type]` sections
//! list `internal default [word value …]` — the category says whether the
//! directive may point at a ruleset (`First`/`All`) or not (`Simple`), the
//! type what a value looks like, and the word/value pairs are the spellings
//! a YesNo directive accepts (`no 0 yes 1 disarm convert`). A conf key such
//! as `Max Children` is matched by lowercasing and dropping everything that
//! is not a letter or digit. No schema means the editor stays untyped.

use crate::layout::EngineLayout;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// A single value; never a ruleset.
    Simple,
    /// Ruleset allowed; the first matching rule wins.
    First,
    /// Ruleset allowed; every matching rule's value applies.
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    YesNo,
    Number,
    File,
    Command,
    Dir,
    Other,
}

impl Ty {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ty::YesNo => "yesno",
            Ty::Number => "number",
            Ty::File => "file",
            Ty::Command => "command",
            Ty::Dir => "dir",
            Ty::Other => "other",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Def {
    pub internal: String,
    pub category: Category,
    pub ty: Ty,
    /// The default as the conf would spell it (`yes`, not `1`).
    pub default: String,
    /// YesNo spellings, in file order (`no`, `yes`, `disarm`…).
    pub words: Vec<String>,
}

impl Def {
    pub fn ruleset_ok(&self) -> bool {
        self.category != Category::Simple
    }
}

#[derive(Debug, Default, Clone)]
pub struct Schema {
    /// Keyed by the normalized internal name.
    defs: HashMap<String, Def>,
    /// Normalized external → normalized internal.
    external: HashMap<String, String>,
}

/// `Max Children` → `maxchildren`, `Archives: Filename Rules` →
/// `archivesfilenamerules`.
pub fn internal_name(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn section(header: &str) -> Option<(Category, Ty)> {
    let inner = header.trim().trim_start_matches('[').trim_end_matches(']');
    let (cat, ty) = match inner.split_once(',') {
        Some((c, t)) => (c.trim(), t.trim()),
        None => ("Simple", inner.trim()),
    };
    let category = match cat.to_ascii_lowercase().as_str() {
        "simple" => Category::Simple,
        "first" => Category::First,
        "all" => Category::All,
        _ => return None,
    };
    let ty = match ty.to_ascii_lowercase().as_str() {
        "yesno" => Ty::YesNo,
        "number" => Ty::Number,
        "file" => Ty::File,
        "command" => Ty::Command,
        "dir" => Ty::Dir,
        "other" => Ty::Other,
        _ => return None,
    };
    Some((category, ty))
}

pub fn parse(text: &str) -> Schema {
    let mut s = Schema::default();
    let mut cur: Option<(Category, Ty)> = None;
    let mut translation = false;
    for raw in text.lines() {
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            translation = line.to_ascii_lowercase().starts_with("[translation");
            cur = section(line);
            continue;
        }
        if translation {
            if let Some((i, e)) = line.split_once('=') {
                s.external
                    .insert(internal_name(e.trim()), internal_name(i.trim()));
            }
            continue;
        }
        let Some((category, ty)) = cur else {
            continue;
        };
        let line = line.replacen('=', " ", 1);
        let mut toks = line.split_whitespace();
        let Some(name) = toks.next() else {
            continue;
        };
        let rest: Vec<&str> = toks.collect();
        let (default, words) = match ty {
            Ty::YesNo => {
                let raw_default = rest.first().copied().unwrap_or("");
                let pairs: Vec<(&str, &str)> = rest[1.min(rest.len())..]
                    .chunks(2)
                    .filter(|c| c.len() == 2)
                    .map(|c| (c[0], c[1]))
                    .collect();
                let default = pairs
                    .iter()
                    .find(|(_, v)| *v == raw_default)
                    .map(|(w, _)| *w)
                    .unwrap_or(raw_default)
                    .to_string();
                (default, pairs.iter().map(|(w, _)| w.to_string()).collect())
            }
            _ => (rest.join(" "), Vec::new()),
        };
        let internal = internal_name(name);
        s.defs.insert(
            internal.clone(),
            Def {
                internal,
                category,
                ty,
                default,
                words,
            },
        );
    }
    s
}

impl Schema {
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// The definition behind a conf key (`Max Children`, `Virus Scanners`).
    pub fn lookup(&self, key: &str) -> Option<&Def> {
        let ext = internal_name(key);
        let internal = self.external.get(&ext).cloned().unwrap_or(ext);
        self.defs.get(&internal)
    }
}

/// The engine's ConfigDefs.pl, when it can be read.
pub fn load(lay: &EngineLayout) -> Option<Schema> {
    let path = crate::layout::configdefs_path(&lay.perl)?;
    let text = std::fs::read_to_string(path).ok()?;
    let s = parse(&text);
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
1;

__DATA__
#
# Translation between Internal and External keyword names.
#
[Translation,Translation]

AFilenameRules                  = ArchivesFilenameRules
children			= maxchildren
CheckSAIfOnSpamList		= checkspamassassinifonspamlist
eximcommand                     = EximCommand

[Simple,YesNo]
bayeswait		0	no	0	yes	1
debug			0	no	0	yes	1

[Simple,Dir]
incomingworkdir		/var/spool/MailScanner/incoming

# Check the first word of these for file existence
[Simple,File]
SpamListDefinitions	/etc/MailScanner/spam.lists.conf

[Simple,Number]
Children			5
#clamavmaxreclevel               8

[Simple,Other]
VirusScanners		auto  # Space-separated list
EximCommand
cachetiming		1800,300,10800,172800,600

[First,YesNo]
CheckSAIfOnSpamList	1	no	0	yes	1

[First,Command]
Sendmail		/usr/sbin/sendmail

[All,YesNo]
AllowIFrameTags		convert	no	0	yes	1	disarm	convert

[All,File]
#FilenameRules		/etc/MailScanner/filename.rules.conf
AFilenameRules      /etc/MailScanner/archives.filename.rules.conf

[All,Other]
# stuff
aallowfilenames
"#;

    #[test]
    fn keys_map_through_the_translation_table() {
        let s = parse(SAMPLE);
        let d = s.lookup("Max Children").unwrap();
        assert_eq!(d.internal, "children");
        assert_eq!(d.category, Category::Simple);
        assert_eq!(d.ty, Ty::Number);
        assert_eq!(d.default, "5");
        assert!(!d.ruleset_ok());
        let d = s.lookup("Check SpamAssassin If On Spam List").unwrap();
        assert_eq!(d.category, Category::First);
        assert_eq!(d.ty, Ty::YesNo);
        assert_eq!(d.default, "yes");
        assert_eq!(d.words, vec!["no", "yes"]);
        assert!(d.ruleset_ok());
        // no translation: the external name is the internal one
        let d = s.lookup("Incoming Work Dir").unwrap();
        assert_eq!(d.ty, Ty::Dir);
        assert_eq!(d.default, "/var/spool/MailScanner/incoming");
        assert_eq!(s.lookup("Archives: Filename Rules").unwrap().ty, Ty::File);
        assert!(s.lookup("Archives: Filename Rules").unwrap().ruleset_ok());
        assert!(s.lookup("No Such Directive").is_none());
    }

    #[test]
    fn defaults_words_comments_and_empties() {
        let s = parse(SAMPLE);
        let v = s.lookup("Virus Scanners").unwrap();
        assert_eq!(v.default, "auto", "trailing comment stripped");
        assert_eq!(v.ty, Ty::Other);
        assert_eq!(s.lookup("Exim Command").unwrap().default, "");
        assert_eq!(
            s.lookup("Cache Timing").unwrap().default,
            "1800,300,10800,172800,600"
        );
        let a = s.lookup("Allow IFrame Tags").unwrap();
        assert_eq!(a.default, "disarm", "value convert is spelled disarm");
        assert_eq!(a.words, vec!["no", "yes", "disarm"]);
        assert_eq!(a.category, Category::All);
        assert_eq!(s.lookup("Sendmail").unwrap().ty, Ty::Command);
        assert!(s.lookup("aallowfilenames").is_some(), "no-default line");
        assert!(s.lookup("clamavmaxreclevel").is_none(), "commented line");
        assert!(s.lookup("Filename Rules").is_none(), "commented line");
        assert_eq!(
            internal_name("Archives: Filename Rules"),
            "archivesfilenamerules"
        );
        assert!(parse("").is_empty());
    }
}
