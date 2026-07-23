//! Structured parsing and canonical serialization of MailScanner ruleset lines.
//!
//! The legacy `msrules.pl` spliced raw text lines with regexes that silently
//! misfired when a hand edit used spaces where tabs were expected. Here rules
//! are a real data type: parsing tokenizes on *any* whitespace (tabs, spaces,
//! or a mix all parse identically) and serialization always emits the canonical
//! TAB-separated form, so a round trip normalizes whatever it is fed.
//!
//! Grammar (a behavioral fact of MailScanner ruleset files):
//!   `<direction> <pattern> [and <direction> <pattern>] <value…>`
//! where direction ∈ {To:, From:, FromOrTo:, FromAndTo:}, the pattern is a
//! single whitespace-free token (`*@domain`, `user@domain`, `default`, …) and
//! the value is everything after the pattern(s) — it may contain spaces
//! (`forward spam@x delete`, `store deliver header "X-Foo: yes"`).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    To,
    From,
    FromOrTo,
    FromAndTo,
}

impl Direction {
    pub fn parse(token: &str) -> Option<Direction> {
        match token.to_ascii_lowercase().as_str() {
            "to:" => Some(Direction::To),
            "from:" => Some(Direction::From),
            "fromorto:" => Some(Direction::FromOrTo),
            "fromandto:" => Some(Direction::FromAndTo),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::To => "To:",
            Direction::From => "From:",
            Direction::FromOrTo => "FromOrTo:",
            Direction::FromAndTo => "FromAndTo:",
        }
    }
}

/// One rule, optionally compound (`To: X and From: Y  value`).
#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub direction: Direction,
    pub pattern: String,
    pub and_direction: Option<Direction>,
    pub and_pattern: Option<String>,
    pub value: String,
}

impl Rule {
    /// Canonical serialization: TAB between the match part and the value; the
    /// compound match itself keeps single spaces (matching what MailScanner
    /// documents and what our generator emits).
    pub fn to_line(&self) -> String {
        match (&self.and_direction, &self.and_pattern) {
            (Some(d2), Some(p2)) => format!(
                "{} {} and {} {}\t{}",
                self.direction.as_str(),
                self.pattern,
                d2.as_str(),
                p2,
                self.value
            ),
            _ => format!(
                "{}\t{}\t{}",
                self.direction.as_str(),
                self.pattern,
                self.value
            ),
        }
    }

    /// Structural validity: non-empty whitespace-free pattern(s), non-empty
    /// value, no control characters anywhere.
    pub fn validate(&self) -> Result<(), String> {
        let ok_pat = |p: &str| {
            !p.is_empty()
                && !p.chars().any(|c| c.is_whitespace() || c.is_control())
        };
        if !ok_pat(&self.pattern) {
            return Err(format!("bad pattern '{}'", self.pattern));
        }
        if let Some(p2) = &self.and_pattern {
            if !ok_pat(p2) {
                return Err(format!("bad pattern '{p2}'"));
            }
            if self.and_direction.is_none() {
                return Err("compound rule missing second direction".into());
            }
        }
        let v = self.value.trim();
        if v.is_empty() || v.chars().any(|c| c.is_control()) {
            return Err("empty or invalid value".into());
        }
        Ok(())
    }
}

/// A parsed line of a ruleset file.
#[derive(Debug, Clone, PartialEq)]
pub enum Line {
    Blank,
    Comment(String),
    Rule(Rule),
    /// Anything that does not parse as a rule — preserved verbatim so nothing
    /// is ever silently dropped.
    Unparsed(String),
}

/// Parse one line, accepting any mix of tabs and spaces between fields.
pub fn parse_line(raw: &str) -> Line {
    let line = raw.trim_end();
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return Line::Blank;
    }
    if trimmed.starts_with('#') {
        return Line::Comment(trimmed.to_string());
    }

    // Tokenize with byte offsets so the value keeps its inner spacing.
    let tokens: Vec<(usize, &str)> = split_offsets(line);
    let tok = |i: usize| tokens.get(i).map(|(_, t)| *t);

    let Some(dir) = tok(0).and_then(Direction::parse) else {
        return Line::Unparsed(line.to_string());
    };
    let Some(pattern) = tok(1) else {
        return Line::Unparsed(line.to_string());
    };

    // Compound form: <dir> <pat> and <dir2> <pat2> <value…>
    if tok(2).is_some_and(|t| t.eq_ignore_ascii_case("and")) {
        if let (Some(d2), Some(p2), Some((vstart, _))) =
            (tok(3).and_then(Direction::parse), tok(4), tokens.get(5))
        {
            return Line::Rule(Rule {
                direction: dir,
                pattern: pattern.to_string(),
                and_direction: Some(d2),
                and_pattern: Some(p2.to_string()),
                value: line[*vstart..].trim_end().to_string(),
            });
        }
        return Line::Unparsed(line.to_string());
    }

    match tokens.get(2) {
        Some((vstart, _)) => Line::Rule(Rule {
            direction: dir,
            pattern: pattern.to_string(),
            and_direction: None,
            and_pattern: None,
            value: line[*vstart..].trim_end().to_string(),
        }),
        None => Line::Unparsed(line.to_string()),
    }
}

fn split_offsets(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, &line[s..i]));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, &line[s..]));
    }
    out
}

/// Parse a whole ruleset file body.
pub fn parse(text: &str) -> Vec<Line> {
    text.lines().map(parse_line).collect()
}

/// Just the rules from a parsed body.
pub fn rules_of(lines: &[Line]) -> Vec<Rule> {
    lines
        .iter()
        .filter_map(|l| match l {
            Line::Rule(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

// ---- custom rules store ------------------------------------------------------
//
// Admin-defined rules live per managed file under `<policy>/custom/<name>`, in
// canonical format (but read tolerantly like everything else). `sync` merges
// them into the generated file ahead of the domain lines, so — MailScanner
// rulesets being first-match-wins — custom rules take precedence and survive
// every regeneration.

fn custom_dir(policy_dir: &Path) -> PathBuf {
    policy_dir.join("custom")
}

pub fn load_custom(policy_dir: &Path, file: &str) -> Vec<Rule> {
    let text = std::fs::read_to_string(custom_dir(policy_dir).join(file)).unwrap_or_default();
    rules_of(&parse(&text))
}

/// All custom rules keyed by managed file name.
pub fn load_all_custom(policy_dir: &Path, managed: &[String]) -> BTreeMap<String, Vec<Rule>> {
    managed
        .iter()
        .map(|name| (name.clone(), load_custom(policy_dir, name)))
        .filter(|(_, v)| !v.is_empty())
        .collect()
}

pub fn save_custom(policy_dir: &Path, file: &str, rules: &[Rule]) -> io::Result<()> {
    for r in rules {
        if let Err(e) = r.validate() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, e));
        }
    }
    let dir = custom_dir(policy_dir);
    std::fs::create_dir_all(&dir)?;
    let body: String = rules.iter().map(|r| r.to_line() + "\n").collect();
    crate::sync::atomic_write(&dir.join(file), body.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tabs_spaces_and_mixes_identically() {
        for line in [
            "To:\t*@a.example\tyes",
            "To: *@a.example yes",
            "To:   *@a.example \t  yes",
            "  To:\t \t*@a.example      yes  ",
        ] {
            let Line::Rule(r) = parse_line(line) else {
                panic!("did not parse: {line:?}");
            };
            assert_eq!(r.direction, Direction::To);
            assert_eq!(r.pattern, "*@a.example");
            assert_eq!(r.value, "yes");
            assert_eq!(r.to_line(), "To:\t*@a.example\tyes");
        }
    }

    #[test]
    fn value_keeps_inner_spacing() {
        let Line::Rule(r) =
            parse_line("To: *@x.example  store deliver header \"X-Spam:  yes\"")
        else {
            panic!()
        };
        assert_eq!(r.value, "store deliver header \"X-Spam:  yes\"");
        assert_eq!(
            r.to_line(),
            "To:\t*@x.example\tstore deliver header \"X-Spam:  yes\""
        );
    }

    #[test]
    fn parses_compound_rules() {
        let Line::Rule(r) = parse_line("To: *@a.example   and  From:\t*@b.example\tyes") else {
            panic!()
        };
        assert_eq!(r.direction, Direction::To);
        assert_eq!(r.and_direction, Some(Direction::From));
        assert_eq!(r.and_pattern.as_deref(), Some("*@b.example"));
        assert_eq!(r.to_line(), "To: *@a.example and From: *@b.example\tyes");
    }

    #[test]
    fn roundtrip_is_canonical_and_stable() {
        let messy = "FromOrTo:   default   deliver striphtml\n#note\n\nFrom: bad@x no";
        let once: String = parse(messy)
            .iter()
            .map(|l| match l {
                Line::Rule(r) => r.to_line() + "\n",
                Line::Comment(c) => c.clone() + "\n",
                Line::Blank => "\n".into(),
                Line::Unparsed(u) => u.clone() + "\n",
            })
            .collect();
        assert_eq!(
            once,
            "FromOrTo:\tdefault\tdeliver striphtml\n#note\n\nFrom:\tbad@x\tno\n"
        );
        // parsing the canonical output again changes nothing
        let twice: String = parse(&once)
            .iter()
            .filter_map(|l| match l {
                Line::Rule(r) => Some(r.to_line() + "\n"),
                Line::Comment(c) => Some(c.clone() + "\n"),
                Line::Blank => Some("\n".into()),
                Line::Unparsed(u) => Some(u.clone() + "\n"),
            })
            .collect();
        assert_eq!(once, twice);
    }

    #[test]
    fn junk_is_preserved_not_dropped() {
        assert_eq!(
            parse_line("this is not a rule"),
            Line::Unparsed("this is not a rule".into())
        );
        assert_eq!(parse_line("To: onlypattern"), Line::Unparsed("To: onlypattern".into()));
        assert_eq!(parse_line("# c"), Line::Comment("# c".into()));
        assert_eq!(parse_line("   "), Line::Blank);
    }

    #[test]
    fn validation_rejects_bad_rules() {
        let ok = Rule {
            direction: Direction::To,
            pattern: "*@a.example".into(),
            and_direction: None,
            and_pattern: None,
            value: "yes".into(),
        };
        assert!(ok.validate().is_ok());
        let mut bad = ok.clone();
        bad.pattern = "has space".into();
        assert!(bad.validate().is_err());
        let mut bad = ok.clone();
        bad.value = " ".into();
        assert!(bad.validate().is_err());
        let mut bad = ok;
        bad.and_pattern = Some("*@b".into());
        assert!(bad.validate().is_err()); // and_pattern without and_direction
    }

    #[test]
    fn custom_store_roundtrip() {
        let d = std::env::temp_dir().join(format!("msfe-rulefile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let rules = vec![Rule {
            direction: Direction::From,
            pattern: "*@spammer.example".into(),
            and_direction: None,
            and_pattern: None,
            value: "delete".into(),
        }];
        save_custom(&d, "spam.action.rules", &rules).unwrap();
        assert_eq!(load_custom(&d, "spam.action.rules"), rules);
        assert!(load_custom(&d, "other.rules").is_empty());
        // hand-mangle the stored file with spaces; it still loads identically
        std::fs::write(
            d.join("custom/spam.action.rules"),
            "From:    *@spammer.example     delete\n",
        )
        .unwrap();
        assert_eq!(load_custom(&d, "spam.action.rules"), rules);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
