//! Comment-preserving model of flat `key = value` configuration files.
//!
//! Backs the visual conf editor: a file is parsed into an ordered list of
//! lines (comments, blanks, entries), so the UI can render entries as fields
//! while showing the surrounding `#` comments — and edits are applied to the
//! *original text* per key, so untouched lines (comments included) survive
//! byte-for-byte. Handles both MailScanner.conf style (keys with spaces,
//! unquoted values) and MSFE-NG's config.toml (quoted string values).

/// One parsed line of a conf file, in file order.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfLine {
    Blank,
    Comment(String),
    Entry {
        key: String,
        value: String,
    },
    /// A line that is neither blank, comment, nor `key = value` — preserved.
    Other(String),
}

pub fn parse(text: &str) -> Vec<ConfLine> {
    text.lines()
        .map(|raw| {
            let line = raw.trim_end();
            let t = line.trim_start();
            if t.is_empty() {
                ConfLine::Blank
            } else if t.starts_with('#') {
                ConfLine::Comment(t.to_string())
            } else if let Some((k, v)) = line.split_once('=') {
                let key = k.trim();
                if key.is_empty() {
                    ConfLine::Other(line.to_string())
                } else {
                    ConfLine::Entry {
                        key: key.to_string(),
                        value: unquote(v.trim()),
                    }
                }
            } else {
                ConfLine::Other(line.to_string())
            }
        })
        .collect()
}

fn unquote(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 2
        && ((b[0] == b'"' && b[b.len() - 1] == b'"') || (b[0] == b'\'' && b[b.len() - 1] == b'\''))
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// How values are written back.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Style {
    /// MailScanner.conf: `Key With Spaces = raw value`
    Plain,
    /// config.toml: strings quoted, integers bare
    Toml,
}

fn render_value(v: &str, style: Style) -> String {
    match style {
        Style::Plain => v.to_string(),
        Style::Toml => {
            if v.parse::<i64>().is_ok() {
                v.to_string()
            } else {
                format!("\"{}\"", v.replace('"', "\\\""))
            }
        }
    }
}

/// Apply `changes` (key → new value) to the original text, replacing only the
/// first live line of each key and preserving every other byte. Keys not
/// present in the file are appended at the end. Returns (new_text, applied).
pub fn apply(text: &str, changes: &[(String, String)], style: Style) -> (String, usize) {
    let mut remaining: Vec<(String, String)> = changes.to_vec();
    let mut out: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        let t = line.trim_start();
        let mut replaced = false;
        if !t.is_empty() && !t.starts_with('#') {
            if let Some((k, _)) = line.split_once('=') {
                let key = k.trim();
                if let Some(pos) = remaining.iter().position(|(ck, _)| ck == key) {
                    let (ck, cv) = remaining.remove(pos);
                    out.push(format!("{ck} = {}", render_value(&cv, style)));
                    replaced = true;
                }
            }
        }
        if !replaced {
            out.push(raw.to_string());
        }
    }
    for (k, v) in &remaining {
        out.push(format!("{k} = {}", render_value(v, style)));
    }
    let applied = changes.len();
    let mut s = out.join("\n");
    if text.ends_with('\n') || !remaining.is_empty() {
        s.push('\n');
    }
    (s, applied)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Main section — do not remove
Max Children = 5

# Queue handling (see docs)
Incoming Queue Dir = /var/spool/exim/mailscanner/input/*
#Commented Directive = old
Run As User = mailnull
";

    #[test]
    fn parse_keeps_structure_and_comments() {
        let lines = parse(SAMPLE);
        assert_eq!(
            lines[0],
            ConfLine::Comment("# Main section — do not remove".into())
        );
        assert_eq!(
            lines[1],
            ConfLine::Entry {
                key: "Max Children".into(),
                value: "5".into()
            }
        );
        assert_eq!(lines[2], ConfLine::Blank);
        assert_eq!(
            lines[5],
            ConfLine::Comment("#Commented Directive = old".into())
        );
    }

    #[test]
    fn apply_changes_only_target_lines() {
        let changes = vec![("Max Children".to_string(), "8".to_string())];
        let (new_text, n) = apply(SAMPLE, &changes, Style::Plain);
        assert_eq!(n, 1);
        assert!(new_text.contains("Max Children = 8"));
        // every comment survives byte-for-byte
        assert!(new_text.contains("# Main section — do not remove"));
        assert!(new_text.contains("# Queue handling (see docs)"));
        assert!(new_text.contains("#Commented Directive = old"));
        // untouched entries survive
        assert!(new_text.contains("Run As User = mailnull"));
    }

    #[test]
    fn apply_appends_missing_keys() {
        let (new_text, _) = apply("a = 1\n", &[("brand new".into(), "x".into())], Style::Plain);
        assert!(new_text.ends_with("brand new = x\n"));
    }

    #[test]
    fn toml_style_quotes_strings_not_numbers() {
        let src = "db_port = 3306\ndb_host = \"localhost\"\n# keep me\n";
        let (t, _) = apply(
            src,
            &[
                ("db_port".into(), "3307".into()),
                ("db_host".into(), "db.example".into()),
            ],
            Style::Toml,
        );
        assert!(t.contains("db_port = 3307"));
        assert!(t.contains("db_host = \"db.example\""));
        assert!(t.contains("# keep me"));
    }

    #[test]
    fn commented_directive_is_never_treated_as_entry() {
        let (t, _) = apply(
            "#Max Children = 5\nMax Children = 5\n",
            &[("Max Children".into(), "9".into())],
            Style::Plain,
        );
        assert_eq!(t, "#Max Children = 5\nMax Children = 9\n");
    }
}
