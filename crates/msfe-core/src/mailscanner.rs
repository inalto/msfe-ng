//! Minimal, idempotent editing of `MailScanner.conf` directives.
//!
//! Used only by the opt-in `msfe-ng mailscanner enable-logging|disable-logging`
//! command to hook our logging plugin via `Always Looked Up Last = &MSFENGLogging`.
//! Editing a live config is deliberately explicit (never done by the installer)
//! and always makes a `.msfe-ng.bak` backup at the call site.

/// The MailScanner directive we hook logging onto.
pub const LOGGING_DIRECTIVE: &str = "Always Looked Up Last";
/// The custom function MailScanner calls per message when logging is enabled.
pub const LOGGING_VALUE: &str = "&MSFENGLogging";

/// Set `key = value` in a MailScanner.conf body, idempotently.
///
/// Replaces the first existing (possibly `#`-commented) `key = ...` line,
/// preserving surrounding lines; if the key is absent, appends it. MailScanner
/// directive keys contain spaces, so we match on the text before `=`.
pub fn set_directive(text: &str, key: &str, value: &str) -> String {
    let mut out = Vec::new();
    let mut done = false;
    for line in text.lines() {
        if !done && line_key_matches(line, key) {
            out.push(format!("{key} = {value}"));
            done = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !done {
        out.push(format!("{key} = {value}"));
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// True if `line` is an assignment of `key` (ignoring leading `#` and spaces).
fn line_key_matches(line: &str, key: &str) -> bool {
    let l = line.trim_start();
    let l = l.strip_prefix('#').unwrap_or(l);
    let l = l.trim_start();
    match l.split_once('=') {
        Some((lhs, _)) => lhs.trim() == key,
        None => false,
    }
}

/// Read the current value of a directive, if present and uncommented.
pub fn get_directive<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with('#') {
            continue;
        }
        if let Some((lhs, rhs)) = t.split_once('=') {
            if lhs.trim() == key {
                return Some(rhs.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_existing_directive() {
        let conf = "Foo = bar\nAlways Looked Up Last = no\nBaz = qux\n";
        let out = set_directive(conf, LOGGING_DIRECTIVE, LOGGING_VALUE);
        assert_eq!(
            out,
            "Foo = bar\nAlways Looked Up Last = &MSFENGLogging\nBaz = qux\n"
        );
        assert_eq!(
            get_directive(&out, LOGGING_DIRECTIVE),
            Some("&MSFENGLogging")
        );
    }

    #[test]
    fn uncomments_and_sets() {
        let conf = "#Always Looked Up Last = no\n";
        let out = set_directive(conf, LOGGING_DIRECTIVE, LOGGING_VALUE);
        assert_eq!(out, "Always Looked Up Last = &MSFENGLogging\n");
    }

    #[test]
    fn appends_when_absent() {
        let conf = "Foo = bar\n";
        let out = set_directive(conf, LOGGING_DIRECTIVE, LOGGING_VALUE);
        assert_eq!(out, "Foo = bar\nAlways Looked Up Last = &MSFENGLogging\n");
    }

    #[test]
    fn idempotent() {
        let conf = "Always Looked Up Last = &MSFENGLogging\n";
        let once = set_directive(conf, LOGGING_DIRECTIVE, LOGGING_VALUE);
        let twice = set_directive(&once, LOGGING_DIRECTIVE, LOGGING_VALUE);
        assert_eq!(once, twice);
    }

    #[test]
    fn commented_get_is_none() {
        assert_eq!(
            get_directive("#Always Looked Up Last = x\n", LOGGING_DIRECTIVE),
            None
        );
    }
}
