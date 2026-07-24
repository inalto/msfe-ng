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
/// Live (uncommented) directives always win: the first live `key = ...` line
/// is replaced and any later live duplicates are commented out (MailScanner
/// takes the last occurrence, so a surviving duplicate would silently
/// override the edit). Only when the key has no live line at all is the first
/// `#`-commented mention taken over — stock MailScanner.conf is full of
/// commented examples (`#Run As User = mail`) sitting *above* the real
/// directive, and touching those instead of the live line leaves the stock
/// value in effect. If the key appears nowhere, it is appended.
pub fn set_directive(text: &str, key: &str, value: &str) -> String {
    let live = |l: &str| !l.trim_start().starts_with('#') && line_key_matches(l, key);
    let has_live = text.lines().any(live);
    let mut out = Vec::new();
    let mut done = false;
    for line in text.lines() {
        if live(line) {
            if done {
                out.push(format!("#{line}")); // duplicate would win — disable it
            } else {
                out.push(format!("{key} = {value}"));
                done = true;
            }
        } else if !has_live && !done && line_key_matches(line, key) {
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
    fn live_line_wins_over_commented_example() {
        // stock MailScanner.conf has doc examples like "#	Incoming Queue Dir = …"
        // far above the real directive — the live line must be the one edited.
        let conf = "#\tIncoming Queue Dir = /var/spool/mqueue.in\nFoo = bar\nIncoming Queue Dir = /var/spool/mqueue.in\n";
        let out = set_directive(
            conf,
            "Incoming Queue Dir",
            "/var/spool/exim/mailscanner/input/*",
        );
        assert_eq!(
            out,
            "#\tIncoming Queue Dir = /var/spool/mqueue.in\nFoo = bar\nIncoming Queue Dir = /var/spool/exim/mailscanner/input/*\n"
        );
    }

    #[test]
    fn later_live_duplicates_are_disabled() {
        // MailScanner takes the last occurrence, so duplicates must not survive.
        let conf = "Run As User = old\nMiddle = x\nRun As User =\n";
        let out = set_directive(conf, "Run As User", "mailnull");
        assert_eq!(out, "Run As User = mailnull\nMiddle = x\n#Run As User =\n");
        assert_eq!(set_directive(&out, "Run As User", "mailnull"), out); // idempotent
        assert_eq!(get_directive(&out, "Run As User"), Some("mailnull"));
    }

    #[test]
    fn commented_get_is_none() {
        assert_eq!(
            get_directive("#Always Looked Up Last = x\n", LOGGING_DIRECTIVE),
            None
        );
    }
}
