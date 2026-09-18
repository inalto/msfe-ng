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

/// Comment out every live `key = …` line (a directive this engine's parser
/// would reject must not stay in effect). Absent key: text unchanged.
pub fn remove_directive(text: &str, key: &str) -> String {
    let mut s = text
        .lines()
        .map(|l| {
            if !l.trim_start().starts_with('#') && line_key_matches(l, key) {
                format!("#{l}")
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
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

/// Where MailScanner actually loads custom functions from: its own
/// `Custom Functions Dir` directive, with `%etc-dir%`-style variables expanded
/// from the definitions at the top of the same file. Only when the directive
/// is absent does the configured `fallback` (`mailscanner_custom_dir`) apply —
/// installing the plugin anywhere else leaves `&MSFENGLogging` undefined
/// (ConfigServer's layout has no `/etc/MailScanner/custom` symlink).
pub fn custom_functions_dir(text: &str, fallback: &str) -> std::path::PathBuf {
    match get_directive(text, "Custom Functions Dir") {
        Some(v) if !v.is_empty() => std::path::PathBuf::from(expand_variables(text, v)),
        _ => std::path::PathBuf::from(fallback),
    }
}

/// The conf's own definition of `%name%` (e.g. `%rules-dir%`), variables
/// expanded; `None` when the conf does not define it.
pub fn variable(text: &str, name: &str) -> Option<String> {
    let v = expand_variables(text, name);
    (v != name && !v.is_empty()).then_some(v)
}

/// Substitute every `%name%` in `value` with its `%name% = …` definition from
/// the conf; unknown variables are left as-is.
pub fn expand_variables(text: &str, value: &str) -> String {
    let mut out = value.to_string();
    // Definitions may reference earlier ones (`%rules-dir% = %etc-dir%/rules`),
    // so pass again while something still expands (bounded: no cycles matter).
    for _ in 0..4 {
        let before = out.clone();
        for line in text.lines() {
            let t = line.trim_start();
            if !t.starts_with('%') {
                continue;
            }
            if let Some((name, val)) = t.split_once('=') {
                let name = name.trim();
                if name.ends_with('%') && out.contains(name) {
                    out = out.replace(name, val.trim());
                }
            }
        }
        if out == before {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_reads_a_definition_and_expands_nested_ones() {
        let conf = "%etc-dir% = /usr/mailscanner/etc\n%rules-dir% = %etc-dir%/rules\nMTA = exim\n";
        assert_eq!(
            variable(conf, "%rules-dir%").as_deref(),
            Some("/usr/mailscanner/etc/rules")
        );
        assert_eq!(variable(conf, "%org-name%"), None);
        assert_eq!(variable("", "%rules-dir%"), None);
    }

    #[test]
    fn remove_directive_disables_every_live_line_and_keeps_the_rest() {
        let conf = "MTA = exim\n# End Of File\nExim Command = /opt/x\nExim Command = /opt/y\n";
        assert_eq!(
            remove_directive(conf, "Exim Command"),
            "MTA = exim\n# End Of File\n#Exim Command = /opt/x\n#Exim Command = /opt/y\n"
        );
        // absent: untouched
        assert_eq!(
            remove_directive("MTA = exim\n", "Exim Command"),
            "MTA = exim\n"
        );
    }

    #[test]
    fn custom_dir_comes_from_the_conf_directive() {
        // ConfigServer layout: nothing under /etc/MailScanner at all.
        let conf = "Custom Functions Dir = /usr/mailscanner/usr/share/MailScanner/perl/custom\n";
        assert_eq!(
            custom_functions_dir(conf, "/etc/MailScanner/custom"),
            std::path::PathBuf::from("/usr/mailscanner/usr/share/MailScanner/perl/custom")
        );
    }

    #[test]
    fn custom_dir_expands_conf_variables() {
        let conf = "%etc-dir% = /usr/mailscanner/etc\nCustom Functions Dir = %etc-dir%/custom\n";
        assert_eq!(
            custom_functions_dir(conf, "/etc/MailScanner/custom"),
            std::path::PathBuf::from("/usr/mailscanner/etc/custom")
        );
    }

    #[test]
    fn custom_dir_falls_back_to_config_when_directive_is_missing() {
        assert_eq!(
            custom_functions_dir("Foo = bar\n", "/etc/MailScanner/custom"),
            std::path::PathBuf::from("/etc/MailScanner/custom")
        );
        assert_eq!(
            custom_functions_dir("Custom Functions Dir =\n", "/etc/MailScanner/custom"),
            std::path::PathBuf::from("/etc/MailScanner/custom")
        );
    }

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
