//! Reject at SMTP time: match rules in Exim's DATA ACL.
//!
//! A match rule normally acts inside MailScanner — the message is accepted,
//! queued, scanned, scored 100 and dropped by the high-spam action, and the
//! source is banned a minute later from the log. With `smtp = true` the rule
//! also bites on the connection: Exim refuses the message at `DATA` with a
//! 550, nothing is queued, MailScanner never sees it, and the minute cron bans
//! the source from `exim_rejectlog` instead. A bot flooding the same subject
//! then costs a refused DATA per attempt, not a scan.
//!
//! The rules become one `deny` stanza each in
//! `<confdir>/exim/smtp-deny.conf`, included from cPanel's custom ACL hook for
//! the message check (`.include_if_exists`, so deleting the fragment is the
//! kill switch; the hook line is harmless without it). Authenticated
//! submissions and loopback are exempt — a local user's reply quoting a banned
//! subject must still go out — and so is every sender on the global whitelist
//! (`smtp-deny-whitelist`, regenerated with the fragment). The SpamAssassin
//! rule stays in place as the second line of defence.
//!
//! Two things about the host cannot be known from here and are therefore
//! overridable: the cPanel ACL block directory ([`DEFAULT_BLOCK`],
//! `MSFE_NG_SMTP_DENY_BLOCK`) and whether a running Exim notices a changed
//! included file (assumed not: Exim is restarted after every change).

use crate::autoban::{self, MatchRule};
use crate::config::Config;
use crate::json::Json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---- paths -----------------------------------------------------------------------

/// cPanel's directory of custom ACL blocks.
pub const DEFAULT_ACL_DIR: &str = "/usr/local/cpanel/etc/exim/acls";
/// The block that runs at the start of cPanel's message check (`acl_smtp_data`,
/// before cPanel's own scans). **Verify on a host before the first live use**:
/// `ls /usr/local/cpanel/etc/exim/acls/` must list it, and after
/// `/scripts/buildeximconf` the built `/etc/exim.conf` must carry our
/// `.include_if_exists` line inside the DATA ACL. The doctor checks the second
/// part; the directory name is overridable with `MSFE_NG_SMTP_DENY_BLOCK`.
pub const DEFAULT_BLOCK: &str = "ACL_CHECK_MESSAGE_PRE_BLOCK";
/// The file inside the block that cPanel includes (the `custom_begin_` prefix
/// is cPanel's convention, as for the named-queue hook in `ACL_MAIL_PRE_BLOCK`).
pub const HOOK_FILE: &str = "custom_begin_check_message_pre";
pub const FRAGMENT: &str = "smtp-deny.conf";
pub const WHITELIST: &str = "smtp-deny-whitelist";
/// What every stanza writes to the reject log; the tailer looks for it.
pub const TAG: &str = "MSFE-NG rule #";
/// What the sending MTA sees (Exim prefixes the 550).
pub const MESSAGE: &str = "Rejected by local policy";
pub const REJECTLOG: &str = "/var/log/exim_rejectlog";

const EXIM: &str = "/usr/sbin/exim";
const BUILDEXIMCONF: &str = "/scripts/buildeximconf";
const RESTARTSRV_EXIM: &str = "/scripts/restartsrv_exim";

pub fn acl_dir() -> PathBuf {
    std::env::var("MSFE_NG_EXIM_ACL_DIR")
        .unwrap_or_else(|_| DEFAULT_ACL_DIR.to_string())
        .into()
}

pub fn block_name() -> String {
    std::env::var("MSFE_NG_SMTP_DENY_BLOCK").unwrap_or_else(|_| DEFAULT_BLOCK.to_string())
}

/// The cPanel hook file our include line goes into.
pub fn hook_path() -> PathBuf {
    acl_dir().join(block_name()).join(HOOK_FILE)
}

/// `<confdir>/exim`: where the fragment and the whitelist live.
pub fn exim_dir(config_file: &Path) -> PathBuf {
    config_file
        .parent()
        .unwrap_or(Path::new("/etc/msfe-ng"))
        .join("exim")
}

pub fn fragment_path(config_file: &Path) -> PathBuf {
    exim_dir(config_file).join(FRAGMENT)
}

pub fn whitelist_path(config_file: &Path) -> PathBuf {
    exim_dir(config_file).join(WHITELIST)
}

pub fn include_line(config_file: &Path) -> String {
    format!(
        ".include_if_exists {}",
        fragment_path(config_file).display()
    )
}

pub fn rejectlog_path() -> PathBuf {
    std::env::var("MSFE_NG_EXIM_REJECTLOG")
        .unwrap_or_else(|_| REJECTLOG.to_string())
        .into()
}

fn skip_cmds() -> bool {
    std::env::var_os("MSFE_NG_SKIP_EXIM_CMDS").is_some()
}

/// cPanel only: the hook is cPanel's mechanism. The test override of the ACL
/// directory counts as cPanel.
pub fn applicable(cfg: &Config) -> bool {
    cfg.panel == "cpanel" || std::env::var_os("MSFE_NG_EXIM_ACL_DIR").is_some()
}

// ---- the rules that reject --------------------------------------------------------

/// Can a rule on this field reject at SMTP time? The DATA ACL sees the
/// headers and the envelope, not the body (`$message_body` is a few hundred
/// bytes of it).
pub fn smtp_allowed(field: &str) -> bool {
    field != "body" && autoban::valid_field(field)
}

/// The enabled rules that reject at SMTP time, in id order.
pub fn active(rules: &[MatchRule]) -> Vec<&MatchRule> {
    let mut v: Vec<&MatchRule> = rules
        .iter()
        .filter(|r| r.enabled && r.smtp && smtp_allowed(&r.field))
        .collect();
    v.sort_by_key(|r| r.id);
    v
}

// ---- the fragment -----------------------------------------------------------------

/// Make `s` safe inside an Exim string expansion: a backslash escapes the
/// next character, `$` starts an item and braces delimit arguments, so each
/// of them is backslash-escaped. Exim turns `\\` back into `\`, `\$` into `$`
/// and `\{` / `\}` into the brace, so what reaches the regex engine is
/// exactly `s`; a `\N` in the input becomes `\\N` and can no longer open
/// Exim's "copy verbatim" mode.
pub fn escape_expansion(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' | '$' | '{' | '}' => {
                out.push('\\');
                out.push(c);
            }
            // never let a pattern span lines or carry a control character
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// The regex Exim's `match` gets: SpamAssassin's `/pattern/flags` (the same
/// `pattern_to_regex` the SA rule uses) as `(?flags)pattern`, escaped for
/// the expansion.
pub fn exim_regex(matcher: &str, pattern: &str) -> Result<String, String> {
    let re = autoban::pattern_to_regex(matcher, pattern)?;
    let rest = re
        .strip_prefix('/')
        .ok_or("a regex must look like /pattern/flags")?;
    let end = rest
        .rfind('/')
        .ok_or("a regex must look like /pattern/flags")?;
    let (pat, flags) = (&rest[..end], &rest[end + 1..]);
    if !flags.chars().all(|c| matches!(c, 'i' | 'm' | 's' | 'x')) {
        return Err(format!("unsupported regex flags '{flags}'"));
    }
    // `/a\/b/` is how SpamAssassin writes a slash; PCRE wants a plain one
    let pat = pat.replace("\\/", "/");
    let raw = if flags.is_empty() {
        pat
    } else {
        format!("(?{flags}){pat}")
    };
    Ok(escape_expansion(&raw))
}

/// The `condition = ` expansion for a field, `re` already escaped.
pub fn condition(field: &str, re: &str) -> Option<String> {
    let m = |v: &str| format!("match{{{v}}}{{{re}}}");
    Some(match field {
        "subject" => format!("${{if {}}}", m("$h_subject:")),
        "from" => format!(
            "${{if or{{{{{}}}{{{}}}}}}}",
            m("$h_from:"),
            m("$sender_address")
        ),
        "to" => format!(
            "${{if or{{{{{}}}{{{}}}{{{}}}}}}}",
            m("$h_to:"),
            m("$h_cc:"),
            m("$recipients")
        ),
        f => {
            let h = f.strip_prefix("header:")?;
            format!("${{if {}}}", m(&format!("$h_{}:", h.to_ascii_lowercase())))
        }
    })
}

fn clip(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s.to_string(),
    }
}

/// One `deny` stanza; `None` for a rule that cannot reject at SMTP time.
pub fn stanza(r: &MatchRule, whitelist: &Path) -> Option<String> {
    if !smtp_allowed(&r.field) {
        return None;
    }
    let re = exim_regex(&r.matcher, &r.pattern).ok()?;
    let cond = condition(&r.field, &re)?;
    let what = escape_expansion(&format!(
        "{} {} {}",
        r.field,
        r.matcher,
        clip(r.pattern.trim(), 60)
    ));
    Some(format!(
        "\n# rule #{id}{comment}\n\
         deny  !authenticated = *\n\
         \x20     !hosts         = <; 127.0.0.0/8 ; ::1\n\
         \x20     !senders       = nwildlsearch;{wl}\n\
         \x20     condition      = {cond}\n\
         \x20     message        = {MESSAGE} ({TAG}{id})\n\
         \x20     log_message    = {TAG}{id}: {what}\n",
        id = r.id,
        comment = if r.comment.trim().is_empty() {
            String::new()
        } else {
            format!(" — {}", clip(r.comment.trim(), 80).replace('\n', " "))
        },
        wl = whitelist.display(),
    ))
}

/// The whole fragment: the banner, then one stanza per active rule. An
/// empty set still yields the banner (the caller removes the file instead).
pub fn fragment_text(rules: &[MatchRule], whitelist: &Path) -> String {
    let mut out = String::from(
        "# Managed by MSFE-NG (Rules → Auto-ban match rules, \"Also reject at SMTP time\"); edits are overwritten.\n\
         # Included from cPanel's message-check ACL; deleting this file switches the rejects off.\n\
         # Authenticated submissions, loopback and whitelisted senders are never refused.\n",
    );
    for r in active(rules) {
        if let Some(s) = stanza(r, whitelist) {
            out.push_str(&s);
        }
    }
    out
}

// ---- the whitelist ---------------------------------------------------------------

/// One `nwildlsearch` key for a MailScanner whitelist pattern, or `None` for
/// a pattern Exim cannot take (an IP, a `/regex/`, `default`, odd characters):
/// `user@domain` and `*@domain` as they are (a leading `*` means "ends with"),
/// `*@*.domain` and `user@*` as anchored regexes, a bare `domain` as `*@domain`.
pub fn whitelist_key(pattern: &str) -> Option<String> {
    let p = pattern.trim().to_ascii_lowercase();
    if p.is_empty()
        || p == "default"
        || p.starts_with('#')
        || p.starts_with('/')
        || !p.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'@' | b'*')
        })
    {
        return None;
    }
    let is_domain = |d: &str| {
        !d.is_empty()
            && !d.starts_with('.')
            && !d.ends_with('.')
            && d.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            && !d.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    };
    let rx = |s: &str| -> String {
        let mut o = String::new();
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || c == '_' {
                o.push(c);
            } else if c == '*' {
                o.push_str(".*");
            } else {
                o.push('\\');
                o.push(c);
            }
        }
        o
    };
    match p.split_once('@') {
        None => is_domain(&p).then(|| format!("*@{p}")),
        Some((local, domain)) => {
            if local.is_empty() || domain.is_empty() || domain.contains('@') {
                return None;
            }
            let any_local = local == "*";
            let sub = domain.strip_prefix("*.");
            match (any_local, sub) {
                (true, None) if is_domain(domain) => Some(p.clone()),
                (false, None) if !local.contains('*') && is_domain(domain) => Some(p.clone()),
                (_, Some(d)) if is_domain(d) => Some(format!("^{}@.*\\.{}$", rx(local), rx(d))),
                (false, None) if domain == "*" => Some(format!("^{}@.*$", rx(local))),
                _ => None,
            }
        }
    }
}

/// The lookup file: one key per usable pattern, a comment line otherwise.
pub fn whitelist_text(patterns: &[String]) -> String {
    let mut out = String::from(
        "# Managed by MSFE-NG: the global whitelist as Exim nwildlsearch keys. Senders listed here are\n\
         # never refused by the SMTP-time match rules. Regenerated with smtp-deny.conf.\n",
    );
    let mut seen = std::collections::BTreeSet::new();
    for p in patterns {
        match whitelist_key(p) {
            Some(k) if seen.insert(k.clone()) => {
                out.push_str(&k);
                out.push('\n');
            }
            Some(_) => {}
            None => out.push_str(&format!(
                "# skipped (not an address pattern): {}\n",
                clip(p.trim(), 80).replace('\n', " ")
            )),
        }
    }
    out
}

/// Every whitelist pattern the policy holds: the global list plus the
/// per-domain ones (a sender a domain whitelists is never refused for
/// anyone — refusing is global, so the exemption errs on the side of
/// delivering).
pub fn whitelist_patterns(policy_dir: &Path) -> Vec<String> {
    let (_, wl, _) = crate::sync::load_policy(policy_dir);
    let mut out = wl;
    for (_, p) in crate::sync::load_overrides(policy_dir) {
        out.extend(p.whitelist);
    }
    out
}

// ---- the reject log ---------------------------------------------------------------

/// One message our ACL refused, as the reject log tells it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reject {
    /// `YYYY-MM-DD HH:MM:SS`, the server's local time.
    pub ts: String,
    pub ip: String,
    pub sender: String,
    pub rule_id: u32,
    /// Exim's `log_message` after the tag: `<field> <matcher> <pattern>`.
    pub what: String,
    /// From the headers Exim appends to the log entry, when it does.
    pub subject: String,
}

pub fn reject_json(r: &Reject) -> Json {
    Json::Object(vec![
        ("ts".into(), Json::str(&r.ts)),
        ("ip".into(), Json::str(&r.ip)),
        ("sender".into(), Json::str(&r.sender)),
        ("rule_id".into(), Json::Int(r.rule_id as i64)),
        ("what".into(), Json::str(&r.what)),
        ("subject".into(), Json::str(&r.subject)),
    ])
}

fn is_log_line(l: &str) -> bool {
    l.len() >= 20 && l.as_bytes()[4] == b'-' && l.as_bytes()[7] == b'-' && l.as_bytes()[10] == b' '
}

/// The rejects with our tag in a stretch of `exim_rejectlog`, oldest first.
/// A DATA rejection is followed by the message's headers (Exim's
/// `rejected_header` log selector, on by default), each prefixed by a
/// one-letter spool flag and a space, or two spaces; the subject is taken
/// from there when present.
pub fn parse_rejects(text: &str) -> Vec<Reject> {
    let mut out: Vec<Reject> = Vec::new();
    let mut open = false;
    for line in text.lines() {
        if is_log_line(line) {
            open = false;
            // only the log entry of a DATA deny of ours (`rejected after
            // DATA: <log_message>`); the SMTP response text carries the tag
            // too, but never at this position
            let marker = format!("rejected after DATA: {TAG}");
            let Some(i) = line.find(&marker) else {
                continue;
            };
            let Some(base) = crate::deliverylog::parse_rejectlog_line(line) else {
                continue;
            };
            let after = &line[i + marker.len()..];
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            let Ok(rule_id) = digits.parse::<u32>() else {
                continue;
            };
            let what = after[digits.len()..]
                .strip_prefix(':')
                .unwrap_or("")
                .trim()
                .to_string();
            out.push(Reject {
                ts: base.ts,
                ip: base.ip.unwrap_or_default(),
                sender: base.who.unwrap_or_default(),
                rule_id,
                what,
                subject: String::new(),
            });
            open = true;
            continue;
        }
        if !open {
            continue;
        }
        if line.trim().is_empty() {
            open = false;
            continue;
        }
        // "  Subject: x" or "F Subject: x" (any flag letter)
        let body = match line.as_bytes() {
            [_, b' ', ..] => &line[2..],
            _ => continue,
        };
        if body.len() >= 8 && body[..8].eq_ignore_ascii_case("subject:") {
            if let Some(last) = out.last_mut() {
                if last.subject.is_empty() {
                    last.subject = body[8..].trim().chars().take(200).collect();
                }
            }
        }
    }
    out
}

/// Where the tailer stopped: the file's inode and the byte offset after the
/// last complete line. Stored as `"<inode>:<pos>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cursor {
    pub inode: u64,
    pub pos: u64,
}

impl Cursor {
    pub fn parse(s: &str) -> Cursor {
        let (i, p) = s.trim().split_once(':').unwrap_or(("0", "0"));
        Cursor {
            inode: i.parse().unwrap_or(0),
            pos: p.parse().unwrap_or(0),
        }
    }
    pub fn to_kv(self) -> String {
        format!("{}:{}", self.inode, self.pos)
    }
}

/// The complete lines written to `path` since `cur`, and the new cursor. A
/// rotated file (new inode) or a truncated one (shorter than `pos`) is read
/// from the start. Bounded to the last 8 MB, so a first run over a huge log
/// stays quick.
pub fn tail_since(path: &Path, cur: Cursor) -> std::io::Result<(String, Cursor)> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;
    const MAX: u64 = 8 << 20;
    let meta = std::fs::metadata(path)?;
    let inode = meta.ino();
    let len = meta.len();
    let mut start = if inode == cur.inode && cur.pos <= len {
        cur.pos
    } else {
        0
    };
    if len - start > MAX {
        start = len - MAX;
    }
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::new();
    f.take(len - start).read_to_end(&mut buf)?;
    // only complete lines: a line still being written waits for the next run
    let keep = match buf.iter().rposition(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => 0,
    };
    let text = String::from_utf8_lossy(&buf[..keep]).into_owned();
    Ok((
        text,
        Cursor {
            inode,
            pos: start + keep as u64,
        },
    ))
}

/// The newest `limit` rejects of ours in the reject log (its last 4 MB),
/// newest first.
pub fn recent(limit: usize) -> Vec<Reject> {
    use std::io::{Read, Seek, SeekFrom};
    let path = rejectlog_path();
    let Ok(meta) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    let start = meta.len().saturating_sub(4 << 20);
    let Ok(mut f) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    if f.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    if f.read_to_end(&mut buf).is_err() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&buf);
    // drop a partial first line
    let text = if start > 0 {
        text.split_once('\n').map(|(_, r)| r).unwrap_or("")
    } else {
        &text
    };
    let mut v = parse_rejects(text);
    v.reverse();
    v.truncate(limit.clamp(1, 1000));
    v
}

/// `YYYY-MM-DD HH:MM:SS` → seconds, read as if UTC (the log is in local
/// time; compare only with stamps from the same clock).
pub fn stamp_secs(ts: &str) -> Option<u64> {
    let (d, t) = ts.split_once(' ')?;
    let date = crate::civil::Date::parse(d)?;
    let mut it = t.split(':');
    let h: u64 = it.next()?.parse().ok()?;
    let m: u64 = it.next()?.parse().ok()?;
    let s: u64 = it.next()?.parse().ok()?;
    Some((date.to_days() as u64) * 86_400 + h * 3600 + m * 60 + s)
}

/// Rejects per rule among `rejects` not older than `window` before `now`
/// (`now` in the log's clock, see [`local_now_secs`]).
pub fn counts(rejects: &[Reject], now: u64, window: u64) -> BTreeMap<u32, usize> {
    let mut out = BTreeMap::new();
    for r in rejects {
        if stamp_secs(&r.ts).is_some_and(|t| t + window >= now) {
            *out.entry(r.rule_id).or_insert(0) += 1;
        }
    }
    out
}

/// Now, in the server's local clock, as a UTC-read epoch (what
/// [`stamp_secs`] gives for a local timestamp of this instant). The offset
/// comes from `date +%z`; without it, UTC.
pub fn local_now_secs() -> u64 {
    let now = crate::dbtools::now_secs();
    let mut c = std::process::Command::new("date");
    c.arg("+%z");
    let off = crate::service::run_with_timeout(&mut c, Duration::from_secs(3))
        .ok()
        .and_then(|o| tz_offset_secs(o.stdout.trim()))
        .unwrap_or(0);
    (now as i64 + off).max(0) as u64
}

/// `+0200` → 7200, `-0530` → -19800.
pub fn tz_offset_secs(z: &str) -> Option<i64> {
    let z = z.trim();
    if z.len() != 5 {
        return None;
    }
    let sign = match &z[..1] {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };
    let h: i64 = z[1..3].parse().ok()?;
    let m: i64 = z[3..5].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

// ---- state on disk ----------------------------------------------------------------

/// Our include line is in the cPanel hook file.
pub fn hooked(config_file: &Path) -> bool {
    std::fs::read_to_string(hook_path())
        .is_ok_and(|t| t.lines().any(|l| l.trim() == include_line(config_file)))
}

/// The built `exim.conf` carries our include line (cPanel's build keeps the
/// hook's text, include lines included).
pub fn built(config_file: &Path) -> bool {
    std::fs::read_to_string(crate::engine::exim_conf_path())
        .is_ok_and(|t| t.lines().any(|l| l.trim() == include_line(config_file)))
}

pub fn fragment_present(config_file: &Path) -> bool {
    fragment_path(config_file).is_file()
}

/// What the doctor says about the wiring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoctorVerdict {
    /// No rule rejects at SMTP time, and no fragment is left behind.
    Silent,
    Ok(String),
    /// Stale or missing fragment, or the hook/built conf do not include it.
    Warn(String),
}

/// Pure: `active` rules exist, the fragment on disk (if any) equals
/// `expected`, the hook file has the include line, the built conf has it.
pub fn doctor_verdict(
    n_active: usize,
    fragment: Option<&str>,
    expected: &str,
    hooked: bool,
    built: bool,
    paths: (&Path, &Path, &Path),
) -> DoctorVerdict {
    let (frag, hook, conf) = paths;
    if n_active == 0 {
        return match fragment {
            None => DoctorVerdict::Silent,
            Some(_) => DoctorVerdict::Warn(format!(
                "{} is still on disk but no rule rejects at SMTP time any more — sync has not run since the rules changed",
                frag.display()
            )),
        };
    }
    match fragment {
        None => DoctorVerdict::Warn(format!(
            "{n_active} rule(s) are set to reject at SMTP time but {} does not exist — sync has not run since the rules changed",
            frag.display()
        )),
        Some(f) if f != expected => DoctorVerdict::Warn(format!(
            "{} does not match the saved rules — sync has not run since they changed",
            frag.display()
        )),
        Some(_) if !hooked => DoctorVerdict::Warn(format!(
            "{} lacks the include line for {} — the rules are not in Exim's DATA ACL (the cPanel block directory {} is assumed, see the wiki)",
            hook.display(),
            frag.display(),
            block_name()
        )),
        Some(_) if !built => DoctorVerdict::Warn(format!(
            "{} does not include {} — cPanel rebuilt exim.conf without the hook, or the block directory {} is not where cPanel reads it (verify with ls {} and the wiki's checklist)",
            conf.display(),
            frag.display(),
            block_name(),
            acl_dir().display()
        )),
        Some(_) => DoctorVerdict::Ok(format!(
            "{n_active} rule(s) refuse matching mail at DATA from {} (included by {}); the source is banned from {}",
            frag.display(),
            hook.display(),
            rejectlog_path().display()
        )),
    }
}

pub fn doctor(cfg: &Config, config_file: &Path, rules: &[MatchRule]) -> DoctorVerdict {
    if !applicable(cfg) {
        return DoctorVerdict::Silent;
    }
    let frag = fragment_path(config_file);
    let on_disk = std::fs::read_to_string(&frag).ok();
    let expected = fragment_text(rules, &whitelist_path(config_file));
    doctor_verdict(
        active(rules).len(),
        on_disk.as_deref(),
        &expected,
        hooked(config_file),
        built(config_file),
        (&frag, &hook_path(), &crate::engine::exim_conf_path()),
    )
}

// ---- running Exim and cPanel's scripts ------------------------------------------

fn run(argv: &[&str], secs: u64) -> Result<String, String> {
    let (bin, args) = argv.split_first().ok_or("empty command")?;
    let mut c = std::process::Command::new(bin);
    c.args(args);
    match crate::service::run_with_timeout(&mut c, Duration::from_secs(secs)) {
        Ok(o) => {
            let text = format!("{}{}", o.stdout, o.stderr).trim_end().to_string();
            if o.ok {
                Ok(text)
            } else if o.timed_out {
                Err(format!("{bin} did not finish in {secs} s"))
            } else {
                Err(if text.is_empty() {
                    format!("{bin} failed (exit {})", o.code.unwrap_or(-1))
                } else {
                    text
                })
            }
        }
        Err(e) => Err(format!("cannot run {bin}: {e}")),
    }
}

/// Does Exim take the regex? `exim -be` expands the rule's condition once
/// against a sample, so a PCRE error surfaces before anything is written
/// (perl has already accepted the pattern; the two engines rarely differ).
/// `Ok` when Exim is absent or the commands are skipped.
pub fn check_with_exim(matcher: &str, pattern: &str) -> Result<(), String> {
    if skip_cmds() || !Path::new(EXIM).exists() {
        return Ok(());
    }
    let re = exim_regex(matcher, pattern)?;
    let expr = format!("${{if match{{sample text}}{{{re}}}{{yes}}{{no}}}}");
    match run(&[EXIM, "-be", &expr], 10) {
        Ok(out) if out.trim() == "yes" || out.trim() == "no" => Ok(()),
        Ok(out) => Err(format!(
            "Exim does not take the pattern: {}",
            clip(out.trim(), 200)
        )),
        Err(e) => Err(format!("Exim does not take the pattern: {}", clip(&e, 200))),
    }
}

// ---- apply ------------------------------------------------------------------------

/// What a refresh did.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub ok: bool,
    pub dry_run: bool,
    /// The fragment or the whitelist changed on disk.
    pub changed: bool,
    /// Exim was restarted (or would be, on a dry run).
    pub restarted: bool,
    pub actions: Vec<String>,
}

pub fn report_json(r: &Report) -> Json {
    Json::Object(vec![
        ("ok".into(), Json::Bool(r.ok)),
        ("dry_run".into(), Json::Bool(r.dry_run)),
        ("changed".into(), Json::Bool(r.changed)),
        ("restarted".into(), Json::Bool(r.restarted)),
        (
            "transcript".into(),
            Json::Array(r.actions.iter().map(Json::str).collect()),
        ),
    ])
}

fn write_public(path: &Path, text: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
        let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755));
    }
    crate::sync::atomic_write(path, text.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}

fn remove_quiet(path: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Bring the fragment, the whitelist and the hook in line with the saved
/// rules and the policy: regenerate when a rule rejects at SMTP time, remove
/// the files otherwise (the hook line stays — harmless without the fragment).
/// A change is validated with `exim -bV`, rolled back when Exim refuses it,
/// and followed by an Exim restart (a running daemon does not re-read an
/// included file). Idempotent: nothing runs when nothing differs.
pub fn refresh(cfg: &Config, config_file: &Path, dry: bool) -> Report {
    let policy = crate::sync::policy_dir(config_file);
    let rules = autoban::load_match_rules(&policy);
    refresh_with(cfg, config_file, &rules, &whitelist_patterns(&policy), dry)
}

pub fn refresh_with(
    cfg: &Config,
    config_file: &Path,
    rules: &[MatchRule],
    whitelist: &[String],
    dry: bool,
) -> Report {
    let mut rep = Report {
        dry_run: dry,
        ..Default::default()
    };
    let n = active(rules).len();
    if !applicable(cfg) {
        rep.ok = n == 0;
        if n > 0 {
            rep.actions.push(
                "✗ rejecting at SMTP time is implemented for cPanel's Exim (custom ACL hook) only"
                    .into(),
            );
        }
        return rep;
    }
    let frag = fragment_path(config_file);
    let wl = whitelist_path(config_file);
    let hook = hook_path();
    let cur_frag = std::fs::read_to_string(&frag).ok();
    let cur_wl = std::fs::read_to_string(&wl).ok();
    let want = (n > 0).then(|| (fragment_text(rules, &wl), whitelist_text(whitelist)));
    let hooked = hooked(config_file);
    let same = match &want {
        None => cur_frag.is_none() && cur_wl.is_none(),
        Some((f, w)) => {
            cur_frag.as_deref() == Some(f.as_str()) && cur_wl.as_deref() == Some(w.as_str())
        }
    };
    let need_hook = want.is_some() && !hooked;
    if same && !need_hook {
        rep.ok = true;
        rep.actions.push(match n {
            0 => "no rule rejects at SMTP time; no fragment on disk".into(),
            _ => format!("{n} rule(s) already in {}", frag.display()),
        });
        return rep;
    }
    if dry {
        rep.ok = true;
        match &want {
            Some(_) => rep.actions.push(format!(
                "would write {} and {}",
                frag.display(),
                wl.display()
            )),
            None => rep.actions.push(format!(
                "would remove {} and {}",
                frag.display(),
                wl.display()
            )),
        }
        if need_hook {
            rep.actions.push(format!(
                "would add the include line to {} and run {BUILDEXIMCONF}",
                hook.display()
            ));
        }
        rep.actions
            .push(format!("would run: exim -bV, {RESTARTSRV_EXIM}"));
        rep.changed = !same;
        rep.restarted = true;
        return rep;
    }
    // every regex through Exim's own engine before anything is written
    if want.is_some() {
        for r in active(rules) {
            if let Err(e) = check_with_exim(&r.matcher, &r.pattern) {
                rep.actions
                    .push(format!("✗ rule #{}: {e} — nothing changed", r.id));
                return rep;
            }
        }
    }
    // write (or remove) the files
    match &want {
        Some((f, w)) => {
            for (p, t) in [(&wl, w), (&frag, f)] {
                if let Err(e) = write_public(p, t) {
                    rep.actions
                        .push(format!("✗ cannot write {}: {e}", p.display()));
                    return rep;
                }
                rep.actions.push(format!("wrote {}", p.display()));
            }
        }
        None => {
            for p in [&frag, &wl] {
                match remove_quiet(p) {
                    Ok(true) => rep.actions.push(format!("removed {}", p.display())),
                    Ok(false) => {}
                    Err(e) => {
                        rep.actions
                            .push(format!("✗ cannot remove {}: {e}", p.display()));
                        return rep;
                    }
                }
            }
        }
    }
    rep.changed = !same;
    // the hook line, once
    let mut rebuilt = false;
    if need_hook {
        let mut t = std::fs::read_to_string(&hook).unwrap_or_default();
        if !t.is_empty() && !t.ends_with('\n') {
            t.push('\n');
        }
        t.push_str(&include_line(config_file));
        t.push('\n');
        if let Err(e) = write_public(&hook, &t) {
            rep.actions
                .push(format!("✗ cannot write {}: {e}", hook.display()));
            rollback(&mut rep, &frag, &wl, cur_frag.as_deref(), cur_wl.as_deref());
            return rep;
        }
        rep.actions
            .push(format!("added the include line to {}", hook.display()));
        if skip_cmds() {
            rep.actions.push(format!("would run: {BUILDEXIMCONF}"));
        } else {
            match run(&[BUILDEXIMCONF], 300) {
                Ok(_) => {
                    rep.actions.push(format!("ran {BUILDEXIMCONF}: ok"));
                    rebuilt = true;
                }
                Err(e) => {
                    rep.actions.push(format!("✗ {BUILDEXIMCONF} failed: {e}"));
                    rollback(&mut rep, &frag, &wl, cur_frag.as_deref(), cur_wl.as_deref());
                    return rep;
                }
            }
        }
    }
    if skip_cmds() {
        rep.actions
            .push("validation skipped (MSFE_NG_SKIP_EXIM_CMDS)".into());
        rep.actions.push(format!("would run: {RESTARTSRV_EXIM}"));
        rep.ok = true;
        rep.restarted = true;
        return rep;
    }
    if let Err(e) = run(&[EXIM, "-bV"], 10) {
        rep.actions
            .push(format!("✗ exim -bV refuses the configuration: {e}"));
        rollback(&mut rep, &frag, &wl, cur_frag.as_deref(), cur_wl.as_deref());
        if rebuilt {
            match run(&[BUILDEXIMCONF], 300) {
                Ok(_) => rep.actions.push(format!("ran {BUILDEXIMCONF} again: ok")),
                Err(e) => rep
                    .actions
                    .push(format!("✗ {BUILDEXIMCONF} failed after the rollback: {e}")),
            }
        }
        return rep;
    }
    rep.actions
        .push("exim -bV: the configuration is valid".into());
    if want.is_some() && !built(config_file) {
        rep.actions.push(format!(
            "⚠ {} does not include the fragment: cPanel's build did not pick up {} — check that the block directory {} exists under {} (MSFE_NG_SMTP_DENY_BLOCK overrides it); the rules are saved but not in Exim's ACL",
            crate::engine::exim_conf_path().display(),
            hook.display(),
            block_name(),
            acl_dir().display()
        ));
    }
    match run(&[RESTARTSRV_EXIM], 120) {
        Ok(_) => {
            rep.actions
                .push(format!("ran {RESTARTSRV_EXIM}: Exim restarted"));
            rep.restarted = true;
            rep.ok = true;
        }
        Err(e) => rep.actions.push(format!(
            "✗ {RESTARTSRV_EXIM} failed: {e} — the configuration is valid; restart Exim by hand"
        )),
    }
    rep
}

fn rollback(
    rep: &mut Report,
    frag: &Path,
    wl: &Path,
    prev_frag: Option<&str>,
    prev_wl: Option<&str>,
) {
    for (p, prev) in [(frag, prev_frag), (wl, prev_wl)] {
        let r = match prev {
            Some(t) => write_public(p, t),
            None => remove_quiet(p).map(|_| ()),
        };
        match r {
            Ok(()) => rep
                .actions
                .push(format!("put {} back as it was", p.display())),
            Err(e) => rep
                .actions
                .push(format!("✗ cannot put {} back: {e}", p.display())),
        }
    }
    rep.changed = false;
}

/// Remove the fragment and the whitelist (the kill switch), leaving the
/// hook line; Exim is restarted so the rejects stop at once.
pub fn remove(cfg: &Config, config_file: &Path, dry: bool) -> Report {
    refresh_with(cfg, config_file, &[], &[], dry)
}

// ---- the ban source for autoban::run ---------------------------------------------

/// The rejects written since the stored cursor, and the cursor to store.
/// Nothing is read when no rule bans from SMTP-time rejects.
pub fn new_rejects(cfg: &Config, rules: &[MatchRule]) -> (Vec<Reject>, Option<Cursor>) {
    if !active(rules).iter().any(|r| r.ban_secs > 0) {
        return (Vec::new(), None);
    }
    let cur = crate::db::kv_get(cfg, "autoban_rejectlog_pos")
        .map(|s| Cursor::parse(&s))
        .unwrap_or_default();
    match tail_since(&rejectlog_path(), cur) {
        Ok((text, next)) => (parse_rejects(&text), Some(next)),
        Err(_) => (Vec::new(), None),
    }
}

/// Ban candidates from the rejects: the first refused message bans, for
/// the rule's duration; `count` is how many were refused in this batch.
pub fn candidates(rejects: &[Reject], rules: &[MatchRule]) -> Vec<autoban::Candidate> {
    let mut by_ip: BTreeMap<&str, Vec<&Reject>> = BTreeMap::new();
    for r in rejects {
        if !r.ip.is_empty() {
            by_ip.entry(r.ip.as_str()).or_default().push(r);
        }
    }
    let mut out = Vec::new();
    for (ip, hits) in by_ip {
        let mut best: Option<autoban::Candidate> = None;
        for m in active(rules).into_iter().filter(|m| m.ban_secs > 0) {
            let mine: Vec<&&Reject> = hits.iter().filter(|r| r.rule_id == m.id).collect();
            let Some(last) = mine.last() else {
                continue;
            };
            let c = autoban::Candidate {
                ip: ip.to_string(),
                reason: "smtp".into(),
                rule_id: Some(m.id),
                count: mine.len() as u32,
                seconds: m.ban_secs,
                sample_id: 0,
                detail: format!(
                    "MSFE-NG auto-ban: refused at SMTP time by rule #{}{}{}",
                    m.id,
                    if m.comment.trim().is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", m.comment.trim())
                    },
                    if last.subject.is_empty() {
                        String::new()
                    } else {
                        format!(" — {}", clip(&last.subject, 60))
                    }
                ),
            };
            if best.as_ref().map_or(true, |b| c.seconds > b.seconds) {
                best = Some(c);
            }
        }
        out.extend(best);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: u32, field: &str, matcher: &str, pattern: &str, smtp: bool) -> MatchRule {
        MatchRule {
            id,
            enabled: true,
            field: field.into(),
            matcher: matcher.into(),
            pattern: pattern.into(),
            block: true,
            ban_secs: 86_400,
            smtp,
            comment: String::new(),
            created: String::new(),
        }
    }

    /// Undo Exim's expansion escapes (what `expand_string` does with literal
    /// text): `\x` → `x`.
    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\\' {
                if let Some(n) = it.next() {
                    out.push(n);
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Count unescaped braces (what Exim's argument reader sees); `$` outside
    /// an escape would start an expansion item.
    fn unescaped(s: &str, which: char) -> usize {
        let mut n = 0;
        let mut esc = false;
        for c in s.chars() {
            if esc {
                esc = false;
                continue;
            }
            if c == '\\' {
                esc = true;
            } else if c == which {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn hostile_patterns_cannot_escape_the_expansion() {
        for (matcher, pattern) in [
            ("contains", "}}{run{/bin/sh}}"),
            ("contains", "${run{/bin/sh -c id}}"),
            ("contains", "\\N${run{id}}\\N"),
            ("regex", "a\\N}}}{{$x"),
            ("regex", "^\\d{3}\\$$"),
            ("regex", "/foo\\/bar/"),
            ("contains", "tab\there$"),
            ("regex", "\\\\N"),
        ] {
            let re = exim_regex(matcher, pattern).unwrap();
            assert_eq!(unescaped(&re, '$'), 0, "{pattern}: {re}");
            assert_eq!(unescaped(&re, '{'), 0, "{pattern}: {re}");
            assert_eq!(unescaped(&re, '}'), 0, "{pattern}: {re}");
            assert!(!re.contains("\\N") || re.contains("\\\\N"), "{re}");
            // never a bare \N: every backslash is itself escaped
            let mut it = re.chars().peekable();
            while let Some(c) = it.next() {
                if c == '\\' {
                    assert!(matches!(it.next(), Some('\\' | '$' | '{' | '}')), "{re}");
                }
            }
            // round trip through Exim's own unescaping gives the SA regex back
            let sa = autoban::pattern_to_regex(matcher, pattern).unwrap();
            let (pat, flags) = {
                let rest = &sa[1..];
                let e = rest.rfind('/').unwrap();
                (&rest[..e], &rest[e + 1..])
            };
            let expect = if flags.is_empty() {
                pat.replace("\\/", "/")
            } else {
                format!("(?{flags}){}", pat.replace("\\/", "/"))
            };
            assert_eq!(unescape(&re), expect.replace('\t', " "), "{pattern}");
            // the condition stays balanced for the argument reader
            let cond = condition("subject", &re).unwrap();
            assert_eq!(unescaped(&cond, '{'), unescaped(&cond, '}'), "{cond}");
            assert!(cond.starts_with("${if match{$h_subject:}{") && cond.ends_with("}}"));
        }
        assert!(exim_regex("regex", "/a/q").is_err());
        assert!(exim_regex("contains", " ").is_err());
    }

    #[test]
    fn conditions_per_field() {
        assert_eq!(
            condition("from", "x").unwrap(),
            "${if or{{match{$h_from:}{x}}{match{$sender_address}{x}}}}"
        );
        assert_eq!(
            condition("to", "x").unwrap(),
            "${if or{{match{$h_to:}{x}}{match{$h_cc:}{x}}{match{$recipients}{x}}}}"
        );
        assert_eq!(
            condition("header:X-Mailer", "x").unwrap(),
            "${if match{$h_x-mailer:}{x}}"
        );
        assert!(condition("body", "x").is_none());
        assert!(smtp_allowed("subject") && smtp_allowed("header:X-Spam") && !smtp_allowed("body"));
        assert!(!smtp_allowed("header:"));
    }

    #[test]
    fn fragment_renders_each_active_rule() {
        let mut a = rule(3, "subject", "contains", "account $uspended", true);
        a.comment = "suspension wave".into();
        let b = rule(4, "from", "regex", "@spammy\\.example$", true);
        let body = rule(5, "body", "contains", "x", true);
        let off = rule(6, "to", "contains", "x", false);
        let mut disabled = rule(7, "subject", "contains", "x", true);
        disabled.enabled = false;
        let wl = Path::new("/etc/msfe-ng/exim/smtp-deny-whitelist");
        let text = fragment_text(&[b.clone(), a.clone(), body, off, disabled], wl);
        assert!(text.starts_with("# Managed by MSFE-NG"));
        let stanzas: Vec<&str> = text.matches("\ndeny  ").collect();
        assert_eq!(stanzas.len(), 2, "{text}");
        assert!(
            text.find("# rule #3").unwrap() < text.find("# rule #4").unwrap(),
            "id order"
        );
        assert!(
            text.contains(
                "# rule #3 — suspension wave\n\
             deny  !authenticated = *\n\
             \x20     !hosts         = <; 127.0.0.0/8 ; ::1\n\
             \x20     !senders       = nwildlsearch;/etc/msfe-ng/exim/smtp-deny-whitelist\n\
             \x20     condition      = ${if match{$h_subject:}{(?i)account\\\\ \\\\\\$uspended}}\n\
             \x20     message        = Rejected by local policy (MSFE-NG rule #3)\n\
             \x20     log_message    = MSFE-NG rule #3: subject contains account \\$uspended\n"
            ),
            "{text}"
        );
        assert!(text.contains("condition      = ${if or{{match{$h_from:}{(?i)@spammy\\\\.example\\$}}{match{$sender_address}{(?i)@spammy\\\\.example\\$}}}}"), "{text}");
        assert!(fragment_text(&[], wl).starts_with("# Managed by MSFE-NG"));
        assert!(!fragment_text(&[], wl).contains("deny"));
        assert_eq!(active(&[a, b.clone()]).len(), 2);
        assert!(stanza(&rule(1, "body", "contains", "x", true), wl).is_none());
    }

    #[test]
    fn whitelist_keys_from_patterns() {
        assert_eq!(
            whitelist_key("User@Example.com").as_deref(),
            Some("user@example.com")
        );
        assert_eq!(
            whitelist_key("*@example.com").as_deref(),
            Some("*@example.com")
        );
        assert_eq!(
            whitelist_key("example.com").as_deref(),
            Some("*@example.com")
        );
        assert_eq!(
            whitelist_key("*@*.example.com").as_deref(),
            Some("^.*@.*\\.example\\.com$")
        );
        assert_eq!(
            whitelist_key("bob@*.example.com").as_deref(),
            Some("^bob@.*\\.example\\.com$")
        );
        assert_eq!(whitelist_key("bob@*").as_deref(), Some("^bob@.*$"));
        for bad in [
            "192.168.1.0/24",
            "10.0.0.1",
            "/.*@x/",
            "default",
            "a b@c.d",
            "@x.y",
            "x@",
            "#c",
            "",
        ] {
            assert_eq!(whitelist_key(bad), None, "{bad}");
        }
        let t = whitelist_text(&[
            "Example.com".into(),
            "*@example.com".into(),
            "10.0.0.1".into(),
            "a@b.c".into(),
        ]);
        assert_eq!(
            t,
            "# Managed by MSFE-NG: the global whitelist as Exim nwildlsearch keys. Senders listed here are\n\
             # never refused by the SMTP-time match rules. Regenerated with smtp-deny.conf.\n\
             *@example.com\n\
             # skipped (not an address pattern): 10.0.0.1\n\
             a@b.c\n"
        );
    }

    const LOG: &str = "2026-10-16 09:00:01 H=(x) [203.0.113.9]:4001 F=<spam@bad.example> rejected RCPT <a@b.c>: Rejected relay attempt\n\
2026-10-16 09:00:02 1vAbCd-0001xy-Zz H=mx.bad.example (ehlo) [203.0.113.5]:5555 I=[198.51.100.1]:25 F=<spam@bad.example> rejected after DATA: MSFE-NG rule #3: subject contains account suspended\n\
Envelope-from: <spam@bad.example>\n\
Envelope-to: <a@b.c>\n\
P Received: from mx.bad.example ([203.0.113.5])\n\
\tby mail.example.net with esmtp\n\
F From: Spammer <spam@bad.example>\n\
T To: a@b.c\n\
\x20 Subject: Your account suspended!\n\
I Message-ID: <1@bad.example>\n\
\n\
2026-10-16 09:00:03 H=(y) [203.0.113.5]:5556 F=<other@bad.example> rejected after DATA: MSFE-NG rule #4: from regex @bad\\.example$\n\
2026-10-16 09:00:04 H=(z) [203.0.113.7]:5557 F=<x@y.z> rejected after DATA: This message scored 20 spam points (mentions MSFE-NG rule #99 elsewhere)\n\
2026-10-16 09:00:05 SMTP call from [1.2.3.4] dropped: too many syntax errors\n";

    #[test]
    fn rejectlog_entries_are_parsed_with_their_subject() {
        let v = parse_rejects(LOG);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0].ts, "2026-10-16 09:00:02");
        assert_eq!(v[0].ip, "203.0.113.5");
        assert_eq!(v[0].sender, "spam@bad.example");
        assert_eq!(v[0].rule_id, 3);
        assert_eq!(v[0].what, "subject contains account suspended");
        assert_eq!(v[0].subject, "Your account suspended!");
        assert_eq!(
            (v[1].rule_id, v[1].subject.as_str(), v[1].ip.as_str()),
            (4, "", "203.0.113.5")
        );
        assert_eq!(v[1].what, "from regex @bad\\.example$");
        assert_eq!(reject_json(&v[0]).to_string(), "{\"ts\":\"2026-10-16 09:00:02\",\"ip\":\"203.0.113.5\",\"sender\":\"spam@bad.example\",\"rule_id\":3,\"what\":\"subject contains account suspended\",\"subject\":\"Your account suspended!\"}");
    }

    #[test]
    fn tail_follows_rotation_and_partial_lines() {
        let dir = std::env::temp_dir().join(format!("msfe-smtpdeny-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("exim_rejectlog");
        let line1 = LOG.lines().nth(1).unwrap();
        std::fs::write(&log, format!("{line1}\n2026-10-16 09:00:03 partial")).unwrap();
        let (text, c1) = tail_since(&log, Cursor::default()).unwrap();
        assert_eq!(text, format!("{line1}\n"));
        assert_eq!(c1.pos as usize, line1.len() + 1);
        assert_eq!(Cursor::parse(&c1.to_kv()), c1);
        // the partial line completes, plus another
        std::fs::write(&log, format!("{line1}\n2026-10-16 09:00:03 H=(y) [203.0.113.6]:1 F=<a@b> rejected after DATA: MSFE-NG rule #4: x\n")).unwrap();
        let (text, c2) = tail_since(&log, c1).unwrap();
        assert!(text.starts_with("2026-10-16 09:00:03 H=(y)"));
        assert_eq!(parse_rejects(&text).len(), 1);
        assert_eq!(c2.pos, std::fs::metadata(&log).unwrap().len());
        // nothing new
        let (text, c3) = tail_since(&log, c2).unwrap();
        assert!(text.is_empty() && c3 == c2);
        // rotation: a new inode starts from 0
        std::fs::remove_file(&log).unwrap();
        std::fs::write(&log, format!("{line1}\n")).unwrap();
        let (text, c4) = tail_since(
            &log,
            Cursor {
                inode: c2.inode + 1,
                pos: 99_999,
            },
        )
        .unwrap();
        assert_eq!(text, format!("{line1}\n"));
        assert_eq!(c4.pos as usize, line1.len() + 1);
        // truncation (same inode, shorter file) also restarts
        std::fs::write(&log, "2026-10-16 09:00:09 x\n").unwrap();
        let (text, _) = tail_since(
            &log,
            Cursor {
                inode: c4.inode,
                pos: 99_999,
            },
        )
        .unwrap();
        assert_eq!(text, "2026-10-16 09:00:09 x\n");
        assert!(tail_since(&dir.join("missing"), Cursor::default()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stamps_counts_and_offsets() {
        assert_eq!(stamp_secs("1970-01-02 00:00:01"), Some(86_401));
        assert_eq!(stamp_secs("junk"), None);
        assert_eq!(tz_offset_secs("+0200"), Some(7_200));
        assert_eq!(tz_offset_secs("-0530"), Some(-19_800));
        assert_eq!(tz_offset_secs("+02:00"), None);
        let v = parse_rejects(LOG);
        let now = stamp_secs("2026-10-17 08:00:00").unwrap();
        let c = counts(&v, now, 86_400);
        assert_eq!(c.get(&3), Some(&1));
        assert_eq!(c.get(&4), Some(&1));
        assert!(counts(&v, now + 7_200, 86_400).is_empty());
    }

    #[test]
    fn candidates_ban_once_per_ip_with_the_longest_rule() {
        let mut a = rule(3, "subject", "contains", "x", true);
        a.comment = "wave".into();
        let mut b = rule(4, "from", "regex", "x", true);
        b.ban_secs = 3_600;
        let mut noban = rule(5, "to", "contains", "x", true);
        noban.ban_secs = 0;
        let v = parse_rejects(LOG);
        let c = candidates(&v, &[a.clone(), b.clone(), noban]);
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].ip, "203.0.113.5");
        assert_eq!(
            (c[0].reason.as_str(), c[0].rule_id, c[0].count, c[0].seconds),
            ("smtp", Some(3), 1, 86_400)
        );
        assert_eq!(
            c[0].detail,
            "MSFE-NG auto-ban: refused at SMTP time by rule #3 (wave) — Your account suspended!"
        );
        // only rule #4 banning: same ip, that rule
        let c = candidates(&v, &[b]);
        assert_eq!((c.len(), c[0].rule_id, c[0].seconds), (1, Some(4), 3_600));
        // a rule that refuses without banning yields nothing
        let mut r3 = a.clone();
        r3.ban_secs = 0;
        assert!(candidates(&v, &[r3]).is_empty());
    }

    #[test]
    fn doctor_verdicts() {
        let p = (Path::new("/f"), Path::new("/h"), Path::new("/c"));
        assert_eq!(
            doctor_verdict(0, None, "", false, false, p),
            DoctorVerdict::Silent
        );
        assert!(
            matches!(doctor_verdict(0, Some("x"), "", true, true, p), DoctorVerdict::Warn(d) if d.contains("still on disk"))
        );
        assert!(
            matches!(doctor_verdict(2, None, "x", true, true, p), DoctorVerdict::Warn(d) if d.contains("does not exist"))
        );
        assert!(
            matches!(doctor_verdict(2, Some("y"), "x", true, true, p), DoctorVerdict::Warn(d) if d.contains("does not match"))
        );
        assert!(
            matches!(doctor_verdict(2, Some("x"), "x", false, true, p), DoctorVerdict::Warn(d) if d.contains("lacks the include line"))
        );
        assert!(
            matches!(doctor_verdict(2, Some("x"), "x", true, false, p), DoctorVerdict::Warn(d) if d.contains("does not include"))
        );
        assert!(
            matches!(doctor_verdict(2, Some("x"), "x", true, true, p), DoctorVerdict::Ok(d) if d.starts_with("2 rule(s) refuse"))
        );
    }

    #[test]
    fn refresh_under_the_env_overrides() {
        let _g = crate::engine::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("msfe-smtpdeny-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("policy")).unwrap();
        let config_file = root.join("config.toml");
        let exim_conf = root.join("exim.conf");
        std::fs::write(&exim_conf, "primary_hostname = h\n").unwrap();
        std::env::set_var("MSFE_NG_EXIM_ACL_DIR", root.join("acls"));
        std::env::set_var("MSFE_NG_EXIM_CONF", &exim_conf);
        std::env::set_var("MSFE_NG_SKIP_EXIM_CMDS", "1");
        let cfg = Config::default(); // panel "none": the override makes it applicable
        assert!(applicable(&cfg));
        let frag = fragment_path(&config_file);
        let wl = whitelist_path(&config_file);
        let hook = hook_path();
        assert_eq!(hook, root.join("acls").join(DEFAULT_BLOCK).join(HOOK_FILE));

        // nothing to do without rules
        let r = refresh_with(&cfg, &config_file, &[], &[], false);
        assert!(r.ok && !r.changed && !frag.exists(), "{r:?}");
        assert_eq!(doctor(&cfg, &config_file, &[]), DoctorVerdict::Silent);

        // a rule: dry run touches nothing
        let a = rule(3, "subject", "contains", "account suspended", true);
        let r = refresh_with(
            &cfg,
            &config_file,
            std::slice::from_ref(&a),
            &["*@vip.example".into()],
            true,
        );
        assert!(
            r.ok && r.dry_run && r.changed && !frag.exists() && !hook.exists(),
            "{r:?}"
        );

        let r = refresh_with(
            &cfg,
            &config_file,
            std::slice::from_ref(&a),
            &["*@vip.example".into()],
            false,
        );
        assert!(r.ok && r.changed && r.restarted, "{r:?}");
        assert_eq!(
            std::fs::read_to_string(&frag).unwrap(),
            fragment_text(std::slice::from_ref(&a), &wl)
        );
        assert!(std::fs::read_to_string(&wl)
            .unwrap()
            .ends_with("*@vip.example\n"));
        assert_eq!(
            std::fs::read_to_string(&hook).unwrap(),
            format!("{}\n", include_line(&config_file))
        );
        assert!(hooked(&config_file) && !built(&config_file));
        assert!(
            r.actions
                .iter()
                .any(|l| l.contains("would run: /scripts/buildeximconf")),
            "{r:?}"
        );
        // the doctor: hooked but the built conf lacks the line
        assert!(
            matches!(doctor(&cfg, &config_file, std::slice::from_ref(&a)), DoctorVerdict::Warn(d) if d.contains("does not include"))
        );
        std::fs::write(
            &exim_conf,
            format!(
                "primary_hostname = h\nbegin acl\n{}\n",
                include_line(&config_file)
            ),
        )
        .unwrap();
        assert!(matches!(
            doctor(&cfg, &config_file, std::slice::from_ref(&a)),
            DoctorVerdict::Ok(_)
        ));

        // idempotent
        let r = refresh_with(
            &cfg,
            &config_file,
            std::slice::from_ref(&a),
            &["*@vip.example".into()],
            false,
        );
        assert!(r.ok && !r.changed && !r.restarted, "{r:?}");

        // the whitelist alone changing is a change (and a restart)
        let r = refresh_with(&cfg, &config_file, std::slice::from_ref(&a), &[], false);
        assert!(r.ok && r.changed && r.restarted, "{r:?}");
        assert!(!std::fs::read_to_string(&wl).unwrap().contains("vip"));

        // the flag off: the files go, the hook line stays
        let mut off = a.clone();
        off.smtp = false;
        let r = refresh_with(&cfg, &config_file, &[off], &[], false);
        assert!(r.ok && r.changed, "{r:?}");
        assert!(!frag.exists() && !wl.exists() && hooked(&config_file));
        assert_eq!(doctor(&cfg, &config_file, &[]), DoctorVerdict::Silent);
        assert!(report_json(&r).to_string().starts_with("{\"ok\":true,"));

        // not applicable (no override, panel none): refused only when needed
        std::env::remove_var("MSFE_NG_EXIM_ACL_DIR");
        assert!(!applicable(&cfg));
        assert!(refresh_with(&cfg, &config_file, &[], &[], false).ok);
        assert!(!refresh_with(&cfg, &config_file, &[a], &[], false).ok);
        std::env::remove_var("MSFE_NG_EXIM_CONF");
        std::env::remove_var("MSFE_NG_SKIP_EXIM_CMDS");
        let _ = std::fs::remove_dir_all(&root);
    }
}
