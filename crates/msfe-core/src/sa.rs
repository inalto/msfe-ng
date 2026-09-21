//! SpamAssassin Bayes training and spam-report parsing.
//!
//! Training operates on the raw message (piped to `sa-learn` on stdin), so it
//! works for any message whose body we can read — i.e. quarantined copies.
//! Report parsing turns MailScanner's stored `spamreport` string into the
//! rule/score component rows the full-email view shows.

use crate::service::ControlOutcome;
use crate::{engine, mailscanner, Config};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// ---- upstream rules ----------------------------------------------------------
//
// SpamAssassin loads the upstream ruleset from `<local state dir>/<version>/
// updates_spamassassin_org`, fetched by sa-update. Without it every scan runs
// on the site rules alone (seen where a CPAN SpamAssassin 4.0.2 whose 4.000002
// dir had never been created — cPanel's nightly sa-update feeds its own
// bundled 4.0.1 — so MailScanner scored with KAM + cPanel's 79 picked rules,
// and `spamassassin -r`, which insists on rules, refused to report).

/// Where the upstream rules for the SpamAssassin MailScanner loads stand.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RulesState {
    /// `$Mail::SpamAssassin::VERSION` under the engine's perl (`4.000002`).
    pub version: String,
    /// `<local state dir>/<version>/updates_spamassassin_org.cf`.
    pub updates_cf: PathBuf,
    /// Age of that file in days, `None` when it does not exist.
    pub age_days: Option<u64>,
}

/// Older than this and sa-update is not running.
pub const RULES_STALE_DAYS: u64 = 30;

fn sa_version(perl: &[String]) -> Option<String> {
    let (interp, args) = perl.split_first()?;
    let out = Command::new(interp)
        .args(args)
        .args([
            "-MMail::SpamAssassin",
            "-e",
            "print $Mail::SpamAssassin::VERSION",
        ])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// `SpamAssassin Local State Dir` from MailScanner.conf when set to a real
/// path (the stock file carries `= # /var/lib/spamassassin`), else SA's own
/// default.
fn local_state_dir(cfg: &Config) -> PathBuf {
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    mailscanner::get_directive(&conf, "SpamAssassin Local State Dir")
        .map(str::trim)
        .filter(|v| v.starts_with('/'))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/spamassassin"))
}

/// The state under the engine's perl; `None` when Mail::SpamAssassin does
/// not load there (the "available" check covers that).
pub fn rules_state(cfg: &Config, perl: &[String]) -> Option<RulesState> {
    let version = sa_version(perl)?;
    Some(rules_state_at(&local_state_dir(cfg), &version, now_secs()))
}

pub fn rules_state_at(state_dir: &std::path::Path, version: &str, now: u64) -> RulesState {
    let updates_cf = state_dir.join(version).join("updates_spamassassin_org.cf");
    let age_days = std::fs::metadata(&updates_cf)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| now.saturating_sub(d.as_secs()) / 86_400);
    RulesState {
        version: version.to_string(),
        updates_cf,
        age_days,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `(level ok?, fail-not-warn?, detail)` for the doctor.
pub fn rules_verdict(s: &RulesState) -> (bool, bool, String) {
    match s.age_days {
        None => (
            false,
            true,
            format!(
                "MailScanner scans with the site rules only — the upstream ruleset for SpamAssassin {} was never fetched ({} missing)",
                s.version,
                s.updates_cf.display()
            ),
        ),
        Some(d) if d > RULES_STALE_DAYS => (
            false,
            false,
            format!(
                "upstream ruleset for SpamAssassin {} is {d} days old — sa-update is not running",
                s.version
            ),
        ),
        Some(d) => (
            true,
            false,
            format!(
                "upstream ruleset for SpamAssassin {} updated {d} day(s) ago",
                s.version
            ),
        ),
    }
}

/// Fetch the upstream rules the way the engine's daily cron does: its own
/// `ms-update-sa` (sa-update, sa-compile, MailScanner restart), else the
/// sa-update beside the engine's perl and a reload. Returns what happened.
pub fn update_rules(perl: &[String]) -> (bool, String) {
    let ms = std::path::Path::new("/usr/sbin/ms-update-sa");
    if ms.is_file() {
        let ok = Command::new(ms)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|st| st.success());
        return (
            ok,
            format!(
                "ms-update-sa (sa-update, compile, MailScanner restart): {}",
                if ok { "ok" } else { "FAILED" }
            ),
        );
    }
    // sa-update lives beside the perl that owns Mail::SpamAssassin
    let sa_update = perl
        .first()
        .map(|p| std::path::Path::new(p).with_file_name("sa-update"))
        .filter(|p| p.is_file())
        .or_else(|| {
            ["/usr/local/bin/sa-update", "/usr/bin/sa-update"]
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file())
        });
    let Some(sa_update) = sa_update else {
        return (false, "no sa-update found".into());
    };
    let st = Command::new(&sa_update)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // sa-update: 0 = updated, 1 = nothing new, >1 = error
    let ok = st.as_ref().is_ok_and(|s| matches!(s.code(), Some(0 | 1)));
    if ok && st.is_ok_and(|s| s.code() == Some(0)) {
        crate::sync::reload_mailscanner();
    }
    (
        ok,
        format!(
            "{}: {}",
            sa_update.display(),
            if ok {
                "ok (MailScanner reloaded)"
            } else {
                "FAILED"
            }
        ),
    )
}

// ---- cPanel's SpamAssassin plugins -----------------------------------------
//
// WHM → Exim Configuration Manager → "Apache SpamAssassin: <plugin>" symlinks
// /usr/local/cpanel/etc/mail/spamassassin/<Name>.cf into the site rules dir.
// P0f's plugin needs cPanel's private perl (IO::SigGuard from its cpanel_lib)
// and cPanel's p0f daemon: under the system perl MailScanner runs, it fails
// to load — at every child start and in every sa-learn/spamassassin
// transcript (a migrated host). It serves cPanel's own spamd only.

/// A `loadplugin` of cPanel's in the site rules that the engine's perl
/// cannot load: `(tweak name, module path, first error line)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokenPlugin {
    pub name: String,
    pub module: String,
    pub error: String,
}

/// `loadplugin Module /usr/local/cpanel/...` lines of the site rules dir,
/// as `(file stem, module path)`.
pub fn cpanel_plugin_loads(site_rules_dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(site_rules_dir) else {
        return out;
    };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        let is_conf = path.extension().is_some_and(|e| e == "cf" || e == "pre");
        if !is_conf {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for l in text.lines() {
            let mut f = l.split_whitespace();
            if f.next() != Some("loadplugin") {
                continue;
            }
            let _module_name = f.next();
            if let Some(file) = f.next().filter(|p| p.starts_with("/usr/local/cpanel/")) {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push((stem, file.to_string()));
            }
        }
    }
    out
}

/// Which of cPanel's plugins fail to load under `perl` (cheap: only the
/// plugin file is required, not the ruleset).
pub fn broken_cpanel_plugins(
    perl: &[String],
    site_rules_dir: &std::path::Path,
) -> Vec<BrokenPlugin> {
    let Some((interp, args)) = perl.split_first() else {
        return Vec::new();
    };
    cpanel_plugin_loads(site_rules_dir)
        .into_iter()
        .filter_map(|(name, module)| {
            let out = Command::new(interp)
                .args(args)
                .args([
                    "-I",
                    "/usr/local/cpanel",
                    "-e",
                    "require $ARGV[0]; 1",
                    "--",
                    &module,
                ])
                .output()
                .ok()?;
            if out.status.success() {
                return None;
            }
            let err = String::from_utf8_lossy(&out.stderr);
            let first = err
                .lines()
                .find(|l| l.contains("Can't locate") || l.contains("error"))
                .or_else(|| err.lines().next())
                .unwrap_or("does not load")
                .trim()
                .to_string();
            Some(BrokenPlugin {
                name,
                module,
                error: first,
            })
        })
        .collect()
}

/// `(ok, detail)` for the doctor.
pub fn cpanel_plugins_verdict(broken: &[BrokenPlugin], spamd_disabled: bool) -> (bool, String) {
    if broken.is_empty() {
        return (
            true,
            "every SpamAssassin plugin in the site rules loads under MailScanner's perl".into(),
        );
    }
    let names: Vec<&str> = broken.iter().map(|b| b.name.as_str()).collect();
    let why = broken
        .iter()
        .map(|b| {
            let short = b
                .error
                .split(" (@INC")
                .next()
                .unwrap_or(&b.error)
                .to_string();
            format!("{}: {short}", b.name)
        })
        .collect::<Vec<_>>()
        .join("; ");
    (
        false,
        format!(
            "cPanel's SpamAssassin plugin(s) {} cannot load under MailScanner's perl — logged at every scan and in every learn/report transcript; they serve cPanel's own spamd{} ({why})",
            names.join(", "),
            if spamd_disabled { ", which is off" } else { "" }
        ),
    )
}

/// The WHM tweak that removes a plugin's symlink.
pub fn cpanel_plugin_off_command(name: &str) -> String {
    format!("whmapi1 set_tweaksetting module=Mail key=spamassassin_plugin_{name} value=0")
}

/// Turn the broken plugins off through cPanel's API. Returns what happened.
pub fn disable_cpanel_plugins(broken: &[BrokenPlugin]) -> Vec<String> {
    broken
        .iter()
        .map(|b| {
            let ok = Command::new("whmapi1")
                .args([
                    "--output=json",
                    "set_tweaksetting",
                    "module=Mail",
                    &format!("key=spamassassin_plugin_{}", b.name),
                    "value=0",
                ])
                .output()
                .is_ok_and(|o| {
                    o.status.success()
                        && String::from_utf8_lossy(&o.stdout).contains("\"result\":1")
                });
            format!(
                "cPanel SpamAssassin plugin {} turned off in WHM: {}",
                b.name,
                if ok { "ok" } else { "FAILED" }
            )
        })
        .collect()
}

/// The Bayes DB MailScanner scans with: `<SpamAssassin User State Dir>/bayes`
/// from MailScanner.conf, or `None` when no state dir is set (sa-learn's own
/// default then — root's `~/.spamassassin`, which the scanning children never
/// see; `engine configure` sets the directive).
pub fn bayes_dbpath(cfg: &Config) -> Option<PathBuf> {
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).ok()?;
    let dir = mailscanner::get_directive(&conf, "SpamAssassin User State Dir")?;
    let dir = dir.trim();
    (!dir.is_empty()).then(|| PathBuf::from(dir).join("bayes"))
}

/// `--dbpath <db>` for every sa-learn run, when a shared DB is configured.
fn dbpath_args(cfg: &Config) -> Vec<String> {
    bayes_dbpath(cfg)
        .map(|p| vec!["--dbpath".to_string(), p.display().to_string()])
        .unwrap_or_default()
}

/// Files sa-learn creates run as root; hand them to the run-as user so the
/// scanning children can read (and auto-learn into) the DB.
fn own_bayes_db(cfg: &Config) {
    if let Some(db) = bayes_dbpath(cfg) {
        if let Some(dir) = db.parent() {
            engine::chown_state_dir(cfg, dir);
        }
    }
}

/// A parsed spam-report component: rule name, score, optional description.
pub struct Component {
    pub rule: String,
    pub score: f64,
    pub desc: Option<&'static str>,
}

/// Parse a MailScanner spamreport, e.g.
/// `spam, SpamAssassin (not cached, score=10.5, required 5, BAYES_99 5.00, ...)`
/// into rule/score rows. Recognizes `RULE_NAME <score>` tokens.
pub fn parse_report(report: &str) -> Vec<Component> {
    let mut out = Vec::new();
    // rule names are UPPER_SNAKE (optionally digits); score is a signed decimal
    let toks: Vec<&str> = report
        .split([',', ' ', '(', ')'])
        .filter(|t| !t.is_empty())
        .collect();
    let mut i = 0;
    while i + 1 < toks.len() {
        let name = toks[i];
        let is_rule = name.len() >= 3
            && name.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
            && name
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            && name.contains('_');
        if is_rule {
            if let Ok(score) = toks[i + 1].parse::<f64>() {
                out.push(Component {
                    rule: name.to_string(),
                    score,
                    desc: describe(name),
                });
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Descriptions for the most common SpamAssassin rules (best-effort; unknown
/// rules simply have none — the raw report is always shown too).
fn describe(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "ALL_TRUSTED" => "Passed through trusted hosts only via SMTP",
        "BAYES_00" => "Bayes spam probability is 0 to 1%",
        "BAYES_99" => "Bayes spam probability is 99 to 100%",
        "BAYES_999" => "Bayes spam probability is 99.9 to 100%",
        "HTML_MESSAGE" => "HTML included in message",
        "MIME_HTML_ONLY" => "Message only has text/html MIME parts",
        "DKIM_SIGNED" => "Message has a DKIM signature",
        "DKIM_VALID" => "Message has a valid DKIM signature",
        "SPF_PASS" => "SPF: sender matches SPF record",
        "SPF_FAIL" => "SPF: sender does not match SPF record",
        "FREEMAIL_FROM" => "Sender uses a free webmail provider",
        "HK_RANDOM_REPLYTO" => "Reply-To username looks random",
        "KAM_DMARC_STATUS" => "DMARC check status",
        "KAM_DMARC_REJECT" => "Domain DMARC policy is reject",
        "KAM_DMARC_QUARANTINE" => "Domain DMARC policy is quarantine",
        "RCVD_IN_DNSWL_BLOCKED" => "DNSWL lookup was blocked (too many queries)",
        "URIBL_BLOCKED" => "URIBL lookup was blocked (too many queries)",
        _ => return None,
    })
}

/// Received-header hops (IP + optional helo/host), newest first. No external
/// geolocation — the note in the UI explains only the last external IP is
/// trustworthy.
pub struct HeaderIp {
    pub ip: String,
    pub host: String,
}

pub fn header_ips(headers: &str) -> Vec<HeaderIp> {
    let mut out = Vec::new();
    for line in headers.lines() {
        let l = line.trim_start();
        if !l.starts_with("Received:") && !line.starts_with(char::is_whitespace) {
            continue;
        }
        if let Some(ip) = extract_bracketed_ip(line) {
            if out.iter().all(|h: &HeaderIp| h.ip != ip) {
                let host = extract_helo(line).unwrap_or_default();
                out.push(HeaderIp { ip, host });
            }
        }
    }
    out
}

fn extract_bracketed_ip(s: &str) -> Option<String> {
    let start = s.find('[')?;
    let end = s[start..].find(']')? + start;
    let cand = &s[start + 1..end];
    let ok = cand.contains('.')
        && cand.split('.').count() == 4
        && cand.split('.').all(|o| o.parse::<u8>().is_ok());
    let ok6 = cand.contains(':') && cand.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    (ok || ok6).then(|| cand.to_string())
}

fn extract_helo(s: &str) -> Option<String> {
    let h = s.find("helo=")?;
    let rest = &s[h + 5..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ')' || c == ']')
        .unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Bayes training / reporting on a raw message. Actions:
/// `ham` | `spam` | `forget` (sa-learn) and `report` (network report + learn).
pub fn learn(cfg: &Config, message: &[u8], action: &str) -> ControlOutcome {
    let mut transcript = Vec::new();
    let dbpath = dbpath_args(cfg);
    let steps: &[(&str, &[&str])] = match action {
        "ham" => &[("sa-learn", &["--ham", "--no-sync"])],
        "spam" => &[("sa-learn", &["--spam", "--no-sync"])],
        "forget" => &[("sa-learn", &["--forget", "--no-sync"])],
        // learn as spam AND report to the collaborative networks
        "report" => &[
            ("sa-learn", &["--spam", "--no-sync"]),
            ("spamassassin", &["-r"]),
        ],
        _ => {
            return ControlOutcome {
                ok: false,
                transcript: vec![format!("unknown learn action '{action}'")],
            }
        }
    };
    let mut ok = true;
    for (cmd, args) in steps {
        let mut args: Vec<&str> = args.to_vec();
        if *cmd == "sa-learn" {
            args.extend(dbpath.iter().map(String::as_str));
        }
        transcript.push(format!("$ {cmd} {}", args.join(" ")));
        match run_with_stdin(cmd, &args, message) {
            Ok((success, output)) => {
                for l in output.lines() {
                    if !l.trim().is_empty() {
                        transcript.push(l.to_string());
                    }
                }
                transcript.push(if success {
                    "→ ok".into()
                } else {
                    "→ failed".into()
                });
                ok &= success;
            }
            Err(e) => {
                transcript.push(format!("→ cannot run: {e}"));
                ok = false;
            }
        }
    }
    if ok {
        // one sync after training so the bayes db is written
        let _ = Command::new("sa-learn")
            .arg("--sync")
            .args(&dbpath)
            .output();
    }
    own_bayes_db(cfg);
    ControlOutcome { ok, transcript }
}

/// SpamAssassin's Bayes database status (`sa-learn --dump magic`), parsed into
/// the handful of numbers that matter: how much ham/spam it has learned, token
/// count, and when it last expired old tokens.
pub fn bayes_status(cfg: &Config) -> Vec<(String, String)> {
    let out = Command::new("sa-learn")
        .args(["--dump", "magic"])
        .args(dbpath_args(cfg))
        .output();
    let Ok(o) = out else {
        return vec![("error".into(), "sa-learn is not installed".into())];
    };
    let text = String::from_utf8_lossy(&o.stdout);
    let mut rows = Vec::new();
    for line in text.lines() {
        // 0.000          0     3577          0  non-token data: nspam
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || !line.contains("non-token data:") {
            continue;
        }
        let key = f[f.len() - 1];
        let value = f[2];
        let label = match key {
            "nspam" => "Spam messages learned",
            "nham" => "Ham messages learned",
            "ntokens" => "Tokens in the database",
            "oldest_token_age" => "Oldest token",
            "newest_token_age" => "Newest token",
            "last_expire" => "Last expiry run",
            "last_journal_sync" => "Last journal sync",
            "last_atime_delta" => "Last atime delta",
            "bayes_db_version" => "Bayes DB version",
            _ => continue,
        };
        let value = if key.ends_with("_age") || key.starts_with("last_") {
            format_epoch(value)
        } else {
            value.to_string()
        };
        rows.push((label.to_string(), value));
    }
    if rows.is_empty() {
        rows.push((
            "status".into(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        ));
    }
    rows
}

/// Epoch seconds → a readable "N days ago"; passes other values through.
fn format_epoch(v: &str) -> String {
    let Ok(secs) = v.parse::<u64>() else {
        return v.to_string();
    };
    if secs == 0 {
        return "never".into();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if secs > 1_000_000_000 && secs <= now {
        let ago = now - secs;
        format!("{} days ago", ago / 86_400)
    } else {
        format!("{} days", secs / 86_400)
    }
}

/// SpamAssassin's own configuration self-check (`spamassassin --lint`).
pub fn lint() -> (bool, String) {
    lint_prefs(None)
}

/// `spamassassin --lint -p <prefs>`: the check with MailScanner's
/// `spamassassin.conf` (or a staged candidate of it) as the user preferences
/// file, the way the engine hands it to SpamAssassin. Without `prefs` SA reads
/// only its own site config.
pub fn lint_prefs(prefs: Option<&std::path::Path>) -> (bool, String) {
    let mut cmd = Command::new("spamassassin");
    cmd.arg("--lint");
    if let Some(p) = prefs {
        cmd.arg("-p").arg(p);
    }
    match cmd.output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            let s = s.trim().to_string();
            (
                o.status.success(),
                if s.is_empty() {
                    "No problems found — SpamAssassin's configuration is valid.".into()
                } else {
                    s
                },
            )
        }
        Err(e) => (false, format!("cannot run spamassassin: {e}")),
    }
}

/// Run a `sa-learn` maintenance command and capture its combined output as a
/// transcript, mirroring `learn`'s shape so the UI renders both the same way.
fn sa_learn(cfg: &Config, args: &[&str]) -> ControlOutcome {
    let mut args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    args.extend(dbpath_args(cfg));
    let mut transcript = vec![format!("$ sa-learn {}", args.join(" "))];
    let out = Command::new("sa-learn").args(&args).output();
    own_bayes_db(cfg);
    match out {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).into_owned();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            for l in s.lines() {
                if !l.trim().is_empty() {
                    transcript.push(l.to_string());
                }
            }
            transcript.push(if o.status.success() {
                "→ ok".into()
            } else {
                "→ failed".into()
            });
            ControlOutcome {
                ok: o.status.success(),
                transcript,
            }
        }
        Err(e) => {
            transcript.push(format!("→ cannot run: {e}"));
            ControlOutcome {
                ok: false,
                transcript,
            }
        }
    }
}

/// Repair the Bayes database: expire old tokens and sync to disk. Non-destructive
/// — it prunes and rebalances what's learned without discarding training.
pub fn bayes_repair(cfg: &Config) -> ControlOutcome {
    sa_learn(cfg, &["--force-expire", "--sync"])
}

/// Wipe the Bayes database entirely (`sa-learn --clear`). Destructive: all ham/
/// spam training is discarded and Bayes starts over. Callers back up first and
/// confirm.
pub fn bayes_reset(cfg: &Config) -> ControlOutcome {
    sa_learn(cfg, &["--clear"])
}

fn run_with_stdin(cmd: &str, args: &[&str], input: &[u8]) -> std::io::Result<(bool, String)> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(input)?;
    let out = child.wait_with_output()?;
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), s))
}

#[cfg(test)]
mod tests {
    use super::*;

    // a host where WHM's P0f plugin symlinked into the site rules, unloadable
    // under the system perl.
    #[test]
    fn cpanel_plugin_loads_are_found_and_judged() {
        let dir = std::env::temp_dir().join(format!("msfe-saplug-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("P0f.cf"),
            "loadplugin Mail::SpamAssassin::Plugin::P0f /usr/local/cpanel/Cpanel/Mail/SpamAssassin/Plugin/P0f.pm\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("v400.pre"),
            "loadplugin Mail::SpamAssassin::Plugin::ExtractText\n",
        )
        .unwrap();
        std::fs::write(dir.join("KAM.cf"), "score KAM_X 1.0\n").unwrap();
        assert_eq!(
            cpanel_plugin_loads(&dir),
            vec![(
                "P0f".to_string(),
                "/usr/local/cpanel/Cpanel/Mail/SpamAssassin/Plugin/P0f.pm".to_string()
            )]
        );
        let broken = vec![BrokenPlugin {
            name: "P0f".into(),
            module: "/usr/local/cpanel/Cpanel/Mail/SpamAssassin/Plugin/P0f.pm".into(),
            error: "Can't locate IO/SigGuard.pm in @INC (you may need to install the IO::SigGuard module) (@INC contains: /usr/local/cpanel)".into(),
        }];
        let (ok, d) = cpanel_plugins_verdict(&broken, true);
        assert!(!ok);
        assert!(
            d.contains("P0f") && d.contains("which is off") && d.contains("IO/SigGuard.pm"),
            "{d}"
        );
        assert!(!d.contains("@INC contains"), "{d}");
        assert!(cpanel_plugins_verdict(&[], false).0);
        assert_eq!(
            cpanel_plugin_off_command("P0f"),
            "whmapi1 set_tweaksetting module=Mail key=spamassassin_plugin_P0f value=0"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // gauss: SpamAssassin 4.0.2 wanted /var/lib/spamassassin/4.000002, which
    // never existed — only cPanel's 4.000001 did.
    #[test]
    fn upstream_rules_missing_stale_or_fresh() {
        let root = std::env::temp_dir().join(format!("msfe-sarules-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("4.000001/updates_spamassassin_org")).unwrap();
        std::fs::write(root.join("4.000001/updates_spamassassin_org.cf"), "").unwrap();
        let now = now_secs();
        let s = rules_state_at(&root, "4.000002", now);
        assert_eq!(s.age_days, None);
        let (ok, fail, d) = rules_verdict(&s);
        assert!(!ok && fail, "{d}");
        assert!(d.contains("never fetched") && d.contains("4.000002"), "{d}");
        // the version that has rules
        let s = rules_state_at(&root, "4.000001", now);
        assert_eq!(s.age_days, Some(0));
        assert!(rules_verdict(&s).0);
        // stale
        let s = rules_state_at(&root, "4.000001", now + 45 * 86_400);
        let (ok, fail, d) = rules_verdict(&s);
        assert!(!ok && !fail && d.contains("45 days old"), "{d}");
        let _ = std::fs::remove_dir_all(&root);
    }
    use crate::Config;

    #[test]
    fn parses_report_components() {
        let r = "spam, SpamAssassin (not cached, score=10.508, required 5, ALL_TRUSTED -1.00, BAYES_99 5.00, HK_RANDOM_REPLYTO 1.00, KAM_DMARC_REJECT 3.00)";
        let c = parse_report(r);
        let names: Vec<&str> = c.iter().map(|x| x.rule.as_str()).collect();
        assert_eq!(
            names,
            [
                "ALL_TRUSTED",
                "BAYES_99",
                "HK_RANDOM_REPLYTO",
                "KAM_DMARC_REJECT"
            ]
        );
        assert_eq!(c[0].score, -1.00);
        assert_eq!(c[1].desc, Some("Bayes spam probability is 99 to 100%"));
        // "required" is not a rule; "score" token ignored
        assert!(!names.contains(&"SpamAssassin"));
    }

    #[test]
    fn extracts_header_ips() {
        let h = "Received: from [49.12.174.167] (port=58074 helo=bassetto.eu)\n    by gauss with esmtpsa\nReceived: from x [10.0.0.1]\n";
        let ips = header_ips(h);
        assert_eq!(ips[0].ip, "49.12.174.167");
        assert_eq!(ips[0].host, "bassetto.eu");
        assert_eq!(ips[1].ip, "10.0.0.1");
    }

    #[test]
    fn rejects_bad_learn_action() {
        assert!(!learn(&Config::default(), b"x", "delete-everything").ok);
    }

    fn cfg_with_state_dir(dir: &str) -> (Config, std::path::PathBuf) {
        let conf =
            std::env::temp_dir().join(format!("msfe-sa-{}-{}.conf", std::process::id(), dir.len()));
        std::fs::write(
            &conf,
            format!("Run As User = mailnull\nSpamAssassin User State Dir = {dir}\n"),
        )
        .unwrap();
        (
            Config {
                mailscanner_conf: conf.display().to_string(),
                ..Default::default()
            },
            conf,
        )
    }

    // Training as root went into /root/.spamassassin — a DB the scanning
    // children (mailnull) never read. Every sa-learn must target the DB
    // MailScanner is configured to use.
    #[test]
    fn sa_learn_targets_mailscanners_bayes_db() {
        let (cfg, conf) = cfg_with_state_dir("/var/spool/MailScanner/spamassassin");
        assert_eq!(
            bayes_dbpath(&cfg),
            Some("/var/spool/MailScanner/spamassassin/bayes".into())
        );
        let out = learn(&cfg, b"From: a\n\nx\n", "spam");
        assert_eq!(
            out.transcript[0],
            "$ sa-learn --spam --no-sync --dbpath /var/spool/MailScanner/spamassassin/bayes"
        );
        let out = bayes_repair(&cfg);
        assert_eq!(
            out.transcript[0],
            "$ sa-learn --force-expire --sync --dbpath /var/spool/MailScanner/spamassassin/bayes"
        );
        std::fs::remove_file(conf).unwrap();
    }

    #[test]
    fn sa_learn_uses_the_default_db_when_no_state_dir_is_set() {
        let (cfg, conf) = cfg_with_state_dir("");
        assert_eq!(bayes_dbpath(&cfg), None);
        let out = learn(&cfg, b"x", "ham");
        assert_eq!(out.transcript[0], "$ sa-learn --ham --no-sync");
        std::fs::remove_file(conf).unwrap();
    }
}
