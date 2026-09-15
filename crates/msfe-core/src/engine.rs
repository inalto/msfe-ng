//! MailScanner engine configuration for panel platforms.
//!
//! A fresh MailScanner install assumes sendmail (`/var/spool/mqueue*`), which
//! does not exist on cPanel/DirectAdmin Exim servers — its own lint fails on
//! the queue directories. `configure` points MailScanner.conf at Exim and
//! creates the incoming split-spool skeleton. Deliberately safe: it never
//! touches Exim's configuration, the safety latch, or mail routing — that is
//! the separate wiring step.
//!
//! Clean-room: the directive names/values are behavioral facts of MailScanner
//! configuration on Exim panel servers (run-as user `mailnull:mail` on cPanel,
//! `mail:mail` otherwise, split incoming/outgoing spools).

use crate::{mailscanner, service, Config};
use std::io;
use std::path::Path;
use std::process::Command;

/// Force MailScanner to spam-check every domain by setting the global
/// `Spam Checks = yes` directive in MailScanner.conf. This is the authoritative
/// switch: MSFE-NG does not point that directive at a per-domain ruleset, so a
/// literal `yes` guarantees SpamAssassin runs on mail for all domains. Returns
/// `(changed, previous_value)`; the caller restarts MailScanner to apply it
/// (MailScanner reads its config only at startup).
pub fn enable_spam_checks_all(cfg: &Config) -> io::Result<(bool, String)> {
    let conf_path = Path::new(&cfg.mailscanner_conf);
    let original = std::fs::read_to_string(conf_path)?;
    let prev = mailscanner::get_directive(&original, "Spam Checks")
        .unwrap_or("(unset)")
        .to_string();
    let text = mailscanner::set_directive(&original, "Spam Checks", "yes");
    let changed = text != original;
    if changed {
        service::save_conf(conf_path, &text)?;
    }
    Ok((changed, prev))
}

pub struct ConfigureReport {
    /// Directives that were changed, as "Key = value".
    pub set: Vec<String>,
    /// Directories created.
    pub created: Vec<String>,
    /// Paths whose ownership could not be set (non-fatal; reported).
    pub chown_failed: Vec<String>,
    /// MailScanner was restarted to apply changed directives.
    pub restarted: bool,
    /// Phishing-list updater repairs: the script patched in place, junk
    /// downloads removed (never a reason to restart).
    pub repaired: Vec<String>,
    /// Non-fatal problems setting up the shared network-check homes (razor
    /// registration needs razor-admin and the network).
    pub warnings: Vec<String>,
}

/// The user MailScanner's scanning children run as on this panel.
pub(crate) fn run_user_for(cfg: &Config) -> &'static str {
    if cfg.panel == "directadmin" {
        "mail"
    } else {
        "mailnull"
    }
}

/// Point MailScanner.conf at Exim and create the incoming spool skeleton.
/// Idempotent; keeps a one-time backup of MailScanner.conf via `save_conf`.
pub fn configure(cfg: &Config) -> io::Result<ConfigureReport> {
    let run_user = run_user_for(cfg);
    let (inc, out) = service::queue_dir_targets();
    let exim_cmd = exim_command();

    let mut directives: Vec<(String, String)> = [
        ("MTA", "exim"),
        ("Run As User", run_user),
        ("Run As Group", "mail"),
        ("Sendmail", "/usr/sbin/exim"),
        ("Sendmail2", "/usr/sbin/exim"),
        // Without an explicit path, MailScanner 5.5.3's `which exim` fallback
        // leaves a trailing newline, its exim version probe silently fails,
        // and it assumes short message IDs — placing outgoing spool files in
        // the wrong split subdirectory, where Exim never finds them. The same
        // probe misreads "4.100" as 4.1, so it goes through our shim.
        ("Exim Command", exim_cmd.as_str()),
        ("Incoming Work Group", "mail"),
        ("Incoming Work Permissions", "0640"),
        ("Quarantine Group", "mail"),
        ("Quarantine Permissions", "0660"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    // The scanning children run as the run-as user but inherit root's HOME,
    // which they cannot read: with no state dir of their own SpamAssassin has
    // no Bayes DB at all, and what the UI trains (as root) never reaches them.
    let sa_state = sa_state_dir();
    directives.push((
        "SpamAssassin User State Dir".into(),
        sa_state.display().to_string(),
    ));
    // When the Exim wiring is active, the queue dirs belong to it: re-assert
    // the named-queue values instead of resetting them to the unwired defaults
    // (which would leave MailScanner watching an empty directory while the
    // ACL queues mail where nothing scans it).
    let wired = is_wired(cfg);
    if wired {
        let split = exim_split_spool();
        let input = named_queue_base().join("input");
        let incoming = if split {
            format!("{}/*", input.display())
        } else {
            input.display().to_string()
        };
        directives.push(("Incoming Queue Dir".into(), incoming));
        directives.push((
            "Split Exim Spool".into(),
            if split { "yes" } else { "no" }.into(),
        ));
    } else {
        directives.push(("Incoming Queue Dir".into(), inc.display().to_string()));
    }
    directives.push(("Outgoing Queue Dir".into(), out.display().to_string()));
    // Point MailScanner at clamd when its socket is present (the engine
    // installer sets clamd up; without a scanner "auto" finds nothing).
    if let Some(sock) = detect_clamd_socket() {
        directives.push(("Virus Scanners".into(), "clamd".into()));
        directives.push(("Clamd Socket".into(), sock));
    }

    let conf_path = Path::new(&cfg.mailscanner_conf);
    let original = std::fs::read_to_string(conf_path)?;
    let mut text = original.clone();
    let mut set = Vec::new();
    for (k, v) in &directives {
        // Always normalize (set_directive is idempotent): comparing values via
        // get_directive would miss live duplicates that override the edit.
        let new_text = mailscanner::set_directive(&text, k, v);
        if new_text != text {
            text = new_text;
            set.push(format!("{k} = {v}"));
        }
    }
    if text != original {
        service::save_conf(conf_path, &text)?;
    }

    // Incoming split-spool skeleton (ours to create and own; pointless when the
    // named-queue wiring owns the incoming path). The outgoing dir is the
    // MTA's real spool — never created or chowned here.
    let mut created = Vec::new();
    let mut chown_failed = Vec::new();
    if wired {
        // named-queue dirs are managed by wire()
    } else if let Some(base) = inc.parent() {
        for d in [base, &inc, &base.join("msglog"), &base.join("db")] {
            if !d.exists() {
                std::fs::create_dir_all(d)?;
                created.push(d.display().to_string());
            }
            set_perms_0750(d);
            if !chown_user_mail(d, run_user) {
                chown_failed.push(d.display().to_string());
            }
        }
    }
    // MailScanner work dirs, owned by the run-as user: created root-owned (by
    // a pre-repair root run or the rpm), the mailnull children cannot write
    // Processing.db and every message stalls in the scanning queue.
    for (d, owner) in scanner_dir_owners(cfg, run_user) {
        if !d.exists() {
            if std::fs::create_dir_all(&d).is_err() {
                chown_failed.push(format!("{} (create failed)", d.display()));
                continue;
            }
            created.push(d.display().to_string());
        }
        set_perms_0750(&d);
        if !chown_deep(&d, &owner) {
            chown_failed.push(d.display().to_string());
        }
    }

    // Shared razor/pyzor homes for the network checks: readable by everyone
    // (the scanning children, cPanel's per-user spamd), written by root, and
    // the one place a razor reporting identity lives.
    let mut warnings = Vec::new();
    let site = sa_site_rules_dir(&text);
    let sa_conf = conf_path.with_file_name("spamassassin.conf");
    if let Ok(sa_text) = std::fs::read_to_string(&sa_conf) {
        if let Some(fixed) = ensure_sa_network_config(&sa_text, &site) {
            service::save_conf(&sa_conf, &fixed)?;
            set.push(format!(
                "{}: razor_config + pyzor_options (shared network-check homes)",
                sa_conf.display()
            ));
        }
    }
    setup_network_homes(&site, &mut created, &mut warnings);

    // MailScanner reads its config only at startup: leaving it running with
    // stale directives is how misfiled spool files kept happening after the
    // Exim Command fix was written to disk.
    let restarted = if !set.is_empty() && service::status().active {
        service::control("restart").ok
    } else {
        false
    };

    let mut repaired = Vec::new();
    let updater = phishing_updater_path();
    if let Ok(script) = std::fs::read_to_string(&updater) {
        if let Some(fixed) = patch_phishing_updater(&script) {
            service::save_conf(&updater, &fixed)?;
            repaired.push(format!(
                "{} (phishing-list download over HTTP/1.1)",
                updater.display()
            ));
        }
    }
    // A challenge page saved as .gz keeps failing even with the patched
    // script: `curl -z` sends its mtime as If-Modified-Since, gets a 304, and
    // gunzip chokes on the same HTML again the next night.
    if let Some(etc) = conf_path.parent() {
        for junk in phishing_junk_downloads(etc) {
            if std::fs::remove_file(&junk).is_ok() {
                repaired.push(format!(
                    "{} (removed: an HTML page, not gzip data)",
                    junk.display()
                ));
            }
        }
    }

    Ok(ConfigureReport {
        set,
        created,
        chown_failed,
        restarted,
        repaired,
        warnings,
    })
}

/// The shared SpamAssassin per-user state dir (Bayes DB, auto-whitelist) the
/// scanning children use — MailScanner's canonical `%spool-dir%/spamassassin`.
pub fn sa_state_dir() -> std::path::PathBuf {
    ms_work_dir().join("spamassassin")
}

/// MailScanner's `SpamAssassin Site Rules Dir`, where the shared razor/pyzor
/// homes live (world-readable, unlike the run-as user's state dir).
pub fn sa_site_rules_dir(ms_conf: &str) -> std::path::PathBuf {
    mailscanner::get_directive(ms_conf, "SpamAssassin Site Rules Dir")
        .filter(|v| !v.is_empty())
        .unwrap_or("/etc/mail/spamassassin")
        .into()
}

pub fn razor_home(site: &Path) -> std::path::PathBuf {
    site.join(".razor")
}
pub fn pyzor_home(site: &Path) -> std::path::PathBuf {
    site.join(".pyzor")
}
/// The registered identity `razor-admin -register` leaves behind; reporting
/// (`spamassassin -r`) dies with "report requires authentication" without it.
pub fn razor_identity(site: &Path) -> std::path::PathBuf {
    razor_home(site).join("identity")
}

pub(crate) const SA_NETWORK_BEGIN: &str =
    "# --- managed by msfe-ng (engine configure): shared homes for network checks ---";
const SA_NETWORK_END: &str = "# --- end msfe-ng ---";

/// spamassassin.conf with our razor/pyzor block pointing at `site`'s shared
/// homes; `None` when it already does. The block is replaced in place, so a
/// moved site dir never leaves a stale duplicate behind.
pub fn ensure_sa_network_config(text: &str, site: &Path) -> Option<String> {
    let block = format!(
        "{SA_NETWORK_BEGIN}\n\
         ifplugin Mail::SpamAssassin::Plugin::Razor2\n\
         razor_config {razor}/razor-agent.conf\n\
         endif\n\
         ifplugin Mail::SpamAssassin::Plugin::Pyzor\n\
         pyzor_options --homedir {pyzor}\n\
         endif\n\
         {SA_NETWORK_END}\n",
        razor = razor_home(site).display(),
        pyzor = pyzor_home(site).display(),
    );
    let out = match (text.find(SA_NETWORK_BEGIN), text.find(SA_NETWORK_END)) {
        (Some(b), Some(e)) if e > b => {
            let end = e + SA_NETWORK_END.len();
            let end = if text[end..].starts_with('\n') {
                end + 1
            } else {
                end
            };
            format!("{}{}{}", &text[..b], block, &text[end..])
        }
        _ => {
            let sep = if text.is_empty() || text.ends_with('\n') {
                ""
            } else {
                "\n"
            };
            format!("{text}{sep}\n{block}")
        }
    };
    (out != text).then_some(out)
}

/// razor-agent.conf with `razorhome` pinned to `home`; `None` when it already
/// is. `razor-admin -create` writes no razorhome, so without this every razor
/// run falls back to $HOME/.razor.
pub fn razor_conf_with_home(conf: &str, home: &Path) -> Option<String> {
    let want = format!("razorhome = {}", home.display());
    let mut found = false;
    let mut lines: Vec<String> = conf
        .lines()
        .map(|l| {
            let key = l.trim_start().split(['=', ' ', '\t']).next().unwrap_or("");
            if key == "razorhome" {
                found = true;
                want.clone()
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        lines.push(want);
    }
    let out = lines.join("\n") + "\n";
    (out != conf).then_some(out)
}

pub(crate) fn razor_admin_available() -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("razor-admin").is_file()))
}

/// Create the shared razor/pyzor homes under the site rules dir and register
/// a razor identity. Everything world-readable: the scanning children and
/// cPanel's per-user spamd read here; only root (reporting) writes.
fn setup_network_homes(site: &Path, created: &mut Vec<String>, warnings: &mut Vec<String>) {
    use std::os::unix::fs::PermissionsExt;
    let readable = |p: &Path, mode: u32| {
        let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    };
    let pyzor = pyzor_home(site);
    if !pyzor.is_dir() {
        match std::fs::create_dir_all(&pyzor) {
            Ok(()) => created.push(pyzor.display().to_string()),
            Err(e) => warnings.push(format!("cannot create {}: {e}", pyzor.display())),
        }
    }
    readable(&pyzor, 0o755);

    let razor = razor_home(site);
    if !razor_admin_available() {
        warnings.push(
            "razor-admin not installed (perl-Razor-Agent): razor checks and reports unavailable"
                .into(),
        );
        return;
    }
    let home_arg = format!("-home={}", razor.display());
    let razor_admin = |args: &[&str]| -> Result<(), String> {
        let mut cmd = Command::new("razor-admin");
        cmd.arg(&home_arg).args(args);
        match service::run_with_timeout(&mut cmd, std::time::Duration::from_secs(60)) {
            Ok(o) if o.ok => Ok(()),
            Ok(o) => Err(o.stderr.trim().to_string()),
            Err(e) => Err(e.to_string()),
        }
    };
    let conf = razor.join("razor-agent.conf");
    if !conf.exists() {
        if let Err(e) = razor_admin(&["-create"]) {
            warnings.push(format!("razor-admin -create failed: {e}"));
            return;
        }
        created.push(razor.display().to_string());
    }
    if let Ok(text) = std::fs::read_to_string(&conf) {
        if let Some(fixed) = razor_conf_with_home(&text, &razor) {
            let _ = std::fs::write(&conf, fixed);
        }
    }
    if !razor.join("servers.catalogue.lst").exists() {
        if let Err(e) = razor_admin(&["-discover"]) {
            warnings.push(format!("razor-admin -discover failed: {e}"));
        }
    }
    if !razor_identity(site).exists() {
        match razor_admin(&["-register"]) {
            Ok(()) => created.push(format!(
                "{} (razor reporting identity)",
                razor_identity(site).display()
            )),
            Err(e) => warnings.push(format!(
                "razor-admin -register failed (spam reports to Razor need it): {e}"
            )),
        }
    }
    readable(&razor, 0o755);
    if let Ok(entries) = std::fs::read_dir(&razor) {
        for e in entries.flatten() {
            let name = e.file_name();
            // the identity is a per-server secret: root-only, as registered
            if !name.to_string_lossy().starts_with("identity") {
                readable(&e.path(), 0o644);
            }
        }
    }
}

/// `.master.gz` files in MailScanner's etc dir that are not gzip data — what
/// ms-update-phishing leaves behind when the download returns a challenge page.
pub fn phishing_junk_downloads(etc: &Path) -> Vec<std::path::PathBuf> {
    ["phishing.bad.sites", "phishing.safe.sites"]
        .iter()
        .map(|n| etc.join(format!("{n}.conf.master.gz")))
        .filter(|p| std::fs::read(p).is_ok_and(|b| !b.starts_with(&[0x1f, 0x8b])))
        .collect()
}

/// MailScanner's daily phishing-list updater (run from cron.daily via ms-cron).
pub fn phishing_updater_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_PHISHING_UPDATER")
        .unwrap_or_else(|_| "/usr/sbin/ms-update-phishing".into())
        .into()
}

/// Make ms-update-phishing fetch over HTTP/1.1. phishing.mailscanner.info sits
/// behind Cloudflare, which answers the HTTP/2 fingerprint of older curls
/// (7.61 on EL8-era panel builds) with a 403 challenge page; plain `curl -S`
/// saves that HTML as the .gz, gunzip rejects it, and the lists never update.
/// The same request over HTTP/1.1 is served. `-f` turns any future 403 into a
/// curl failure so the script's own wget fallback runs instead of gunzipping
/// HTML. Returns the rewritten script, or `None` when there is nothing to do
/// (already patched, or not the known upstream form — never guess).
pub fn patch_phishing_updater(script: &str) -> Option<String> {
    const UPSTREAM: &str = "curl -S -A \"msv5";
    const PATCHED: &str = "curl -fS --http1.1 -A \"msv5";
    if !script.contains(UPSTREAM) {
        return None;
    }
    Some(script.replace(UPSTREAM, PATCHED))
}

pub struct ArchiveReport {
    pub enabled: bool,
    pub changed: Vec<String>,
    pub restarted: bool,
}

/// Keep MailScanner's `Archive Mail` directive in step with the generated
/// `archive.rules`. Called at the end of every sync; a no-op when nothing
/// changed, so the ten-minute sync cron can never restart MailScanner in a loop.
///
/// When no domain archives, the directive is emptied rather than left pointing
/// at a ruleset with no matching lines — clearer for anyone reading the config.
pub fn apply_archive(cfg: &Config, config_file: &Path) -> io::Result<ArchiveReport> {
    let pdir = crate::sync::policy_dir(config_file);
    let (settings, _, _) = crate::sync::load_policy(&pdir);
    let overrides = crate::sync::load_overrides(&pdir);
    let rs = crate::rules::RuleSettings::from_settings(&settings, &cfg.archive_dir);
    let any_domain_on = overrides.values().any(|p| {
        p.archive
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("yes"))
    });
    let enabled = rs.archive || any_domain_on;

    let rules_path = Path::new(&cfg.mailscanner_rules_dir).join("archive.rules");
    let directives = [
        (
            "Archive Mail",
            if enabled {
                rules_path.display().to_string()
            } else {
                String::new()
            },
        ),
        ("Missing Mail Archive Is", "directory".to_string()),
    ];

    let conf_path = Path::new(&cfg.mailscanner_conf);
    let original = std::fs::read_to_string(conf_path).unwrap_or_default();
    let mut text = original.clone();
    let mut changed = Vec::new();
    for (k, v) in &directives {
        let new_text = mailscanner::set_directive(&text, k, v);
        if new_text != text {
            text = new_text;
            changed.push(format!("{k} = {v}"));
        }
    }
    if !original.is_empty() && text != original {
        service::save_conf(conf_path, &text)?;
    }

    // The archive tree is ours to create and own (same treatment as quarantine).
    if enabled {
        let dir = Path::new(&cfg.archive_dir);
        if !dir.as_os_str().is_empty() && !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
        if dir.exists() {
            set_perms_0750(dir);
            chown_user_mail(dir, run_user_for(cfg));
        }
    }

    // MailScanner reads its config only at startup; the ruleset file itself is
    // re-read per batch, so per-domain changes cost no restart.
    let restarted = if !changed.is_empty() && service::status().active {
        service::control("restart").ok
    } else {
        false
    };
    Ok(ArchiveReport {
        enabled,
        changed,
        restarted,
    })
}

/// The directories MailScanner's children must be able to create entries in,
/// each with the user that must own it. Every one of them — the quarantine
/// included — is written as the run-as user: spam-store and the max-attempts
/// archive both create per-day subdirs from a scanning child, and a root-owned
/// 0750 quarantine makes every such write die, wedging the whole queue on the
/// first high-spam message.
fn scanner_dir_owners(cfg: &Config, run_user: &str) -> Vec<(std::path::PathBuf, String)> {
    let work_base = ms_work_dir();
    vec![
        (work_base.clone(), run_user.to_string()),
        (work_base.join("incoming"), run_user.to_string()),
        (sa_state_dir(), run_user.to_string()),
        (
            Path::new(&cfg.quarantine_dir).to_path_buf(),
            run_user.to_string(),
        ),
        (
            Path::new(&cfg.archive_dir).to_path_buf(),
            run_user.to_string(),
        ),
    ]
}

/// MailScanner's work directory (`Incoming Work Dir` parent).
fn ms_work_dir() -> std::path::PathBuf {
    std::env::var("MSFE_NG_MS_WORK_DIR")
        .unwrap_or_else(|_| "/var/spool/MailScanner".to_string())
        .into()
}

/// The `LocalSocket` path from a clamd.conf body, if uncommented. The socket
/// path clamd's own config declares beats any hardcoded probe list — package
/// updates move the socket (cpanel-clamav 1.5.3 moved it to
/// /run/clamav/clamd.sock and silently dropped the TCP listener).
pub(crate) fn parse_clamd_localsocket(conf: &str) -> Option<String> {
    conf.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let rest = l.strip_prefix("LocalSocket")?;
            // not LocalSocketGroup / LocalSocketMode
            if !rest.starts_with([' ', '\t', '=']) {
                return None;
            }
            let v = rest.trim_start_matches([' ', '\t', '=']).trim();
            (!v.is_empty()).then(|| v.to_string())
        })
}

/// Find a live clamd socket: env override, then the path clamd's own config
/// declares, then known packaging defaults.
pub(crate) fn detect_clamd_socket() -> Option<String> {
    if let Ok(p) = std::env::var("MSFE_NG_CLAMD_SOCKET") {
        return Path::new(&p).exists().then_some(p);
    }
    use std::os::unix::fs::FileTypeExt;
    let is_socket = |p: &str| {
        std::fs::metadata(p)
            .map(|m| m.file_type().is_socket())
            .unwrap_or(false)
    };
    for conf in [
        "/usr/local/cpanel/3rdparty/etc/clamd.conf",
        "/etc/clamd.conf",
        "/etc/clamd.d/scan.conf",
    ] {
        if let Some(p) = std::fs::read_to_string(conf)
            .ok()
            .as_deref()
            .and_then(parse_clamd_localsocket)
        {
            if is_socket(&p) {
                return Some(p);
            }
        }
    }
    [
        "/var/clamd",
        "/run/clamav/clamd.sock",
        "/run/clamd.scan/clamd.sock",
        "/run/clamd.socket",
    ]
    .iter()
    .find(|p| is_socket(p))
    .map(|p| p.to_string())
}

/// Can clamd be reached at the MailScanner `Clamd Socket` target? A leading
/// `/` means a unix socket; anything else is a host reached over TCP `port`.
/// One actual connect — a directive pointing at a dead socket wedges every
/// scan batch in MailScanner's retry loop, silently.
pub(crate) fn clamd_reachable(socket: &str, port: u16) -> bool {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;
    if socket.starts_with('/') {
        return std::os::unix::net::UnixStream::connect(socket).is_ok();
    }
    (socket, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .map(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).is_ok())
        .unwrap_or(false)
}

/// Hand a SpamAssassin state dir (and the Bayes files in it) to the run-as
/// user after root wrote to it; best-effort, no-op for a missing dir.
pub(crate) fn chown_state_dir(cfg: &Config, dir: &Path) {
    if dir.is_dir() {
        chown_deep(dir, run_user_for(cfg));
    }
}

/// chown `path` (and its direct children) to `<user>:mail`; best-effort.
fn chown_deep(path: &Path, user: &str) -> bool {
    let mut ok = chown_user_mail(path, user);
    if let Ok(entries) = std::fs::read_dir(path) {
        for e in entries.flatten() {
            ok &= chown_user_mail(&e.path(), user);
        }
    }
    ok
}

// ---- Exim wiring (named-queue method) ----------------------------------------
//
// Behavioral facts from the legacy integration's "new method": a cPanel-
// supported custom ACL include (`custom_begin_mail_pre`, survives
// buildeximconf) routes every incoming message into the Exim *named queue*
// `mailscanner` with `control = queue_only`; MailScanner scans that queue and
// moves messages into the normal queue, where Exim delivers them. No split
// spool root, no second Exim config. The include is `.include_if_exists`, so
// removing the fragment file instantly restores direct (unscanned) delivery.

const DEFAULT_ACL_HOOK: &str =
    "/usr/local/cpanel/etc/exim/acls/ACL_MAIL_PRE_BLOCK/custom_begin_mail_pre";
const DEFAULT_NAMED_QUEUE_BASE: &str = "/var/spool/exim/mailscanner";

fn acl_hook_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_EXIM_ACL_HOOK")
        .unwrap_or_else(|_| DEFAULT_ACL_HOOK.to_string())
        .into()
}
fn named_queue_base() -> std::path::PathBuf {
    std::env::var("MSFE_NG_NAMED_QUEUE_DIR")
        .unwrap_or_else(|_| DEFAULT_NAMED_QUEUE_BASE.to_string())
        .into()
}
fn exim_conf_path() -> std::path::PathBuf {
    std::env::var("MSFE_NG_EXIM_CONF")
        .unwrap_or_else(|_| "/etc/exim.conf".to_string())
        .into()
}

fn acl_fragment() -> String {
    "# Managed by MSFE-NG (engine wire). Routes incoming mail into the\n\
     # 'mailscanner' named queue for scanning. Deleting/renaming this file\n\
     # instantly restores direct delivery (the include is include_if_exists).\n\
     accept\n\
     \tremove_header = X-MailScanner-SpamBox\n\
     \tqueue         = mailscanner\n\
     \tcontrol       = queue_only\n"
        .to_string()
}

fn include_line(cfg: &Config) -> String {
    format!(".include_if_exists {}", cfg.mailscannerq_conf)
}

/// Where the installer puts the `Exim Command` shim (packaging/exim-shim.sh).
pub const EXIM_SHIM: &str = "/opt/msfe-ng/bin/msfe-ng-exim";

/// The value for MailScanner's `Exim Command`: our shim when installed, else
/// the real binary. MailScanner uses it only to run `-bV` at startup and
/// decide long vs short message ids with `(split / /, $out[0])[2] >= 4.97` —
/// Perl reads "4.100" (Exim 4.100, cPanel 138) as 4.1, so with the real
/// binary every outgoing spool file is misfiled and every quarantined body is
/// copied from the wrong offset. The shim rewrites that banner line only.
pub fn exim_command() -> String {
    let shim = std::env::var("MSFE_NG_EXIM_SHIM").unwrap_or_else(|_| EXIM_SHIM.into());
    if Path::new(&shim).is_file() {
        shim
    } else {
        "/usr/sbin/exim".into()
    }
}

/// `(major, minor)` from an `exim -bV` banner ("Exim version 4.100 #2 …").
pub fn exim_version(bv_output: &str) -> Option<(u32, u32)> {
    let first = bv_output.lines().next()?;
    let mut words = first.split(' ');
    if words.next()? != "Exim" || words.next()? != "version" {
        return None;
    }
    let mut parts = words.next()?.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

/// Exim writes long message ids from 4.97.
pub fn exim_long_ids(version: (u32, u32)) -> bool {
    version >= (4, 97)
}

/// What MailScanner 5.5.3 concludes from this `Exim Command -bV` output —
/// its exact Perl: `$ver = (split / /, $out[0])[2]; $ver >= 4.97`, where a
/// string numifies to its leading decimal prefix ("4.100" → 4.1, junk → 0).
pub fn mailscanner_probe_long_ids(bv_output: &str) -> bool {
    let token = bv_output
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(2))
        .unwrap_or("");
    perl_numify(token) >= 4.97
}

fn perl_numify(s: &str) -> f64 {
    let s = s.trim_start();
    let mut end = 0;
    let mut seen_dot = false;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() || (c == '.' && !seen_dot) {
            seen_dot |= c == '.';
            end = i + 1;
        } else {
            break;
        }
    }
    s[..end].parse().unwrap_or(0.0)
}

/// Does cPanel's generated exim.conf use a split spool? Decides whether the
/// named queue needs single-character subdirs and the `/*` glob.
pub fn exim_split_spool() -> bool {
    let text = std::fs::read_to_string(exim_conf_path()).unwrap_or_default();
    text.lines().any(|l| {
        let t = l.trim();
        t.strip_prefix("split_spool_directory")
            .map(|rest| {
                let v = rest.trim_start_matches([' ', '=']).trim();
                v.is_empty() || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("yes")
            })
            .unwrap_or(false)
    })
}

/// True when mail is currently routed through MailScanner: the ACL hook
/// includes our fragment and the fragment file is live.
pub fn is_wired(cfg: &Config) -> bool {
    Path::new(&cfg.mailscannerq_conf).exists()
        && std::fs::read_to_string(acl_hook_path())
            .map(|t| t.contains(&include_line(cfg)))
            .unwrap_or(false)
}

pub struct WireReport {
    pub actions: Vec<String>,
    pub dry_run: bool,
}

fn exim_rebuild(actions: &mut Vec<String>, dry: bool) {
    for cmd in ["/scripts/buildeximconf", "/scripts/restartsrv_exim"] {
        if dry || std::env::var("MSFE_NG_SKIP_EXIM_CMDS").is_ok() {
            actions.push(format!("would run: {cmd}"));
            continue;
        }
        let ok = std::process::Command::new(cmd)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        actions.push(format!("ran {cmd}: {}", if ok { "ok" } else { "FAILED" }));
    }
}

/// Route mail through MailScanner (cPanel named-queue method). Idempotent.
/// `dry` reports every step without changing anything.
pub fn wire(cfg: &Config, dry: bool) -> io::Result<WireReport> {
    if cfg.panel != "cpanel" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exim wiring is currently implemented for cPanel only",
        ));
    }
    if !service::engine_configured() && std::env::var("MSFE_NG_EXIM_ACL_HOOK").is_err() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "MailScanner engine is not installed/configured — run engine install + configure first",
        ));
    }
    let mut actions = Vec::new();
    let split = exim_split_spool();
    let base = named_queue_base();
    let input = base.join("input");
    let run_user = "mailnull";

    // 1. named-queue spool skeleton
    let mut dirs: Vec<std::path::PathBuf> = vec![base.clone(), input.clone(), base.join("msglog")];
    if split {
        for c in ('a'..='z').chain('A'..='Z').chain('0'..='9') {
            dirs.push(input.join(c.to_string()));
        }
    }
    for d in &dirs {
        if !d.exists() {
            if dry {
                actions.push(format!("would create {}", d.display()));
            } else {
                std::fs::create_dir_all(d)?;
                actions.push(format!("created {}", d.display()));
            }
        }
        if !dry {
            set_perms_0750(d);
            chown_user_mail(d, run_user);
        }
    }

    // 2. MailScanner.conf: scan the named queue, emit into the normal queue
    let (_, outgoing) = service::queue_dir_targets();
    let incoming = if split {
        format!("{}/*", input.display())
    } else {
        input.display().to_string()
    };
    let exim_cmd = exim_command();
    let directives = [
        ("Incoming Queue Dir", incoming.as_str()),
        ("Outgoing Queue Dir", &outgoing.display().to_string()),
        ("Split Exim Spool", if split { "yes" } else { "no" }),
        ("Sendmail", "/usr/sbin/exim"),
        ("Sendmail2", "/usr/sbin/exim"),
        // See configure(): required for MailScanner's long-message-ID
        // detection on Exim >= 4.97 (wrong split subdir otherwise).
        ("Exim Command", exim_cmd.as_str()),
    ];
    let conf_path = Path::new(&cfg.mailscanner_conf);
    if let Ok(original) = std::fs::read_to_string(conf_path) {
        let mut text = original.clone();
        for (k, v) in directives {
            // always normalize — repairs live duplicates too (last one wins)
            let new_text = mailscanner::set_directive(&text, k, v);
            if new_text != text {
                text = new_text;
                actions.push(format!(
                    "{} MailScanner.conf: {k} = {v}",
                    if dry { "would set" } else { "set" }
                ));
            }
        }
        if !dry && text != original {
            service::save_conf(conf_path, &text)?;
        }
    }

    // 3. the ACL fragment + cPanel hook include
    let frag = Path::new(&cfg.mailscannerq_conf);
    if dry {
        actions.push(format!("would write {}", frag.display()));
    } else {
        if let Some(dir) = frag.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::sync::atomic_write(frag, acl_fragment().as_bytes())?;
        actions.push(format!("wrote {}", frag.display()));
    }
    let hook = acl_hook_path();
    let hook_text = std::fs::read_to_string(&hook).unwrap_or_default();
    if !hook_text.contains(&include_line(cfg)) {
        if dry {
            actions.push(format!("would add include to {}", hook.display()));
        } else {
            if let Some(dir) = hook.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut t = hook_text;
            if !t.is_empty() && !t.ends_with('\n') {
                t.push('\n');
            }
            t.push_str(&include_line(cfg));
            t.push('\n');
            crate::sync::atomic_write(&hook, t.as_bytes())?;
            actions.push(format!("added include to {}", hook.display()));
        }
    }

    // 4. rebuild + restart Exim so the ACL takes effect
    exim_rebuild(&mut actions, dry);

    // 5. restart MailScanner so it re-reads its queue dirs (only if allowed)
    if !dry && service::engine_run_enabled() == Some(true) {
        let o = service::control("restart");
        actions.push(format!(
            "restarted MailScanner: {}",
            if o.ok { "ok" } else { "FAILED" }
        ));
    }
    Ok(WireReport {
        actions,
        dry_run: dry,
    })
}

/// Restore direct delivery: drop the include from the cPanel hook, remove the
/// fragment, rebuild Exim. MailScanner may keep running — with nothing routed
/// into its queue it simply idles.
pub fn unwire(cfg: &Config, dry: bool) -> io::Result<WireReport> {
    let mut actions = Vec::new();
    let hook = acl_hook_path();
    if let Ok(text) = std::fs::read_to_string(&hook) {
        if text.contains(&include_line(cfg)) {
            if dry {
                actions.push(format!("would remove include from {}", hook.display()));
            } else {
                let new: String = text
                    .lines()
                    .filter(|l| l.trim() != include_line(cfg))
                    .map(|l| l.to_string() + "\n")
                    .collect();
                crate::sync::atomic_write(&hook, new.as_bytes())?;
                actions.push(format!("removed include from {}", hook.display()));
            }
        }
    }
    let frag = Path::new(&cfg.mailscannerq_conf);
    if frag.exists() {
        if dry {
            actions.push(format!("would remove {}", frag.display()));
        } else {
            std::fs::remove_file(frag)?;
            actions.push(format!("removed {}", frag.display()));
        }
    }
    exim_rebuild(&mut actions, dry);
    Ok(WireReport {
        actions,
        dry_run: dry,
    })
}

fn set_perms_0750(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o750));
}

/// chown `path` to `<user>:mail`, resolving ids from /etc/passwd//etc/group.
/// Best-effort: returns false when the user/group is missing or chown fails
/// (e.g. tests running unprivileged).
fn chown_user_mail(path: &Path, user: &str) -> bool {
    let (Some(uid), Some(gid)) = (uid_of(user), gid_of("mail")) else {
        return false;
    };
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).is_ok()
}

pub(crate) fn uid_of(name: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != name {
            return None;
        }
        f.next(); // password field
        f.next()?.parse().ok()
    })
}

pub(crate) fn gid_of(name: &str) -> Option<u32> {
    let group = std::fs::read_to_string("/etc/group").ok()?;
    group.lines().find_map(|l| {
        let mut f = l.split(':');
        if f.next()? != name {
            return None;
        }
        f.next(); // password field
        f.next()?.parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    // Both tests mutate shared process env vars — serialize them.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // MailScanner 5.5.3 (usr/sbin/MailScanner) probes `Exim Command -bV` and
    // tests `(split / /, $out[0])[2] >= 4.97` — Perl numifies "4.100" to 4.1.
    #[test]
    fn exim_version_reads_the_bv_banner() {
        assert_eq!(
            exim_version("Exim version 4.100 #2 built 20-Aug-2026\nSupport for: TLS\n"),
            Some((4, 100))
        );
        assert_eq!(exim_version("Exim version 4.98.2 #2 built"), Some((4, 98)));
        assert_eq!(exim_version("Exim version 5.0 #1"), Some((5, 0)));
        assert_eq!(exim_version(""), None);
        assert_eq!(exim_version("exim: permission denied\n"), None);
    }

    #[test]
    fn mailscanner_probe_mirrors_perls_numeric_read() {
        // the trap: a real 4.100 reads as 4.1 < 4.97 → short ids
        assert!(!mailscanner_probe_long_ids(
            "Exim version 4.100 #2 built 20-Aug-2026"
        ));
        assert!(mailscanner_probe_long_ids("Exim version 4.99.2 #2 built"));
        assert!(mailscanner_probe_long_ids("Exim version 4.97 #2 built"));
        assert!(!mailscanner_probe_long_ids("Exim version 4.96 #2 built"));
        // what the shim emits
        assert!(mailscanner_probe_long_ids(
            "Exim version 4.99 #2 built 20-Aug-2026 (msfe-ng shim: real 4.100)"
        ));
        // empty/garbage output: `$ver` undef → 0 >= 4.97 is false
        assert!(!mailscanner_probe_long_ids(""));
        assert!(!mailscanner_probe_long_ids("Something unexpected"));
    }

    #[test]
    fn exim_command_prefers_the_installed_shim() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-eximcmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let shim = base.join("msfe-ng-exim");
        std::env::set_var("MSFE_NG_EXIM_SHIM", &shim);
        // not installed yet → the real binary
        assert_eq!(exim_command(), "/usr/sbin/exim");
        std::fs::write(&shim, "#!/bin/sh\n").unwrap();
        assert_eq!(exim_command(), shim.display().to_string());
        std::env::remove_var("MSFE_NG_EXIM_SHIM");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn parses_localsocket_from_clamd_conf() {
        let conf = "# comment\n#LocalSocket /old/path\nLocalSocketGroup virusgroup\nLocalSocketMode 666\nTCPAddr 127.0.0.1\nLocalSocket /run/clamav/clamd.sock\n";
        assert_eq!(
            parse_clamd_localsocket(conf).as_deref(),
            Some("/run/clamav/clamd.sock")
        );
        assert_eq!(parse_clamd_localsocket("#LocalSocket /x\n"), None);
        assert_eq!(parse_clamd_localsocket("TCPSocket 3310\n"), None);
    }

    // Regression for a 2-day scanning outage: cpanel-clamav moved the clamd
    // socket, MailScanner.conf kept pointing at the old target, and every scan
    // batch wedged in the silent retry loop. Reachability must be a real
    // connect, not a directive check.
    #[test]
    fn clamd_reachability_is_a_real_connect() {
        let base = std::env::temp_dir().join(format!("msfe-clamd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let sock = base.join("clamd.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        assert!(clamd_reachable(&sock.display().to_string(), 3310));
        assert!(
            !clamd_reachable(&base.join("gone.sock").display().to_string(), 3310),
            "missing unix socket must be unreachable"
        );
        // TCP mode: a live local listener is reachable, a dead port is not
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        assert!(clamd_reachable("127.0.0.1", port));
        drop(tcp);
        assert!(
            !clamd_reachable("127.0.0.1", port),
            "closed TCP port must be unreachable"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    // Regression for a 15-hour production outage: the quarantine was chowned
    // root 0750 while the scanning children run as mailnull, so spam-store and
    // the max-attempts archive died on every write — killing each child at
    // batch build and wedging the whole scanning queue.
    #[test]
    fn quarantine_is_owned_by_the_run_as_user() {
        let cfg = Config {
            quarantine_dir: "/var/spool/MailScanner/quarantine".into(),
            archive_dir: "/var/spool/MailScanner/archive".into(),
            ..Default::default()
        };
        for (dir, owner) in scanner_dir_owners(&cfg, "mailnull") {
            assert_eq!(
                owner,
                "mailnull",
                "{} must be writable by the scanning children",
                dir.display()
            );
        }
    }

    #[test]
    fn wire_and_unwire_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-wire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let msconf = base.join("MailScanner.conf");
        std::fs::write(&msconf, "MTA = exim\n# a comment\n").unwrap();
        std::fs::write(base.join("exim.conf"), "split_spool_directory = true\n").unwrap();
        std::env::set_var("MSFE_NG_EXIM_ACL_HOOK", base.join("hook"));
        std::env::set_var("MSFE_NG_NAMED_QUEUE_DIR", base.join("msqueue"));
        std::env::set_var("MSFE_NG_EXIM_CONF", base.join("exim.conf"));
        std::env::set_var("MSFE_NG_SKIP_EXIM_CMDS", "1");
        std::env::set_var("MSFE_NG_INCOMING_QUEUE", base.join("in"));
        std::env::set_var("MSFE_NG_OUTGOING_QUEUE", base.join("exim/input"));

        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: msconf.display().to_string(),
            mailscannerq_conf: base.join("mailscannerq.conf").display().to_string(),
            ..Default::default()
        };

        // dry run changes nothing
        let dry = wire(&cfg, true).unwrap();
        assert!(dry.dry_run && !dry.actions.is_empty());
        assert!(!Path::new(&cfg.mailscannerq_conf).exists());
        assert!(!is_wired(&cfg));

        // real wire
        wire(&cfg, false).unwrap();
        assert!(is_wired(&cfg));
        let hook = std::fs::read_to_string(base.join("hook")).unwrap();
        assert_eq!(hook.matches(".include_if_exists").count(), 1);
        let frag = std::fs::read_to_string(&cfg.mailscannerq_conf).unwrap();
        assert!(frag.contains("queue         = mailscanner"));
        assert!(frag.contains("control       = queue_only"));
        let text = std::fs::read_to_string(&msconf).unwrap();
        assert!(mailscanner::get_directive(&text, "Incoming Queue Dir")
            .unwrap()
            .ends_with("msqueue/input/*"));
        assert_eq!(
            mailscanner::get_directive(&text, "Split Exim Spool"),
            Some("yes")
        );
        assert!(text.contains("# a comment"));
        assert!(base.join("msqueue/input/a").is_dir()); // split subdirs

        // idempotent: no duplicate include
        wire(&cfg, false).unwrap();
        let hook = std::fs::read_to_string(base.join("hook")).unwrap();
        assert_eq!(hook.matches(".include_if_exists").count(), 1);

        // regression: configure while wired must NOT revert the queue dirs —
        // it re-asserts the named-queue values instead.
        std::env::set_var("MSFE_NG_MS_WORK_DIR", base.join("work"));
        let cfg_q = Config {
            quarantine_dir: base.join("quarantine").display().to_string(),
            ..cfg.clone()
        };
        configure(&cfg_q).unwrap();
        let text = std::fs::read_to_string(&msconf).unwrap();
        assert!(mailscanner::get_directive(&text, "Incoming Queue Dir")
            .unwrap()
            .ends_with("msqueue/input/*"));
        std::env::remove_var("MSFE_NG_MS_WORK_DIR");

        // unwire restores direct delivery
        unwire(&cfg, false).unwrap();
        assert!(!is_wired(&cfg));
        assert!(!Path::new(&cfg.mailscannerq_conf).exists());
        assert!(!std::fs::read_to_string(base.join("hook"))
            .unwrap()
            .contains(".include_if_exists"));

        for v in [
            "MSFE_NG_EXIM_ACL_HOOK",
            "MSFE_NG_NAMED_QUEUE_DIR",
            "MSFE_NG_EXIM_CONF",
            "MSFE_NG_SKIP_EXIM_CMDS",
            "MSFE_NG_INCOMING_QUEUE",
            "MSFE_NG_OUTGOING_QUEUE",
        ] {
            std::env::remove_var(v);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    // MailScanner 5.5.3's ms-update-phishing fetches phishing.mailscanner.info
    // with plain curl; Cloudflare challenges the HTTP/2 fingerprint of older
    // curls (403 + HTML saved as .gz) but serves the same request over HTTP/1.1.
    const UPDATER: &str = "#!/usr/bin/env bash\nCONFIGDIR='/etc/MailScanner';\n\
if [ $CURLORWGET = 'curl' ]; then\n  curl -S -A \"msv5 Update Script v0.3.1\" -z $CONFIGDIR/phishing.bad.sites.conf.master.gz -o $CONFIGDIR/phishing.bad.sites.conf.master.gz $BADURL &> /dev/null\n\
  curl -S -A \"msv5 Update Script v0.3.1\" -z $CONFIGDIR/phishing.safe.sites.conf.master.gz -o $CONFIGDIR/phishing.safe.sites.conf.master.gz $SAFEURL &> /dev/null\n\
  wget -q --user-agent=\"msv5 Update Script v0.3.1\" -N -O x $BADURL\n";

    #[test]
    fn phishing_updater_patch_forces_http11_on_both_curl_lines() {
        let patched = patch_phishing_updater(UPDATER).expect("upstream form is patched");
        assert_eq!(patched.matches("curl -fS --http1.1 -A \"msv5").count(), 2);
        assert!(!patched.contains("curl -S -A"));
        // wget line and everything else untouched
        assert!(
            patched.contains("wget -q --user-agent=\"msv5 Update Script v0.3.1\" -N -O x $BADURL")
        );
        assert!(patched.starts_with("#!/usr/bin/env bash\n"));
    }

    #[test]
    fn phishing_updater_patch_is_idempotent_and_leaves_unknown_scripts_alone() {
        let once = patch_phishing_updater(UPDATER).unwrap();
        assert_eq!(patch_phishing_updater(&once), None);
        assert_eq!(patch_phishing_updater("#!/bin/sh\nwget $BADURL\n"), None);
        assert_eq!(patch_phishing_updater(""), None);
    }

    #[test]
    fn configures_conf_and_creates_spool() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-engine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let conf = base.join("MailScanner.conf");
        std::fs::write(
            &conf,
            "MTA = sendmail\nIncoming Queue Dir = /var/spool/mqueue.in\nOutgoing Queue Dir = /var/spool/mqueue\nRun As User = \n",
        )
        .unwrap();
        let inc = base.join("exim_incoming/input");
        let out = base.join("exim/input");
        std::env::set_var("MSFE_NG_INCOMING_QUEUE", &inc);
        std::env::set_var("MSFE_NG_OUTGOING_QUEUE", &out);
        std::env::set_var("MSFE_NG_MS_WORK_DIR", base.join("work"));
        let shim = base.join("msfe-ng-exim");
        std::fs::write(&shim, "#!/bin/sh\n").unwrap();
        std::env::set_var("MSFE_NG_EXIM_SHIM", &shim);
        let updater = base.join("ms-update-phishing");
        std::fs::write(&updater, UPDATER).unwrap();
        std::fs::set_permissions(&updater, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("MSFE_NG_PHISHING_UPDATER", &updater);

        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: conf.display().to_string(),
            quarantine_dir: base.join("quarantine").display().to_string(),
            ..Default::default()
        };
        // a failed download left the Cloudflare page saved as .gz: its mtime
        // poisons `curl -z` (304 → gunzip fails again) even once the script
        // fetches over HTTP/1.1. A real gzip leftover is the updater's own.
        let junk = base.join("phishing.bad.sites.conf.master.gz");
        std::fs::write(&junk, "<!DOCTYPE html>Just a moment...").unwrap();
        let real_gz = base.join("phishing.safe.sites.conf.master.gz");
        std::fs::write(&real_gz, [0x1f, 0x8b, 0x08, 0x00]).unwrap();

        let r = configure(&cfg).unwrap();
        // the phishing-list updater fetches over HTTP/1.1 (Cloudflare fix),
        // stays executable, keeps a backup, and is not a reason to restart
        let script = std::fs::read_to_string(&updater).unwrap();
        assert_eq!(script.matches("curl -fS --http1.1").count(), 2);
        assert_eq!(
            std::fs::metadata(&updater).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(base.join("ms-update-phishing.msfe-ng.bak").exists());
        assert!(!junk.exists(), "HTML saved as .gz must be removed");
        assert!(real_gz.exists(), "a genuine gzip download is left alone");
        assert_eq!(r.repaired.len(), 2, "{:?}", r.repaired);
        assert!(r.repaired[0].starts_with(&updater.display().to_string()));
        assert!(r.repaired[1].starts_with(&junk.display().to_string()));
        let text = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(mailscanner::get_directive(&text, "MTA"), Some("exim"));
        // the version probe goes through our shim (Exim 4.100 banner fix)
        assert_eq!(
            mailscanner::get_directive(&text, "Exim Command"),
            Some(shim.display().to_string().as_str())
        );
        assert_eq!(
            mailscanner::get_directive(&text, "Run As User"),
            Some("mailnull")
        );
        assert_eq!(
            mailscanner::get_directive(&text, "Incoming Queue Dir"),
            Some(inc.display().to_string().as_str())
        );
        assert!(inc.is_dir());
        assert!(inc.parent().unwrap().join("msglog").is_dir());
        assert!(!out.exists(), "outgoing spool must never be created");
        assert!(r.set.iter().any(|s| s.starts_with("MTA = exim")));
        // backup of the original was kept
        assert!(conf.with_extension("conf.msfe-ng.bak").exists());

        // second run is a no-op on the conf
        let r2 = configure(&cfg).unwrap();
        assert!(r2.set.is_empty());
        assert!(r2.created.is_empty());
        assert!(r2.repaired.is_empty());

        std::env::remove_var("MSFE_NG_INCOMING_QUEUE");
        std::env::remove_var("MSFE_NG_OUTGOING_QUEUE");
        std::env::remove_var("MSFE_NG_MS_WORK_DIR");
        std::env::remove_var("MSFE_NG_EXIM_SHIM");
        std::env::remove_var("MSFE_NG_PHISHING_UPDATER");
        std::fs::remove_dir_all(&base).unwrap();
    }

    // MailScanner's children run as the scan user with root's HOME, so without
    // a state dir of their own SpamAssassin has no Bayes DB (no BAYES_* hits at
    // all in production) and pyzor dies on "Permission denied: /root/.pyzor".
    #[test]
    fn sa_state_dir_is_shared_and_owned_by_the_run_as_user() {
        let cfg = Config::default();
        let owners = scanner_dir_owners(&cfg, "mailnull");
        let state = sa_state_dir();
        assert!(state.ends_with("spamassassin"));
        assert!(
            owners.iter().any(|(d, o)| *d == state && o == "mailnull"),
            "{:?}",
            owners
        );
    }

    #[test]
    fn sa_network_block_points_razor_and_pyzor_at_shared_homes() {
        let site = Path::new("/etc/mail/spamassassin");
        let text = "bayes_ignore_header X-Foo\n";
        let out = ensure_sa_network_config(text, site).expect("block added");
        assert!(out.starts_with(text));
        assert!(out.contains("\nrazor_config /etc/mail/spamassassin/.razor/razor-agent.conf\n"));
        assert!(
            out.ends_with(&format!("\nendif\n{SA_NETWORK_END}\n")),
            "{out:?}"
        );
        assert!(out.contains("pyzor_options --homedir /etc/mail/spamassassin/.pyzor\n"));
        // guarded so a config without the plugins still lints clean
        assert!(out.contains("ifplugin Mail::SpamAssassin::Plugin::Razor2\n"));
        assert!(out.contains("ifplugin Mail::SpamAssassin::Plugin::Pyzor\n"));
        // idempotent
        assert_eq!(ensure_sa_network_config(&out, site), None);
        // a moved site dir rewrites the block in place, without duplicating it
        let moved = ensure_sa_network_config(&out, Path::new("/opt/sa")).unwrap();
        assert!(moved.contains("razor_config /opt/sa/.razor/razor-agent.conf\n"));
        assert!(!moved.contains("/etc/mail/spamassassin/.razor"));
        assert_eq!(moved.matches(SA_NETWORK_BEGIN).count(), 1);
    }

    // razor-admin -create writes no razorhome, so every razor run would fall
    // back to $HOME/.razor — the unreadable /root for the scanning children.
    #[test]
    fn razor_conf_gets_an_explicit_home() {
        let home = Path::new("/etc/mail/spamassassin/.razor");
        let conf = "debuglevel = 3\nlogfile = razor-agent.log\n";
        let out = razor_conf_with_home(conf, home).unwrap();
        assert!(out.ends_with("razorhome = /etc/mail/spamassassin/.razor\n"));
        assert_eq!(razor_conf_with_home(&out, home), None);
        let stale = "razorhome = /root/.razor\ndebuglevel = 3\n";
        let fixed = razor_conf_with_home(stale, home).unwrap();
        assert_eq!(
            fixed,
            "razorhome = /etc/mail/spamassassin/.razor\ndebuglevel = 3\n"
        );
    }

    #[test]
    fn configure_sets_up_bayes_state_dir_and_network_check_homes() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let base = std::env::temp_dir().join(format!("msfe-engine-sa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let site = base.join("sa-site");
        std::fs::create_dir_all(&site).unwrap();
        let conf = base.join("MailScanner.conf");
        std::fs::write(
            &conf,
            format!(
                "MTA = exim\nSpamAssassin User State Dir =\nSpamAssassin Site Rules Dir = {}\n",
                site.display()
            ),
        )
        .unwrap();
        let sa_conf = base.join("spamassassin.conf");
        std::fs::write(&sa_conf, "lock_method flock\n").unwrap();
        std::env::set_var("MSFE_NG_INCOMING_QUEUE", base.join("in/input"));
        std::env::set_var("MSFE_NG_OUTGOING_QUEUE", base.join("exim/input"));
        std::env::set_var("MSFE_NG_MS_WORK_DIR", base.join("work"));
        std::env::set_var("MSFE_NG_SKIP_EXIM_CMDS", "1");
        let cfg = Config {
            panel: "cpanel".into(),
            mailscanner_conf: conf.display().to_string(),
            quarantine_dir: base.join("quarantine").display().to_string(),
            archive_dir: base.join("archive").display().to_string(),
            ..Default::default()
        };

        let r = configure(&cfg).unwrap();
        let text = std::fs::read_to_string(&conf).unwrap();
        let state = base.join("work/spamassassin");
        assert_eq!(
            mailscanner::get_directive(&text, "SpamAssassin User State Dir"),
            Some(state.display().to_string().as_str())
        );
        assert!(state.is_dir(), "shared Bayes state dir created");
        assert!(site.join(".pyzor").is_dir(), "shared pyzor home created");
        let sa_text = std::fs::read_to_string(&sa_conf).unwrap();
        assert!(sa_text.starts_with("lock_method flock\n"));
        assert!(sa_text.contains(&format!(
            "pyzor_options --homedir {}/.pyzor\n",
            site.display()
        )));
        assert!(base.join("spamassassin.conf.msfe-ng.bak").exists());
        // the SA config is read at MailScanner startup: a restart-worthy change
        assert!(
            r.set.iter().any(|s| s.contains("spamassassin.conf")),
            "{:?}",
            r.set
        );
        // razor registration needs razor-admin (not on the build box) — that
        // is reported, never fatal
        if !razor_admin_available() {
            assert!(
                r.warnings.iter().any(|w| w.contains("razor-admin")),
                "{:?}",
                r.warnings
            );
        }

        let r2 = configure(&cfg).unwrap();
        assert!(r2.set.is_empty(), "{:?}", r2.set);
        assert!(r2.created.is_empty(), "{:?}", r2.created);

        std::env::remove_var("MSFE_NG_INCOMING_QUEUE");
        std::env::remove_var("MSFE_NG_OUTGOING_QUEUE");
        std::env::remove_var("MSFE_NG_MS_WORK_DIR");
        std::env::remove_var("MSFE_NG_SKIP_EXIM_CMDS");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
