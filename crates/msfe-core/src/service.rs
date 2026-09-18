//! MailScanner service operations: process status and control, mail-queue
//! inspection and repair, maillog tailing, ruleset/config file access, and an
//! on-demand release check.
//!
//! Everything here is root-only surface, exposed through the admin API and the
//! `msfe-ng service` CLI command. External commands follow the same
//! systemd-first / SysV-fallback pattern as `sync::reload_mailscanner`.

use crate::Config;
use crate::{layout, mailscanner};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// systemd unit / SysV service names for MailScanner.
const SYSTEMD_UNIT: &str = "mailscanner";
const SYSV_NAME: &str = "MailScanner";

/// Fallback queue locations for a cPanel split-spool MailScanner setup, used
/// when MailScanner.conf does not declare `Incoming/Outgoing Queue Dir`.
const DEFAULT_INCOMING_QUEUE: &str = "/var/spool/exim_incoming/input";
const DEFAULT_OUTGOING_QUEUE: &str = "/var/spool/exim/input";

/// A queue file pair missing its other half must be at least this old before
/// it is considered orphaned (Exim/MailScanner write -H and -D moments apart).
const ORPHAN_MIN_AGE_SECS: u64 = 600;

// ---- command execution with a deadline ----------------------------------------

/// Result of a spawned command that is never allowed to block forever.
pub struct CmdOutput {
    pub ok: bool,
    /// Exit code, when the command ran to completion and provided one.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Run `cmd`, killing it after `timeout`. The daemon serves requests one at a
/// time, so any command that can block indefinitely — `exim -Mvh/-Mvb` waiting
/// on a spool lock held by a wedged scanner child, `MailScanner --lint`
/// entering a scanner retry loop — takes the whole UI down with it. Every
/// spawn on the request path goes through here.
pub fn run_with_timeout(cmd: &mut Command, timeout: std::time::Duration) -> io::Result<CmdOutput> {
    use std::os::unix::process::CommandExt;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    // Own process group, so the deadline can kill the command's whole tree:
    // killing only the direct child leaves grandchildren (a shell's fork, a
    // scanner's workers) alive AND holding the output pipes open.
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()?;

    // Drain each pipe on a thread into a shared buffer. The threads are never
    // joined: a detached descendant (e.g. a daemonized grandchild) can hold
    // the pipe open forever, and a join would block the deadline with it.
    fn drain<R: std::io::Read + Send + 'static>(
        mut pipe: R,
        buf: Arc<Mutex<Vec<u8>>>,
        done: mpsc::Sender<()>,
    ) {
        std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
            let _ = done.send(());
        });
    }
    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    let (done_tx, done_rx) = mpsc::channel();
    if let Some(p) = child.stdout.take() {
        drain(p, Arc::clone(&out_buf), done_tx.clone());
    }
    if let Some(p) = child.stderr.take() {
        drain(p, Arc::clone(&err_buf), done_tx.clone());
    }
    drop(done_tx);

    let start = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait()? {
            Some(st) => break Some(st),
            None if start.elapsed() >= timeout => {
                timed_out = true;
                // negative pid = the whole process group
                let _ = Command::new("kill")
                    .args(["-9", "--", &format!("-{}", child.id())])
                    .stderr(Stdio::null())
                    .status();
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    // Bounded grace for the readers to hit EOF (immediate in the normal case);
    // a pipe held open by an escaped descendant just yields what we have.
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let stdout = out_buf.lock().unwrap().clone();
    let stderr = err_buf.lock().unwrap().clone();
    Ok(CmdOutput {
        ok: status.map(|s| s.success()).unwrap_or(false),
        code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        timed_out,
    })
}

// ---- process status & control ------------------------------------------------

pub struct ServiceStatus {
    /// Service reported active by systemd (or SysV status as fallback).
    pub active: bool,
    /// Number of running MailScanner processes.
    pub procs: usize,
}

/// True when the MailScanner engine itself is installed: the binary of the
/// resolved layout (RPM or ConfigServer tree), or the RPM's lib dir.
pub fn engine_installed(cfg: &Config) -> bool {
    engine_installed_at(&layout::resolve(cfg))
}

pub fn engine_installed_at(lay: &layout::EngineLayout) -> bool {
    lay.bin.is_file()
        || Path::new("/usr/lib/MailScanner").is_dir()
        || Path::new("/usr/local/cpanel/3rdparty/mailscanner").is_dir()
}

/// True when the engine looks *usable*: installed and with its config present.
/// (`/etc/MailScanner` alone proves nothing — MSFE-NG creates its rules dir.)
pub fn engine_configured(cfg: &Config) -> bool {
    engine_configured_at(&layout::resolve(cfg))
}

pub fn engine_configured_at(lay: &layout::EngineLayout) -> bool {
    engine_installed_at(lay) && lay.conf.is_file()
}

fn ms_defaults_path(cfg: &Config) -> PathBuf {
    layout::resolve(cfg).defaults
}

/// MailScanner's own startup latch: fresh installs ship
/// `/etc/MailScanner/defaults` with `run_mailscanner=0` and ms-init refuses to
/// start until an admin flips it (the wiring step does, once Exim is set up).
/// Returns None when the defaults file is absent/unreadable.
pub fn engine_run_enabled(cfg: &Config) -> Option<bool> {
    ms_defaults_flag(cfg, "run_mailscanner")
}

/// Whether ms-cron DAILY runs the phishing-list updater (`ms_cron_ps`,
/// on by default in the shipped defaults). None when the file is absent.
pub fn phishing_update_enabled(cfg: &Config) -> Option<bool> {
    ms_defaults_flag(cfg, "ms_cron_ps")
}

/// A `key=0|1` flag from MailScanner's defaults file.
fn ms_defaults_flag(cfg: &Config, key: &str) -> Option<bool> {
    let text = std::fs::read_to_string(ms_defaults_path(cfg)).ok()?;
    for line in text.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix(key).and_then(|r| r.strip_prefix('=')) {
            return Some(v.trim() == "1");
        }
    }
    None
}

/// Flip the startup latch (`run_mailscanner=` in MailScanner's defaults file),
/// preserving the rest of the file; appends the line if absent.
pub fn set_engine_run(cfg: &Config, enabled: bool) -> io::Result<()> {
    let path = ms_defaults_path(cfg);
    let text = std::fs::read_to_string(&path)?;
    let val = if enabled { "1" } else { "0" };
    let mut found = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("run_mailscanner=") {
                found = true;
                format!("run_mailscanner={val}")
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        out.push(format!("run_mailscanner={val}"));
    }
    crate::sync::atomic_write(&path, (out.join("\n") + "\n").as_bytes())
}

pub struct LintReport {
    pub ok: bool,
    pub output: String,
}

/// Run MailScanner's own self-check (`--lint`): validates the configuration,
/// perl modules, virus scanner and spam engine. Slow (tens of seconds).
///
/// Runs the engine the layout resolves to — the one `MailScanner.service`
/// runs — never a second copy that happens to be on the PATH.
pub fn lint(cfg: &Config) -> LintReport {
    lint_with(&layout::resolve(cfg).bin)
}

pub fn lint_with(bin: &Path) -> LintReport {
    let mut cmd = Command::new(bin);
    cmd.arg("--lint");
    // lint scans a real test batch: with a scanner unreachable it enters
    // MailScanner's retry loop and never exits — it once held the daemon
    // hostage for 90 minutes (WSOD in WHM)
    match run_with_timeout(&mut cmd, std::time::Duration::from_secs(180)) {
        Ok(o) if o.timed_out => LintReport {
            ok: false,
            output: "MailScanner --lint did not finish within 180s — \
                     a virus/spam scanner is probably unreachable (check clamd and its socket)"
                .into(),
        },
        Ok(o) => LintReport {
            ok: o.ok,
            output: format!("{}{}", o.stdout, o.stderr).trim().to_string(),
        },
        Err(_) => LintReport {
            ok: false,
            output: format!(
                "MailScanner engine is not installed at {} (run: msfe-ng engine install)",
                bin.display()
            ),
        },
    }
}

pub fn status() -> ServiceStatus {
    let active = Command::new("systemctl")
        .args(["is-active", "--quiet", SYSTEMD_UNIT])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
        || Command::new("service")
            .args([SYSV_NAME, "status"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    ServiceStatus {
        active,
        procs: count_processes(),
    }
}

/// Count running MailScanner processes by scanning /proc cmdlines.
fn count_processes() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter(|e| {
            std::fs::read(e.path().join("cmdline"))
                .map(|c| String::from_utf8_lossy(&c).contains("MailScanner"))
                .unwrap_or(false)
        })
        .count()
}

/// What a control action actually did: which command line succeeded (or that
/// both paths failed) and everything the commands printed, so the UI/CLI can
/// show the operator what happened instead of a bare ok/failed.
pub struct ControlOutcome {
    pub ok: bool,
    /// Transcript lines: each attempted command and its captured output.
    pub transcript: Vec<String>,
}

/// Run a service action (`start|stop|reload|restart`), systemd first then SysV,
/// capturing each attempt's output into a transcript.
pub fn control(action: &str) -> ControlOutcome {
    if !matches!(action, "start" | "stop" | "reload" | "restart") {
        return ControlOutcome {
            ok: false,
            transcript: vec![format!("unknown action '{action}'")],
        };
    }
    // Units without an ExecReload= still honor reload-or-restart.
    let sysd_verb = if action == "reload" {
        "reload-or-restart"
    } else {
        action
    };
    let mut transcript = Vec::new();
    let mut run = |cmd: &str, args: &[&str]| -> bool {
        transcript.push(format!("$ {cmd} {}", args.join(" ")));
        match Command::new(cmd).args(args).output() {
            Ok(o) => {
                for stream in [&o.stdout, &o.stderr] {
                    for l in String::from_utf8_lossy(stream).lines() {
                        if !l.trim().is_empty() {
                            transcript.push(l.to_string());
                        }
                    }
                }
                let code = o.status.code().unwrap_or(-1);
                transcript.push(if o.status.success() {
                    "→ ok".to_string()
                } else {
                    format!("→ exit {code}")
                });
                o.status.success()
            }
            Err(e) => {
                transcript.push(format!("→ cannot run: {e}"));
                false
            }
        }
    };
    let ok = run("systemctl", &[sysd_verb, SYSTEMD_UNIT]) || run("service", &[SYSV_NAME, action]);
    ControlOutcome { ok, transcript }
}

/// Recent journal entries for the MailScanner unit(s), for the restart console.
/// Covers both the native unit name and the SysV-generator one; empty when
/// journalctl is unavailable or has nothing.
pub fn journal(lines: usize) -> String {
    let n = lines.clamp(10, 500).to_string();
    Command::new("journalctl")
        .args([
            "-u",
            SYSTEMD_UNIT,
            "-u",
            SYSV_NAME,
            "-n",
            &n,
            "--no-pager",
            "-o",
            "short",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim_end().to_string())
        .unwrap_or_default()
}

// ---- mail queues -------------------------------------------------------------

/// The queue dirs this platform *should* use (env override or the split-spool
/// defaults) — what `engine::configure` writes into MailScanner.conf.
pub fn queue_dir_targets() -> (PathBuf, PathBuf) {
    if let (Ok(i), Ok(o)) = (
        std::env::var("MSFE_NG_INCOMING_QUEUE"),
        std::env::var("MSFE_NG_OUTGOING_QUEUE"),
    ) {
        return (i.into(), o.into());
    }
    (DEFAULT_INCOMING_QUEUE.into(), DEFAULT_OUTGOING_QUEUE.into())
}

/// Incoming/outgoing Exim queue input dirs: MailScanner.conf directives when
/// present, cPanel split-spool defaults otherwise. Env overrides for tests.
pub fn queue_dirs(cfg: &Config) -> (PathBuf, PathBuf) {
    if let (Ok(i), Ok(o)) = (
        std::env::var("MSFE_NG_INCOMING_QUEUE"),
        std::env::var("MSFE_NG_OUTGOING_QUEUE"),
    ) {
        return (i.into(), o.into());
    }
    let conf = std::fs::read_to_string(&cfg.mailscanner_conf).unwrap_or_default();
    let dir = |key: &str, fallback: &str| -> PathBuf {
        mailscanner::get_directive(&conf, key)
            .filter(|v| !v.is_empty())
            .unwrap_or(fallback)
            // named-queue/split configs use a `/*` glob — counts want the dir
            .trim_end_matches("/*")
            .into()
    };
    (
        dir("Incoming Queue Dir", DEFAULT_INCOMING_QUEUE),
        dir("Outgoing Queue Dir", DEFAULT_OUTGOING_QUEUE),
    )
}

/// Count queued messages (`*-H` header files) in an Exim input dir, following
/// split-spool subdirectories one level down.
pub fn count_queue(dir: &Path) -> usize {
    queue_files(dir)
        .iter()
        .filter(|p| p.to_string_lossy().ends_with("-H"))
        .count()
}

/// All -H/-D files in an Exim input dir (flat or split-spool).
pub(crate) fn queue_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in entries.filter_map(|e| e.ok()) {
        let p = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if p.is_dir() && name.len() == 1 {
            // split_spool_directory: single-character subdirs
            if let Ok(sub) = std::fs::read_dir(&p) {
                out.extend(sub.filter_map(|e| e.ok()).map(|e| e.path()));
            }
        } else {
            out.push(p);
        }
    }
    out.retain(|p| {
        let n = p.to_string_lossy();
        n.ends_with("-H") || n.ends_with("-D")
    });
    out
}

/// Queue files whose -H/-D partner is missing and that are older than
/// `min_age_secs` — stuck remnants that block or confuse queue runs.
pub fn find_orphans(dir: &Path, min_age_secs: u64) -> Vec<PathBuf> {
    use std::collections::HashMap;
    let files = queue_files(dir);
    let mut pairs: HashMap<String, (bool, bool)> = HashMap::new();
    for p in &files {
        let name = p.to_string_lossy().into_owned();
        let (id, is_h) = if let Some(s) = name.strip_suffix("-H") {
            (s.to_string(), true)
        } else if let Some(s) = name.strip_suffix("-D") {
            (s.to_string(), false)
        } else {
            continue;
        };
        let e = pairs.entry(id).or_insert((false, false));
        if is_h {
            e.0 = true;
        } else {
            e.1 = true;
        }
    }
    files
        .into_iter()
        .filter(|p| {
            let name = p.to_string_lossy().into_owned();
            let id = name
                .strip_suffix("-H")
                .or_else(|| name.strip_suffix("-D"))
                .unwrap_or(&name)
                .to_string();
            let Some((h, d)) = pairs.get(&id) else {
                return false;
            };
            (!h || !d) && older_than(p, min_age_secs)
        })
        .collect()
}

fn older_than(p: &Path, secs: u64) -> bool {
    if secs == 0 {
        return true;
    }
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|age| age.as_secs() >= secs)
        .unwrap_or(false)
}

pub struct QueueFixReport {
    pub moved: usize,
    pub badqueue_dir: PathBuf,
    pub flush_started: bool,
}

/// Move orphaned queue files out of the way (into a sibling `msfe-ng-badqueue`
/// dir — never deleted) and kick off a forced Exim delivery run.
pub fn queue_fix(cfg: &Config) -> io::Result<QueueFixReport> {
    let (inc, out) = queue_dirs(cfg);
    let badqueue = out
        .parent()
        .unwrap_or(Path::new("/var/spool"))
        .join("msfe-ng-badqueue");
    let mut moved = 0usize;
    for dir in [&inc, &out] {
        let orphans = find_orphans(dir, orphan_min_age());
        if orphans.is_empty() {
            continue;
        }
        std::fs::create_dir_all(&badqueue)?;
        for p in orphans {
            if let Some(name) = p.file_name() {
                if std::fs::rename(&p, badqueue.join(name)).is_ok() {
                    moved += 1;
                }
            }
        }
    }
    Ok(QueueFixReport {
        moved,
        badqueue_dir: badqueue,
        flush_started: force_queue_run(),
    })
}

fn orphan_min_age() -> u64 {
    std::env::var("MSFE_NG_ORPHAN_MIN_AGE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(ORPHAN_MIN_AGE_SECS)
}

/// Spawn a forced queue run (`exim -qff`) in the background; a large queue can
/// take minutes, so the API never waits for it.
fn force_queue_run() -> bool {
    if std::env::var("MSFE_NG_SKIP_QUEUE_RUN").is_ok() {
        return false;
    }
    for exim in ["/usr/sbin/exim", "exim"] {
        let spawned = Command::new(exim)
            .arg("-qff")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        if spawned.is_ok() {
            return true;
        }
    }
    false
}

/// Human-readable queue listing (`exim -bp`), optionally for a named queue
/// (e.g. the `mailscanner` scanning queue). Shows age, size, id, sender and
/// recipients per message — what admins expect from mailq.
pub fn queue_listing(named: Option<&str>) -> String {
    for exim in ["/usr/sbin/exim", "exim"] {
        let mut c = Command::new(exim);
        if let Some(q) = named {
            c.arg(format!("-qG{q}"));
        }
        c.arg("-bp");
        match run_with_timeout(&mut c, std::time::Duration::from_secs(30)) {
            Ok(o) if o.ok => {
                let s = o.stdout.trim_end().to_string();
                return if s.is_empty() {
                    "(queue is empty)".into()
                } else {
                    s
                };
            }
            Ok(o) if o.timed_out => {
                return "exim -bp timed out — the queue may be locked by a scanning process".into()
            }
            Ok(o) => return format!("exim -bp failed: {}", o.stderr.trim()),
            Err(_) => continue,
        }
    }
    "(exim binary not found)".into()
}

/// Exim's split-spool subdirectory for a message id: its sixth character.
/// (Verified against Exim 4.99, which also files msglog under that letter.)
pub fn expected_subdir(id: &str) -> Option<char> {
    id.chars().nth(5)
}

pub struct MisplacedMsg {
    pub id: String,
    pub found_in: String,
    pub expected: char,
    pub files: Vec<PathBuf>,
}

/// Spool files sitting in the wrong split-spool subdirectory. Exim lists such
/// messages in the queue but can never deliver them: it derives the path from
/// the message id, so they wait forever. (MailScanner 5.5.3 misfiles them when
/// its Exim version probe fails — see engine::configure's `Exim Command`.)
/// Only messages older than a minute are reported, so in-flight writes are
/// never touched.
pub fn misplaced_spool(dir: &Path) -> Vec<MisplacedMsg> {
    use std::collections::BTreeMap;
    let mut by_id: BTreeMap<(String, String), Vec<PathBuf>> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for sub in entries.filter_map(|e| e.ok()) {
        let subname = sub.file_name().to_string_lossy().into_owned();
        if !sub.path().is_dir() || subname.chars().count() != 1 {
            continue;
        }
        let Ok(files) = std::fs::read_dir(sub.path()) else {
            continue;
        };
        for f in files.filter_map(|e| e.ok()) {
            let name = f.file_name().to_string_lossy().into_owned();
            // <id>-<suffix>, e.g. 1wnE6V-00000004Oi2-3lJH-H
            let Some(id) = name.rsplit_once('-').map(|(id, _)| id.to_string()) else {
                continue;
            };
            if !valid_exim_id(&id) || !older_than(&f.path(), 60) {
                continue;
            }
            by_id
                .entry((id, subname.clone()))
                .or_default()
                .push(f.path());
        }
    }
    by_id
        .into_iter()
        .filter_map(|((id, found_in), files)| {
            let expected = expected_subdir(&id)?;
            (!found_in.starts_with(expected)).then_some(MisplacedMsg {
                id,
                found_in,
                expected,
                files,
            })
        })
        .collect()
}

pub struct SpoolRepairReport {
    pub moved: usize,
    pub actions: Vec<String>,
    pub flush_started: bool,
    pub dry_run: bool,
}

/// Move misplaced spool files into the subdirectory Exim looks in, then force
/// a delivery run. Never deletes anything.
pub fn repair_spool(dir: &Path, dry: bool) -> io::Result<SpoolRepairReport> {
    let mut actions = Vec::new();
    let mut moved = 0usize;
    for m in misplaced_spool(dir) {
        let target = dir.join(m.expected.to_string());
        actions.push(format!(
            "{} {} : {} → {}",
            if dry { "would move" } else { "moving" },
            m.id,
            m.found_in,
            m.expected
        ));
        if dry {
            continue;
        }
        if !target.exists() {
            std::fs::create_dir_all(&target)?;
            set_perms_0750(&target);
            chown_run_user(&target);
        }
        for f in &m.files {
            if let Some(name) = f.file_name() {
                match std::fs::rename(f, target.join(name)) {
                    Ok(()) => moved += 1,
                    Err(e) => actions.push(format!("  FAILED {}: {e}", name.to_string_lossy())),
                }
            }
        }
    }
    if actions.is_empty() {
        actions.push("no misplaced spool files".into());
    }
    let flush_started = if dry || moved == 0 {
        false
    } else {
        force_queue_run()
    };
    Ok(SpoolRepairReport {
        moved,
        actions,
        flush_started,
        dry_run: dry,
    })
}

fn chown_run_user(p: &Path) {
    if let (Some(uid), Some(gid)) = (
        crate::engine::uid_of("mailnull").or_else(|| crate::engine::uid_of("mail")),
        crate::engine::gid_of("mail"),
    ) {
        let _ = std::os::unix::fs::chown(p, Some(uid), Some(gid));
    }
}

fn set_perms_0750(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o750));
}

/// Age in seconds of the oldest queued message (-H file) in a queue input dir.
pub fn oldest_queue_age(dir: &Path) -> Option<u64> {
    queue_files(dir)
        .iter()
        .filter(|p| p.to_string_lossy().ends_with("-H"))
        .filter_map(|p| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
        })
        .map(|d| d.as_secs())
        .max()
}

/// Valid Exim message id (old or new format): word chars and dashes only.
pub fn valid_exim_id(id: &str) -> bool {
    (10..=30).contains(&id.len())
        && id.contains('-')
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Act on many queued messages at once. `delete` runs `exim -Mrm` in batches
/// of 100 and reports per-batch results; `deliver` starts detached `exim -M`
/// runs (a bulk synchronous delivery could block for minutes on slow remotes).
/// The whole batch is rejected if any id fails validation — ids come from the
/// UI or from cleanup criteria, never free-form. `dry` reports what would be
/// done without touching the queue.
pub fn queue_bulk_action(
    named: Option<&str>,
    ids: &[String],
    action: &str,
    dry: bool,
) -> ControlOutcome {
    if ids.is_empty() {
        return ControlOutcome {
            ok: true,
            transcript: vec!["nothing to do (no matching messages)".into()],
        };
    }
    if let Some(bad) = ids.iter().find(|i| !valid_exim_id(i)) {
        return ControlOutcome {
            ok: false,
            transcript: vec![format!("invalid message id '{bad}' — batch rejected")],
        };
    }
    if !matches!(action, "delete" | "deliver") {
        return ControlOutcome {
            ok: false,
            transcript: vec![format!("unknown action '{action}'")],
        };
    }
    if dry {
        let mut transcript = vec![format!("dry-run: would {action} {} message(s):", ids.len())];
        transcript.extend(ids.iter().map(|i| format!("  {i}")));
        return ControlOutcome {
            ok: true,
            transcript,
        };
    }
    let mut transcript = Vec::new();
    let mut ok = true;
    for chunk in ids.chunks(100) {
        if action == "delete" {
            transcript.push(format!(
                "$ exim {}-Mrm <{} ids>",
                named.map(|q| format!("-qG{q} ")).unwrap_or_default(),
                chunk.len()
            ));
            match run_with_timeout(
                exim_cmd(named).arg("-Mrm").args(chunk),
                std::time::Duration::from_secs(60),
            ) {
                Ok(o) => {
                    for stream in [&o.stdout, &o.stderr] {
                        for l in stream.lines() {
                            if !l.trim().is_empty() {
                                transcript.push(l.to_string());
                            }
                        }
                    }
                    if o.timed_out {
                        transcript.push(
                            "→ timed out — some messages may be locked by a scanning process"
                                .into(),
                        );
                        ok = false;
                        continue;
                    }
                    // a message delivered mid-flight makes -Mrm exit non-zero;
                    // that's a soft error, not a batch failure — the per-id
                    // lines above show what happened
                    if !o.ok {
                        transcript.push(format!(
                            "→ exit {} (some ids may already be gone)",
                            o.code.unwrap_or(-1)
                        ));
                    }
                }
                Err(e) => {
                    transcript.push(format!("→ cannot run exim: {e}"));
                    ok = false;
                }
            }
        } else {
            // deliver: fire-and-forget so a slow remote can't hang the request
            match exim_cmd(named)
                .arg("-M")
                .args(chunk)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(_) => transcript.push(format!(
                    "started delivery run for {} message(s)",
                    chunk.len()
                )),
                Err(e) => {
                    transcript.push(format!("→ cannot run exim: {e}"));
                    ok = false;
                }
            }
        }
    }
    if ok {
        transcript.push(format!("→ {action}: {} message(s) processed", ids.len()));
    }
    ControlOutcome { ok, transcript }
}

fn exim_cmd(named: Option<&str>) -> Command {
    let bin = if Path::new("/usr/sbin/exim").exists() {
        "/usr/sbin/exim"
    } else {
        "exim"
    };
    let mut c = Command::new(bin);
    if let Some(q) = named {
        c.arg(format!("-qG{q}"));
    }
    c
}

/// View a queued message: its headers, body, or delivery-log history.
pub fn queue_msg_view(cfg: &Config, named: Option<&str>, id: &str, what: &str) -> String {
    if !valid_exim_id(id) {
        return "invalid message id".into();
    }
    // `exim -Mvh/-Mvb` waits for the message's spool lock: a message held by a
    // wedged scanner child would block this (and the whole daemon) forever
    let view_timeout = std::time::Duration::from_secs(10);
    let out = match what {
        "headers" => run_with_timeout(exim_cmd(named).args(["-Mvh", id]), view_timeout),
        "body" => run_with_timeout(exim_cmd(named).args(["-Mvb", id]), view_timeout),
        "log" => {
            // delivery history from the mainlog (exigrep threads it; plain
            // grep as fallback)
            let ex = run_with_timeout(
                Command::new("/usr/sbin/exigrep").args([id, &cfg.exim_mainlog_path]),
                view_timeout,
            );
            match ex {
                Ok(o) if o.ok => Ok(o),
                _ => run_with_timeout(
                    Command::new("grep").args([id, &cfg.exim_mainlog_path]),
                    view_timeout,
                ),
            }
        }
        _ => return "unknown view".into(),
    };
    match out {
        Ok(o) if o.timed_out => {
            "timed out — the message is probably locked by a scanning process right now".into()
        }
        Ok(o) => {
            let s = format!("{}{}", o.stdout, o.stderr);
            let s = s.trim();
            if s.is_empty() {
                "(no output)".into()
            } else {
                s.to_string()
            }
        }
        Err(e) => format!("cannot run exim: {e}"),
    }
}

/// Act on a queued message: force delivery now (`-v -M`, frozen included) or
/// delete it (`-v -Mrm`). Returns a transcript like `control()`.
pub fn queue_msg_action(named: Option<&str>, id: &str, action: &str) -> ControlOutcome {
    if !valid_exim_id(id) {
        return ControlOutcome {
            ok: false,
            transcript: vec!["invalid message id".into()],
        };
    }
    let args: &[&str] = match action {
        "deliver" => &["-v", "-M"],
        "delete" => &["-v", "-Mrm"],
        _ => {
            return ControlOutcome {
                ok: false,
                transcript: vec![format!("unknown action '{action}'")],
            }
        }
    };
    let mut transcript = vec![format!(
        "$ exim {}{} {id}",
        named.map(|q| format!("-qG{q} ")).unwrap_or_default(),
        args.join(" ")
    )];
    // deliveries legitimately take a while on slow remotes; deletes should be
    // instant unless the message is locked by a scanning process
    let timeout = std::time::Duration::from_secs(if action == "deliver" { 120 } else { 30 });
    match run_with_timeout(exim_cmd(named).args(args).arg(id), timeout) {
        Ok(o) => {
            for stream in [&o.stdout, &o.stderr] {
                for l in stream.lines() {
                    if !l.trim().is_empty() {
                        transcript.push(l.to_string());
                    }
                }
            }
            if o.timed_out {
                transcript.push(format!(
                    "→ timed out after {}s — the message may be locked by a scanning process",
                    timeout.as_secs()
                ));
                return ControlOutcome {
                    ok: false,
                    transcript,
                };
            }
            let ok = o.ok;
            transcript.push(if ok {
                "→ ok".into()
            } else {
                format!("→ exit {}", o.code.unwrap_or(-1))
            });
            ControlOutcome { ok, transcript }
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

// ---- maillog tail ------------------------------------------------------------

/// Read the last `lines` lines of `path`, scanning at most the final 1 MiB.
pub fn tail_file(path: &Path, lines: usize) -> io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    const MAX_SCAN: u64 = 1024 * 1024;
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    let start = len.saturating_sub(MAX_SCAN);
    f.seek(SeekFrom::Start(start))?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf)?;
    let text = String::from_utf8_lossy(&buf);
    let all: Vec<&str> = text.lines().collect();
    let from = all.len().saturating_sub(lines);
    // When we started mid-file the first line is likely partial — drop it.
    let from = if start > 0 && from == 0 {
        1.min(all.len())
    } else {
        from
    };
    Ok(all[from..].join("\n"))
}

// ---- ruleset / config file access --------------------------------------------

/// True for plain filenames safe to resolve inside a managed directory.
pub fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Ruleset files in the managed rules dir as (name, size) pairs, sorted.
pub fn list_rules(cfg: &Config) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = std::fs::read_dir(&cfg.mailscanner_rules_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let size = e.metadata().ok()?.len();
                    safe_name(&name).then_some((name, size))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

pub fn read_rule(cfg: &Config, name: &str) -> io::Result<String> {
    if !safe_name(name) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad name"));
    }
    std::fs::read_to_string(Path::new(&cfg.mailscanner_rules_dir).join(name))
}

/// Save an editable config file, keeping a one-time `.msfe-ng.bak` of the
/// original and writing atomically.
pub fn save_conf(path: &Path, content: &str) -> io::Result<()> {
    if path.exists() {
        let backup = PathBuf::from(format!("{}.msfe-ng.bak", path.display()));
        if !backup.exists() {
            std::fs::copy(path, &backup)?;
        }
    }
    crate::sync::atomic_write(path, content.as_bytes())
}

// ---- release check -----------------------------------------------------------

const UPDATE_REPO: &str = "inalto/msfe-ng";

/// Latest released version, resolved on demand from the GitHub release-page
/// redirect via curl (the codebase has no TLS client). Never called
/// automatically — only from the admin's explicit "check for updates".
pub fn latest_version() -> Option<String> {
    let repo = std::env::var("MSFE_NG_UPDATE_REPO").unwrap_or_else(|_| UPDATE_REPO.to_string());
    let url = format!("https://github.com/{repo}/releases/latest");
    let out = Command::new("curl")
        .args([
            "-sSfL",
            "-o",
            "/dev/null",
            "-w",
            "%{url_effective}",
            "-m",
            "8",
            &url,
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    extract_tag(String::from_utf8_lossy(&out.stdout).trim())
}

/// `…/releases/tag/v1.2.3` → `1.2.3`.
fn extract_tag(url: &str) -> Option<String> {
    let tag = url.rsplit('/').next()?;
    let ver = tag.strip_prefix('v')?;
    (!ver.is_empty() && ver.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        .then(|| ver.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-svc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lint_runs_the_engine_binary_of_the_layout() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmpdir("lint");
        // a ConfigServer-style engine: not /usr/sbin/MailScanner
        let bin = d.join("usr/mailscanner/usr/sbin/MailScanner");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\necho \"lint from $0 $1\"\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let r = lint_with(&bin);
        assert!(r.ok, "{}", r.output);
        assert_eq!(r.output, format!("lint from {} --lint", bin.display()));
        // no engine at that path: an install hint, not a crash
        let r = lint_with(&d.join("missing"));
        assert!(!r.ok && r.output.contains("not installed"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn engine_presence_follows_the_layout() {
        let d = tmpdir("engine");
        let root = d.join("usr/mailscanner");
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("usr/sbin")).unwrap();
        let conf = root.join("etc/MailScanner.conf");
        let cfg = Config {
            mailscanner_conf: conf.display().to_string(),
            ..Default::default()
        };
        // ConfigServer tree with the binary but no conf yet
        std::fs::write(root.join("usr/sbin/MailScanner"), "#!/usr/bin/perl\n").unwrap();
        let lay = crate::layout::resolve(&cfg);
        assert_eq!(lay.bin, root.join("usr/sbin/MailScanner"));
        assert!(engine_installed_at(&lay));
        assert!(!engine_configured_at(&lay));
        std::fs::write(&conf, "MTA = exim\n").unwrap();
        assert!(engine_configured_at(&crate::layout::resolve(&cfg)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn tail_returns_last_lines() {
        let d = tmpdir("tail");
        let f = d.join("log");
        std::fs::write(&f, "one\ntwo\nthree\nfour\n").unwrap();
        assert_eq!(tail_file(&f, 2).unwrap(), "three\nfour");
        assert_eq!(tail_file(&f, 99).unwrap(), "one\ntwo\nthree\nfour");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn queue_count_and_orphans() {
        let d = tmpdir("queue");
        // complete pair + orphaned -H + orphaned -D in a split-spool subdir
        std::fs::write(d.join("1aaaaa-000001-AA-H"), "h").unwrap();
        std::fs::write(d.join("1aaaaa-000001-AA-D"), "d").unwrap();
        std::fs::write(d.join("1bbbbb-000002-BB-H"), "h").unwrap();
        std::fs::create_dir(d.join("c")).unwrap();
        std::fs::write(d.join("c/1ccccc-000003-CC-D"), "d").unwrap();
        std::fs::write(d.join("ignore.txt"), "x").unwrap();

        assert_eq!(count_queue(&d), 2); // two -H files
        let orphans = find_orphans(&d, 0); // min age 0 → all orphans count
        let names: Vec<String> = orphans
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(orphans.len(), 2);
        assert!(names.contains(&"1bbbbb-000002-BB-H".to_string()));
        assert!(names.contains(&"1ccccc-000003-CC-D".to_string()));
        // with a huge min-age nothing is old enough
        assert!(find_orphans(&d, 3600).is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn safe_name_rejects_traversal() {
        assert!(safe_name("spam.whitelist.rules"));
        assert!(safe_name("a_b-c.1"));
        assert!(!safe_name(""));
        assert!(!safe_name(".hidden"));
        assert!(!safe_name("../etc/passwd"));
        assert!(!safe_name("a/b"));
        assert!(!safe_name("a b"));
    }

    // Regression for a daemon wedge: `exim -Mvb` on a message locked by a
    // stuck MailScanner child blocks forever, and the single-threaded daemon
    // died with it (WSOD in WHM). Spawned commands must have a deadline.
    #[test]
    fn run_with_timeout_kills_a_hung_command() {
        let start = std::time::Instant::now();
        let mut cmd = Command::new("sh");
        // `sh` forks the sleeps (no exec): killing only the direct child would
        // leave grandchildren alive holding the pipes — CI caught exactly that
        cmd.args(["-c", "sleep 8 & sleep 8"]);
        let r = run_with_timeout(&mut cmd, std::time::Duration::from_millis(300)).unwrap();
        assert!(r.timed_out, "must report the timeout");
        assert!(!r.ok, "a killed command is not a success");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "must return promptly, not wait for the command"
        );
    }

    #[test]
    fn run_with_timeout_passes_through_fast_commands() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out; echo err >&2"]);
        let r = run_with_timeout(&mut cmd, std::time::Duration::from_secs(5)).unwrap();
        assert!(r.ok && !r.timed_out);
        assert_eq!(r.stdout.trim(), "out");
        assert_eq!(r.stderr.trim(), "err");
    }

    #[test]
    fn save_conf_backs_up_once() {
        let d = tmpdir("conf");
        let f = d.join("test.conf");
        std::fs::write(&f, "original\n").unwrap();
        save_conf(&f, "edited\n").unwrap();
        save_conf(&f, "edited again\n").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "edited again\n");
        let bak = d.join("test.conf.msfe-ng.bak");
        assert_eq!(std::fs::read_to_string(&bak).unwrap(), "original\n");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn extracts_release_tag() {
        assert_eq!(
            extract_tag("https://github.com/inalto/msfe-ng/releases/tag/v0.0.3"),
            Some("0.0.3".into())
        );
        assert_eq!(
            extract_tag("https://github.com/inalto/msfe-ng/releases"),
            None
        );
        assert_eq!(
            extract_tag("https://github.com/x/y/releases/tag/main"),
            None
        );
    }
}
