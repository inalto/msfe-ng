//! Background jobs: privileged, long-running installers started from the UI
//! and followed through a log file.
//!
//! A job runs detached from the daemon as a transient systemd unit
//! (`systemd-run --unit msfe-ng-job-<name>`), in its own cgroup, so it survives
//! the daemon restarting — the self-upgrade replaces the very daemon that
//! started it — and never occupies a request thread. Jobs are a fixed set;
//! the API can start one by name, never run a command of its own.
//!
//! Files under `/var/log/msfe-ng/jobs/`: `<name>.log` (output, truncated at
//! start), `<name>.pid` (the wrapper shell, written first) and
//! `<name>.status` (`exit=N`, written last). Running = pid file, no status
//! file, and the pid alive — a reboot mid-job reads as interrupted, never as
//! running forever.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DEFAULT_DIR: &str = "/var/log/msfe-ng/jobs";
const LOG_TAIL_BYTES: u64 = 64 * 1024;

/// Where job files live (`MSFE_NG_JOBS_DIR` overrides; tests use a tempdir).
pub fn dir() -> PathBuf {
    std::env::var("MSFE_NG_JOBS_DIR")
        .unwrap_or_else(|_| DEFAULT_DIR.to_string())
        .into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobStatus {
    /// Has this job ever been started (a log exists)?
    pub known: bool,
    pub running: bool,
    /// Exit code once finished; `None` while running or when interrupted.
    pub exit: Option<i32>,
    /// Last part of the log.
    pub log_tail: String,
}

/// The jobs directory, for other single-instance guards (the auto-ban run).
pub fn jobs_dir() -> PathBuf {
    dir()
}

fn paths(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let d = dir();
    (
        d.join(format!("{name}.log")),
        d.join(format!("{name}.pid")),
        d.join(format!("{name}.status")),
    )
}

fn script_path(name: &str) -> PathBuf {
    dir().join(format!("{name}.sh"))
}

/// Does the pid in `pid_file` name a live process?
pub fn pid_alive(pid_file: &Path) -> bool {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .is_some_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

pub fn status(name: &str) -> JobStatus {
    let (log, pid, st) = paths(name);
    let exit = std::fs::read_to_string(&st)
        .ok()
        .and_then(|s| s.trim().strip_prefix("exit=").and_then(|n| n.parse().ok()));
    let running = !st.exists() && pid_alive(&pid);
    JobStatus {
        known: log.exists(),
        running,
        exit,
        log_tail: tail(&log),
    }
}

fn tail(path: &Path) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let skip = len.saturating_sub(LOG_TAIL_BYTES);
    if skip > 0 && f.seek(SeekFrom::Start(skip)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if skip > 0 {
        // drop the partial first line
        if let Some(i) = text.find('\n') {
            text.drain(..=i);
        }
    }
    text
}

/// Start `script` (a `sh` snippet) as job `name` with extra environment.
/// Refuses while the job is running.
pub fn start(name: &str, script: &str, env: &[(&str, String)]) -> io::Result<()> {
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(io::Error::other(format!("bad job name '{name}'")));
    }
    if status(name).running {
        return Err(io::Error::other(format!("job '{name}' is already running")));
    }
    let (log, pid, st) = paths(name);
    std::fs::create_dir_all(dir())?;
    std::fs::write(&log, b"")?;
    let _ = std::fs::remove_file(&st);
    let _ = std::fs::remove_file(&pid);
    // The wrapper records its pid first and its exit code last; everything
    // the job prints lands in the log. A subshell, so the script's own `exit`
    // cannot skip the status line. It goes through a file: on systemd's
    // command line `$$` is an escaped `$` and `$VAR` is substituted.
    let wrapper = format!(
        "#!/bin/sh\necho $$ > {pid}\n( {script} ) >> {log} 2>&1\necho exit=$? > {st}\n",
        pid = sh_quote(&pid),
        log = sh_quote(&log),
        st = sh_quote(&st),
    );
    let sh_file = script_path(name);
    std::fs::write(&sh_file, wrapper)?;
    let sh_file = sh_file.display().to_string();
    let mut env: Vec<(String, String)> = env
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
    env.push((
        "PATH".into(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
    ));
    env.push(("HOME".into(), "/root".into()));
    let unit = format!("msfe-ng-job-{name}");
    let use_systemd = std::env::var("MSFE_NG_JOBS_RUNNER").as_deref() != Ok("direct")
        && Path::new("/usr/bin/systemd-run").exists();
    let mut cmd = if use_systemd {
        // a failed leftover unit of the same name would block systemd-run
        let _ = Command::new("systemctl")
            .args(["reset-failed", &unit])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let mut c = Command::new("systemd-run");
        c.args(["--unit", &unit, "--collect", "--quiet"]);
        for (k, v) in &env {
            c.arg(format!("--setenv={k}={v}"));
        }
        c.args(["/bin/sh", &sh_file]);
        c
    } else {
        // detached the plain way: a new session, forked so nothing waits on it
        let mut c = Command::new("setsid");
        c.args(["-f", "/bin/sh", &sh_file]);
        for (k, v) in &env {
            c.env(k, v);
        }
        c
    };
    // Only systemd-run's own stderr is worth capturing; the forked direct
    // runner would hold a pipe open for the job's whole life.
    cmd.stdin(Stdio::null()).stdout(Stdio::null());
    if use_systemd {
        cmd.stderr(Stdio::piped());
    } else {
        cmd.stderr(Stdio::null());
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "cannot start job: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

pub(crate) fn sh_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// One dir per test process (env vars are process-wide and the tests run
    /// in parallel); each test uses its own job names.
    fn jobs_dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-jobs-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var("MSFE_NG_JOBS_DIR", &d);
        std::env::set_var("MSFE_NG_JOBS_RUNNER", "direct");
        d
    }

    fn wait_done(name: &str) -> JobStatus {
        let t0 = Instant::now();
        loop {
            let s = status(name);
            if !s.running && s.known && (s.exit.is_some() || t0.elapsed() > Duration::from_secs(5))
            {
                return s;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn a_job_logs_its_output_and_exit_code() {
        jobs_dir();
        assert!(!status("t1").known);
        start(
            "t1",
            "echo hello; echo err >&2; exit 3",
            &[("MSFE_NG_T", "x".into())],
        )
        .unwrap();
        let s = wait_done("t1");
        assert_eq!(s.exit, Some(3));
        assert!(
            s.log_tail.contains("hello\n") && s.log_tail.contains("err\n"),
            "{}",
            s.log_tail
        );
        // environment reaches the script
        start("t2", "echo env=$MSFE_NG_T", &[("MSFE_NG_T", "ok".into())]).unwrap();
        assert!(wait_done("t2").log_tail.contains("env=ok"));
    }

    #[test]
    fn a_running_job_is_not_started_twice_and_a_dead_one_reads_interrupted() {
        let d = jobs_dir();
        start("slow", "sleep 2; echo done", &[]).unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert!(status("slow").running);
        let err = start("slow", "true", &[]).unwrap_err();
        assert!(err.to_string().contains("already running"));
        let s = wait_done("slow");
        assert_eq!(s.exit, Some(0));
        assert!(s.log_tail.contains("done"));

        // interrupted: pid file names a dead process, no status file
        std::fs::write(d.join("gone.log"), "started\n").unwrap();
        std::fs::write(d.join("gone.pid"), "4194304\n").unwrap();
        let s = status("gone");
        assert!(s.known && !s.running && s.exit.is_none());
        start("gone", "echo again", &[]).unwrap(); // restartable
        assert!(wait_done("gone").log_tail.contains("again"));
    }
}
