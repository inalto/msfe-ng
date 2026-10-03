//! Helpers shared by tests that write an executable script and run it.
//!
//! Tests run on many threads in one process. A thread that forks while
//! another is still writing a script holds a copy of the write fd until its
//! exec, and exec-ing that script meanwhile fails with ETXTBSY ("Text file
//! busy", os error 26). So scripts are written to a temp name, closed,
//! chmod-ed and renamed into place, and [`write_script_ready`] additionally
//! waits (bounded) until the script can really be exec-ed.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

/// How often and how long a busy script is retried.
const TRIES: u32 = 300;
const PAUSE: Duration = Duration::from_millis(10);

/// True for the exec error "Text file busy" (ETXTBSY, os error 26).
pub(crate) fn is_text_busy(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(26)
}

/// Write an executable script so that no write fd is open when it is
/// exec-ed: temp name, close, chmod 0755, rename into place.
pub(crate) fn write_script(path: &Path, body: &str) {
    let mut name = path.file_name().unwrap().to_os_string();
    name.push(".tmp-script");
    let tmp = path.with_file_name(name);
    {
        let mut f = std::fs::File::create(&tmp).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.sync_all().unwrap();
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

/// Spawn `cmd` and wait for it, retrying a bounded number of times while the
/// spawn fails with ETXTBSY. Any other spawn error is returned at once.
pub(crate) fn spawn_retry(cmd: &mut Command) -> std::io::Result<std::process::ExitStatus> {
    let mut tries = 0;
    loop {
        match cmd.status() {
            Err(e) if is_text_busy(&e) && tries < TRIES => {
                tries += 1;
                std::thread::sleep(PAUSE);
            }
            r => return r,
        }
    }
}

/// [`write_script`], then wait until the script can be exec-ed: it is run
/// once with no arguments and its output and exit status are ignored, so
/// use it only for scripts that are harmless to run bare.
pub(crate) fn write_script_ready(path: &Path, body: &str) {
    write_script(path, body);
    let _ = spawn_retry(
        Command::new(path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-testutil-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn script_is_executable_and_leaves_no_temp() {
        let d = dir("w");
        let p = d.join("s");
        write_script_ready(&p, "#!/bin/sh\necho hi\n");
        let m = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o755);
        let out = Command::new(&p).output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
        let names: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn busy_is_only_os_error_26() {
        assert!(is_text_busy(&std::io::Error::from_raw_os_error(26)));
        assert!(!is_text_busy(&std::io::Error::from_raw_os_error(2)));
        assert!(!is_text_busy(&std::io::Error::other("x")));
    }

    #[test]
    fn spawn_retry_returns_other_errors_at_once() {
        let r = spawn_retry(&mut Command::new("/nonexistent/definitely-not-here"));
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }
}
