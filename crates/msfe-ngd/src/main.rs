//! MSFE-NG daemon (`msfe-ngd`).
//!
//! Listens on a Unix domain socket and speaks minimal HTTP/1.1. The panel
//! shims (cPanel UAPI module, DirectAdmin CGI, WHM CGI) connect to this socket
//! and forward the browser request, so all real logic can live here in Rust.
//!
//! Dependency-free on purpose (std only). Each connection is served on its own
//! thread — connections are short-lived and local, and a long read (a search
//! over the whole maillog) must not stall the dashboard or the end-user page.
//! Mutating requests are serialised by `WRITE_LOCK` so handlers that rewrite
//! config or drive the queue never interleave, exactly as when the daemon was
//! single-threaded.

mod api;
mod conf_api;
mod http;
mod views;

use msfe_api::{DEFAULT_SOCKET_PATH, VERSION};
use msfe_core::{detect_panel, users};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Mutex;

/// Held for the whole of every non-GET request: handlers that write policy
/// files, run sync, or repair the queue were never concurrent and must stay so.
static WRITE_LOCK: Mutex<()> = Mutex::new(());

/// Anything but a GET may change state on disk and takes `WRITE_LOCK`.
fn is_mutating(method: &str) -> bool {
    method != "GET"
}

fn socket_path() -> String {
    std::env::var("MSFE_NG_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
}

fn web_root() -> String {
    std::env::var("MSFE_NG_WEBROOT").unwrap_or_else(|_| "/opt/msfe-ng/web".to_string())
}

fn config_path() -> String {
    std::env::var("MSFE_NG_CONFIG").unwrap_or_else(|_| msfe_api::DEFAULT_CONFIG_FILE.to_string())
}

fn main() -> io::Result<()> {
    let path = socket_path();
    let panel = detect_panel();
    eprintln!(
        "msfe-ngd {VERSION} starting: socket={path} panel={} webroot={}",
        panel.kind().as_str(),
        web_root()
    );

    // Remove a stale socket from a previous run so bind() succeeds.
    if Path::new(&path).exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(dir) = Path::new(&path).parent() {
        std::fs::create_dir_all(dir)?;
    }

    // a save that died mid-validation leaves its staged etc copy behind
    msfe_core::confstage::sweep(&msfe_core::Config::load(std::path::Path::new(
        &config_path(),
    )));

    let listener = UnixListener::bind(&path)?;
    // World-connectable on purpose: the panel's end-user CGIs run as the
    // account (cPanel LiveAPI, DirectAdmin user plugins). Every connection is
    // authorised by its peer uid in `handle` — see http::peer_scope.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    eprintln!("msfe-ngd: listening on {path}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                std::thread::spawn(move || {
                    if let Err(e) = handle(s) {
                        eprintln!("msfe-ngd: connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("msfe-ngd: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: UnixStream) -> io::Result<()> {
    let mut req = http::Request::read(&stream)?;
    if let Some(denied) = http::peer_scope(&mut req, peer_uid(&stream), users::username_of_uid) {
        return denied.write(stream);
    }
    // A handler that panicked while holding the lock must not wedge the daemon.
    let _serialised =
        is_mutating(&req.method).then(|| WRITE_LOCK.lock().unwrap_or_else(|p| p.into_inner()));
    let panel = detect_panel();

    let resp = if req.path == "/health" || req.path == "/api/health" {
        http::Response::json(
            200,
            &format!(
                "{{\"status\":\"ok\",\"version\":\"{VERSION}\",\"panel\":\"{}\"}}",
                panel.kind().as_str()
            ),
        )
    } else if req.path.starts_with("/api/") {
        let cfg_file = config_path();
        let cfg = msfe_core::Config::load(std::path::Path::new(&cfg_file));
        api::handle(&req, &cfg, std::path::Path::new(&cfg_file))
    } else {
        match req.path.as_str() {
            "/" | "/whm" | "/whm/" | "/index.html" => {
                http::Response::html(200, &views::render(msfe_api::View::Admin, panel.as_ref()))
            }
            "/user" | "/user/" => {
                http::Response::html(200, &views::render(msfe_api::View::User, panel.as_ref()))
            }
            _ => http::Response::html(404, &views::not_found()),
        }
    };

    resp.write(stream)
}

/// The uid of the process on the other end of a Unix socket (Linux
/// SO_PEERCRED). None if the kernel would not tell us — treated as untrusted.
/// std's `UnixStream::peer_cred` is still unstable, hence the small FFI.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *mut std::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let mut cred = Ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<Ucred>() as u32;
    // SAFETY: fd is a live socket owned by `stream`; `cred`/`len` are valid,
    // correctly sized out-pointers for the duration of the call.
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut Ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<Ucred>()).then_some(cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_get_requests_skip_the_write_lock() {
        assert!(!is_mutating("GET"));
        for m in ["POST", "PUT", "DELETE", "PATCH", ""] {
            assert!(is_mutating(m), "{m}");
        }
    }
}
