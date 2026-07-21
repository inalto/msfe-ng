//! MSFE-NG daemon (`msfe-ngd`).
//!
//! Listens on a Unix domain socket and speaks minimal HTTP/1.1. In M0 it serves
//! placeholder WHM/user pages plus a `/health` endpoint. The panel shims
//! (cPanel UAPI module, DirectAdmin CGI, WHM CGI) connect to this socket and
//! forward the browser request, so all real logic can live here in Rust.
//!
//! Dependency-free on purpose (std only) — later milestones swap in an async
//! runtime + router. Keep the handler small until then.

mod http;
mod views;

use msfe_api::{DEFAULT_SOCKET_PATH, VERSION};
use msfe_core::detect_panel;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

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

    let listener = UnixListener::bind(&path)?;
    eprintln!("msfe-ngd: listening on {path}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                // M0 is single-threaded; connections are short. M1 adds a pool.
                if let Err(e) = handle(s) {
                    eprintln!("msfe-ngd: connection error: {e}");
                }
            }
            Err(e) => eprintln!("msfe-ngd: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: UnixStream) -> io::Result<()> {
    let req = http::Request::read(&stream)?;
    let panel = detect_panel();

    let resp = match req.path.as_str() {
        "/health" | "/api/health" => http::Response::json(
            200,
            &format!(
                "{{\"status\":\"ok\",\"version\":\"{VERSION}\",\"panel\":\"{}\"}}",
                panel.kind().as_str()
            ),
        ),
        "/api/config" => {
            let cfg = msfe_core::Config::load(std::path::Path::new(&config_path()));
            http::Response::json(200, &cfg.to_public_json().to_string())
        }
        "/" | "/whm" | "/whm/" | "/index.html" => {
            http::Response::html(200, &views::render(msfe_api::View::Admin, panel.as_ref()))
        }
        "/user" | "/user/" => {
            http::Response::html(200, &views::render(msfe_api::View::User, panel.as_ref()))
        }
        _ => http::Response::html(404, &views::not_found()),
    };

    resp.write(stream)
}
