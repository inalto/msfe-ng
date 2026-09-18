//! Minimal HTTP/1.1 request reader and response writer over a stream.
//!
//! Deliberately tiny: request line + headers + (Content-Length) body. Not a
//! general HTTP server — no keep-alive, no chunked encoding. Replaced by a real
//! router crate in a later milestone.

use std::io::{self, BufRead, BufReader, Read, Write};

pub struct Request {
    pub method: String,
    /// Path only (query stripped).
    pub path: String,
    /// Raw query string (without the leading `?`), if any.
    pub query: String,
    /// Request body (read per Content-Length).
    pub body: String,
    /// Authenticated panel user, injected by the user-side proxy shim
    /// (`X-MSFE-User`). Empty for the admin/WHM surface (root, unscoped).
    pub user: String,
}

impl Request {
    pub fn read<R: Read>(stream: R) -> io::Result<Request> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let raw_path = parts.next().unwrap_or("/").to_string();
        let (path, query) = match raw_path.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (raw_path.clone(), String::new()),
        };

        // Read headers, capturing Content-Length and X-MSFE-User, to the blank line.
        let mut content_length = 0usize;
        let mut user = String::new();
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim();
                if k.eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().unwrap_or(0);
                } else if k.eq_ignore_ascii_case("x-msfe-user") {
                    user = v.trim().to_string();
                }
            }
        }

        // Read exactly Content-Length body bytes (bounded to avoid abuse).
        let mut body = String::new();
        if content_length > 0 && content_length <= 4 * 1024 * 1024 {
            let mut buf = vec![0u8; content_length];
            reader.read_exact(&mut buf)?;
            body = String::from_utf8_lossy(&buf).into_owned();
        }

        Ok(Request {
            method,
            path,
            query,
            body,
            user,
        })
    }

    /// Look up a query-string parameter, percent-decoded (search text, IPv6
    /// addresses and bracketed client addresses all arrive encoded).
    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key {
                Some(percent_decode(v))
            } else {
                None
            }
        })
    }
}

/// Decode `%XX` escapes and `+` in a query-string value.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Apply the trust the kernel gives us about the caller. The socket is shared
/// by the root-run admin shims and the panel's per-account user CGIs, so who
/// is on the other end is decided by SO_PEERCRED, never by headers:
///
/// * uid 0 — the admin surface; `X-MSFE-User` is honoured (the WHM/DA shims
///   run as root and vouch for the panel session).
/// * any other uid — only the end-user page and `/api/user/*`, and the user
///   IS the account that uid belongs to, whatever the header said.
/// * unknown uid / undetermined — health only.
///
/// Returns the response to send instead when the request is refused.
pub fn peer_scope(
    req: &mut Request,
    peer_uid: Option<u32>,
    name_of: impl Fn(u32) -> Option<String>,
) -> Option<Response> {
    if peer_uid == Some(0) {
        return None;
    }
    if req.path == "/health" || req.path == "/api/health" {
        return None;
    }
    let user = peer_uid.and_then(&name_of);
    let user_route =
        req.path == "/user" || req.path == "/user/" || req.path.starts_with("/api/user/");
    match user {
        Some(u) if user_route => {
            req.user = u;
            None
        }
        _ => Some(Response::json(
            403,
            r#"{"error":"forbidden: not an admin connection"}"#,
        )),
    }
}

pub struct Response {
    pub status: u16,
    content_type: &'static str,
    body: String,
}

impl Response {
    pub fn html(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.to_string(),
        }
    }

    pub fn json(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "application/json",
            body: body.to_string(),
        }
    }

    pub fn text(status: u16, body: &str) -> Response {
        Response {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.to_string(),
        }
    }

    pub fn write<W: Write>(&self, mut stream: W) -> io::Result<()> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "OK",
        };
        let head = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Cache-Control: no-store\r\n\
             Connection: close\r\n\r\n",
            self.status,
            reason,
            self.content_type,
            self.body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(self.body.as_bytes())?;
        stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(query: &str) -> Request {
        Request {
            method: "GET".into(),
            path: "/x".into(),
            query: query.into(),
            body: String::new(),
            user: String::new(),
        }
    }

    fn path_req(method: &str, path: &str, user: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            body: String::new(),
            user: user.into(),
        }
    }

    fn name_of(uid: u32) -> Option<String> {
        (uid == 1001).then(|| "bob".to_string())
    }

    #[test]
    fn root_peer_keeps_admin_surface_and_header_user() {
        let mut r = path_req("GET", "/api/messages", "alice");
        assert!(peer_scope(&mut r, Some(0), name_of).is_none());
        assert_eq!(r.user, "alice");
    }

    #[test]
    fn unprivileged_peer_is_the_account_it_runs_as() {
        // the header is whatever the client chose to send — never trusted
        let mut r = path_req("GET", "/api/user/domains", "alice");
        assert!(peer_scope(&mut r, Some(1001), name_of).is_none());
        assert_eq!(r.user, "bob");
        let mut r = path_req("GET", "/user", "");
        assert!(peer_scope(&mut r, Some(1001), name_of).is_none());
        assert_eq!(r.user, "bob");
    }

    #[test]
    fn unprivileged_peer_cannot_reach_admin_routes() {
        for (m, p) in [
            ("GET", "/api/messages"),
            ("GET", "/"),
            ("GET", "/whm"),
            ("POST", "/api/config"),
            ("GET", "/api/userx"),
        ] {
            let mut r = path_req(m, p, "");
            let denied = peer_scope(&mut r, Some(1001), name_of).expect(p);
            assert_eq!(denied.status, 403, "{p}");
        }
    }

    #[test]
    fn unknown_or_undetermined_peer_gets_nothing_but_health() {
        let mut r = path_req("GET", "/health", "");
        assert!(peer_scope(&mut r, None, name_of).is_none());
        let mut r = path_req("GET", "/api/user/domains", "alice");
        assert_eq!(peer_scope(&mut r, None, name_of).unwrap().status, 403);
        // uid with no passwd entry
        let mut r = path_req("GET", "/api/user/domains", "alice");
        assert_eq!(peer_scope(&mut r, Some(4242), name_of).unwrap().status, 403);
    }

    #[test]
    fn decodes_query_values() {
        // the bracketed client address MailScanner records, URL-encoded
        assert_eq!(
            req("ip=%5B35.247.160.179%5D%3A45570")
                .query_param("ip")
                .unwrap(),
            "[35.247.160.179]:45570"
        );
        // search text with spaces and @
        assert_eq!(
            req("text=user%40example.com+test")
                .query_param("text")
                .unwrap(),
            "user@example.com test"
        );
        assert_eq!(req("days=30").query_param("days").unwrap(), "30");
        assert_eq!(req("a=1&b=2").query_param("b").unwrap(), "2");
        assert!(req("a=1").query_param("zz").is_none());
    }
}
