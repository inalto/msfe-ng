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

    /// Look up a query-string parameter (no percent-decoding needed for our
    /// numeric/identifier params).
    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            if k == key {
                Some(v.to_string())
            } else {
                None
            }
        })
    }
}

pub struct Response {
    status: u16,
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
