//! Minimal HTTP/1.1 request reader and response writer over a stream.
//!
//! Deliberately tiny: enough to route the placeholder UI in M0. Not a general
//! HTTP server — no keep-alive, no chunked encoding. Replaced by a real router
//! crate in a later milestone.

use std::io::{self, BufRead, BufReader, Read, Write};

pub struct Request {
    /// Reserved for M1 routing (POST form handling from the panel shims).
    #[allow(dead_code)]
    pub method: String,
    pub path: String,
}

impl Request {
    /// Read just the request line + headers; the body (if any) is ignored in M0.
    pub fn read<R: Read>(stream: R) -> io::Result<Request> {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line)?;

        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let raw_path = parts.next().unwrap_or("/").to_string();
        // Strip any query string; routing in M0 is path-only.
        let path = raw_path.split('?').next().unwrap_or("/").to_string();

        // Drain headers up to the blank line so the socket is left clean.
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
        }

        Ok(Request { method, path })
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
