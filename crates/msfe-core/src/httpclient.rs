//! One HTTPS GET through the system `curl`, pinned to an address the caller
//! already vetted: no redirects, https only, a size cap, HTTP/1.1 (old curl
//! builds trip over some CDNs on HTTP/2). Used for MTA-STS policies and
//! the like — never for anything the report would act on blindly.

use crate::service::run_with_timeout;
use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResult {
    pub status: u16,
    pub body: String,
    /// The `Content-Type` header, lower-cased, when the server sent one.
    pub content_type: Option<String>,
}

/// Where curl must connect for `host:port` (SSRF guard: the caller resolved
/// and checked the address).
#[derive(Debug, Clone)]
pub struct Pin {
    pub host: String,
    pub port: u16,
    pub ip: IpAddr,
}

/// GET `url`, returning the status and body (≤ `max_bytes`), or why not.
pub fn get(
    url: &str,
    timeout: Duration,
    pin: Option<&Pin>,
    max_bytes: u64,
) -> Result<HttpResult, String> {
    if !url.starts_with("https://") {
        return Err("only https URLs are fetched".into());
    }
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "--http1.1",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--max-time",
        &timeout.as_secs().max(1).to_string(),
        "--max-filesize",
        &max_bytes.to_string(),
        "-A",
        "msfe-ng delivery test",
        "-D",
        "-", // headers on stdout, before the body
    ]);
    if let Some(p) = pin {
        cmd.arg("--resolve");
        cmd.arg(format!("{}:{}:{}", p.host, p.port, p.ip));
    }
    cmd.arg(url);
    let out = run_with_timeout(&mut cmd, timeout + Duration::from_secs(2))
        .map_err(|e| format!("cannot run curl: {e}"))?;
    if out.timed_out {
        return Err(format!("no reply within {} s", timeout.as_secs()));
    }
    if !out.ok {
        let msg = out
            .stderr
            .lines()
            .last()
            .unwrap_or("")
            .trim()
            .trim_start_matches("curl: ")
            .to_string();
        return Err(match out.code {
            Some(6) => format!("cannot resolve the host ({msg})"),
            Some(7) => format!("cannot connect ({msg})"),
            Some(28) => format!("timed out ({msg})"),
            Some(35) => format!("TLS handshake failed ({msg})"),
            Some(47) => "the server redirects (redirects are not followed)".into(),
            Some(60) => format!("the certificate is not trusted ({msg})"),
            Some(63) => format!("the document is larger than {max_bytes} bytes"),
            Some(c) => format!("curl exit {c}: {msg}"),
            None => format!("curl failed: {msg}"),
        });
    }
    parse_response(&out.stdout)
}

/// Split curl's `-D -` output (status line, headers, blank line, body).
pub fn parse_response(raw: &str) -> Result<HttpResult, String> {
    // curl may emit several header blocks (100 Continue); take the last
    let mut rest = raw;
    let mut content_type = None;
    let status;
    loop {
        let (head, body) = match rest
            .split_once("\r\n\r\n")
            .or_else(|| rest.split_once("\n\n"))
        {
            Some(x) => x,
            None => return Err("malformed HTTP response".into()),
        };
        let mut lines = head.lines();
        let first = lines.next().unwrap_or("");
        if !first.starts_with("HTTP/") {
            return Err(format!("malformed status line `{first}`"));
        }
        let code: u16 = first
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or("malformed status line")?;
        for l in lines {
            if let Some((k, v)) = l.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-type") {
                    content_type = Some(v.trim().to_ascii_lowercase());
                }
            }
        }
        rest = body;
        if code / 100 != 1 || !rest.starts_with("HTTP/") {
            status = code;
            break;
        }
    }
    Ok(HttpResult {
        status,
        body: rest.to_string(),
        content_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_curl_header_dumps() {
        let r = parse_response("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello").unwrap();
        assert_eq!(
            (r.status, r.body.as_str(), r.content_type.as_deref()),
            (200, "hello", Some("text/plain; charset=utf-8"))
        );
        let r = parse_response(
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nX: y\r\n\r\nnope\n",
        )
        .unwrap();
        assert_eq!((r.status, r.body.as_str()), (404, "nope\n"));
        assert!(parse_response("garbage").is_err());
        assert!(parse_response("HTTP/1.1 xx\r\n\r\n").is_err());
    }

    #[test]
    fn refuses_plain_http() {
        assert!(get("http://example.com/", Duration::from_secs(1), None, 100).is_err());
    }
}
