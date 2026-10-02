//! The only outbound path of the OSINT feature. Origins are compiled in by the
//! caller (`Request.host`); every destination IP is checked with
//! `outbound_allowed(ip, false)` and pinned; HTTPS only; no redirects; the
//! credential travels on curl's stdin, never in argv; the response is read
//! through a bounded reader so a hostile or broken server cannot make the
//! daemon buffer an unbounded body.

use crate::netguard;
use crate::service;
use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

const HEAD_ALLOWANCE: usize = 16 * 1024;
const STDERR_CAP: usize = 4 * 1024;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const UA: &str = "msfe-ng osint";
/// Trailer written by curl (`-w`) after the body; its last occurrence is the
/// connected address.
const IP_MARKER: &str = "\n--msfe-remote-ip:";

/// One outbound request. `path` begins with `/` and is already
/// percent-encoded (use [`pct_encode`] for dynamic segments).
#[derive(Debug, Clone)]
pub struct Request {
    pub provider: &'static str,
    pub host: String,
    pub path: String,
    pub query: Vec<(&'static str, String)>,
    pub headers: Vec<(&'static str, String)>,
    pub timeout: Duration,
    pub max_body: usize,
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub retry_after: Option<u64>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HttpError {
    Blocked(String),
    Resolve(String),
    Timeout,
    TooLarge,
    Tls(String),
    Refused(String),
    Other(String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Blocked(s) => write!(f, "destination blocked: {s}"),
            HttpError::Resolve(s) => write!(f, "name resolution failed: {s}"),
            HttpError::Timeout => write!(f, "request timed out"),
            HttpError::TooLarge => write!(f, "response too large"),
            HttpError::Tls(s) => write!(f, "TLS/connection error: {s}"),
            HttpError::Refused(s) => write!(f, "request refused: {s}"),
            HttpError::Other(s) => write!(f, "request failed: {s}"),
        }
    }
}

pub fn pct_encode(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Quoted curl-config value. Control characters are refused by the caller
/// (curl would turn an escaped `\n` back into a real newline).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn has_control(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

pub fn config_doc(url: &str, headers: &[(&'static str, String)]) -> Result<String, HttpError> {
    if has_control(url) {
        return Err(HttpError::Refused(
            "control character in the request URL".into(),
        ));
    }
    let mut s = format!("url = \"{}\"\n", esc(url));
    for (k, v) in headers {
        if has_control(k) || has_control(v) {
            return Err(HttpError::Refused(
                "control character in a request header".into(),
            ));
        }
        s.push_str(&format!("header = \"{}: {}\"\n", esc(k), esc(v)));
    }
    Ok(s)
}

pub fn curl_args(
    timeout_secs: u64,
    max_body: usize,
    pin: Option<&str>,
    allow_http: bool,
) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-q".into(), // first: ignore any curlrc
        "-sS".into(),
        "-g".into(), // --globoff: {} and [] never expand into several requests
        "--http1.1".into(),
        "--proto".into(),
        if allow_http {
            "=http".into()
        } else {
            "=https".into()
        },
        "--max-redirs".into(),
        "0".into(),
        "--noproxy".into(),
        "*".into(),
        "--max-time".into(),
        timeout_secs.max(1).to_string(),
        "--max-filesize".into(),
        max_body.saturating_add(1).to_string(),
        "-A".into(),
        UA.into(),
        "-D".into(),
        "-".into(),
        "-w".into(),
        format!("{IP_MARKER}%{{remote_ip}}"),
        "--config".into(),
        "-".into(),
    ];
    if let Some(p) = pin {
        a.push("--resolve".into());
        a.push(p.into());
    }
    a
}

/// Parse the response head dumped by `-D -`: returns the final status, the
/// headers (names lower-cased) and the offset of the body. Interim 1xx heads
/// are skipped.
type Head = (u16, Vec<(String, String)>, usize);

pub fn parse_head(raw: &[u8]) -> Result<Head, String> {
    let mut pos = 0usize;
    loop {
        let rest = &raw[pos..];
        let end = rest
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "incomplete response head".to_string())?;
        let head = String::from_utf8_lossy(&rest[..end]).into_owned();
        let next = pos + end + 4;
        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or("");
        let status: u16 = first
            .split_whitespace()
            .nth(1)
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| "malformed status line".to_string())?;
        if (100..200).contains(&status) {
            pos = next;
            continue;
        }
        let headers = lines
            .filter_map(|l| {
                l.split_once(':')
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            })
            .collect();
        return Ok((status, headers, next));
    }
}

pub fn parse_retry_after(s: &str) -> Option<u64> {
    s.trim().parse::<u64>().ok().map(|n| n.min(86_400))
}

/// Remove secrets and any URL (which can carry an address in its path) from
/// text that may leave this module.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut t = text.to_string();
    for s in secrets {
        if !s.is_empty() {
            t = t.replace(s, "***");
        }
    }
    let lower = t.to_ascii_lowercase();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < t.len() {
        let rest = &lower[i..];
        if rest.starts_with("https://") || rest.starts_with("http://") {
            let stop = rest.find(char::is_whitespace).unwrap_or(rest.len());
            out.push_str("<url>");
            i += stop;
        } else {
            let c = t[i..].chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

/// `MSFE_NG_OSINT_BASE_<PROVIDER>`: test stand-in, honoured only for exactly
/// `http://127.0.0.1:<digits>`.
fn override_base(provider: &str) -> Option<String> {
    let v = std::env::var(format!(
        "MSFE_NG_OSINT_BASE_{}",
        provider.to_ascii_uppercase()
    ))
    .ok()?;
    let port = v.strip_prefix("http://127.0.0.1:")?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(v)
}

/// The first candidate that may be contacted. Never allows loopback, private,
/// link-local or this server's own addresses.
fn choose_address(candidates: &[IpAddr]) -> Result<IpAddr, HttpError> {
    let mut last = "no address".to_string();
    for ip in candidates {
        match netguard::outbound_allowed(*ip, false) {
            Ok(()) => return Ok(*ip),
            Err(why) => last = why,
        }
    }
    Err(HttpError::Blocked(last))
}

/// Split curl's `-w` trailer off the captured stdout: the last marker is the
/// trailer, so a body containing the marker text cannot spoof the address.
fn split_remote_ip(raw: &[u8]) -> Option<(&[u8], String)> {
    let m = IP_MARKER.as_bytes();
    let pos = raw.windows(m.len()).rposition(|w| w == m)?;
    let ip = String::from_utf8_lossy(&raw[pos + m.len()..])
        .trim()
        .to_string();
    Some((&raw[..pos], ip))
}

/// The connection must have gone to the address that passed the guard.
fn check_pin(chosen: Option<IpAddr>, remote: &str) -> Result<(), HttpError> {
    let Some(want) = chosen else { return Ok(()) };
    match remote.parse::<IpAddr>() {
        Ok(got) if got == want => Ok(()),
        _ => Err(HttpError::Blocked(
            "connected to an address other than the checked one".into(),
        )),
    }
}

/// Errors that take precedence once curl is gone: overflow, then deadline,
/// then a stdout reader that never reached EOF (a truncated body must not
/// pass for a complete one).
fn reader_outcome(overflow: bool, timed_out: bool, eof: bool) -> Result<(), HttpError> {
    if overflow {
        Err(HttpError::TooLarge)
    } else if timed_out {
        Err(HttpError::Timeout)
    } else if !eof {
        Err(HttpError::Other("response read incomplete".into()))
    } else {
        Ok(())
    }
}

fn path_allowed(path: &str) -> bool {
    path.starts_with('/')
        && path.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'%' | b'/')
        })
}

fn resolve(host: String) -> Result<Vec<IpAddr>, HttpError> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let r = (host.as_str(), 443u16)
            .to_socket_addrs()
            .map(|it| it.map(|a| a.ip()).collect::<Vec<_>>())
            .map_err(|e| e.to_string());
        let _ = tx.send(r);
    });
    match rx.recv_timeout(RESOLVE_TIMEOUT) {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(HttpError::Resolve(redact(&e, &[]))),
        Err(_) => Err(HttpError::Resolve("lookup timed out".into())),
    }
}

fn run_hash(tool: &str, data: &[u8], len: usize) -> Result<String, String> {
    let out = service::run_with_stdin(&mut Command::new(tool), data, Duration::from_secs(5))
        .map_err(|e| format!("{tool}: {e}"))?;
    if !out.ok {
        return Err(format!("{tool} failed"));
    }
    let tok = out.stdout.split_whitespace().next().unwrap_or("");
    if tok.len() != len || !tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{tool}: unexpected output"));
    }
    Ok(tok.to_string())
}

pub fn sha256_hex(data: &[u8]) -> Result<String, String> {
    run_hash("sha256sum", data, 64).map(|s| s.to_ascii_lowercase())
}

pub fn sha1_hex_upper(data: &[u8]) -> Result<String, String> {
    run_hash("sha1sum", data, 40).map(|s| s.to_ascii_uppercase())
}

fn kill_group(child: &mut std::process::Child) {
    // negative pid = the whole process group (see service::run_with_input)
    let _ = Command::new("kill")
        .args(["-9", "--", &format!("-{}", child.id())])
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

/// Strict public DNS name check for hosts discovered at run time (RDAP
/// bootstrap). Lower-case ASCII letters, digits, `-` and `.` only; at least
/// two labels; the last label starts with a letter, which rules out every
/// numeric IPv4 form (`1.2.3.4`, `127.1`, `0x7f.1`); no `localhost`.
pub fn valid_public_hostname(h: &str) -> bool {
    if h.len() < 3 || h.len() > 253 || !h.contains('.') {
        return false;
    }
    if !h
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return false;
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels
        .iter()
        .any(|l| l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-'))
    {
        return false;
    }
    let last = labels[labels.len() - 1];
    if !last.as_bytes()[0].is_ascii_lowercase() {
        return false;
    }
    !(h == "localhost" || h.ends_with(".localhost"))
}

pub fn fetch(req: &Request) -> Result<Response, HttpError> {
    if !valid_public_hostname(&req.host) {
        return Err(HttpError::Refused("invalid host".into()));
    }
    if !path_allowed(&req.path) {
        return Err(HttpError::Refused(
            "request path must start with / and hold only unreserved characters, % and /".into(),
        ));
    }
    // A bootstrap-chosen registry host must never carry a credential.
    if req.provider.starts_with("rdap")
        && req
            .headers
            .iter()
            .any(|(k, _)| !k.eq_ignore_ascii_case("accept"))
    {
        return Err(HttpError::Refused(
            "RDAP requests may carry only an Accept header".into(),
        ));
    }
    let mut query = String::new();
    for (k, v) in &req.query {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str(&pct_encode(k));
        query.push('=');
        query.push_str(&pct_encode(v));
    }
    let over = override_base(req.provider);
    let origin = match &over {
        Some(b) => b.clone(),
        None => format!("https://{}", req.host),
    };
    let mut url = format!("{origin}{}", req.path);
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query);
    }
    // refuses control characters before anything starts
    let doc = config_doc(&url, &req.headers)?;
    let secrets: Vec<&str> = req.headers.iter().map(|(_, v)| v.as_str()).collect();

    let chosen = if over.is_some() {
        None
    } else {
        Some(choose_address(&resolve(req.host.clone())?)?)
    };
    let pin = chosen.map(|ip| format!("{}:443:{ip}", req.host));
    let args = curl_args(
        req.timeout.as_secs().max(1),
        req.max_body,
        pin.as_deref(),
        over.is_some(),
    );
    let mut child = Command::new("curl")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| HttpError::Other(format!("cannot start curl: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        // on a thread: a curl that never reads must not block us
        std::thread::spawn(move || {
            let _ = stdin.write_all(doc.as_bytes());
        });
    }

    let cap = req
        .max_body
        .saturating_add(HEAD_ALLOWANCE)
        .saturating_add(1);
    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let overflow = Arc::new(AtomicBool::new(false));
    let out_eof = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    if let Some(mut p) = child.stdout.take() {
        let (buf, flag, eof, tx) = (
            Arc::clone(&out_buf),
            Arc::clone(&overflow),
            Arc::clone(&out_eof),
            done_tx.clone(),
        );
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match p.read(&mut chunk) {
                    Ok(0) => {
                        eof.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(_) => break,
                    Ok(n) => {
                        let mut b = buf.lock().unwrap();
                        let room = cap.saturating_sub(b.len());
                        if n > room {
                            b.extend_from_slice(&chunk[..room]);
                            flag.store(true, Ordering::SeqCst);
                            break;
                        }
                        b.extend_from_slice(&chunk[..n]);
                    }
                }
            }
            let _ = tx.send(());
        });
    }
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    if let Some(mut p) = child.stderr.take() {
        let (buf, tx) = (Arc::clone(&err_buf), done_tx.clone());
        std::thread::spawn(move || {
            let mut chunk = [0u8; 1024];
            loop {
                match p.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut b = buf.lock().unwrap();
                        let room = STDERR_CAP.saturating_sub(b.len());
                        b.extend_from_slice(&chunk[..n.min(room)]);
                        // keep draining so curl never blocks, but keep no more
                    }
                }
            }
            let _ = tx.send(());
        });
    }
    drop(done_tx);

    let deadline = Instant::now() + req.timeout + Duration::from_secs(2);
    let mut timed_out = false;
    let mut cut = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(e) => {
                kill_group(&mut child);
                return Err(HttpError::Other(format!("wait failed: {e}")));
            }
        }
        if overflow.load(Ordering::SeqCst) {
            cut = true;
            kill_group(&mut child);
            break None;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill_group(&mut child);
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // bounded grace for both readers to hit EOF
    let grace = Instant::now() + Duration::from_millis(500);
    for _ in 0..2 {
        let left = grace.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    // the stdout reader's EOF can trail curl's exit under load: give it a
    // bounded extra moment before calling the read incomplete
    let eof_by = Instant::now() + Duration::from_millis(500);
    while !out_eof.load(Ordering::SeqCst)
        && !overflow.load(Ordering::SeqCst)
        && Instant::now() < eof_by
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    let ov = cut || overflow.load(Ordering::SeqCst);
    if ov || timed_out {
        reader_outcome(ov, timed_out, true)?;
    }
    let status = status.ok_or_else(|| HttpError::Other("curl did not finish".into()))?;
    let stderr_text = {
        let raw = err_buf.lock().unwrap().clone();
        let t: String = String::from_utf8_lossy(&raw)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        redact(t.trim(), &secrets)
    };
    if !status.success() {
        return Err(match status.code() {
            Some(63) => HttpError::TooLarge,
            Some(28) => HttpError::Timeout,
            Some(35 | 51 | 58 | 59 | 60 | 77 | 83) => HttpError::Tls(stderr_text),
            Some(6) => HttpError::Resolve(stderr_text),
            _ => HttpError::Other(stderr_text),
        });
    }
    reader_outcome(false, false, out_eof.load(Ordering::SeqCst))?;
    let all = out_buf.lock().unwrap().clone();
    let (raw, remote_ip) =
        split_remote_ip(&all).ok_or_else(|| HttpError::Other("response read incomplete".into()))?;
    check_pin(chosen, &remote_ip)?;
    let (st, headers, off) = parse_head(raw).map_err(HttpError::Other)?;
    let body = raw[off..].to_vec();
    if body.len() > req.max_body {
        return Err(HttpError::TooLarge);
    }
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    Ok(Response {
        status: st,
        retry_after: get("retry-after").and_then(|v| parse_retry_after(&v)),
        content_type: get("content-type").map(|v| v.to_ascii_lowercase()),
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn curl_available() -> bool {
        Command::new("curl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// One-shot HTTP stand-in: serves `reply` (raw bytes) to the first
    /// connection and returns the request head it received.
    fn serve(reply: Vec<u8>) -> (u16, std::thread::JoinHandle<String>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 8192];
            let mut head = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..n]);
                if head.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = s.write_all(&reply);
            String::from_utf8_lossy(&head).into_owned()
        });
        (port, h)
    }

    fn req(provider: &'static str, path: &str) -> Request {
        Request {
            provider,
            host: "haveibeenpwned.com".to_string(),
            path: path.into(),
            query: vec![],
            headers: vec![("hibp-api-key", "SECRETKEY123".into())],
            timeout: Duration::from_secs(10),
            max_body: 64 * 1024,
        }
    }

    #[test]
    fn hostname_validation_accepts_public_names_only() {
        for ok in [
            "rdap.verisign.com",
            "a-b.example.org",
            "xn--p1ai.example.com",
            "a1.b2.io",
        ] {
            assert!(valid_public_hostname(ok), "{ok}");
        }
        let long_name = format!("{}.com", "a.".repeat(125));
        let long_label = format!("{}.com", "a".repeat(64));
        let bad = [
            "",
            "localhost",
            "LOCALHOST.com",
            "Example.org",
            "1.2.3.4",
            "[::1]",
            "a b.com",
            "a..b.com",
            "-a.com",
            "a-.com",
            "host:8080",
            "host.com.",
            "host.com/path",
            "x",
            "127.1",
            "0x7f.1",
            "0x7f.0x1",
            "a.0x7f",
            "2130706433",
            "999.999.999.999",
            ".example.com",
            "..",
            "a.localhost",
            "host.com@evil.com",
            "exämple.com",
            "ex_ample.com",
            "a.b.c.1",
            &long_name,
            &long_label,
        ];
        assert_eq!(long_name.len(), 254);
        for b in bad {
            assert!(!valid_public_hostname(b), "{b:?}");
        }
    }

    #[test]
    fn fetch_refuses_invalid_hosts_even_with_override() {
        let mut r = req("hibp", "/x");
        r.host = "127.0.0.1".into();
        assert!(matches!(fetch(&r), Err(HttpError::Refused(_))));
        r.host = "localhost".into();
        assert!(matches!(fetch(&r), Err(HttpError::Refused(_))));
    }

    #[test]
    fn rdap_requests_refuse_any_header_but_accept() {
        let mut r = req("rdap_registry", "/x");
        r.host = "rdap.example.net".into();
        r.headers = vec![("authorization", "Bearer secret".to_string())];
        assert!(matches!(fetch(&r), Err(HttpError::Refused(_))));
        r.provider = "rdap-bootstrap";
        r.headers = vec![
            ("accept", "application/json".to_string()),
            ("X-Key", "k".into()),
        ];
        assert!(matches!(fetch(&r), Err(HttpError::Refused(_))));
    }

    #[test]
    fn pct_encode_keeps_unreserved_and_encodes_the_rest() {
        assert_eq!(pct_encode("a-b_c.d~E9"), "a-b_c.d~E9");
        assert_eq!(pct_encode("a+b@x.org"), "a%2Bb%40x.org");
        assert_eq!(pct_encode("a/b?c#d%e f"), "a%2Fb%3Fc%23d%25e%20f");
    }

    #[test]
    fn config_doc_rejects_control_characters_in_values() {
        for bad in ["a\nb", "a\rb", "a\x00b", "a\x7fb", "a\tb"] {
            let r = config_doc("https://x.example/", &[("hibp-api-key", bad.to_string())]);
            assert!(r.is_err(), "{bad:?}");
        }
        let ok = config_doc(
            "https://x.example/p",
            &[("hibp-api-key", "ab\"cd\\ef".to_string())],
        )
        .unwrap();
        assert!(ok.contains("url = \"https://x.example/p\""));
        assert!(ok.contains("header = \"hibp-api-key: ab\\\"cd\\\\ef\""));
    }

    #[test]
    fn curl_args_never_carry_the_secret_and_pin_the_address() {
        let a = curl_args(10, 65536, Some("haveibeenpwned.com:443:203.0.113.9"), false);
        let joined = a.join(" ");
        assert!(!joined.contains("SECRETKEY123"));
        assert_eq!(a[0], "-q", "curlrc must be disabled first");
        assert!(
            joined.contains("--proto =https")
                || (a.contains(&"--proto".to_string()) && a.contains(&"=https".to_string()))
        );
        assert!(a.contains(&"--max-redirs".to_string()) && a.contains(&"0".to_string()));
        assert!(a.contains(&"--noproxy".to_string()));
        assert!(
            joined.contains("--resolve haveibeenpwned.com:443:203.0.113.9")
                || a.windows(2)
                    .any(|w| w[0] == "--resolve" && w[1] == "haveibeenpwned.com:443:203.0.113.9")
        );
        assert!(a.contains(&"--config".to_string()));
    }

    #[test]
    fn parse_head_reads_status_headers_and_skips_100_continue() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Type: Application/JSON\r\n\r\nBODY";
        let (st, h, off) = parse_head(raw).unwrap();
        assert_eq!(st, 429);
        assert!(h.iter().any(|(k, v)| k == "retry-after" && v == "17"));
        assert_eq!(&raw[off..], b"BODY");
        assert!(parse_head(b"garbage").is_err());
    }

    #[test]
    fn retry_after_accepts_seconds_and_ignores_garbage() {
        assert_eq!(parse_retry_after("17"), Some(17));
        assert_eq!(parse_retry_after(" 3 "), Some(3));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-5"), None);
        assert_eq!(parse_retry_after("99999999999999999999"), None);
    }

    #[test]
    fn redact_removes_secrets_and_full_address_paths() {
        let t = "curl: (22) https://h/api/v3/breachedaccount/a%40b.org?x=1 key SECRETKEY123 failed";
        let r = redact(t, &["SECRETKEY123"]);
        assert!(!r.contains("SECRETKEY123"));
        assert!(!r.contains("a%40b.org"));
        assert!(!r.contains("?x=1"));
    }

    #[test]
    fn hashes_match_known_vectors() {
        if Command::new("sha256sum").arg("--version").output().is_err() {
            return;
        }
        assert_eq!(
            sha256_hex(b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha1_hex_upper(b"abc").unwrap(),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
    }

    #[test]
    fn end_to_end_sends_the_key_header_and_returns_status_and_body() {
        if !curl_available() {
            return;
        }
        let (port, h) = serve(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n[]".to_vec());
        std::env::set_var("MSFE_NG_OSINT_BASE_T1", format!("http://127.0.0.1:{port}"));
        let r = fetch(&Request {
            provider: "t1",
            ..req("t1", "/api/v3/x")
        })
        .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"[]");
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        let head = h.join().unwrap().to_ascii_lowercase();
        assert!(head.contains("hibp-api-key: secretkey123"));
        assert!(head.contains("user-agent: msfe-ng"));
    }

    #[test]
    fn rate_limit_status_and_retry_after_are_returned() {
        if !curl_available() {
            return;
        }
        let (port, _h) = serve(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 9\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec());
        std::env::set_var("MSFE_NG_OSINT_BASE_T2", format!("http://127.0.0.1:{port}"));
        let r = fetch(&Request {
            provider: "t2",
            ..req("t2", "/x")
        })
        .unwrap();
        assert_eq!(r.status, 429);
        assert_eq!(r.retry_after, Some(9));
    }

    #[test]
    fn oversized_chunked_body_is_cut_at_the_cap() {
        if !curl_available() {
            return;
        }
        let mut reply =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..40 {
            reply.extend_from_slice(b"1000\r\n");
            reply.extend_from_slice(&[b'x'; 0x1000]);
            reply.extend_from_slice(b"\r\n");
        }
        reply.extend_from_slice(b"0\r\n\r\n");
        let (port, _h) = serve(reply);
        std::env::set_var("MSFE_NG_OSINT_BASE_T3", format!("http://127.0.0.1:{port}"));
        let e = fetch(&Request {
            provider: "t3",
            max_body: 8 * 1024,
            ..req("t3", "/x")
        })
        .unwrap_err();
        assert_eq!(e, HttpError::TooLarge);
    }

    #[test]
    fn a_non_loopback_override_is_ignored() {
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "http://203.0.113.9:80");
        assert!(override_base("t4").is_none());
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "https://127.0.0.1:1");
        assert!(override_base("t4").is_none());
        std::env::set_var("MSFE_NG_OSINT_BASE_T4", "http://127.0.0.1:8080");
        assert_eq!(
            override_base("t4").as_deref(),
            Some("http://127.0.0.1:8080")
        );
    }

    #[test]
    fn header_injection_in_a_secret_is_refused_before_any_process_starts() {
        let mut r = req("t5", "/x");
        r.headers = vec![("hibp-api-key", "k\r\nX-Evil: 1".into())];
        match fetch(&r) {
            Err(HttpError::Refused(_)) => {}
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn choose_address_rejects_non_public_and_picks_the_first_public() {
        let bad: Vec<IpAddr> = [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.5",
            "169.254.1.1",
            "::1",
            "fe80::1",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert!(matches!(choose_address(&bad), Err(HttpError::Blocked(_))));
        assert!(matches!(choose_address(&[]), Err(HttpError::Blocked(_))));
        let own = netguard::own_addresses();
        if !own.is_empty() {
            assert!(matches!(choose_address(&own), Err(HttpError::Blocked(_))));
        }
        let mut mixed = bad.clone();
        mixed.push("8.8.8.8".parse().unwrap());
        mixed.push("1.1.1.1".parse().unwrap());
        assert_eq!(
            choose_address(&mixed).unwrap(),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn error_strings_never_carry_urls_or_secrets() {
        let e = HttpError::Other(redact(
            "fail https://h/p?q=1 SECRETKEY123",
            &["SECRETKEY123"],
        ));
        let s = e.to_string();
        assert!(!s.contains("SECRETKEY123") && !s.contains("?q=1"));
    }

    /// Manual check (see the task report): run against a slow stand-in on
    /// `MSFE_NG_OSINT_BASE_T9` and watch the process list meanwhile.
    #[test]
    #[ignore]
    fn manual_slow_fetch_for_process_list_check() {
        let r = fetch(&Request {
            provider: "t9",
            ..req("t9", "/slow")
        })
        .unwrap();
        assert_eq!(r.status, 200);
    }

    #[test]
    fn trailer_is_split_exactly_and_cannot_be_spoofed_by_the_body() {
        let (b, ip) =
            split_remote_ip(b"HEAD\r\n\r\nbody\n\n\n--msfe-remote-ip:203.0.113.9").unwrap();
        assert_eq!(b, b"HEAD\r\n\r\nbody\n\n");
        assert_eq!(ip, "203.0.113.9");
        let (b, ip) =
            split_remote_ip(b"x\n--msfe-remote-ip:6.6.6.6 more\n--msfe-remote-ip:1.2.3.4").unwrap();
        assert_eq!(ip, "1.2.3.4");
        assert!(b.ends_with(b"more"));
        assert!(split_remote_ip(b"no trailer").is_none());
    }

    #[test]
    fn a_connection_to_another_address_is_blocked() {
        let want: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(check_pin(Some(want), "8.8.8.8").is_ok());
        assert!(matches!(
            check_pin(Some(want), "9.9.9.9"),
            Err(HttpError::Blocked(_))
        ));
        assert!(matches!(
            check_pin(Some(want), ""),
            Err(HttpError::Blocked(_))
        ));
        assert!(check_pin(None, "127.0.0.1").is_ok());
    }

    #[test]
    fn an_unfinished_reader_is_an_incomplete_read_not_a_body() {
        assert_eq!(reader_outcome(true, true, false), Err(HttpError::TooLarge));
        assert_eq!(reader_outcome(false, true, false), Err(HttpError::Timeout));
        assert_eq!(
            reader_outcome(false, false, false),
            Err(HttpError::Other("response read incomplete".into()))
        );
        assert!(reader_outcome(false, false, true).is_ok());
    }

    #[test]
    fn paths_outside_the_safe_set_are_refused_and_globbing_is_off() {
        assert!(curl_args(10, 1, None, false).contains(&"-g".to_string()));
        for bad in [
            "x", "/a{b,c}", "/a[1-3]", "/a b", "/a?x=1", "/a\n", "/a#f", "/a\\b",
        ] {
            let mut r = req("t6", bad);
            r.path = bad.into();
            assert!(matches!(fetch(&r), Err(HttpError::Refused(_))), "{bad:?}");
        }
        assert!(path_allowed("/api/v3/breachedaccount/a%40b.org"));
    }

    #[test]
    fn a_body_ending_in_newlines_survives_the_trailer() {
        if !curl_available() {
            return;
        }
        let (port, _h) = serve(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nab\n\n\n".to_vec(),
        );
        std::env::set_var("MSFE_NG_OSINT_BASE_T7", format!("http://127.0.0.1:{port}"));
        let r = fetch(&Request {
            provider: "t7",
            ..req("t7", "/x")
        })
        .unwrap();
        assert_eq!(r.body, b"ab\n\n\n");
    }
}
