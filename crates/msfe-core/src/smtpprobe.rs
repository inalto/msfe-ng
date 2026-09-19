//! Talking SMTP to a mail server just enough to learn about it: connect,
//! read the banner, EHLO, note the capabilities, QUIT. Never MAIL FROM or
//! RCPT TO against a third party's server — the probe is a courtesy call,
//! not a delivery attempt. Also the small submission client the test-mail
//! feature uses against this server's own MTA.

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SmtpProbe {
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    pub connect_ms: u64,
    pub banner_ms: u64,
    pub banner: String,
    /// The name the server gave in its EHLO reply.
    pub ehlo_name: Option<String>,
    pub caps: Vec<String>,
    pub starttls: bool,
    pub size: Option<u64>,
    pub auth: Vec<String>,
    pub pipelining: bool,
    pub eightbit: bool,
    pub smtputf8: bool,
    pub enhanced_codes: bool,
    /// When AUTH was advertised on the clear-text connection: the reply code
    /// to a bare `AUTH PLAIN` (334 = accepted in clear, 5xx = refused).
    pub auth_clear: Option<u16>,
    pub transcript: String,
    pub error: Option<String>,
}

/// Read one SMTP reply (all `NNN-` lines up to the `NNN ` one) before `deadline`.
pub fn read_reply<R: BufRead>(r: &mut R, deadline: Instant) -> std::io::Result<(u16, Vec<String>)> {
    let mut lines = Vec::new();
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "reply timeout",
            ));
        }
        let mut line = String::new();
        let n = r.read_line(&mut line)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.len() < 3 || !line[..3].bytes().all(|b| b.is_ascii_digit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("not an SMTP reply: {line}"),
            ));
        }
        let code: u16 = line[..3].parse().unwrap_or(0);
        let last = line.len() == 3 || line.as_bytes()[3] == b' ';
        lines.push(line);
        if last {
            return Ok((code, lines));
        }
        if lines.len() > 100 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "reply too long",
            ));
        }
    }
}

/// Fill the capability fields from an EHLO reply.
pub fn parse_ehlo(lines: &[String], p: &mut SmtpProbe) {
    for (i, l) in lines.iter().enumerate() {
        let body = l.get(4..).unwrap_or("").trim();
        if i == 0 {
            p.ehlo_name = body
                .split_whitespace()
                .next()
                .map(|s| s.to_ascii_lowercase());
            continue;
        }
        let up = body.to_ascii_uppercase();
        p.caps.push(body.to_string());
        if up == "STARTTLS" {
            p.starttls = true;
        } else if let Some(s) = up.strip_prefix("SIZE") {
            p.size = s.trim().parse().ok();
        } else if let Some(a) = up.strip_prefix("AUTH") {
            p.auth = a
                .trim_start_matches('=')
                .split_whitespace()
                .map(str::to_string)
                .collect();
        } else if up == "PIPELINING" {
            p.pipelining = true;
        } else if up == "8BITMIME" {
            p.eightbit = true;
        } else if up == "SMTPUTF8" {
            p.smtputf8 = true;
        } else if up == "ENHANCEDSTATUSCODES" {
            p.enhanced_codes = true;
        }
    }
}

/// A read that ran out of time (`WouldBlock` is what a socket timeout gives on Linux).
fn timed_out(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// Banner → EHLO → QUIT against `ip:port`, introducing ourselves as `helo`.
/// `session` bounds the replies after the greeting; the greeting itself gets
/// `banner`, which should be generous: many MTAs deliberately delay it
/// (greet-pause) to shake off spam bots.
pub fn probe(
    ip: IpAddr,
    port: u16,
    host: &str,
    helo: &str,
    connect: Duration,
    banner: Duration,
    session: Duration,
) -> SmtpProbe {
    let mut p = SmtpProbe {
        host: host.to_string(),
        ip: Some(ip),
        port,
        ..Default::default()
    };
    let t0 = Instant::now();
    let addr = SocketAddr::new(ip, port);
    let stream = match TcpStream::connect_timeout(&addr, connect) {
        Ok(s) => s,
        Err(e) => {
            p.connect_ms = t0.elapsed().as_millis() as u64;
            p.error = Some(match e.kind() {
                std::io::ErrorKind::TimedOut => {
                    format!("connection timed out after {} s", connect.as_secs())
                }
                std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
                _ => format!("cannot connect: {e}"),
            });
            return p;
        }
    };
    p.connect_ms = t0.elapsed().as_millis() as u64;
    let _ = stream.set_read_timeout(Some(banner));
    let _ = stream.set_write_timeout(Some(session));
    let mut w = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            p.error = Some(format!("socket error: {e}"));
            return p;
        }
    };
    let mut r = BufReader::new(stream);
    let mut tr = String::new();
    match read_reply(&mut r, Instant::now() + banner) {
        Ok((code, lines)) => {
            p.banner_ms = t0.elapsed().as_millis() as u64;
            tr.push_str(&lines.join("\n"));
            tr.push('\n');
            p.banner = lines.join(" ");
            if code != 220 {
                p.error = Some(format!("greeting was {code}, not 220: {}", lines.join(" ")));
                p.transcript = tr;
                return p;
            }
        }
        Err(e) => {
            p.error = Some(if timed_out(&e) {
                format!("no greeting within {} s", banner.as_secs())
            } else {
                format!("no greeting: {e}")
            });
            p.transcript = tr;
            return p;
        }
    }
    let deadline = Instant::now() + session;
    let _ = r.get_ref().set_read_timeout(Some(session));
    let ehlo = format!("EHLO {helo}\r\n");
    tr.push_str(&format!("> EHLO {helo}\n"));
    if let Err(e) = w.write_all(ehlo.as_bytes()) {
        p.error = Some(format!("cannot send EHLO: {e}"));
        p.transcript = tr;
        return p;
    }
    match read_reply(&mut r, deadline) {
        Ok((250, lines)) => {
            tr.push_str(&lines.join("\n"));
            tr.push('\n');
            parse_ehlo(&lines, &mut p);
        }
        Ok((code, lines)) => {
            tr.push_str(&lines.join("\n"));
            tr.push('\n');
            // an old server: try HELO
            let _ = w.write_all(format!("HELO {helo}\r\n").as_bytes());
            tr.push_str(&format!("> HELO {helo}\n"));
            match read_reply(&mut r, deadline) {
                Ok((250, l2)) => {
                    tr.push_str(&l2.join("\n"));
                    tr.push('\n');
                    p.ehlo_name = l2
                        .first()
                        .and_then(|l| l.get(4..))
                        .and_then(|b| b.split_whitespace().next())
                        .map(|s| s.to_ascii_lowercase());
                    p.caps.push("(HELO only — no extensions)".into());
                }
                Ok((c2, l2)) => {
                    tr.push_str(&l2.join("\n"));
                    p.error = Some(format!("EHLO refused ({code}), HELO refused ({c2})"));
                }
                Err(e) => p.error = Some(format!("EHLO refused ({code}); HELO: {e}")),
            }
        }
        Err(e) => p.error = Some(format!("no EHLO reply: {e}")),
    }
    // AUTH advertised in clear: does the server really take it, or refuse
    // until TLS (538)? A bare AUTH PLAIN carries no credentials; a 334 is
    // cancelled with "*"
    if !p.auth.is_empty() && p.error.is_none() && w.write_all(b"AUTH PLAIN\r\n").is_ok() {
        tr.push_str("> AUTH PLAIN\n");
        if let Ok((code, lines)) = read_reply(&mut r, deadline) {
            tr.push_str(&lines.join("\n"));
            tr.push('\n');
            p.auth_clear = Some(code);
            if code == 334 {
                let _ = w.write_all(b"*\r\n");
                tr.push_str("> *\n");
                if let Ok((_, l2)) = read_reply(&mut r, deadline) {
                    tr.push_str(&l2.join("\n"));
                    tr.push('\n');
                }
            }
        }
    }
    let _ = w.write_all(b"QUIT\r\n");
    tr.push_str("> QUIT\n");
    if let Ok((_, lines)) = read_reply(&mut r, Instant::now() + Duration::from_secs(2)) {
        tr.push_str(&lines.join("\n"));
        tr.push('\n');
    }
    p.transcript = tr;
    p
}

/// Can this host reach port 25 of an external mail server? Connects to the
/// first address that answers, reads the banner, QUITs.
pub fn outbound_25_reachable(
    host: &str,
    ips: &[IpAddr],
    timeout: Duration,
) -> Result<(IpAddr, String), String> {
    let mut last = String::from("no address to try");
    for ip in ips {
        let p = probe(*ip, 25, host, "localhost", timeout, timeout, timeout);
        if p.error.is_none() || !p.banner.is_empty() {
            return Ok((*ip, p.banner));
        }
        last = p.error.unwrap_or_default();
    }
    Err(last)
}

/// Submit a message to a local MTA over plain SMTP (EHLO, MAIL, RCPT, DATA);
/// returns the queue reply (`250 OK id=…`).
pub fn submit_local(
    addr: &str,
    from: &str,
    to: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> std::io::Result<String> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let deadline = Instant::now() + Duration::from_secs(60);
    let expect = |r: &mut BufReader<TcpStream>, want: u16| -> std::io::Result<Vec<String>> {
        let (code, lines) = read_reply(r, deadline)?;
        if code / 100 != want / 100 {
            return Err(std::io::Error::other(format!(
                "expected {want}, got: {}",
                lines.join(" ")
            )));
        }
        Ok(lines)
    };
    expect(&mut r, 220)?;
    w.write_all(b"EHLO localhost\r\n")?;
    expect(&mut r, 250)?;
    w.write_all(format!("MAIL FROM:<{from}>\r\n").as_bytes())?;
    expect(&mut r, 250)?;
    w.write_all(format!("RCPT TO:<{to}>\r\n").as_bytes())?;
    expect(&mut r, 250)?;
    w.write_all(b"DATA\r\n")?;
    expect(&mut r, 354)?;
    let mut msg = String::new();
    for (k, v) in headers {
        msg.push_str(&format!("{k}: {v}\r\n"));
    }
    msg.push_str("\r\n");
    for line in body.lines() {
        if line.starts_with('.') {
            msg.push('.');
        }
        msg.push_str(line);
        msg.push_str("\r\n");
    }
    msg.push_str(".\r\n");
    w.write_all(msg.as_bytes())?;
    let queued = expect(&mut r, 250)?;
    let _ = w.write_all(b"QUIT\r\n");
    Ok(queued.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;

    #[test]
    fn replies_and_ehlo_parse() {
        let mut c = Cursor::new("220 mx.example ESMTP ready\r\n250-mx.example Hello\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250-ENHANCEDSTATUSCODES\r\n250 SMTPUTF8\r\n");
        let (code, lines) = read_reply(&mut c, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!((code, lines.len()), (220, 1));
        let (code, lines) = read_reply(&mut c, Instant::now() + Duration::from_secs(1)).unwrap();
        assert_eq!((code, lines.len()), (250, 8));
        let mut p = SmtpProbe::default();
        parse_ehlo(&lines, &mut p);
        assert_eq!(p.ehlo_name.as_deref(), Some("mx.example"));
        assert!(p.starttls && p.pipelining && p.eightbit && p.smtputf8 && p.enhanced_codes);
        assert_eq!(p.size, Some(52_428_800));
        assert_eq!(p.auth, vec!["PLAIN", "LOGIN"]);
        assert!(read_reply(
            &mut Cursor::new("garbage\r\n"),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
        assert!(read_reply(
            &mut Cursor::new(""),
            Instant::now() + Duration::from_secs(1)
        )
        .is_err());
    }

    fn fake_smtp(script: Vec<(&'static str, &'static str)>, greet: &'static str) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut w = s.try_clone().unwrap();
                let mut r = BufReader::new(s);
                let _ = w.write_all(greet.as_bytes());
                let mut line = String::new();
                let mut in_data = false;
                while r.read_line(&mut line).unwrap_or(0) > 0 {
                    let cmd = line.trim_end_matches("\r\n").to_ascii_uppercase();
                    if in_data && cmd != "." {
                        line.clear();
                        continue; // message text until the lone dot
                    }
                    let reply = script
                        .iter()
                        .find(|(k, _)| cmd.starts_with(k))
                        .map(|(_, v)| *v)
                        .unwrap_or("500 what\r\n");
                    let _ = w.write_all(reply.as_bytes());
                    in_data = cmd.starts_with("DATA") && reply.starts_with("354");
                    if cmd.starts_with("QUIT") {
                        break;
                    }
                    line.clear();
                }
            }
        });
        addr
    }

    #[test]
    fn probes_a_fake_server_and_handles_silence() {
        let addr = fake_smtp(
            vec![
                (
                    "EHLO",
                    "250-mx.test Hello\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 1000\r\n",
                ),
                ("AUTH", "538 Encryption required for requested authentication mechanism\r\n"),
                ("QUIT", "221 bye\r\n"),
            ],
            "220 mx.test ESMTP\r\n",
        );
        let p = probe(
            addr.ip(),
            addr.port(),
            "mx.test",
            "probe.local",
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        assert!(p.error.is_none(), "{:?}", p.error);
        assert_eq!(p.banner, "220 mx.test ESMTP");
        assert!(p.starttls);
        assert_eq!(p.size, Some(1000));
        assert_eq!(p.auth_clear, Some(538));
        assert!(p.transcript.contains("> EHLO probe.local") && p.transcript.contains("221 bye"));
        // HELO fallback
        let addr = fake_smtp(
            vec![
                ("EHLO", "502 no\r\n"),
                ("HELO", "250 old.test\r\n"),
                ("QUIT", "221\r\n"),
            ],
            "220 old.test\r\n",
        );
        let p = probe(
            addr.ip(),
            addr.port(),
            "old.test",
            "probe.local",
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        assert!(p.error.is_none());
        assert_eq!(p.ehlo_name.as_deref(), Some("old.test"));
        assert!(!p.starttls);
        // a 554 greeting
        let addr = fake_smtp(vec![], "554 go away\r\n");
        let p = probe(
            addr.ip(),
            addr.port(),
            "x",
            "probe.local",
            Duration::from_secs(2),
            Duration::from_secs(2),
            Duration::from_secs(2),
        );
        assert!(p.error.as_deref().unwrap().contains("554"));
        // silent server: the session timeout cuts it
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let silent = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let _keep: Vec<_> = l.incoming().take(1).flatten().collect();
            std::thread::sleep(Duration::from_secs(5));
        });
        let t0 = Instant::now();
        let p = probe(
            silent.ip(),
            silent.port(),
            "s",
            "probe.local",
            Duration::from_secs(2),
            Duration::from_millis(400),
            Duration::from_secs(2),
        );
        assert_eq!(p.error.as_deref(), Some("no greeting within 0 s"));
        assert!(t0.elapsed() < Duration::from_secs(2));
        // refused
        let p = probe(
            "127.0.0.1".parse().unwrap(),
            1,
            "r",
            "probe.local",
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        );
        assert!(p.error.as_deref().unwrap().contains("refused"));
    }

    #[test]
    fn submits_to_a_fake_mta() {
        let addr = fake_smtp(
            vec![
                ("EHLO", "250 mta\r\n"),
                ("MAIL", "250 ok\r\n"),
                ("RCPT", "250 ok\r\n"),
                ("DATA", "354 go\r\n"),
                (".", "250 OK id=1abc-2\r\n"),
                ("QUIT", "221\r\n"),
            ],
            "220 mta\r\n",
        );
        let r = submit_local(
            &addr.to_string(),
            "a@x.test",
            "b@y.test",
            &[("Subject", "hi")],
            "body\n.leading dot\n",
        )
        .unwrap();
        assert!(r.contains("id=1abc-2"), "{r}");
    }
}
