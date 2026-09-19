//! A small DNS client for the delivery test: builds queries with EDNS0 (and
//! the DO bit, so a validating resolver reports AD), parses answers with
//! name decompression and TTLs for the record types the checks need, retries
//! over UDP and falls back to TCP on a truncated reply, and caches answers
//! for the life of a `Client` (one run).
//!
//! It asks the system resolver (`/etc/resolv.conf`, `MSFE_NG_RESOLVER`
//! overrides as `host[:port]`) with recursion desired, or a nameserver
//! directly without it when the checks want an authoritative view.

use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Soa = 6,
    Ptr = 12,
    Mx = 15,
    Txt = 16,
    Aaaa = 28,
    Ds = 43,
    Tlsa = 52,
    Caa = 257,
}

impl RType {
    pub fn code(&self) -> u16 {
        *self as u16
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            RType::A => "A",
            RType::Ns => "NS",
            RType::Cname => "CNAME",
            RType::Soa => "SOA",
            RType::Ptr => "PTR",
            RType::Mx => "MX",
            RType::Txt => "TXT",
            RType::Aaaa => "AAAA",
            RType::Ds => "DS",
            RType::Tlsa => "TLSA",
            RType::Caa => "CAA",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(String),
    Cname(String),
    Ptr(String),
    Mx {
        pref: u16,
        host: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// The character-strings of one TXT record, in order (joined = the value).
    Txt(Vec<String>),
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: Vec<u8>,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    Other(u16, Vec<u8>),
}

impl RData {
    /// Zone-file style presentation, for evidence.
    pub fn present(&self) -> String {
        match self {
            RData::A(a) => a.to_string(),
            RData::Aaaa(a) => a.to_string(),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => format!("{n}."),
            RData::Mx { pref, host } => format!("{pref} {host}."),
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname}. {rname}. {serial} {refresh} {retry} {expire} {minimum}"),
            RData::Txt(parts) => parts
                .iter()
                .map(|p| format!("\"{}\"", p.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(" "),
            RData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => format!("{key_tag} {algorithm} {digest_type} {}", hex(digest)),
            RData::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => format!("{usage} {selector} {matching} {}", hex(data)),
            RData::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            RData::Other(t, d) => format!("TYPE{t} \\# {} {}", d.len(), hex(d)),
        }
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

impl Rr {
    pub fn present(&self) -> String {
        let t = match self.rtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            43 => "DS",
            46 => "RRSIG",
            52 => "TLSA",
            257 => "CAA",
            _ => "TYPE",
        };
        format!(
            "{}. {} IN {} {}",
            self.name,
            self.ttl,
            t,
            self.data.present()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub rcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub ad: bool,
    pub answers: Vec<Rr>,
    pub authority: Vec<Rr>,
    pub additional: Vec<Rr>,
    pub server: String,
    pub elapsed_ms: u64,
}

impl Response {
    pub fn rcode_name(&self) -> &'static str {
        rcode_name(self.rcode)
    }
    pub fn nxdomain(&self) -> bool {
        self.rcode == 3
    }
    /// Answer records of the queried type (CNAME chains are followed by the
    /// resolver; the answer section then holds both).
    pub fn of(&self, rtype: RType) -> Vec<&Rr> {
        self.answers
            .iter()
            .filter(|r| r.rtype == rtype.code())
            .collect()
    }
    /// The CNAME the resolver followed for `name`, if any.
    pub fn cname_of(&self, name: &str) -> Option<String> {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.answers.iter().find_map(|r| match &r.data {
            RData::Cname(t) if r.name.eq_ignore_ascii_case(&n) => Some(t.clone()),
            _ => None,
        })
    }
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "other",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    Timeout,
    Io(String),
    Refused,
    ServFail,
    FormErr,
    Malformed(String),
    NoServer,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsError::Timeout => write!(f, "no answer within the timeout"),
            DnsError::Io(e) => write!(f, "network error: {e}"),
            DnsError::Refused => write!(f, "the server refused the query (REFUSED)"),
            DnsError::ServFail => write!(
                f,
                "the server failed (SERVFAIL — often a DNSSEC or zone problem)"
            ),
            DnsError::FormErr => write!(f, "the server rejected the query format (FORMERR)"),
            DnsError::Malformed(m) => write!(f, "unreadable answer: {m}"),
            DnsError::NoServer => write!(f, "no nameserver configured"),
        }
    }
}

// ---- wire format ------------------------------------------------------------

/// A query for `name`/`rtype`: RD as asked, EDNS0 OPT with a 4096-byte UDP
/// payload and the DO bit when `do_bit`.
pub fn build_query(id: u16, name: &str, rtype: RType, rd: bool, do_bit: bool) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.push(if rd { 0x01 } else { 0x00 });
    q.push(0x00);
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 1]); // QD=1, AN=0, NS=0, AR=1 (OPT)
    for label in name.trim_end_matches('.').split('.') {
        let l = label.as_bytes();
        q.push(l.len().min(63) as u8);
        q.extend_from_slice(&l[..l.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&rtype.code().to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    // OPT RR: root name, type 41, class = UDP size, TTL = ext-rcode/version/flags
    q.push(0);
    q.extend_from_slice(&41u16.to_be_bytes());
    q.extend_from_slice(&4096u16.to_be_bytes());
    q.extend_from_slice(&[0, 0, if do_bit { 0x80 } else { 0 }, 0]);
    q.extend_from_slice(&[0, 0]);
    q
}

/// Read a (possibly compressed) name at `off`; returns the name and the
/// offset just after it in the *uncompressed* stream.
pub fn read_name(msg: &[u8], off: usize) -> Result<(String, usize), DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = off;
    let mut end: Option<usize> = None;
    let mut hops = 0;
    loop {
        let len = *msg
            .get(pos)
            .ok_or_else(|| DnsError::Malformed("name runs past the message".into()))?
            as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            let lo = *msg
                .get(pos + 1)
                .ok_or_else(|| DnsError::Malformed("pointer runs past the message".into()))?
                as usize;
            let ptr = ((len & 0x3f) << 8) | lo;
            if end.is_none() {
                end = Some(pos + 2);
            }
            hops += 1;
            if hops > 32
                || ptr >= msg.len()
                || ptr >= pos && end.is_some_and(|e| ptr >= e - 2) && ptr == pos
            {
                return Err(DnsError::Malformed("compression pointer loop".into()));
            }
            pos = ptr;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(DnsError::Malformed("bad label type".into()));
        }
        let bytes = msg
            .get(pos + 1..pos + 1 + len)
            .ok_or_else(|| DnsError::Malformed("label runs past the message".into()))?;
        labels.push(
            bytes
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() && b != b'.' {
                        b as char
                    } else {
                        '?'
                    }
                })
                .collect(),
        );
        pos += 1 + len;
        if labels.len() > 128 {
            return Err(DnsError::Malformed("name has too many labels".into()));
        }
    }
    Ok((labels.join(".").to_ascii_lowercase(), end.unwrap_or(pos)))
}

fn u16_at(msg: &[u8], off: usize) -> Result<u16, DnsError> {
    msg.get(off..off + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| DnsError::Malformed("short message".into()))
}

fn u32_at(msg: &[u8], off: usize) -> Result<u32, DnsError> {
    msg.get(off..off + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| DnsError::Malformed("short message".into()))
}

fn read_rr(msg: &[u8], off: usize) -> Result<(Option<Rr>, usize), DnsError> {
    let (name, mut p) = read_name(msg, off)?;
    let rtype = u16_at(msg, p)?;
    let ttl = u32_at(msg, p + 4)?;
    let rdlen = u16_at(msg, p + 8)? as usize;
    p += 10;
    let rd = msg
        .get(p..p + rdlen)
        .ok_or_else(|| DnsError::Malformed("rdata runs past the message".into()))?;
    let next = p + rdlen;
    if rtype == 41 {
        return Ok((None, next)); // OPT pseudo-record
    }
    let data = match rtype {
        1 if rdlen == 4 => RData::A(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3])),
        28 if rdlen == 16 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(rd);
            RData::Aaaa(Ipv6Addr::from(o))
        }
        2 => RData::Ns(read_name(msg, p)?.0),
        5 => RData::Cname(read_name(msg, p)?.0),
        12 => RData::Ptr(read_name(msg, p)?.0),
        15 => {
            let pref = u16_at(msg, p)?;
            RData::Mx {
                pref,
                host: read_name(msg, p + 2)?.0,
            }
        }
        6 => {
            let (mname, a) = read_name(msg, p)?;
            let (rname, b) = read_name(msg, a)?;
            RData::Soa {
                mname,
                rname,
                serial: u32_at(msg, b)?,
                refresh: u32_at(msg, b + 4)?,
                retry: u32_at(msg, b + 8)?,
                expire: u32_at(msg, b + 12)?,
                minimum: u32_at(msg, b + 16)?,
            }
        }
        16 => {
            let mut parts = Vec::new();
            let mut i = 0;
            while i < rd.len() {
                let l = rd[i] as usize;
                let s = rd
                    .get(i + 1..i + 1 + l)
                    .ok_or_else(|| DnsError::Malformed("TXT string runs past rdata".into()))?;
                parts.push(String::from_utf8_lossy(s).into_owned());
                i += 1 + l;
            }
            RData::Txt(parts)
        }
        43 if rdlen >= 4 => RData::Ds {
            key_tag: u16::from_be_bytes([rd[0], rd[1]]),
            algorithm: rd[2],
            digest_type: rd[3],
            digest: rd[4..].to_vec(),
        },
        52 if rdlen >= 3 => RData::Tlsa {
            usage: rd[0],
            selector: rd[1],
            matching: rd[2],
            data: rd[3..].to_vec(),
        },
        257 if rdlen >= 2 => {
            let tl = rd[1] as usize;
            let tag = String::from_utf8_lossy(rd.get(2..2 + tl).unwrap_or(&[])).into_owned();
            let value = String::from_utf8_lossy(rd.get(2 + tl..).unwrap_or(&[])).into_owned();
            RData::Caa {
                flags: rd[0],
                tag,
                value,
            }
        }
        _ => RData::Other(rtype, rd.to_vec()),
    };
    Ok((
        Some(Rr {
            name,
            rtype,
            ttl,
            data,
        }),
        next,
    ))
}

/// Parse a whole message (header, question skipped, the three sections).
pub fn parse_message(msg: &[u8]) -> Result<Response, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::Malformed("shorter than a header".into()));
    }
    let flags = u16_at(msg, 2)?;
    let (qd, an, ns, ar) = (
        u16_at(msg, 4)?,
        u16_at(msg, 6)?,
        u16_at(msg, 8)?,
        u16_at(msg, 10)?,
    );
    let mut p = 12;
    for _ in 0..qd {
        let (_, n) = read_name(msg, p)?;
        p = n + 4;
    }
    let mut sections: [Vec<Rr>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (i, count) in [an, ns, ar].iter().enumerate() {
        for _ in 0..*count {
            let (rr, n) = read_rr(msg, p)?;
            if let Some(rr) = rr {
                sections[i].push(rr);
            }
            p = n;
        }
    }
    let [answers, authority, additional] = sections;
    Ok(Response {
        rcode: (flags & 0x0f) as u8,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        ad: flags & 0x0020 != 0,
        answers,
        authority,
        additional,
        server: String::new(),
        elapsed_ms: 0,
    })
}

/// `in-addr.arpa` / `ip6.arpa` name of an address.
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for b in v6.octets().iter().rev() {
                s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
                s.push('.');
                s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                s.push('.');
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

// ---- client -------------------------------------------------------------------

pub struct Client {
    pub servers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub tries: u8,
    pub do_bit: bool,
    cache: Mutex<HashMap<(String, u16), Result<Response, DnsError>>>,
    seq: Mutex<u16>,
}

impl Client {
    /// The system resolver: `MSFE_NG_RESOLVER` (`host[:port]`), else every
    /// `nameserver` of /etc/resolv.conf, else 127.0.0.1.
    pub fn system() -> Client {
        let servers: Vec<SocketAddr> = if let Ok(v) = std::env::var("MSFE_NG_RESOLVER") {
            v.split(',')
                .filter_map(|s| parse_server(s.trim()))
                .collect()
        } else {
            let resolv = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
            crate::resolver::nameservers_of(&resolv)
                .iter()
                .filter_map(|s| parse_server(s))
                .collect()
        };
        let servers = if servers.is_empty() {
            vec![SocketAddr::from(([127, 0, 0, 1], 53))]
        } else {
            servers
        };
        Client::with(servers)
    }

    pub fn at(server: SocketAddr) -> Client {
        Client::with(vec![server])
    }

    fn with(servers: Vec<SocketAddr>) -> Client {
        Client {
            servers,
            timeout: Duration::from_secs(4),
            tries: 2,
            do_bit: true,
            cache: Mutex::new(HashMap::new()),
            seq: Mutex::new((std::process::id() as u16).wrapping_mul(31).wrapping_add(7)),
        }
    }

    fn next_id(&self) -> u16 {
        let mut g = self.seq.lock().unwrap_or_else(|e| e.into_inner());
        *g = g.wrapping_add(1);
        *g
    }

    /// A recursive query through the configured servers, cached per client.
    pub fn query(&self, name: &str, rtype: RType) -> Result<Response, DnsError> {
        let key = (
            name.trim_end_matches('.').to_ascii_lowercase(),
            rtype.code(),
        );
        if let Some(r) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return r.clone();
        }
        let mut last = Err(DnsError::NoServer);
        for server in &self.servers {
            last = self.exchange(*server, name, rtype, true);
            match &last {
                Ok(_) | Err(DnsError::Refused) | Err(DnsError::FormErr) => break,
                _ => continue, // timeout/servfail: try the next server
            }
        }
        // negative answers are cached too — a run asks the same name often
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, last.clone());
        last
    }

    /// A non-recursive query at one server (an authoritative view); never cached.
    pub fn query_authoritative(
        &self,
        server: SocketAddr,
        name: &str,
        rtype: RType,
    ) -> Result<Response, DnsError> {
        self.exchange(server, name, rtype, false)
    }

    fn exchange(
        &self,
        server: SocketAddr,
        name: &str,
        rtype: RType,
        rd: bool,
    ) -> Result<Response, DnsError> {
        let mut last = Err(DnsError::Timeout);
        for _ in 0..self.tries.max(1) {
            let id = self.next_id();
            let q = build_query(id, name, rtype, rd, self.do_bit);
            let t0 = Instant::now();
            match udp_exchange(server, &q, id, self.timeout) {
                Ok(buf) => {
                    let mut resp = parse_message(&buf)?;
                    if resp.tc {
                        if let Ok(buf) = tcp_exchange(server, &q, self.timeout) {
                            resp = parse_message(&buf)?;
                        }
                    }
                    resp.server = server.to_string();
                    resp.elapsed_ms = t0.elapsed().as_millis() as u64;
                    return match resp.rcode {
                        0 | 3 => Ok(resp),
                        1 => Err(DnsError::FormErr),
                        2 => Err(DnsError::ServFail),
                        5 => Err(DnsError::Refused),
                        _ => Ok(resp),
                    };
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    last = Err(DnsError::Timeout);
                }
                Err(e) => return Err(DnsError::Io(e.to_string())),
            }
        }
        last
    }

    // ---- conveniences ----

    /// MX records sorted by preference; empty when none (NXDOMAIN included).
    pub fn mx(&self, domain: &str) -> Result<Vec<(u16, String)>, DnsError> {
        let r = self.query(domain, RType::Mx)?;
        let mut v: Vec<(u16, String)> = r
            .of(RType::Mx)
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::Mx { pref, host } => Some((*pref, host.clone())),
                _ => None,
            })
            .collect();
        v.sort();
        Ok(v)
    }

    /// A and AAAA of a host (following CNAMEs the resolver expanded).
    pub fn addrs(&self, host: &str) -> Result<(Vec<Ipv4Addr>, Vec<Ipv6Addr>), DnsError> {
        let a = self.query(host, RType::A)?;
        let v4: Vec<Ipv4Addr> = a
            .of(RType::A)
            .iter()
            .filter_map(|rr| match rr.data {
                RData::A(x) => Some(x),
                _ => None,
            })
            .collect();
        let v6: Vec<Ipv6Addr> = match self.query(host, RType::Aaaa) {
            Ok(r) => r
                .of(RType::Aaaa)
                .iter()
                .filter_map(|rr| match rr.data {
                    RData::Aaaa(x) => Some(x),
                    _ => None,
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        Ok((v4, v6))
    }

    /// The TXT records at `name`, each record's strings joined.
    pub fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let r = self.query(name, RType::Txt)?;
        Ok(r.of(RType::Txt)
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::Txt(parts) => Some(parts.concat()),
                _ => None,
            })
            .collect())
    }

    /// PTR names of an address.
    pub fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let r = self.query(&reverse_name(ip), RType::Ptr)?;
        Ok(r.of(RType::Ptr)
            .iter()
            .filter_map(|rr| match &rr.data {
                RData::Ptr(p) => Some(p.clone()),
                _ => None,
            })
            .collect())
    }
}

fn parse_server(s: &str) -> Option<SocketAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return inner
            .parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53));
    }
    s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
}

fn udp_exchange(
    server: SocketAddr,
    q: &[u8],
    id: u16,
    timeout: Duration,
) -> std::io::Result<Vec<u8>> {
    let sock = UdpSocket::bind(if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })?;
    sock.set_read_timeout(Some(timeout))?;
    sock.send_to(q, server)?;
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, from) = sock.recv_from(&mut buf)?;
        // only the answer to our id from the server we asked
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id && from.ip() == server.ip() {
            buf.truncate(n);
            return Ok(buf);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"));
        }
        sock.set_read_timeout(Some(deadline - now))?;
    }
}

fn tcp_exchange(server: SocketAddr, q: &[u8], timeout: Duration) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&server, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut msg = Vec::with_capacity(q.len() + 2);
    msg.extend_from_slice(&(q.len() as u16).to_be_bytes());
    msg.extend_from_slice(q);
    s.write_all(&msg)?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
pub(crate) mod testsupport {
    //! A canned-answer UDP server for tests: answers every query with the
    //! records the closure returns for (name, type), or stays silent.
    use super::*;
    use std::sync::Arc;

    pub type Answer = Box<dyn Fn(&str, u16) -> Option<(u8, Vec<Rr>, bool /*tc*/)> + Send + Sync>;

    pub fn encode_name(name: &str, out: &mut Vec<u8>) {
        for label in name.trim_end_matches('.').split('.') {
            if label.is_empty() {
                continue;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    pub fn encode_rr(rr: &Rr, out: &mut Vec<u8>) {
        encode_name(&rr.name, out);
        out.extend_from_slice(&rr.rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&rr.ttl.to_be_bytes());
        let mut rd = Vec::new();
        match &rr.data {
            RData::A(a) => rd.extend_from_slice(&a.octets()),
            RData::Aaaa(a) => rd.extend_from_slice(&a.octets()),
            RData::Ns(n) | RData::Cname(n) | RData::Ptr(n) => encode_name(n, &mut rd),
            RData::Mx { pref, host } => {
                rd.extend_from_slice(&pref.to_be_bytes());
                encode_name(host, &mut rd);
            }
            RData::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                encode_name(mname, &mut rd);
                encode_name(rname, &mut rd);
                for v in [serial, refresh, retry, expire, minimum] {
                    rd.extend_from_slice(&v.to_be_bytes());
                }
            }
            RData::Txt(parts) => {
                for p in parts {
                    rd.push(p.len() as u8);
                    rd.extend_from_slice(p.as_bytes());
                }
            }
            RData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                rd.extend_from_slice(&key_tag.to_be_bytes());
                rd.push(*algorithm);
                rd.push(*digest_type);
                rd.extend_from_slice(digest);
            }
            RData::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => {
                rd.extend_from_slice(&[*usage, *selector, *matching]);
                rd.extend_from_slice(data);
            }
            RData::Caa { flags, tag, value } => {
                rd.push(*flags);
                rd.push(tag.len() as u8);
                rd.extend_from_slice(tag.as_bytes());
                rd.extend_from_slice(value.as_bytes());
            }
            RData::Other(_, d) => rd.extend_from_slice(d),
        }
        out.extend_from_slice(&(rd.len() as u16).to_be_bytes());
        out.extend_from_slice(&rd);
    }

    /// Build a response to `query` with the given answer records.
    pub fn encode_response(query: &[u8], rcode: u8, answers: &[Rr], tc: bool, ad: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&query[0..2]);
        let mut flags: u16 = 0x8180 | rcode as u16; // QR, RD, RA
        if tc {
            flags |= 0x0200;
        }
        if ad {
            flags |= 0x0020;
        }
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        // copy the question
        let (_, qend) = read_name(query, 12).unwrap();
        out.extend_from_slice(&query[12..qend + 4]);
        for rr in answers {
            encode_rr(rr, &mut out);
        }
        out
    }

    pub struct FakeServer {
        pub addr: SocketAddr,
        pub hits: Arc<Mutex<Vec<(String, u16)>>>,
    }

    /// Start a fake server on 127.0.0.1; it runs until the test process ends.
    pub fn start(answer: Answer, ad: bool) -> FakeServer {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(Vec::new()));
        let h2 = hits.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                let q = &buf[..n];
                let Ok((name, qend)) = read_name(q, 12) else {
                    continue;
                };
                let rtype = u16::from_be_bytes([q[qend], q[qend + 1]]);
                h2.lock().unwrap().push((name.clone(), rtype));
                if let Some((rcode, rrs, tc)) = answer(&name, rtype) {
                    let resp = encode_response(q, rcode, &rrs, tc, ad);
                    let _ = sock.send_to(&resp, from);
                }
            }
        });
        FakeServer { addr, hits }
    }
}

#[cfg(test)]
mod tests {
    use super::testsupport::*;
    use super::*;

    fn rr(name: &str, ttl: u32, data: RData) -> Rr {
        let rtype = match &data {
            RData::A(_) => 1,
            RData::Aaaa(_) => 28,
            RData::Ns(_) => 2,
            RData::Cname(_) => 5,
            RData::Ptr(_) => 12,
            RData::Mx { .. } => 15,
            RData::Soa { .. } => 6,
            RData::Txt(_) => 16,
            RData::Ds { .. } => 43,
            RData::Tlsa { .. } => 52,
            RData::Caa { .. } => 257,
            RData::Other(t, _) => *t,
        };
        Rr {
            name: name.into(),
            rtype,
            ttl,
            data,
        }
    }

    #[test]
    fn query_has_edns_and_flags() {
        let q = build_query(0x1234, "Example.COM.", RType::Mx, true, true);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[2], 0x01, "RD");
        assert_eq!(&q[4..12], &[0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&q[12..25], b"\x07Example\x03COM\x00");
        assert_eq!(&q[25..29], &[0, 15, 0, 1]);
        assert_eq!(&q[29..40], &[0, 0, 41, 16, 0, 0, 0, 0x80, 0, 0, 0]);
        let q = build_query(1, "a.b", RType::A, false, false);
        assert_eq!(q[2], 0x00);
        assert_eq!(q[q.len() - 4], 0, "no DO bit");
    }

    #[test]
    fn parses_every_record_type_with_compression_and_ttls() {
        let q = build_query(7, "example.com", RType::Mx, true, true);
        let answers = vec![
            rr(
                "example.com",
                3600,
                RData::Mx {
                    pref: 10,
                    host: "mail.example.com".into(),
                },
            ),
            rr(
                "example.com",
                300,
                RData::Txt(vec!["v=spf1 ".into(), "-all".into()]),
            ),
            rr(
                "example.com",
                60,
                RData::Soa {
                    mname: "ns1.example.com".into(),
                    rname: "hostmaster.example.com".into(),
                    serial: 2026091901,
                    refresh: 7200,
                    retry: 900,
                    expire: 1209600,
                    minimum: 86400,
                },
            ),
            rr(
                "mail.example.com",
                120,
                RData::A("192.0.2.25".parse().unwrap()),
            ),
            rr(
                "mail.example.com",
                120,
                RData::Aaaa("2001:db8::25".parse().unwrap()),
            ),
            rr("example.com", 1, RData::Ns("ns1.example.com".into())),
            rr("www.example.com", 1, RData::Cname("example.com".into())),
            rr(
                "25.2.0.192.in-addr.arpa",
                1,
                RData::Ptr("mail.example.com".into()),
            ),
            rr(
                "example.com",
                1,
                RData::Ds {
                    key_tag: 12345,
                    algorithm: 13,
                    digest_type: 2,
                    digest: vec![0xab, 0xcd],
                },
            ),
            rr(
                "_25._tcp.mail.example.com",
                1,
                RData::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: vec![1, 2, 3],
                },
            ),
            rr(
                "example.com",
                1,
                RData::Caa {
                    flags: 0,
                    tag: "issue".into(),
                    value: "letsencrypt.org".into(),
                },
            ),
            rr("example.com", 1, RData::Other(99, vec![9, 9])),
        ];
        let mut msg = encode_response(&q, 0, &answers, false, true);
        // hand-insert a compression pointer: replace the second RR's name with a pointer to offset 12
        let (_, qend) = read_name(&msg, 12).unwrap();
        let first_rr_end = {
            let (_, n) = read_name(&msg, qend + 4).unwrap();
            let rdlen = u16::from_be_bytes([msg[n + 8], msg[n + 9]]) as usize;
            n + 10 + rdlen
        };
        let name_len = read_name(&msg, first_rr_end).unwrap().1 - first_rr_end;
        msg.splice(first_rr_end..first_rr_end + name_len, [0xc0, 12]);
        let r = parse_message(&msg).unwrap();
        assert_eq!(r.rcode, 0);
        assert!(r.ad);
        assert_eq!(r.answers.len(), 12);
        assert_eq!(
            r.answers[0].data,
            RData::Mx {
                pref: 10,
                host: "mail.example.com".into()
            }
        );
        assert_eq!(r.answers[0].ttl, 3600);
        assert_eq!(r.answers[1].name, "example.com", "decompressed");
        assert_eq!(
            r.answers[1].data,
            RData::Txt(vec!["v=spf1 ".into(), "-all".into()])
        );
        assert!(matches!(
            r.answers[2].data,
            RData::Soa {
                serial: 2026091901,
                ..
            }
        ));
        assert_eq!(r.answers[3].data.present(), "192.0.2.25");
        assert_eq!(r.answers[4].data.present(), "2001:db8::25");
        assert_eq!(
            r.answers[6].present(),
            "www.example.com. 1 IN CNAME example.com."
        );
        assert_eq!(r.answers[8].data.present(), "12345 13 2 abcd");
        assert_eq!(r.answers[9].data.present(), "3 1 1 010203");
        assert_eq!(r.answers[10].data.present(), "0 issue \"letsencrypt.org\"");
        assert_eq!(
            r.cname_of("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(r.of(RType::A).len(), 1);
    }

    #[test]
    fn malformed_messages_are_errors_not_panics() {
        assert!(matches!(
            parse_message(&[0; 5]),
            Err(DnsError::Malformed(_))
        ));
        // pointer loop
        let mut msg = vec![0u8; 12];
        msg[5] = 1; // QDCOUNT
        msg.extend_from_slice(&[0xc0, 12]);
        assert!(matches!(parse_message(&msg), Err(DnsError::Malformed(_))));
        // name past the end
        let mut msg = vec![0u8; 12];
        msg[5] = 1;
        msg.extend_from_slice(&[5, b'a']);
        assert!(parse_message(&msg).is_err());
        // truncated rdata
        let q = build_query(1, "x.example", RType::A, true, false);
        let mut m = encode_response(
            &q,
            0,
            &[rr("x.example", 1, RData::A("1.2.3.4".parse().unwrap()))],
            false,
            false,
        );
        m.truncate(m.len() - 2);
        assert!(parse_message(&m).is_err());
    }

    #[test]
    fn reverse_names() {
        assert_eq!(
            reverse_name("192.0.2.25".parse().unwrap()),
            "25.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn client_queries_caches_retries_and_reports_rcodes() {
        let srv = start(
            Box::new(|name, rtype| match (name, rtype) {
                ("example.com", 15) => Some((
                    0,
                    vec![
                        Rr {
                            name: "example.com".into(),
                            rtype: 15,
                            ttl: 10,
                            data: RData::Mx {
                                pref: 20,
                                host: "b.example.com".into(),
                            },
                        },
                        Rr {
                            name: "example.com".into(),
                            rtype: 15,
                            ttl: 10,
                            data: RData::Mx {
                                pref: 10,
                                host: "a.example.com".into(),
                            },
                        },
                    ],
                    false,
                )),
                ("example.com", 16) => Some((
                    0,
                    vec![Rr {
                        name: "example.com".into(),
                        rtype: 16,
                        ttl: 10,
                        data: RData::Txt(vec!["v=spf1 ".into(), "mx -all".into()]),
                    }],
                    false,
                )),
                ("a.example.com", 1) => Some((
                    0,
                    vec![Rr {
                        name: "a.example.com".into(),
                        rtype: 1,
                        ttl: 10,
                        data: RData::A("192.0.2.1".parse().unwrap()),
                    }],
                    false,
                )),
                ("a.example.com", 28) => Some((0, vec![], false)),
                ("nx.example.com", _) => Some((3, vec![], false)),
                ("fail.example.com", _) => Some((2, vec![], false)),
                ("refused.example.com", _) => Some((5, vec![], false)),
                ("1.2.0.192.in-addr.arpa", 12) => Some((
                    0,
                    vec![Rr {
                        name: "1.2.0.192.in-addr.arpa".into(),
                        rtype: 12,
                        ttl: 1,
                        data: RData::Ptr("a.example.com".into()),
                    }],
                    false,
                )),
                ("silent.example.com", _) => None,
                _ => Some((3, vec![], false)),
            }),
            true,
        );
        let mut c = Client::at(srv.addr);
        c.timeout = Duration::from_millis(300);
        assert_eq!(
            c.mx("example.com").unwrap(),
            vec![(10, "a.example.com".into()), (20, "b.example.com".into())]
        );
        assert_eq!(c.txt("example.com").unwrap(), vec!["v=spf1 mx -all"]);
        assert_eq!(
            c.addrs("a.example.com").unwrap().0,
            vec!["192.0.2.1".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            c.ptr("192.0.2.1".parse().unwrap()).unwrap(),
            vec!["a.example.com"]
        );
        assert!(c.query("example.com", RType::Mx).unwrap().ad);
        let r = c.query("nx.example.com", RType::A).unwrap();
        assert!(r.nxdomain());
        assert_eq!(
            c.query("fail.example.com", RType::A),
            Err(DnsError::ServFail)
        );
        assert_eq!(
            c.query("refused.example.com", RType::A),
            Err(DnsError::Refused)
        );
        let t0 = Instant::now();
        assert_eq!(
            c.query("silent.example.com", RType::A),
            Err(DnsError::Timeout)
        );
        assert!(t0.elapsed() >= Duration::from_millis(550), "two tries");
        // cache: the MX was asked once although used twice
        let _ = c.mx("example.com");
        let hits = srv.hits.lock().unwrap();
        assert_eq!(
            hits.iter()
                .filter(|(n, t)| n == "example.com" && *t == 15)
                .count(),
            1
        );
        assert_eq!(
            hits.iter()
                .filter(|(n, _)| n == "silent.example.com")
                .count(),
            2
        );
    }

    #[test]
    fn system_resolver_override_and_server_parsing() {
        assert_eq!(parse_server("1.2.3.4"), Some("1.2.3.4:53".parse().unwrap()));
        assert_eq!(
            parse_server("1.2.3.4:5353"),
            Some("1.2.3.4:5353".parse().unwrap())
        );
        assert_eq!(parse_server("[::1]"), Some("[::1]:53".parse().unwrap()));
        assert_eq!(
            parse_server("[::1]:5353"),
            Some("[::1]:5353".parse().unwrap())
        );
        assert_eq!(parse_server("nonsense"), None);
        std::env::set_var("MSFE_NG_RESOLVER", "127.0.0.1:5353, 10.0.0.1");
        let c = Client::system();
        assert_eq!(
            c.servers,
            vec![
                "127.0.0.1:5353".parse().unwrap(),
                "10.0.0.1:53".parse().unwrap()
            ]
        );
        std::env::remove_var("MSFE_NG_RESOLVER");
    }
}
