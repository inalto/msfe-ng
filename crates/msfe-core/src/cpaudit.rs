//! The cPanel server audit of the delivery test: for an address hosted here,
//! what this server does with it — the account, how Exim routes it, the
//! identity it sends with, the services and ports, the limits and filters.
//! Read-only: files under the cPanel root, `exim -bt`, `uapi`/`whmapi1`
//! queries, `ss`, `systemctl is-active`. Under `MSFE_NG_CPANEL_ROOT` (tests)
//! files come from the fixture tree and command output from `_cmd/<name>.txt`.

use crate::delivery::Inputs;
use crate::delivery::{Category, Check, Fix, Scope, Severity, Verdict};
use crate::deliveryrun::{Ctx, Results, Task};
use crate::json::Json;
use crate::service::run_with_timeout;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const S: Scope = Scope::Server;
const CMD_TIMEOUT: Duration = Duration::from_secs(15);

// ---- the host ------------------------------------------------------------------

/// Where the cPanel files live and how commands run.
pub struct Cp {
    pub root: PathBuf,
}

impl Cp {
    pub fn detect() -> Cp {
        Cp {
            root: std::env::var("MSFE_NG_CPANEL_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/")),
        }
    }
    pub fn live(&self) -> bool {
        self.root == Path::new("/")
    }
    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel.trim_start_matches('/'))
    }
    pub fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.path(rel)).ok()
    }
    pub fn exists(&self, rel: &str) -> bool {
        self.path(rel).exists()
    }
    /// Run a command (live) or read its canned output (fixture). `None` when
    /// it cannot run at all.
    pub fn cmd(&self, name: &str, program: &str, args: &[&str]) -> Option<(bool, String)> {
        if !self.live() {
            let text = self.read(&format!("_cmd/{name}.txt"))?;
            return Some((true, text));
        }
        let mut c = Command::new(program);
        c.args(args);
        let out = run_with_timeout(&mut c, CMD_TIMEOUT).ok()?;
        if out.timed_out {
            return None;
        }
        Some((out.ok, format!("{}{}", out.stdout, out.stderr)))
    }
    /// A uapi call as the account, JSON output.
    pub fn uapi(
        &self,
        name: &str,
        user: &str,
        module: &str,
        func: &str,
        args: &[&str],
    ) -> Option<Json> {
        let mut a = vec![
            format!("--user={user}"),
            "--output=json".into(),
            module.into(),
            func.into(),
        ];
        a.extend(args.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let (_, text) = self.cmd(name, "uapi", &refs)?;
        Json::parse(&text).ok()
    }
    pub fn whmapi1(&self, name: &str, func: &str, args: &[&str]) -> Option<Json> {
        let mut a = vec!["--output=json".to_string(), func.into()];
        a.extend(args.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let (_, text) = self.cmd(name, "whmapi1", &refs)?;
        Json::parse(&text).ok()
    }
}

// ---- parsers -------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    Local,
    Remote,
    SecondaryMx,
    Unlisted,
}

impl DomainKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainKind::Local => "local",
            DomainKind::Remote => "remote",
            DomainKind::SecondaryMx => "secondary MX",
            DomainKind::Unlisted => "not listed",
        }
    }
}

/// Which of cPanel's routing files lists the domain.
pub fn domain_kind(cp: &Cp, domain: &str) -> DomainKind {
    let listed = |file: &str| {
        cp.read(file)
            .is_some_and(|t| t.lines().any(|l| l.trim().eq_ignore_ascii_case(domain)))
    };
    if listed("/etc/localdomains") {
        DomainKind::Local
    } else if listed("/etc/secondarymx") {
        DomainKind::SecondaryMx
    } else if listed("/etc/remotedomains") {
        DomainKind::Remote
    } else {
        DomainKind::Unlisted
    }
}

/// `KEY=value` lines of `/var/cpanel/users/<user>`.
pub fn parse_cpuser(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

pub fn cpuser_get<'a>(kv: &'a [(String, String)], key: &str) -> Option<&'a str> {
    kv.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// `key=value` lines of `/etc/exim.conf.localopts`.
pub fn parse_localopts(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            match l.split_once('=') {
                Some((k, v)) => Some((k.trim().to_string(), v.trim().to_string())),
                None => Some((l.to_string(), String::new())),
            }
        })
        .collect()
}

/// `/etc/mailips` (`domain: ip` or `*: ip`) → the IP for `domain`.
pub fn parse_mailips(text: &str, domain: &str) -> Option<IpAddr> {
    let mut star = None;
    for l in text.lines() {
        let Some((d, ip)) = l.split_once(':') else {
            continue;
        };
        let ip: IpAddr = match ip.trim().parse() {
            Ok(i) => i,
            Err(_) => continue,
        };
        let d = d.trim();
        if d.eq_ignore_ascii_case(domain) {
            return Some(ip);
        }
        if d == "*" {
            star = Some(ip);
        }
    }
    star
}

/// `/etc/mailhelo` (`domain: name` or `*: name`) → the HELO name for `domain`.
pub fn parse_mailhelo(text: &str, domain: &str) -> Option<String> {
    let mut star = None;
    for l in text.lines() {
        let Some((d, name)) = l.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let d = d.trim();
        if d.eq_ignore_ascii_case(domain) {
            return Some(name.to_string());
        }
        if d == "*" {
            star = Some(name.to_string());
        }
    }
    star
}

/// One line of `/etc/valiases/<domain>`: `local: target1, target2`.
#[derive(Debug, Clone, PartialEq)]
pub struct Alias {
    pub local: String,
    pub targets: Vec<String>,
}

pub fn parse_valiases(text: &str) -> Vec<Alias> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let (local, rest) = l.split_once(':')?;
            let targets = split_targets(rest.trim());
            Some(Alias {
                local: local.trim().to_string(),
                targets,
            })
        })
        .collect()
}

/// Comma-separated targets, quotes kept whole (`":fail: No Such User"`).
fn split_targets(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in s.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                cur.push(ch);
            }
            ',' if !quoted => {
                let t = cur.trim();
                if !t.is_empty() {
                    out.push(t.to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    let t = cur.trim();
    if !t.is_empty() {
        out.push(t.to_string());
    }
    out
}

/// What a forwarder target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Address(String),
    Fail(String),
    Blackhole,
    Pipe(String),
    File(String),
    Other(String),
}

pub fn classify_target(t: &str) -> Target {
    let t = t.trim().trim_matches('"').trim();
    if let Some(msg) = t.strip_prefix(":fail:") {
        Target::Fail(msg.trim().to_string())
    } else if t == ":blackhole:" || t == "/dev/null" {
        Target::Blackhole
    } else if let Some(cmd) = t.strip_prefix('|') {
        Target::Pipe(cmd.trim().to_string())
    } else if t.starts_with('/') {
        Target::File(t.to_string())
    } else if t.contains('@') {
        Target::Address(t.to_ascii_lowercase())
    } else {
        Target::Other(t.to_string())
    }
}

/// One address `exim -bt` reported.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BtHop {
    pub address: String,
    pub parents: Vec<String>,
    pub router: Option<String>,
    pub transport: Option<String>,
    pub hosts: Vec<String>,
    pub error: Option<String>,
}

/// Parse the output of `exim -bt <address>`.
pub fn parse_exim_bt(text: &str) -> Vec<BtHop> {
    let mut out: Vec<BtHop> = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let t = line.trim();
        if !line.starts_with(' ') {
            // "addr is undeliverable: reason" / "addr cannot be resolved"
            if let Some((addr, why)) = t.split_once(" is undeliverable: ") {
                out.push(BtHop {
                    address: addr.to_string(),
                    error: Some(why.trim_end_matches('"').to_string()),
                    ..Default::default()
                });
            } else if let Some((addr, why)) = t.split_once(" cannot be resolved") {
                out.push(BtHop {
                    address: addr.to_string(),
                    error: Some(format!("cannot be resolved{why}")),
                    ..Default::default()
                });
            } else {
                out.push(BtHop {
                    address: t.to_string(),
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(cur) = out.last_mut() else { continue };
        if let Some(p) = t.strip_prefix("<-- ") {
            cur.parents.push(p.trim().to_string());
        } else if t.starts_with("router = ") {
            for part in t.split(", ") {
                if let Some(r) = part.strip_prefix("router = ") {
                    cur.router = Some(r.trim().to_string());
                } else if let Some(tr) = part.strip_prefix("transport = ") {
                    cur.transport = Some(tr.trim().to_string());
                }
            }
        } else if let Some(h) = t.strip_prefix("host ") {
            cur.hosts
                .push(h.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    out
}

/// `ss -ltnH` → the listening ports (any address).
pub fn parse_ss_listeners(text: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = text
        .lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            // LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* … (with -H no header; the
            // state column may be absent when -l is given on some versions)
            let local = cols
                .iter()
                .find(|c| c.contains(':') && !c.ends_with(":*"))?;
            local.rsplit_once(':')?.1.parse().ok()
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// A mailbox row of `uapi Email list_pops_with_disk`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Mailbox {
    pub email: String,
    pub suspended_incoming: bool,
    pub suspended_login: bool,
    pub disk_used_mb: f64,
    /// `None` = unlimited.
    pub quota_mb: Option<f64>,
    pub used_percent: f64,
}

pub fn parse_list_pops(v: &Json, address: &str) -> Result<Option<Mailbox>, String> {
    let result = v.get("result").ok_or("no result object")?;
    if let Some(errs) = result.get("errors").and_then(|e| e.as_array()) {
        if !errs.is_empty() {
            return Err(errs
                .iter()
                .filter_map(|e| e.as_str())
                .collect::<Vec<_>>()
                .join("; "));
        }
    }
    let rows = result
        .get("data")
        .and_then(|d| d.as_array())
        .ok_or("no data array")?;
    let num = |j: Option<&Json>| -> Option<f64> {
        match j {
            Some(Json::Int(n)) => Some(*n as f64),
            Some(Json::Num(s)) => s.parse().ok(),
            Some(Json::Str(s)) => s.parse().ok(),
            _ => None,
        }
    };
    let truthy = |j: Option<&Json>| match j {
        Some(Json::Int(n)) => *n != 0,
        Some(Json::Bool(b)) => *b,
        Some(Json::Str(s)) => s != "0" && !s.is_empty(),
        _ => false,
    };
    for r in rows {
        let email = r.get("email").and_then(Json::as_str).unwrap_or("");
        if !email.eq_ignore_ascii_case(address) {
            continue;
        }
        let quota = match r.get("diskquota").and_then(Json::as_str) {
            Some("unlimited") | None => None,
            Some(s) => s.parse::<f64>().ok(),
        };
        return Ok(Some(Mailbox {
            email: email.to_ascii_lowercase(),
            suspended_incoming: truthy(r.get("suspended_incoming")),
            suspended_login: truthy(r.get("suspended_login")),
            disk_used_mb: num(r.get("diskused")).unwrap_or(0.0),
            quota_mb: quota,
            used_percent: num(r.get("diskusedpercent_float"))
                .or_else(|| num(r.get("diskusedpercent")))
                .unwrap_or(0.0),
        }));
    }
    Ok(None)
}

/// Hide other people's addresses in evidence: `j***@example.com`.
pub fn mask_address(addr: &str) -> String {
    match addr.split_once('@') {
        Some((l, d)) => format!("{}***@{d}", l.chars().next().unwrap_or('*')),
        None => addr.to_string(),
    }
}

// ---- the account -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Account {
    pub user: String,
    pub home: PathBuf,
    pub suspended: bool,
    pub max_email_per_hour: Option<u64>,
    pub max_defer_fail_percentage: Option<String>,
    pub kind: DomainKind,
}

/// The account that owns `domain` on this server, with what its cpuser
/// file says. `None` when the domain is not hosted here.
pub fn resolve_account(cp: &Cp, domain: &str) -> Option<Account> {
    let user = if cp.live() {
        crate::users::owner_of_domain(domain)?
    } else {
        // fixture: /etc/userdomains under the root
        let text = cp.read("/etc/userdomains")?;
        text.lines().find_map(|l| {
            let (d, u) = l.split_once(':')?;
            (d.trim().eq_ignore_ascii_case(domain)).then(|| u.trim().to_string())
        })?
    };
    if !crate::users::valid_username(&user) {
        return None;
    }
    let kv = parse_cpuser(
        &cp.read(&format!("/var/cpanel/users/{user}"))
            .unwrap_or_default(),
    );
    let home = cp
        .read("/etc/passwd")
        .and_then(|p| {
            p.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 5 && f[0] == user).then(|| PathBuf::from(f[5]))
            })
        })
        .unwrap_or_else(|| PathBuf::from(format!("/home/{user}")));
    Some(Account {
        suspended: cpuser_get(&kv, "SUSPENDED").is_some_and(|v| v == "1"),
        max_email_per_hour: cpuser_get(&kv, "MAX_EMAIL_PER_HOUR").and_then(|v| v.parse().ok()),
        max_defer_fail_percentage: cpuser_get(&kv, "MAX_DEFER_FAIL_PERCENTAGE").map(str::to_string),
        kind: domain_kind(cp, domain),
        user,
        home,
    })
}

// ---- tasks ---------------------------------------------------------------------

pub fn tasks(inputs: &Inputs) -> Vec<Task> {
    if !inputs.audit {
        return vec![];
    }
    vec![
        Task::new("acct", &["dns.mx"], acct_task),
        Task::new("route", &["acct"], route_task),
        Task::new("out", &["acct", "spf", "dkim"], out_task),
        Task::new("svc", &["acct"], svc_task),
        Task::new("limit", &["acct"], limit_task),
    ]
}

fn unknown(id: &str, cat: Category, title: &str, why: impl Into<String>) -> Check {
    Check::new(id, S, cat, Verdict::Unknown, Severity::Info, title, why)
}

fn na(id: &str, cat: Category, title: impl Into<String>, why: impl Into<String>) -> Check {
    Check::new(
        id,
        S,
        cat,
        Verdict::NotApplicable,
        Severity::Info,
        title,
        why,
    )
}

/// `acct.domain_kind`: Exim's routing list for the domain against where
/// the public MX points (needs the MX addresses, hence a task of its own).
fn domain_kind_check(res: &Results, d: &str, kind: DomainKind) -> Check {
    let cat = Category::Account;
    // local/remote vs where the public MX points
    let served_here = match res.fact("mx_ips") {
        Some(Json::Object(f)) => {
            let own = crate::netguard::own_addresses();
            f.iter().any(|(_, ips)| {
                ips.as_array().is_some_and(|a| {
                    a.iter().any(|i| {
                        i.as_str()
                            .and_then(|s| s.parse::<IpAddr>().ok())
                            .is_some_and(|ip| own.contains(&ip))
                    })
                })
            })
        }
        _ => false,
    };
    let mx_known = res.fact("mx_ips").is_some();
    match (kind, served_here, mx_known) {
        (DomainKind::Local, true, _) => Check::new("acct.domain_kind", S, cat, Verdict::Pass, Severity::Info, "mail routing: local, and the MX points here", "Exim delivers mail for the domain to the local mailboxes, and the public MX record brings it here"),
        (DomainKind::Local, false, true) => Check::new("acct.domain_kind", S, cat, Verdict::Fail, Severity::High, "mail routing: local, but the public MX points elsewhere", format!("{d} is in /etc/localdomains, so mail sent *from this server* to the domain is delivered locally — while the world delivers to the MX host(s). Local senders (web forms, other accounts, cron) never reach the real mailboxes"))
            .fix(Fix {
                summary: "Set the domain's Email Routing to Remote Mail Exchanger so this server hands mail to the MX like everyone else".into(),
                location: Some("WHM → Email Routing (or cPanel → Email Routing) → Remote Mail Exchanger".into()),
                ..Default::default()
            }),
        (DomainKind::Local, false, false) => Check::new("acct.domain_kind", S, cat, Verdict::Pass, Severity::Info, "mail routing: local", "Exim delivers mail for the domain to the local mailboxes (the public MX could not be compared)"),
        (DomainKind::Remote, true, _) => Check::new("acct.domain_kind", S, cat, Verdict::Fail, Severity::Critical, "mail routing: remote, but the public MX points here", format!("{d} is in /etc/remotedomains, so Exim tries to hand mail to the MX — which is this server: a loop. Mail bounces with \"lowest numbered MX record points to local host\""))
            .fix(Fix {
                summary: "Set Email Routing to Local Mail Exchanger".into(),
                location: Some("WHM → Email Routing → Local Mail Exchanger".into()),
                ..Default::default()
            }),
        (DomainKind::Remote, false, _) => Check::new("acct.domain_kind", S, cat, Verdict::Pass, Severity::Info, "mail routing: remote", "this server hands mail for the domain to its public MX; no local mailboxes are used"),
        (DomainKind::SecondaryMx, _, _) => Check::new("acct.domain_kind", S, cat, Verdict::Pass, Severity::Info, "mail routing: backup MX", "this server accepts mail for the domain and relays it to the primary MX"),
        (DomainKind::Unlisted, _, _) => Check::new("acct.domain_kind", S, cat, Verdict::Warn, Severity::Medium, "mail routing: the domain is in none of Exim's domain lists", "neither /etc/localdomains, /etc/remotedomains nor /etc/secondarymx lists it — Exim treats it as non-local and routes by MX; local mailboxes, if any, are unreachable")
            .fix(Fix {
                summary: "Choose the routing explicitly".into(),
                location: Some("WHM → Email Routing".into()),
                ..Default::default()
            }),
    }
}

fn acct_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Account;
    let cp = Cp::detect();
    let d = &ctx.inputs.domain;
    let addr = &ctx.inputs.address;
    let mut out = Vec::new();
    let Some(acct) = resolve_account(&cp, d) else {
        res.set_fact("acct_hosted", Json::Bool(false));
        out.push(na("acct.owner", cat, format!("{d} is not hosted on this server"), "no cPanel account owns the domain (/etc/userdomains); the server audit does not apply — the public checks above are all there is to say"));
        return (out, vec![]);
    };
    if let Some(scope_user) = &ctx.inputs.user_scope {
        if scope_user != &acct.user {
            res.set_fact("acct_hosted", Json::Bool(false));
            out.push(na(
                "acct.owner",
                cat,
                "not your domain",
                "the domain belongs to another account on this server",
            ));
            return (out, vec![]);
        }
    }
    res.set_fact("acct_hosted", Json::Bool(true));
    res.set_fact("acct_user", Json::str(&acct.user));
    res.set_fact("acct_home", Json::str(acct.home.display().to_string()));
    res.set_fact("acct_kind", Json::str(acct.kind.as_str()));
    out.push(Check::new(
        "acct.owner",
        S,
        cat,
        Verdict::Pass,
        Severity::Info,
        format!("{d} belongs to account {}", acct.user),
        format!("home {}", acct.home.display()),
    ));

    // the routing list vs the public MX: once the MX addresses are known
    let hosts = res.fact_strs("mx_hosts");
    let kind = acct.kind;
    let dom = d.clone();
    let mut more = Vec::new();
    if hosts.is_empty() {
        out.push(domain_kind_check(res, d, kind));
    } else {
        let deps: Vec<String> = hosts
            .iter()
            .filter(|h| h.parse::<IpAddr>().is_err())
            .map(|h| format!("dns.mx.host.{h}"))
            .collect();
        let dep_refs: Vec<&str> = deps.iter().map(String::as_str).collect();
        more.push(Task::new("acct.domain_kind", &dep_refs, move |_, res| {
            (vec![domain_kind_check(res, &dom, kind)], vec![])
        }));
    }
    if acct.suspended {
        out.push(Check::new("acct.suspended", S, cat, Verdict::Fail, Severity::Critical, format!("account {} is suspended", acct.user), "cPanel queues or rejects mail for suspended accounts (`suspended_account_deliveries` in Exim's options) and blocks logins").fix(Fix {
            summary: "Unsuspend the account, or expect its mail to stay queued".into(),
            location: Some("WHM → Manage Account Suspension".into()),
            ..Default::default()
        }));
    } else {
        out.push(Check::new(
            "acct.suspended",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            format!("account {} is active", acct.user),
            "not suspended",
        ));
    }

    // the mailbox
    if acct.kind == DomainKind::Local {
        let call = format!("domain={d}");
        match cp.uapi(
            "list_pops",
            &acct.user,
            "Email",
            "list_pops_with_disk",
            &[&call],
        ) {
            Some(v) => match parse_list_pops(&v, addr) {
                Ok(Some(m)) => {
                    res.set_fact("acct_mailbox", Json::Bool(true));
                    if m.suspended_incoming {
                        out.push(
                            Check::new(
                                "acct.mailbox",
                                S,
                                cat,
                                Verdict::Fail,
                                Severity::Critical,
                                "incoming mail is suspended for this mailbox",
                                "cPanel rejects new mail for it (\"Mailbox is suspended\")",
                            )
                            .fix(Fix {
                                summary: "Unsuspend incoming mail".into(),
                                location: Some(
                                    "cPanel → Email Accounts → Manage → Restrictions".into(),
                                ),
                                ..Default::default()
                            }),
                        );
                    } else if m.quota_mb.is_some_and(|q| q > 0.0 && m.disk_used_mb >= q)
                        || m.used_percent >= 100.0
                    {
                        out.push(Check::new("acct.mailbox", S, cat, Verdict::Fail, Severity::High, "the mailbox is full", format!("{:.0} MB used of {} — Exim defers or rejects with \"quota exceeded\"", m.disk_used_mb, m.quota_mb.map(|q| format!("{q:.0} MB")).unwrap_or_else(|| "?".into()))).fix(Fix {
                            summary: "Raise the quota or delete mail".into(),
                            location: Some("cPanel → Email Accounts → Manage → Storage".into()),
                            ..Default::default()
                        }));
                    } else if m.used_percent >= 90.0 {
                        out.push(
                            Check::new(
                                "acct.mailbox",
                                S,
                                cat,
                                Verdict::Warn,
                                Severity::Medium,
                                format!("the mailbox is {:.0}% full", m.used_percent),
                                format!(
                                    "{:.0} MB used; new mail will start bouncing soon",
                                    m.disk_used_mb
                                ),
                            )
                            .fix_summary("Raise the quota or archive old mail"),
                        );
                    } else {
                        out.push(Check::new("acct.mailbox", S, cat, Verdict::Pass, Severity::Info, "the mailbox exists", format!("{:.0} MB used{}{}", m.disk_used_mb, m.quota_mb.map(|q| format!(" of {q:.0} MB")).unwrap_or_else(|| " (no quota)".into()), if m.suspended_login { " — logins are suspended (receiving works, the user cannot read)" } else { "" })));
                    }
                    if m.suspended_login {
                        out.push(Check::new("acct.mailbox.login", S, cat, Verdict::Warn, Severity::Medium, "logins are suspended for this mailbox", "mail is accepted but the user cannot log in over IMAP/POP/webmail or send").fix(Fix {
                            summary: "Unsuspend logins".into(),
                            location: Some("cPanel → Email Accounts → Manage → Restrictions".into()),
                            ..Default::default()
                        }));
                    }
                }
                Ok(None) => {
                    res.set_fact("acct_mailbox", Json::Bool(false));
                    // maybe an alias — the routing task tells; here: no mailbox
                    out.push(Check::new("acct.mailbox", S, cat, Verdict::Warn, Severity::Info, "no mailbox with this address", "the account has no email account named like this; a forwarder, the default address or a filter may still handle it (see Routing)"));
                }
                Err(e) => out.push(unknown(
                    "acct.mailbox",
                    cat,
                    "mailbox",
                    format!("uapi Email list_pops_with_disk failed: {e}"),
                )),
            },
            None => out.push(unknown(
                "acct.mailbox",
                cat,
                "mailbox",
                "uapi could not be run",
            )),
        }
        // the default (catch-all) address
        let aliases = parse_valiases(&cp.read(&format!("/etc/valiases/{d}")).unwrap_or_default());
        res.set_fact(
            "acct_aliases",
            Json::Array(
                aliases
                    .iter()
                    .map(|a| Json::str(format!("{}: {}", a.local, a.targets.join(", "))))
                    .collect(),
            ),
        );
        match aliases.iter().find(|a| a.local == "*") {
            Some(a) => {
                let t = a.targets.first().map(|t| classify_target(t));
                out.push(match t {
                    Some(Target::Fail(msg)) => Check::new("acct.default_address", S, cat, Verdict::Pass, Severity::Info, "default address: reject unknown recipients", format!("unknown addresses are rejected at SMTP time (\"{msg}\") — the right setting: no backscatter, no spam sink")),
                    Some(Target::Blackhole) => Check::new("acct.default_address", S, cat, Verdict::Warn, Severity::Low, "default address: discard unknown recipients", "mail to non-existent addresses is accepted and silently dropped — senders never learn of a typo, and the server takes every dictionary attack").fix(Fix {
                        summary: "Set the default address to \"Discard with error to sender (at SMTP time)\"".into(),
                        location: Some("cPanel → Default Address".into()),
                        ..Default::default()
                    }),
                    Some(Target::Address(to)) => Check::new("acct.default_address", S, cat, Verdict::Warn, Severity::Medium, format!("default address: forward everything to {}", mask_address(&to)), "a catch-all collects every misaddressed message and all the spam sent to guessed names; if the target is external, the server also forwards spam and hurts its own reputation").fix(Fix {
                        summary: "Prefer rejecting unknown recipients, or at least forward to a local mailbox".into(),
                        location: Some("cPanel → Default Address".into()),
                        ..Default::default()
                    }),
                    Some(other) => Check::new("acct.default_address", S, cat, Verdict::Warn, Severity::Low, "default address: custom handler", format!("{other:?}")),
                    None => Check::new("acct.default_address", S, cat, Verdict::Unknown, Severity::Info, "default address", "the `*:` entry has no target"),
                });
            }
            None => out.push(Check::new(
                "acct.default_address",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                "no default address entry",
                format!("/etc/valiases/{d} has no `*:` line — unknown recipients are rejected"),
            )),
        }
    }
    (out, more)
}

fn route_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Routing;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let d = &ctx.inputs.domain;
    let addr = &ctx.inputs.address;
    let user = res.fact_str("acct_user").unwrap_or_default();
    let home = PathBuf::from(res.fact_str("acct_home").unwrap_or_default());
    let mut out = Vec::new();

    // exim -bt
    match cp.cmd("exim-bt", "exim", &["-bt", addr]) {
        Some((_, text)) => {
            let hops = parse_exim_bt(&text);
            let local = hops
                .iter()
                .filter(|h| {
                    h.transport
                        .as_deref()
                        .is_some_and(|t| t.contains("dovecot") || t.contains("local"))
                })
                .count();
            let remote: Vec<&BtHop> = hops
                .iter()
                .filter(|h| {
                    h.transport
                        .as_deref()
                        .is_some_and(|t| t.contains("remote_smtp"))
                })
                .collect();
            let errors: Vec<&BtHop> = hops.iter().filter(|h| h.error.is_some()).collect();
            let ev = text.trim().to_string();
            if hops.is_empty() {
                out.push(
                    unknown(
                        "route.exim_bt",
                        cat,
                        "Exim routing",
                        "exim -bt printed nothing recognisable",
                    )
                    .evidence("exim -bt", ev),
                );
            } else if !errors.is_empty() && local == 0 && remote.is_empty() {
                let why = errors[0].error.clone().unwrap_or_default();
                out.push(
                    Check::new("route.exim_bt", S, cat, Verdict::Fail, Severity::Critical, format!("Exim cannot deliver {addr}"), format!("`exim -bt` says: {why}. Mail to the address is rejected at RCPT time (\"No Such User Here\") — there is no mailbox, forwarder or default address for it"))
                        .evidence("exim -bt", ev)
                        .fix(Fix {
                            summary: "Create the email account or a forwarder for it".into(),
                            location: Some("cPanel → Email Accounts / Forwarders".into()),
                            ..Default::default()
                        }),
                );
            } else {
                let kind = res.fact_str("acct_kind").unwrap_or_default();
                let mut desc = Vec::new();
                for h in &hops {
                    if let (Some(r), Some(t)) = (&h.router, &h.transport) {
                        desc.push(format!(
                            "{} via {r}/{t}{}",
                            if h.address == *addr {
                                "delivered".to_string()
                            } else {
                                format!("→ {}", mask_other(&h.address, d))
                            },
                            if h.hosts.is_empty() {
                                String::new()
                            } else {
                                format!(" ({})", h.hosts[0])
                            }
                        ));
                    }
                }
                if kind == "local" && local == 0 && !remote.is_empty() {
                    out.push(Check::new("route.exim_bt", S, cat, Verdict::Warn, Severity::Medium, "the address only forwards off-server", format!("{} — nothing is kept locally; if the forwarder target rejects (many do for forwarded spam), the mail is lost or bounced back", desc.join("; "))).evidence("exim -bt", ev));
                } else {
                    out.push(
                        Check::new(
                            "route.exim_bt",
                            S,
                            cat,
                            Verdict::Pass,
                            Severity::Info,
                            "Exim routes the address",
                            desc.join("; "),
                        )
                        .evidence("exim -bt", ev),
                    );
                }
            }
            res.set_fact(
                "route_remote_targets",
                Json::Array(remote.iter().map(|h| Json::str(&h.address)).collect()),
            );
        }
        None => out.push(unknown(
            "route.exim_bt",
            cat,
            "Exim routing",
            "exim -bt could not be run",
        )),
    }

    // forwarders (valiases)
    let aliases: Vec<(String, Vec<String>)> = res
        .fact_strs("acct_aliases")
        .iter()
        .filter_map(|l| {
            l.split_once(": ")
                .map(|(a, b)| (a.to_string(), split_targets(b)))
        })
        .collect();
    let local_part = ctx.inputs.local_part.to_ascii_lowercase();
    if let Some((_, targets)) = aliases
        .iter()
        .find(|(l, _)| l.eq_ignore_ascii_case(&format!("{local_part}@{d}")))
    {
        let external: Vec<String> = targets
            .iter()
            .filter_map(|t| match classify_target(t) {
                Target::Address(a)
                    if !a.ends_with(&format!("@{d}"))
                        && crate::users::owner_of_domain(a.rsplit('@').next().unwrap_or(""))
                            .is_none() =>
                {
                    Some(a)
                }
                _ => None,
            })
            .collect();
        let loops: Vec<String> = targets
            .iter()
            .filter_map(|t| match classify_target(t) {
                Target::Address(a) if a == addr.to_ascii_lowercase() => Some(a),
                _ => None,
            })
            .collect();
        let pipes: Vec<String> = targets
            .iter()
            .filter_map(|t| match classify_target(t) {
                Target::Pipe(p) => Some(p),
                _ => None,
            })
            .collect();
        if !loops.is_empty() {
            out.push(Check::new("route.aliases", S, cat, Verdict::Fail, Severity::High, "the forwarder points at itself", "a forwarder whose target is its own address loops; Exim detects it and bounces").evidence("valiases", targets.join(", ")).fix_summary("Remove the self-referencing target (a forwarder that also keeps a copy is set up in cPanel with the mailbox itself as one target — that is fine only when the mailbox exists)"));
        } else if !external.is_empty() {
            let srs = cp
                .read("/etc/exim.conf.localopts")
                .map(|t| parse_localopts(&t))
                .and_then(|kv| {
                    kv.into_iter()
                        .find(|(k, _)| k == "srs")
                        .map(|(_, v)| v == "1")
                });
            let mut c = Check::new("route.aliases", S, cat, Verdict::Warn, Severity::Medium, format!("forwards to an external address ({})", external.iter().map(|a| mask_address(a)).collect::<Vec<_>>().join(", ")), format!("forwarded mail keeps the original sender's envelope, so the target checks *this server* against the original domain's SPF and fails it; Gmail and Microsoft then junk or reject the copy. Forwarded spam also counts against this server's reputation{}", match srs { Some(true) => " — SRS is enabled, which fixes the SPF part", Some(false) => " — SRS is off", None => "" }))
                .evidence("valiases", targets.join(", "));
            if srs != Some(true) {
                c = c.fix(Fix {
                    summary: "Enable Sender Rewriting Scheme (SRS) so forwarded mail passes SPF at the target, and keep a local copy instead of a pure forward where possible".into(),
                    location: Some("WHM → Exim Configuration Manager → Basic Editor → Mail → Enable Sender Rewriting Scheme (SRS) Support".into()),
                    ..Default::default()
                });
            }
            out.push(c);
        } else if !pipes.is_empty() {
            out.push(
                Check::new(
                    "route.aliases",
                    S,
                    cat,
                    Verdict::Warn,
                    Severity::Low,
                    "the address is piped to a program",
                    pipes.join("; ").to_string(),
                )
                .evidence("valiases", targets.join(", "))
                .fix_summary(
                    "Make sure the program exits 0 on success; a non-zero exit bounces the message",
                ),
            );
        } else {
            out.push(
                Check::new(
                    "route.aliases",
                    S,
                    cat,
                    Verdict::Pass,
                    Severity::Info,
                    "forwarder to local addresses",
                    targets
                        .iter()
                        .map(|t| mask_other(t, d))
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .evidence("valiases", targets.join(", ")),
            );
        }
    }

    // filters: account-level and per-address (Exim filter files)
    let mut filter_notes = Vec::new();
    for (label, path) in [
        ("domain filter", cp.path(&format!("/etc/vfilters/{d}"))),
        (
            "mailbox filter",
            cp.root
                .join(home.strip_prefix("/").unwrap_or(&home))
                .join("etc")
                .join(d)
                .join(&local_part)
                .join("filter"),
        ),
    ] {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let rules = text
                .lines()
                .filter(|l| l.trim_start().starts_with("if "))
                .count();
            let discards = text
                .lines()
                .filter(|l| {
                    l.contains("/dev/null")
                        || l.trim_start().starts_with("seen finish") && !text.contains("save")
                })
                .count();
            if rules > 0 {
                filter_notes.push(format!(
                    "{label}: {rules} rule(s){}",
                    if discards > 0 {
                        format!(", {discards} discard(s)")
                    } else {
                        String::new()
                    }
                ));
            }
        }
    }
    if filter_notes.is_empty() {
        out.push(Check::new(
            "route.filters",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "no email filters",
            "no domain or mailbox filter rules act on this address",
        ));
    } else if filter_notes.iter().any(|n| n.contains("discard")) {
        out.push(Check::new("route.filters", S, cat, Verdict::Warn, Severity::Medium, "filters discard mail", filter_notes.join("; ")).fix(Fix {
            summary: "Review the filter rules that discard (save to /dev/null): a broad condition silently loses wanted mail".into(),
            location: Some("cPanel → Email Filters / Global Email Filters".into()),
            ..Default::default()
        }));
    } else {
        out.push(Check::new(
            "route.filters",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            "email filters present",
            filter_notes.join("; "),
        ));
    }

    // autoresponder and BoxTrapper
    let ar = cp
        .root
        .join(home.strip_prefix("/").unwrap_or(&home))
        .join(".autorespond")
        .join(format!("{local_part}@{d}"));
    if ar.exists() {
        out.push(Check::new("route.autoresponder", S, cat, Verdict::Pass, Severity::Info, "an autoresponder is active", "every sender gets an automatic reply; spammers use that to confirm the address, and replies to forged senders are backscatter"));
    }
    let bt = cp
        .root
        .join(home.strip_prefix("/").unwrap_or(&home))
        .join("etc")
        .join(d)
        .join(&local_part)
        .join("boxtrapper.conf");
    if bt.exists() {
        let enabled = std::fs::read_to_string(&bt)
            .map(|t| {
                t.lines()
                    .any(|l| l.trim() == "enabled=1" || l.trim().starts_with("enabled = 1"))
            })
            .unwrap_or(true);
        if enabled {
            out.push(Check::new("route.boxtrapper", S, cat, Verdict::Warn, Severity::Medium, "BoxTrapper is on", "challenge–response: every unknown sender gets a verification request and their mail waits in a queue. Automated senders (shops, banks, newsletters) never answer, and challenges to forged senders are spam in their own right").fix(Fix {
                summary: "Turn BoxTrapper off and rely on the spam filter".into(),
                location: Some("cPanel → BoxTrapper".into()),
                ..Default::default()
            }));
        }
    }

    // MailScanner and cPanel's own SpamAssassin
    let ms_on = crate::mailflow::scanning_enabled(&ctx.cfg);
    let method = crate::engine::exim_method(&ctx.cfg);
    out.push(match (method.is_some(), ms_on) {
        (true, true) => Check::new("route.mailscanner", S, cat, Verdict::Pass, Severity::Info, "MailScanner scans mail for this address", "Exim hands every message to MailScanner before delivery (see Rules for per-domain settings)"),
        (true, false) => Check::new("route.mailscanner", S, cat, Verdict::Warn, Severity::Medium, "MailScanner is wired but scanning is disabled", "the toggle is off: mail is delivered unscanned").fix(Fix {
            summary: "Re-enable scanning".into(),
            command: Some("msfe-ng exim enable-scanning".into()),
            ..Default::default()
        }),
        (false, _) => Check::new("route.mailscanner", S, cat, Verdict::Warn, Severity::Low, "MailScanner is not in the mail path", "Exim is not wired to MailScanner on this server; only cPanel's own filters apply").fix(Fix {
            summary: "Wire MailScanner".into(),
            command: Some("msfe-ng engine wire".into()),
            ..Default::default()
        }),
    });
    let sa = crate::mailflow::cpanel_sa_state_at(&cp.root);
    let sa_on =
        !sa.off_server_wide() && (sa.forced_on || sa.accounts_on.iter().any(|u| u == &user));
    if sa_on && method.is_some() && ms_on {
        out.push(Check::new("route.cpanel_sa", S, cat, Verdict::Warn, Severity::Low, "cPanel's SpamAssassin scans too (double scan)", "mail is scored twice — by MailScanner and by cPanel's Spam Filters; the second pass adds headers and time and can quarantine what the first already handled").fix(Fix {
            summary: "Turn off cPanel's Spam Filters for the account (MailScanner does the job)".into(),
            command: Some("msfe-ng exim disable-cpanel-spamassassin".into()),
            ..Default::default()
        }));
    } else {
        out.push(Check::new(
            "route.cpanel_sa",
            S,
            cat,
            Verdict::Pass,
            Severity::Info,
            if sa_on {
                "cPanel's Spam Filters are on"
            } else if sa.off_server_wide() {
                "cPanel's SpamAssassin is off server-wide"
            } else {
                "cPanel's Spam Filters are off for this account"
            },
            if sa.service_disabled {
                "the Apache SpamAssassin service is off in WHM → Service Manager; Exim skips it for every account"
            } else if sa.feature_disabled {
                "the spam filter is off in WHM → Tweak Settings; the feature does not exist for any account"
            } else if sa.forced_on {
                "forced on for every account (/etc/global_spamassassin_enable)"
            } else {
                "per-account setting"
            },
        ));
    }
    if let Some(v) = cp.whmapi1("cpgreylist_status", "cpgreylist_status", &[]) {
        let on = matches!(
            v.get("data").and_then(|d| d.get("is_enabled")),
            Some(Json::Int(1))
        );
        out.push(Check::new("route.greylist", S, cat, Verdict::Pass, Severity::Info, if on { "cPanel Greylisting is on" } else { "cPanel Greylisting is off" }, if on { "first contact from an unknown host is deferred for a few minutes; legitimate senders retry, most spam bots do not — expect delayed first messages" } else { "no greylisting delay on inbound mail" }));
    }
    (out, vec![])
}

/// Mask addresses that are not the tested domain's.
fn mask_other(addr: &str, domain: &str) -> String {
    if addr.to_ascii_lowercase().ends_with(&format!("@{domain}")) {
        addr.to_string()
    } else {
        mask_address(addr)
    }
}

fn out_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::OutboundIdentity;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let d = &ctx.inputs.domain;
    let mut out = Vec::new();
    let localopts = parse_localopts(&cp.read("/etc/exim.conf.localopts").unwrap_or_default());
    let opt = |k: &str| {
        localopts
            .iter()
            .find(|(x, _)| x == k)
            .map(|(_, v)| v.as_str())
    };

    // the IP mail leaves from
    let mainip: Option<IpAddr> = cp
        .read("/var/cpanel/mainip")
        .and_then(|t| t.trim().parse().ok());
    let per_domain = opt("per_domain_mailips") == Some("1") || opt("custom_mailips") == Some("1");
    let mailips = cp
        .read("/etc/mailips")
        .map(|t| parse_mailips(&t, d))
        .unwrap_or(None);
    let out_ip = if per_domain {
        mailips.or(mainip)
    } else {
        mailips
            .filter(|_| opt("custom_mailips") == Some("1"))
            .or(mainip)
    };
    match out_ip {
        Some(ip) => {
            res.set_fact("out_ip", Json::str(ip.to_string()));
            let note = if mailips.is_some() && per_domain {
                "from /etc/mailips (per-domain sending IP)"
            } else {
                "the server's main IP (/var/cpanel/mainip)"
            };
            let mut c = Check::new(
                "out.ip",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                format!("mail from {d} leaves from {ip}"),
                note.to_string(),
            );
            if let Some(given) = ctx.inputs.ip {
                if given != ip {
                    c = Check::new("out.ip", S, cat, Verdict::Warn, Severity::Low, format!("mail from {d} leaves from {ip}, not {given}"), format!("{note}; the sending IP entered under Advanced differs — the SPF and blocklist rows above were computed for {given}")).fix_summary(format!("Re-run the test with sending IP {ip}, or check /etc/mailips if a dedicated IP was intended"));
                }
            }
            out.push(c);
        }
        None => out.push(unknown(
            "out.ip",
            cat,
            "outbound IP",
            "/var/cpanel/mainip and /etc/mailips give no address",
        )),
    }

    // HELO name
    let helo = cp
        .read("/etc/mailhelo")
        .and_then(|t| parse_mailhelo(&t, d))
        .or_else(|| cp.read("/etc/hostname").map(|h| h.trim().to_string()))
        .or_else(|| {
            cp.cmd("hostname", "hostname", &["-f"])
                .map(|(_, t)| t.trim().to_string())
        })
        .unwrap_or_default();
    if helo.is_empty() {
        out.push(unknown(
            "out.helo",
            cat,
            "HELO name",
            "no /etc/mailhelo entry and no hostname",
        ));
    } else {
        res.set_fact("out_helo", Json::str(&helo));
        // FCrDNS of the HELO name against the outbound IP
        match (out_ip, ctx.dns.addrs(&helo)) {
            (Some(ip), Ok((v4, v6))) => {
                let forward_ok = v4.iter().any(|a| IpAddr::V4(*a) == ip)
                    || v6.iter().any(|a| IpAddr::V6(*a) == ip);
                let ptr = ctx.dns.ptr(ip).unwrap_or_default();
                let ptr_ok = ptr.iter().any(|p| p.eq_ignore_ascii_case(&helo));
                if forward_ok && ptr_ok {
                    out.push(Check::new(
                        "out.helo",
                        S,
                        cat,
                        Verdict::Pass,
                        Severity::Info,
                        format!("HELO {helo} matches the outbound IP both ways"),
                        format!("{helo} → {ip} and the PTR of {ip} is {helo} (FCrDNS)"),
                    ));
                } else if forward_ok {
                    out.push(Check::new("out.helo", S, cat, Verdict::Warn, Severity::Medium, format!("the PTR of {ip} is not {helo}"), format!("the HELO name resolves to the outbound IP, but the reverse name is {}; strict receivers (and many blocklists) want the PTR to match the HELO", if ptr.is_empty() { "missing".to_string() } else { ptr.join(", ") })).fix_summary(format!("Set the PTR of {ip} to {helo} at the hosting provider (Hetzner: Robot/Cloud console → rDNS), or set the HELO to the PTR name in /etc/mailhelo")));
                } else {
                    out.push(Check::new("out.helo", S, cat, Verdict::Fail, Severity::High, format!("HELO {helo} does not resolve to the outbound IP {ip}"), format!("the server introduces itself with a name that points elsewhere ({}); Microsoft and many others reject or junk such mail", if v4.is_empty() && v6.is_empty() { "no address at all".to_string() } else { v4.iter().map(|a| a.to_string()).chain(v6.iter().map(|a| a.to_string())).collect::<Vec<_>>().join(", ") })).fix(Fix {
                        summary: format!("Make {helo} resolve to {ip} (A record) and set the PTR of {ip} to {helo}"),
                        dns_record: Some(format!("{helo}. 3600 IN A {ip}")),
                        location: Some("WHM → Basic WebHost Manager Setup → hostname, and the DNS zone of the hostname's domain".into()),
                        ..Default::default()
                    }));
                }
            }
            (Some(_), Err(e)) => out.push(unknown(
                "out.helo",
                cat,
                &format!("HELO {helo}"),
                format!("could not resolve: {e}"),
            )),
            (None, _) => out.push(unknown(
                "out.helo",
                cat,
                &format!("HELO {helo}"),
                "no outbound IP to compare with",
            )),
        }
        if opt("use_rdns_for_helo") == Some("1") {
            out.push(Check::new("out.helo.rdns", S, cat, Verdict::Pass, Severity::Info, "Exim uses the reverse DNS name as HELO", "cPanel's `use_rdns_for_helo` — the HELO follows each sending IP's PTR, which keeps HELO and PTR consistent"));
        }
    }

    // is the outbound IP in the domain's SPF?
    if let Some(ip) = out_ip {
        if res.fact_str("spf_record").is_some()
            && std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_none()
        {
            let (r, trace) = crate::spf::evaluate(&ctx.dns, d, ip);
            use crate::spf::SpfResult;
            out.push(match r {
                SpfResult::Pass => Check::new("out.spf_includes_ip", S, cat, Verdict::Pass, Severity::Info, format!("SPF authorises {ip}"), "mail sent from this server passes the domain's SPF").evidence("evaluation", trace.join("\n")),
                SpfResult::Fail | SpfResult::SoftFail => Check::new("out.spf_includes_ip", S, cat, Verdict::Fail, Severity::Critical, format!("SPF does not authorise this server ({ip})"), format!("the domain's SPF evaluates to {} for the IP the server sends from — receivers junk or reject, and DMARC fails on the SPF side", r.as_str()))
                    .evidence("evaluation", trace.join("\n"))
                    .fix(Fix {
                        summary: "Add this server to the SPF record".to_string(),
                        dns_record: Some(format!("{d}. 3600 IN TXT \"v=spf1 {} … -all\"  (add ip{}:{ip})", res.fact_str("spf_record").map(|s| s.trim_start_matches("v=spf1").trim().trim_end_matches("-all").trim_end_matches("~all").trim().to_string()).unwrap_or_default(), if ip.is_ipv4() { "4" } else { "6" })),
                        location: Some("cPanel → Email Deliverability → Manage → SPF → Repair (cPanel writes the record including this server's IPs)".into()),
                        ..Default::default()
                    }),
                SpfResult::Neutral | SpfResult::None => Check::new("out.spf_includes_ip", S, cat, Verdict::Warn, Severity::High, format!("SPF gives no verdict for {ip}"), format!("result {} — the record neither allows nor forbids this server; DMARC needs a pass", r.as_str())).evidence("evaluation", trace.join("\n")).fix_summary("Add this server's IP to the SPF record (cPanel → Email Deliverability → Repair)"),
                SpfResult::PermError => Check::new("out.spf_includes_ip", S, cat, Verdict::Fail, Severity::High, "SPF is broken (permerror)", "receivers treat a permanent error as no SPF at all").evidence("evaluation", trace.join("\n")).fix_summary("Fix the record (see the SPF rows above)"),
                SpfResult::TempError => unknown("out.spf_includes_ip", cat, "SPF evaluation", "temporary DNS error").evidence("evaluation", trace.join("\n")),
            });
        }
    }

    // cPanel's DKIM key vs what DNS publishes
    let key_file = cp.read(&format!("/var/cpanel/domain_keys/public/{d}"));
    match key_file {
        None => out.push(Check::new("out.dkim_cpanel", S, cat, Verdict::Fail, Severity::High, "no DKIM key on this server for the domain", "cPanel has no key under /var/cpanel/domain_keys, so outgoing mail is not signed").fix(Fix {
            summary: "Install DKIM for the domain (cPanel generates a 2048-bit key and publishes default._domainkey)".into(),
            location: Some("cPanel → Email Deliverability → Manage → DKIM → Install / Repair".into()),
            ..Default::default()
        })),
        Some(pem) => {
            let local_key = pem_to_der_b64(&pem);
            let published: Vec<String> = ctx.dns.txt(&format!("default._domainkey.{d}")).unwrap_or_default();
            let pub_key = published.iter().find(|t| t.contains("p=")).map(|t| crate::dkim::parse_record("default", t));
            match pub_key {
                Some(k) if !k.revoked && crate::b64::encode(&k.p) == local_key => {
                    out.push(Check::new("out.dkim_cpanel", S, cat, Verdict::Pass, Severity::Info, "DKIM: the published key matches this server's", "outgoing mail is signed with selector default and receivers can verify it"));
                }
                Some(_) => out.push(Check::new("out.dkim_cpanel", S, cat, Verdict::Fail, Severity::High, "DKIM: the published key differs from this server's", "default._domainkey in DNS holds another key (or a revoked one) — the signatures this server adds fail verification, which is worse than no signature under DMARC. Typical after a DNS move or a key rotation on another server").fix(Fix {
                    summary: "Publish this server's key (if DNS is hosted elsewhere, copy the record cPanel shows)".into(),
                    dns_record: Some(format!("default._domainkey.{d}. 3600 IN TXT \"v=DKIM1; k=rsa; p={local_key}\"")),
                    location: Some("cPanel → Email Deliverability → Manage → DKIM → Repair (or copy the suggested record to the external DNS)".into()),
                    ..Default::default()
                })),
                None => out.push(Check::new("out.dkim_cpanel", S, cat, Verdict::Fail, Severity::High, "DKIM key exists here but is not published", format!("default._domainkey.{d} has no DKIM record; outgoing mail is signed with a key receivers cannot fetch — DKIM fails")).fix(Fix {
                    summary: "Publish the DKIM record".into(),
                    dns_record: Some(format!("default._domainkey.{d}. 3600 IN TXT \"v=DKIM1; k=rsa; p={local_key}\"")),
                    location: Some("cPanel → Email Deliverability → Manage → DKIM → Repair".into()),
                    ..Default::default()
                })),
            }
        }
    }

    // smarthost / queue_only
    match opt("smarthost_routelist") {
        Some(v) if !v.trim().is_empty() => out.push(Check::new("out.smarthost", S, cat, Verdict::Pass, Severity::Info, "outgoing mail goes through a smarthost", format!("route list: {v} — the smarthost's IP, not this server's, must be in SPF")).fix_summary("Make sure the smarthost is covered by the domain's SPF (an include: of the provider)")),
        _ => out.push(Check::new("out.smarthost", S, cat, Verdict::Pass, Severity::Info, "direct delivery (no smarthost)", "Exim delivers to recipients' MX hosts itself")),
    }
    let exim_conf = std::fs::read_to_string(crate::engine::exim_conf_path()).unwrap_or_default();
    if exim_conf
        .lines()
        .any(|l| l.trim() == "queue_only" || l.trim().starts_with("queue_only "))
        && crate::engine::exim_method(&ctx.cfg) != Some(crate::engine::EximMethod::TwoConfig)
    {
        out.push(Check::new("out.queue_only", S, cat, Verdict::Warn, Severity::Medium, "Exim is in queue_only mode", "messages are queued and delivered only by queue runner passes — every delivery waits for the next run").fix_summary("Remove `queue_only` from the Exim configuration unless a scanner is meant to pick the queue up"));
    }

    // can the server reach port 25 outside?
    if std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_some() || !cp.live() {
        out.push(unknown(
            "out.port25",
            cat,
            "outbound port 25",
            "network probes are disabled",
        ));
    } else {
        let probe_host = "gmail-smtp-in.l.google.com";
        match ctx.dns.addrs(probe_host) {
            Ok((v4, _)) if !v4.is_empty() => {
                let ips: Vec<IpAddr> = v4.iter().take(2).map(|a| IpAddr::V4(*a)).collect();
                match crate::smtpprobe::outbound_25_reachable(probe_host, &ips, Duration::from_secs(8)) {
                    Ok((ip, banner)) => out.push(Check::new("out.port25", S, cat, Verdict::Pass, Severity::Info, "outbound port 25 is open", format!("{probe_host} [{ip}] greeted: {banner}"))),
                    Err(e) => out.push(Check::new("out.port25", S, cat, Verdict::Fail, Severity::Critical, "outbound port 25 is blocked", format!("connecting to {probe_host}: {e}. Without port 25 the server cannot deliver to any external MX — every outgoing message stays in the queue")).fix(Fix {
                        summary: "Open outbound TCP 25 (csf TCP_OUT, SMTP_BLOCK) or ask the hosting provider to unblock the port; otherwise route through a smarthost on port 587".into(),
                        location: Some("WHM → ConfigServer Security & Firewall → Firewall Configuration → TCP_OUT / SMTP_BLOCK".into()),
                        ..Default::default()
                    })),
                }
            }
            _ => out.push(unknown(
                "out.port25",
                cat,
                "outbound port 25",
                "could not resolve the probe host",
            )),
        }
    }

    // reputation of the outbound IP (the sender-side lists)
    if let Some(ip) = out_ip {
        if ctx.inputs.ip != Some(ip) {
            // not already covered by rbl.sender: query the lists now
            let mut listed = Vec::new();
            let mut problems = Vec::new();
            for list in crate::dnsbl::lists_for(if ip.is_ipv4() {
                crate::dnsbl::Kind::Ip4
            } else {
                crate::dnsbl::Kind::Ip6
            })
            .into_iter()
            .filter(|l| l.polarity == crate::dnsbl::Polarity::Block)
            {
                match crate::dnsbl::query_ip(&ctx.dns, list, ip) {
                    crate::dnsbl::ListVerdict::Listed(l) => listed.push(format!(
                        "{}: {} (see {})",
                        list.name,
                        l.iter()
                            .map(|x| x.meaning.clone())
                            .collect::<Vec<_>>()
                            .join("; "),
                        list.removal_url
                    )),
                    crate::dnsbl::ListVerdict::Refused(w) => {
                        problems.push(format!("{}: {w}", list.name))
                    }
                    crate::dnsbl::ListVerdict::NoAnswer => {
                        problems.push(format!("{}: no answer", list.name))
                    }
                    _ => {}
                }
            }
            out.push(if !listed.is_empty() {
                Check::new("out.ip_reputation", S, cat, Verdict::Fail, Severity::High, format!("outbound IP {ip} is on a blocklist"), listed.join(" · ")).evidence("listings", listed.join("\n")).fix_summary("Find the cause (compromised account, script, open relay — see the logs rows), stop it, then request delisting at the list's page")
            } else if problems.len() >= 4 {
                unknown("out.ip_reputation", cat, &format!("blocklists for {ip}"), "most lists refused or did not answer this resolver").evidence("lists", problems.join("\n")).fix_summary("Install the private resolver: msfe-ng resolver install")
            } else {
                Check::new("out.ip_reputation", S, cat, Verdict::Pass, Severity::Info, format!("outbound IP {ip} is on no blocklist"), if problems.is_empty() { "all lists answered".to_string() } else { format!("{} list(s) did not answer", problems.len()) })
            });
        }
    }
    (out, vec![])
}

/// The base64 DER of a PEM public key (cPanel's domain_keys file).
pub fn pem_to_der_b64(pem: &str) -> String {
    pem.lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect::<Vec<_>>()
        .concat()
}

fn svc_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Services;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let mut out = Vec::new();
    for (svc, sev, why) in [
        ("exim", Severity::Critical, "no mail is received or sent"),
        (
            "dovecot",
            Severity::Critical,
            "no IMAP/POP logins and local delivery fails (dovecot_virtual_delivery)",
        ),
        ("cphulkd", Severity::Low, "brute-force protection is off"),
        (
            "mailscanner",
            Severity::High,
            "mail queues in the MailScanner queue and is not delivered",
        ),
    ] {
        match cp.cmd(
            &format!("systemctl-{svc}"),
            "systemctl",
            &["is-active", svc],
        ) {
            Some((_, t)) => {
                let state = t.trim().to_string();
                out.push(if state == "active" {
                    Check::new(
                        format!("svc.{svc}"),
                        S,
                        cat,
                        Verdict::Pass,
                        Severity::Info,
                        format!("{svc} is running"),
                        "active",
                    )
                    .target(svc)
                } else if svc == "mailscanner" && crate::engine::exim_method(&ctx.cfg).is_none() {
                    na(
                        &format!("svc.{svc}"),
                        cat,
                        format!("{svc} is not running"),
                        "MailScanner is not wired into Exim here, so this does not affect delivery",
                    )
                    .target(svc)
                } else {
                    Check::new(
                        format!("svc.{svc}"),
                        S,
                        cat,
                        Verdict::Fail,
                        sev,
                        format!("{svc} is {state}"),
                        why,
                    )
                    .target(svc)
                    .fix(Fix {
                        summary: "Start the service and look at its log for why it stopped"
                            .to_string(),
                        command: Some(format!("systemctl start {svc} && systemctl status {svc}")),
                        location: Some("WHM → Service Manager".into()),
                        ..Default::default()
                    })
                });
            }
            None => out.push(
                unknown(
                    &format!("svc.{svc}"),
                    cat,
                    svc,
                    "systemctl could not be run",
                )
                .target(svc),
            ),
        }
    }
    // listeners
    match cp.cmd("ss", "ss", &["-ltnH"]) {
        Some((_, t)) => {
            let ports = parse_ss_listeners(&t);
            let need = [
                (25, Severity::Critical, "SMTP — no inbound mail at all"),
                (465, Severity::Medium, "SMTPS submission"),
                (
                    587,
                    Severity::Medium,
                    "submission (STARTTLS) — mail clients cannot send",
                ),
                (143, Severity::Low, "IMAP"),
                (993, Severity::Medium, "IMAPS"),
                (110, Severity::Low, "POP3"),
                (995, Severity::Low, "POP3S"),
            ];
            let missing: Vec<String> = need
                .iter()
                .filter(|(p, _, _)| !ports.contains(p))
                .map(|(p, _, w)| format!("{p} ({w})"))
                .collect();
            if missing.is_empty() {
                out.push(
                    Check::new(
                        "svc.listeners",
                        S,
                        cat,
                        Verdict::Pass,
                        Severity::Info,
                        "all mail ports are listening",
                        "25, 465, 587, 143, 993, 110, 995",
                    )
                    .evidence(
                        "ss -ltn",
                        t.lines()
                            .filter(|l| need.iter().any(|(p, _, _)| l.contains(&format!(":{p} "))))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                );
            } else {
                let worst = need
                    .iter()
                    .filter(|(p, _, _)| !ports.contains(p))
                    .map(|(_, s, _)| *s)
                    .min()
                    .unwrap_or(Severity::Low);
                out.push(Check::new("svc.listeners", S, cat, if worst <= Severity::High { Verdict::Fail } else { Verdict::Warn }, worst, format!("not listening on {}", missing.join(", ")), "the service for these ports is down or bound elsewhere").evidence("ss -ltn", t.clone()).fix(Fix {
                    summary: "Check the services (exim, dovecot) and their port configuration".into(),
                    location: Some("WHM → Service Manager; WHM → Exim Configuration Manager → Basic Editor → Options → daemon ports".into()),
                    ..Default::default()
                }));
            }
        }
        None => out.push(unknown(
            "svc.listeners",
            cat,
            "listening ports",
            "ss could not be run",
        )),
    }
    // csf ports
    if let Some(csf) = cp.read("/etc/csf/csf.conf") {
        let get = |k: &str| {
            csf.lines().find_map(|l| {
                l.strip_prefix(&format!("{k} = "))
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        let has = |list: &str, port: u16| {
            list.split(',').any(|p| {
                p.trim() == port.to_string()
                    || p.trim().split_once(':').is_some_and(|(a, b)| {
                        a.trim().parse::<u16>().is_ok_and(|a| a <= port)
                            && b.trim().parse::<u16>().is_ok_and(|b| b >= port)
                    })
            })
        };
        let (tcp_in, tcp_out) = (
            get("TCP_IN").unwrap_or_default(),
            get("TCP_OUT").unwrap_or_default(),
        );
        let missing_in: Vec<u16> = [25, 465, 587, 143, 993, 110, 995]
            .into_iter()
            .filter(|p| !has(&tcp_in, *p))
            .collect();
        let out25 = has(&tcp_out, 25);
        let smtp_block = get("SMTP_BLOCK").as_deref() == Some("1");
        let mut notes = Vec::new();
        if !missing_in.is_empty() {
            notes.push(format!(
                "TCP_IN lacks {}",
                missing_in
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !out25 {
            notes.push("TCP_OUT lacks 25 (no outbound SMTP)".into());
        }
        notes.dedup();
        let critical = missing_in.contains(&25) || !out25;
        out.push(if notes.is_empty() {
            Check::new("svc.csf_ports", S, cat, Verdict::Pass, Severity::Info, "csf allows the mail ports", format!("TCP_IN and TCP_OUT cover them{}", if smtp_block { "; SMTP_BLOCK is on (only exim/mailman/root may connect out on 25 — the right setting)" } else { "" }))
        } else {
            Check::new("svc.csf_ports", S, cat, if critical { Verdict::Fail } else { Verdict::Warn }, if critical { Severity::Critical } else { Severity::Medium }, "csf blocks mail ports", notes.join("; ")).evidence("csf.conf", format!("TCP_IN = {tcp_in}\nTCP_OUT = {tcp_out}\nSMTP_BLOCK = {}", if smtp_block { 1 } else { 0 })).fix(Fix {
                summary: "Add the ports to TCP_IN / TCP_OUT and restart csf".into(),
                location: Some("WHM → ConfigServer Security & Firewall → Firewall Configuration".into()),
                command: Some("csf -r".into()),
                ..Default::default()
            })
        });
    }
    // Exim version and secure auth
    if let Some((_, bv)) = cp.cmd("exim-bV", "exim", &["-bV"]) {
        let ver = crate::engine::exim_version(&bv)
            .map(|(a, b)| format!("{a}.{b}"))
            .unwrap_or_else(|| "unknown".into());
        let localopts = parse_localopts(&cp.read("/etc/exim.conf.localopts").unwrap_or_default());
        let secure = localopts
            .iter()
            .any(|(k, v)| k == "require_secure_auth" && v == "1");
        out.push(Check::new("svc.exim_version", S, cat, Verdict::Pass, Severity::Info, format!("Exim {ver}"), (if secure { "authentication requires TLS (require_secure_auth)" } else { "plain-text authentication is allowed on port 25/587 without TLS (require_secure_auth=0)" }).to_string()));
        if !secure {
            out.push(Check::new("svc.secure_auth", S, cat, Verdict::Warn, Severity::Medium, "SMTP AUTH without TLS is allowed", "passwords can travel in clear text; also a favourite of credential-stuffing bots").fix(Fix {
                summary: "Require TLS for authentication".into(),
                location: Some("WHM → Exim Configuration Manager → Basic Editor → Security → Require clients to connect with SSL or issue the STARTTLS command before they are allowed to authenticate".into()),
                ..Default::default()
            }));
        }
    }
    // local TLS on submission
    if cp.live() && std::env::var_os("MSFE_NG_DELIVERY_NO_NET").is_none() {
        let name = format!("mail.{}", ctx.inputs.domain);
        let t = crate::tlsprobe::starttls(
            "127.0.0.1".parse().unwrap(),
            587,
            &name,
            &[],
            Duration::from_secs(10),
        );
        out.push(match (&t.protocol, t.verify_code, t.leaf.as_ref()) {
            (None, _, _) => Check::new("svc.tls_local", S, cat, Verdict::Warn, Severity::Medium, "no TLS on the submission port", format!("STARTTLS on 127.0.0.1:587 failed: {}", t.error.clone().unwrap_or_default())).evidence("openssl", t.transcript.clone()).fix_summary("Check Exim's TLS configuration and certificate (WHM → Service Manager / Manage Service SSL Certificates)"),
            (Some(_), Some(0), Some(leaf)) if crate::tlsprobe::hostname_matches(&leaf.sans, leaf.subject_cn.as_deref(), &name) => Check::new("svc.tls_local", S, cat, Verdict::Pass, Severity::Info, format!("submission TLS presents a valid certificate for {name}"), format!("issuer {}", leaf.issuer)),
            (Some(_), Some(0), Some(leaf)) => Check::new("svc.tls_local", S, cat, Verdict::Warn, Severity::Low, format!("the submission certificate does not name {name}"), format!("clients configured with {name} get a certificate warning; the certificate covers {}", leaf.sans.join(", "))).fix(Fix {
                summary: format!("Let AutoSSL cover {name} (the mail. subdomain is included by default when it resolves here), or tell clients to use the server hostname"),
                location: Some("WHM → Manage AutoSSL → Run".into()),
                ..Default::default()
            }),
            (Some(_), code, _) => Check::new("svc.tls_local", S, cat, Verdict::Warn, Severity::Medium, "the submission certificate is not trusted", format!("openssl verify code {} ({}); mail clients show warnings and some refuse", code.unwrap_or(-1), t.verify_text)).evidence("openssl", t.transcript.clone()).fix(Fix {
                summary: "Install a trusted certificate for the mail service (AutoSSL covers the hostname and mail.<domain>)".into(),
                location: Some("WHM → Manage Service SSL Certificates → Exim / Dovecot".into()),
                ..Default::default()
            }),
        });
    }
    (out, vec![])
}

fn limit_task(ctx: &Ctx, res: &Results) -> (Vec<Check>, Vec<Task>) {
    let cat = Category::Limits;
    if res.fact_bool("acct_hosted") != Some(true) {
        return (vec![], vec![]);
    }
    let cp = Cp::detect();
    let user = res.fact_str("acct_user").unwrap_or_default();
    let acct = resolve_account(&cp, &ctx.inputs.domain);
    let mut out = Vec::new();
    let localopts = parse_localopts(&cp.read("/etc/exim.conf.localopts").unwrap_or_default());
    let opt = |k: &str| {
        localopts
            .iter()
            .find(|(x, _)| x == k)
            .map(|(_, v)| v.as_str())
    };

    // hourly limit vs the last hour of authenticated sends by the account's addresses
    let max = acct.as_ref().and_then(|a| a.max_email_per_hour);
    let domains: Vec<String> = if cp.live() {
        crate::users::user_domains(&user)
    } else {
        vec![ctx.inputs.domain.clone()]
    };
    let sent = recent_auth_sends(&cp, &ctx.cfg, &user, &domains);
    match (max, sent) {
        (Some(0), _) => out.push(Check::new("limit.hourly", S, cat, Verdict::Pass, Severity::Info, "no hourly sending limit", "MAX_EMAIL_PER_HOUR=0 (unlimited)")),
        (Some(m), Some(n)) => {
            let pct = n * 100 / m.max(1);
            out.push(if n >= m {
                Check::new("limit.hourly", S, cat, Verdict::Fail, Severity::High, format!("hourly limit reached: {n} of {m} messages"), "cPanel defers further mail from the account (\"Domain has exceeded the max emails per hour\") until the hour rolls over; a burst like this from a small site usually means a compromised mailbox or script").fix(Fix {
                    summary: "Check who is sending (Logs → outbound bursts, the abuse rows below); raise the limit only if the volume is legitimate".into(),
                    location: Some("WHM → Modify an Account → Maximum Hourly Email by Domain Relayed".into()),
                    ..Default::default()
                })
            } else if pct >= 80 {
                Check::new("limit.hourly", S, cat, Verdict::Warn, Severity::Medium, format!("{pct}% of the hourly limit used ({n} of {m})"), "close to the point where cPanel defers outgoing mail").fix_summary("Raise the limit (WHM → Modify an Account) or spread the sending")
            } else {
                Check::new("limit.hourly", S, cat, Verdict::Pass, Severity::Info, format!("{n} of {m} messages in the last hour"), "under the account's hourly limit")
            });
        }
        (Some(m), None) => out.push(Check::new("limit.hourly", S, cat, Verdict::Pass, Severity::Info, format!("hourly limit {m}"), "the last hour's count could not be read from the Exim log")),
        (None, _) => out.push(Check::new("limit.hourly", S, cat, Verdict::Pass, Severity::Info, "hourly limit: server default", "MAX_EMAIL_PER_HOUR is not set for the account (WHM → Tweak Settings → Max hourly emails per domain applies)")),
    }
    if let Some(a) = &acct {
        if let Some(p) = &a.max_defer_fail_percentage {
            if p != "unlimited" && p != "0" {
                out.push(Check::new("limit.defer_fail", S, cat, Verdict::Pass, Severity::Info, format!("defer/fail cutoff {p}%"), "when more than this share of the account's mail in an hour is deferred or fails, cPanel stops accepting its outgoing mail for the rest of the hour — a bad recipient list triggers it"));
            }
        }
    }
    // ACL options that shape acceptance
    let mut notes = Vec::new();
    let mut warns = Vec::new();
    if opt("senderverify") == Some("0") {
        warns.push("sender verification is off: mail from non-existent sender addresses is accepted (more spam, and backscatter when it bounces)");
    }
    if opt("acl_ratelimit") == Some("1") {
        notes.push("rate limiting of incoming connections is on");
    }
    if opt("acl_dictionary_attack") == Some("1") {
        notes.push("dictionary-attack protection is on");
    }
    if opt("acl_requirehelo") == Some("1") {
        notes.push("HELO is required");
    }
    if opt("acl_spamcop_rbl") == Some("1") || opt("acl_spamhaus_rbl") == Some("1") {
        notes.push(
            "Exim rejects at SMTP time by RBL (Spamhaus/SpamCop) before MailScanner sees the mail",
        );
    }
    if opt("acl_delay_unknown_hosts") == Some("1") {
        notes.push(
            "greeting delay for unknown hosts (the greet-pause seen in the Mail servers rows)",
        );
    }
    if let Some(h) = opt("spam_header") {
        if !h.is_empty() {
            notes.push("cPanel's SpamAssassin tags subjects");
        }
    }
    if opt("exiscanall") == Some("1") {
        notes.push("exiscanall: cPanel scans mail from authenticated senders too");
    }
    if let Some(w) = opt("rbl_whitelist") {
        if !w.trim().is_empty() {
            notes.push("an RBL whitelist is configured");
        }
    }
    out.push(if warns.is_empty() {
        Check::new("limit.ratelimit_acl", S, cat, Verdict::Pass, Severity::Info, "Exim acceptance options", if notes.is_empty() { "defaults".to_string() } else { notes.join("; ") })
    } else {
        Check::new("limit.ratelimit_acl", S, cat, Verdict::Warn, Severity::Low, "Exim acceptance options worth a look", format!("{}{}", warns.join("; "), if notes.is_empty() { String::new() } else { format!(". Also: {}", notes.join("; ")) })).fix(Fix {
            summary: "Turn sender verification on".into(),
            location: Some("WHM → Exim Configuration Manager → Basic Editor → ACL Options → Sender Verification".into()),
            ..Default::default()
        })
    });
    // cPanel SpamAssassin per-account settings
    if let Some(a) = &acct {
        let home = cp.root.join(a.home.strip_prefix("/").unwrap_or(&a.home));
        let sa = crate::mailflow::cpanel_sa_state_at(&cp.root);
        let sa_on = !sa.off_server_wide()
            && (home.join(".spamassassinenable").exists()
                || cp.exists("/etc/global_spamassassin_enable"));
        if sa_on {
            let prefs =
                std::fs::read_to_string(home.join(".spamassassin/user_prefs")).unwrap_or_default();
            let score = prefs.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("required_score")
                    .map(|v| v.trim().to_string())
            });
            let autodelete = cp
                .read(&format!("/etc/vfilters/{}", ctx.inputs.domain))
                .is_some_and(|t| t.contains("/dev/null"));
            let mut c = Check::new(
                "limit.spamassassin",
                S,
                cat,
                Verdict::Pass,
                Severity::Info,
                "cPanel Spam Filters on",
                format!(
                    "required score {}{}",
                    score.clone().unwrap_or_else(|| "5 (default)".into()),
                    if home.join(".spamassassinboxenable").exists() {
                        ", spam goes to the Spam Box folder"
                    } else {
                        ""
                    }
                ),
            );
            if autodelete {
                c = Check::new("limit.spamassassin", S, cat, Verdict::Warn, Severity::Medium, "cPanel auto-deletes spam", format!("a domain filter discards messages above the spam score ({}); false positives are lost without a trace", score.unwrap_or_else(|| "5".into()))).fix(Fix {
                    summary: "Prefer the Spam Box (a folder) over auto-delete, or raise the auto-delete threshold well above the tag score".into(),
                    location: Some("cPanel → Spam Filters → Automatically Delete New Spam".into()),
                    ..Default::default()
                });
            }
            out.push(c);
        }
    }
    (out, vec![])
}

/// Authenticated sends in the last hour by `user` or any address at the
/// account's domains (the tail of the Exim main log).
fn recent_auth_sends(
    cp: &Cp,
    cfg: &crate::config::Config,
    user: &str,
    domains: &[String],
) -> Option<u64> {
    let path = if cp.live() {
        PathBuf::from(&cfg.exim_mainlog_path)
    } else {
        cp.path("/var/log/exim_mainlog")
    };
    let text = tail_bytes(&path, 8 * 1024 * 1024)?;
    let cutoff = if cp.live() {
        let out = Command::new("date")
            .args(["-d", "60 minutes ago", "+%Y-%m-%d %H:%M:%S"])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    } else {
        "0000-00-00 00:00:00".to_string()
    };
    let counts = crate::monitor::count_auth_sends(&text, &cutoff);
    Some(
        counts
            .iter()
            .filter(|(login, _)| {
                login.as_str() == user
                    || domains
                        .iter()
                        .any(|d| login.to_ascii_lowercase().ends_with(&format!("@{d}")))
            })
            .map(|(_, n)| *n as u64)
            .sum(),
    )
}

/// The last `max` bytes of a file as text (from the first full line).
pub fn tail_bytes(path: &Path, max: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 {
        if let Some(nl) = text.find('\n') {
            text = text[nl + 1..].to_string();
        }
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BT_FORWARD: &str = "booking@transfervda.com\n    <-- booking@transfervda.com\n  router = virtual_user, transport = dovecot_virtual_delivery\ntaxiaosta@gmail.com\n    <-- booking@transfervda.com\n    <-- booking@transfervda.com\n  router = lookuphost, transport = remote_smtp\n  host gmail-smtp-in.l.google.com      [64.233.167.27]  MX=5\n  host alt1.gmail-smtp-in.l.google.com [142.250.147.27] MX=10\n";

    #[test]
    fn parses_exim_bt() {
        let hops = parse_exim_bt(BT_FORWARD);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].router.as_deref(), Some("virtual_user"));
        assert_eq!(
            hops[0].transport.as_deref(),
            Some("dovecot_virtual_delivery")
        );
        assert_eq!(hops[1].address, "taxiaosta@gmail.com");
        assert_eq!(hops[1].parents.len(), 2);
        assert_eq!(hops[1].hosts.len(), 2);
        assert!(hops[1].hosts[0].starts_with("gmail-smtp-in.l.google.com [64.233.167.27] MX=5"));
        let hops =
            parse_exim_bt("webmaster@transfervda.com is undeliverable: No Such User Here\"\n");
        assert_eq!(hops[0].error.as_deref(), Some("No Such User Here"));
        let hops = parse_exim_bt(
            "info@transfervda.com\n  router = virtual_user, transport = dovecot_virtual_delivery\n",
        );
        assert_eq!(hops.len(), 1);
        assert!(hops[0].error.is_none());
    }

    #[test]
    fn parses_cpanel_files() {
        let a = parse_valiases("booking@transfervda.com: taxiaosta@gmail.com\n*: \":fail: No Such User Here\"\nmulti@x.test: a@x.test, \"|/usr/bin/prog\"\n");
        assert_eq!(a.len(), 3);
        assert_eq!(a[0].targets, vec!["taxiaosta@gmail.com"]);
        assert_eq!(
            classify_target(&a[1].targets[0]),
            Target::Fail("No Such User Here".into())
        );
        assert_eq!(a[2].targets.len(), 2);
        assert_eq!(
            classify_target(&a[2].targets[1]),
            Target::Pipe("/usr/bin/prog".into())
        );
        assert_eq!(classify_target(":blackhole:"), Target::Blackhole);
        let kv =
            parse_cpuser("DNS=transfervda.com\nMAX_EMAIL_PER_HOUR=200\nSUSPENDED=0\n# comment\n");
        assert_eq!(cpuser_get(&kv, "MAX_EMAIL_PER_HOUR"), Some("200"));
        let lo =
            parse_localopts("acl_requirehelo=1\nsmarthost_routelist=\nacl_deny_rcpt_hard_limit\n");
        assert_eq!(lo.len(), 3);
        assert_eq!(lo[1], ("smarthost_routelist".into(), String::new()));
        assert_eq!(
            parse_mailips("*: 203.0.113.9\nx.test: 203.0.113.10\n", "x.test"),
            Some("203.0.113.10".parse().unwrap())
        );
        assert_eq!(
            parse_mailips("*: 203.0.113.9\n", "y.test"),
            Some("203.0.113.9".parse().unwrap())
        );
        assert_eq!(parse_mailips("", "y.test"), None);
        assert_eq!(
            parse_mailhelo("*: ncc.transfervda.com", "x.test").as_deref(),
            Some("ncc.transfervda.com")
        );
        let ports = parse_ss_listeners("LISTEN 0 4096 0.0.0.0:25 0.0.0.0:* users:((\"exim\",pid=1,fd=5))\nLISTEN 0 100 [::]:993 [::]:*\nLISTEN 0 4096 127.0.0.1:783 0.0.0.0:*\n");
        assert_eq!(ports, vec![25, 783, 993]);
        assert_eq!(mask_address("john@example.com"), "j***@example.com");
        assert_eq!(
            pem_to_der_b64("-----BEGIN PUBLIC KEY-----\nMIIB\nAQ==\n-----END PUBLIC KEY-----\n"),
            "MIIBAQ=="
        );
    }

    #[test]
    fn parses_list_pops() {
        let v = Json::parse(r#"{"result":{"status":1,"errors":null,"data":[{"email":"booking@transfervda.com","diskused":"246.23","diskquota":"unlimited","suspended_incoming":0,"suspended_login":1,"diskusedpercent_float":0},{"email":"full@transfervda.com","diskused":"250","diskquota":"250","suspended_incoming":0,"suspended_login":0,"diskusedpercent_float":100}]}}"#).unwrap();
        let m = parse_list_pops(&v, "Booking@transfervda.com")
            .unwrap()
            .unwrap();
        assert!(m.quota_mb.is_none() && m.suspended_login && !m.suspended_incoming);
        let f = parse_list_pops(&v, "full@transfervda.com")
            .unwrap()
            .unwrap();
        assert_eq!(f.quota_mb, Some(250.0));
        assert_eq!(f.used_percent, 100.0);
        assert!(parse_list_pops(&v, "nobody@transfervda.com")
            .unwrap()
            .is_none());
        let e =
            Json::parse(r#"{"result":{"status":0,"errors":["Provide the domain"],"data":null}}"#)
                .unwrap();
        assert!(parse_list_pops(&e, "x@y").is_err());
    }

    #[test]
    fn audit_over_a_fixture_root() {
        use crate::config::Config;
        use crate::deliveryrun::{execute, Ctx, Results};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let root = std::env::temp_dir().join(format!("msfe-cpaudit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let w = |rel: &str, text: &str| {
            let p = root.join(rel.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        };
        w("/etc/userdomains", "x.test: bob\n");
        w("/etc/passwd", "bob:x:1001:1001::/home/bob:/bin/bash\n");
        w(
            "/var/cpanel/users/bob",
            "MAX_EMAIL_PER_HOUR=100\nSUSPENDED=0\n",
        );
        w("/etc/localdomains", "x.test\n");
        w(
            "/etc/valiases/x.test",
            "fwd@x.test: someone@gmail.com\n*: \":blackhole:\"\n",
        );
        w("/etc/exim.conf.localopts", "senderverify=0\nacl_delay_unknown_hosts=1\nrequire_secure_auth=1\nsmarthost_routelist=\nacl_dkim_disable=0\n");
        w("/var/cpanel/mainip", "203.0.113.9\n");
        w("/etc/mailhelo", "*: mail.x.test\n");
        w(
            "/etc/csf/csf.conf",
            "TCP_IN = \"22,80,443,465,587,993\"\nTCP_OUT = \"80,443\"\nSMTP_BLOCK = \"1\"\n",
        );
        w("/_cmd/exim-bt.txt", "fwd@x.test\n    <-- fwd@x.test\n  router = virtual_user, transport = dovecot_virtual_delivery\nsomeone@gmail.com\n    <-- fwd@x.test\n  router = lookuphost, transport = remote_smtp\n");
        w(
            "/_cmd/list_pops.txt",
            r#"{"result":{"status":1,"errors":null,"data":[{"email":"fwd@x.test","diskused":"1","diskquota":"unlimited","suspended_incoming":0,"suspended_login":0,"diskusedpercent_float":0}]}}"#,
        );
        w("/_cmd/systemctl-exim.txt", "active\n");
        w("/_cmd/systemctl-dovecot.txt", "inactive\n");
        w(
            "/_cmd/ss.txt",
            "LISTEN 0 4096 0.0.0.0:25 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:587 0.0.0.0:*\n",
        );
        w(
            "/_cmd/exim-bV.txt",
            "Exim version 4.100 #2 built 10-Sep-2026\n",
        );
        w("/var/log/exim_mainlog", "2026-09-19 10:00:00 1x-1 <= a@x.test H=h [1.2.3.4] P=esmtpsa A=dovecot_login:a@x.test S=1 for b@y\n2026-09-19 10:01:00 1x-2 <= a@x.test H=h [1.2.3.4] P=esmtpsa A=dovecot_login:a@x.test S=1 for b@y\n");
        std::env::set_var("MSFE_NG_CPANEL_ROOT", &root);
        std::env::set_var("MSFE_NG_DELIVERY_NO_NET", "1");
        // a DNS server that knows nothing: every lookup is a fast empty answer
        let dns = crate::dns::testsupport::start(Box::new(|_, _| Some((0, vec![], false))), false);
        let inputs =
            crate::deliveryrun::parse_inputs("fwd@x.test", None, None, None, true, true, None)
                .unwrap();
        let ctx = Arc::new(Ctx {
            cfg: Config::default(),
            inputs: inputs.clone(),
            dns: Arc::new(crate::dns::Client::at(dns.addr)),
            deadline: std::time::Instant::now() + Duration::from_secs(30),
            cancel: Arc::new(AtomicBool::new(false)),
            helo: "t.local".into(),
        });
        // the audit tasks alone, with the facts the DNS tasks would have left
        let mut tasks = tasks(&inputs);
        for t in &mut tasks {
            t.deps.retain(|d| d == "acct");
        }
        let res = Results::default();
        let _ = res;
        let (checks, unfinished) = execute(ctx, tasks, &mut |_| {}, &mut |_| {});
        assert!(unfinished.is_empty(), "{unfinished:?}");
        let by = |id: &str| {
            checks.iter().find(|c| c.id == id).unwrap_or_else(|| {
                panic!(
                    "no {id} in {:?}",
                    checks.iter().map(|c| c.id.clone()).collect::<Vec<_>>()
                )
            })
        };
        assert_eq!(by("acct.owner").verdict, Verdict::Pass);
        assert_eq!(
            by("acct.domain_kind").verdict,
            Verdict::Pass,
            "local, MX unknown"
        );
        assert_eq!(by("acct.mailbox").verdict, Verdict::Pass);
        assert_eq!(
            by("acct.default_address").verdict,
            Verdict::Warn,
            "blackhole"
        );
        assert_eq!(by("route.exim_bt").verdict, Verdict::Pass);
        assert_eq!(
            by("route.aliases").verdict,
            Verdict::Warn,
            "external forward"
        );
        assert!(by("route.aliases")
            .fix
            .as_ref()
            .unwrap()
            .summary
            .contains("SRS"));
        assert_eq!(by("out.ip").verdict, Verdict::Pass);
        assert_eq!(
            by("out.helo").verdict,
            Verdict::Fail,
            "mail.x.test resolves to nothing"
        );
        assert_eq!(by("out.dkim_cpanel").verdict, Verdict::Fail, "no key file");
        assert_eq!(by("svc.exim").verdict, Verdict::Pass);
        assert_eq!(by("svc.dovecot").verdict, Verdict::Fail);
        assert_eq!(
            by("svc.listeners").verdict,
            Verdict::Warn,
            "993 etc missing but 25 present"
        );
        assert_eq!(
            by("svc.csf_ports").verdict,
            Verdict::Fail,
            "TCP_IN lacks 25, TCP_OUT lacks 25"
        );
        assert_eq!(by("limit.hourly").verdict, Verdict::Pass);
        assert!(by("limit.hourly").title.starts_with("2 of 100"));
        assert_eq!(
            by("limit.ratelimit_acl").verdict,
            Verdict::Warn,
            "senderverify=0"
        );
        std::env::remove_var("MSFE_NG_CPANEL_ROOT");
        std::env::remove_var("MSFE_NG_DELIVERY_NO_NET");
        let _ = std::fs::remove_dir_all(&root);
    }
}
