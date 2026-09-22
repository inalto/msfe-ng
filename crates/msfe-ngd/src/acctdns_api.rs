//! `/api/acctdns/*`: the Account DNS view of the Delivery tab — one scan over
//! every domain hosted on this server, and cPanel's own installers behind a
//! repair button.
//!
//! Three routes only. `GET /api/acctdns/scan` is the poller's endpoint: it
//! answers the scan in memory, else the last one from disk, with its age, and
//! `404 {"error":…}` when nothing has ever run. `POST /api/acctdns/scan`
//! either re-checks one domain inline (fast enough for a request) or starts
//! the background scan and returns its id at once, so the write lock every
//! non-GET holds is released in milliseconds. `POST /api/acctdns/fix` runs one
//! installer and returns the transcript with the re-checked row; it is the
//! only route that changes anything, and it holds the write lock throughout.

use crate::http::{Request, Response};
use msfe_core::acctdns::{self, Filter, Scan, StartError, What};
use msfe_core::cpaudit::Cp;
use msfe_core::dns::Client;
use msfe_core::json::Json;
use msfe_core::Config;
use std::path::Path;

pub fn handle(
    method: &str,
    path: &str,
    req: &Request,
    cfg: &Config,
    config_file: &Path,
) -> Response {
    let _ = config_file; // nothing here reads the config file yet
    match (method, path) {
        ("GET", "/api/acctdns/scan") => scan_get(),
        ("POST", "/api/acctdns/scan") => scan_post(req, cfg),
        ("POST", "/api/acctdns/fix") => fix(req),
        _ => Response::json(404, r#"{"error":"not found"}"#),
    }
}

fn err(status: u16, msg: &str) -> Response {
    Response::json(
        status,
        &Json::Object(vec![("error".into(), Json::str(msg))]).to_string(),
    )
}

/// A body that may be absent: `POST … {}` and `POST …` with no body at all
/// mean the same thing (scan everything).
fn body_json(req: &Request) -> Result<Json, Response> {
    if req.body.trim().is_empty() {
        return Ok(Json::Null);
    }
    Json::parse(&req.body).map_err(|e| err(400, &format!("bad json: {e}")))
}

/// A non-empty, trimmed string field, or `None`.
fn field(v: &Json, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// The scan as the tab reads it: the JSON contract plus how old it is (since
/// it finished, or since it started while it still runs).
fn scan_json(s: &Scan) -> Json {
    let mut f = match s.to_json() {
        Json::Object(f) => f,
        _ => Vec::new(),
    };
    let since = s.finished.unwrap_or(s.started);
    let age = msfe_core::delivery::now_secs().saturating_sub(since);
    f.push(("age_secs".into(), Json::Int(age as i64)));
    Json::Object(f)
}

/// `{error, supported:false, panel}` — what the tab turns into "Account DNS
/// needs cPanel (this host: …)".
fn unsupported(cp: &Cp, status: u16) -> Response {
    let panel = acctdns::panel_name(cp);
    Response::json(
        status,
        &Json::Object(vec![
            (
                "error".into(),
                Json::str(format!("Account DNS needs cPanel (this host: {panel})")),
            ),
            ("supported".into(), Json::Bool(false)),
            ("panel".into(), Json::str(&panel)),
        ])
        .to_string(),
    )
}

/// The current or last scan. On a host this cannot run on the answer is a
/// well-formed Scan carrying `supported:false`, so the tab renders the
/// explanation instead of an error.
fn scan_get() -> Response {
    let cp = Cp::detect();
    if !acctdns::supported(&cp) {
        return Response::json(200, &acctdns::unsupported_scan(&cp).to_json().to_string());
    }
    match acctdns::last() {
        Some(s) => Response::json(200, &scan_json(&s).to_string()),
        None => err(404, "no scan yet"),
    }
}

/// `{user?, domain?}`: one domain inline, or a background scan of the rest.
fn scan_post(req: &Request, cfg: &Config) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    if let Some(given) = field(&v, "domain") {
        let domain = given.trim_end_matches('.').to_ascii_lowercase();
        if !msfe_core::netguard::valid_hostname(&domain) {
            return err(400, &format!("'{given}' is not a domain name"));
        }
        let cp = Cp::detect();
        if !acctdns::supported(&cp) {
            return unsupported(&cp, 501);
        }
        return match acctdns::check_one(&cp, &Client::system(), &domain) {
            Some(row) => {
                // the re-checked row replaces the stored one, so a reload agrees
                acctdns::update_row(&row);
                Response::json(
                    200,
                    &Json::Object(vec![("row".into(), row.to_json())]).to_string(),
                )
            }
            None => err(404, "not hosted here"),
        };
    }
    let filter = Filter {
        user: field(&v, "user"),
        domain: None,
    };
    match acctdns::start(cfg, Some(filter)) {
        Ok(id) => Response::json(
            202,
            &Json::Object(vec![("id".into(), Json::str(&id))]).to_string(),
        ),
        Err(StartError::Busy(id)) => Response::json(
            200,
            &Json::Object(vec![
                ("id".into(), Json::str(&id)),
                ("running".into(), Json::Bool(true)),
            ])
            .to_string(),
        ),
        Err(StartError::Unsupported) => unsupported(&Cp::detect(), 501),
        Err(StartError::Invalid(why)) => err(400, &why),
    }
}

/// `{domain, what, record?}`: one installer call, then the re-checked row.
fn fix(req: &Request) -> Response {
    let v = match body_json(req) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let Some(domain) = field(&v, "domain") else {
        return err(400, "domain required");
    };
    let Some(what) = What::parse(&v.str_field("what")) else {
        return err(400, "what must be spf, dkim or dmarc");
    };
    let record = field(&v, "record");
    match acctdns::fix(&Cp::detect(), &domain, what, record.as_deref()) {
        Ok(r) => Response::json(200, &r.to_json().to_string()),
        Err(e) => Response::json(400, &e.to_json().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// `MSFE_NG_CPANEL_ROOT`, `MSFE_NG_ACCTDNS_FILE` and the scan registry are
    /// process-wide: one test at a time.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn req(method: &str, path: &str, body: &str) -> Request {
        Request {
            method: method.into(),
            path: path.into(),
            query: String::new(),
            body: body.into(),
            user: String::new(),
        }
    }

    /// The route's status and its parsed body. `Response` keeps its body
    /// private, so the test reads what the socket would have received.
    fn call(method: &str, path: &str, body: &str) -> (u16, Json) {
        let r = handle(
            method,
            path,
            &req(method, path, body),
            &Config::default(),
            Path::new("/nonexistent/msfe-ng.toml"),
        );
        let mut wire: Vec<u8> = Vec::new();
        r.write(&mut wire).unwrap();
        let wire = String::from_utf8_lossy(&wire).into_owned();
        let sent = wire.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let v = Json::parse(sent).unwrap_or_else(|e| panic!("{e}: {sent}"));
        (r.status, v)
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("msfe-acctdns-api-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    /// A cPanel-shaped tree with two documentation domains, both missing every
    /// record, and an installer that answers OK.
    fn tree(tag: &str) -> PathBuf {
        let root = tmpdir(tag);
        write(
            &root,
            "/etc/userdomains",
            "example.com: alice\nshop.example.com: alice\n*: nobody\n",
        );
        write(
            &root,
            "/var/cpanel/userdata/alice/main",
            "main_domain: example.com\naddon_domains: []\nparked_domains: []\nsub_domains:\n  - shop.example.com\n",
        );
        write(
            &root,
            "/etc/localdomains",
            "example.com\nshop.example.com\n",
        );
        let entry = |d: &str| {
            format!("{{\"domain\":\"{d}\",\"state\":\"MISSING\",\"expected\":\"ip4:192.0.2.10\",\"ip_address\":\"192.0.2.10\",\"ip_version\":4,\"records\":[],\"error\":null}}")
        };
        write(
            &root,
            "/_cmd/acctdns_spfs.txt",
            &format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{},{}]}}}}",
                entry("example.com"),
                entry("shop.example.com")
            ),
        );
        write(
            &root,
            "/_cmd/acctdns_dkims.txt",
            &format!(
                "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{},{}]}}}}",
                entry("default._domainkey.example.com"),
                entry("default._domainkey.shop.example.com")
            ),
        );
        write(
            &root,
            "/_cmd/acctdns_authority.txt",
            r#"{"metadata":{"reason":"OK","result":1},"data":{"records":[
              {"domain":"example.com","zone":"example.com","local_authority":1,"nameservers":["ns1.example.com"],"error":null},
              {"domain":"shop.example.com","zone":"example.com","local_authority":1,"nameservers":["ns1.example.com"],"error":null}
            ]}}"#,
        );
        for what in ["spf", "dkim", "dmarc"] {
            write(
                &root,
                &format!("/_cmd/acctdns_fix_{what}.txt"),
                r#"{"metadata":{"command":"install_spf_records","reason":"OK","result":1}}"#,
            );
        }
        root
    }

    /// A resolver on loopback that answers every query NXDOMAIN at once. A
    /// closed port would do as well for the verdict, but an unanswered UDP
    /// packet costs the client's full timeout twice over; the tests must not
    /// reach the network and must not wait for it either.
    fn nxdomain_resolver() -> String {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                if n < 12 {
                    continue;
                }
                let mut reply = buf[..n].to_vec();
                reply[2] = 0x80; // QR: an answer
                reply[3] = 3; // NXDOMAIN
                reply[6..12].fill(0); // no answer, authority or additional records
                let _ = sock.send_to(&reply, from);
            }
        });
        addr
    }

    /// Point the module at a fixture tree, a scan file nothing has written and
    /// a resolver that answers at once, so a DMARC lookup takes milliseconds.
    fn env(root: &Path) {
        std::env::set_var("MSFE_NG_CPANEL_ROOT", root);
        std::env::set_var("MSFE_NG_ACCTDNS_FILE", root.join("acctdns.json"));
        std::env::set_var("MSFE_NG_RESOLVER", nxdomain_resolver());
        acctdns::reset();
    }

    #[test]
    fn get_before_any_scan_is_a_404() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("never");
        env(&root);
        let (status, v) = call("GET", "/api/acctdns/scan", "");
        assert_eq!(status, 404);
        assert_eq!(v.str_field("error"), "no scan yet");
    }

    #[test]
    fn a_bad_domain_is_refused() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("baddomain");
        env(&root);
        let (status, v) = call("POST", "/api/acctdns/scan", r#"{"domain":"not a domain"}"#);
        assert_eq!(status, 400);
        assert!(
            v.str_field("error").contains("not a domain name"),
            "{}",
            v.str_field("error")
        );
        // a well-formed name that no account owns is a 404, not a 400
        let (status, v) = call("POST", "/api/acctdns/scan", r#"{"domain":"example.net"}"#);
        assert_eq!(status, 404, "{v}");
        assert_eq!(v.str_field("error"), "not hosted here");
    }

    #[test]
    fn fix_needs_a_domain_and_a_record_kind() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("fixargs");
        env(&root);
        let (status, v) = call("POST", "/api/acctdns/fix", r#"{"domain":"example.com"}"#);
        assert_eq!(status, 400);
        assert!(v.str_field("error").contains("spf"), "{v}");
        let (status, _) = call("POST", "/api/acctdns/fix", r#"{"what":"spf"}"#);
        assert_eq!(status, 400);
        let (status, v) = call(
            "POST",
            "/api/acctdns/fix",
            r#"{"domain":"example.com","what":"rrsig"}"#,
        );
        assert_eq!(status, 400);
        assert!(v.str_field("error").contains("spf"), "{v}");
    }

    #[test]
    fn fix_installs_the_spf_record_and_returns_the_row() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("fixspf");
        env(&root);
        let (status, v) = call(
            "POST",
            "/api/acctdns/fix",
            r#"{"domain":"example.com","what":"spf","record":"v=spf1 +mx +a ip4:192.0.2.10 ~all"}"#,
        );
        assert_eq!(status, 200, "{v}");
        assert!(matches!(v.get("ok"), Some(Json::Bool(true))), "{v}");
        let actions = v.get("actions").and_then(Json::as_array).unwrap();
        assert!(
            actions
                .iter()
                .filter_map(Json::as_str)
                .any(|a| a.contains("install_spf_records")),
            "{v}"
        );
        assert_eq!(
            v.get("row").map(|r| r.str_field("domain")).unwrap(),
            "example.com"
        );
        // an installer that refuses is a 400 carrying the transcript
        write(
            &root,
            "/_cmd/acctdns_fix_spf.txt",
            r#"{"metadata":{"reason":"Access denied","result":0}}"#,
        );
        let (status, v) = call(
            "POST",
            "/api/acctdns/fix",
            r#"{"domain":"example.com","what":"spf","record":"v=spf1 +mx +a ip4:192.0.2.10 ~all"}"#,
        );
        assert_eq!(status, 400, "{v}");
        assert!(v.str_field("error").contains("Access denied"), "{v}");
        assert!(v.get("actions").and_then(Json::as_array).is_some(), "{v}");
    }

    #[test]
    fn a_scan_of_one_account_starts_and_is_polled() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = tree("start");
        env(&root);
        let (status, v) = call("POST", "/api/acctdns/scan", r#"{"user":"alice"}"#);
        assert_eq!(status, 202, "{v}");
        assert!(!v.str_field("id").is_empty(), "{v}");
        // the poller sees a scan with a boolean `done` and an age
        let (status, v) = call("GET", "/api/acctdns/scan", "");
        assert_eq!(status, 200);
        assert!(matches!(v.get("done"), Some(Json::Bool(_))), "{v}");
        assert!(v.get("age_secs").and_then(Json::as_i64).is_some(), "{v}");
        assert!(matches!(v.get("supported"), Some(Json::Bool(true))), "{v}");
        // a bad account name never reaches the registry
        let (status, v) = call("POST", "/api/acctdns/scan", r#"{"user":"not a user"}"#);
        assert_eq!(status, 400, "{v}");
        acctdns::reset();
    }
}
