//! Argument handling of the `msfe-ng` binary: a flag a subcommand does not
//! take must be an error, never silently dropped — `exim enable-scanning
//! --dry-run` once flipped the kill switch for real (issue #8).

use std::path::PathBuf;
use std::process::Command;

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("msfe-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn msfe_ng(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(args)
        .env("MSFE_NG_CONFIG", dir.join("config.toml"))
        .env("MSFE_NG_EXIM_ACL_HOOK", dir.join("hook"))
        .env("MSFE_NG_SKIP_EXIM_CMDS", "1")
        .output()
        .unwrap()
}

#[test]
fn unknown_flag_is_rejected_before_anything_changes() {
    let d = tmp("dryrun");
    // a named-queue wiring switched off: the fragment sits as .disabled
    let frag = d.join("mailscannerq.conf");
    let latch = d.join("mailscannerq.conf.disabled");
    std::fs::write(
        d.join("config.toml"),
        format!("mailscannerq_conf = \"{}\"\n", frag.display()),
    )
    .unwrap();
    std::fs::write(
        d.join("hook"),
        format!(".include_if_exists {}\n", frag.display()),
    )
    .unwrap();
    std::fs::write(&latch, "queue = mailscanner\n").unwrap();

    let out = msfe_ng(&d, &["exim", "enable-scanning", "--dry-run"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--dry-run") && err.contains("usage:"), "{err}");
    assert!(
        latch.exists() && !frag.exists(),
        "the kill switch must not have been touched"
    );
    // the real thing flips it
    let out = msfe_ng(&d, &["exim", "status"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("DISABLED"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let out = msfe_ng(&d, &["exim", "enable-scanning"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(frag.exists() && !latch.exists());

    // the same for a subcommand that takes no flags at all
    let out = msfe_ng(&d, &["engine", "configure", "--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--dry-run"));

    // `wire` does take --dry-run: not an argument error
    let out = msfe_ng(&d, &["engine", "wire", "--dry-run"]);
    assert_ne!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// `mailscanner enable-logging` on a host whose conf is not where config.toml
/// says (a ConfigServer engine, issue seen on `como`) must name the missing
/// file and touch nothing — not print a bare "No such file or directory".
#[test]
fn enable_logging_names_the_missing_conf_and_installs_nothing() {
    let d = tmp("enable-logging");
    let conf = d.join("MailScanner.conf");
    let custom = d.join("custom");
    std::fs::write(
        d.join("config.toml"),
        format!(
            "mailscanner_conf = \"{}\"\nmailscanner_custom_dir = \"{}\"\n",
            conf.display(),
            custom.display()
        ),
    )
    .unwrap();

    let out = msfe_ng(&d, &["mailscanner", "enable-logging"]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&conf.display().to_string()) && err.contains("mailscanner_conf"),
        "{err}"
    );
    assert!(
        !custom.exists(),
        "no plugin dir without a conf to hook it into"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// `exim disable-cpanel-spamassassin` turns Spam Filters off for the accounts
/// that have it on and remembers them; `enable-` restores exactly those.
#[test]
fn cpanel_spamassassin_toggle_uses_the_forced_off_flag() {
    let d = tmp("cpanel-sa");
    std::fs::create_dir_all(d.join("etc")).unwrap();
    std::fs::create_dir_all(d.join("home/alice")).unwrap();
    std::fs::write(
        d.join("etc/passwd"),
        "alice:x:1001:1001::/home/alice:/bin/bash\n",
    )
    .unwrap();
    std::fs::write(d.join("home/alice/.spamassassinenable"), "").unwrap();
    std::fs::write(d.join("config.toml"), "panel = \"cpanel\"\n").unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
            .args(args)
            .env("MSFE_NG_CONFIG", d.join("config.toml"))
            .env("MSFE_NG_CPANEL_ROOT", &d)
            .output()
            .unwrap()
    };
    let out = run(&["exim", "status"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("1 account(s) have cPanel Spam Filters on")
    );

    let out = run(&["exim", "disable-cpanel-spamassassin"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!d.join("home/alice/.spamassassinenable").exists());
    assert!(String::from_utf8_lossy(&out.stdout).contains("off for 1 account(s): alice"));
    assert_eq!(
        std::fs::read_to_string(d.join("etc/msfe-ng/cpanel-sa-accounts")).unwrap(),
        "alice\n"
    );

    let out = run(&["exim", "enable-cpanel-spamassassin"]);
    assert!(out.status.success());
    assert!(d.join("home/alice/.spamassassinenable").exists());
    assert!(!d.join("etc/msfe-ng/cpanel-sa-accounts").exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// `doctor --fix` with nothing installed has nothing mechanical to do and
/// says so; it never invents work (no engine → the doctor stops early).
#[test]
fn doctor_fix_reports_nothing_to_fix_without_an_engine() {
    let d = tmp("doctor-fix");
    std::fs::write(
        d.join("config.toml"),
        format!(
            "mailscanner_conf = \"{}\"\nmailscanner_rules_dir = \"{}\"\n",
            d.join("MailScanner.conf").display(),
            d.join("rules").display()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(["doctor", "--fix"])
        .env("MSFE_NG_CONFIG", d.join("config.toml"))
        .env("MSFE_NG_MS_BIN", d.join("no-such-engine"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("nothing to fix automatically"), "{text}");
    assert!(!d.join("rules").exists(), "no sync ran");
    // a flag the doctor does not take is still rejected
    let out = Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(["doctor", "--force"])
        .env("MSFE_NG_CONFIG", d.join("config.toml"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn conf_test_validates_its_arguments() {
    let d = tmp("conftest");
    let out = msfe_ng(&d, &["conf", "test", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--bogus") && err.contains("usage:"), "{err}");
    let out = msfe_ng(&d, &["conf"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("conf <test"));
    // --with needs id=file, and the file must exist
    let out = msfe_ng(&d, &["conf", "test", "--with", "nonsense"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("<id>=<file>"));
    let out = msfe_ng(
        &d,
        &[
            "conf",
            "test",
            "--with",
            "ms:MailScanner.conf=/nonexistent/x",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read"));
}

#[test]
fn snapshot_export_list_and_dry_run_import() {
    let d = tmp("snapshot");
    // the engine tree and the backups live outside the MSFE-NG config dir
    let side = tmp("snapshot-side");
    let etc = side.join("MailScanner");
    std::fs::create_dir_all(etc.join("rules")).unwrap();
    std::fs::write(
        etc.join("MailScanner.conf"),
        format!("%etc-dir% = {}\nMax Children = 5\n", etc.display()),
    )
    .unwrap();
    std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default no\n").unwrap();
    std::fs::write(
        d.join("config.toml"),
        format!(
            "mailscanner_conf = \"{}\"\nmailscanner_rules_dir = \"{}\"\nbackup_dir = \"{}\"\n",
            etc.join("MailScanner.conf").display(),
            etc.join("rules").display(),
            side.join("backups").display()
        ),
    )
    .unwrap();

    let out = msfe_ng(&d, &["snapshot", "export", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let out = msfe_ng(&d, &["snapshot"]);
    assert_eq!(out.status.code(), Some(2));

    let out = msfe_ng(&d, &["snapshot", "export"]);
    let so = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{so}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(so.contains("snapshot written:"), "{so}");
    let out = msfe_ng(&d, &["snapshot", "list"]);
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(so.contains("msfe-ng-snapshot-"), "{so}");
    let path = so.split_whitespace().last().unwrap().to_string();

    // change live, dry-run shows it and touches nothing
    std::fs::write(etc.join("rules/bounce.rules"), "FromOrTo: default yes\n").unwrap();
    let out = msfe_ng(&d, &["snapshot", "import", &path, "--dry-run"]);
    let so = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{so}");
    assert!(so.contains("changed  * ms:rules/bounce.rules"), "{so}");
    assert!(so.contains("dry run: 1 file(s)"), "{so}");
    assert_eq!(
        std::fs::read_to_string(etc.join("rules/bounce.rules")).unwrap(),
        "FromOrTo: default yes\n"
    );

    // the legacy commands still work and produce the new format
    let bk = d.join("bk.tar.gz");
    let out = msfe_ng(&d, &["backup", bk.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bk.exists());
    let out = msfe_ng(&d, &["restore", bk.to_str().unwrap(), "--yes"]);
    let so = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{so}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(so.contains("nothing to import"), "{so}");
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&side);
}

/// `legacy decommission` without `--run` only reports; an unknown flag and
/// an unknown subcommand are usage errors, and with nothing of /usr/msfe on
/// this machine `--run` refuses rather than writing a backup.
#[test]
fn legacy_decommission_reports_and_refuses_when_nothing_is_left() {
    let d = tmp("decom");
    let out = msfe_ng(&d, &["legacy", "decommission", "--dry-run"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage:"));
    let out = msfe_ng(&d, &["legacy", "remove"]);
    assert_eq!(out.status.code(), Some(2));

    if std::path::Path::new("/usr/msfe").exists() {
        return; // a host with the real thing: not a machine to test on
    }
    let out = msfe_ng(&d, &["legacy", "decommission"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("ConfigServer front-end: nothing left"),
        "{text}"
    );
    assert!(
        text.contains("procedure: https://github.com/inalto/msfe-ng/wiki/Migration"),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(1), "blocked");
    let out = msfe_ng(&d, &["legacy", "decommission", "--run"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already decommissioned"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `autoban` with nothing configured reports "off" and does nothing; its
/// flags are checked like everyone else's.
#[test]
fn autoban_status_is_off_by_default_and_flags_are_checked() {
    let d = tmp("autoban");
    std::fs::write(d.join("config.toml"), "panel = \"cpanel\"\n").unwrap();
    let out = msfe_ng(&d, &["autoban", "status"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("auto-ban: off"), "{text}");
    assert!(
        text.contains("high spam: off — 1 message(s) in 10m → ban 1d"),
        "{text}"
    );
    assert!(
        text.contains("spam: off — 3 message(s) in 1h → ban 2h"),
        "{text}"
    );
    let out = msfe_ng(&d, &["autoban", "run", "--dry-run"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("nothing enabled"));
    let out = msfe_ng(&d, &["autoban", "run", "--force"]);
    assert_eq!(out.status.code(), Some(2));
    let out = msfe_ng(&d, &["autoban", "wipe"]);
    assert_eq!(out.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&d);
}

/// A resolver on loopback that answers every query NXDOMAIN at once, so the
/// DMARC lookups of a scan neither reach the network nor wait for a timeout.
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

fn write_at(root: &std::path::Path, rel: &str, text: &str) {
    let p = root.join(rel.trim_start_matches('/'));
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// A cPanel-shaped tree: one account, its main domain and one subdomain, with
/// the three validators answering MISSING for everything.
fn cpanel_tree(root: &std::path::Path) {
    write_at(
        root,
        "/etc/userdomains",
        "example.com: alice\nshop.example.com: alice\n*: nobody\n",
    );
    write_at(root, "/etc/trueuserdomains", "example.com: alice\n");
    write_at(
        root,
        "/var/cpanel/userdata/alice/main",
        "main_domain: example.com\naddon_domains: []\nparked_domains: []\nsub_domains:\n  - shop.example.com\n",
    );
    write_at(root, "/etc/localdomains", "example.com\nshop.example.com\n");
    let entry = |d: &str| {
        format!("{{\"domain\":\"{d}\",\"state\":\"MISSING\",\"expected\":\"ip4:192.0.2.10\",\"ip_address\":\"192.0.2.10\",\"ip_version\":4,\"records\":[],\"error\":null}}")
    };
    write_at(
        root,
        "/_cmd/acctdns_spfs.txt",
        &format!(
            "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{},{}]}}}}",
            entry("example.com"),
            entry("shop.example.com")
        ),
    );
    write_at(
        root,
        "/_cmd/acctdns_dkims.txt",
        &format!(
            "{{\"metadata\":{{\"reason\":\"OK\",\"result\":1}},\"data\":{{\"payload\":[{},{}]}}}}",
            entry("default._domainkey.example.com"),
            entry("default._domainkey.shop.example.com")
        ),
    );
    write_at(
        root,
        "/_cmd/acctdns_authority.txt",
        r#"{"metadata":{"reason":"OK","result":1},"data":{"records":[
          {"domain":"example.com","zone":"example.com","local_authority":1,"nameservers":["ns1.example.com"],"error":null},
          {"domain":"shop.example.com","zone":"example.com","local_authority":1,"nameservers":["ns1.example.com"],"error":null}
        ]}}"#,
    );
}

/// `acctdns`: the flags of each subcommand are checked before anything runs,
/// and a scan over a fixture tree reports every account domain (subdomains
/// only when asked).
#[test]
fn acctdns_checks_its_flags_and_scans_a_fixture_tree() {
    let d = tmp("acctdns");
    let out = msfe_ng(&d, &["acctdns", "scan", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--bogus") && err.contains("usage:"), "{err}");
    // `fix` needs a domain and a record kind
    let out = msfe_ng(&d, &["acctdns", "fix"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("usage: msfe-ng acctdns"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = msfe_ng(&d, &["acctdns", "fix", "example.com", "rrsig"]);
    assert_eq!(out.status.code(), Some(2));
    let out = msfe_ng(&d, &["acctdns", "wipe"]);
    assert_eq!(out.status.code(), Some(2));

    // a fixture tree that looks like cPanel: the scan runs inline
    let root = d.join("root");
    cpanel_tree(&root);
    let out = Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(["acctdns", "scan", "--json"])
        .env("MSFE_NG_CONFIG", d.join("config.toml"))
        .env("MSFE_NG_CPANEL_ROOT", &root)
        .env("MSFE_NG_RESOLVER", nxdomain_resolver())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    // everything is missing, so the row fails
    assert_eq!(
        out.status.code(),
        Some(1),
        "{text}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("\"rows\":["), "{text}");
    assert!(text.contains("\"domain\":\"example.com\""), "{text}");
    assert!(text.contains("\"user\":\"alice\""), "{text}");
    assert!(
        !text.contains("shop.example.com"),
        "subdomains are noise unless asked for: {text}"
    );

    // --all brings the subdomain in, and the plain output is one line per domain
    let out = Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(["acctdns", "scan", "--all"])
        .env("MSFE_NG_CONFIG", d.join("config.toml"))
        .env("MSFE_NG_CPANEL_ROOT", &root)
        .env("MSFE_NG_RESOLVER", nxdomain_resolver())
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("[FAIL] example.com  spf: "), "{text}");
    assert!(text.contains("[FAIL] shop.example.com  spf: "), "{text}");
    assert!(text.contains("2 domains · 2 fail"), "{text}");

    // a host that is not cPanel says so and runs nothing
    let bare = d.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_msfe-ng"))
        .args(["acctdns", "scan"])
        .env("MSFE_NG_CONFIG", d.join("config.toml"))
        .env("MSFE_NG_CPANEL_ROOT", &bare)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("needs cPanel"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&d);
}
