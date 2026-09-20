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
