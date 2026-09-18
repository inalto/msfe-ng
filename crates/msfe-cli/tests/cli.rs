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
        .env("MSFE_NG_EXISCANDISABLE", dir.join("exiscandisable"))
        .output()
        .unwrap()
}

#[test]
fn unknown_flag_is_rejected_before_anything_changes() {
    let d = tmp("dryrun");
    let latch = d.join("exiscandisable");
    std::fs::write(&latch, "disabled\n").unwrap();

    let out = msfe_ng(&d, &["exim", "enable-scanning", "--dry-run"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--dry-run") && err.contains("usage:"), "{err}");
    assert!(latch.exists(), "the kill switch must not have been touched");

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

/// `exim disable-cpanel-spamassassin` writes cPanel's Forced-Global-OFF flag
/// and nothing else; `enable-` removes it and leaves accounts' own choice.
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
            .env("MSFE_NG_EXISCANDISABLE", d.join("exiscandisable"))
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
    assert!(d.join("etc/global_spamassassin_disable").is_file());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Forced Global OFF"));

    let out = run(&["exim", "enable-cpanel-spamassassin"]);
    assert!(out.status.success());
    assert!(!d.join("etc/global_spamassassin_disable").exists());
    assert!(d.join("home/alice/.spamassassinenable").exists());
    let _ = std::fs::remove_dir_all(&d);
}
