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
