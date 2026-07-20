//! `msfe-ng` — the MSFE-NG command line tool.
//!
//! Used by admins directly and by the installer / cron / panel hooks. M0 ships
//! the subcommands needed to prove the skeleton works end to end; the heavier
//! ones (`sync`, `selftest`) are honest stubs that announce they're unimplemented
//! rather than pretending to succeed.

use msfe_api::{DEFAULT_SOCKET_PATH, VERSION};
use msfe_core::detect_panel;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

fn socket_path() -> String {
    std::env::var("MSFE_NG_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");

    match cmd {
        "version" | "--version" | "-V" => {
            println!("msfe-ng {VERSION}");
            ExitCode::SUCCESS
        }
        "panel" => {
            let p = detect_panel();
            println!("{}\t{}", p.kind().as_str(), p.display_name());
            ExitCode::SUCCESS
        }
        "health" => cmd_health(),
        "sync" => {
            eprintln!("msfe-ng sync: not implemented yet (arrives in M2: rule reconciliation).");
            ExitCode::from(3)
        }
        "selftest" => {
            eprintln!(
                "msfe-ng selftest: not implemented yet (arrives in M2: GTUBE/EICAR/clean mail probe)."
            );
            ExitCode::from(3)
        }
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("msfe-ng: unknown command '{other}'\n");
            print_help();
            ExitCode::from(2)
        }
    }
}

/// Probe the daemon over its Unix socket. Returns non-zero if it isn't answering,
/// which the installer uses to verify the service came up.
fn cmd_health() -> ExitCode {
    let path = socket_path();
    let mut stream = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("msfe-ng health: cannot connect to {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if stream
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        eprintln!("msfe-ng health: write failed");
        return ExitCode::from(1);
    }
    let mut buf = String::new();
    if stream.read_to_string(&mut buf).is_err() {
        eprintln!("msfe-ng health: read failed");
        return ExitCode::from(1);
    }
    // Split headers/body and print the JSON payload on success.
    let body = buf.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    if buf.starts_with("HTTP/1.1 200") {
        println!("{body}");
        ExitCode::SUCCESS
    } else {
        eprintln!("msfe-ng health: daemon returned:\n{buf}");
        ExitCode::from(1)
    }
}

fn print_help() {
    println!(
        "msfe-ng {VERSION} — MailScanner Front-End (open-source)

USAGE:
    msfe-ng <command>

COMMANDS:
    health      Check the running daemon via its Unix socket
    panel       Report the detected control panel (cpanel/directadmin/none)
    version     Print version
    sync        [M2] Reconcile per-user/domain policy into MailScanner rules
    selftest    [M2] Send GTUBE/EICAR/clean test mail and verify scanning
    help        Show this help

ENVIRONMENT:
    MSFE_NG_SOCKET   Override the daemon socket path (default: {DEFAULT_SOCKET_PATH})"
    );
}
