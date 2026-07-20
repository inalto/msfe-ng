# Contributing to MSFE-NG

Thanks for helping build an open-source MailScanner front-end for cPanel and
DirectAdmin. Please read the clean-room policy below **before** writing code —
it is the legal foundation of this project.

## Clean-room policy (mandatory)

MSFE-NG is a *from-scratch* reimplementation. The original ConfigServer
MailScanner Front-End (MSFE) and its readable Perl are **proprietary, all rights
reserved** ("Way to the Web Product License"). The company closing did **not**
release that copyright.

Rules:

1. **Never copy, paste, or transliterate** any original MSFE code — obfuscated
   or readable — into this repository.
2. You may **read the original only to understand *what* it does** (its behavior,
   the file formats it reads/writes, the external commands it runs), then write
   fresh code that achieves the same result, better.
3. Treat the following as reusable **facts/interfaces**, not as expression:
   flat-file config formats, MailScanner rule syntax, the `maillog` DB schema,
   Exim/MailScanner integration steps, and cPanel's own AppConfig/UAPI/hook APIs.
4. When a file or function is modeled on original behavior, add a short comment
   saying so (e.g. "spec: original msbe.pl domain reconciliation") — describing
   the *observed behavior*, never quoting the code.
5. **MailWatch** (GPL) may be used as a *reference* the same way, and — because
   it is GPL-compatible — small pieces *may* be adapted **with attribution** if
   clearly marked. When in doubt, reimplement.

If you have ever seen the original source and are unsure whether something is
tainted, ask in a PR before contributing it.

## Architecture at a glance

- **Rust** (`crates/`) — daemon (`msfe-ngd`), CLI (`msfe-ng`), core logic.
- **Thin Perl shims** (`panel/`) — only where cPanel/MailScanner load code by
  package name (UAPI module, managed hooks, MailScanner CustomConfig, cpwrapd).
  Keep them minimal; they forward to the daemon over its Unix socket.
- **Web** (`web/`) — the SPA served by the daemon.
- **Packaging** (`packaging/`) — `install.sh` / `uninstall.sh` and service unit.

See `docs/architecture.md` and `docs/feature-parity.md`.

## Dev setup

```sh
rustup toolchain install stable
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets
cargo fmt --all
```

Shell scripts should pass `shellcheck packaging/*.sh`; Perl shims should pass
`perl -c`.

## Licensing of contributions

By contributing you agree your work is licensed under **GPL-3.0-or-later**, the
license of this project.
