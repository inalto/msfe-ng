# Local submission privacy (issue #15)

Webmail (Roundcube) submits to Exim over authenticated SMTP on loopback. Exim's
stock `received_header_text` then prints the sending host, so every webmail
message leaves with `Received: from localhost (server.name) [127.0.0.1]`.
Neither MailScanner nor MSFE-NG touches trace headers, and nothing should
rewrite `Received:` after reception (it breaks tracing). The fix belongs in
Exim's own template, applied through cPanel's supported override so it
survives `buildeximconf`. Three levels, as the reporter suggested.

## 1. Detection (doctor, read-only)

Check **"webmail submissions hide the loopback hop"** (cPanel only):

- effective template = `exim -bP received_header_text` (10 s timeout; fall
  back to grepping `/etc/exim.conf` when exim cannot run);
- *ours* when the value guards the `from` clause with `def:authenticated_id`
  **and** `match_ip{$sender_host_address}` (the exact text is not required —
  an admin may have written an equivalent by hand);
- *exposes* when the value prints `$sender_rcvhost` / `$sender_host_address`
  without such a guard (the stock template);
- Warn when it exposes and our block is not installed, fix text = the switch
  in Settings or `msfe-ng localsub on`, proposal `Commands([["msfe-ng","localsub","on"]])`;
- Warn when our block **is** installed but not in effect (cPanel rebuilt
  without it, someone edited the file): fix = `/scripts/buildeximconf &&
  /scripts/restartsrv_exim`, proposal with those commands — never applied by
  `--fix` (an admin's hand edit is not overwritten silently);
- Ok with detail "Exim prints no host for authenticated loopback submissions
  (installed by MSFE-NG | by the administrator)".
- Not cPanel → no check.

## 2. The switch (module `crates/msfe-core/src/localsub.rs`)

State on disk only (no config.toml key): the block between markers
`# --- MSFE-NG local submission privacy start/end ---` under the `@CONFIG@`
section of `/etc/exim.conf.local` (`MSFE_NG_EXIM_CONF_LOCAL` in tests, same
as diaginbox). Splice like `diaginbox::splice` (strip our block everywhere,
re-insert after `@CONFIG@`, add the marker at the end when missing). The
block sets:

```
received_header_text = Received: ${if and{{def:authenticated_id}{match_ip{$sender_host_address}{<; 127.0.0.0/8 ; ::1}}}\
  {}\
  {${if def:sender_rcvhost {from $sender_rcvhost\n\t}{${if def:sender_ident {from ${quote_local_part:$sender_ident} }}${if def:sender_helo_name {(helo=$sender_helo_name)\n\t}}}}}}\
  by $primary_hostname ${if def:received_protocol {with $received_protocol }}${if def:tls_in_ver { ($tls_in_ver)}}${if def:tls_in_cipher_std { tls $tls_in_cipher_std\n\t}}(Exim $version_number)\n\t${if def:sender_address {(envelope-from <$sender_address>)\n\t}}id $message_exim_id${if def:received_for {\n\tfor $received_for}}
```

i.e. Exim's stock text with one condition: authenticated **and** from
127.0.0.0/8 or ::1 → no `from …` clause at all (RFC 5321 allows a Received
line without it; `with esmtpsa` still records that it was authenticated).
Everything else (TLS, protocol, envelope-from, id, for) is unchanged, and any
other hop — external authenticated clients included — prints exactly as
before.

`apply(cfg, install: bool, dry) -> Report { ok, actions: Vec<String>, backup: Option<stamp> }`:

1. refuse unless `cfg.panel == "cpanel"` (or the test env var is set);
2. refuse to install when `/etc/exim.conf` (`engine::exim_conf_path()`)
   already sets `received_header_text` outside our block — Exim rejects an
   option set twice; the report names the line;
3. backup `/etc/exim.conf.local` byte for byte to
   `/etc/msfe-ng/localsub/<stamp>/exim.conf.local` (+ `state.json`: action,
   time, effective template before); stamps unique per second like footers;
   keep the last 10; `backup_root` honours `config_file`'s dir like
   `footers::backup_root`;
4. splice, `sync::atomic_write` (or the same atomic helper footers uses);
5. `/scripts/buildeximconf`, then validate: `exim -bV` exits 0 **and**
   `exim -bP received_header_text` shows the guard (install) / no longer
   shows it (uninstall). On any failure: put the backup back, run
   buildeximconf again, report failure with the output — nothing stays
   half-applied;
6. `/scripts/restartsrv_exim`;
7. `MSFE_NG_SKIP_EXIM_CMDS` → log "would run" and skip validation (tests).

`restore(cfg, stamp, dry)` puts a backup back (steps 5–6 again).
`state(cfg) -> State { applicable, installed, effective: Effective::{Ours,Hand,Exposes,Unknown}, conflict: Option<String>, backups, preview }`.

**Preview** (best effort, hidden when exim is missing): expand the
template as Exim would for two simulated hops with
`exim -be -oMa <ip> -oMai user@example.com -oMr esmtpsa -oMs <host> '<template>'`
— `127.0.0.1`, `::1` (hidden) and `203.0.113.5` (shown) — so the UI can show
the resulting `Received:` lines side by side before and after. If `-be` fails
the preview is simply absent.

## 3. Roundcube origin header (read-only guidance)

`localsub::roundcube_state()` reads `http_received_header` and
`http_received_header_encrypt` from cPanel's Roundcube config
(`/usr/local/cpanel/base/3rdparty/roundcube/config/config.inc.php`, plus
`/var/cpanel/roundcube/config.inc.php` when present) and reports on/off/unknown.
MSFE-NG does **not** write Roundcube's config (cPanel regenerates
`config.inc.php` on every update; the route to persist a custom value is
cPanel's, not ours — the docs name the option and the privacy trade-off, the
card shows the current value). Off by default; nothing changes.

## Surfaces

- API: `GET /api/localsub` (state_json), `POST /api/localsub/apply {install: bool, dry?: bool}`,
  `POST /api/localsub/restore {stamp}`; same response shape as footers
  (`report_json`: ok, actions/transcript, backup).
- CLI: `msfe-ng localsub <status [--json] | on [--dry-run] | off [--dry-run] | restore [<backup>] [--dry-run] | backups>`
  (usage table + flags table in main.rs; tests in `crates/msfe-cli/tests/cli.rs`
  like `footers_flags_and_usage`).
- UI, Settings tab, new card **"Local submission privacy"** right after the
  footers card (`renderLocalsubCard(v)`): one paragraph of explanation; a
  status line (hidden / exposed / set by the administrator / not cPanel /
  conflict); the preview (two `Received:` lines, "webmail on this server" vs
  "external authenticated client"); one button **Hide the loopback hop** /
  **Show it again** (confirm, then POST apply, transcript in a `pre.log`);
  backups `<details>` with **Put back** like footers; a sub-block
  **Roundcube origin header** showing the current value with the explanation
  and privacy caution (no button).
- Doctor check (section 1) in `doctor::run` next to the other cPanel Exim
  checks; `doctor::apply` already runs `Proposal::Commands`.
- `packaging/uninstall.sh`: `msfe-ng localsub off` next to the diagnostic
  inbox uninstall (best effort).

## Tests

- splice: install → idempotent → uninstall round trip, `@CONFIG@` missing
  gets added, an older block elsewhere in the file is removed, other
  sections untouched;
- verdict on `exim -bP` samples: stock text → Exposes; ours → Ours; a
  hand-written guard (`def:authenticated_id` + `match_ip`) → Hand; empty → Unknown;
- conflict detection on an `exim.conf` that sets `received_header_text`;
- apply/restore under `MSFE_NG_EXIM_CONF_LOCAL` + `MSFE_NG_SKIP_EXIM_CMDS`
  with a tempdir: backup written, file spliced, restore is byte-identical;
- CLI usage/flags.

CI: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`, `node --check` on the inlined script, shellcheck.
