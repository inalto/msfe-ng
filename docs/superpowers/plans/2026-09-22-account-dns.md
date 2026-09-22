# Account DNS — implementation plan

Spec: `docs/superpowers/specs/2026-09-22-account-dns-design.md` (read it first;
it holds the data model, the JSON contract, the cPanel facts and the UI).

Conventions for every task: no external crates; `cargo fmt`; `cargo test
--workspace` and `cargo clippy --workspace --all-targets -- -D warnings` green
before the commit; fixtures use documentation domains only (`example.com`,
`example.net`, `example.org`, subdomains of those) and documentation IPs
(`192.0.2.x`, `198.51.100.x`); never a real host name, customer domain or
customer address anywhere (commits, comments, fixtures, docs); one commit per
task, message in the repo's style (`Area: what changed`, present tense, no
server names), ending with the Co-Authored-By line given in the session.

## Task 1 — core module `crates/msfe-core/src/acctdns.rs`

Deliver everything under "Module `acctdns.rs`" in the spec: model + `to_json`
/ `from_json`, `parse_userdata_main`, `list_domains`, the three validator
parsers, `suggest_spf`, `spf_notes`, `dkim_notes`, `dkim_suggested`,
`suggest_dmarc`, `dmarc_check`, `classify_spf`, `classify_dkim`, `row_level`,
`validate` (chunked `whmapi1` calls through `cpaudit::Cp`), `check_one`, `fix`,
the scan registry (`start`, `snapshot`, `last`, `StartError`), persistence
(`MSFE_NG_ACCTDNS_FILE`), and `pub mod acctdns;` in `lib.rs`. Fixture tree under
`crates/msfe-core/tests/fixtures/acctdns/` (or inline strings + a tempdir, the
way `cpaudit.rs` tests do it) with `_cmd/acctdns_spfs.txt`,
`_cmd/acctdns_dkims.txt`, `_cmd/acctdns_authority.txt`,
`_cmd/acctdns_fix_spf.txt`, `_cmd/acctdns_fix_dkim.txt`,
`_cmd/acctdns_fix_dmarc.txt` shaped exactly like the captured JSON quoted in
the spec. Tests as listed under "Tests" in the spec. Keep `cpaudit.rs`
untouched except for making `pem_to_der_b64` reachable (it is already `pub`).

## Task 2 — daemon route and CLI

`crates/msfe-ngd/src/acctdns_api.rs` with `handle(m, p, req, cfg, config_file)`
for the three routes in the spec, routed from `api.rs` next to `delivery_api`
(`p.starts_with("/api/acctdns/")`), `mod acctdns_api;` in `main.rs`. CLI
`acctdns scan|fix` in `crates/msfe-cli/src/main.rs` (`accepted_flags`,
`usage_of`, `print_help`, dispatch, `cmd_acctdns`), exit codes as in the spec.
Tests: daemon request validation (the `http.rs` test style with `path_req`),
CLI integration in `crates/msfe-cli/tests/cli.rs` (`--bogus` → 2 with usage;
`fix` without args → 2; `scan --json` under `MSFE_NG_CPANEL_ROOT` pointing at a
tempdir fixture prints rows).

## Task 3 — UI and docs

`web/whm/index.html`: rail label "Delivery"; `renderDelivery` dispatcher with
the view pills; the existing body unchanged inside `renderDeliveryTest`;
`renderAcctDns` with controls, table, detail rows, repair modal, poller
(`dlvAcctTimer`, cleared on tab switch); `deliveryTestFor` selects the test
view. `web/src/app.css` additions, then `cd web && npm run build` (commits both
`whm/app.css` and `user/app.css`). Docs: `docs/wiki/Account-DNS.md`,
`_Sidebar.md`, `Home.md`, `Admin-UI-basics.md` (tab label), `CLI.md`,
`README.md` feature list. Check the JS with `node --check` on the extracted
script (or a quick `node -e` parse of the `<script>` body) and load the page
through the dev daemon if one is available; otherwise verify by reading.

Order: Task 1 first; Tasks 2 and 3 in parallel afterwards.
