# Delivery → OSINT, Phase 5 (history and monitoring) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator watch an address: scheduled OSINT re-checks (at most daily), stored history in MySQL, change detection on stable finding identities, a monthly provider-usage budget, and separate Telegram alerts for new exposure, changed public references and provider problems — without duplicate alerts, duplicate charges, or a run when the monitor is disabled or removed.

**Architecture:** A new `osintmon.rs` mirrors `deliverymon.rs` (Monitor rows, runs history, `run_due` called from the existing `*/5` `msfe-ng monitor` pass) but keeps OSINT semantics separate: its own tables (`osint_monitors`, `osint_runs`, `osint_usage`, migration `0006`), its own cadence (≥ 1440 minutes), its own alert kinds and cooldown keys. All database access goes through a small `Store` trait so the orchestration, diffing, budget and baseline logic are unit-tested against an in-memory fake; the MySQL implementation is exercised against a scratch MariaDB instance. A scheduled run reuses `osintrun::start` (blocking poll like the CLI), with `force = true`.

**Tech Stack:** Rust 1.74 std only, system `mysql` client via `db.rs`, vanilla JS.

**Spec:** `docs/superpowers/specs/2026-10-02-delivery-osint-design.md` (§10 storage and monitoring, §9 gates "Monitoring"). Earlier plans: phases 1–4/6 in `docs/superpowers/plans/`.

**Branch policy:** the user asked for phases to be committed directly on `main`. Commit each task to `main`; do not push, tag or release unless the user asks (the user has authorised a final bump and push after all phases are done; that is a separate step).

## Global Constraints

- Rust 1.74, std only; `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`; unit tests never need a database or network (fake `Store`, fixture provider via `MSFE_NG_OSINT_FIXTURE`).
- Monitoring is opt-in and silent without it: no DB, a missing table, `osint_enabled=false`, no configured provider → `run_due` returns no work and no noise (like `deliverymon`).
- Minimum interval 1440 minutes (daily), maximum 10080; default 1440. A monitor never runs more often.
- A monitor stores its **approved source set** at creation (ids from `osintproviders::is_known`, validated; `delivery` is never allowed; `hunter` only if named explicitly); runs use exactly that set with `force=true`.
- Provider usage is metered per calendar month in `osint_usage` (provider, period `YYYYMM`, reserved units, final units, run id; no credentials). A monthly cap `osint_monitor_budget` (default 300 units, 0 = unlimited) is checked before every scheduled run; at the cap monitors skip and one "budget reached" alert is sent per month.
- Change detection compares stable identities, never `observed_at`: finding identity = `source_id` + group + (`source_url` if present else `title`); source state transitions are compared separately. The first run of a monitor is a baseline and never alerts.
- Alert kinds are separate messages: **new exposure/public references** (new findings in groups exposure/profile/reference/domain/validation), **provider unavailable** (a source that answered in the baseline now `failed`/`restricted`), **budget reached**. "No longer listed" and recoveries are never alerted, only recorded in history. Alerts never mix into Delivery alerts and never attach breach detail to Delivery messages.
- No duplicate alerts: a per-monitor baseline pointer (kv `osint_base_<monitor>` = run id) advances only when there is nothing to alert, the alert was sent, or Telegram is not configured; a failed send keeps the old baseline so the change is retried on the next run; the cooldown (`alert_cooldown_mins`) is per monitor and kind and is set only on a successful send.
- Removing a monitor deletes its runs and usage rows and its kv keys; disabling stops it; a run in flight when the monitor is removed or disabled stores nothing and sends nothing.
- At most `MAX_PER_PASS = 2` monitors run per `msfe-ng monitor` pass and a guard (`kv osintmon_running` timestamp, 10-minute stale limit) prevents overlapping passes.
- History retention `osint_history_days` (default 90) and at most 100 runs per monitor, pruned in housekeeping; stored reports contain no avatar bytes and `asset_id`/`asset_mime` are stripped before storing (assets expire).
- Admin (root) only; no `/api/user/` route. Alert text goes only to the already-configured Telegram destination.
- No server names (the user's production hostnames) in commits, docs, code or comments. Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- If a Tailwind class is added, `npm run build` in `web/` and commit `web/whm/app.css` and `web/user/app.css`.

## Review Focus

- Alert on a failed Telegram send must be retried on the next run, and a successful send must not repeat on the following run. Pinned in Task 2/3.
- A monitor removed or disabled while its run is in flight must leave no run row, no usage row and no alert. Pinned in Task 3.
- A source that flaps (matched → rate_limited → matched) must not alert as "provider unavailable"; only `failed`/`restricted` do. Pinned in Task 2.
- Budget: reserved units are settled to the real units after the run; a run that fails to start releases its reservation; the cap blocks a run without partial charges. Pinned in Task 3.
- First run of a monitor never alerts; a monitor re-created for the same address starts a new baseline. Pinned in Task 2/3.
- Addresses keep their exact local-part case (spec: the cache and monitor identity must not blindly lower-case); the UNIQUE key is case-sensitive (`utf8mb4_bin`), so `A@x.org` and `a@x.org` are two monitors. Pinned in Task 1.

---

## File Structure

| File | Responsibility |
|---|---|
| `db/migrations/0006_osint_monitors.sql` (create) | Three tables |
| `crates/msfe-core/src/osintmon.rs` (create) | Types, `Store` trait + `MysqlStore` + `FakeStore` (cfg(test)), SQL builders, diff/alerts, `run_due` |
| `crates/msfe-core/src/config.rs` (modify) | `osint_max_monitors`, `osint_history_days`, `osint_monitor_budget` |
| `crates/msfe-core/src/monitor.rs` (modify) | Step 5: `osintmon::run_due` |
| `crates/msfe-cli/src/main.rs` (modify) | `delivery osint monitor …`, housekeeping prune |
| `crates/msfe-ngd/src/osint_api.rs` (modify) | Monitor routes |
| `web/whm/index.html` (modify) | Monitors card in the OSINT view |
| `docs/wiki/OSINT.md`, `CLI.md`, `Config.md` (modify) | Docs |

---

### Task 1: Migration, settings and the data layer

**Files:** Create `db/migrations/0006_osint_monitors.sql`, `crates/msfe-core/src/osintmon.rs` (data layer part), modify `crates/msfe-core/src/config.rs`, `crates/msfe-core/src/lib.rs` (`pub mod osintmon;`).

**Interfaces (produces):**
- Config: `osint_max_monitors: u32` (default 10, clamp 1..100), `osint_history_days: u32` (90, clamp 1..730), `osint_monitor_budget: u32` (300, 0 = unlimited, clamp 0..100000); keys parsed like the other `osint_*` keys; public JSON exposes them as ints.
- `pub const MIN_INTERVAL_MINS: u32 = 1440; MAX_INTERVAL_MINS: u32 = 10080; DEFAULT_INTERVAL_MINS: u32 = 1440; KEEP_RUNS: usize = 100; MAX_PER_PASS: usize = 2;`
- `pub struct Monitor { id: u32, address: String, owner: String, sources: Vec<String>, interval_mins: u32, enabled: bool, created_at: u64, last_run_at: u64, last_summary: String }` with `due(now) -> bool` (`enabled && now - last_run_at >= interval_mins*60`), `to_json()` (adds `due`).
- `pub struct RunRow { id: u32, monitor_id: u32, started_at: u64, duration_ms: u32, state: String, n_findings: u32, n_sources_ok: u32, n_sources_bad: u32 }` with `to_json()`.
- `pub trait Store { fn list(&self, owner: Option<&str>) -> Result<Vec<Monitor>, String>; fn get(&self, id: u32) -> Result<Option<Monitor>, String>; fn add(&self, address: &str, owner: &str, sources: &[String], interval_mins: u32, max: u32) -> Result<Monitor, String>; fn remove(&self, id: u32) -> Result<bool, String>; fn set_enabled(&self, id: u32, enabled: bool) -> Result<(), String>; fn store_run(&self, monitor_id: u32, report: &OsintReport, duration_ms: u32, summary: &str) -> Result<u32, String>; fn runs(&self, monitor_id: u32, limit: usize) -> Result<Vec<RunRow>, String>; fn run_report(&self, run_id: u32) -> Result<Option<OsintReport>, String>; fn previous_run(&self, monitor_id: u32, before_run_id: u32) -> Result<Option<(u32, OsintReport)>, String>; fn run_by_id(&self, id: u32) -> Result<Option<(u32, OsintReport)>, String>; fn usage_month(&self, period: &str) -> Result<u32, String>; fn usage_reserve(&self, monitor_id: u32, period: &str, units: u32, run_id: &str) -> Result<(), String>; fn usage_settle(&self, run_id: &str, final_units: u32) -> Result<(), String>; fn usage_release(&self, run_id: &str) -> Result<(), String>; fn kv_get(&self, key: &str) -> Option<String>; fn kv_set(&self, key: &str, value: &str) -> Result<(), String>; fn touch_last_run(&self, id: u32, when: u64) -> Result<(), String>; fn prune(&self, days: u32) -> Result<(), String>; }`
- `pub struct MysqlStore<'a> { cfg: &'a Config }` implementing `Store` with the `db.rs` helpers (`query`, `exec_stdin`, `quote`, `kv_get`, `kv_set`); and `#[cfg(test)] pub struct FakeStore` (in-memory, `RefCell`/`Mutex`) implementing `Store` with the same semantics (unique address+owner case-sensitive, max cap, `KEEP_RUNS` trimming, cascading remove including usage rows and kv keys starting with `osint_base_<id>`/`alert_osint_<id>_`).
- Pure helpers: `clamp_interval(mins) -> u32`, `validate_sources(&[String], cfg) -> Result<Vec<String>, String>` (known ids, no `delivery`, de-duplicated, ≥1, `hunter` kept only if present in the input), `period_for(unix_secs) -> String` (`YYYYMM` via `civil::Date::from_unix`), `strip_assets(&mut OsintReport)` (sets `asset_id`/`asset_mime` to `None`), SQL builders returning `String` for every statement (unit-tested for quoting/escaping: an address containing `'`, `\` and a newline is impossible after `parse_address` but the builder must still escape via `db::quote`).

**Migration `0006_osint_monitors.sql`** (conventions of 0003/0005: `--` header comment, `CREATE TABLE IF NOT EXISTS`, `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`, `INT UNSIGNED` timestamps, `TINYINT(1)` booleans, no foreign keys):

```sql
CREATE TABLE IF NOT EXISTS osint_monitors (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  address VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  owner VARCHAR(64) NOT NULL DEFAULT '',
  sources VARCHAR(255) NOT NULL,
  interval_mins INT UNSIGNED NOT NULL DEFAULT 1440,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at INT UNSIGNED NOT NULL,
  last_run_at INT UNSIGNED NOT NULL DEFAULT 0,
  last_summary VARCHAR(255) NOT NULL DEFAULT '',
  UNIQUE KEY osint_monitors_addr (address(191), owner)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS osint_runs (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  monitor_id INT UNSIGNED NOT NULL,
  started_at INT UNSIGNED NOT NULL,
  duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
  state VARCHAR(16) NOT NULL,
  n_findings INT UNSIGNED NOT NULL DEFAULT 0,
  n_sources_ok INT UNSIGNED NOT NULL DEFAULT 0,
  n_sources_bad INT UNSIGNED NOT NULL DEFAULT 0,
  report MEDIUMTEXT NOT NULL,
  KEY osint_runs_monitor (monitor_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE TABLE IF NOT EXISTS osint_usage (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  monitor_id INT UNSIGNED NOT NULL,
  period CHAR(6) NOT NULL,
  reserved INT UNSIGNED NOT NULL DEFAULT 0,
  final_units INT UNSIGNED NULL,
  run_id VARCHAR(32) NOT NULL,
  created_at INT UNSIGNED NOT NULL,
  KEY osint_usage_period (period),
  UNIQUE KEY osint_usage_run (run_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

`usage_month(period)` = `SUM(COALESCE(final_units, reserved))` for that period (a reservation counts until settled).

- [ ] **Step 1: Failing tests** (pure + `FakeStore`): clamp (0 → 1440, 100 → 1440, 20000 → 10080, 2880 → 2880); `Monitor::due`; `validate_sources` (rejects empty/unknown/`delivery`, keeps `hunter` only when given, de-dups, preserves order); `period_for(0)` = `197001`, a December timestamp rolls correctly; `strip_assets`; SQL builders escape quotes/backslashes/newlines and produce the expected statements (assert on exact strings for the insert/upsert, the trim DELETE with `LIMIT KEEP_RUNS` and the cascading remove); `FakeStore` semantics: case-sensitive uniqueness (`A@x.org` and `a@x.org` are two monitors), max cap error text, `KEEP_RUNS` trimming keeps the newest, cascading remove deletes runs, usage rows and the monitor's kv keys, `usage_month` counts reserved until settled then final; `previous_run` returns the run with the next-lower id for that monitor only; config test for the three new keys (defaults and clamps).
- [ ] **Step 2: Run to verify failure:** `PATH=$HOME/.cargo/bin:$PATH cargo test -p msfe-core osintmon:: 2>&1 | tail`.
- [ ] **Step 3: Implement** the migration, config keys, data layer and `FakeStore`. Follow `deliverymon.rs` for the SQL style (`ON DUPLICATE KEY UPDATE`, multi-statement `exec_stdin` for store_run: INSERT run + UPDATE monitor `last_run_at`,`last_summary` + trim).
- [ ] **Step 4: Real MariaDB integration check** (not a repo test; report the output): `mariadb`/`mariadbd` are installed locally but inactive. Start a scratch instance as the current user in the scratchpad dir (`mariadb-install-db --no-defaults --datadir=<dir>/data --auth-root-authentication-method=normal` then `mariadbd --no-defaults --datadir=<dir>/data --socket=<dir>/sock --skip-networking --port=0 &`; adapt if the binaries differ), create a database and user, point a `Config` at it the way `db.rs` connects (read `db.rs` for host/socket/user/pass handling — if only TCP/localhost is supported, run with `--bind-address=127.0.0.1 --port=<free port>`), apply migrations 0001..0006 with `msfe-ng db-migrate` (`MSFE_NG_MIGRATIONS=db/migrations`) or `migrate::apply`, then drive `MysqlStore` from a scratch crate OUTSIDE the repo (scratchpad `smoke5`, path dependency on `crates/msfe-core`): add/list/get/remove, store a run with a report containing quotes/newlines/unicode, read it back identical, `previous_run`, usage reserve/settle/release/month, kv, prune, duplicate add, case-sensitive addresses, the cap. Shut the instance down and delete its data dir afterwards. If a scratch MariaDB cannot be started, say so plainly and do not claim the SQL was verified.
- [ ] **Step 5: Gates + commit**

```bash
git add -A crates db
git commit -m "OSINT: history tables, usage metering and the monitor data layer (phase 5)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Change detection, baseline policy and alert text (pure)

**Files:** Modify `crates/msfe-core/src/osintmon.rs`.

**Interfaces (produces):**
- `pub struct Delta { pub new_findings: Vec<FindingRef>, pub gone_findings: Vec<FindingRef>, pub went_bad: Vec<SourceRef>, pub recovered: Vec<SourceRef> }`, `FindingRef { source_id, group, title, source_url: Option<String>, severity }`, `SourceRef { id, from, to, detail }`.
- `pub fn finding_key(f: &Finding) -> String` = `format!("{}|{}|{}", f.source_id, f.group.as_str(), f.source_url.clone().unwrap_or_else(|| f.title.clone()))`.
- `pub fn diff_reports(prev: &OsintReport, cur: &OsintReport) -> Delta`: `new_findings` = keys in `cur` not in `prev`; `gone_findings` = keys in `prev` not in `cur` **only for sources whose state in `cur` is Matched or NoMatch** (a source that failed this time must not make its findings "gone"); `went_bad` = a source that was Matched/NoMatch in `prev` and is `Failed`/`Restricted` in `cur`; `recovered` = the reverse; `RateLimited`, `Inconclusive`, `NotConfigured`, `NotRequested`, `Unknown(_)` are never "bad" and never "ok" (ignored).
- `pub enum AlertKind { Findings, Providers, Budget }` with `key_part() -> &'static str` (`findings`, `providers`, `budget`).
- `pub fn alert_texts(host: &str, address: &str, delta: &Delta) -> Vec<(AlertKind, String)>`: one message per kind that has content. `Findings`: "OSINT watch of {address} on {host}: {n} new public item(s)\n" + up to 5 lines `• [{group}] {title}` (titles `clean_text`-ed to ≤100 chars) + "…and N more" when more; `Providers`: "OSINT watch of {address} on {host}: source problem\n" + lines `• {id}: answered before, now {to} ({detail})` (≤5). Recoveries and gone findings never produce text.
- `pub fn baseline_decision(delta_has_alerts: bool, all_sent_or_unconfigured: bool) -> bool` (true = advance the baseline to the current run).
- `pub fn cooldown_ok(now: u64, last: Option<u64>, cooldown_mins: u32) -> bool`.

- [ ] **Step 1: Failing tests:** identical reports → empty delta; a new finding in `cur` → one `new_findings`; the same finding with a different `observed_at`/evidence text/title but same source+group+url → NOT new (key stable); a finding without a URL keyed by title; a finding vanishing while its source is Matched → `gone`; vanishing while its source is `Failed` → NOT gone; went_bad: hibp Matched → Failed and → Restricted yes, → RateLimited no, → NotConfigured no, Failed → Failed no; recovered the reverse; `Unknown("x")` states ignored; alert texts: contents/limits (≤5 lines + "and N more", title cleaned and capped, address shown once, no evidence text and no raw URLs beyond the title), no text when only `gone`/`recovered`; `baseline_decision` truth table; `cooldown_ok` (None → true, exact boundary).
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** (pure functions only; reuse `osintproviders::clean_text`).
- [ ] **Step 4: Gates + commit**

```bash
git add -A crates
git commit -m "OSINT: stable change detection and alert text for monitors (phase 5)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 3: The scheduler (`run_due`), budget, alerts and hooks

**Files:** Modify `crates/msfe-core/src/osintmon.rs`, `crates/msfe-core/src/monitor.rs`, `crates/msfe-cli/src/main.rs` (housekeeping prune + `delivery osint monitor …` + flag table + usage), `packaging/cron/msfe-ng` only if a comment is useful (no new line: it rides the `*/5 monitor` pass).

**Interfaces (produces):**
- `pub trait Runner { fn run(&self, cfg: &Config, address: &str, sources: &[String]) -> Result<OsintReport, RunSkip>; }` with `pub enum RunSkip { Disabled, Busy, RateLimited, TooManyRuns, Invalid(String), Failed(String) }`; the real runner uses `osintrun::parse_inputs`/`start(force=true)` and polls `snapshot` every 200 ms until the state leaves `Running` or `osint_deadline_secs + 15` s pass (then `cancel` and `Failed("timed out")`); a `FakeRunner` (cfg(test)) returns canned reports/skips.
- `pub trait Notifier { fn configured(&self) -> bool; fn send(&self, text: &str) -> Result<(), String>; fn now(&self) -> u64; fn host(&self) -> String; }` with a `TelegramNotifier` and a `FakeNotifier` (records sends, can fail on demand, controllable clock).
- `pub fn run_due(cfg: &Config, dry: bool) -> Vec<String>` (public entry, wires the real implementations) and `pub fn run_due_with(cfg: &Config, store: &dyn Store, runner: &dyn Runner, notifier: &dyn Notifier, dry: bool) -> Vec<String>` (all logic).
- Behaviour of `run_due_with`, in order:
  1. `!cfg.osint_enabled` → `vec![]`. `store.list(None)` error (no DB / table) → `vec![]` silently.
  2. Guard: `kv osintmon_running` younger than 600 s → return one note "previous pass still running"; else set it to now (cleared at the end).
  3. Due, enabled monitors only, oldest `last_run_at` first, at most `MAX_PER_PASS`. Dry run: a "due … dry run, not started" note per monitor, nothing else.
  4. Budget: `period_for(now)`; `units = number of the monitor's sources that are configured (osintproviders::infos(cfg) configured flag)`; if `osint_monitor_budget > 0 && usage_month + units > budget` → skip the monitor with a note, and send ONE budget alert per month (kv `alert_osint_budget_<period>`), nothing reserved.
  5. Reserve (`usage_reserve` with an opaque run id string = `new_id()`); run via `Runner`; on `RunSkip::{Busy,RateLimited,TooManyRuns}` → `usage_release`, note, keep `last_run_at` unchanged (retried next pass); `Disabled`/`Invalid`/`Failed` → release, note.
  6. Re-check `store.get(id)`: if the monitor was removed or disabled while running → release the reservation, store nothing, alert nothing.
  7. Settle usage with the real units (sources that issued a request: state not `NotConfigured`/`NotRequested`); `strip_assets`; `store_run` (also updates `last_run_at`/`last_summary` = `"{n} finding(s), {ok} source(s) ok, {bad} not"`); `previous_run` → none ⇒ baseline run (set `osint_base_<id>` to this run id, note "baseline stored", no alert).
  8. Else diff against the **baseline run** (`kv osint_base_<id>` → `run_by_id`, falling back to `previous_run` if the pointer is missing/invalid), build texts; for each kind: cooldown (`alert_osint_<id>_<kind>` stores the last successful send time) → suppressed note, or send via `Notifier` (not configured → note and treat as "unconfigured" for the baseline decision; success → set the cooldown key; failure → note "Telegram failed: …", baseline stays). Advance the baseline (`osint_base_<id>` = this run id) per `baseline_decision` (nothing to alert, all sent, or Telegram unconfigured; a cooldown-suppressed kind counts as NOT sent → baseline stays so the change is alerted once the cooldown ends).
  9. Notes mention "Telegram alert sent" on a successful send (the monitor pass counts that substring).
- `monitor.rs`: step 5 after the Delivery step: `for n in osintmon::run_due(cfg, dry) { if n.contains("alert sent") { alerts_sent += 1 } notes.push(n) }` (mirror step 4; `dry` passed through).
- Housekeeping (`cmd_housekeeping`, next to the OSINT file sweep): `osintmon::prune(cfg, cfg.osint_history_days)`; result ignored like Delivery's.
- CLI `delivery osint monitor`: `list [--json]`, `add <address> [--sources a,b] [--interval-mins n]` (default sources = `osint_default_sources` minus nothing; `hunter` only when named), `remove <id|address>` (exact-case address match), `enable|disable <id>`, `run [--dry-run] [--id n]` (sets `last_run_at=0` for that id then calls `run_due`, printing notes), `history <id> [--json]`. Exit codes: 0 ok, 1 DB or cap error, 2 usage, 3 invalid input. Add `("delivery", Some("osint"))` flag entries for `--sources`, `--interval-mins`, `--dry-run`, `--id` (check `accepted_flags`/`rejected_flag` so `osint monitor` flags are not rejected and the existing `osint` flags still work), extend `usage_of("delivery")`.

- [ ] **Step 1: Failing tests** (all with `FakeStore`/`FakeRunner`/`FakeNotifier`): not enabled → no work; no due monitors → empty; a never-run monitor runs and stores a baseline with no alert; second run with a new finding alerts once with "alert sent", a third identical run does NOT alert again; Telegram send failure → baseline unchanged, next run alerts again, then success stops it (assert baseline pointer values); Telegram unconfigured → baseline advances, no spam; cooldown suppresses a second alert within the window and alerts after it (controlled clock) without losing the change (baseline stayed); `went_bad` alert once then not again; flapping matched→rate_limited→matched → no alert; removal/disable during the run (use a `FakeRunner` hook that mutates the store) → no run row, usage released, no alert; budget: cap reached → skipped, ONE budget alert per month, usage not reserved; reservation settled to final units, released on Busy/RateLimited/Disabled; `MAX_PER_PASS` honoured with 5 due monitors; the running guard (fresh → skip note, stale → proceed); dry run starts nothing; `last_run_at` unchanged on Busy; asset ids never stored; a `Failed` runner leaves history untouched; CLI: flag acceptance for the new subcommand flags and unchanged behaviour of `delivery osint <address>` flags, `osint monitor add` validation (interval clamp, unknown source → exit 3, `delivery` source refused), usage text.
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: If the scratch MariaDB from Task 1 can be started again, run one real end-to-end pass** with the fixture provider (`MSFE_NG_OSINT_FIXTURE=1`): `msfe-ng delivery osint monitor add fixture.test@example.org --sources fixture`, `monitor run`, change the fixture result (`breach.` local part) and run again, show the notes and the stored history rows; clean up. State plainly whether this was done.
- [ ] **Step 5: Gates + commit**

```bash
git add -A crates packaging
git commit -m "OSINT: scheduled monitoring with a usage budget, baselines and Telegram alerts (phase 5)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 4: API and the monitors card

**Files:** Modify `crates/msfe-ngd/src/osint_api.rs`, `web/whm/index.html`.

**API (all root-only, inside the existing OSINT prefix arm; `db_error(e)` as in `delivery_api.rs`: 503 with the "apply the pending migration: msfe-ng db-migrate" hint when the table is missing):**
- `GET /api/delivery/osint/monitors` → `{monitors:[Monitor json], max, budget:{cap, used, period}, telegram:bool, enabled:bool}`.
- `POST /api/delivery/osint/monitors` `{address, sources:[…], interval_mins?}` → 201 monitor JSON; 400 invalid address/sources/cap (`parse_address`, `validate_sources`, `osint_max_monitors`); 403 when `osint_enabled=false`; 503 DB.
- `POST /api/delivery/osint/monitors/remove` `{id}` (also `DELETE ?id=`) → 200/404; `POST .../enable` `{id, enabled}`; `POST .../run` `{id}` → 202 and spawns a thread calling `run_due` after `touch_last_run(id, 0)` (as the Delivery route does; note in a comment that it runs all due monitors, at most `MAX_PER_PASS`).
- `GET .../monitors/runs?id=&limit=` → `{runs:[RunRow json]}` (limit 1..200); `GET .../monitors/report?run=&format=json|html` → the stored report (HTML via `osinthtml::render`; no assets; 404 unknown).
- IDs must be positive integers; everything else 400.

**UI:** a collapsible "Monitors — watch an address" card appended to the OSINT view, mirroring the Delivery monitors card (`renderMonitors`, `showHistory`): explanatory text (daily at most, uses provider quota, alerts go to Telegram, first run is a baseline, monthly budget `used/cap`), an add row (address input prefilled from the current OSINT address, source checkboxes from `/providers` with the same default ticks as the Run form — configured, not `hunter`, no `delivery` — and an interval select 24 h / 48 h / 7 d), the table (address, sources, interval, last run, last result, buttons run now / history / pause|resume / remove with `confirm()`), a history modal (when, duration, state, findings, sources ok/bad; "open" renders the stored report with the same `paint` code as a live run; "html" export), all text through `el()`.

- [ ] **Step 1: Failing tests** (`Request::test` pattern): without a DB each endpoint returns 503 with the migration hint (the tests run without a database), `osint_enabled=false` → 403 on add, invalid address / unknown source / `delivery` source / interval clamp / bad id → 400, unknown route 404, non-root peer 403 (existing peer_scope test pattern for the new paths).
- [ ] **Step 2: Run to verify failure.**
- [ ] **Step 3: Implement** the API with a `Store` injected through a function parameter (default `MysqlStore`) so a unit test with `FakeStore` can cover list/add/remove/enable/runs/report success paths (cfg(test) constructor `handle_with_store`).
- [ ] **Step 4: UI + gates** (web build, `node --check`); real-browser check with headless Firefox as in earlier phases if the tooling in the scratchpad still works, using the scratch MariaDB if available (else stub `/api/...` responses in the page and say so): add a monitor, see it listed, pause/resume, history modal, remove; state plainly what was and was not checked.
- [ ] **Step 5: Commit**

```bash
git add -A crates web
git commit -m "OSINT: monitor API and the Monitors card (phase 5)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Documentation and final gates

**Files:** Modify `docs/wiki/OSINT.md`, `CLI.md`, `Config.md`, `Home.md`.

- [ ] **Step 1: Docs** (true to the code): what monitoring does and its opt-in nature (daily at most; needs the database and migration 0006: `msfe-ng db-migrate`, applied automatically on upgrade); the three tables; history retention (`osint_history_days`, 100 runs per monitor, reports stored without avatars; the "reports are only files for 24 h" statement in OSINT.md must now say that monitor runs are the exception); the monthly budget (`osint_monitor_budget`, units = sources that issued a request, reserved then settled, cap behaviour and the single monthly alert); change semantics (first run baseline, stable identities, what alerts and what does not, "no longer listed" and recoveries are history only, providers that go failed/restricted); alert separation and content (Telegram only, no Delivery mixing; the alert names the address and up to 5 titles — mention this is personal data sent to Telegram); retries/duplicates policy; removal/disable semantics; limits (`osint_max_monitors` default 10, at most 2 runs per 5-minute pass, one pass at a time); CLI `delivery osint monitor …` and the API summary; Config keys table; privacy and provider-terms note (recurring lookups multiply what each provider sees; check each provider's terms for monitoring use). No server names.
- [ ] **Step 2: Final gates** (paste results): `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace`; `(cd web && npm run build) && git diff --exit-code web/whm/app.css web/user/app.css`; `node --check` of the extracted script blocks; a `grep -rniE` over docs/wiki/OSINT.md crates/msfe-core/src/osint*.rs crates/msfe-ngd/src/osint_api.rs db/migrations/0006_osint_monitors.sql for the user\'s production hostnames listed in the project memory prints nothing; `shellcheck`/`perl -c` untouched.
- [ ] **Step 3: Commit**

```bash
git add -A docs
git commit -m "OSINT: phase 5 documentation (monitoring, history, budget, alerts)

Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>"
```

Do not push, tag or release in this plan; the release is a separate final step.

---

## Self-Review

**Spec coverage (§8 phase 5, §9 Monitoring, §10):** migration with monitors/runs/usage tables (T1); daily-at-most separate cadence (T1 constants, T3 guard); event-style change detection on stable IDs with separate alert kinds (T2); budget reservation/settlement without duplicate charges (T1 usage, T3); once-per-change alerts with retry on failure (T2 baseline policy, T3); revocation and expiry (T3 removal-in-flight, T1 prune); no breach detail in Delivery alerts (T2 text builders, T3 separate keys); works only with a DB and silently otherwise (T3).

**Placeholder scan:** adaptation points are explicit (`db.rs` connection style for the scratch instance, `accepted_flags`/`rejected_flag` shape, `Store::touch_last_run`).

**Type consistency:** `Store`, `Monitor`, `RunRow`, `Delta`, `AlertKind`, `Runner`, `Notifier`, `run_due(_with)` are defined once (T1–T3) and used in T3–T4; `touch_last_run` is added to `Store` in T3 if T1 omitted it.
