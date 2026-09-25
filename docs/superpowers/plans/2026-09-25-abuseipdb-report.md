# Report a banned IP to AbuseIPDB — plan

*2026-09-25. Manual only: when the admin blocks an address in the client-IP
view (csf), they can also report it to AbuseIPDB — typically a bot that posts
unsolicited web forms. Nothing automatic, no cron, no auto-ban involvement,
no database change.*

## Decisions (with the user)

- Target: **AbuseIPDB** (`https://api.abuseipdb.com/api/v2/report`, header
  `Key: <key>`, `Accept: application/json`, form fields `ip`, `categories`
  (comma list), `comment` (≤ 1024 chars), optional `timestamp` ISO 8601).
  A free account: 1,000 reports/day; the same IP is refused within 15
  minutes (HTTP 422, `errors[0].detail` says "reported … within the last 15
  minutes") — treated as "already reported", not a failure.
- Lookup: `https://api.abuseipdb.com/api/v2/check?ipAddress=<ip>&maxAgeInDays=90`
  → `data.abuseConfidenceScore`, `data.totalReports`, `data.lastReportedAt`,
  `data.isWhitelisted`, `data.usageType`, `data.isp`, `data.domain`.
- Categories offered (AbuseIPDB ids): 10 Web Spam, 19 Bad Web Bot (both
  preselected — the user's case), 11 Email Spam, 18 Brute-Force, 21 Web App
  Attack, 14 Port Scan. Reports carry at least one.
- The comment is public: the code never puts recipients, subjects, senders
  or the admin's domains in it. Prefill: `automated abuse from this address
  (<category names>); <N> message(s) seen by this mail server in the last 30
  days` (the count only when the activity is available). ≤ 1024 chars.
- The key is a secret: config key `abuseipdb_key`, masked as
  `abuseipdb_configured` in `to_public_json` (like `telegram_bot_token`),
  passed to curl through a private 0600 `--config` file (copy the pattern in
  `telegram.rs`), never on argv.
- Refused before any request: private / loopback / own addresses
  (`netguard::is_public`, `netguard::own_addresses`), addresses csf allows
  (`csf::list_state` → allow), an empty key, no categories, a CIDR (only a
  single address is reported; the ban may be a /24 — the report is the
  address that was seen).

## Conventions (binding)

Zero external crates. `cargo fmt`; `cargo test --workspace` and
`cargo clippy --workspace --all-targets -- -D warnings` green before the
commit. Fixtures use documentation addresses only (`192.0.2.x`,
`198.51.100.x`, `203.0.113.x`, `example.com`); never a real host name or
customer domain anywhere (commits, comments, fixtures, docs). One commit,
message in the repo style (`Area: what changed`, present tense), ending with
the trailer line given in the brief. Do not bump the version or tag.

## Task 1 — core: `crates/msfe-core/src/report.rs`

```rust
pub struct Category { pub id: u8, pub name: &'static str, pub hint: &'static str }
pub const CATEGORIES: &[Category];                 // the six above, in that order
pub fn category(id: u8) -> Option<&'static Category>;
pub struct Report { pub ip: String, pub categories: Vec<u8>, pub comment: String }
pub fn default_comment(categories: &[u8], messages_30d: Option<u64>) -> String;
pub fn validate(cfg: &Config, r: &Report) -> Result<(), String>;   // the refusals above, comment length, ip parse
pub enum Outcome { Reported { score: Option<u32> }, AlreadyReported, Refused(String), Failed(String) }
pub fn parse_report_reply(status: u16, body: &str) -> Outcome;     // 200 → data.abuseConfidenceScore; 422 with "15 minutes" → AlreadyReported; other 4xx/5xx → Failed(detail)
pub fn send(cfg: &Config, r: &Report) -> Outcome;                  // curl POST via --config (key in the file: `header = "Key: …"`), --max-time 15, -w for the status code
pub struct CheckInfo { pub score: u32, pub total_reports: u32, pub last_reported: Option<String>, pub whitelisted: bool, pub usage_type: String, pub isp: String, pub domain: String }
pub fn parse_check_reply(body: &str) -> Result<CheckInfo, String>;
pub fn check(cfg: &Config, ip: &str) -> Result<CheckInfo, String>;  // GET, same curl pattern
pub struct LogEntry { pub at: u64, pub ip: String, pub categories: Vec<u8>, pub comment: String, pub outcome: String, pub detail: String }
pub fn log_file(cfg: &Config) -> PathBuf;   // `<backup_dir>/reports.jsonl`, 0600; `MSFE_NG_REPORT_LOG` overrides (tests)
pub fn log_append(cfg: &Config, e: &LogEntry) -> io::Result<()>;
pub fn history(cfg: &Config, ip: Option<&str>, limit: usize) -> Vec<LogEntry>;  // newest first
```

`config.rs`: `abuseipdb_key: String` (default empty), parsed from
`abuseipdb_key`, exposed only as `abuseipdb_configured: bool` in
`to_public_json`, settable through the same path Settings uses for
`telegram_bot_token` (find how that key is written and mirror it; the UI
Settings card gains an "AbuseIPDB API key" field in the Telegram/alerts
group). `lib.rs`: `pub mod report;`.

Tests (inline): categories lookup; `default_comment` with and without the
count and its length cap; `validate` refusing private, loopback, a CIDR, no
categories, a 1100-char comment, and an allowed address (fixture csf root —
see how `csf::list_state_at` tests do it); `parse_report_reply` on captured
shapes: `{"data":{"ipAddress":"203.0.113.9","abuseConfidenceScore":47}}`,
`{"errors":[{"detail":"You can only report the same IP address (`203.0.113.9`) once in 15 minutes.","status":422}]}`,
`{"errors":[{"detail":"Authentication failed. Your API key is either missing, incorrect, or revoked.","status":401}]}`;
`parse_check_reply`; the log round trip (append, history newest first,
filter by ip, limit, junk lines skipped); `send` with an empty key returns
`Refused` without running curl.

## Task 2 — daemon + CLI

`api.rs` next to the `/api/ip/*` routes:

- `GET /api/ip/report?ip=` → `{configured, categories:[{id,name,hint}], default_comment, history:[{at,categories,outcome,detail}], check: {…}|null}` (`check` only when configured; a failed check is `null` with `check_error`).
- `POST /api/ip/report` `{ip, categories:[ids], comment}` → `200 {ok:true, outcome:"reported"|"already_reported", score}` / `400 {error}` for `Refused` / `502 {error}` for `Failed`. Every outcome (including refusals that reached the API) is appended to the log.
- `POST /api/ip/ban` unchanged; the UI calls report after a successful ban.

CLI in `crates/msfe-cli/src/main.rs`: `msfe-ng report <ip> [--category <id|name>]... [--comment <text>] [--dry-run] [--json]` (default categories 10,19; `--dry-run` prints the request and validates without sending), `msfe-ng report list [--ip <ip>] [--limit n] [--json]`. `accepted_flags`, `usage_of("report")`, dispatch, `print_help` lines next to `autoban`. Exit 0 / 1 on a refusal or failure / 2 usage.

Tests: daemon request validation in the `http.rs` test style (POST without ip → 400; private ip → 400; no key → 400 with "abuseipdb_key"); CLI `report --bogus` → 2, `report 10.0.0.1 --dry-run` → 1 with "private" on stderr, `report 203.0.113.9 --dry-run` → 0 printing the categories and comment, `report list` on an empty log → 0.

## Task 3 — UI + wiki

`web/whm/index.html`, `showIp` (the client-IP modal, around line 412):

- After the csf transcript and before the ban controls: a **Report to AbuseIPDB** block. Not configured → one muted line "Set the AbuseIPDB API key in Settings to report addresses" and nothing else. Configured → the check result line ("AbuseIPDB: confidence 47 %, 12 reports, last 2026-09-20 · hosting · ISP name" or "not known to AbuseIPDB"), the category checkboxes (10 and 19 ticked, each with its hint as title), a comment `textarea.mono` prefilled with `default_comment` (counter "n / 1024"), a note that the comment is public and must not contain addresses of your users, and a **Report now** button. Below it the history for this IP (date, categories, outcome) when any.
- In the ban controls: a checkbox **also report to AbuseIPDB** (only when configured; unticked by default) — after a successful ban, `doBan` posts the report with the categories and comment from the block above and appends the outcome to the transcript.
- Settings tab: an "AbuseIPDB API key" password field in the alerts/Telegram card, saved like the Telegram token; shows "configured" when set.
- CSS: none beyond existing classes if possible.
- Wiki: `docs/wiki/Messages.md` (client-IP view section) gets a "Report to AbuseIPDB" paragraph: manual only, what is sent, that the comment is public, the 15-minute rule, where the key is set, where the history lives; `docs/wiki/Settings.md` the key; `docs/wiki/CLI.md` the two commands.
- Verify: `node --check` on the extracted script; `cd web && npm run build` if the CSS changed.

Order: Task 1, then Tasks 2 and 3 (independent once the JSON contract above exists). One agent may do all three in sequence.
