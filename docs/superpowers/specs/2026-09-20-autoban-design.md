# Auto-ban and match rules — design

Date: 2026-09-20. Status: approved in conversation, to implement.

## Problem

Spam sources keep sending after MailScanner has scored them; the admin sees
the same IPs in the Messages tab and blocks them by hand from the client-IP
modal. Campaigns are recognisable by a subject or a sender long before the
scores agree. Wanted: temporary csf bans driven by MailScanner's verdicts,
per-severity thresholds with the option to ban on the first message, and
admin-defined match rules (subject, sender, header, body) that both block
delivery and ban the source — all configurable and switchable from the UI,
including straight from a message row.

## Existing code reused

- `csf.rs`: `ban(target, comment, …)` (gains a seconds form), `validate_target`
  (own/loopback/private refusal), `lookup` (`csf -g`), `unban`.
- `maillog` (DB): `id`, `msg_ts`, `clientip`, `isspam`, `ishighspam`,
  `sascore`, `spamreport`, `subject`, `from_address`; `db::kv_get/kv_set`.
- `sync::run` (writes generated files, reloads MailScanner only on change),
  `policy_dir` (`/etc/msfe-ng/policy`), snapshots (carry the policy dir).
- `telegram::send`, `config.rs` key pattern (`queue_clean_*`), the Settings
  tab card pattern, the client-IP modal, `packaging` cron file
  (`/etc/cron.d/msfe-ng`), doctor `check()`.

## Architecture decisions

1. **Bans come from the log, not from the scan.** A cron command
   (`msfe-ng autoban run`, every minute) reads `maillog` rows newer than the
   last processed id (kv `autoban_last_id`) and decides. Latency ≤ 1 min; the
   scanning path is untouched; a dry run is trivial.
2. **Match rules are SpamAssassin rules.** `sync` generates
   `/etc/mail/spamassassin/msfe-ng-match.cf` from the match rules: `header`
   / `body` rules named `MSFE_MATCH_<id>`, score 100 when the rule blocks
   (above any high-spam threshold → the domain's high-spam action, i.e. never
   delivered), 0.01 when it only bans (tagged in the report, verdict
   unchanged). Whitelisted mail skips SpamAssassin and therefore match rules.
   A pattern is validated at save time exactly as SpamAssassin will compile
   it — `perl -e 'qr/…/i'` under the engine's perl (`autoban::check_regex`)
   — so a bad regex is refused with perl's message before anything is
   written. After writing, `sync` runs `spamassassin --lint` (`sa::lint_prefs`
   style, whole site config); on failure the previous file is restored and
   the error reported.
3. **Safeguards are fixed, not knobs**: never ban own/loopback/private
   addresses, an address in `csf.allow`/`csf.ignore` or already denied
   (`csf -g`), an address that also delivered clean mail in the rule's window
   (a shared provider IP with one false positive), or an address banned by
   this engine within the last window (dedup). Cheap checks first, `csf -g`
   last and only for candidates.
4. **Every ban is a row** in a new table `autoban` — the UI history, the
   Telegram line, and the dedup source. Match rules live in the policy dir as
   JSON so snapshots, backups and `sync` carry them; severity thresholds are
   config.toml keys.

## Data

`db/migrations/0004_autoban.sql`:

```sql
CREATE TABLE autoban (
  id        BIGINT AUTO_INCREMENT PRIMARY KEY,
  banned_at DATETIME NOT NULL,
  expires_at DATETIME NULL,
  ip        VARCHAR(45) NOT NULL,
  reason    VARCHAR(16) NOT NULL,   -- 'high', 'spam', 'match'
  rule_id   INT NULL,               -- match rule id
  count     INT NOT NULL,
  seconds   INT NOT NULL,
  detail    VARCHAR(255) NOT NULL,  -- the comment given to csf
  sample_id BIGINT NULL,            -- a maillog id that triggered it
  KEY autoban_ip_idx (ip), KEY autoban_banned_at_idx (banned_at)
);
```

config.toml keys (all default off / stock values):

```
autoban_high_enabled = false   autoban_high_count = 1   autoban_high_window_secs = 600    autoban_high_ban_secs = 86400
autoban_spam_enabled = false   autoban_spam_count = 3   autoban_spam_window_secs = 3600   autoban_spam_ban_secs = 7200
autoban_telegram = true        (a line per ban when Telegram is configured)
```

`/etc/msfe-ng/policy/match.rules.json`:

```json
[{"id":3,"enabled":true,"field":"subject","match":"contains","pattern":"Your account has been suspended",
  "block":true,"ban_secs":86400,"comment":"suspension phishing wave","created":"2026-09-20T18:00:00Z"}]
```
`field`: `subject` | `from` | `to` | `header:<Name>` | `body`. `match`:
`contains` (escaped, case-insensitive) | `regex` (PCRE as SpamAssassin takes
it, `/…/i` added when no delimiters given). Ids are never reused.

## Modules (msfe-core)

`autoban.rs`
- `Rules { high: Threshold, spam: Threshold }` from `Config`;
  `Threshold { enabled, count, window_secs, ban_secs }`.
- `MatchRule` (+ `load_match_rules(policy_dir)`, `save_match_rules`,
  `next_id`), `sa_rules_text(&[MatchRule]) -> String` (pure; the `.cf`).
- `pattern_to_regex(match, pattern) -> String` (pure; escapes `contains`).
- `Candidate { ip, reason, rule_id, count, seconds, sample_id, detail }`.
- `evaluate(rows: &[Row], rules, match_rules, now) -> Vec<Candidate>` (pure:
  grouping by IP, windows, clean-mail exemption, per-IP dedup across reasons —
  the longest ban wins).
- `run(cfg, config_file, dry) -> Report { candidates, banned, skipped:
  Vec<(ip, why)> }`: query rows since `autoban_last_id` (bounded: last 24 h
  and 20 000 rows), evaluate, filter by csf state and recent `autoban` rows,
  ban, insert rows, advance the kv, Telegram.
- `history(cfg, limit) -> Vec<BanRow>`.
- `csf::ban_secs(target, comment, secs)` (csf `-td <ip> <secs>`).
- `sync`: writes `msfe-ng-match.cf` from the match rules when the engine has
  a site rules dir; lint first; counted as a changed file (→ reload).

Units: the UI edits value + unit (s/m/h/d) and stores seconds; the CLI
prints `1d`, `2h`, `10m`. Helper `format_secs`/`parse_secs` (pure, tested).

## API

- `GET /api/autoban` → thresholds, `csf_available`, `telegram_configured`,
  match rules, last run (kv `autoban_last_run`), counts.
- `PUT /api/autoban/settings` (thresholds), `PUT /api/autoban/rules`
  (whole list; lint failure → 400 with text and nothing written; success →
  `sync` and reload only if the `.cf` changed).
- `POST /api/autoban/test` `{field, match, pattern}` → validates the pattern
  (`check_regex`) and, for `subject`/`from`/`to`, lists which of the last 200
  messages in `maillog` would match — evaluated by the same perl `qr//` over
  the stored subject/sender (one perl run, the values on stdin), so the
  answer is SpamAssassin's own regex engine; `header:`/`body` rules are only
  validated (the DB holds no bodies or arbitrary headers).
- `POST /api/autoban/run` `{dry_run}` → the report.
- `GET /api/autoban/history?limit=50`.
- Existing `POST /api/ip/unban` for the unban button.

## UI (`web/whm/index.html`)

Config tab (Maintenance & tools) card **Auto-ban spam sources (csf)**: a note when csf is absent;
two threshold rows (enabled, count, window value+unit, ban value+unit);
**Match rules** table (enabled, field, match, pattern, block, ban, comment;
add / edit / delete; **Test** shows matching recent messages); **Save**;
**Dry run now** with its transcript; **Recent auto-bans** (IP, when, reason,
expires, *unban*).

Messages tab: row action and full-email view button **Ban rule…** → the
match-rule editor prefilled (subject contains ⟨subject⟩ by default; From
address, or the client IP as a one-off csf ban that goes through the existing
`/api/ip/ban`), save → live.

## CLI

`msfe-ng autoban status` (rules, last run, counts), `msfe-ng autoban run
[--dry-run]` (the cron command; prints the report), `msfe-ng autoban rules`
(the match rules). Cron: `* * * * * root /opt/msfe-ng/bin/msfe-ng autoban run
>/dev/null 2>&1` in `/etc/cron.d/msfe-ng` (a no-op in under 50 ms when
nothing is enabled: the kv/config check comes before any query).

## Doctor

`auto-ban` check: Warn when a threshold or match rule is enabled and csf is
not installed, or the generated `.cf` is missing/stale versus the rules
(`sync` fixes it — mechanical, in `--fix`).

## Tests

Pure: `evaluate` (threshold reached / not; window edges; clean-mail
exemption; dedup; match rule immediate; longest ban wins; disabled rules),
`sa_rules_text` and `pattern_to_regex` (escaping, delimiters, header names),
`parse_secs/format_secs`, match-rule JSON round trip and id allocation.
Integration: `sync` writes the `.cf` on a fixture (lint skipped when no
`spamassassin` binary is on the PATH, reported as such); CLI `autoban status`
with nothing enabled; migration 0004 listed by `db-migrate --status`.

## Out of scope

Real-time (per-message) banning inside MailScanner; permanent bans; banning
networks; scoring budgets; un-banning on clean mail.
