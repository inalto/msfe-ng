# Quarantine browser + purge (admin) — design

Approved 2026-08-09. Admin-facing view of what is actually on disk in the
MailScanner quarantine, with manual purge. Motivated by the Aug 4–9 incidents:
quarantine received files the DB never logged (max-attempts archived
messages), and the only deletion mechanism was the nightly `bodydays` prune.

## Decisions (user-confirmed)

- **Source of truth: the disk.** List `/var/spool/MailScanner/quarantine`
  (config `quarantine_dir`), enriched from `maillog` where a row exists.
  Files without a DB row still appear.
- **Purge = selection + older-than.** Multi-select purge of chosen items, and
  "purge everything older than N days" with a dry-run preview. No
  purge-everything button.
- **Quarantine only.** The archive tree keeps its automatic retention and is
  out of scope.

## Backend (`msfe-core::quarantine`)

- `QuarantineEntry { date: String /*YYYYMMDD*/, id: String, kind: &'static
  str /*"spam"|"held"*/, size: u64, mtime: u64 }`.
- `list_quarantine(cfg, cap) -> QuarantineListing { total, bytes, truncated,
  entries }` — walks `<qdir>/<YYYYMMDD>/`, two layouts: `spam/<file>` (kind
  spam) and `<id>/` dirs or bare files at the date level (kind held; size =
  recursive). Newest date first. Non-`\d{8}` top-level entries ignored.
- Enrichment (API layer): one chunked
  `SELECT message_id, from_address, to_address, subject, sascore FROM maillog
  WHERE message_id IN (…)` via `db::query`.
- `purge_items(cfg, items: &[(String, String)], dry) -> PurgeReport { removed,
  bytes, errors }` — each (date, id) validated (`^\d{8}$`,
  `valid_message_id`-style name, no separators) and resolved under
  `quarantine_dir` only; deletes the file or dir. Empty date dirs removed.
- `purge_older_than(cfg, days, dry) -> PurgeReport` — compares the *date-dir
  name* against today−days (lexicographic on YYYYMMDD); deletes whole date
  dirs strictly older. Dry-run counts entries + bytes without deleting.
- DB rows are never touched: history remains; Messages "view body" already
  degrades when the file is gone.

## API (`msfe-ngd`)

- `GET  /api/quarantine?limit=` → `{ total, bytes, truncated, entries: [{date,
  id, kind, size, mtime, from?, to?, subject?, sascore?}] }`
- `POST /api/quarantine/purge` `{items: [{date, id}], dry}` → PurgeReport
- `POST /api/quarantine/purge-older` `{days, dry}` → PurgeReport
- `GET  /api/quarantine/message?date=&id=` → headers preview (safe reader,
  first ~200 lines) for files with no DB row.

## UI (WHM, new left-rail tab "Quarantine")

Table like Queues: Date · ID · kind badge · Size · From · Subject · Score,
checkbox multi-select; header totals ("N items, X MB"). Actions: Purge
selected (confirm), and "Purge older than [N] days" with Preview (dry-run)
then Purge (confirm). Row click = message view (Messages modal when the DB
knows the id, headers preview otherwise). No release here — that stays in
Messages.

## Testing

Fixture tree exercising both layouts and a junk top-level dir; purge item
validation (traversal, absolute paths, bad dates rejected); older-than
boundary (dir exactly at cutoff survives); dry-run leaves files and reports
identical counts to the real run.
