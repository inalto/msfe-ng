# Database

MSFE-NG uses **MySQL/MariaDB**. Migrations are `NNNN_name.sql` files in
`migrations/`, applied with `msfe-ng db-migrate` (which shells out to the `mysql`
client and tracks applied versions in `schema_migrations`). Run
`msfe-ng db-migrate --status` to see pending vs applied.

`0001_init.sql` creates:
- `maillog` — one row per scanned message (spam/virus/MCP verdicts, scores,
  reports, quarantine flag, addresses, headers, timestamps). Column set follows
  the MailScanner logging contract and is compatible with MailWatch's schema
  (reference only — no code copied). Written by the `MailScanner::CustomConfig`
  logging plugin (`panel/mailscanner/MSFENG.pm`).
- `quarantine` — index of held messages for the viewer/release UI (M4).
- `msfe_config` — scoped (global/domain/user) key/value app config; the importer
  (`msfe-ng import`) targets this.
- `schema_migrations` — applied-migration bookkeeping.

The database holds user mail data and is never dropped automatically on
uninstall; the uninstaller prints the manual `DROP DATABASE` command instead.
