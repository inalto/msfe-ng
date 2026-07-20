# Database

MSFE-NG uses **MySQL/MariaDB**. Schema migrations live in `migrations/` and are
applied by the installer/daemon starting in **M1**.

M1 will add:
- `maillog` — one row per scanned message (spam/virus verdicts, scores, report,
  quarantine flag, addresses, timestamps). Column set is modeled on the
  MailScanner logging contract and MailWatch's schema (reference only).
- `quarantine` — index of held messages for the viewer/release UI (M4).
- app config/state tables (or keep config in `/etc/msfe-ng` — decided in M1).

Nothing here is created in M0, so the M0 uninstaller has no database to drop.
