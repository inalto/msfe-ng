-- OSINT monitors (Delivery -> OSINT): an address checked on a schedule with
-- the source set approved when it was added; one row per run carrying the
-- stored report (no avatar bytes); and the provider units metered per
-- calendar month, so a monthly cap can be enforced. Address and owner are
-- compared case-sensitively (utf8mb4_bin): the local part is not blindly
-- lower-cased.
-- No foreign keys: removing a monitor deletes its rows explicitly.
CREATE TABLE IF NOT EXISTS osint_monitors (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  address VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  owner VARCHAR(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  sources VARCHAR(255) NOT NULL,
  interval_mins INT UNSIGNED NOT NULL DEFAULT 1440,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  created_at INT UNSIGNED NOT NULL,
  last_run_at INT UNSIGNED NOT NULL DEFAULT 0,
  last_summary VARCHAR(255) NOT NULL DEFAULT '',
  UNIQUE KEY osint_monitors_addr (address, owner)
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
