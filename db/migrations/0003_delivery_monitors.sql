-- Delivery-test monitors: an address (with its test options) re-tested on a
-- schedule by `msfe-ng monitor`, and the history of those runs. The report
-- column holds the full JSON report so a past run can be opened and compared.
CREATE TABLE IF NOT EXISTS delivery_monitors (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  address       VARCHAR(254) NOT NULL,
  owner         VARCHAR(64)  NOT NULL DEFAULT '',
  options       TEXT         NOT NULL,
  interval_mins INT UNSIGNED NOT NULL DEFAULT 360,
  enabled       TINYINT(1)   NOT NULL DEFAULT 1,
  created_at    INT UNSIGNED NOT NULL,
  last_run_at   INT UNSIGNED NOT NULL DEFAULT 0,
  last_summary  VARCHAR(255) NOT NULL DEFAULT '',
  UNIQUE KEY delivery_monitors_addr (address, owner)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS delivery_runs (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  monitor_id  INT UNSIGNED NOT NULL,
  started_at  INT UNSIGNED NOT NULL,
  duration_ms INT UNSIGNED NOT NULL DEFAULT 0,
  n_pass      INT UNSIGNED NOT NULL DEFAULT 0,
  n_warn      INT UNSIGNED NOT NULL DEFAULT 0,
  n_fail      INT UNSIGNED NOT NULL DEFAULT 0,
  n_unknown   INT UNSIGNED NOT NULL DEFAULT 0,
  report      MEDIUMTEXT   NOT NULL,
  KEY delivery_runs_monitor (monitor_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
