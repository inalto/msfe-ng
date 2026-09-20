-- Auto-ban: every temporary csf ban the engine placed, with why. The UI's
-- history, the dedup source for the next run, and what Telegram reports.
CREATE TABLE IF NOT EXISTS autoban (
  id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  banned_at   DATETIME     NOT NULL,
  expires_at  DATETIME     NULL,
  ip          VARCHAR(45)  NOT NULL,
  reason      VARCHAR(16)  NOT NULL,
  rule_id     INT UNSIGNED NULL,
  count       INT UNSIGNED NOT NULL DEFAULT 0,
  seconds     INT UNSIGNED NOT NULL DEFAULT 0,
  detail      VARCHAR(255) NOT NULL DEFAULT '',
  sample_id   BIGINT UNSIGNED NULL,
  KEY autoban_ip_idx (ip),
  KEY autoban_banned_at_idx (banned_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
