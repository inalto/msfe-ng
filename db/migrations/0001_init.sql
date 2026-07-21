-- MSFE-NG schema, migration 0001 (MySQL/MariaDB, utf8mb4).
-- Clean-room: column set for `maillog` follows the MailScanner logging contract
-- and is compatible with MailWatch's schema (facts/interfaces — no code copied).

CREATE TABLE IF NOT EXISTS schema_migrations (
  version     INT UNSIGNED NOT NULL PRIMARY KEY,
  name        VARCHAR(191) NOT NULL,
  applied_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per message scanned by MailScanner (written by the CustomConfig plugin).
CREATE TABLE IF NOT EXISTS maillog (
  row_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  msg_ts          DATETIME        NOT NULL,
  message_id      VARCHAR(191)    NOT NULL DEFAULT '',
  size            INT UNSIGNED    NOT NULL DEFAULT 0,
  from_address    VARCHAR(255)    NOT NULL DEFAULT '',
  from_domain     VARCHAR(255)    NOT NULL DEFAULT '',
  to_address      TEXT,
  to_domain       VARCHAR(255)    NOT NULL DEFAULT '',
  to_domains      TEXT,
  subject         TEXT,
  clientip        VARCHAR(45)     NOT NULL DEFAULT '',
  archive         TEXT,
  isspam          TINYINT(1)      NOT NULL DEFAULT 0,
  ishighspam      TINYINT(1)      NOT NULL DEFAULT 0,
  issaspam        TINYINT(1)      NOT NULL DEFAULT 0,
  isrblspam       TINYINT(1)      NOT NULL DEFAULT 0,
  isfp            TINYINT(1)      NOT NULL DEFAULT 0,
  isfn            TINYINT(1)      NOT NULL DEFAULT 0,
  spamwhitelisted TINYINT(1)      NOT NULL DEFAULT 0,
  spamblacklisted TINYINT(1)      NOT NULL DEFAULT 0,
  sascore         DECIMAL(8,2)    NOT NULL DEFAULT 0.00,
  spamreport      TEXT,
  rblspamreport   TEXT,
  virusinfected   TINYINT(1)      NOT NULL DEFAULT 0,
  nameinfected    TINYINT(1)      NOT NULL DEFAULT 0,
  otherinfected   TINYINT(1)      NOT NULL DEFAULT 0,
  report          TEXT,
  ismcp           TINYINT(1)      NOT NULL DEFAULT 0,
  ishighmcp       TINYINT(1)      NOT NULL DEFAULT 0,
  issamcp         TINYINT(1)      NOT NULL DEFAULT 0,
  mcpwhitelisted  TINYINT(1)      NOT NULL DEFAULT 0,
  mcpblacklisted  TINYINT(1)      NOT NULL DEFAULT 0,
  mcpsascore      DECIMAL(8,2)    NOT NULL DEFAULT 0.00,
  mcpreport       TEXT,
  hostname        VARCHAR(191)    NOT NULL DEFAULT '',
  headers         MEDIUMTEXT,
  quarantined     TINYINT(1)      NOT NULL DEFAULT 0,
  token           CHAR(40)        NOT NULL DEFAULT '',
  KEY maillog_msg_ts_idx (msg_ts),
  KEY maillog_message_id_idx (message_id),
  KEY maillog_from_domain_idx (from_domain),
  KEY maillog_to_domain_idx (to_domain),
  KEY maillog_clientip_idx (clientip),
  KEY maillog_isspam_idx (isspam),
  KEY maillog_ishighspam_idx (ishighspam),
  KEY maillog_virusinfected_idx (virusinfected),
  KEY maillog_quarantined_idx (quarantined),
  KEY maillog_token_idx (token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Index of quarantined messages, backing the viewer/release UI (M4).
CREATE TABLE IF NOT EXISTS quarantine (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_id   VARCHAR(191)    NOT NULL DEFAULT '',
  kind         ENUM('spam','virus','mcp','other') NOT NULL DEFAULT 'spam',
  stored_path  VARCHAR(1024)   NOT NULL DEFAULT '',
  from_address VARCHAR(255)    NOT NULL DEFAULT '',
  to_address   VARCHAR(255)    NOT NULL DEFAULT '',
  to_domain    VARCHAR(255)    NOT NULL DEFAULT '',
  subject      TEXT,
  quarantined_at DATETIME      NOT NULL,
  released      TINYINT(1)     NOT NULL DEFAULT 0,
  released_by  VARCHAR(191)    NOT NULL DEFAULT '',
  released_at  DATETIME        NULL,
  KEY quarantine_to_domain_idx (to_domain),
  KEY quarantine_released_idx (released),
  KEY quarantine_message_id_idx (message_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Application config as scoped key/value (global / per-domain / per-user).
-- The importer (msfe-ng import) writes migrated legacy settings here.
CREATE TABLE IF NOT EXISTS msfe_config (
  id       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  scope    ENUM('global','domain','user') NOT NULL DEFAULT 'global',
  scope_id VARCHAR(255)    NOT NULL DEFAULT '',
  ckey     VARCHAR(191)    NOT NULL,
  cvalue   TEXT,
  UNIQUE KEY msfe_config_scope_key (scope, scope_id, ckey)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
