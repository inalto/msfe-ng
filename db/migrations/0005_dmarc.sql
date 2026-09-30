-- DMARC aggregate reports read from the rua= mailbox (msfe-ng dmarc fetch).
-- One row per report; its per-source records; and one row per sending
-- source and domain, carrying the admin's triage. Classes (pass, forwarded,
-- this server, legitimate, suspect) are derived when queried, so re-triaging
-- a source reclassifies its whole history.
CREATE TABLE IF NOT EXISTS dmarc_reports (
  id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  org_name     VARCHAR(128) NOT NULL,
  org_email    VARCHAR(255) NOT NULL DEFAULT '',
  report_id    VARCHAR(255) NOT NULL,
  domain       VARCHAR(253) NOT NULL,
  date_begin   BIGINT       NOT NULL,
  date_end     BIGINT       NOT NULL,
  day          DATE         NOT NULL,
  p            VARCHAR(16)  NOT NULL DEFAULT '',
  sp           VARCHAR(16)  NOT NULL DEFAULT '',
  pct          SMALLINT UNSIGNED NULL,
  adkim        VARCHAR(4)   NOT NULL DEFAULT '',
  aspf         VARCHAR(4)   NOT NULL DEFAULT '',
  fo           VARCHAR(16)  NOT NULL DEFAULT '',
  records      INT UNSIGNED NOT NULL DEFAULT 0,
  messages     BIGINT UNSIGNED NOT NULL DEFAULT 0,
  imported_at  DATETIME     NOT NULL,
  origin       VARCHAR(8)   NOT NULL DEFAULT 'imap',
  UNIQUE KEY dmarc_reports_uniq (org_name, report_id(191)),
  KEY dmarc_reports_domain_day (domain, day),
  KEY dmarc_reports_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dmarc_records (
  id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  report         BIGINT UNSIGNED NOT NULL,
  day            DATE          NOT NULL,
  source_ip      VARCHAR(45)   NOT NULL,
  count          INT UNSIGNED  NOT NULL DEFAULT 0,
  disposition    VARCHAR(16)   NOT NULL DEFAULT '',
  dmarc_dkim     VARCHAR(16)   NOT NULL DEFAULT '',
  dmarc_spf      VARCHAR(16)   NOT NULL DEFAULT '',
  passed         TINYINT(1)    NOT NULL DEFAULT 0,
  forwarded      TINYINT(1)    NOT NULL DEFAULT 0,
  header_from    VARCHAR(253)  NOT NULL DEFAULT '',
  envelope_from  VARCHAR(253)  NOT NULL DEFAULT '',
  envelope_to    VARCHAR(253)  NOT NULL DEFAULT '',
  dkim_auth      VARCHAR(1024) NOT NULL DEFAULT '',
  spf_auth       VARCHAR(1024) NOT NULL DEFAULT '',
  reasons        VARCHAR(512)  NOT NULL DEFAULT '',
  KEY dmarc_records_report (report),
  KEY dmarc_records_from_day (header_from, day),
  KEY dmarc_records_ip (source_ip),
  KEY dmarc_records_day (day)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dmarc_sources (
  ip          VARCHAR(45)  NOT NULL,
  domain      VARCHAR(253) NOT NULL,
  first_seen  DATE         NOT NULL,
  last_seen   DATE         NOT NULL,
  rdns        VARCHAR(253) NULL,
  status      VARCHAR(12)  NOT NULL DEFAULT 'unknown',
  note        VARCHAR(255) NOT NULL DEFAULT '',
  alerted_at  DATETIME     NULL,
  PRIMARY KEY (ip, domain(191))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
