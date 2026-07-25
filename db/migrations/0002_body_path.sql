-- Record where each message's body copy actually lives (quarantine or archive),
-- so the UI resolves bodies by path instead of scanning the spool blindly.
--
-- Appended at the END of the table on purpose: an InnoDB ADD COLUMN with a
-- DEFAULT at the end is instant, so this does not rebuild a multi-million-row
-- maillog. Guarded so re-running the migration is harmless.
SET @c := (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = DATABASE()
             AND TABLE_NAME = 'maillog'
             AND COLUMN_NAME = 'body_path');
SET @s := IF(@c = 0,
  'ALTER TABLE maillog ADD COLUMN body_path VARCHAR(512) NOT NULL DEFAULT ''''',
  'SELECT 1');
PREPARE stmt FROM @s;
EXECUTE stmt;
DEALLOCATE PREPARE stmt;
