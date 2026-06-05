-- H1: make free-tier issuance an ATOMIC per-(ip_hash, day_bucket) cap.
--
-- A new `slot` column (0-based index within each ip+day group) plus a UNIQUE
-- index on (ip_hash, granted_day_bucket, slot) turns issuance into a race-safe
-- gate: a new grant inserts with `slot = COUNT(existing grants for this
-- ip+day)`, so two concurrent requests compute the same slot and collide on
-- the unique index — exactly one wins. Closes the prior check-then-insert
-- TOCTOU where racing callers could each pass the count check and over-issue.
--
-- The backfill assigns distinct slots to any rows that already share an
-- (ip_hash, granted_day_bucket) pair (legitimate under the old code for NATed
-- networks) so the UNIQUE index builds without collision on existing data. It
-- uses a correlated subquery (count of earlier ids in the same group) rather
-- than a window function, for maximum portability across D1 / better-sqlite3 /
-- libSQL. On a fresh DB the UPDATE is a no-op.
ALTER TABLE `free_grants` ADD `slot` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
UPDATE `free_grants`
SET `slot` = (
  SELECT COUNT(*) FROM `free_grants` AS `g2`
  WHERE `g2`.`ip_hash` = `free_grants`.`ip_hash`
    AND `g2`.`granted_day_bucket` = `free_grants`.`granted_day_bucket`
    AND `g2`.`id` < `free_grants`.`id`
);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_free_grants_ip_day_slot` ON `free_grants` (`ip_hash`,`granted_day_bucket`,`slot`);
