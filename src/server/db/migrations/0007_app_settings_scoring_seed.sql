-- Backfill the two `outline.scoring.*` setting rows on installs that already
-- applied 0006 before this seed was added. The values match the compiled-in
-- defaults so behavior is unchanged on first apply; the rows just become
-- visible/editable in the admin Settings page.
--
-- `INSERT OR IGNORE` keeps the migration idempotent if an admin already
-- created the rows via PATCH /api/v1/admin/settings.
INSERT OR IGNORE INTO `app_settings` (`key`, `value`) VALUES
  ('outline.scoring.latency_weight',   '1'),
  ('outline.scoring.key_count_weight', '100');
