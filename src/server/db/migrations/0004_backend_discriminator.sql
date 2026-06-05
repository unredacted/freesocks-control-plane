-- Stage 2 of the Outline rollout. Adds per-tier and per-subscription backend
-- discriminator columns, renames Remnawave-specific subscription columns to
-- generic names, and replaces the singleton-civicrm-type unique constraint
-- with a composite (civicrm_membership_type_id, backend) constraint so two
-- tiers can share a CiviCRM type if they target different backends.
--
-- Existing rows: `backend` defaults to 'remnawave' so all current data is
-- categorized correctly without a manual backfill.

ALTER TABLE `tiers` ADD COLUMN `backend` text DEFAULT 'remnawave' NOT NULL;
--> statement-breakpoint
ALTER TABLE `subscriptions` ADD COLUMN `backend` text DEFAULT 'remnawave' NOT NULL;
--> statement-breakpoint
ALTER TABLE `subscriptions` RENAME COLUMN `remnawave_user_uuid` TO `backend_user_id`;
--> statement-breakpoint
ALTER TABLE `subscriptions` RENAME COLUMN `remnawave_short_uuid` TO `backend_short_id`;
--> statement-breakpoint
-- SQLite's RENAME COLUMN updates the index's column reference but keeps the
-- old name. Drop and recreate with names that match the columns for clarity.
DROP INDEX `subscriptions_remnawave_user_uuid_unique`;
--> statement-breakpoint
DROP INDEX `subscriptions_remnawave_short_uuid_unique`;
--> statement-breakpoint
-- Existing app code expects uniqueness on (backend_user_id) globally. That
-- remains correct: a single Outline access-key id and a single Remnawave
-- uuid are both globally unique within their backend, and the two namespaces
-- don't collide because Outline ids are short numeric strings while
-- Remnawave uses UUIDv4.
CREATE UNIQUE INDEX `subscriptions_backend_user_id_unique` ON `subscriptions` (`backend_user_id`);
--> statement-breakpoint
CREATE UNIQUE INDEX `subscriptions_backend_short_id_unique` ON `subscriptions` (`backend_short_id`);
--> statement-breakpoint
-- Replace the singleton-civicrm-type unique with a composite that allows two
-- tiers sharing a CiviCRM membership type if they target different backends.
DROP INDEX `idx_tiers_civicrm_type`;
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_tiers_civicrm_type_backend`
  ON `tiers` (`civicrm_membership_type_id`, `backend`)
  WHERE civicrm_membership_type_id IS NOT NULL;
