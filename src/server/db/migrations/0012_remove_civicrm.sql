-- Remove CiviCRM integration. Membership entitlements now arrive through the
-- `setMembership` seam (and, later, the in-house billing portal) instead of the
-- CiviCRM reconcile/poll. Drops the membership-type/contact columns, their
-- indexes, and the membership_snapshots audit table.
DROP INDEX `idx_tiers_civicrm_type_backend`;--> statement-breakpoint
ALTER TABLE `tiers` DROP COLUMN `civicrm_membership_type_id`;--> statement-breakpoint
ALTER TABLE `tiers` DROP COLUMN `civicrm_membership_status_ids`;--> statement-breakpoint
DROP INDEX `users_civicrm_contact_id_unique`;--> statement-breakpoint
DROP INDEX `idx_users_civicrm_contact`;--> statement-breakpoint
ALTER TABLE `users` DROP COLUMN `civicrm_contact_id`;--> statement-breakpoint
ALTER TABLE `users` DROP COLUMN `last_membership_check_at`;--> statement-breakpoint
ALTER TABLE `tier_history` DROP COLUMN `membership_snapshot_id`;--> statement-breakpoint
DROP TABLE `membership_snapshots`;
