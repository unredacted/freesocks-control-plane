-- Self-service account-number auth (docs/account-number-design.md). Every issued
-- user can get a unique, opaque 16-digit number to sign back in without
-- email/OIDC. We persist only a SHA-256 hash + a 4-digit plaintext prefix (for
-- admin search); the plaintext is revealed exactly once at issuance and never
-- stored. Nullable on existing rows — anonymous free users are not backfilled
-- (they never saw a number); OIDC members get backfilled by
-- scripts/backfill-account-ids.ts during the member-link rollout. The whole
-- feature ships behind the `account_id_enabled` app setting (default off).
ALTER TABLE `users` ADD `account_id_hash` text;--> statement-breakpoint
ALTER TABLE `users` ADD `account_id_prefix` text;--> statement-breakpoint
ALTER TABLE `users` ADD `account_id_created_at` integer;--> statement-breakpoint
ALTER TABLE `users` ADD `account_id_rotated_at` integer;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_users_account_id_hash` ON `users` (`account_id_hash`) WHERE account_id_hash IS NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_users_account_id_prefix` ON `users` (`account_id_prefix`) WHERE account_id_prefix IS NOT NULL;
