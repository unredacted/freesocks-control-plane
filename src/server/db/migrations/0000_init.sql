CREATE TABLE `tiers` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`slug` text NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`monthly_traffic_gb` integer DEFAULT 0 NOT NULL,
	`device_limit` integer DEFAULT 1 NOT NULL,
	`hwid_limit` integer DEFAULT 1 NOT NULL,
	`hwid_enabled` integer DEFAULT 1 NOT NULL,
	`traffic_strategy` text DEFAULT 'MONTH' NOT NULL,
	`remnawave_squad_uuid` text,
	`civicrm_membership_type_id` integer,
	`civicrm_membership_status_ids` text DEFAULT '[]' NOT NULL,
	`is_default_free` integer DEFAULT 0 NOT NULL,
	`is_active` integer DEFAULT 1 NOT NULL,
	`priority` integer DEFAULT 0 NOT NULL,
	`expiration_days_after_membership_lapse` integer DEFAULT 7 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tiers_slug_unique` ON `tiers` (`slug`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_tiers_civicrm_type` ON `tiers` (`civicrm_membership_type_id`) WHERE civicrm_membership_type_id IS NOT NULL;
--> statement-breakpoint
CREATE INDEX `idx_tiers_active` ON `tiers` (`is_active`);
--> statement-breakpoint
CREATE TABLE `users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`authentik_subject` text,
	`civicrm_contact_id` integer,
	`email` text,
	`email_verified_at` integer,
	`tier_id` integer NOT NULL,
	`current_subscription_id` integer,
	`status` text DEFAULT 'active' NOT NULL,
	`disabled_reason` text,
	`membership_expires_at` integer,
	`last_membership_check_at` integer,
	`suspended_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`tier_id`) REFERENCES `tiers`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_authentik_subject_unique` ON `users` (`authentik_subject`);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_civicrm_contact_id_unique` ON `users` (`civicrm_contact_id`);
--> statement-breakpoint
CREATE INDEX `idx_users_civicrm_contact` ON `users` (`civicrm_contact_id`);
--> statement-breakpoint
CREATE INDEX `idx_users_status` ON `users` (`status`);
--> statement-breakpoint
CREATE INDEX `idx_users_tier` ON `users` (`tier_id`);
--> statement-breakpoint
CREATE INDEX `idx_users_membership_expires` ON `users` (`membership_expires_at`) WHERE status IN ('active', 'grace');
--> statement-breakpoint
CREATE TABLE `subscriptions` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`remnawave_user_uuid` text NOT NULL,
	`remnawave_short_uuid` text NOT NULL,
	`subscription_url` text NOT NULL,
	`subscription_mirrors` text DEFAULT '[]' NOT NULL,
	`raw_content_hash` text,
	`state` text DEFAULT 'active' NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`deleted_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `subscriptions_remnawave_user_uuid_unique` ON `subscriptions` (`remnawave_user_uuid`);
--> statement-breakpoint
CREATE UNIQUE INDEX `subscriptions_remnawave_short_uuid_unique` ON `subscriptions` (`remnawave_short_uuid`);
--> statement-breakpoint
CREATE INDEX `idx_subscriptions_user` ON `subscriptions` (`user_id`);
--> statement-breakpoint
CREATE INDEX `idx_subscriptions_state` ON `subscriptions` (`state`);
--> statement-breakpoint
CREATE TABLE `tier_history` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`from_tier_id` integer,
	`to_tier_id` integer NOT NULL,
	`reason` text NOT NULL,
	`triggered_by` text NOT NULL,
	`membership_snapshot_id` integer,
	`changed_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`from_tier_id`) REFERENCES `tiers`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`to_tier_id`) REFERENCES `tiers`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_tier_history_user` ON `tier_history` (`user_id`,`changed_at`);
--> statement-breakpoint
CREATE TABLE `membership_snapshots` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`civicrm_contact_id` integer NOT NULL,
	`civicrm_membership_id` integer NOT NULL,
	`membership_type_id` integer NOT NULL,
	`status_id` integer NOT NULL,
	`start_date` text,
	`end_date` text,
	`modified_date` text NOT NULL,
	`raw_payload` text NOT NULL,
	`fetched_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`applied` integer DEFAULT 0 NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_snapshots_user_fetched` ON `membership_snapshots` (`user_id`,`fetched_at`);
--> statement-breakpoint
CREATE INDEX `idx_snapshots_unapplied` ON `membership_snapshots` (`applied`,`fetched_at`) WHERE applied = 0;
--> statement-breakpoint
CREATE TABLE `free_grants` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` integer NOT NULL,
	`ip_hash` text NOT NULL,
	`ip_country` text,
	`asn` integer,
	`tls_fingerprint` text,
	`turnstile_action` text,
	`turnstile_cdata` text,
	`user_agent_hash` text,
	`granted_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`granted_day_bucket` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_free_grants_ip_day` ON `free_grants` (`ip_hash`,`granted_day_bucket`);
--> statement-breakpoint
CREATE INDEX `idx_free_grants_granted_at` ON `free_grants` (`granted_at`);
--> statement-breakpoint
CREATE TABLE `audit_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`actor_type` text NOT NULL,
	`actor_id` text,
	`action` text NOT NULL,
	`target_type` text,
	`target_id` text,
	`payload` text,
	`request_id` text,
	`ip_hash` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_audit_target` ON `audit_log` (`target_type`,`target_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX `idx_audit_actor` ON `audit_log` (`actor_type`,`actor_id`,`created_at`);
--> statement-breakpoint
CREATE INDEX `idx_audit_action` ON `audit_log` (`action`,`created_at`);
--> statement-breakpoint
CREATE TABLE `admin_users` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`username` text NOT NULL,
	`display_name` text NOT NULL,
	`email` text,
	`is_active` integer DEFAULT 1 NOT NULL,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`last_login_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `admin_users_username_unique` ON `admin_users` (`username`);
--> statement-breakpoint
CREATE TABLE `passkey_credentials` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`admin_user_id` integer NOT NULL,
	`credential_id` text NOT NULL,
	`public_key` text NOT NULL,
	`counter` integer DEFAULT 0 NOT NULL,
	`transports` text,
	`device_label` text,
	`aaguid` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`last_used_at` integer,
	FOREIGN KEY (`admin_user_id`) REFERENCES `admin_users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `passkey_credentials_credential_id_unique` ON `passkey_credentials` (`credential_id`);
--> statement-breakpoint
CREATE INDEX `idx_passkey_admin` ON `passkey_credentials` (`admin_user_id`);
--> statement-breakpoint
CREATE TABLE `webauthn_registration_challenges` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`admin_user_id` integer NOT NULL,
	`challenge` text NOT NULL,
	`expires_at` integer NOT NULL,
	`consumed_at` integer,
	FOREIGN KEY (`admin_user_id`) REFERENCES `admin_users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_webauthn_reg_admin` ON `webauthn_registration_challenges` (`admin_user_id`,`expires_at`);
--> statement-breakpoint
CREATE TABLE `email_log` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`to_email` text NOT NULL,
	`subject` text NOT NULL,
	`template_key` text NOT NULL,
	`params` text NOT NULL,
	`status` text NOT NULL,
	`provider_message_id` text,
	`error` text,
	`dedupe_key` text,
	`attempted_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`sent_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_email_dedupe` ON `email_log` (`dedupe_key`) WHERE dedupe_key IS NOT NULL;
--> statement-breakpoint
CREATE INDEX `idx_email_to` ON `email_log` (`to_email`,`attempted_at`);
--> statement-breakpoint
CREATE TABLE `app_state` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE TABLE `idempotency_keys` (
	`key` text PRIMARY KEY NOT NULL,
	`user_id` integer,
	`response_status` integer,
	`response_body` text,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`expires_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_idempotency_expires` ON `idempotency_keys` (`expires_at`);
--> statement-breakpoint
CREATE TABLE `webhook_events` (
	`id` text PRIMARY KEY NOT NULL,
	`source` text NOT NULL,
	`received_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`processed_at` integer,
	`payload` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_webhook_events_source` ON `webhook_events` (`source`,`received_at`);
--> statement-breakpoint
CREATE TABLE `kv_table` (
	`namespace` text NOT NULL,
	`key` text NOT NULL,
	`value` blob,
	`metadata` text,
	`expires_at` integer,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_kv_table_pk` ON `kv_table` (`namespace`,`key`);
--> statement-breakpoint
CREATE INDEX `idx_kv_table_expires` ON `kv_table` (`expires_at`);
