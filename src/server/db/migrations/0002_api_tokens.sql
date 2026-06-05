CREATE TABLE `api_tokens` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`token_hash` text NOT NULL,
	`token_prefix` text NOT NULL,
	`created_by_admin_id` integer NOT NULL,
	`scopes` text DEFAULT '[]' NOT NULL,
	`subject_type` text DEFAULT 'service' NOT NULL,
	`subject_user_id` integer,
	`expires_at` integer,
	`last_used_at` integer,
	`revoked_at` integer,
	`created_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	`updated_at` integer DEFAULT (unixepoch() * 1000) NOT NULL,
	FOREIGN KEY (`created_by_admin_id`) REFERENCES `admin_users`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`subject_user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `api_tokens_token_hash_unique` ON `api_tokens` (`token_hash`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_api_tokens_hash` ON `api_tokens` (`token_hash`);
--> statement-breakpoint
CREATE INDEX `idx_api_tokens_creator` ON `api_tokens` (`created_by_admin_id`);
--> statement-breakpoint
CREATE INDEX `idx_api_tokens_active` ON `api_tokens` (`revoked_at`,`expires_at`);
