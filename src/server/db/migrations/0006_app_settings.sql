-- Typed admin-editable global settings. Each row is one named setting with
-- a JSON-serialized value validated server-side against a Zod schema in
-- `AppSettingsService`. This is the durable home for "admin flips a switch
-- in the CMS and the system behaves differently" — unlike env vars (which
-- require a redeploy) and tier columns (which are per-tier).
--
-- Seed values ship with `outline.enabled=false` so installing the migration
-- alone doesn't change behavior. Admin must explicitly turn Outline on via
-- the settings page after wiring up at least one outline_servers row.
CREATE TABLE `app_settings` (
  `key`                 text PRIMARY KEY NOT NULL,
  `value`               text NOT NULL,
  `updated_at`          integer DEFAULT (unixepoch() * 1000) NOT NULL,
  `updated_by_admin_id` integer REFERENCES `admin_users`(`id`)
);
--> statement-breakpoint
INSERT INTO `app_settings` (`key`, `value`) VALUES
  ('outline.enabled',                  'false'),
  ('remnawave.enabled',                'true'),
  ('subscription.default_backend',     '"remnawave"'),
  ('subscription.user_choice_enabled', 'false'),
  ('subscription.backend_labels',      '{"remnawave":"Xray","outline":"Outline"}'),
  ('outline.scoring.latency_weight',   '1'),
  ('outline.scoring.key_count_weight', '100');
