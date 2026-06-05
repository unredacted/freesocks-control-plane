-- Outline Manager API endpoint registry. One row per Outline server the
-- system can issue keys against. The `api_url` includes the secret path
-- segment from the Outline Manager API (`https://HOST:PORT/<random-secret>/`)
-- and is therefore SENSITIVE — never log it, redact it in audit payloads.
--
-- `websocket_enabled` flips on the non-stock Shadowsocks-over-WSS path for
-- servers running the FreeSocks Outline fork; when enabled, key issuance
-- POSTs a `websocket: {…}` body to /access-keys and the resulting YAML
-- config is uploaded to S3 and served as a `ssconf://` URL.
--
-- `prometheus_url` is kept for forward compatibility with the original
-- codebase's per-key metrics flow but is unused in v1 (Outline's stock
-- `/metrics/transfer` endpoint covers v1's needs).
CREATE TABLE `outline_servers` (
  `id`                 integer PRIMARY KEY AUTOINCREMENT NOT NULL,
  `name`               text NOT NULL,
  `slug`               text NOT NULL,
  `api_url`            text NOT NULL,
  `websocket_enabled`  integer DEFAULT 0 NOT NULL,
  `websocket_domain`   text,
  `prometheus_url`     text,
  `is_active`          integer DEFAULT 1 NOT NULL,
  `priority`           integer DEFAULT 0 NOT NULL,
  `last_health_ok_at`  integer,
  `access_key_count`   integer DEFAULT 0 NOT NULL,
  `created_at`         integer DEFAULT (unixepoch() * 1000) NOT NULL,
  `updated_at`         integer DEFAULT (unixepoch() * 1000) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `outline_servers_slug_unique` ON `outline_servers` (`slug`);
--> statement-breakpoint
CREATE INDEX `idx_outline_servers_active` ON `outline_servers` (`is_active`, `priority`);
--> statement-breakpoint
-- Outline-backed subscriptions need to know which server they live on so
-- subsequent calls (read, delete, set-limit) route to the right Manager API.
-- NULL for Remnawave-backed rows (and a CHECK isn't worth the migration
-- complexity; the BackendRegistry enforces correct routing).
ALTER TABLE `subscriptions` ADD COLUMN `outline_server_id` integer REFERENCES `outline_servers`(`id`);
