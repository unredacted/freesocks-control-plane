-- Rename the user-facing label for the Remnawave-backed tier from
-- "Remnawave" to "Xray". The internal id stays `remnawave` (kept on the
-- BackendId enum, DB rows, and the `<X>.enabled` setting key) — only the
-- displayed label changes. Xray is what users actually connect to;
-- Remnawave is just the management panel we use behind the scenes.
--
-- Idempotency: only rewrite the row if it's still on the original default
-- value. If the admin has already customized the label via the Settings
-- page, leave their choice alone — we should never overwrite a deliberate
-- admin edit during a migration.
UPDATE `app_settings`
SET    `value` = '{"remnawave":"Xray","outline":"Outline"}'
WHERE  `key`   = 'subscription.backend_labels'
  AND  `value` = '{"remnawave":"Remnawave","outline":"Outline"}';
