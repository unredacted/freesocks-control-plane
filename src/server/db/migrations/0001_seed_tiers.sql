INSERT INTO `tiers` (`slug`, `name`, `description`, `monthly_traffic_gb`, `device_limit`, `hwid_limit`, `hwid_enabled`, `traffic_strategy`, `civicrm_membership_status_ids`, `is_default_free`, `is_active`, `priority`, `expiration_days_after_membership_lapse`)
VALUES
  ('free', 'Free', 'Anonymous, Turnstile-gated access for users in censored regions', 50, 1, 1, 1, 'MONTH', '[]', 1, 1, 0, 0),
  ('member', 'Member', 'Standard FreeSocks supporters - 3 devices, 500GB/month', 500, 3, 3, 1, 'MONTH', '[1,2]', 0, 1, 10, 7),
  ('patron', 'Patron', 'Premium tier - 5 devices, unlimited traffic', 0, 5, 5, 1, 'NO_RESET', '[1,2]', 0, 1, 20, 7);
