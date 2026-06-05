-- Drop the unused `idempotency_keys` table. It was scaffolding for per-POST
-- subscription idempotency that was never wired up — no server code reads or
-- writes it, and the dead `SubscriptionRequest.idempotencyKey` field is removed
-- alongside this migration. Double-issue is already guarded by the atomic
-- free-tier cap (0009) and Turnstile, so the table serves no purpose.
DROP TABLE IF EXISTS `idempotency_keys`;
