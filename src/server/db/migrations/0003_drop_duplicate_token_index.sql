-- Drop the redundant unique index on api_tokens.token_hash. The column already
-- has a `.unique()` constraint, which Drizzle materializes as the index
-- `api_tokens_token_hash_unique`. The explicit `idx_api_tokens_hash` from
-- migration 0002 was an unnecessary second copy of the same constraint —
-- doubling write cost on every insert with no read benefit (the planner uses
-- whichever lookup-by-hash index is cheapest, and they're identical).
DROP INDEX IF EXISTS `idx_api_tokens_hash`;
