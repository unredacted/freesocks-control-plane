import { query } from './_generated/server';
import { v } from 'convex/values';

/**
 * Resolve an `fsv1_` bearer token by its SHA-256 hash (the caller hashes the
 * presented plaintext). Returns null for unknown, revoked, or expired tokens.
 * Scope enforcement happens at the call site (the HTTP action / function), not
 * here — this is the unique-index lookup only.
 */
export const byTokenHash = query({
  args: { tokenHash: v.string() },
  handler: async (ctx, { tokenHash }) => {
    const tok = await ctx.db
      .query('apiTokens')
      .withIndex('by_token_hash', (q) => q.eq('tokenHash', tokenHash))
      .unique();
    if (!tok || tok.revokedAt) return null;
    if (tok.expiresAt && tok.expiresAt < Date.now()) return null;
    return tok;
  },
});
