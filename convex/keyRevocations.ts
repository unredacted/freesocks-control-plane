/**
 * Revoked-kid list store (CDN-blinding Phase 3c). The current revocation is the
 * row with the highest `version`. New versions are published by the break-glass
 * action e2eeCrypto.signRevocation (it manifest-signs the list); the client
 * fetches it via /api/v1/e2ee/keys, verifies the signature, and refuses to seal
 * to any listed kid. `version` is monotonic so a CDN cannot roll back to a list
 * that omits a compromised kid.
 */
import { internalMutation, internalQuery } from './_generated/server';
import { v } from 'convex/values';

export const current = internalQuery({
  args: {},
  handler: async (ctx) => {
    const row = await ctx.db.query('keyRevocations').withIndex('by_version').order('desc').first();
    if (!row) return null;
    return {
      version: row.version,
      revokedKids: row.revokedKids,
      notAfter: row.notAfter,
      manifestSig: row.manifestSig,
      manifestSigPq: row.manifestSigPq,
    };
  },
});

export const insert = internalMutation({
  args: {
    version: v.number(),
    revokedKids: v.array(v.string()),
    notAfter: v.number(),
    manifestSig: v.string(),
    manifestSigPq: v.optional(v.string()),
  },
  handler: async (ctx, row) => {
    await ctx.db.insert('keyRevocations', row);
    return null;
  },
});
