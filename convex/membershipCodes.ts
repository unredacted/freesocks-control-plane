/**
 * Membership redemption codes (W4). Admin-minted bearer codes a signed-in member
 * redeems to grant/extend a paid tier — the privacy-preserving upgrade path that
 * needs no billing portal (the future portal just calls the same mint mutation).
 *
 * Security:
 *  - Codes are SECRETS: only the SHA-256 hash + a short display prefix are stored
 *    (minting needs CSPRNG, so it lives in an action; see lib/membershipCode.ts).
 *  - Redemption is SINGLE-USE by construction: `consumeAndGrant` is a serializable
 *    mutation that flips status active→redeemed and grants membership atomically,
 *    so a double-redeem race burns the code exactly once and grants exactly once.
 *  - No oracle: every redeem failure (unknown / revoked / already-redeemed /
 *    rate-limited / malformed) returns the SAME generic result, so a guesser
 *    learns nothing about which codes exist.
 */
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { v } from 'convex/values';
import { randomHex, sha256Hex } from './lib/crypto';
import { writeAuditLog } from './lib/audit';
import { applyMembership } from './lifecycle';
import {
  generateMembershipCode,
  isValidMembershipCode,
  membershipCodePrefix,
  normalizeMembershipCode,
} from './lib/membershipCode';

const DAY_MS = 86_400_000;
const MAX_BATCH = 100;

// --- admin: mint / list / revoke -------------------------------------------

/**
 * Mint `count` codes for a tier (CSPRNG → action). Returns the plaintext codes
 * ONCE (the caller reveals them; they're never recoverable after). Audited.
 */
export const mintCodes = internalAction({
  args: {
    tierId: v.id('tiers'),
    durationDays: v.number(),
    count: v.number(),
    note: v.optional(v.string()),
    actorAdminId: v.id('adminUsers'),
  },
  handler: async (ctx, a): Promise<{ codes: string[]; batchId: string }> => {
    const count = Math.floor(a.count);
    if (!Number.isFinite(count) || count < 1 || count > MAX_BATCH) {
      throw new Error(`count must be between 1 and ${MAX_BATCH}`);
    }
    if (!Number.isInteger(a.durationDays) || a.durationDays < 1 || a.durationDays > 3650) {
      throw new Error('durationDays must be an integer in [1, 3650]');
    }
    const batchId = randomHex(8);
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      // Retry on the astronomically rare hash collision.
      for (let attempt = 0; attempt < 3; attempt++) {
        const plaintext = generateMembershipCode();
        const codeHash = await sha256Hex(plaintext);
        try {
          await ctx.runMutation(internal.membershipCodes.insertCode, {
            codeHash,
            codePrefix: membershipCodePrefix(plaintext),
            tierId: a.tierId,
            durationDays: a.durationDays,
            note: a.note,
            batchId,
            mintedByAdminId: a.actorAdminId,
          });
          codes.push(plaintext);
          break;
        } catch (err) {
          if (attempt === 2) throw err;
        }
      }
    }
    await ctx.runMutation(internal.membershipCodes.recordMintAudit, {
      actorAdminId: a.actorAdminId,
      count: codes.length,
      tierId: a.tierId,
      durationDays: a.durationDays,
      batchId,
    });
    return { codes, batchId };
  },
});

export const insertCode = internalMutation({
  args: {
    codeHash: v.string(),
    codePrefix: v.string(),
    tierId: v.id('tiers'),
    durationDays: v.number(),
    note: v.optional(v.string()),
    batchId: v.optional(v.string()),
    mintedByAdminId: v.id('adminUsers'),
  },
  handler: async (ctx, a) => {
    const clash = await ctx.db
      .query('redemptionCodes')
      .withIndex('by_code_hash', (q) => q.eq('codeHash', a.codeHash))
      .unique();
    if (clash) throw new Error('code hash collision');
    return ctx.db.insert('redemptionCodes', { ...a, status: 'active', updatedAt: Date.now() });
  },
});

export const recordMintAudit = internalMutation({
  args: {
    actorAdminId: v.id('adminUsers'),
    count: v.number(),
    tierId: v.id('tiers'),
    durationDays: v.number(),
    batchId: v.string(),
  },
  handler: async (ctx, a) => {
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId,
      action: 'membership_code.mint',
      targetType: 'membership_code_batch',
      targetId: a.batchId,
      payload: { count: a.count, tierId: a.tierId, durationDays: a.durationDays },
    });
    return null;
  },
});

function maskCode(c: Doc<'redemptionCodes'>, tierSlugById: Map<string, string>) {
  return {
    id: c._id as string,
    codePrefix: c.codePrefix,
    tierSlug: tierSlugById.get(c.tierId) ?? null,
    durationDays: c.durationDays,
    status: c.status,
    note: c.note ?? null,
    batchId: c.batchId ?? null,
    redeemedByUserId: (c.redeemedByUserId as string | undefined) ?? null,
    redeemedAt: c.redeemedAt != null ? new Date(c.redeemedAt).toISOString() : null,
    createdAt: new Date(c._creationTime).toISOString(),
  };
}

/**
 * Admin list: codes newest-first, masked (never the hash/plaintext), with an
 * opaque keyset cursor over `_creationTime` (mirrors adminApi.auditList /
 * usersSearch). The `by_status` index appends `_creationTime`, so newest-first
 * ordering + the cursor upper-bound compose on either the filtered or the
 * unfiltered scan.
 */
export const listCodes = internalQuery({
  args: {
    status: v.optional(v.string()),
    cursor: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, { status, cursor, limit }) => {
    const tiers = await ctx.db.query('tiers').collect();
    const tierSlugById = new Map<string, string>(tiers.map((t) => [t._id as string, t.slug]));
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);
    const before = cursor && Number.isFinite(Number(cursor)) ? Number(cursor) : null;

    const ordered =
      status === 'active' || status === 'redeemed' || status === 'revoked'
        ? ctx.db
            .query('redemptionCodes')
            .withIndex('by_status', (q) => q.eq('status', status))
            .order('desc')
        : ctx.db.query('redemptionCodes').order('desc');

    const rows = await ordered
      .filter((f) =>
        before != null ? f.lt(f.field('_creationTime'), before) : f.gt(f.field('_creationTime'), 0),
      )
      .take(pageSize + 1);

    const hasMore = rows.length > pageSize;
    const page = rows.slice(0, pageSize);
    const last = page[page.length - 1];
    const nextCursor = hasMore && last ? String(last._creationTime) : null;
    return { codes: page.map((c) => maskCode(c, tierSlugById)), nextCursor };
  },
});

/**
 * Member list: the codes this user PURCHASED (gift codes), newest first. A
 * leak-safe projection — prefix + tier + status + redeemed timestamp, never the
 * hash/plaintext nor the recipient's userId (which `maskCode` would expose).
 */
export const listPurchasedCodes = internalQuery({
  args: { userId: v.id('users') },
  handler: async (ctx, { userId }) => {
    const tiers = await ctx.db.query('tiers').collect();
    const tierSlugById = new Map<string, string>(tiers.map((t) => [t._id as string, t.slug]));
    const rows = await ctx.db
      .query('redemptionCodes')
      .withIndex('by_purchaser', (q) => q.eq('purchasedByUserId', userId))
      .order('desc')
      .take(200);
    return rows.map((c) => ({
      codePrefix: c.codePrefix,
      tierSlug: tierSlugById.get(c.tierId) ?? null,
      durationDays: c.durationDays,
      status: c.status,
      redeemedAt: c.redeemedAt != null ? new Date(c.redeemedAt).toISOString() : null,
      createdAt: new Date(c._creationTime).toISOString(),
    }));
  },
});

/** Admin revoke: an active code can no longer be redeemed. Audited. */
export const revokeCode = internalMutation({
  args: { id: v.id('redemptionCodes'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const code = await ctx.db.get(id);
    if (!code) throw new Error('code not found');
    if (code.status === 'active') {
      await ctx.db.patch(id, { status: 'revoked', updatedAt: Date.now() });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId,
      action: 'membership_code.revoke',
      targetType: 'membership_code',
      targetId: id,
      payload: { codeId: id },
    });
    return { ok: true as const, status: code.status === 'active' ? 'revoked' : code.status };
  },
});

// --- member: redeem ---------------------------------------------------------

type RedeemResult =
  | {
      ok: true;
      tierSlug: string;
      tierName: string;
      durationDays: number;
      membershipExpiresAt: string;
    }
  | { ok: false };

/**
 * Redeem a code as a signed-in member. Hard rate-limited (W2 `code.redeem`) and
 * generic on every failure. On success, consumes the code and extends membership
 * to max(now, currentExpiry) + durationDays, atomically.
 */
export const redeemCode = internalAction({
  args: { userId: v.id('users'), code: v.string() },
  handler: async (ctx, { userId, code }): Promise<RedeemResult> => {
    const rl = await ctx.runMutation(internal.rateLimits.enforce, {
      policyKey: 'code.redeem',
      subject: userId,
    });
    if (!rl.allowed) return { ok: false };

    const normalized = normalizeMembershipCode(code);
    if (!isValidMembershipCode(normalized)) return { ok: false };
    const codeHash = await sha256Hex(normalized);

    const granted = await ctx.runMutation(internal.membershipCodes.consumeAndGrant, {
      userId,
      codeHash,
    });
    if (!granted.ok) return { ok: false };
    return {
      ok: true,
      tierSlug: granted.tierSlug,
      tierName: granted.tierName,
      durationDays: granted.durationDays,
      membershipExpiresAt: new Date(granted.expiresAtMs).toISOString(),
    };
  },
});

type ConsumeResult =
  | { ok: true; tierSlug: string; tierName: string; durationDays: number; expiresAtMs: number }
  | { ok: false };

/**
 * Serializable single-use consume + grant. Two concurrent redeems of the same
 * code conflict on the row; the loser re-reads status !== 'active' and fails.
 */
export const consumeAndGrant = internalMutation({
  args: { userId: v.id('users'), codeHash: v.string() },
  handler: async (ctx, { userId, codeHash }): Promise<ConsumeResult> => {
    const code = await ctx.db
      .query('redemptionCodes')
      .withIndex('by_code_hash', (q) => q.eq('codeHash', codeHash))
      .unique();
    if (!code || code.status !== 'active') return { ok: false };
    const user = await ctx.db.get(userId);
    if (!user) return { ok: false };
    const tier = await ctx.db.get(code.tierId);
    if (!tier) return { ok: false };

    const now = Date.now();
    await ctx.db.patch(code._id, {
      status: 'redeemed',
      redeemedByUserId: userId,
      redeemedAt: now,
      updatedAt: now,
    });

    const base = Math.max(now, user.membershipExpiresAt ?? 0);
    const expiresAtMs = base + code.durationDays * DAY_MS;
    await applyMembership(ctx, {
      userId,
      tierId: code.tierId,
      expiresAtMs,
      reason: 'code_redeem',
      triggeredBy: 'member',
    });
    await writeAuditLog(ctx, {
      actorType: 'member',
      actorId: userId,
      action: 'membership_code.redeem',
      targetType: 'membership_code',
      targetId: code._id,
      payload: { tierId: code.tierId, durationDays: code.durationDays },
    });
    return {
      ok: true,
      tierSlug: tier.slug,
      tierName: tier.name,
      durationDays: code.durationDays,
      expiresAtMs,
    };
  },
});
