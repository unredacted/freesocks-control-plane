/**
 * Obligation rows: the external side effects of the bootstrap workflows
 * (docs/servers.md "Node lifecycle"). A row lands BEFORE the call; an
 * outstanding one blocks its identity whatever generation owns it
 * (`blocksIdentity`, lib/backend/obligations.ts); a lease expiry only resumes
 * discovery of the same attempt, and the owning workflow settles a late result
 * against what it wants now. Nothing here calls a provider.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { blocksIdentity } from './lib/backend/obligations';
import { fenceHolds } from './lib/backend/fencing';

export const ownerKind = v.union(
  v.literal('setup'),
  v.literal('intent'),
  v.literal('activation'),
  v.literal('retirement'),
);
export const obligationKind = v.union(
  v.literal('profile.create'),
  v.literal('dns.record'),
  v.literal('host'),
  v.literal('node'),
  v.literal('test_credential'),
  v.literal('edge_publication'),
  v.literal('mirror.withdraw'),
  v.literal('mirror.replace'),
  v.literal('machine_cleanup'),
);
const obligationState = v.union(
  v.literal('pending'),
  v.literal('sent'),
  v.literal('unresolved'),
  v.literal('confirmed'),
  v.literal('failed'),
);

/** The obligation on this identity that still blocks it, if any (any owner, any generation). */
export async function blockingObligationFor(
  db: { query: DbQuery },
  backendServerId: Id<'backendServers'>,
  kind: Doc<'backendObligations'>['kind'],
  identity: string,
): Promise<Doc<'backendObligations'> | null> {
  const rows = await db
    .query('backendObligations')
    .withIndex('by_server_kind_identity', (q) =>
      q.eq('backendServerId', backendServerId).eq('kind', kind).eq('identity', identity),
    )
    .collect();
  return rows.find((r) => blocksIdentity(r)) ?? null;
}
type DbQuery = import('./_generated/server').QueryCtx['db']['query'];

export const blockingFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), kind: obligationKind, identity: v.string() },
  handler: (ctx, a) => blockingObligationFor(ctx.db, a.backendServerId, a.kind, a.identity),
});

export const listForOwner = internalQuery({
  args: { ownerKind, ownerId: v.string() },
  handler: (ctx, { ownerKind: k, ownerId }) =>
    ctx.db
      .query('backendObligations')
      .withIndex('by_owner', (q) => q.eq('ownerKind', k).eq('ownerId', ownerId))
      .collect(),
});

/** Persist the obligation before the call. Refuses while one on the identity is outstanding. */
export const open = internalMutation({
  args: {
    backendServerId: v.id('backendServers'),
    ownerKind,
    ownerId: v.string(),
    ownerGeneration: v.number(),
    attemptId: v.string(),
    kind: obligationKind,
    identity: v.string(),
    verb: v.union(v.literal('create'), v.literal('update'), v.literal('delete')),
    ownership: v.union(v.literal('created'), v.literal('adopted'), v.literal('shared')),
    intent: v.string(),
    dns: v.optional(
      v.object({
        accountId: v.id('edgeProviderAccounts'),
        zoneId: v.string(),
        zoneName: v.string(),
        recordId: v.optional(v.string()),
        marker: v.string(),
      }),
    ),
  },
  handler: async (ctx, a) => {
    // A node's attempt writes only while it still holds the node, and never
    // once the node is being retired: an attempt that read it before the
    // retirement must not put back what the retirement withdraws.
    if (a.ownerKind === 'intent') {
      const id = ctx.db.normalizeId('panelNodeIntents', a.ownerId);
      const owner = id ? await ctx.db.get(id) : null;
      if (
        !owner ||
        owner.state === 'retiring' ||
        owner.state === 'retired' ||
        !fenceHolds(owner, { generation: a.ownerGeneration, attemptId: a.attemptId })
      )
        return { ok: false as const, fenced: true };
    }
    const blocking = await blockingObligationFor(ctx.db, a.backendServerId, a.kind, a.identity);
    if (blocking) return { ok: false as const, blockedBy: blocking._id };
    const now = Date.now();
    const id = await ctx.db.insert('backendObligations', {
      ...a,
      state: 'pending',
      createdAt: now,
      updatedAt: now,
    });
    return { ok: true as const, id };
  },
});

export const mark = internalMutation({
  args: {
    id: v.id('backendObligations'),
    state: obligationState,
    resourceRef: v.optional(v.string()),
    code: v.optional(v.string()),
    recordId: v.optional(v.string()),
  },
  handler: async (ctx, { id, state, resourceRef, code, recordId }) => {
    const row = await ctx.db.get(id);
    if (!row) return null;
    const now = Date.now();
    await ctx.db.patch(id, {
      state,
      ...(resourceRef !== undefined ? { resourceRef } : {}),
      ...(code !== undefined ? { code } : {}),
      ...(recordId !== undefined && row.dns ? { dns: { ...row.dns, recordId } } : {}),
      ...(state === 'sent' ? { sentAt: now } : {}),
      ...(state === 'confirmed' || state === 'failed' ? { settledAt: now } : {}),
      updatedAt: now,
    });
    return null;
  },
});
