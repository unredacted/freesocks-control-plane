/**
 * Obligation rows: the external side effects of the bootstrap workflows
 * (docs/servers.md "Node lifecycle"). A row lands BEFORE the call; an
 * outstanding one blocks its identity whatever generation owns it; a lease
 * expiry only resumes discovery of the same attempt; settlement reconciles
 * the result against what is wanted now (lib/panel/obligations.ts). Nothing
 * here calls a provider.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { blocksIdentity } from './lib/panel/obligations';

export const ownerKind = v.union(
  v.literal('setup'),
  v.literal('intent'),
  v.literal('activation'),
  v.literal('retirement'),
  v.literal('migration'),
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
  kind: Doc<'panelObligations'>['kind'],
  identity: string,
): Promise<Doc<'panelObligations'> | null> {
  const rows = await db
    .query('panelObligations')
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
      .query('panelObligations')
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
    const blocking = await blockingObligationFor(ctx.db, a.backendServerId, a.kind, a.identity);
    if (blocking) return { ok: false as const, blockedBy: blocking._id };
    const now = Date.now();
    const id = await ctx.db.insert('panelObligations', {
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
    id: v.id('panelObligations'),
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

export const get = internalQuery({
  args: { id: v.id('panelObligations') },
  handler: (ctx, { id }) => ctx.db.get(id),
});
