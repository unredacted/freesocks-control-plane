/**
 * Test reads and writes through the LIVE helpers. They replace internal
 * functions that only tests called (a deployed function should have a
 * production caller): the same lookups, run in one `t.run` transaction.
 */
import type { TestConvex } from 'convex-test';
import type { Doc, Id } from '../../../_generated/dataModel';
import type schema from '../../../schema';
import { evaluateAutoQualificationFor } from '../../../edgeProviderAccounts';
import { defaultLocationOf } from '../../../edgeLocations';
import { insertPlannedEdge, mapEdgeAdmin, type PlannedEdgeInput } from '../../../edges';
import { nodeGateFor } from '../../../nodeIntents';
import { deliveryBindingFor, relayForBackendNode } from '../../../relays';
import { bumpEpochAndRefresh } from '../relayGuards';
import type { ProvisionIntent } from '../intent';

type T = TestConvex<typeof schema>;
type NodeRef = { backendServerId: Id<'backendServers'>; nodeName?: string };

/** The active delivery binding of one node (`deliveryBindingFor`). */
export const deliveryBindingOf = (t: T, a: NodeRef) =>
  t.run((ctx) => deliveryBindingFor(ctx.db, a.backendServerId, a.nodeName));

/** The delivery gate of one node, as every render reads it (`nodeGateFor`). */
export const gateOfNode = (t: T, a: NodeRef) =>
  t.run((ctx) => nodeGateFor(ctx, a.backendServerId, a.nodeName));

/** The origin that serves one node (`relayForBackendNode`). */
export const relayForNode = (t: T, a: NodeRef) =>
  t.run((ctx) => relayForBackendNode(ctx.db, a.backendServerId, a.nodeName));

export const relayBySlug = (t: T, a: { slug: string }) =>
  t.run((ctx) =>
    ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', a.slug))
      .unique(),
  );

export const listenerById = (t: T, a: { id: Id<'relayListeners'> }) =>
  t.run((ctx) => ctx.db.get(a.id));

export const edgesOfRelay = (t: T, a: { relayId: Id<'relays'> }) =>
  t.run((ctx) =>
    ctx.db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', a.relayId))
      .collect(),
  );

/** One edge as the admin API maps it (`mapEdgeAdmin`). */
export const edgeAdminView = (t: T, a: { id: Id<'edges'> }) =>
  t.run(async (ctx) => {
    const e = await ctx.db.get(a.id);
    return e ? mapEdgeAdmin(e) : null;
  });

/** The open mirror-upload obligations of one subscription. */
export const openMirrorUploads = (t: T, a: { subscriptionId: Id<'subscriptions'> }) =>
  t.run((ctx) =>
    ctx.db
      .query('mirrorUploads')
      .withIndex('by_subscription', (q) =>
        q.eq('subscriptionId', a.subscriptionId).eq('state', 'open'),
      )
      .collect(),
  );

/** A planned edge row, as a rotation inserts it (`insertPlannedEdge`). */
export const insertPlanned = (
  t: T,
  a: Omit<PlannedEdgeInput, 'provisionIntent'> & { provisionIntent?: unknown },
) =>
  t.run((ctx) =>
    insertPlannedEdge(ctx, {
      ...a,
      provisionIntent: (a.provisionIntent as ProvisionIntent | undefined) ?? null,
    }),
  );

/** The L7 auto-qualification judgement of one account (`evaluateAutoQualificationFor`). */
export const evaluateAutoQualification = (t: T, a: { accountId: Id<'edgeProviderAccounts'> }) =>
  t.run((ctx) => evaluateAutoQualificationFor(ctx, a.accountId));

/** Bump an origin's publication epoch and refresh its mirrors (`bumpEpochAndRefresh`). */
export const bumpEpoch = (t: T, a: { relayId: Id<'relays'> }) =>
  t.run(async (ctx) => {
    const origin = await ctx.db.get(a.relayId);
    if (origin) await bumpEpochAndRefresh(ctx, origin);
    return null;
  });

/** Expire a temporary test credential now (the sweep then removes it). */
export const expireTestCredential = (t: T, a: { id: Id<'edgeTestCredentials'> }) =>
  t.run(async (ctx) => {
    const row = await ctx.db.get(a.id);
    if (row && row.removal === 'pending')
      await ctx.db.patch(a.id, {
        expiresAt: Math.min(row.expiresAt, Date.now()),
        updatedAt: Date.now(),
      });
    return null;
  });

/**
 * The location an account's trust lives in for the account-level calls: its
 * default one (`defaultLocationOf`). Trust, its hash, its evidence and the
 * manual hold are read and patched there.
 */
export const defaultLocationRow = (t: T, accountId: Id<'edgeProviderAccounts'>) =>
  t.run(async (ctx) => {
    const account = await ctx.db.get(accountId);
    return account ? defaultLocationOf(ctx.db, account) : null;
  });

/** Patch an account's default location directly (a fixture shortcut for its trust fields). */
export const patchDefaultLocation = (
  t: T,
  accountId: Id<'edgeProviderAccounts'>,
  patch: Partial<Doc<'edgeLocations'>>,
) =>
  t.run(async (ctx) => {
    const account = await ctx.db.get(accountId);
    const loc = account ? await defaultLocationOf(ctx.db, account) : null;
    if (!loc) throw new Error('the account has no location');
    await ctx.db.patch(loc._id, patch);
    return loc._id;
  });
