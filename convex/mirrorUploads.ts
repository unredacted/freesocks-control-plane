/**
 * The mirror barrier (docs/servers.md "Node lifecycle"): a mirror object is
 * written by an upload that takes real time, and the delivery policy it was
 * rendered under (a node gate, maintenance, a binding, a candidate set) can
 * move while it is in flight. A token check BEFORE the upload cannot see
 * that, so every upload holds an obligation:
 *
 *  - opened before the object is written, with the delivery token the body
 *    was rendered under (`edgeRender.epochFor`);
 *  - settled (dropped) only when the token read AFTER a successful upload
 *    is still that token;
 *  - otherwise left open: the repair pass (storage.ts `repairMirrorUploads`,
 *    a cron) re-renders and re-uploads the subscription's mirrors under the
 *    CURRENT policy (a gated or edge-required place with nothing renderable
 *    gets the unavailable stub), or withdraws an object no subscription
 *    references any more. That later upload settles it, under the same rule.
 *
 * Rows hold no content and no address: a subscription id, the object path,
 * provider names and the token.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';

/** An obligation younger than this may still be an upload in flight: the repair leaves it alone. */
export const REPAIR_GRACE_MS = 2 * 60_000;
const REPAIR_BATCH = 25;

/**
 * Open an obligation before an upload. It supersedes (drops) every earlier
 * open one of the same object whose providers this upload writes too: the
 * newer write decides what the object holds, so one record per object stays
 * open at most, however often the policy flaps. Returns whether it superseded
 * any, so an upload that then writes nothing keeps its record open.
 */
export const open = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    objectPath: v.string(),
    providers: v.array(v.string()),
    tokenBefore: v.union(v.string(), v.null()),
    kind: v.union(v.literal('initial'), v.literal('refresh'), v.literal('repair')),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    let superseded = 0;
    for (const r of await ctx.db
      .query('mirrorUploads')
      .withIndex('by_subscription', (q) =>
        q.eq('subscriptionId', a.subscriptionId).eq('state', 'open'),
      )
      .collect()) {
      // one subscription's open uploads: a handful at most
      if (r.objectPath !== a.objectPath || !r.providers.every((p) => a.providers.includes(p)))
        continue;
      await ctx.db.delete(r._id);
      superseded++;
    }
    const id = await ctx.db.insert('mirrorUploads', {
      ...a,
      state: 'open' as const,
      attempts: 0,
      startedAt: now,
      updatedAt: now,
    });
    return { id, superseded };
  },
});

/**
 * A re-issue carried the mirrors onto a new subscription row (the object now
 * serves the new key): its open obligations follow, so the repair judges the
 * object by the row that holds it.
 */
export async function moveOpenUploads(
  ctx: MutationCtx,
  from: Id<'subscriptions'>,
  to: Id<'subscriptions'>,
): Promise<void> {
  const now = Date.now();
  for (const r of await ctx.db
    .query('mirrorUploads')
    .withIndex('by_subscription', (q) => q.eq('subscriptionId', from).eq('state', 'open'))
    .collect())
    await ctx.db.patch(r._id, { subscriptionId: to, updatedAt: now });
}

/**
 * Settle (drop) obligations an upload under a stable token satisfied: the
 * upload's own, plus (`subscriptionId`) every earlier open one of the same
 * subscription and object, which that upload overwrote.
 */
export const settle = internalMutation({
  args: {
    id: v.id('mirrorUploads'),
    subscriptionId: v.optional(v.id('subscriptions')),
  },
  handler: async (ctx, { id, subscriptionId }) => {
    const own = await ctx.db.get(id);
    if (!own) return { settled: 0 };
    let settled = 0;
    const rows = subscriptionId
      ? await ctx.db
          .query('mirrorUploads')
          .withIndex('by_subscription', (q) =>
            q.eq('subscriptionId', subscriptionId).eq('state', 'open'),
          )
          .collect() // one subscription's open uploads: a handful at most
      : [own];
    for (const r of rows) {
      // An earlier record is met only for the copies this upload rewrote.
      if (
        r._id !== own._id &&
        (r.objectPath !== own.objectPath || !r.providers.every((p) => own.providers.includes(p)))
      )
        continue;
      await ctx.db.delete(r._id);
      settled++;
    }
    return { settled };
  },
});

/** Keep an obligation open for only these copies (the others were rewritten or withdrawn). */
export const narrow = internalMutation({
  args: { id: v.id('mirrorUploads'), providers: v.array(v.string()) },
  handler: async (ctx, { id, providers }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    if (providers.length === 0) await ctx.db.delete(id);
    else await ctx.db.patch(id, { providers, updatedAt: Date.now() });
    return null;
  },
});

/** The repair pass counts its attempts (and moves the row past the in-flight grace again). */
export const markAttempt = internalMutation({
  args: { id: v.id('mirrorUploads') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    await ctx.db.patch(id, { attempts: r.attempts + 1, updatedAt: Date.now() });
    return null;
  },
});

/** Open obligations past the in-flight grace, oldest first (bounded). */
export const listDue = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const rows = await ctx.db
      .query('mirrorUploads')
      .withIndex('by_state', (q) => q.eq('state', 'open').lt('updatedAt', now - REPAIR_GRACE_MS))
      .take(REPAIR_BATCH);
    const out = [];
    for (const r of rows) {
      const sub = await ctx.db.get(r.subscriptionId);
      const live = (provider: string) =>
        !!sub &&
        sub.state === 'active' &&
        sub.subscriptionMirrors.some(
          (m) => m.provider === provider && m.objectPath === r.objectPath,
        );
      out.push({
        id: r._id,
        subscriptionId: r.subscriptionId,
        objectPath: r.objectPath,
        providers: r.providers,
        attempts: r.attempts,
        // A copy the subscription still serves is repaired in place; a copy
        // nothing references any more is residue and is withdrawn.
        referenced: r.providers.some(live),
        residueProviders: r.providers.filter((p) => !live(p)),
      });
    }
    return out;
  },
});

/** Open obligations of one subscription (tests and the admin view). */
export const openFor = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: (ctx, { subscriptionId }) =>
    ctx.db
      .query('mirrorUploads')
      .withIndex('by_subscription', (q) =>
        q.eq('subscriptionId', subscriptionId).eq('state', 'open'),
      )
      .collect(),
});
