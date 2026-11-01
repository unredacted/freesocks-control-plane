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
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Id } from './_generated/dataModel';

/** How many open records one check reads; past it the answer is "yes" (the safe side). */
const OPEN_SCAN_CAP = 2000;

/**
 * Does any open record (an upload or a withdrawal) name this provider? Its
 * repair needs the provider's credentials, found by name: while one does, the
 * provider can neither go nor change its name. Open records are few (uploads
 * in flight and copies that keep failing); past the cap the answer is yes.
 */
export async function openRecordsName(db: DatabaseReader, provider: string): Promise<boolean> {
  const rows = await db
    .query('mirrorUploads')
    .withIndex('by_state', (q) => q.eq('state', 'open'))
    .take(OPEN_SCAN_CAP);
  return rows.length >= OPEN_SCAN_CAP || rows.some((r) => r.providers.includes(provider));
}

/** An obligation younger than this may still be an upload in flight: the repair leaves it alone. */
export const REPAIR_GRACE_MS = 2 * 60_000;
const REPAIR_BATCH = 25;
/** The longest wait between two repair attempts of one obligation. */
const REPAIR_BACKOFF_CAP_MS = 6 * 3_600_000;

/**
 * When an obligation that has failed `attempts` times is due again: the first
 * two retries come at the grace, then the wait doubles up to the cap (a
 * provider that stays down is not re-fetched and re-uploaded every five
 * minutes forever).
 */
export function repairBackoffMs(attempts: number): number {
  if (attempts <= 2) return REPAIR_GRACE_MS;
  return Math.min(REPAIR_GRACE_MS * 2 ** (attempts - 2), REPAIR_BACKOFF_CAP_MS);
}

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
    // A record this upload replaces hands on its failed attempts and its
    // backoff: the repair's own upload supersedes the record it repairs, and
    // a provider that stays down must not start from zero every time.
    let attempts = 0;
    let dueAt: number | undefined;
    for (const r of await ctx.db
      .query('mirrorUploads')
      .withIndex('by_subscription', (q) =>
        q.eq('subscriptionId', a.subscriptionId).eq('state', 'open'),
      )
      .collect()) {
      // one subscription's open uploads: a handful at most
      if (
        r.kind === 'withdraw' ||
        r.objectPath !== a.objectPath ||
        !r.providers.every((p) => a.providers.includes(p))
      )
        continue;
      attempts = Math.max(attempts, r.attempts);
      if (r.dueAt !== undefined) dueAt = Math.max(dueAt ?? 0, r.dueAt);
      await ctx.db.delete(r._id);
      superseded++;
    }
    const id = await ctx.db.insert('mirrorUploads', {
      ...a,
      state: 'open' as const,
      attempts,
      startedAt: now,
      updatedAt: now,
      ...(dueAt !== undefined ? { dueAt } : {}),
    });
    return { id, superseded };
  },
});

/**
 * A delete of copies nothing should serve any more did not go through (a
 * member cleared their mirrors, a key was torn down, a provider is being
 * removed): the object still holds a key's config in a third-party bucket, so
 * it is recorded as residue and the repair pass deletes it until it is gone.
 */
export const openWithdrawal = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    objectPath: v.string(),
    providers: v.array(v.string()),
  },
  handler: async (ctx, a) => {
    if (a.providers.length === 0) return null;
    const now = Date.now();
    return ctx.db.insert('mirrorUploads', {
      ...a,
      tokenBefore: null,
      kind: 'withdraw' as const,
      state: 'open' as const,
      attempts: 0,
      startedAt: now,
      updatedAt: now,
      dueAt: now,
    });
  },
});

/** The repair found the copies held by another row of the same key: the record follows them. */
export const rehome = internalMutation({
  args: { id: v.id('mirrorUploads'), subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { id, subscriptionId }) => {
    const r = await ctx.db.get(id);
    if (!r || r.subscriptionId === subscriptionId) return null;
    await ctx.db.patch(id, { subscriptionId, updatedAt: Date.now() });
    return null;
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
      // An earlier record is met only for the copies this upload rewrote (a
      // withdrawal is met only by its delete).
      if (
        r._id !== own._id &&
        (r.kind === 'withdraw' ||
          r.objectPath !== own.objectPath ||
          !r.providers.every((p) => own.providers.includes(p)))
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

/**
 * The repair pass counts its attempts and sets when the record is due again
 * (`repairBackoffMs`): a success settles the record, so this wait only matters
 * for one that keeps failing.
 */
export const markAttempt = internalMutation({
  args: { id: v.id('mirrorUploads') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    const now = Date.now();
    const attempts = r.attempts + 1;
    await ctx.db.patch(id, { attempts, updatedAt: now, dueAt: now + repairBackoffMs(attempts) });
    return null;
  },
});

/**
 * Open obligations that are due, oldest first (bounded): past the in-flight
 * grace since their last write, and past their backoff when they have one.
 *
 * Which row holds a copy is asked of every active row of the key's account,
 * not only the record's own: a re-issue carries the mirrors (and the object
 * path) to a new row, and a record left on the old row must repair the object
 * the new row serves, never withdraw it.
 */
export const listDue = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const candidates = await ctx.db
      .query('mirrorUploads')
      .withIndex('by_state_due', (q) => q.eq('state', 'open').lte('dueAt', now))
      .take(REPAIR_BATCH * 4);
    // Whatever its backoff says, a record touched within the grace may be an
    // upload in flight.
    const rows = candidates
      .filter((r) => r.updatedAt < now - REPAIR_GRACE_MS)
      .slice(0, REPAIR_BATCH);
    const out = [];
    for (const r of rows) {
      const sub = await ctx.db.get(r.subscriptionId);
      // The key's live rows: normally one, transiently two during a re-issue.
      const holders = sub
        ? await ctx.db
            .query('subscriptions')
            .withIndex('by_user_state', (q) => q.eq('userId', sub.userId).eq('state', 'active'))
            .collect()
        : [];
      const holderOf = (provider: string) =>
        holders.find((s) =>
          s.subscriptionMirrors.some(
            (m) => m.provider === provider && m.objectPath === r.objectPath,
          ),
        ) ?? null;
      const live = r.kind === 'withdraw' ? [] : r.providers.filter((p) => holderOf(p) !== null);
      out.push({
        id: r._id,
        subscriptionId: r.subscriptionId,
        objectPath: r.objectPath,
        providers: r.providers,
        attempts: r.attempts,
        kind: r.kind,
        // A copy a live row still serves is repaired in place, under the row
        // that holds it now; a copy nothing references any more is residue
        // and is withdrawn.
        referenced: live.length > 0,
        ownerId: live.length > 0 ? holderOf(live[0]!)!._id : null,
        residueProviders: r.providers.filter((p) => !live.includes(p)),
      });
    }
    return out;
  },
});
