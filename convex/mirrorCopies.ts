/**
 * The mirror sync ledger (docs/mirrors.md): one row per
 * copy of a member's mirror (subscription x provider), so FCP can say for every
 * requested mirror whether the object matches what it would serve right now,
 * when it last synced and what failed. The rules live in lib/mirrorSync.ts;
 * this module holds the rows and keeps them in step with
 * `subscriptions.subscriptionMirrors`, which stays the truth for what the member
 * holds: every write of that list goes through a helper here (insert, move,
 * drop), every state change bumps the `stats:mirrorCopies` counter
 * (lib/statusCounters.ts), and a daily reconcile rebuilds the counter and drops
 * rows the subscription no longer lists.
 *
 * The rows also drive the mirror passes (storage.ts): the sweep and the full
 * pass page this table, so their cost follows the mirrors members asked for,
 * not every active key. Legacy mirrors (from before the ledger) get their rows
 * once, from a pass that pages the active keys (`seedPage`).
 *
 * Privacy: hashes, provider names and times only. No content, no country, no
 * address, no IP.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import { runWithCronOutcome } from './cronHeartbeat';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import type { BackendId } from './lib/backendIds';
import {
  afterCheck,
  afterInvalidation,
  afterVerify,
  MIRROR_ATTENTION_AFTER_MS,
  MIRROR_CHECK_OVERDUE_MS,
  MIRROR_REVERIFY_AFTER_MS,
  MIRROR_VERIFY_EVERY_MS,
  type CopyOutcome,
  type CopySync,
  type MirrorReason,
  type VerifyOutcome,
} from './lib/mirrorSync';
import {
  beginCounterReconcile,
  bumpMirrorCopyCounts,
  finishCounterReconcile,
  MIRROR_COPY_COUNTER,
  readMirrorCopyCounts,
  scanCounterPage,
  type MirrorCopyCounts,
  type MirrorCopyState,
} from './lib/statusCounters';

type Copy = Doc<'mirrorCopies'>;

const stateValidator = v.union(
  v.literal('in_sync'),
  v.literal('stale'),
  v.literal('failing'),
  v.literal('never'),
);

/** One subscription's copies (a handful at most: bounded by `mirror.maxPerUser`). */
export async function copiesOf(db: DatabaseReader, subscriptionId: Id<'subscriptions'>) {
  return db
    .query('mirrorCopies')
    .withIndex('by_subscription', (q) => q.eq('subscriptionId', subscriptionId))
    .collect();
}

function syncOf(c: Copy): CopySync {
  return {
    state: c.state,
    reason: c.reason,
    since: c.since,
    checkedAt: c.checkedAt,
    syncedAt: c.syncedAt,
    uploadedAt: c.uploadedAt,
    objectHash: c.objectHash,
    servedHash: c.servedHash,
    servedEpoch: c.servedEpoch,
    stub: c.stub,
    failures: c.failures,
    lastError: c.lastError,
    lastErrorAt: c.lastErrorAt,
  };
}

/** Write a copy's new sync (absent fields cleared) and bump the counter when its state moved. */
async function writeSync(ctx: MutationCtx, row: Copy, next: CopySync, extra: Partial<Copy> = {}) {
  await ctx.db.patch(row._id, {
    reason: undefined,
    checkedAt: undefined,
    syncedAt: undefined,
    uploadedAt: undefined,
    objectHash: undefined,
    servedHash: undefined,
    servedEpoch: undefined,
    stub: undefined,
    lastError: undefined,
    lastErrorAt: undefined,
    ...next,
    ...extra,
    updatedAt: Date.now(),
  });
  if (row.state !== next.state)
    await bumpMirrorCopyCounts(ctx, [
      { from: row.state, to: next.state, creationTime: row._creationTime },
    ]);
}

/** A new copy row (the counter counts it). */
export async function insertCopy(
  ctx: MutationCtx,
  a: { subscriptionId: Id<'subscriptions'>; provider: string; objectPath: string; sync: CopySync },
): Promise<Id<'mirrorCopies'>> {
  const id = await ctx.db.insert('mirrorCopies', {
    subscriptionId: a.subscriptionId,
    provider: a.provider,
    objectPath: a.objectPath,
    ...a.sync,
    updatedAt: Date.now(),
  });
  const row = (await ctx.db.get(id))!;
  await bumpMirrorCopyCounts(ctx, [{ from: null, to: row.state, creationTime: row._creationTime }]);
  return id;
}

async function deleteCopy(ctx: MutationCtx, row: Copy) {
  await ctx.db.delete(row._id);
  await bumpMirrorCopyCounts(ctx, [{ from: row.state, to: null, creationTime: row._creationTime }]);
}

/** Drop a subscription's copies (all, or only these providers'): its mirrors were cleared, withdrawn or retired. */
export async function deleteCopiesOf(
  ctx: MutationCtx,
  subscriptionId: Id<'subscriptions'>,
  providers?: readonly string[],
): Promise<number> {
  let n = 0;
  for (const row of await copiesOf(ctx.db, subscriptionId)) {
    if (providers && !providers.includes(row.provider)) continue;
    await deleteCopy(ctx, row);
    n++;
  }
  return n;
}

/**
 * Something the served body depends on moved for this key (an in-place switch,
 * the member's country): every copy is stale until the next check renders it.
 */
export async function invalidateCopies(
  ctx: MutationCtx,
  subscriptionId: Id<'subscriptions'>,
  reason: MirrorReason,
): Promise<number> {
  const now = Date.now();
  const rows = await copiesOf(ctx.db, subscriptionId);
  for (const row of rows) await writeSync(ctx, row, afterInvalidation(syncOf(row), reason, now));
  return rows.length;
}

/**
 * The copies that do not hold `hash` (the body FCP serves now, just written to
 * another copy) are stale: their content changed.
 */
export async function invalidateCopiesNotHolding(
  ctx: MutationCtx,
  subscriptionId: Id<'subscriptions'>,
  hash: string,
  reason: MirrorReason,
): Promise<number> {
  const sub = await ctx.db.get(subscriptionId);
  if (!sub) return 0;
  const now = Date.now();
  let n = 0;
  for (const row of await ensureCopies(ctx, sub)) {
    if (row.objectHash === hash) continue;
    await writeSync(ctx, row, afterInvalidation(syncOf(row), reason, now));
    n++;
  }
  return n;
}

/**
 * The mirrors moved to another row of the same key (a re-issue carried them, or
 * a failed saga handed them back): the copies follow, stale, because the object
 * still holds what the row they left served.
 */
export async function moveCopies(
  ctx: MutationCtx,
  from: Id<'subscriptions'>,
  to: Id<'subscriptions'>,
): Promise<void> {
  const now = Date.now();
  const already = new Set((await copiesOf(ctx.db, to)).map((r) => r.provider));
  for (const row of await copiesOf(ctx.db, from)) {
    if (already.has(row.provider)) {
      // The destination tracks this copy already: the newer record wins.
      await deleteCopy(ctx, row);
      continue;
    }
    await writeSync(ctx, row, afterInvalidation(syncOf(row), 'reissued', now), {
      subscriptionId: to,
    });
  }
}

/**
 * Bring one subscription's rows in step with its mirror list: a listed copy
 * without a row gets one (a legacy mirror: stale until its first check, with
 * the subscription-wide hash as what the object holds when its last refresh
 * succeeded), a row the list (or an inactive key) no longer has goes, a row of
 * another object path follows the list. Returns the rows as they are now.
 */
export async function ensureCopies(ctx: MutationCtx, sub: Doc<'subscriptions'>): Promise<Copy[]> {
  const now = Date.now();
  const listed =
    sub.state === 'active'
      ? sub.subscriptionMirrors.filter(
          (m): m is typeof m & { objectPath: string } => typeof m.objectPath === 'string',
        )
      : [];
  const rows = await copiesOf(ctx.db, sub._id);
  const out: Copy[] = [];
  for (const row of rows) {
    const entry = listed.find((m) => m.provider === row.provider);
    if (!entry) {
      await deleteCopy(ctx, row);
      continue;
    }
    if (entry.objectPath !== row.objectPath) {
      await writeSync(ctx, row, afterInvalidation(syncOf(row), 'reissued', now), {
        objectPath: entry.objectPath,
        objectHash: undefined,
      });
      out.push((await ctx.db.get(row._id))!);
      continue;
    }
    out.push(row);
  }
  for (const entry of listed) {
    if (rows.some((r) => r.provider === entry.provider)) continue;
    const id = await insertCopy(ctx, {
      subscriptionId: sub._id,
      provider: entry.provider,
      objectPath: entry.objectPath,
      sync: {
        state: 'stale',
        reason: 'unchecked',
        since: now,
        objectHash: entry.status !== 'failed' ? sub.rawContentHash : undefined,
        failures: 0,
      },
    });
    out.push((await ctx.db.get(id))!);
  }
  return out;
}

// --- the refresh's view of a mirrored key -----------------------------------------------------------

/** One mirrored key, as the refresh (storage.ts `refreshOneSubMirrors`) needs it. */
export interface MirrorItem {
  id: Id<'subscriptions'>;
  backend: BackendId;
  backendServerId: Id<'backendServers'> | null;
  backendShortId: string;
  subscriptionUrl: string;
  rawContentHash: string | null;
  objectPath: string | null;
  /** The node this key is moving OFF (switch-server / regenerate). The refresh
   *  MUST re-pin with the same exclusion the live route uses: node pinning is
   *  deterministic, so fetching without it regenerates the old node, the hash
   *  matches, and the mirror stays parked on the server the member just left. */
  excludeNode: string | null;
  /** The providers THIS sub was mirrored to (names) — refresh re-uploads to these only. */
  providers: string[];
  /** What each copy holds as far as FCP knows (null = unknown): the per-copy skip-if-unchanged. */
  copies: { provider: string; objectHash: string | null }[];
  /** The row's `deliveryRev` at read: an upload that outlives an in-place move stamps nothing. */
  deliveryRev: number;
  /** The row's `countryRev` at read: a check that straddles a country change records no sync. */
  countryRev: number;
}

/** One page of mirrored keys for a mirror pass. */
export interface MirrorPage {
  isDone: boolean;
  continueCursor: string;
  items: MirrorItem[];
}

/** The refresh item of one active, mirrored subscription (copies from the ledger, else the legacy hash). */
export async function mirrorItemOf(
  db: DatabaseReader,
  s: Doc<'subscriptions'>,
): Promise<MirrorItem | null> {
  if (s.state !== 'active' || s.subscriptionMirrors.length === 0) return null;
  const rows = await copiesOf(db, s._id);
  return {
    id: s._id,
    backend: s.backend,
    backendServerId: s.backendServerId ?? null,
    backendShortId: s.backendShortId,
    subscriptionUrl: s.subscriptionUrl,
    rawContentHash: s.rawContentHash ?? null,
    objectPath: s.subscriptionMirrors[0]?.objectPath ?? null,
    excludeNode: s.excludeNode ?? null,
    providers: s.subscriptionMirrors.map((m) => m.provider),
    copies: s.subscriptionMirrors.map((m) => {
      const row = rows.find((r) => r.provider === m.provider);
      if (row) return { provider: m.provider, objectHash: row.objectHash ?? null };
      return {
        provider: m.provider,
        objectHash: m.status !== 'failed' ? (s.rawContentHash ?? null) : null,
      };
    }),
    deliveryRev: s.deliveryRev ?? 0,
    countryRev: s.countryRev ?? 0,
  };
}

/**
 * Page the mirrored keys through the ledger (by subscription, so one key's
 * copies are adjacent). `after`: the key the previous page ended on; its
 * remaining copies here are skipped (it was refreshed whole).
 */
export const pageMirrored = internalQuery({
  args: {
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
    after: v.optional(v.id('subscriptions')),
  },
  handler: async (ctx, { cursor, numItems, after }): Promise<MirrorPage> => {
    const res = await ctx.db
      .query('mirrorCopies')
      .withIndex('by_subscription')
      .paginate({ cursor, numItems });
    const seen = new Set<string>(after ? [after] : []);
    const items: MirrorItem[] = [];
    for (const c of res.page) {
      if (seen.has(c.subscriptionId)) continue;
      seen.add(c.subscriptionId);
      const sub = await ctx.db.get(c.subscriptionId);
      const item = sub ? await mirrorItemOf(ctx.db, sub) : null;
      if (item) items.push(item);
    }
    return { isDone: res.isDone, continueCursor: res.continueCursor, items };
  },
});

/** The legacy rows are in: the passes page the ledger from now on. */
const SEEDED_KEY = 'mirror-copies:seeded';

export const isSeeded = internalQuery({
  args: {},
  handler: async (ctx): Promise<boolean> =>
    !!(await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', SEEDED_KEY))
      .unique()),
});

export const markSeeded = internalMutation({
  args: {},
  handler: async (ctx) => {
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', SEEDED_KEY))
      .unique();
    if (!row)
      await ctx.db.insert('appState', { key: SEEDED_KEY, value: '1', updatedAt: Date.now() });
    return null;
  },
});

/**
 * The one pass over the active keys that gives the mirrors from before the
 * ledger their rows (and returns those keys for the pass to refresh). Pages
 * active subscriptions, so it runs until the first pass completes and never
 * again (`markSeeded`).
 */
export const seedPage = internalMutation({
  args: { cursor: v.union(v.string(), v.null()), numItems: v.number() },
  handler: async (ctx, { cursor, numItems }): Promise<MirrorPage> => {
    const res = await ctx.db
      .query('subscriptions')
      .withIndex('by_state', (q) => q.eq('state', 'active'))
      .paginate({ cursor, numItems });
    const items: MirrorItem[] = [];
    for (const s of res.page) {
      if (s.subscriptionMirrors.length === 0) continue;
      await ensureCopies(ctx, s);
      const item = await mirrorItemOf(ctx.db, s);
      if (item) items.push(item);
    }
    return { isDone: res.isDone, continueCursor: res.continueCursor, items };
  },
});

// --- recording what a check, an upload or a read found --------------------------------------------

const outcomeValidator = v.union(
  v.object({ kind: v.literal('confirmed') }),
  v.object({ kind: v.literal('uploaded'), moved: v.boolean() }),
  v.object({ kind: v.literal('upload_failed') }),
  v.object({ kind: v.literal('fetch_failed') }),
  v.object({ kind: v.literal('provider_missing') }),
);

/**
 * Record one check of a key's copies (a refresh, a repair, a first mirror).
 * A check that straddled a move of the key itself (its `deliveryRev` or
 * `countryRev` changed since the read) confirms nothing: what it wrote is
 * still recorded (the object holds it now), but the copy stays stale; the
 * change scheduled its own refresh.
 */
export const recordCheck = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    deliveryRev: v.number(),
    countryRev: v.number(),
    at: v.number(),
    served: v.union(
      v.object({ hash: v.string(), epoch: v.union(v.number(), v.null()), stub: v.boolean() }),
      v.null(),
    ),
    outcomes: v.array(v.object({ provider: v.string(), outcome: outcomeValidator })),
  },
  handler: async (ctx, a) => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || sub.state !== 'active') return { recorded: 0 };
    const rows = await ensureCopies(ctx, sub);
    const current =
      (sub.deliveryRev ?? 0) === a.deliveryRev && (sub.countryRev ?? 0) === a.countryRev;
    let recorded = 0;
    for (const { provider, outcome } of a.outcomes) {
      const row = rows.find((r) => r.provider === provider);
      if (!row) continue;
      let o: CopyOutcome = outcome;
      if (!current) {
        if (o.kind === 'confirmed') continue;
        if (o.kind === 'uploaded') o = { kind: 'uploaded', moved: true };
      }
      const next = afterCheck(syncOf(row), o, a.at, current ? a.served : null);
      // A write that a move overtook keeps the reason the move gave it.
      if (!current && o.kind === 'uploaded' && row.state === 'stale') next.reason = row.reason;
      await writeSync(ctx, row, next);
      recorded++;
    }
    return { recorded };
  },
});

/**
 * An upload of an older row of this key overwrote these copies (a refresh that
 * read the row before a re-issue carried the mirrors here): the object holds
 * that body now, so the owner's copies are stale until it rewrites them.
 */
export const noteOverwritten = internalMutation({
  args: {
    subscriptionId: v.id('subscriptions'),
    objectPath: v.string(),
    providers: v.array(v.string()),
    writtenHash: v.string(),
  },
  handler: async (ctx, a) => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || sub.state !== 'active') return { marked: 0 };
    const now = Date.now();
    let marked = 0;
    for (const row of await ensureCopies(ctx, sub)) {
      if (row.objectPath !== a.objectPath || !a.providers.includes(row.provider)) continue;
      await writeSync(
        ctx,
        row,
        { ...afterInvalidation(syncOf(row), 'overwritten', now), objectHash: a.writtenHash },
        {},
      );
      marked++;
    }
    return { marked };
  },
});

/** Copies whose member-facing URL is due a read (never read first, then the oldest read). */
export const dueForVerify = internalQuery({
  args: { now: v.number(), limit: v.number() },
  handler: async (ctx, { now, limit }) => {
    // Problems first (re-read soon after the rewrite they caused), then the
    // never-read and the oldest reads.
    const rows: Copy[] = [];
    for (const verify of ['missing', 'mismatch'] as const) {
      if (rows.length >= limit) break;
      rows.push(
        ...(await ctx.db
          .query('mirrorCopies')
          .withIndex('by_verify', (q) =>
            q.eq('verify', verify).lt('verifiedAt', now - MIRROR_REVERIFY_AFTER_MS),
          )
          .take(limit - rows.length)),
      );
    }
    if (rows.length < limit) {
      const seen = new Set(rows.map((r) => r._id as string));
      for (const r of await ctx.db
        .query('mirrorCopies')
        .withIndex('by_verified', (q) => q.lt('verifiedAt', now - MIRROR_VERIFY_EVERY_MS))
        .take(limit - rows.length))
        if (!seen.has(r._id)) rows.push(r);
    }
    const out: {
      id: Id<'mirrorCopies'>;
      subscriptionId: Id<'subscriptions'>;
      provider: string;
      publicUrl: string;
      objectHash: string | null;
    }[] = [];
    for (const r of rows) {
      const sub = await ctx.db.get(r.subscriptionId);
      const entry = sub?.subscriptionMirrors.find(
        (m) => m.provider === r.provider && m.objectPath === r.objectPath,
      );
      // A row the subscription no longer lists is dropped by the reconcile.
      if (!sub || sub.state !== 'active' || !entry) continue;
      out.push({
        id: r._id,
        subscriptionId: r.subscriptionId,
        provider: r.provider,
        publicUrl: entry.publicUrl,
        objectHash: r.objectHash ?? null,
      });
    }
    return { rows: out, scanned: rows.length };
  },
});

/**
 * Record a read of a copy's member-facing URL. `objectHash`: what the row held
 * when the read started; an upload that landed meanwhile makes the read
 * meaningless, so only its time is kept. Returns whether the copy now needs an
 * upload (the caller schedules the refresh).
 */
export const recordVerify = internalMutation({
  args: {
    id: v.id('mirrorCopies'),
    objectHash: v.union(v.string(), v.null()),
    at: v.number(),
    outcome: v.union(
      v.object({ kind: v.literal('match') }),
      v.object({ kind: v.literal('mismatch'), observedHash: v.string() }),
      v.object({ kind: v.literal('missing') }),
      v.object({ kind: v.literal('unreachable') }),
    ),
  },
  handler: async (ctx, { id, objectHash, at, outcome }): Promise<{ needsUpload: boolean }> => {
    const row = await ctx.db.get(id);
    if (!row) return { needsUpload: false };
    if ((row.objectHash ?? null) !== objectHash) {
      await ctx.db.patch(id, { verifiedAt: at, updatedAt: Date.now() });
      return { needsUpload: false };
    }
    const { next, reupload } = afterVerify(
      syncOf(row),
      { verify: row.verify, verifiedAt: row.verifiedAt },
      outcome as VerifyOutcome,
      at,
    );
    // An unreachable read keeps what the last real read found (its retry
    // decides): only a read that got an answer replaces it.
    await writeSync(ctx, row, next, {
      verifiedAt: at,
      verify: outcome.kind === 'unreachable' && row.verify ? row.verify : outcome.kind,
    });
    return { needsUpload: reupload };
  },
});

// --- admin views --------------------------------------------------------------------------------------

/** Bounded counts past a cutoff (the attention figures): exact up to `cap`, then "cap+". */
const ATTENTION_CAP = 500;

async function countSince(
  db: DatabaseReader,
  state: MirrorCopyState,
  cutoff: number,
): Promise<{ count: number; capped: boolean; oldest: number | null }> {
  const rows = await db
    .query('mirrorCopies')
    .withIndex('by_state_since', (q) => q.eq('state', state).lt('since', cutoff))
    .take(ATTENTION_CAP + 1);
  return {
    count: Math.min(rows.length, ATTENTION_CAP),
    capped: rows.length > ATTENTION_CAP,
    oldest: rows[0]?.since ?? null,
  };
}

/** The mirror pass state (`mirrorProviders.claimMirrorPass`), read-only. */
async function passOf(db: DatabaseReader): Promise<{ running: boolean; at: number | null }> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', 'mirror:pass'))
    .unique();
  if (!row) return { running: false, at: null };
  try {
    const p = JSON.parse(row.value) as { running?: boolean; at?: number };
    return { running: p.running === true, at: typeof p.at === 'number' ? p.at : null };
  } catch {
    return { running: false, at: null };
  }
}

/**
 * The sync figures for the dashboard and Admin -> Storage: the maintained
 * counts (O(1)), and the attention figures from bounded index reads (copies
 * stale, failing or not uploaded past the bound; in-sync copies the sweep has
 * not checked for too long). Never a scan of the ledger, never a scan of keys.
 */
export async function mirrorSyncSummary(db: DatabaseReader, now: number) {
  const { counts, initialized } = await readMirrorCopyCounts(db);
  const cutoff = now - MIRROR_ATTENTION_AFTER_MS;
  const [stale, failing, never] = await Promise.all([
    countSince(db, 'stale', cutoff),
    countSince(db, 'failing', cutoff),
    countSince(db, 'never', cutoff),
  ]);
  const uncheckedRows = await db
    .query('mirrorCopies')
    .withIndex('by_state_checked', (q) =>
      q.eq('state', 'in_sync').lt('checkedAt', now - MIRROR_CHECK_OVERDUE_MS),
    )
    .take(ATTENTION_CAP + 1);
  const unchecked = {
    count: Math.min(uncheckedRows.length, ATTENTION_CAP),
    capped: uncheckedRows.length > ATTENTION_CAP,
    oldest: uncheckedRows[0]?.checkedAt ?? null,
  };
  const pass = await passOf(db);
  const overdue = stale.count + failing.count + never.count + unchecked.count;
  return {
    counts: {
      inSync: counts.in_sync,
      stale: counts.stale,
      failing: counts.failing,
      never: counts.never,
      total: counts.in_sync + counts.stale + counts.failing + counts.never,
    },
    initialized,
    attentionAfterMs: MIRROR_ATTENTION_AFTER_MS,
    checkOverdueMs: MIRROR_CHECK_OVERDUE_MS,
    overdue: { stale, failing, never, unchecked },
    attention: overdue > 0,
    pass,
  };
}

export const summary = internalQuery({
  args: {},
  handler: async (ctx) => mirrorSyncSummary(ctx.db, Date.now()),
});

const hashPrefix = (h: string | undefined) => (h ? h.slice(0, 12) : null);

/**
 * Per-mirror detail for Admin -> Storage, one page at a time: by state (oldest
 * in that state first), or `attention` (stale, failing and not uploaded, past
 * the bound). Hash prefixes only; never the object path or URL (a capability).
 */
export const listForAdmin = internalQuery({
  args: {
    state: v.optional(stateValidator),
    cursor: v.union(v.string(), v.null()),
    numItems: v.number(),
  },
  handler: async (ctx, { state, cursor, numItems }) => {
    const res = state
      ? await ctx.db
          .query('mirrorCopies')
          .withIndex('by_state_since', (q) => q.eq('state', state))
          .paginate({ cursor, numItems: Math.min(numItems, 100) })
      : await ctx.db
          .query('mirrorCopies')
          .order('desc')
          .paginate({ cursor, numItems: Math.min(numItems, 100) });
    const page = [];
    for (const c of res.page) {
      const sub = await ctx.db.get(c.subscriptionId);
      page.push({
        id: c._id as string,
        subscriptionId: c.subscriptionId as string,
        userId: (sub?.userId as string | undefined) ?? null,
        provider: c.provider,
        state: c.state,
        reason: c.reason ?? null,
        since: c.since,
        checkedAt: c.checkedAt ?? null,
        syncedAt: c.syncedAt ?? null,
        uploadedAt: c.uploadedAt ?? null,
        verifiedAt: c.verifiedAt ?? null,
        verify: c.verify ?? null,
        failures: c.failures,
        lastError: c.lastError ?? null,
        lastErrorAt: c.lastErrorAt ?? null,
        objectHash: hashPrefix(c.objectHash),
        servedHash: hashPrefix(c.servedHash),
        matches: !!c.objectHash && c.objectHash === c.servedHash,
        servedEpoch: c.servedEpoch ?? null,
        stub: c.stub === true,
      });
    }
    return { page, isDone: res.isDone, continueCursor: res.continueCursor };
  },
});

/** One copy, for the admin re-check (which subscription and provider to refresh and read). */
export const copyRef = internalQuery({
  args: { id: v.id('mirrorCopies') },
  handler: async (ctx, { id }) => {
    const c = await ctx.db.get(id);
    return c ? { subscriptionId: c.subscriptionId, provider: c.provider } : null;
  },
});

/** One copy's member-facing URL and what FCP last wrote to it (the admin re-check's read). */
export const verifyTarget = internalQuery({
  args: { id: v.id('mirrorCopies') },
  handler: async (ctx, { id }) => {
    const c = await ctx.db.get(id);
    if (!c) return null;
    const sub = await ctx.db.get(c.subscriptionId);
    const entry = sub?.subscriptionMirrors.find(
      (m) => m.provider === c.provider && m.objectPath === c.objectPath,
    );
    return entry ? { publicUrl: entry.publicUrl, objectHash: c.objectHash ?? null } : null;
  },
});

/** These providers' copies of one key, for a read right after their rewrite. */
export const verifyTargetsOf = internalQuery({
  args: { subscriptionId: v.id('subscriptions'), providers: v.array(v.string()) },
  handler: async (ctx, { subscriptionId, providers }) => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub || sub.state !== 'active') return [];
    const out: { id: Id<'mirrorCopies'>; publicUrl: string; objectHash: string | null }[] = [];
    for (const c of await copiesOf(ctx.db, subscriptionId)) {
      if (!providers.includes(c.provider)) continue;
      const entry = sub.subscriptionMirrors.find(
        (m) => m.provider === c.provider && m.objectPath === c.objectPath,
      );
      if (entry)
        out.push({ id: c._id, publicUrl: entry.publicUrl, objectHash: c.objectHash ?? null });
    }
    return out;
  },
});

/** How many copies a provider holds (exact up to the cap): its name is their match key. */
export async function copiesOnProvider(
  db: DatabaseReader,
  provider: string,
  cap = 1000,
): Promise<{ count: number; capped: boolean }> {
  const rows = await db
    .query('mirrorCopies')
    .withIndex('by_provider', (q) => q.eq('provider', provider))
    .take(cap + 1);
  return { count: Math.min(rows.length, cap), capped: rows.length > cap };
}

/** A page of one provider's copies (its withdrawal, storage.ts `withdrawProviderMirrors`). */
export const pageOnProvider = internalQuery({
  args: { provider: v.string(), numItems: v.number() },
  handler: async (ctx, { provider, numItems }) => {
    const rows = await ctx.db
      .query('mirrorCopies')
      .withIndex('by_provider', (q) => q.eq('provider', provider))
      .take(numItems);
    return rows.map((r) => ({
      subscriptionId: r.subscriptionId,
      provider: r.provider,
      objectPath: r.objectPath,
    }));
  },
});

// --- the daily reconcile ------------------------------------------------------------------------------

const RECONCILE_PAGE = 200;

/**
 * Drop rows whose subscription no longer lists them (or is no longer active):
 * every write keeps them in step, so this only catches what a crash between
 * two writes left behind. One page per call; returns the cursor.
 */
export const dropOrphansPage = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  handler: async (ctx, { cursor }) => {
    const res = await ctx.db.query('mirrorCopies').paginate({ cursor, numItems: RECONCILE_PAGE });
    let dropped = 0;
    for (const row of res.page) {
      const sub = await ctx.db.get(row.subscriptionId);
      const listed =
        !!sub &&
        sub.state === 'active' &&
        sub.subscriptionMirrors.some(
          (m) => m.provider === row.provider && m.objectPath === row.objectPath,
        );
      if (listed) continue;
      await deleteCopy(ctx, row);
      dropped++;
    }
    return { isDone: res.isDone, continueCursor: res.continueCursor, dropped };
  },
});

export const beginCountsReconcile = internalMutation({
  args: {},
  handler: async (ctx): Promise<number> => beginCounterReconcile(ctx, MIRROR_COPY_COUNTER),
});

export const scanCountsPage = internalMutation({
  args: {},
  handler: async (ctx) =>
    scanCounterPage(
      ctx,
      MIRROR_COPY_COUNTER,
      (row) => ({ [row.state]: 1 }) as Partial<Record<MirrorCopyState, number>>,
      RECONCILE_PAGE,
    ),
});

export const finishCountsReconcile = internalMutation({
  args: { token: v.number() },
  handler: async (ctx, { token }): Promise<boolean> =>
    finishCounterReconcile(ctx, MIRROR_COPY_COUNTER, token),
});

export const getCounts = internalQuery({
  args: {},
  handler: async (ctx) => readMirrorCopyCounts(ctx.db),
});

/**
 * Daily: drop orphaned rows, then rebuild the counter exactly (the
 * statusCounters protocol). Idempotent; a missed bump heals here.
 */
export const reconcile = internalAction({
  args: {},
  handler: async (ctx): Promise<{ dropped: number; counts: MirrorCopyCounts }> =>
    runWithCronOutcome(ctx, 'mirror-copies-reconcile', async () => {
      let cursor: string | null = null;
      let dropped = 0;
      for (let i = 0; i < 10_000; i++) {
        const res: { isDone: boolean; continueCursor: string; dropped: number } =
          await ctx.runMutation(internal.mirrorCopies.dropOrphansPage, { cursor });
        dropped += res.dropped;
        if (res.isDone) break;
        cursor = res.continueCursor;
      }
      const token: number = await ctx.runMutation(internal.mirrorCopies.beginCountsReconcile, {});
      for (let i = 0; i < 100_000; i++) {
        const res: { done: boolean; rows: number } = await ctx.runMutation(
          internal.mirrorCopies.scanCountsPage,
          {},
        );
        if (res.done) break;
      }
      const applied: boolean = await ctx.runMutation(internal.mirrorCopies.finishCountsReconcile, {
        token,
      });
      if (!applied) console.warn('[mirror-copies-reconcile] superseded by a newer run; skipped');
      const st: { counts: MirrorCopyCounts; initialized: boolean } = await ctx.runQuery(
        internal.mirrorCopies.getCounts,
        {},
      );
      return { dropped, counts: st.counts };
    }),
});
