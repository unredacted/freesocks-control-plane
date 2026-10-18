/**
 * The one-time move of every provider account's FIXED location into a
 * location (docs/edges.md § "Deploy notes"). Run from `seed:seedCutover` on
 * every deploy until its completion marker is written; by hand through the
 * deployer container as `seed:migrateEdgeLocations`, its state read with
 * `seed:edgeLocationsStatus`.
 *
 * Six phases, each with its OWN predicate ("work left"), each paged and
 * idempotent, so a run killed anywhere resumes at the first phase that still
 * has work:
 *
 *   1 locations   a legacy account (an L4 one whose settings still hold a
 *                 placement no location of it has; an L7 one with no
 *                 location) gets its location: placement, place key, the
 *                 trust and the inventory it held.
 *   2 edges       a non-destroyed edge with an account and no frozen
 *                 placement gets its account's location frozen on it.
 *                 `templateHash` is never touched: the L4 tick binds to it.
 *   3 setup runs  a run with the old single `accountId` gets `picks`, and
 *                 every listener entry its location.
 *   4 reviews     every stored review entry that names an account but no
 *                 location gets it; the stored review HASH is not recomputed
 *                 (`committedReviewOf` matches on it, and nothing recomputes
 *                 a committed shape on a schedule).
 *   5 relays      a backend-node origin with live edges gets its provider set.
 *   6 cleanup     an account still holding the moved fields (placement keys,
 *                 trust, inventory), once every one of its edges is frozen,
 *                 loses them. An edge-scoped provider call reads the account
 *                 first and the edge second, so a call racing this phase
 *                 always sees a placement on one of the two.
 *
 * The marker is written only when every predicate counts zero.
 *
 * The guard: when no legacy row exists (a fresh deployment, CI, a prod with
 * no accounts) the marker is written and nothing else happens. Otherwise the
 * edges maintenance switch must be held (`needs_freeze` writes nothing), and
 * every phase mutation re-checks quiescence before it writes anything (no
 * rotation, setup run, running activation or provisioning edge in flight:
 * `not_quiescent` writes nothing). That catches work that entered while the
 * old functions still served, between the operator's checks and the push.
 */
import { v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { readMaintenance } from './lib/edges/maintenance';
import {
  EDGE_PLACEMENT_SETTINGS,
  placementKeysOf,
  validatePlacement,
  withoutPlacementKeys,
} from './lib/edges/accountSettings';
import { placementHashOf } from './lib/edges/locations';
import { isTerminalRunState } from './lib/edges/setupRuns';
import { ROTATION_PHASES, TERMINAL_PHASES } from './lib/edges/rotation';
import { defaultLocationOf, upsertLocation } from './edgeLocations';

export const MIGRATION_KEY = 'edge:locationsMigration';
export const MIGRATION_VERSION = 1;
const PAGE = 100;

type Account = Doc<'edgeProviderAccounts'>;

// --- predicates (pure over rows) -------------------------------------------------------------

/** Account fields that moved to locations (cleared by phase 6). */
const MOVED_ACCOUNT_FIELDS = [
  'qualified',
  'qualifiedTemplateHash',
  'qualification',
  'autoQualifyHold',
  'inventorySnapshot',
  'inventoryAt',
] as const;

function legacyPlacementOf(a: Account): Record<string, unknown> | null {
  const keys = placementKeysOf(a.provider, a.settings as Record<string, unknown>);
  return keys ? { ...keys, type: a.provider } : null;
}

function holdsMovedFields(a: Account): boolean {
  return (
    !!placementKeysOf(a.provider, a.settings as Record<string, unknown>) ||
    MOVED_ACCOUNT_FIELDS.some((k) => a[k] !== undefined)
  );
}

/** The location an account's legacy fixed place became (null: not created yet). */
async function migratedLocationOf(
  db: DatabaseReader,
  a: Account,
): Promise<Doc<'edgeLocations'> | null> {
  if (EDGE_PLACEMENT_SETTINGS[a.provider].length === 0) return defaultLocationOf(db, a);
  const legacy = legacyPlacementOf(a);
  if (!legacy) return defaultLocationOf(db, a);
  const parsed = validatePlacement(a.provider, legacy);
  if (!parsed.ok) return null;
  const hash = placementHashOf(parsed.placement);
  return (
    (await db
      .query('edgeLocations')
      .withIndex('by_account_placement', (q) => q.eq('accountId', a._id).eq('placementHash', hash))
      .first()) ?? null
  );
}

async function accountNeedsLocation(db: DatabaseReader, a: Account): Promise<boolean> {
  if (EDGE_PLACEMENT_SETTINGS[a.provider].length === 0) return !(await defaultLocationOf(db, a));
  if (!legacyPlacementOf(a)) return false; // a credentials-only account: nothing to move
  return !(await migratedLocationOf(db, a));
}

function edgeNeedsPlacement(e: Doc<'edges'>): boolean {
  return e.status !== 'destroyed' && !!e.accountId && !e.placement;
}

function runNeedsPicks(r: Doc<'edgeSetupRuns'>): boolean {
  if (r.accountId !== undefined) return true;
  return !!r.picks && r.listeners.some((l) => !l.locationId);
}

function reviewEntriesWithoutLocation(review: string): number {
  try {
    const shape = JSON.parse(review) as {
      listeners?: Array<{ accountId?: string | null; locationId?: string | null }>;
    };
    return (shape.listeners ?? []).filter((l) => !!l.accountId && l.locationId === undefined)
      .length;
  } catch {
    return 0;
  }
}

// --- the guard -------------------------------------------------------------------------------------

async function quiescenceCounts(db: DatabaseReader) {
  let rotations = 0;
  for (const phase of ROTATION_PHASES) {
    if ((TERMINAL_PHASES as readonly string[]).includes(phase)) continue;
    rotations += (
      await db
        .query('edgeRotations')
        .withIndex('by_phase', (q) => q.eq('phase', phase))
        .take(50)
    ).length;
  }
  let setupRuns = 0;
  for (const state of ['running', 'waiting', 'needs_you'] as const)
    setupRuns += (
      await db
        .query('edgeSetupRuns')
        .withIndex('by_state', (q) => q.eq('state', state))
        .take(50)
    ).length;
  const activations = (
    await db
      .query('panelActivationRuns')
      .withIndex('by_state', (q) => q.eq('state', 'running'))
      .take(50)
  ).length;
  let provisioningEdges = 0;
  for (const status of ['planning', 'provisioning'] as const)
    provisioningEdges += (
      await db
        .query('edges')
        .withIndex('by_status', (q) => q.eq('status', status))
        .take(50)
    ).length;
  return { rotations, setupRuns, activations, provisioningEdges };
}

type GuardResult =
  | { ok: true }
  | { ok: false; code: 'needs_freeze' }
  | { ok: false; code: 'not_quiescent'; counts: Awaited<ReturnType<typeof quiescenceCounts>> };

/** Checked inside every phase mutation, before it writes anything. */
async function guard(db: DatabaseReader): Promise<GuardResult> {
  if (!(await readMaintenance(db)).frozen) return { ok: false, code: 'needs_freeze' };
  const counts = await quiescenceCounts(db);
  if (counts.rotations + counts.setupRuns + counts.activations + counts.provisioningEdges > 0)
    return { ok: false, code: 'not_quiescent', counts };
  return { ok: true };
}

// --- status ----------------------------------------------------------------------------------------

export async function migrationStatus(db: DatabaseReader) {
  let accounts = 0;
  let cleanup = 0;
  for (const a of await db.query('edgeProviderAccounts').collect()) {
    if (await accountNeedsLocation(db, a)) accounts++;
    if (holdsMovedFields(a)) cleanup++;
  }
  let edges = 0;
  for (const e of await db.query('edges').collect()) if (edgeNeedsPlacement(e)) edges++;
  let runs = 0;
  for (const r of await db.query('edgeSetupRuns').collect()) if (runNeedsPicks(r)) runs++;
  let reviews = 0;
  for (const r of await db.query('panelActivationRuns').collect())
    if (reviewEntriesWithoutLocation(r.candidate.review) > 0) reviews++;
  let relays = 0;
  for (const r of await db.query('relays').collect()) if (await relayNeedsSet(db, r)) relays++;
  const marker = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', MIGRATION_KEY))
    .unique();
  return {
    accounts,
    edges,
    runs,
    reviews,
    relays,
    cleanup,
    done: accounts + edges + runs + reviews + relays + cleanup === 0,
    marker: marker ? (JSON.parse(marker.value) as { version: number; completedAt: number }) : null,
  };
}

async function relayNeedsSet(db: DatabaseReader, r: Doc<'relays'>): Promise<boolean> {
  if (r.origin.kind !== 'panel-node' || r.providerSet !== undefined) return false;
  const live = await db
    .query('edges')
    .withIndex('by_relay_status', (q) => q.eq('relayId', r._id))
    .collect();
  return live.some((e) => e.status !== 'destroyed' && !!e.accountId);
}

export const status = internalQuery({
  args: {},
  handler: async (ctx) => ({
    ...(await migrationStatus(ctx.db)),
    frozen: (await readMaintenance(ctx.db)).frozen,
    quiescence: await quiescenceCounts(ctx.db),
  }),
});

// --- phases ----------------------------------------------------------------------------------------

const phaseResult = v.object({
  ok: v.boolean(),
  code: v.optional(v.string()),
  wrote: v.number(),
  cursor: v.union(v.string(), v.null()),
  isDone: v.boolean(),
});

/** Phase 1: a location for each legacy account (trust and inventory moved over). */
export const phaseLocations = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('edgeProviderAccounts').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    for (const a of page.page) {
      if (!(await accountNeedsLocation(ctx.db, a))) continue;
      const placement = legacyPlacementOf(a) ?? { type: a.provider };
      if (!validatePlacement(a.provider, placement).ok) continue; // reported by the status
      const res = await upsertLocation(ctx, a, placement, {}, { quiet: true });
      // The trust and the inventory the account held were taken in this place.
      await ctx.db.patch(res.id, {
        qualified: a.qualified === true,
        ...(a.qualifiedTemplateHash ? { qualifiedTemplateHash: a.qualifiedTemplateHash } : {}),
        ...(a.qualification ? { qualification: a.qualification } : {}),
        ...(a.autoQualifyHold ? { autoQualifyHold: true } : {}),
        ...(a.inventorySnapshot ? { inventorySnapshot: a.inventorySnapshot } : {}),
        ...(a.inventoryAt ? { inventoryAt: a.inventoryAt } : {}),
        updatedAt: Date.now(),
      });
      const fresh = (await ctx.db.get(a._id))!;
      if (!fresh.defaultLocationId) await ctx.db.patch(a._id, { defaultLocationId: res.id });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Phase 2: each live edge of an account freezes that account's location. */
export const phaseEdges = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('edges').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    for (const e of page.page) {
      if (!edgeNeedsPlacement(e)) continue;
      const account = await ctx.db.get(e.accountId!);
      if (!account) continue;
      const loc = await migratedLocationOf(ctx.db, account);
      if (!loc) continue; // phase 1 has not reached the account: the status says so
      // `templateHash` stays as it is: the L4 tick and the approval bind to it.
      await ctx.db.patch(e._id, {
        locationId: loc._id,
        placeKey: loc.placeKey,
        placement: loc.placement,
      });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Phase 3: setup runs name their pick instead of one account. */
export const phaseRuns = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('edgeSetupRuns').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    for (const r of page.page) {
      if (!runNeedsPicks(r)) continue;
      const accountId = r.picks?.[0]?.accountId ?? r.accountId;
      const account = accountId ? await ctx.db.get(accountId) : null;
      const loc = r.picks?.[0]
        ? await ctx.db.get(r.picks[0].locationId)
        : account
          ? await migratedLocationOf(ctx.db, account)
          : null;
      if (!account || !loc) {
        // A run of an account that no longer exists: it can never act again.
        if (!account && isTerminalRunState(r.state)) {
          await ctx.db.patch(r._id, { accountId: undefined });
          wrote++;
        }
        continue;
      }
      await ctx.db.patch(r._id, {
        picks: [{ locationId: loc._id, accountId: account._id }],
        accountId: undefined,
        listeners: r.listeners.map((l) => ({ ...l, locationId: l.locationId ?? loc._id })),
      });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Phase 4: stored reviews name the location of each account entry (the hash stays). */
export const phaseReviews = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('panelActivationRuns').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    for (const r of page.page) {
      if (reviewEntriesWithoutLocation(r.candidate.review) === 0) continue;
      const shape = JSON.parse(r.candidate.review) as {
        listeners: Array<{ accountId?: string | null; locationId?: string | null }>;
      };
      for (const entry of shape.listeners) {
        if (!entry.accountId || entry.locationId !== undefined) continue;
        const account = await ctx.db.get(entry.accountId as Id<'edgeProviderAccounts'>);
        const loc = account ? await migratedLocationOf(ctx.db, account) : null;
        // An account gone since: its entry can match nothing new.
        entry.locationId = loc ? (loc._id as string) : null;
      }
      await ctx.db.patch(r._id, {
        candidate: { ...r.candidate, review: JSON.stringify(shape) },
      });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Phase 5: a backend-node origin's provider set is the locations its live edges are in. */
export const phaseRelays = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('relays').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    const now = Date.now();
    for (const r of page.page) {
      if (!(await relayNeedsSet(ctx.db, r))) continue;
      const edges = (
        await ctx.db
          .query('edges')
          .withIndex('by_relay_status', (q) => q.eq('relayId', r._id))
          .collect()
      )
        .filter((e) => e.status !== 'destroyed' && !!e.locationId)
        .sort((a, b) => a._creationTime - b._creationTime);
      const ids: Id<'edgeLocations'>[] = [];
      for (const e of edges) if (!ids.includes(e.locationId!)) ids.push(e.locationId!);
      if (ids.length === 0) continue; // phase 2 has not reached its edges: the status says so
      await ctx.db.patch(r._id, {
        providerSet: ids.map((locationId) => ({ locationId, addedAt: now })),
      });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Phase 6: an account whose edges are all frozen loses the fields that moved. */
export const phaseCleanup = internalMutation({
  args: { cursor: v.union(v.string(), v.null()) },
  returns: phaseResult,
  handler: async (ctx, { cursor }) => {
    const g = await guard(ctx.db);
    if (!g.ok) return { ok: false, code: g.code, wrote: 0, cursor, isDone: true };
    const page = await ctx.db.query('edgeProviderAccounts').paginate({ cursor, numItems: PAGE });
    let wrote = 0;
    for (const a of page.page) {
      if (!holdsMovedFields(a)) continue;
      if (await accountNeedsLocation(ctx.db, a)) continue; // phase 1 first
      const unfrozen = await ctx.db
        .query('edges')
        .withIndex('by_account_status', (q) => q.eq('accountId', a._id))
        .collect();
      if (unfrozen.some(edgeNeedsPlacement)) continue; // phase 2 first
      await ctx.db.patch(a._id, {
        settings: withoutPlacementKeys(a.provider, a.settings as Record<string, unknown>) as never,
        qualified: undefined,
        qualifiedTemplateHash: undefined,
        qualification: undefined,
        autoQualifyHold: undefined,
        inventorySnapshot: undefined,
        inventoryAt: undefined,
      });
      wrote++;
    }
    return { ok: true, wrote, cursor: page.continueCursor, isDone: page.isDone };
  },
});

/** Whether there is anything to migrate at all (a fresh deployment has nothing). */
export const hasLegacy = internalQuery({
  args: {},
  handler: async (ctx) => !(await migrationStatus(ctx.db)).done,
});

/**
 * Write the completion marker, only when every predicate counts zero (audited
 * with the counts the run wrote). Returns the status either way.
 */
export const finish = internalMutation({
  args: {
    wrote: v.object({
      accounts: v.number(),
      edges: v.number(),
      runs: v.number(),
      reviews: v.number(),
      relays: v.number(),
    }),
  },
  handler: async (ctx, { wrote }) => {
    const st = await migrationStatus(ctx.db);
    if (!st.done) return { done: false, status: st };
    await writeMarker(ctx);
    if (wrote.accounts + wrote.edges + wrote.runs + wrote.reviews + wrote.relays > 0)
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.locations.migrated',
        targetType: 'app_state',
        payload: wrote,
      });
    return { done: true, status: st };
  },
});

async function writeMarker(ctx: MutationCtx): Promise<void> {
  const value = JSON.stringify({ version: MIGRATION_VERSION, completedAt: Date.now() });
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', MIGRATION_KEY))
    .unique();
  if (row) await ctx.db.patch(row._id, { value, updatedAt: Date.now() });
  else await ctx.db.insert('appState', { key: MIGRATION_KEY, value, updatedAt: Date.now() });
}

/** The marker alone (a deployment with nothing to migrate). */
export const markDone = internalMutation({
  args: {},
  handler: async (ctx) => {
    if (!(await migrationStatus(ctx.db)).done) return { done: false };
    await writeMarker(ctx);
    return { done: true };
  },
});

/** Whether the marker is written (the cheap check `seedCutover` makes first). */
export const markerWritten = internalQuery({
  args: {},
  handler: async (ctx) =>
    !!(await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', MIGRATION_KEY))
      .unique()),
});

type PhaseRef =
  | typeof internal.edgeLocationsMigration.phaseLocations
  | typeof internal.edgeLocationsMigration.phaseEdges
  | typeof internal.edgeLocationsMigration.phaseRuns
  | typeof internal.edgeLocationsMigration.phaseReviews
  | typeof internal.edgeLocationsMigration.phaseRelays
  | typeof internal.edgeLocationsMigration.phaseCleanup;

/**
 * Drive the phases in order, each over every page, then write the marker.
 * Returns what happened: `done`, `nothing_to_migrate`, `needs_freeze`,
 * `not_quiescent` (with the counts) or `incomplete` (a predicate still counts
 * work after a pass: the status names it, the next run resumes).
 */
export const drive = internalAction({
  args: {},
  handler: async (
    ctx,
  ): Promise<{
    result:
      | 'done'
      | 'nothing_to_migrate'
      | 'already_done'
      | 'needs_freeze'
      | 'not_quiescent'
      | 'incomplete';
    wrote: {
      accounts: number;
      edges: number;
      runs: number;
      reviews: number;
      relays: number;
      cleanup: number;
    };
    status?: unknown;
  }> => {
    const wrote = { accounts: 0, edges: 0, runs: 0, reviews: 0, relays: 0, cleanup: 0 };
    if (await ctx.runQuery(internal.edgeLocationsMigration.markerWritten, {}))
      return { result: 'already_done', wrote };
    if (!(await ctx.runQuery(internal.edgeLocationsMigration.hasLegacy, {}))) {
      await ctx.runMutation(internal.edgeLocationsMigration.markDone, {});
      return { result: 'nothing_to_migrate', wrote };
    }
    const phases: Array<[keyof typeof wrote, PhaseRef]> = [
      ['accounts', internal.edgeLocationsMigration.phaseLocations],
      ['edges', internal.edgeLocationsMigration.phaseEdges],
      ['runs', internal.edgeLocationsMigration.phaseRuns],
      ['reviews', internal.edgeLocationsMigration.phaseReviews],
      ['relays', internal.edgeLocationsMigration.phaseRelays],
      ['cleanup', internal.edgeLocationsMigration.phaseCleanup],
    ];
    for (const [key, fn] of phases) {
      let cursor: string | null = null;
      for (;;) {
        const r: {
          ok: boolean;
          code?: string;
          wrote: number;
          cursor: string | null;
          isDone: boolean;
        } = await ctx.runMutation(fn, { cursor });
        if (!r.ok) {
          const status = await ctx.runQuery(internal.edgeLocationsMigration.status, {});
          return {
            result: r.code === 'needs_freeze' ? 'needs_freeze' : 'not_quiescent',
            wrote,
            status,
          };
        }
        wrote[key] += r.wrote;
        if (r.isDone) break;
        cursor = r.cursor;
      }
    }
    const fin: { done: boolean; status: unknown } = await ctx.runMutation(
      internal.edgeLocationsMigration.finish,
      {
        wrote: {
          accounts: wrote.accounts,
          edges: wrote.edges,
          runs: wrote.runs,
          reviews: wrote.reviews,
          relays: wrote.relays,
        },
      },
    );
    return { result: fin.done ? 'done' : 'incomplete', wrote, status: fin.status };
  },
});
