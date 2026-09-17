/**
 * One-shot reset of the Edges tables before the generic-relay schema lands
 * (clean break; see docs/edges.md § "Reset drain"). A guarded DRAIN, not a
 * delete:
 *
 *   1. `freeze` (edgeMaintenance.freeze): no new edge work is admitted; every
 *      completion path (rotation steps, rollback, cancel, unpublish, destroy,
 *      quarantine / needs_operator resolution, relay delete, credential
 *      removal) keeps running.
 *   2. `status` (read-only, ANY environment): what still has to settle before
 *      a wipe is safe. The operator finishes that work through the ordinary
 *      machine; the report must come back empty.
 *   3. `wipe` (allow-listed environments only, explicit confirm): REFUSES while
 *      anything in the status report remains, otherwise deletes the edge
 *      tables in bounded pages and turns the edge.* switches off.
 *   4. `thaw` (edgeMaintenance.thaw) after the new schema is deployed.
 *
 * Kept on purpose: probeTargets (operator data) and their custom rollups,
 * edgeProviderAccounts (credentials, qualification, inventory), edgeTemplates,
 * backendNodeInventory, relayReportMarks, auditLog, issueReports.
 *
 * The deploy entrypoint pushes the schema BEFORE any `convex run`, so this
 * module ships on its own (PR0), is run, and only then is the schema change
 * deployed.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { EDGE_KEYS } from './lib/edgeConfig';
import { readMaintenance } from './lib/edges/maintenance';
import { ROTATION_PHASES, isTerminalPhase } from './lib/edges/rotation';

/** Environments where a wipe may run. An allowlist: a missing or misspelled value refuses. */
const WIPE_ENVIRONMENTS: ReadonlySet<string> = new Set(['development', 'beta']);
const CONFIRM = 'wipe-edges';
const PAGE = 200;

export function wipeAllowedIn(environment: string | undefined): boolean {
  return environment !== undefined && WIPE_ENVIRONMENTS.has(environment);
}

export interface ResetStatus {
  frozen: boolean;
  rotationsOpen: Array<{ id: string; phase: string; relayId: string }>;
  edgesOpen: Array<{ id: string; status: string; relayId: string; reason: string }>;
  locksHeld: number;
  relaysQuarantined: string[];
  relaysDeleting: string[];
  relaysWithCredential: string[];
  relaysOwingRemovals: string[];
  /** Empty when a wipe would be safe. */
  blockers: string[];
}

async function computeStatus(ctx: QueryCtx): Promise<ResetStatus> {
  const m = await readMaintenance(ctx.db);
  const rotationsOpen: ResetStatus['rotationsOpen'] = [];
  for (const phase of ROTATION_PHASES) {
    if (isTerminalPhase(phase)) continue;
    const rows = await ctx.db
      .query('edgeRotations')
      .withIndex('by_phase', (q) => q.eq('phase', phase))
      .take(PAGE);
    for (const r of rows) rotationsOpen.push({ id: r._id, phase: r.phase, relayId: r.relayId });
  }
  // Every managed edge must be `destroyed` (its provider resources confirmed
  // gone). Observe-only edges (`managed:false`) hold nothing at a provider.
  const edgesOpen: ResetStatus['edgesOpen'] = [];
  const live = await ctx.runQuery(internal.edges.listLive, {});
  for (const e of live) {
    if (!e.managed) continue;
    const reason = e.currentOp
      ? 'open operation'
      : e.status === 'needs_operator'
        ? 'needs operator'
        : e.resources.some((r) => r.deleteState !== 'confirmed_gone')
          ? 'provider resources present'
          : 'not destroyed';
    edgesOpen.push({ id: e._id, status: e.status, relayId: e.relayId, reason });
  }
  const locks = await ctx.db.query('externalLocks').take(PAGE);
  const relays = await ctx.db.query('relays').collect(); // small operator table
  const relaysQuarantined = relays.filter((r) => r.quarantine).map((r) => r.slug);
  const relaysDeleting = relays.filter((r) => r.deleting).map((r) => r.slug);
  const relaysWithCredential = relays.filter((r) => r.qualificationUserId).map((r) => r.slug);
  const relaysOwingRemovals = relays
    .filter((r) => (r.qualificationRemovalPending?.length ?? 0) > 0)
    .map((r) => r.slug);
  const blockers: string[] = [];
  if (!m.frozen) blockers.push('not frozen: run edgeMaintenance:freeze first');
  if (rotationsOpen.length) blockers.push(`${rotationsOpen.length} rotation(s) not terminal`);
  if (edgesOpen.length) blockers.push(`${edgesOpen.length} managed edge(s) not destroyed`);
  if (locks.length) blockers.push(`${locks.length} external lock(s) held`);
  if (relaysQuarantined.length) blockers.push(`quarantined: ${relaysQuarantined.join(', ')}`);
  if (relaysDeleting.length) blockers.push(`delete in progress: ${relaysDeleting.join(', ')}`);
  if (relaysWithCredential.length)
    blockers.push(
      `qualification credential still active (revoke it first): ${relaysWithCredential.join(', ')}`,
    );
  if (relaysOwingRemovals.length)
    blockers.push(`credential removal still owed: ${relaysOwingRemovals.join(', ')}`);
  return {
    frozen: m.frozen,
    rotationsOpen,
    edgesOpen,
    locksHeld: locks.length,
    relaysQuarantined,
    relaysDeleting,
    relaysWithCredential,
    relaysOwingRemovals,
    blockers,
  };
}

/** Read-only; admitted in every environment (production included). */
export const status = internalQuery({
  args: {},
  handler: (ctx) => computeStatus(ctx),
});

const WIPE_TABLES = [
  'edgeRotations',
  'edges',
  'relaySlots',
  'protocolProfiles',
  'relays',
  'externalLocks',
  'relaySamples',
] as const;
type WipeTable = (typeof WIPE_TABLES)[number];

async function deletePage(ctx: MutationCtx, table: WipeTable): Promise<number> {
  const rows = await ctx.db.query(table).take(PAGE);
  for (const r of rows) await ctx.db.delete(r._id);
  return rows.length;
}

async function deleteProbePage(
  ctx: MutationCtx,
  table: 'probeRuns' | 'probeReachability',
  kind: 'edge' | 'relay',
): Promise<number> {
  const rows =
    table === 'probeRuns'
      ? await ctx.db
          .query('probeRuns')
          .withIndex('by_target_requested', (q) => q.eq('targetKind', kind))
          .take(PAGE)
      : await ctx.db
          .query('probeReachability')
          .withIndex('by_target_country', (q) => q.eq('targetKind', kind))
          .take(PAGE);
  for (const r of rows) await ctx.db.delete(r._id);
  return rows.length;
}

/** One bounded page of deletes; the action loops until every page is empty. */
export const wipeBatch = internalMutation({
  args: {
    table: v.union(
      ...WIPE_TABLES.map((t) => v.literal(t)),
      v.literal('probeRuns'),
      v.literal('probeReachability'),
    ),
    kind: v.optional(v.union(v.literal('edge'), v.literal('relay'))),
  },
  handler: async (ctx, { table, kind }) => {
    if (table === 'probeRuns' || table === 'probeReachability') {
      if (!kind) throw new ConvexError({ code: 'validation', message: 'kind required' });
      return { deleted: await deleteProbePage(ctx, table, kind) };
    }
    return { deleted: await deletePage(ctx, table) };
  },
});

/** Turn every enabling switch off so the new model comes up dormant. */
export const disableSwitches = internalMutation({
  args: {},
  handler: async (ctx) => {
    const keys = [
      EDGE_KEYS.enabled,
      EDGE_KEYS.autoRotate,
      EDGE_KEYS.autoProvisionToDesired,
      'edge.render.enabled',
      'edge.probe.enabled',
      'edge.l7.autoSelect',
    ];
    for (const key of keys) await upsertSettingRow(ctx, key, 'false');
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'admin.edge.config.change',
      targetType: 'app_settings',
      payload: { changedKeys: keys },
    });
  },
});

export const wipe = internalAction({
  args: { confirm: v.string() },
  handler: async (ctx, { confirm }) => {
    if (confirm !== CONFIRM)
      throw new ConvexError({
        code: 'validation',
        message: `pass {"confirm":"${CONFIRM}"} to wipe the edge tables`,
      });
    if (!wipeAllowedIn(process.env.ENVIRONMENT))
      throw new ConvexError({
        code: 'forbidden',
        message: `edge wipe is allowed only where ENVIRONMENT is one of ${[...WIPE_ENVIRONMENTS].join(', ')}`,
      });
    const before = await ctx.runQuery(internal.seedEdgesReset.status, {});
    if (before.blockers.length > 0)
      throw new ConvexError({
        code: 'edge.reset_blocked',
        message: `not safe to wipe: ${before.blockers.join('; ')}`,
      });
    const deleted: Record<string, number> = {};
    for (const table of WIPE_TABLES) {
      let n = 0;
      for (;;) {
        const r = await ctx.runMutation(internal.seedEdgesReset.wipeBatch, { table });
        n += r.deleted;
        if (r.deleted < PAGE) break;
      }
      deleted[table] = n;
    }
    for (const table of ['probeRuns', 'probeReachability'] as const) {
      let n = 0;
      for (const kind of ['edge', 'relay'] as const) {
        for (;;) {
          const r = await ctx.runMutation(internal.seedEdgesReset.wipeBatch, { table, kind });
          n += r.deleted;
          if (r.deleted < PAGE) break;
        }
      }
      deleted[table] = n;
    }
    await ctx.runMutation(internal.seedEdgesReset.disableSwitches, {});
    await ctx.runMutation(internal.seedEdgesReset.recordWipe, { deleted });
    return { deleted };
  },
});

export const recordWipe = internalMutation({
  args: { deleted: v.record(v.string(), v.number()) },
  handler: async (ctx, { deleted }) => {
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'admin.edge.reset',
      targetType: 'app_state',
      payload: { phase: 'wipe', deleted: Object.values(deleted).reduce((a, b) => a + b, 0) },
    });
  },
});
