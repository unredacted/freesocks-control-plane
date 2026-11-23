/**
 * V8 entry points for crons whose real work runs in the Node runtime.
 *
 * A `"use node"` cron target starts a Node action on every tick, even when it
 * then finds nothing to do. These gates run in the default V8 runtime instead:
 * they read whether anything is due and schedule the Node action only then.
 * The same pattern as `keyEpochs.maybeRotate`.
 *
 * Heartbeats: an idle tick stamps the run (start + success) here
 * (`recordSkippedRun`). A tick with work leaves both stamps to the Node
 * action's own `runWithCronOutcome`, so the dashboard counts one run per tick
 * either way.
 *
 * The Node actions keep their own full checks: a gate that says "due" when the
 * action then finds nothing costs one Node run, never a wrong result.
 *
 * One run at a time: Convex never starts a cron target while its previous run
 * is still going, but here the target is the gate, which returns at once. So
 * each gate keeps the id of the run it scheduled (`appState`
 * `cron-gate:<name>`) and schedules no other while that one is pending or in
 * progress, the way the cron itself skipped a tick that overlapped a long run
 * (sni-qualify spaces its handshakes, so a big due list outlasts 5 minutes).
 */
import type { FunctionReference } from 'convex/server';
import { internalAction, internalMutation, type MutationCtx } from './_generated/server';
import { internal } from './_generated/api';
import { recordSkippedRun, runWithCronOutcome } from './cronHeartbeat';
import { hasDueQualification } from './sniFamilies';
import { hasDueRepair } from './mirrorUploads';
import { hasDueVerify } from './mirrorCopies';
import { MAX_LISTS } from './lib/edges/lists/facts';

type GateResult = { scheduled: boolean; running?: true };
type NodeCronAction = FunctionReference<'action', 'internal', Record<string, never>>;

const leaseKey = (name: string) => `cron-gate:${name}`;

/** Whether the run this gate last scheduled is still pending or in progress. */
async function previousRunActive(ctx: MutationCtx, name: string): Promise<boolean> {
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', leaseKey(name)))
    .unique();
  const jobId = row && ctx.db.system.normalizeId('_scheduled_functions', row.value);
  if (!jobId) return false;
  const job = await ctx.db.system.get(jobId);
  return !!job && (job.state.kind === 'pending' || job.state.kind === 'inProgress');
}

/** Schedule the Node run now and remember its id as the gate's lease. */
async function scheduleRun(ctx: MutationCtx, name: string, fn: NodeCronAction): Promise<void> {
  const jobId = await ctx.scheduler.runAfter(0, fn, {});
  const key = leaseKey(name);
  const row = await ctx.db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  const now = Date.now();
  if (row) await ctx.db.patch(row._id, { value: jobId, updatedAt: now });
  else await ctx.db.insert('appState', { key, value: jobId, updatedAt: now });
}

/**
 * The shared gate: skip the tick while the last scheduled run is still going
 * (no stamp, like a skipped cron tick); else schedule the run when `isDue`
 * says so, or stamp an idle run.
 */
async function gate(
  ctx: MutationCtx,
  name: string,
  fn: NodeCronAction,
  isDue: () => Promise<boolean>,
  onIdle?: () => Promise<void>,
): Promise<GateResult> {
  if (await previousRunActive(ctx, name)) return { scheduled: false, running: true };
  if (await isDue()) {
    await scheduleRun(ctx, name, fn);
    return { scheduled: true };
  }
  if (onIdle) await onIdle();
  await recordSkippedRun(ctx, name);
  return { scheduled: false };
}

/** `sni-qualify`: TLS checks of due names (sniQualifyOps.run, Node). */
export const sniQualify = internalMutation({
  args: {},
  handler: (ctx): Promise<GateResult> =>
    gate(
      ctx,
      'sni-qualify',
      internal.sniQualifyOps.run,
      () => hasDueQualification(ctx.db, Date.now()),
      // What `run` does on every tick, due names or not: FCP's own test of sends
      // still waiting on a node (sniAutoConfirm.ts; a no-op while it is off).
      async () => {
        await ctx.scheduler.runAfter(0, internal.sniAutoConfirm.sweep, {});
      },
    ),
});

/** `mirror-barrier-repair`: unfinished mirror uploads (storage.repairMirrorUploads, Node). */
export const mirrorBarrierRepair = internalMutation({
  args: {},
  handler: (ctx): Promise<GateResult> =>
    gate(ctx, 'mirror-barrier-repair', internal.storage.repairMirrorUploads, () =>
      hasDueRepair(ctx.db, Date.now()),
    ),
});

/** `mirror-verify`: read published mirror copies back (storage.verifyMirrorCopies, Node). */
export const mirrorVerify = internalMutation({
  args: {},
  handler: (ctx): Promise<GateResult> =>
    gate(ctx, 'mirror-verify', internal.storage.verifyMirrorCopies, () =>
      hasDueVerify(ctx.db, Date.now()),
    ),
});

/**
 * Lists started per cron pass: every one that is due (a pass only schedules
 * them; each read is its own action), so an hourly list is read every hour.
 */
const FETCH_PER_PASS = MAX_LISTS;

/**
 * `country-lists`: the hourly pass over the country lists. It only calls
 * queries and mutations (`requestFetch` schedules the Node fetch itself), so it
 * runs in V8. It used to live in the `"use node"` countryListOps.ts, which
 * started a Node action every hour for nothing.
 */
export const countryLists = internalAction({
  args: {},
  handler: async (ctx): Promise<void> =>
    runWithCronOutcome(ctx, 'country-lists', async () => {
      // Rows new since the last refresh (a sweep's finds, a family's new names) get their facts.
      await ctx.runMutation(internal.countryListFacts.kick, {});
      const due = await ctx.runQuery(internal.countryLists.dueForFetch, {
        now: Date.now(),
        limit: FETCH_PER_PASS,
      });
      for (const listId of due) {
        try {
          await ctx.runMutation(internal.countryLists.requestFetch, { listId });
        } catch {
          // Busy (an operator's fetch got there first): the next pass takes it.
        }
      }
      // New edges and new addresses since the last pass get checked against the watched lists.
      await ctx.runMutation(internal.countryListEdges.kick, {});
    }),
});
