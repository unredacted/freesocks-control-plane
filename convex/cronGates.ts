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
 */
import { internalAction, internalMutation } from './_generated/server';
import { internal } from './_generated/api';
import { recordSkippedRun, runWithCronOutcome } from './cronHeartbeat';
import { hasDueQualification } from './sniFamilies';
import { hasDueRepair } from './mirrorUploads';
import { hasDueVerify } from './mirrorCopies';
import { MAX_LISTS } from './lib/edges/lists/facts';

/** `sni-qualify`: TLS checks of due names (sniQualifyOps.run, Node). */
export const sniQualify = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ scheduled: boolean }> => {
    if (await hasDueQualification(ctx.db, Date.now())) {
      await ctx.scheduler.runAfter(0, internal.sniQualifyOps.run, {});
      return { scheduled: true };
    }
    // What `run` does on every tick, due names or not: FCP's own test of sends
    // still waiting on a node (sniAutoConfirm.ts; a no-op while it is off).
    await ctx.scheduler.runAfter(0, internal.sniAutoConfirm.sweep, {});
    await recordSkippedRun(ctx, 'sni-qualify');
    return { scheduled: false };
  },
});

/** `mirror-barrier-repair`: unfinished mirror uploads (storage.repairMirrorUploads, Node). */
export const mirrorBarrierRepair = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ scheduled: boolean }> => {
    if (await hasDueRepair(ctx.db, Date.now())) {
      await ctx.scheduler.runAfter(0, internal.storage.repairMirrorUploads, {});
      return { scheduled: true };
    }
    await recordSkippedRun(ctx, 'mirror-barrier-repair');
    return { scheduled: false };
  },
});

/** `mirror-verify`: read published mirror copies back (storage.verifyMirrorCopies, Node). */
export const mirrorVerify = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ scheduled: boolean }> => {
    if (await hasDueVerify(ctx.db, Date.now())) {
      await ctx.scheduler.runAfter(0, internal.storage.verifyMirrorCopies, {});
      return { scheduled: true };
    }
    await recordSkippedRun(ctx, 'mirror-verify');
    return { scheduled: false };
  },
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
