/**
 * Saving what an action read about Globalping's allowance (its limits answers
 * and create headers, collected by `recordingClient`) into the account row the
 * Probes page shows (probes.ts `noteGlobalping`).
 */
import type { ActionCtx } from '../../../_generated/server';
import { internal } from '../../../_generated/api';
import type { TimedReading } from './globalping';

/** Hand the collected readings over and empty `readings`; never fails the action. */
export async function saveGlobalpingReadings(
  ctx: Pick<ActionCtx, 'runMutation'>,
  readings: TimedReading[],
): Promise<void> {
  if (readings.length === 0) return;
  const batch = readings.splice(0);
  try {
    await ctx.runMutation(internal.probes.noteGlobalping, { readings: batch });
  } catch {
    // The account view is a convenience: a lost reading is replaced by the next one.
  }
}
