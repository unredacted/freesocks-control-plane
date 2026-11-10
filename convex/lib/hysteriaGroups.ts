/**
 * The Hysteria groups a key was ever placed in, kept on its subscription
 * (`subscriptions.hysteriaGroups`). The revocation watch reads it
 * (convex/revocationWatches.ts): a Hysteria connection opened while the key was
 * in such a group outlives a disable, a delete and an in-place switch away
 * from the mode, so the key is watched by what it WAS issued into, never by the
 * current, operator-editable mode pools.
 */
import type { DatabaseReader } from '../_generated/server';
import type { BackendId } from './backends/types';
import { poolFromConfig } from './remnawavePlacement';
import { HYSTERIA_MODE_IDS } from '../../src/shared/hysteriaModes';

/** Whether a group is in a Hysteria mode's pool on this backend right now. */
export async function isHysteriaGroup(
  db: DatabaseReader,
  backend: BackendId,
  placement: string | null | undefined,
): Promise<boolean> {
  if (!placement) return false;
  for (const slug of HYSTERIA_MODE_IDS) {
    const row = await db
      .query('modePlacements')
      .withIndex('by_mode_backend', (q) => q.eq('modeSlug', slug).eq('backend', backend))
      .unique();
    if (row && poolFromConfig(row.config).includes(placement)) return true;
  }
  return false;
}

/** The sticky list after a key is placed in `placement` (undefined when it stays empty). */
export async function hysteriaGroupsAfter(
  db: DatabaseReader,
  backend: BackendId,
  prev: readonly string[] | undefined,
  placement: string | null | undefined,
): Promise<string[] | undefined> {
  const have = prev ?? [];
  if (!placement || have.includes(placement) || !(await isHysteriaGroup(db, backend, placement)))
    return have.length > 0 ? [...have] : undefined;
  return [...have, placement];
}
