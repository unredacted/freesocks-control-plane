/**
 * Pool strip slot computation (pure; PoolStrip.svelte renders the result).
 *
 * A relay's published pool is an index-addressed array with holes
 * (`RelayAdmin.publishedEdgeIds`: `string | null` per pool index) and a wanted
 * size (`desiredPublished`). The strip shows, in order: every pool index up to
 * the larger of the two, then the standbys, then the draining edges.
 *
 * Exports: poolSlots(input) -> PoolSlot[], poolSummary(input) -> string, PoolSlot, PoolInput.
 */
export type PoolSlotKind = 'published' | 'missing' | 'vacant' | 'standby' | 'draining';

export interface PoolSlot {
  kind: PoolSlotKind;
  /** Pool index for published / missing / vacant slots, null for standbys and draining. */
  poolIndex: number | null;
  edgeId: string | null;
  /** True for a published slot beyond the desired size (the pool is larger than wanted). */
  surplus: boolean;
}

export interface PoolInput {
  publishedEdgeIds: ReadonlyArray<string | null>;
  desired: number;
  /** Standby edge ids when known, else a count. */
  standbys?: ReadonlyArray<string> | number;
  draining?: number;
}

const MAX_SLOTS = 24;

function clampCount(n: number | undefined): number {
  if (n === undefined || !Number.isFinite(n) || n < 0) return 0;
  return Math.min(MAX_SLOTS, Math.floor(n));
}

export function poolSlots(input: PoolInput): PoolSlot[] {
  const desired = clampCount(input.desired);
  const ids = input.publishedEdgeIds.slice(0, MAX_SLOTS);
  const width = Math.max(desired, ids.length);
  const slots: PoolSlot[] = [];
  for (let i = 0; i < width; i++) {
    const edgeId = ids[i] ?? null;
    if (edgeId) slots.push({ kind: 'published', poolIndex: i, edgeId, surplus: i >= desired });
    else if (i < desired)
      slots.push({ kind: 'missing', poolIndex: i, edgeId: null, surplus: false });
    else slots.push({ kind: 'vacant', poolIndex: i, edgeId: null, surplus: false });
  }
  // Trailing vacant slots say nothing (a hole past the desired size with nothing after it).
  while (slots.length > 0 && slots[slots.length - 1]!.kind === 'vacant') slots.pop();

  const standbys = input.standbys;
  if (Array.isArray(standbys)) {
    for (const edgeId of standbys.slice(0, MAX_SLOTS)) {
      slots.push({ kind: 'standby', poolIndex: null, edgeId, surplus: false });
    }
  } else {
    for (let i = 0; i < clampCount(standbys as number | undefined); i++) {
      slots.push({ kind: 'standby', poolIndex: null, edgeId: null, surplus: false });
    }
  }
  for (let i = 0; i < clampCount(input.draining); i++) {
    slots.push({ kind: 'draining', poolIndex: null, edgeId: null, surplus: false });
  }
  return slots;
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** "2 of 3 published, 1 standby, 1 draining" (the strip's accessible name and caption). */
export function poolSummary(input: PoolInput): string {
  const published = input.publishedEdgeIds.filter((id) => !!id).length;
  const standbys = Array.isArray(input.standbys)
    ? input.standbys.length
    : clampCount(input.standbys as number | undefined);
  const draining = clampCount(input.draining);
  const parts = [`${published} of ${clampCount(input.desired)} published`];
  if (standbys > 0) parts.push(plural(standbys, 'standby', 'standbys'));
  if (draining > 0) parts.push(`${draining} draining`);
  return parts.join(', ');
}
