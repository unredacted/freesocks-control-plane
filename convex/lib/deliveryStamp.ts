/**
 * What recording one fronted delivery writes (convex/subscriptions.ts
 * `markDelivered`), as a pure plan over the row. The mutation applies it to
 * the row it reads; the subscription route evaluates it first on the row its
 * delivery context read, and skips the mutation altogether when the plan
 * writes nothing (most polls: the stamp is throttled). One function, so the
 * two can never disagree on what is due.
 */
import type { Doc } from '../_generated/dataModel';

/** How often an unchanged delivery is stamped again. */
export const DELIVERY_STAMP_THROTTLE_MS = 60_000;

type Snapshot = NonNullable<Doc<'subscriptions'>['lastRender']>;
export type GivenSnapshot = Omit<Snapshot, 'at'>;

/** Every field of a render snapshot that says what the member was handed (not when). */
export function sameSnapshot(a: Omit<Snapshot, 'at'> | undefined, b: GivenSnapshot): boolean {
  return (
    !!a &&
    a.epoch === b.epoch &&
    a.family === b.family &&
    a.primaryEdgeId === b.primaryEdgeId &&
    a.backupEdgeId === b.backupEdgeId &&
    a.autoGroup === b.autoGroup &&
    a.primaryTwin === b.primaryTwin &&
    a.backupTwin === b.backupTwin &&
    a.twinNames === b.twinNames &&
    a.country === b.country &&
    a.primaryTier === b.primaryTier &&
    a.backupTier === b.backupTier &&
    a.listenerKeys.join(',') === b.listenerKeys.join(',')
  );
}

/**
 * Whether a write from a request that read the row at `rev` may still land: the
 * key has not moved in place since (`invalidateDelivery`). An absent `rev` (a
 * caller that read no row first) always may.
 */
export function revCurrent(sub: Doc<'subscriptions'>, rev: number | undefined): boolean {
  return rev === undefined || rev === (sub.deliveryRev ?? 0);
}

export interface DeliveryFacts {
  contentAt: number;
  renderedEpoch?: number | null;
  render?: GivenSnapshot | null;
  deliveryRev?: number;
  lane?: 'open' | 'trusted' | null;
}

export interface DeliveryPlan {
  /** The handed-out pair is new to the row: record its first exposure (convex/edgeTrust.ts). */
  noteExposures: boolean;
  /** The row patch, null when nothing is due. */
  patch: Partial<Doc<'subscriptions'>> | null;
}

/**
 * The plan for one delivery against `sub` at `now`.
 *  - `laneNow`: the account's address lane now; read only when `facts.lane` is
 *    given (undefined otherwise).
 *  - `storedCountry`: the row's stored country now; read only when the
 *    snapshot names a country on a row that is not deleted (`needsStoredCountry`).
 */
export function planDelivery(
  sub: Doc<'subscriptions'>,
  facts: DeliveryFacts,
  now: number,
  live: { laneNow?: 'open' | 'trusted' | null; storedCountry?: string | null },
): DeliveryPlan {
  const given = facts.render;
  // Whatever else is kept, the account WAS handed these addresses: their
  // first exposure is recorded (convex/edgeTrust.ts), stale revision, moved
  // lane or not. Only when the snapshot differs from the stored one, so a
  // poll that hands out the same pair writes nothing.
  const noteExposures = !!given && !sameSnapshot(sub.lastRender, given);
  const stale = now - (sub.lastDeliveredAt ?? 0) >= DELIVERY_STAMP_THROTTLE_MS;
  // A request that read the row before the key moved in place served what it
  // carried THEN: the delivery is recorded, never its content time, epoch or
  // snapshot (they describe a placement the key has left). The same for a
  // body rendered under an address lane the account no longer has (the
  // fence, convex/edgeLanes.ts).
  const laneMoved = facts.lane !== undefined && facts.lane !== live.laneNow;
  if (!revCurrent(sub, facts.deliveryRev) || laneMoved)
    return { noteExposures, patch: stale ? { lastDeliveredAt: now } : null };
  // The snapshot is a stored copy of the member's country: one that names
  // anything but the row's stored country NOW (a request that read an older
  // state, a switch or "Somewhere else" in between) keeps only its plain
  // delivery facts (convex/memberCountry.ts, the one invariant).
  let render = given ?? null;
  if (needsStoredCountry(sub, facts) && render && render.country !== live.storedCountry) {
    const { country, primaryTier, backupTier, ...plain } = render;
    void country;
    void primaryTier;
    void backupTier;
    render = plain;
  }
  if (sub.state === 'deleted') render = null;
  const contentAdvanced = (sub.lastDeliveredContentAt ?? 0) < facts.contentAt;
  const epochChanged =
    typeof facts.renderedEpoch === 'number' && facts.renderedEpoch !== sub.lastRenderedEpoch;
  // Any change in what the member was handed (the edges, the listeners, the
  // client family, the country or a tier) rewrites the snapshot, cache hit or not.
  const snapshotChanged = !!render && !sameSnapshot(sub.lastRender, render);
  // A rendered body was served (the evidence that this key's app no longer
  // holds a raw body: convex/edgeFrontKeys.ts), on the same throttle.
  const renderedDue = !!render && now - (sub.lastRenderedAt ?? 0) >= DELIVERY_STAMP_THROTTLE_MS;
  if (!contentAdvanced && !epochChanged && !snapshotChanged && !stale && !renderedDue)
    return { noteExposures, patch: null };
  return {
    noteExposures,
    patch: {
      lastDeliveredAt: now,
      lastDeliveredContentAt: Math.max(sub.lastDeliveredContentAt ?? 0, facts.contentAt),
      ...(epochChanged ? { lastRenderedEpoch: facts.renderedEpoch as number } : {}),
      ...(render && snapshotChanged ? { lastRender: { ...render, at: now } } : {}),
      ...(render ? { lastRenderedAt: now } : {}),
    },
  };
}

/** Whether the plan needs the row's stored country (it judges a snapshot's country). */
export function needsStoredCountry(sub: Doc<'subscriptions'>, facts: DeliveryFacts): boolean {
  return facts.render?.country !== undefined && sub.state !== 'deleted';
}

/** Nothing to record: the route need not call `markDelivered` at all. */
export function nothingDue(plan: DeliveryPlan): boolean {
  return !plan.noteExposures && plan.patch === null;
}
