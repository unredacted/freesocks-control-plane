/**
 * Dark members, counted (docs/edges.md § "Operations safety"): every refusal
 * the subscription route answers under edge-required delivery (the 503 with
 * `x-fcp-delivery: <reason>`) bumps a counter per reason. The route is hot,
 * so the counter is SHARDED: a refusal writes one of REFUSAL_SHARDS `appState`
 * rows (`edge:refusals:<n>`), picked at random, and concurrent refusals rarely
 * touch the same row. The route schedules the write instead of awaiting it, so
 * a burst (a fleet-wide gate close) never slows the 503s down; a write that
 * conflicts is retried by the scheduler. Each shard keeps ten-minute buckets
 * for the last hour; the attention list sums the shards (`delivery_refusals`).
 *
 * A row holds reason codes and counts only: never a token, a member, a node
 * or an address.
 */
import { v } from 'convex/values';
import { internalMutation } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { DELIVERY_UNAVAILABLE_CODES } from '../src/shared/contracts/edgeCodes';

export const REFUSAL_SHARDS = 8;
const BUCKET_MS = 10 * 60_000;
/** How far back the attention sum looks. */
export const REFUSAL_WINDOW_MS = 60 * 60_000;
/** Refusals in the window from which the attention item is critical (members are dark now). */
export const REFUSALS_CRITICAL_AT = 25;

const KNOWN = new Set<string>(DELIVERY_UNAVAILABLE_CODES);
const keyOf = (shard: number) => `edge:refusals:${shard}`;

interface Bucket {
  t: number;
  counts: Record<string, number>;
}
interface Shard {
  buckets: Bucket[];
}

/** A reason the counter keeps by name; anything else is `other` (the key set stays bounded). */
export function refusalReason(reason: string): string {
  return KNOWN.has(reason) ? reason : 'other';
}

/** Count one refusal (the subscription route schedules this; it never reaches the answer). */
export const record = internalMutation({
  args: { reason: v.string() },
  handler: async (ctx, { reason }) => {
    const now = Date.now();
    const shard = Math.floor(Math.random() * REFUSAL_SHARDS) % REFUSAL_SHARDS;
    const key = keyOf(shard);
    const cur = (await readStateJson<Shard>(ctx.db, key)) ?? { buckets: [] };
    const t = now - (now % BUCKET_MS);
    const buckets = (Array.isArray(cur.buckets) ? cur.buckets : []).filter(
      (b) => typeof b?.t === 'number' && b.t > now - REFUSAL_WINDOW_MS - BUCKET_MS,
    );
    let bucket = buckets.find((b) => b.t === t);
    if (!bucket) {
      bucket = { t, counts: {} };
      buckets.push(bucket);
    }
    const r = refusalReason(reason);
    bucket.counts[r] = (bucket.counts[r] ?? 0) + 1;
    await writeStateJson(ctx.db, key, { buckets });
    return null;
  },
});

/** Refusals in the last hour, by reason (sums every shard; small fixed read). */
export async function readRefusals(
  db: DatabaseReader,
  now: number,
): Promise<{ total: number; byReason: Record<string, number>; since: number | null }> {
  const byReason: Record<string, number> = {};
  let total = 0;
  let since: number | null = null;
  for (let i = 0; i < REFUSAL_SHARDS; i++) {
    const shard = await readStateJson<Shard>(db, keyOf(i));
    for (const b of shard?.buckets ?? []) {
      if (typeof b?.t !== 'number' || b.t + BUCKET_MS <= now - REFUSAL_WINDOW_MS) continue;
      for (const [reason, n] of Object.entries(b.counts ?? {})) {
        if (typeof n !== 'number' || n <= 0) continue;
        byReason[reason] = (byReason[reason] ?? 0) + n;
        total += n;
      }
      since = since === null ? b.t : Math.min(since, b.t);
    }
  }
  return { total, byReason, since };
}
