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
 * A row holds reason codes and counts, and per reason which node the body
 * resolved to and which client family asked (`detail`), so the operator can
 * tell where members are dark: never a token, a member or an address. The
 * detail keys are bounded per bucket (`DETAIL_KEYS_MAX`).
 */
import { v } from 'convex/values';
import { internalMutation } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import { readStateJson, writeStateJson } from './lib/appStateJson';
import { isRenderClientFamily } from './lib/edgeConfig';
import { DELIVERY_UNAVAILABLE_CODES } from '../src/shared/contracts/edgeCodes';

export const REFUSAL_SHARDS = 8;
const BUCKET_MS = 10 * 60_000;
/** How far back the attention sum looks. */
export const REFUSAL_WINDOW_MS = 60 * 60_000;
/** Refusals in the window from which the attention item is critical (members are dark now). */
export const REFUSALS_CRITICAL_AT = 25;
/**
 * Refusals no edge would change: the member's app got no connection from the
 * backend at all (`no_entries`, an app that cannot speak the node's protocol).
 * Counted and shown, but never what grades the attention item.
 */
export const APP_REFUSALS: ReadonlySet<string> = new Set(['no_entries']);

const KNOWN = new Set<string>(DELIVERY_UNAVAILABLE_CODES);
const keyOf = (shard: number) => `edge:refusals:${shard}`;

interface Bucket {
  t: number;
  counts: Record<string, number>;
  /** `reason|node|family` -> count (`detailKey`); absent on a bucket from before it. */
  detail?: Record<string, number>;
}

/** Distinct reason/node/family keys one bucket keeps; past it a refusal counts under its reason alone. */
export const DETAIL_KEYS_MAX = 100;
/** The breakdown the attention item shows. */
export const TOP_SOURCES = 3;

/** One key of the breakdown: a node is a fleet name (`-` none), a family one of the render families. */
export function detailKey(reason: string, node?: string | null, family?: string | null): string {
  const n = node && node.length > 0 ? node.slice(0, 64).replace(/\|/g, '') : '-';
  const f = isRenderClientFamily(family) ? family : 'other';
  return `${reason}|${n}|${f}`;
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
  args: {
    reason: v.string(),
    /** The node the body resolved to (else the stored pin), when one is known. */
    node: v.optional(v.string()),
    /** The client family that asked (lib/edges/clientFamilies.ts). */
    family: v.optional(v.string()),
  },
  handler: async (ctx, { reason, node, family }) => {
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
    const detail = (bucket.detail ??= {});
    const k = detailKey(r, node, family);
    if (k in detail || Object.keys(detail).length < DETAIL_KEYS_MAX)
      detail[k] = (detail[k] ?? 0) + 1;
    await writeStateJson(ctx.db, key, { buckets });
    return null;
  },
});

export interface RefusalSource {
  reason: string;
  /** The node the body resolved to, or null when none was known. */
  node: string | null;
  family: string;
  count: number;
}

/**
 * Refusals in the last hour, by reason, and the reason/node/family pairs with
 * the most of them (`top`, at most TOP_SOURCES). Sums every shard; small fixed read.
 */
export async function readRefusals(
  db: DatabaseReader,
  now: number,
): Promise<{
  total: number;
  byReason: Record<string, number>;
  top: RefusalSource[];
  since: number | null;
}> {
  const byReason: Record<string, number> = {};
  const detail: Record<string, number> = {};
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
      for (const [k, n] of Object.entries(b.detail ?? {}))
        if (typeof n === 'number' && n > 0) detail[k] = (detail[k] ?? 0) + n;
      since = since === null ? b.t : Math.min(since, b.t);
    }
  }
  const top = Object.entries(detail)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, TOP_SOURCES)
    .map(([k, count]) => {
      const [reason = 'other', node = '-', family = 'other'] = k.split('|');
      return { reason, node: node === '-' ? null : node, family, count };
    });
  return { total, byReason, top, since };
}
