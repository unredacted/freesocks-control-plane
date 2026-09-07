/**
 * Relay attribution for member issue reports: which origin (by the key's pinned
 * node) and — only when the member said which connection failed and that choice
 * maps to exactly one edge — which edge. Also the per-member-per-window dedupe
 * mark that turns a report into a 0/1 detector contribution. Everything here is
 * operator-infrastructure labelling; the telemetry row stays unlinked.
 */
import type { Doc } from './_generated/dataModel';
import type { DatabaseReader, DatabaseWriter } from './_generated/server';
import { resolveEdgeConfig, edgeMs } from './lib/edgeConfig';
import { assignEndpoints } from './lib/edges/assignment';
import { publishedEdgesOf } from './edgeRender';

export const CONNECTION_CHOICES = ['primary', 'backup', 'auto', 'direct', 'unsure'] as const;
export type ConnectionChoice = (typeof CONNECTION_CHOICES)[number];

export function sanitizeConnectionChoice(raw: unknown): ConnectionChoice | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();
  return (CONNECTION_CHOICES as readonly string[]).includes(s) ? (s as ConnectionChoice) : null;
}

export interface EdgeAttribution {
  relaySlug: string;
  relayEdgeId: string | null;
  refreshNotObserved: boolean;
}

/**
 * Resolve the origin behind the subscription's pinned node and, for an explicit
 * connection choice, the one edge it denotes under this subscriber's assignment.
 * `auto` resolves only when a single edge is published (nothing else to pick).
 */
export async function resolveEdgeAttribution(
  db: DatabaseReader,
  sub: Doc<'subscriptions'> | null,
  choice: ConnectionChoice | null,
  now: number,
): Promise<EdgeAttribution | null> {
  if (!sub || !sub.backendServerId || !sub.pinnedNode) return null;
  const origins = await db
    .query('relays')
    .withIndex('by_node_hostname', (q) => q.eq('nodeHostname', sub.pinnedNode!))
    .collect();
  const origin = origins.find((o) => o.backendServerId === sub.backendServerId);
  if (!origin) return null;
  const refreshNotObserved =
    origin.lastRotatedAt !== undefined && (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt;
  let relayEdgeId: string | null = null;
  if (choice && choice !== 'unsure' && choice !== 'direct') {
    const { published } = await publishedEdgesOf({ db }, origin);
    if (published.length === 1 && (choice === 'auto' || choice === 'primary')) {
      relayEdgeId = published[0].edgeId;
    } else if (
      published.length > 1 &&
      sub.renderKey &&
      (choice === 'primary' || choice === 'backup')
    ) {
      const cfg = await resolveEdgeConfig(db);
      const assigned = assignEndpoints(sub.renderKey, published, {
        now,
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        includeBackup: true,
        subscriberLastContentAt: sub.lastDeliveredContentAt ?? null,
      });
      const ep = choice === 'primary' ? assigned.primary : assigned.backup;
      relayEdgeId = ep?.edge.edgeId ?? null;
    }
  }
  return { relaySlug: origin.slug, relayEdgeId, refreshNotObserved };
}

/**
 * Insert-if-absent dedupe mark. `key` is a peppered HMAC computed in the HTTP
 * action (member id + window bucket); the row never carries the member id.
 * Returns 1 for the member's first contribution in the window, else 0.
 */
export async function claimReportMark(
  db: DatabaseWriter,
  key: string,
  now: number,
): Promise<0 | 1> {
  const existing = await db
    .query('relayReportMarks')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (existing && existing.expiresAt > now) return 0;
  const cfg = await resolveEdgeConfig(db);
  const expiresAt = now + edgeMs.detectWindow(cfg);
  if (existing) await db.patch(existing._id, { firstAt: now, expiresAt });
  else await db.insert('relayReportMarks', { key, firstAt: now, expiresAt });
  return 1;
}

/** Window bucket for the mark key: the same member reports once per detector window. */
export function markBucket(now: number, windowMs: number): number {
  return Math.floor(now / Math.max(1, windowMs));
}
