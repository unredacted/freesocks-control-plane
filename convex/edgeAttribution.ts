/**
 * Relay attribution for member issue reports: which origin (by the key's pinned
 * node) and — only when the member said which connection failed and that choice
 * maps to exactly one edge — which edge. Also the per-member-per-window dedupe
 * mark that turns a report into a 0/1 detector contribution. Everything here is
 * operator-infrastructure labelling; the telemetry row stays unlinked.
 */
import type { Doc } from './_generated/dataModel';
import type { DatabaseReader, DatabaseWriter } from './_generated/server';
import { resolveEdgeConfig, edgeMs, RENDER_CLIENT_FAMILIES } from './lib/edgeConfig';
import { assignEndpoints } from './lib/edges/assignment';
import { CLIENT_FAMILY_FORMATS } from './lib/edges/clientFamilies';
import { effectiveRule, formatHasAutoGroup, ruleCanEmitV6 } from './lib/edges/render';
import { publishedEdgesOf } from './edgeRender';
import { relayForBackendNode } from './relays';

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
 * `auto` resolves only when a single edge is published (nothing else to pick),
 * and an assignment over a larger pool only when every enabled client family's
 * render rule picks the same edge (the family the member used is unknown).
 */
export async function resolveEdgeAttribution(
  db: DatabaseReader,
  sub: Doc<'subscriptions'> | null,
  choice: ConnectionChoice | null,
  now: number,
): Promise<EdgeAttribution | null> {
  if (!sub || !sub.backendServerId || !sub.pinnedNode) return null;
  const origin = await relayForBackendNode(db, sub.backendServerId, sub.pinnedNode);
  if (!origin) return null;
  // Preferred: the publication epoch the key's content was last rendered
  // against (`subscriptions.lastRenderedEpoch`, stamped by the renderer) vs
  // the relay's current one — this catches EVERY pool change (publish,
  // unpublish, adoption), not only rotations. Keys never rendered since the
  // field exists fall back to the delivery-time vs last-rotation comparison.
  const lastRenderedEpoch = sub.lastRenderedEpoch;
  const refreshNotObserved =
    lastRenderedEpoch !== undefined
      ? lastRenderedEpoch < origin.publicationEpoch
      : origin.lastRotatedAt !== undefined &&
        (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt;
  let relayEdgeId: string | null = null;
  // A member who has not fetched content since the pool last changed is still
  // on the OLD pool: recomputing their assignment from the current pool would
  // pin a report about the drained edge onto its healthy replacement. No edge
  // attribution in that state (the report still counts at origin level).
  if (choice && choice !== 'unsure' && choice !== 'direct' && !refreshNotObserved) {
    // The SAME pool view the renderer used (ineligible edges kept, flagged) so
    // the recomputed primary/backup is the one the member actually received;
    // a compressed pool would shift the modulus onto a different, healthy edge.
    const { published } = await publishedEdgesOf({ db }, origin, { includeIneligible: true });
    if (
      published.length === 1 &&
      published[0].eligible !== false &&
      (choice === 'auto' || choice === 'primary')
    ) {
      relayEdgeId = published[0].edgeId;
    } else if (
      published.length > 1 &&
      sub.renderKey &&
      (choice === 'primary' || choice === 'backup')
    ) {
      const cfg = await resolveEdgeConfig(db);
      // The member's client family is not recorded with the report, and the
      // assignment depends on it: a family whose rule cannot emit IPv6 skips a
      // v6-only edge, so the same key lands on a different edge per family.
      // Attribute only when EVERY enabled family agrees on the edge behind the
      // chosen connection; a disagreement (or no enabled family at all, i.e.
      // the member's body was never rendered) leaves the report at origin level.
      const picked = new Set<string | null>();
      for (const family of RENDER_CLIENT_FAMILIES) {
        const rule = effectiveRule(cfg.render, cfg.render.clients[family]);
        if (!rule.enabled) continue;
        const canEmitV6 = ruleCanEmitV6(
          rule,
          formatHasAutoGroup(rule, CLIENT_FAMILY_FORMATS[family]),
        );
        const assigned = assignEndpoints(sub.renderKey, published, {
          now,
          preferDistinctProviders: cfg.render.preferDistinctProviders,
          // Which edge the choice DENOTES, not whether this family renders it:
          // a family that omits the backup is one the member cannot have been
          // reporting a backup from.
          includeBackup: true,
          canEmitV6,
        });
        const ep = choice === 'primary' ? assigned.primary : assigned.backup;
        picked.add(ep?.edge.edgeId ?? null);
      }
      relayEdgeId = picked.size === 1 ? [...picked][0] : null;
    }
  }
  return { relaySlug: origin.slug, relayEdgeId, refreshNotObserved };
}

/**
 * Insert-if-absent dedupe mark. `key` is a peppered, TIME-INDEPENDENT HMAC of
 * the member id computed in the HTTP action; the row never carries the member
 * id. The window slides from the member's first report (`expiresAt` = first
 * report + detector window), matching the detector's own sliding window, so a
 * report either side of a clock-aligned boundary cannot count twice.
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
