/**
 * Origin attribution for member issue reports: which origin (by the key's pinned
 * node) and — only when the member said which connection failed and that choice
 * maps to exactly one edge — which edge. Also the per-member-per-window dedupe
 * mark that turns a report into a 0/1 detector contribution. Everything here is
 * operator-infrastructure labelling; the telemetry row stays unlinked.
 */
import type { Doc } from './_generated/dataModel';
import { resolveEdgeConfig, edgeMs } from './lib/edgeConfig';
import type { DatabaseReader, DatabaseWriter } from './_generated/server';
import { relayForBackendNode } from './relays';

export const CONNECTION_CHOICES = ['primary', 'backup', 'auto', 'direct', 'unsure'] as const;
export type ConnectionChoice = (typeof CONNECTION_CHOICES)[number];

export function sanitizeConnectionChoice(raw: unknown): ConnectionChoice | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();
  return (CONNECTION_CHOICES as readonly string[]).includes(s) ? (s as ConnectionChoice) : null;
}

/** Which of an address's two entries the member used, where their body carried both. */
export const CONNECTION_ENTRIES = ['encrypted', 'plain'] as const;
export type ConnectionEntry = (typeof CONNECTION_ENTRIES)[number];

export function sanitizeConnectionEntry(raw: unknown): ConnectionEntry | null {
  if (typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();
  return (CONNECTION_ENTRIES as readonly string[]).includes(s) ? (s as ConnectionEntry) : null;
}

/**
 * Whether a report of one address names its EDGE, given how the member's body
 * handed that address out (`lastRender.<role>Twin`, docs/backends.md "VLESS
 * Encryption"):
 *  - the plain entry alone (no twin): yes, as ever;
 *  - encrypted first with the plain one behind it (`fallback`, the rule for an
 *    app family nobody has proven speaks the layer): only when the member says
 *    the PLAIN entry failed. An old app fails on the encrypted entry whatever
 *    the address does, so such a report says nothing about the address, and it
 *    would otherwise read as a block and replace a healthy one. A report that
 *    does not say which entry (an older page) is the same uncertainty;
 *  - encrypted alone (`only`, the rule an operator gives a family known to
 *    speak it): yes. There is no other entry to mistake it for.
 */
export function entryNamesEdge(
  twin: 'fallback' | 'only' | undefined,
  entry: ConnectionEntry | null,
): boolean {
  return twin !== 'fallback' || entry === 'plain';
}

export interface EdgeAttribution {
  relaySlug: string;
  relayEdgeId: string | null;
  refreshNotObserved: boolean;
}

/**
 * Resolve the origin behind the subscription (its pinned node, or the whole
 * backend server for an unpinned key such as Outline) and, for an explicit
 * connection choice, the edge that choice denotes.
 *
 * The edge comes ONLY from the persisted render snapshot
 * (`subscriptions.lastRender`: what this subscriber was actually handed). An
 * assignment is never recomputed here: with several listeners a body may
 * resolve only some of them, so a recomputation over the origin-wide pool could
 * name an edge the member never received and feed the detector false evidence.
 * No snapshot, or one from an older epoch, leaves the report at origin level.
 */
export async function resolveEdgeAttribution(
  db: DatabaseReader,
  sub: Doc<'subscriptions'> | null,
  choice: ConnectionChoice | null,
  _now: number,
  /** Which of the address's two entries, where the body carried both (`entryNamesEdge`). */
  entry: ConnectionEntry | null = null,
): Promise<EdgeAttribution | null> {
  if (!sub || !sub.backendServerId) return null;
  const origin = await relayForBackendNode(db, sub.backendServerId, sub.pinnedNode ?? undefined);
  if (!origin) return null;
  // The publication epoch the key's content was last rendered against vs the
  // origin's current one: catches EVERY pool change (publish, unpublish,
  // adoption), not only rotations. Keys never rendered fall back to the
  // delivery-time vs last-rotation comparison.
  const renderedEpoch = sub.lastRender?.epoch ?? sub.lastRenderedEpoch;
  const refreshNotObserved =
    renderedEpoch !== undefined
      ? renderedEpoch < origin.publicationEpoch
      : origin.lastRotatedAt !== undefined &&
        (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt;
  let relayEdgeId: string | null = null;
  const snap = sub.lastRender;
  // A member who has not fetched since the pool last changed is still on the
  // OLD pool: their snapshot names edges of that epoch, and a report about a
  // drained edge must not land on its healthy replacement.
  if (choice && snap && snap.epoch === origin.publicationEpoch && !refreshNotObserved) {
    if (choice === 'primary' && entryNamesEdge(snap.primaryTwin, entry))
      relayEdgeId = snap.primaryEdgeId ?? null;
    else if (choice === 'backup' && entryNamesEdge(snap.backupTwin, entry))
      relayEdgeId = snap.backupEdgeId ?? null;
    // `auto` denotes one edge only when nothing else was handed out: not a
    // second address, and not a second entry of the one address.
    else if (choice === 'auto' && !snap.backupEdgeId && entryNamesEdge(snap.primaryTwin, entry))
      relayEdgeId = snap.primaryEdgeId ?? null;
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
