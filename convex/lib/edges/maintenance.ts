/**
 * Edge maintenance gate: separates ADMISSION of new work from COMPLETION of
 * work already in flight.
 *
 * While frozen, nothing new is admitted (a rotation start of any kind, an origin
 * or slot registration, an edge import, a direct publish, provider account /
 * template / profile writes, probe requests, detector evaluation, reconcile
 * pool upkeep). Everything that finishes or unwinds existing work stays
 * admitted and keeps its own fencing: rotation steps and re-kicks past
 * `select`, rollback, cancel, unpublish, destroy runs and their confirmation,
 * quarantine / needs_operator resolution, origin delete finalisation, and the
 * qualification-credential removal retry. Deleting ledger rows under a live
 * external operation would strand provider resources, so the reset drain
 * (`convex/seedEdgesReset.ts`) freezes first, waits for the completion paths to
 * settle, and only then wipes.
 *
 * Stored as ONE `appState` row (`edge:maintenance`), read inside the
 * transaction that admits work, so a freeze is observed by every subsequent
 * mutation without a cache.
 */
import { ConvexError } from 'convex/values';
import type { DatabaseReader, DatabaseWriter } from '../../_generated/server';

export const MAINTENANCE_KEY = 'edge:maintenance';

export type AdmissionKind =
  | 'rotation.start'
  | 'registration'
  | 'adopt'
  | 'publish'
  | 'provider.write'
  | 'template.write'
  | 'profile.write'
  | 'probe.request'
  | 'detector'
  | 'upkeep'
  // A guided setup run finishing work it was admitted for BEFORE the freeze
  // (its publish rotations at stage 5): completion, not new work. Only a
  // rotation start carrying `setupRun` may name this kind (edgeRotations.ts).
  | 'setup.complete';

/** Kinds that are completion of admitted work: never refused by a freeze. */
export const COMPLETION_KINDS: ReadonlySet<AdmissionKind> = new Set<AdmissionKind>([
  'setup.complete',
]);

export interface MaintenanceState {
  frozen: boolean;
  since: number | null;
  reason: string | null;
}

export const MAINTENANCE_CLEAR: MaintenanceState = { frozen: false, since: null, reason: null };

export function parseMaintenance(raw: string | null | undefined): MaintenanceState {
  if (!raw) return MAINTENANCE_CLEAR;
  try {
    const v = JSON.parse(raw) as Partial<MaintenanceState>;
    return {
      frozen: v.frozen === true,
      since: typeof v.since === 'number' ? v.since : null,
      reason: typeof v.reason === 'string' ? v.reason.slice(0, 200) : null,
    };
  } catch {
    return MAINTENANCE_CLEAR;
  }
}

export async function readMaintenance(db: DatabaseReader): Promise<MaintenanceState> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', MAINTENANCE_KEY))
    .unique();
  return parseMaintenance(row?.value);
}

export async function writeMaintenance(
  db: DatabaseWriter,
  next: MaintenanceState,
): Promise<MaintenanceState> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', MAINTENANCE_KEY))
    .unique();
  const value = JSON.stringify(next);
  const now = Date.now();
  if (row) await db.patch(row._id, { value, updatedAt: now });
  else await db.insert('appState', { key: MAINTENANCE_KEY, value, updatedAt: now });
  return next;
}

/**
 * Refuse new work while frozen. Callers are the ADMISSION entry points only;
 * a completion path must never route through here.
 */
export async function assertAdmission(db: DatabaseReader, kind: AdmissionKind): Promise<void> {
  const m = await readMaintenance(db);
  if (!m.frozen) return;
  if (COMPLETION_KINDS.has(kind)) return;
  throw new ConvexError({
    code: 'edge.maintenance',
    message: `Edges are in maintenance (${kind} is not admitted)${m.reason ? `: ${m.reason}` : ''}`,
  });
}

/** Non-throwing variant for cron paths that skip instead of failing. */
export async function admitted(db: DatabaseReader): Promise<boolean> {
  return !(await readMaintenance(db)).frozen;
}
