/**
 * Which Globalping probes the newest name-check batch from a country asked
 * for, and what the free probe listing said about the country then
 * (lib/edges/probes/nameCheck.ts `planNameProbes`): one `appState` row per
 * country, written by `sniVantage.noteNamePool`, read by the country page to
 * say plainly when a country has too few probes for a verdict. Shown only
 * while it still describes how the checks run (`currentNamePool`).
 */
import type { DatabaseReader } from '../../../_generated/server';
import type { NamePool } from '../probes/nameCheck';

export const namePoolKey = (country: string) => `sniVantage:namePool:${country}`;

export interface NotedNamePool extends NamePool {
  at: number;
}

const MODES = new Set(['eyeball', 'topped_up', 'any']);
const count = (x: unknown) => (typeof x === 'number' && Number.isInteger(x) && x >= 0 ? x : null);

/** A stored row's value, or null when it is not one (never throws). */
export function parseNamePool(value: string): NotedNamePool | null {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(value) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!raw || typeof raw !== 'object' || !MODES.has(raw.mode as string)) return null;
  const at = typeof raw.at === 'number' && Number.isFinite(raw.at) ? raw.at : null;
  const eyeball = count(raw.eyeball);
  const total = count(raw.total);
  const limit = count(raw.limit);
  const needs = count(raw.needs);
  if (at === null || eyeball === null || total === null || limit === null || needs === null)
    return null;
  if (typeof raw.preferEyeball !== 'boolean') return null;
  return {
    at,
    mode: raw.mode as NamePool['mode'],
    eyeball,
    total,
    limit,
    needs,
    preferEyeball: raw.preferEyeball,
  };
}

export async function readNamePool(
  db: DatabaseReader,
  country: string,
): Promise<NotedNamePool | null> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', namePoolKey(country)))
    .unique();
  return row ? parseNamePool(row.value) : null;
}

/** A note counts this long at least, even with a short check interval. */
const MIN_FRESH_MS = 24 * 3_600_000;

/**
 * The note while it still describes the checks: Globalping is still a name
 * check source, the note is newer than two check intervals (a country with
 * names on a published address gets a batch at least once an interval), and
 * the limit, the floor and the home-network preference are what they were.
 * Otherwise null: the page says nothing rather than something stale.
 */
export function currentNamePool(
  note: NotedNamePool | null,
  now: {
    at: number;
    globalping: boolean;
    limit: number;
    needs: number;
    preferEyeball: boolean;
    intervalHours: number;
  },
): NotedNamePool | null {
  if (!note || !now.globalping) return null;
  if (now.at - note.at > Math.max(MIN_FRESH_MS, 2 * now.intervalHours * 3_600_000)) return null;
  if (note.limit !== Math.max(1, Math.min(now.limit, 10))) return null;
  if (note.needs !== now.needs || note.preferEyeball !== now.preferEyeball) return null;
  return note;
}
