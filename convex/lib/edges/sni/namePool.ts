/**
 * How the newest name-check batch from a country found its Globalping probes
 * (lib/edges/probes/nameCheck.ts `createFirstNameMeasurement`): one `appState`
 * row per country, written by `sniVantage.noteNamePool`, read by the country
 * page to say plainly when a country has too few probes for a verdict.
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
  const got = count(raw.got);
  const limit = count(raw.limit);
  const needs = count(raw.needs);
  const eyeball = count(raw.eyeball);
  if (at === null || got === null || limit === null || needs === null) return null;
  return {
    at,
    mode: raw.mode as NamePool['mode'],
    ...(eyeball !== null ? { eyeball } : {}),
    got,
    limit,
    needs,
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
