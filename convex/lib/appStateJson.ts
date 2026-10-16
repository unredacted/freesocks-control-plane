/**
 * One JSON value per `appState` key: read (null when absent or unparseable)
 * and upsert. For small operator state (a brake, a dedupe set, a counter
 * shard); never for anything that grows with traffic.
 */
import type { DatabaseReader, DatabaseWriter } from '../_generated/server';

export async function readStateJson<T>(db: DatabaseReader, key: string): Promise<T | null> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  if (!row) return null;
  try {
    return JSON.parse(row.value) as T;
  } catch {
    return null;
  }
}

export async function writeStateJson(db: DatabaseWriter, key: string, value: unknown) {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', key))
    .unique();
  const now = Date.now();
  const json = JSON.stringify(value);
  if (row) await db.patch(row._id, { value: json, updatedAt: now });
  else await db.insert('appState', { key, value: json, updatedAt: now });
}
