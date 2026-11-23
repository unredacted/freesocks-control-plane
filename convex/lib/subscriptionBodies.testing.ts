/**
 * Test helpers for the per-UA body cache (lib/subscriptionBodies.ts): the
 * cached entries of a key as one JSON array, newest first (the shape the old
 * `subscriptions.subCache` blob had), and the way back. Not a Convex entry
 * point (a multi-dot name), and imported by tests only.
 */
import type { DatabaseReader, DatabaseWriter } from '../_generated/server';
import type { Id } from '../_generated/dataModel';
import { bodyRowsOf, parseEntry } from './subscriptionBodies';

/** The key's cached entries as a JSON array (newest first), undefined when there are none. */
export async function cacheBlob(
  db: DatabaseReader,
  subscriptionId: Id<'subscriptions'>,
): Promise<string | undefined> {
  const rows = await bodyRowsOf(db, subscriptionId);
  if (rows.length === 0) return undefined;
  const entries = rows
    .map((r) => JSON.parse(r.entry) as { at: number })
    .sort((a, b) => b.at - a.at);
  return JSON.stringify(entries);
}

/** Replace the key's cached entries with the blob's (undefined or '[]': none). */
export async function setCacheBlob(
  db: DatabaseWriter,
  subscriptionId: Id<'subscriptions'>,
  blob: string | undefined,
): Promise<void> {
  for (const row of await bodyRowsOf(db, subscriptionId)) await db.delete(row._id);
  if (!blob) return;
  for (const raw of JSON.parse(blob) as unknown[]) {
    const text = JSON.stringify(raw);
    const entry = parseEntry(text);
    if (!entry) throw new Error('not a cache entry');
    await db.insert('subscriptionBodies', {
      subscriptionId,
      ua: entry.ua,
      at: entry.at,
      ...(typeof entry.region === 'string' ? { region: entry.region } : {}),
      entry: text,
    });
  }
}

/**
 * The row as tests used to read it: `subCache` holds the key's cached entries
 * (the table's, else what is left of the row's old blob).
 */
export async function withBodies<T extends { _id: Id<'subscriptions'>; subCache?: string }>(
  db: DatabaseReader,
  sub: T | null,
): Promise<T | null> {
  if (!sub) return sub;
  return { ...sub, subCache: (await cacheBlob(db, sub._id)) ?? sub.subCache };
}
