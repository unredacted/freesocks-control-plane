/**
 * What the country lists say about names and addresses (docs/edges.md
 * "Country lists"). Every reader goes through here, and membership is read
 * ONLY through a list's `activeVersionId`: a query reads one snapshot, so the
 * pointer and the rows it points at always agree.
 *
 * `lookupEntries` answers the operator's lookup box and shows every list with
 * an active version, flagged. `listFactsFor` is what evidence reads: only
 * enabled lists whose source confirmed them within `edge.lists.staleDays`,
 * and nothing at all while `edge.lists.enabled` is off.
 */
import type { DatabaseReader } from '../../../_generated/server';
import type { Doc, Id } from '../../../_generated/dataModel';
import { resolveEdgeConfig } from '../../edgeConfig';
import { addressKey, chunkHolds } from './intervals';
import { matchKeys } from './names';
import { readEntry } from './parse';

/** Lists a deployment may follow: every read here walks them all. */
export const MAX_LISTS = 50;

const DAY = 24 * 60 * 60 * 1000;

export type ListDoc = Doc<'countryLists'>;
type VersionId = Id<'countryListVersions'>;

export function isFresh(list: ListDoc, staleDays: number, now: number): boolean {
  return list.confirmedAt !== undefined && now - list.confirmedAt <= staleDays * DAY;
}

export interface ListFact {
  listId: Id<'countryLists'>;
  label: string;
  country: string;
  regime: 'allowlist' | 'blocklist';
  networks: number[];
  /** An exact name, a wildcard over a parent, or a range. */
  how: 'exact' | 'wildcard' | 'range';
  enabled: boolean;
  fresh: boolean;
}

interface Active {
  list: ListDoc;
  versionId: VersionId;
  fresh: boolean;
}

async function activeLists(db: DatabaseReader, staleDays: number, now: number): Promise<Active[]> {
  const out: Active[] = [];
  for (const list of await db.query('countryLists').take(MAX_LISTS))
    if (list.activeVersionId)
      out.push({ list, versionId: list.activeVersionId, fresh: isFresh(list, staleDays, now) });
  return out;
}

/** Whether a version's ranges hold an address: one chunk read and a binary search. */
export async function versionHoldsAddress(
  db: DatabaseReader,
  versionId: VersionId,
  ip: string,
): Promise<boolean> {
  const k = addressKey(ip);
  if (!k) return false;
  const chunk = await db
    .query('countryListChunks')
    .withIndex('by_version_family_lo', (q) =>
      q.eq('versionId', versionId).eq('family', k.family).lte('firstLo', k.hex),
    )
    .order('desc')
    .first();
  return !!chunk && chunkHolds(chunk.text, k.family, k.hex);
}

/** Which of the given versions hold a name, and how (exact beats a wildcard). */
async function versionsHoldingName(
  db: DatabaseReader,
  versions: ReadonlySet<string>,
  name: string,
): Promise<Map<string, 'exact' | 'wildcard'>> {
  const out = new Map<string, 'exact' | 'wildcard'>();
  for (const key of matchKeys(name)) {
    const rows = await db
      .query('countryListMembers')
      .withIndex('by_name_version', (q) => q.eq('name', key.name))
      // Per list: the version in use, one waiting, one being written, one ended
      // and not yet cleaned, each maybe exact and wildcard.
      .take(MAX_LISTS * 8);
    for (const r of rows) {
      if (r.wildcard !== key.wildcard || !versions.has(r.versionId)) continue;
      if (!out.has(r.versionId) || !key.wildcard)
        out.set(r.versionId, key.wildcard ? 'wildcard' : 'exact');
    }
  }
  return out;
}

function factOf(a: Active, how: ListFact['how']): ListFact {
  return {
    listId: a.list._id,
    label: a.list.label,
    country: a.list.country,
    regime: a.list.regime,
    networks: a.list.networks,
    how,
    enabled: a.list.enabled,
    fresh: a.fresh,
  };
}

async function factsFor(
  db: DatabaseReader,
  lists: readonly Active[],
  entry: string,
): Promise<{ kind: 'name' | 'address' | 'invalid'; facts: ListFact[] }> {
  const e = readEntry(entry.trim());
  if (e.kind === 'v4' || e.kind === 'v6') {
    if (e.lo !== e.hi) return { kind: 'invalid', facts: [] };
    const facts: ListFact[] = [];
    for (const a of lists)
      if (await versionHoldsAddress(db, a.versionId, entry.trim())) facts.push(factOf(a, 'range'));
    return { kind: 'address', facts };
  }
  if (e.kind !== 'name') return { kind: 'invalid', facts: [] };
  const held = await versionsHoldingName(db, new Set(lists.map((a) => a.versionId)), e.name);
  const facts = lists.flatMap((a) => {
    const how = held.get(a.versionId);
    return how ? [factOf(a, how)] : [];
  });
  return { kind: 'name', facts };
}

/** The operator's lookup: every list with an active version, each flagged enabled and fresh. */
export async function lookupEntries(
  db: DatabaseReader,
  entries: readonly string[],
  now: number,
): Promise<Array<{ entry: string; kind: 'name' | 'address' | 'invalid'; facts: ListFact[] }>> {
  const cfg = await resolveEdgeConfig(db);
  const lists = await activeLists(db, cfg.lists.staleDays, now);
  const out = [];
  for (const entry of entries) out.push({ entry, ...(await factsFor(db, lists, entry)) });
  return out;
}

/**
 * What evidence may read: only enabled, fresh lists, and none while the
 * switch is off. Keyed by the name or address as given.
 */
export async function listFactsFor(
  db: DatabaseReader,
  q: { names?: readonly string[]; addresses?: readonly string[]; now: number },
): Promise<Map<string, ListFact[]>> {
  const out = new Map<string, ListFact[]>();
  const cfg = await resolveEdgeConfig(db);
  if (!cfg.lists.enabled) return out;
  const lists = (await activeLists(db, cfg.lists.staleDays, q.now)).filter(
    (a) => a.list.enabled && a.fresh,
  );
  if (lists.length === 0) return out;
  for (const entry of [...(q.names ?? []), ...(q.addresses ?? [])]) {
    const { facts } = await factsFor(db, lists, entry);
    if (facts.length > 0) out.set(entry, facts);
  }
  return out;
}
