/**
 * Candidate bookkeeping shared by `sniHunt.ts` and the family import
 * (`sniFamilies.ts`): the per-scope counts row (`sniHuntScopes`) and the one
 * transition every successful family import makes, a held name's candidates
 * becoming `added`. docs/edges.md "Finding names".
 */
import type { DatabaseReader, DatabaseWriter } from '../../../../_generated/server';
import type { Id } from '../../../../_generated/dataModel';

export interface HuntScope {
  networkId?: Id<'edgeNetworks'>;
  familyId?: Id<'sniFamilies'>;
}

/** The scope a candidate (or an ignore, a read) belongs to, without empty keys. */
export function candidateScope(r: HuntScope): HuntScope {
  return {
    ...(r.networkId ? { networkId: r.networkId } : {}),
    ...(r.familyId ? { familyId: r.familyId } : {}),
  };
}

export function scopeRow(db: DatabaseReader, s: HuntScope) {
  return db
    .query('sniHuntScopes')
    .withIndex('by_scope', (q) => q.eq('networkId', s.networkId).eq('familyId', s.familyId))
    .first();
}

/**
 * A scope's candidates changed: its counts row is marked for a recount (made
 * when missing). `inserted` candidates are added to `total` at once, so the
 * per-scope cap holds before the recount.
 */
export async function touchScope(db: DatabaseWriter, s: HuntScope, now: number, inserted = 0) {
  const row = await scopeRow(db, s);
  if (!row) {
    await db.insert('sniHuntScopes', {
      ...candidateScope(s),
      kind: s.familyId ? 'family' : 'network',
      total: inserted,
      ready: 0,
      dirty: true,
      updatedAt: now,
    });
    return;
  }
  if (row.dirty && inserted === 0) return;
  await db.patch(row._id, { dirty: true, total: row.total + inserted, updatedAt: now });
}

/**
 * Names a family now holds: every candidate row of each is `added` (names are
 * fleet-unique, so in every scope). Called from the family import itself, so
 * whichever route added a name, its candidates follow.
 */
export async function markCandidatesAdded(
  db: DatabaseWriter,
  names: readonly string[],
  now: number,
) {
  let marked = 0;
  for (const name of names)
    for await (const c of db.query('sniCandidates').withIndex('by_name', (q) => q.eq('name', name)))
      if (c.state !== 'added') {
        await db.patch(c._id, { state: 'added', updatedAt: now });
        await touchScope(db, candidateScope(c), now);
        marked++;
      }
  return marked;
}
