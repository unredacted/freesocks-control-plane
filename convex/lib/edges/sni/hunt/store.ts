/**
 * Candidate bookkeeping shared by `sniHunt.ts` and the family import
 * (`sniFamilies.ts`): the per-scope counts row (`sniHuntScopes`) and the one
 * transition every successful family import makes, a held name's candidates
 * becoming `added`. docs/edges.md "Finding names".
 */
import type { DatabaseReader, DatabaseWriter } from '../../../../_generated/server';
import type { Id } from '../../../../_generated/dataModel';
import { usableCandidate } from '../../../../../src/shared/contracts/sni';

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
 * A scope's candidates changed: its counts move by what the caller knows
 * changed (`total` for an insert or a delete, `ready` for a candidate that
 * became usable or stopped being so), so the overview is exact at once, with
 * no cron tick between. The row is also marked for a recount, which makes the
 * counts absolute again whatever was missed; the oldest-marked row is
 * recounted first (`dirtyAt`), so a busy scope never starves another.
 */
export async function bumpScope(
  db: DatabaseWriter,
  s: HuntScope,
  now: number,
  delta: { total?: number; ready?: number } = {},
) {
  const row = await scopeRow(db, s);
  const dt = delta.total ?? 0;
  const dr = delta.ready ?? 0;
  if (!row) {
    await db.insert('sniHuntScopes', {
      ...candidateScope(s),
      kind: s.familyId ? 'family' : 'network',
      total: Math.max(0, dt),
      ready: Math.max(0, Math.min(dt, dr)),
      dirty: true,
      dirtyAt: now,
      updatedAt: now,
    });
    return;
  }
  if (row.dirty && dt === 0 && dr === 0) return;
  const total = Math.max(0, row.total + dt);
  await db.patch(row._id, {
    total,
    ready: Math.max(0, Math.min(total, row.ready + dr)),
    dirty: true,
    ...(row.dirty ? {} : { dirtyAt: now }),
    updatedAt: now,
  });
}

/** Inserts into a scope (the cap holds on `total` before any recount). */
export const touchScope = (db: DatabaseWriter, s: HuntScope, now: number, inserted = 0) =>
  bumpScope(db, s, now, { total: inserted });

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
        await bumpScope(db, candidateScope(c), now, { ready: usableCandidate(c) ? -1 : 0 });
        marked++;
      }
  return marked;
}
