/**
 * Per-country judgements of server names (`sniNameCountry`) as a listener's
 * entries carry them (docs/edges.md "Names for the member's country").
 *
 * A render reads the marks off the listener's own entries, never the table, so
 * every writer that puts a name on a listener copies them on: registration,
 * a reactivation, a rollout's activation and a mark itself. A name that
 * reaches a listener after it was judged is then never offered where it is
 * known blocked.
 *
 * Per-country selection needs the growth-stable pick (`hrw1`): the legacy
 * modulus ignores the member's country. A listener whose names carry a mark is
 * therefore moved onto it (`pickForJudgedNames`) and stays there.
 *
 * The entries carry one more copy, `listedIn`: the curated countries where an
 * allowlist that prefers its names holds the name (docs/edges.md "Names on a
 * country's allowlist"). It is not a judgement, but it shapes a body by
 * country exactly as a mark does, so everything here treats it alike.
 */
import type { Doc, Id } from '../../../_generated/dataModel';
import type { DatabaseReader, MutationCtx } from '../../../_generated/server';
import { writeAuditLog } from '../../audit';
import { resolveEdgeConfig } from '../../edgeConfig';
import { resolveSniConfig } from '../../sniConfig';
import { evidenceLists } from '../lists/facts';
import { listedCountries, type PreferContext } from '../lists/prefer';
import { protocolUsesSni } from '../protocols';
import { bumpEpochAndRefresh } from '../relayGuards';

export type ListenerName = NonNullable<Doc<'relayListeners'>['tlsNames']>[number];

/**
 * The allowlists whose names are preferred now: `edge.lists.preferNames` on,
 * and each list on, fresh, with a version in use (what evidence reads) and
 * its own switch on. Null while nothing is preferred, so nothing more is read.
 */
export async function preferContext(
  db: DatabaseReader,
  now: number,
): Promise<PreferContext | null> {
  const cfg = await resolveEdgeConfig(db);
  if (!cfg.lists.preferNames) return null;
  const lists = (await evidenceLists(db, now)).filter(
    (a) => a.list.regime === 'allowlist' && a.list.preferNames === true,
  );
  if (lists.length === 0) return null;
  const { curatedCountries } = await resolveSniConfig(db);
  return {
    lists: new Map(lists.map((a) => [a.list._id as string, a.list.country])),
    curated: new Set(curatedCountries),
  };
}

/**
 * The marks of one name, as they are copied onto a listener's entry for it.
 * `prefer` is read here when the caller does not pass it (a caller copying
 * many names reads it once).
 */
export async function marksOfName(
  db: DatabaseReader,
  name: string,
  prefer?: PreferContext | null,
): Promise<{ blockedIn?: string[]; provenIn?: string[]; listedIn?: string[] }> {
  const rows = await db
    .query('sniNameCountry')
    .withIndex('by_name', (q) => q.eq('name', name))
    .collect();
  const blockedIn = rows
    .filter((r) => r.state === 'blocked')
    .map((r) => r.country)
    .sort();
  const provenIn = rows
    .filter((r) => r.state === 'proven')
    .map((r) => r.country)
    .sort();
  const ctx = prefer === undefined ? await preferContext(db, Date.now()) : prefer;
  // Only a family's name has stored list facts (names are fleet-unique).
  const row = ctx
    ? await db
        .query('sniNames')
        .withIndex('by_name', (q) => q.eq('name', name))
        .first()
    : null;
  const listedIn = listedCountries(row?.onLists, ctx);
  return {
    ...(blockedIn.length ? { blockedIn } : {}),
    ...(provenIn.length ? { provenIn } : {}),
    ...(listedIn.length ? { listedIn } : {}),
  };
}

/**
 * `names` with every ACTIVE entry carrying the marks its name has now; retired
 * entries (never selected) are left as they are. Order, status and drain are
 * unchanged.
 */
export async function withCountryMarks(
  db: DatabaseReader,
  names: readonly ListenerName[],
): Promise<ListenerName[]> {
  const out: ListenerName[] = [];
  const prefer = await preferContext(db, Date.now());
  for (const n of names) {
    if (n.status !== 'active') {
      out.push(n);
      continue;
    }
    const { blockedIn: _b, provenIn: _p, listedIn: _l, ...rest } = n;
    out.push({ ...rest, ...(await marksOfName(db, n.name, prefer)) });
  }
  return out;
}

/** Whether two lists carry the same names with the same marks (order of keys aside). */
export function sameCountryMarks(a: readonly ListenerName[], b: readonly ListenerName[]): boolean {
  const set = (c: readonly string[] | undefined) => [...(c ?? [])].sort().join(',');
  const key = (n: ListenerName) =>
    `${n.name}|${n.status}|${set(n.blockedIn)}|${set(n.provenIn)}|${set(n.listedIn)}`;
  return a.length === b.length && a.every((n, i) => key(n) === key(b[i]!));
}

/**
 * Whether any active entry is judged in some country, or preferred in one by
 * an allowlist: either way the member's country decides which names they get.
 */
export function namesJudged(names: readonly ListenerName[] | undefined): boolean {
  return (names ?? []).some(
    (n) =>
      n.status === 'active' &&
      ((n.blockedIn?.length ?? 0) > 0 ||
        (n.provenIn?.length ?? 0) > 0 ||
        (n.listedIn?.length ?? 0) > 0),
  );
}

/**
 * The pick a listener needs for these names: `hrw1` once any of them is judged
 * (the legacy modulus would hand a member a name blocked where they are), its
 * current pick otherwise. Never moves a listener back.
 */
export function pickForJudgedNames(
  current: 'hrw1' | undefined,
  names: readonly ListenerName[] | undefined,
): 'hrw1' | undefined {
  return current === 'hrw1' || namesJudged(names) ? 'hrw1' : undefined;
}

/**
 * The audit row of an existing listener moved onto `hrw1` because its names are
 * judged: the entry an operator's switch writes (`relayListeners.setSniPick`),
 * with the reason. Every member of it gets a re-ranked name at their next
 * refresh, among the names the node already accepts.
 */
export async function auditPickForMarks(
  ctx: MutationCtx,
  l: Pick<Doc<'relayListeners'>, '_id' | 'relayId' | 'listenerKey'>,
  pick: 'hrw1' | undefined,
): Promise<void> {
  const relay = await ctx.db.get(l.relayId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'relay.listener.sni_pick',
    targetType: 'relay_listener',
    targetId: l._id,
    payload: {
      relaySlug: relay?.slug ?? '',
      listenerKey: l.listenerKey,
      version: pick ?? 'legacy',
      reason: 'country_marks',
    },
  });
}

/**
 * Every live listener's names carry the marks (and the allowlist preference)
 * they have now, and a listener with such a name is on `hrw1`. Only a listener
 * that really changes is written, and each origin it belongs to moves its
 * publication epoch once: a pass that finds nothing to change costs members
 * nothing.
 */
export async function reconcileListenerMarks(
  ctx: MutationCtx,
): Promise<{ changed: number; switched: number; origins: number }> {
  const now = Date.now();
  const origins = new Set<Id<'relays'>>();
  let changed = 0;
  let switched = 0;
  // Small operator table (as `writeCountryMarks` reads it).
  for (const l of await ctx.db.query('relayListeners').collect()) {
    if (l.retired || !l.tlsNames?.length) continue;
    const next = await withCountryMarks(ctx.db, l.tlsNames);
    const pick = protocolUsesSni(l) ? pickForJudgedNames(l.sniPick, next) : l.sniPick;
    const namesMoved = !sameCountryMarks(l.tlsNames, next);
    if (!namesMoved && pick === l.sniPick) continue;
    await ctx.db.patch(l._id, {
      ...(namesMoved ? { tlsNames: next, namesRevision: (l.namesRevision ?? 0) + 1 } : {}),
      ...(pick !== l.sniPick ? { sniPick: pick } : {}),
      updatedAt: now,
    });
    if (pick !== l.sniPick) {
      switched++;
      await auditPickForMarks(ctx, l, pick);
    }
    changed++;
    origins.add(l.relayId);
  }
  for (const id of origins) {
    const relay = await ctx.db.get(id);
    if (relay) await bumpEpochAndRefresh(ctx, relay);
  }
  return { changed, switched, origins: origins.size };
}
