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
 */
import type { Doc } from '../../../_generated/dataModel';
import type { DatabaseReader, MutationCtx } from '../../../_generated/server';
import { writeAuditLog } from '../../audit';

export type ListenerName = NonNullable<Doc<'relayListeners'>['tlsNames']>[number];

/** The marks of one name, as they are copied onto a listener's entry for it. */
export async function marksOfName(
  db: DatabaseReader,
  name: string,
): Promise<{ blockedIn?: string[]; provenIn?: string[] }> {
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
  return {
    ...(blockedIn.length ? { blockedIn } : {}),
    ...(provenIn.length ? { provenIn } : {}),
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
  for (const n of names) {
    if (n.status !== 'active') {
      out.push(n);
      continue;
    }
    const { blockedIn: _b, provenIn: _p, ...rest } = n;
    out.push({ ...rest, ...(await marksOfName(db, n.name)) });
  }
  return out;
}

/** Whether any active entry is judged in some country. */
export function namesJudged(names: readonly ListenerName[] | undefined): boolean {
  return (names ?? []).some(
    (n) =>
      n.status === 'active' && ((n.blockedIn?.length ?? 0) > 0 || (n.provenIn?.length ?? 0) > 0),
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
