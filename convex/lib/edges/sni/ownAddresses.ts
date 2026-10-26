/**
 * FCP's own addresses (canonical), for the checks that dial a name's REAL site
 * from inside a country: an answer among them is never dialled as one.
 */
import type { DatabaseReader } from '../../../_generated/server';
import { normalizeAddress } from '../hosts';

/**
 * Every address FCP members are handed or nodes listen on (bounded: operator
 * scale), canonical (`normalizeAddress`: brackets, case and IPv6 spellings
 * folded) so a resolver's spelling of the same address still matches.
 */
export async function ownAddresses(
  db: DatabaseReader,
  dialled: ReadonlyArray<{ address: string }>,
): Promise<string[]> {
  const out = new Set<string>();
  const add = (a: string | undefined) => {
    if (a) out.add(normalizeAddress(a));
  };
  for (const t of dialled) add(t.address);
  for (const relay of await db.query('relays').take(500)) {
    add(relay.originAddress);
    for (const a of relay.nodeAddresses ?? []) add(a);
    for (const status of ['active', 'draining'] as const)
      for (const e of await db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id).eq('status', status))
        .take(200))
        for (const a of [e.addresses.v4, e.addresses.v6]) add(a);
  }
  return [...out];
}
