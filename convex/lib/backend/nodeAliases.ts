/**
 * The names a node had before a rename (`panelNodeAliases`, written by
 * backendNodeRenames.ts). A rename moves FCP's own rows in one transaction,
 * but some names lag by design: a subscription's pin until the drain reaches
 * it, a body whose Hosts still carry the old remark, the node role calling by
 * the name in its inventory. Every lookup that answers a delivery or a role
 * question resolves such a name here, so nothing it decides falls back to
 * "no origin" or "no gate" in between.
 */
import type { QueryCtx } from '../../_generated/server';
import type { Id } from '../../_generated/dataModel';

/** A chain A -> B -> C is followed at most this far (a loop cannot happen; a bound is cheap). */
const MAX_HOPS = 8;

/** The current name of a node `name` was a former name of, or null when it is no former name. */
export async function currentNodeName(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
  name: string,
): Promise<string | null> {
  let at = name;
  let moved = false;
  for (let i = 0; i < MAX_HOPS; i++) {
    const row = await db
      .query('panelNodeAliases')
      .withIndex('by_server_former', (q) =>
        q.eq('backendServerId', backendServerId).eq('formerName', at),
      )
      .first();
    if (!row) break;
    at = row.name;
    moved = true;
  }
  return moved ? at : null;
}

/** Every former name of each current name, for a backend (a small table). */
export async function formerNamesByName(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
): Promise<Map<string, string[]>> {
  const rows = await db
    .query('panelNodeAliases')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .collect();
  const out = new Map<string, string[]>();
  for (const r of rows) {
    // Resolve each to the end of its chain, so A -> B -> C lists A and B under C.
    let cur = r.name;
    for (let i = 0; i < MAX_HOPS; i++) {
      const next = rows.find((x) => x.formerName === cur);
      if (!next) break;
      cur = next.name;
    }
    out.set(cur, [...(out.get(cur) ?? []), r.formerName]);
  }
  return out;
}
