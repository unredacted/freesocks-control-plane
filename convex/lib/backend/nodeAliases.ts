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

/**
 * A rename points every alias of its old name at the new one (they are
 * flattened), so one hop resolves; the walk still follows a chain to its end,
 * with a guard against a loop no write can make.
 */
export async function currentNodeName(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
  name: string,
): Promise<string | null> {
  let at = name;
  const seen = new Set<string>([name]);
  for (;;) {
    const row = await db
      .query('panelNodeAliases')
      .withIndex('by_server_former', (q) =>
        q.eq('backendServerId', backendServerId).eq('formerName', at),
      )
      .first();
    if (!row || seen.has(row.name)) break;
    at = row.name;
    seen.add(at);
  }
  return at === name ? null : at;
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
  const next = new Map(rows.map((r) => [r.formerName, r.name]));
  const out = new Map<string, string[]>();
  for (const r of rows) {
    // Resolve each to the end of its chain, so A -> B -> C lists A and B under C.
    let cur = r.name;
    const seen = new Set<string>([r.formerName, cur]);
    while (next.has(cur) && !seen.has(next.get(cur)!)) {
      cur = next.get(cur)!;
      seen.add(cur);
    }
    out.set(cur, [...(out.get(cur) ?? []), r.formerName]);
  }
  return out;
}

/**
 * The rename running on a node of this backend, matched by its backend uuid or
 * by either of its names (an origin keeps the name in lower case). Workflows
 * that would add a reference to the node (an origin, a setup run) or take it
 * away (retirement) wait for it.
 */
export async function runningRenameOf(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
  node: { nodeUuid?: string; name?: string },
) {
  const lower = node.name?.toLowerCase();
  return (
    (
      await db
        .query('panelNodeRenames')
        .withIndex('by_state', (q) => q.eq('state', 'running'))
        .collect()
    ).find(
      (r) =>
        r.backendServerId === backendServerId &&
        ((!!node.nodeUuid && r.nodeUuid === node.nodeUuid) ||
          (!!lower && (r.from.toLowerCase() === lower || r.to.toLowerCase() === lower))),
    ) ?? null
  );
}
