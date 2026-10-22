/**
 * Freedom modes only through edges, DB half (the rule: lib/edges/freedomDelivery.ts;
 * docs/edges.md "Freedom modes only through edges"): the pinner's rules for a
 * key, whether a key's raw backend URL is withheld, which nodes of the freedom
 * modes' pools are withheld and why (the attention items, the preview), and
 * the switch itself.
 *
 * A freedom mode's pool on a backend is what FCP knows of it: the enrolled
 * nodes serving the mode whose gate is open, the observed nodes serving a
 * transport of a group in the mode's pool, and the nodes members of the mode
 * are pinned to. Operator-scale everywhere (nodes, groups, bindings); member
 * counts are paged from an action, never read in one transaction.
 */
import { ConvexError, v } from 'convex/values';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type QueryCtx,
} from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { protectionAt } from './edgeRender';
import { writeAuditLog } from './lib/audit';
import { formerNamesByName, currentNodeName } from './lib/backend/nodeAliases';
import { resolveModeCatalog } from './lib/connectionModes';
import { cohortPage, type CohortCursor } from './lib/edges/cohorts';
import {
  FREEDOM_EDGES_ONLY_KEY,
  FREEDOM_FAMILY,
  freedomEdgesOnly,
  freedomHoldOf,
  intentAt,
  setupFrontings,
  withheldReason,
  type NodeProtection,
} from './lib/edges/freedomDelivery';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { poolFromConfig } from './lib/remnawavePlacement';
import { blockedNamesOf } from './nodeIntents';
import { relayForBackendNode } from './relays';
import type { FreedomWithheldReason } from '../src/shared/contracts/edgeCodes';
import type { ModeFronting } from '../src/shared/contracts/servers';
import type { AttentionItem } from './edgeOperator';

type Db = QueryCtx['db'];

/** Distinct pinned node names one backend's walk looks at (operator-scale; more is a stale tail). */
export const MAX_PINNED_NODES = 200;
/**
 * Keys one count page reads. A key row carries its cached bodies (up to four),
 * so a page stays small enough for one query's read limit.
 */
const COUNT_PAGE = 100;
/** Pages one preview counts at most per figure (100,000 keys) before it answers `approximate`. */
const MAX_COUNT_PAGES = 1000;

// --- the pinner and the raw URL ----------------------------------------------------------------------

/** The active key a backend short id names on one backend (a test key has none). */
async function keyOf(
  db: Db,
  backendServerId: Id<'backendServers'>,
  backendShortId: string,
): Promise<Doc<'subscriptions'> | null> {
  const rows = await db
    .query('subscriptions')
    .withIndex('by_backend_short_id', (q) => q.eq('backendShortId', backendShortId))
    .take(10);
  const here = rows.filter((r) => r.backendServerId === backendServerId);
  return here.find((r) => r.state === 'active') ?? here[0] ?? null;
}

/**
 * What the pinner may pick for one key: `blocked`, every node whose delivery
 * gate is closed (never picked while another exists), and `servable`, for a
 * key held to freedom delivery while the switch is on, the nodes an origin
 * with a live edge of the node's layer covers (the pick is made among them
 * while one is in the body). `servable` is null when nothing narrows the pick.
 */
export const pinRules = internalQuery({
  args: { backendServerId: v.id('backendServers'), backendShortId: v.string() },
  handler: async (
    ctx,
    { backendServerId, backendShortId },
  ): Promise<{ blocked: string[]; servable: string[] | null }> => {
    const blocked = await blockedNamesOf(ctx, backendServerId);
    if (!(await freedomEdgesOnly(ctx.db))) return { blocked, servable: null };
    const sub = await keyOf(ctx.db, backendServerId, backendShortId);
    const hold = sub ? await freedomHoldOf(ctx.db, sub, sub.pinnedNode) : null;
    if (!hold) return { blocked, servable: null };
    const covers = (p: NodeProtection, fronting: ModeFronting | null) =>
      withheldReason({ protection: p, enrolled: true, fronting }) === null;
    // A whole-server origin with a live edge covers every node.
    if (covers(await protectionAt(ctx, backendServerId, undefined), hold.fronting))
      return { blocked, servable: null };
    const bindings = await ctx.db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) => q.eq('backendServerId', backendServerId))
      .collect();
    const frontings = await setupFrontings(ctx.db, backendServerId);
    const formers = await formerNamesByName(ctx.db, backendServerId);
    const servable: string[] = [];
    for (const b of bindings) {
      if (b.state !== 'active' || !b.nodeName) continue;
      // An enrolled node is judged at its own mode's layer, any other at the key's.
      const intent = await intentAt(ctx.db, backendServerId, b.nodeName);
      const fronting = intent ? (frontings.get(intent.mode) ?? null) : hold.fronting;
      if (!covers(await protectionAt(ctx, backendServerId, b.nodeName), fronting)) continue;
      servable.push(b.nodeName, ...(formers.get(b.nodeName) ?? []));
    }
    return { blocked, servable };
  },
});

/**
 * Whether a key's raw backend URL must not be shown to its member: the switch
 * is on and the key is held to freedom delivery (the backend URL hands out the
 * nodes' own addresses, whatever FCP's fronted route would).
 */
export const rawUrlWithheld = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { subscriptionId }): Promise<boolean> => {
    if (!(await freedomEdgesOnly(ctx.db))) return false;
    const sub = await ctx.db.get(subscriptionId);
    return !!sub && (await freedomHoldOf(ctx.db, sub, sub.pinnedNode)) !== null;
  },
});

// --- the pools ---------------------------------------------------------------------------------------

/** One node of a freedom mode's pool on one backend, and whether its members may be handed it. */
export interface PoolNode {
  node: string;
  nodeUuid: string | null;
  enrolled: boolean;
  /** null: it may serve the mode's members. */
  reason: FreedomWithheldReason | null;
  /** The origin that covers it, when one does. */
  relaySlug: string | null;
}

/** One freedom mode on one backend. */
export interface PoolEntry {
  backendServerId: Id<'backendServers'>;
  serverSlug: string;
  mode: string;
  label: string | null;
  fronting: ModeFronting | null;
  /** The mode's placements (group uuids): INTERNAL, never in an admin answer. */
  placements: string[];
  nodes: PoolNode[];
  /** When the node was last changed (an enrolled node), for the attention row. */
  since: Record<string, number>;
}

/** The distinct node names active keys of a backend are pinned to (one read per name). */
async function pinnedNodeNames(db: Db, sid: Id<'backendServers'>): Promise<string[]> {
  const out: string[] = [];
  let after = '';
  while (out.length < MAX_PINNED_NODES) {
    const next = await db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q.eq('backendServerId', sid).gt('pinnedNode', after),
      )
      .first();
    if (!next || !next.pinnedNode) break;
    after = next.pinnedNode;
    const active = await db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q.eq('backendServerId', sid).eq('pinnedNode', after).eq('state', 'active'),
      )
      .first();
    if (active) out.push(after);
  }
  return out;
}

/** The placements of the active keys pinned to a node (one read per placement). */
async function pinnedPlacements(
  ctx: { db: Db },
  sid: Id<'backendServers'>,
  nodeName: string,
): Promise<string[]> {
  const out: string[] = [];
  let cursor: CohortCursor | null = null;
  for (let page = 0; page < 20; page++) {
    const p = await cohortPage(ctx, { backendServerId: sid, nodeName }, cursor);
    for (const c of p.cohorts) if (c.placement) out.push(c.placement);
    if (!p.next) break;
    cursor = p.next;
  }
  return out;
}

/**
 * Every freedom mode's pool on every Remnawave backend, each node judged
 * (lib/edges/freedomDelivery.ts `withheldReason`). Read whether the switch is
 * on or not: the preview is what it WOULD withhold.
 */
export async function freedomPools(ctx: { db: Db }): Promise<PoolEntry[]> {
  const db = ctx.db;
  const { modes } = await resolveModeCatalog(db);
  const freedom = modes.filter((m) => m.family === FREEDOM_FAMILY);
  if (freedom.length === 0) return [];
  const labels = new Map(freedom.map((m) => [m.id, m.label ?? null]));
  const placements = new Map<string, string[]>();
  for (const r of await db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', 'remnawave'))
    .collect())
    if (labels.has(r.modeSlug)) placements.set(r.modeSlug, poolFromConfig(r.config));
  const modesOfPlacement = (p: string) =>
    [...placements].filter(([, pool]) => pool.includes(p)).map(([slug]) => slug);
  const servers = (await db.query('backendServers').collect()).filter(
    (s) => s.backend === 'remnawave',
  );
  const out: PoolEntry[] = [];
  for (const server of servers) {
    const sid = server._id;
    const frontings = await setupFrontings(db, sid);
    const intents = (
      await db
        .query('panelNodeIntents')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((i) => i.state !== 'retiring' && i.state !== 'retired');
    // node name -> what is known of it; mode slug -> node names
    const known = new Map<string, { nodeUuid: string | null; enrolled: boolean; since?: number }>();
    const byMode = new Map<string, Set<string>>();
    const add = (mode: string, node: string) => {
      if (!labels.has(mode)) return;
      const set = byMode.get(mode) ?? new Set<string>();
      set.add(node);
      byMode.set(mode, set);
    };
    // Enrolled nodes: their own mode. A node whose gate is closed is withheld
    // by the gate already, from every member.
    for (const i of intents) {
      known.set(i.name, { nodeUuid: i.nodeUuid ?? null, enrolled: true, since: i.updatedAt });
      if (i.delivery.disposition === 'live' && !i.maintenance) add(i.mode, i.name);
    }
    const enrolledUuids = new Set(intents.map((i) => i.nodeUuid).filter(Boolean));
    // Observed nodes serving a transport of a group in a freedom mode's pool.
    const squads = await db
      .query('panelSquads')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    const observed = await db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect();
    for (const n of observed) {
      if (n.isDisabled || known.has(n.name) || enrolledUuids.has(n.nodeUuid)) continue;
      known.set(n.name, { nodeUuid: n.nodeUuid, enrolled: false });
      const served = new Set(n.activeInboundUuids);
      for (const sq of squads)
        if (sq.inboundUuids.some((u) => served.has(u)))
          for (const mode of modesOfPlacement(sq.squadUuid)) add(mode, n.name);
    }
    // Nodes members are pinned to, by the placements of the keys pinned there.
    for (const name of await pinnedNodeNames(db, sid)) {
      const current = (await currentNodeName(db, sid, name)) ?? name;
      const k = known.get(current);
      if (k?.enrolled) continue;
      if (!k) known.set(current, { nodeUuid: null, enrolled: false });
      for (const p of await pinnedPlacements(ctx, sid, name))
        for (const mode of modesOfPlacement(p)) add(mode, current);
    }
    const protection = new Map<string, NodeProtection>();
    for (const [mode, names] of byMode) {
      const fronting = frontings.get(mode) ?? null;
      const nodes: PoolNode[] = [];
      const since: Record<string, number> = {};
      for (const name of [...names].sort()) {
        const k = known.get(name)!;
        let p = protection.get(name);
        if (!p) {
          p = await protectionAt(ctx, sid, name);
          protection.set(name, p);
        }
        const reason = withheldReason({ protection: p, enrolled: k.enrolled, fronting });
        const relay = p.bound ? await relayForBackendNode(db, sid, name) : null;
        nodes.push({
          node: name,
          nodeUuid: k.nodeUuid,
          enrolled: k.enrolled,
          reason,
          relaySlug: relay?.slug ?? null,
        });
        if (k.since) since[name] = k.since;
      }
      out.push({
        backendServerId: sid,
        serverSlug: server.slug,
        mode,
        label: labels.get(mode) ?? null,
        fronting,
        placements: placements.get(mode) ?? [],
        nodes,
        since,
      });
    }
  }
  return out.sort(
    (a, b) => a.serverSlug.localeCompare(b.serverSlug) || a.mode.localeCompare(b.mode),
  );
}

/**
 * Whether turning the switch on would stop handing any member their node: a
 * withheld node an active key of the mode is pinned to, or a mode with no node
 * that may serve it and an active key in its pool. Indexed existence reads
 * only (one per withheld node and placement): what a mutation can afford.
 */
async function anyMemberAffected(db: Db, pools: PoolEntry[]): Promise<boolean> {
  for (const e of pools) {
    const servable = e.nodes.some((n) => n.reason === null);
    if (!servable)
      for (const p of e.placements) {
        const key = await db
          .query('subscriptions')
          .withIndex('by_backend_server_state', (q) =>
            q
              .eq('backendServerId', e.backendServerId)
              .eq('state', 'active')
              .eq('backendPlacement', p),
          )
          .first();
        if (key) return true;
      }
    for (const n of e.nodes) {
      if (n.reason === null) continue;
      const pinned = (placement?: string) =>
        db
          .query('subscriptions')
          .withIndex('by_backend_server_pinned', (q) => {
            const base = q
              .eq('backendServerId', e.backendServerId)
              .eq('pinnedNode', n.node)
              .eq('state', 'active');
            return placement === undefined ? base : base.eq('backendPlacement', placement);
          })
          .first();
      if (n.enrolled) {
        if (await pinned()) return true;
        continue;
      }
      for (const p of e.placements) if (await pinned(p)) return true;
    }
  }
  return false;
}

// --- the switch ----------------------------------------------------------------------------------------

async function switchRow(db: Db) {
  return db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', FREEDOM_EDGES_ONLY_KEY))
    .unique();
}

export interface FreedomDeliveryState {
  on: boolean;
  /** When the switch last changed (or the seed set it); null when it was never set. */
  since: string | null;
}

async function stateOf(db: Db): Promise<FreedomDeliveryState> {
  const row = await switchRow(db);
  return {
    on: await freedomEdgesOnly(db),
    since: row ? new Date(row.updatedAt).toISOString() : null,
  };
}

export const view = internalQuery({
  args: {},
  handler: (ctx) => stateOf(ctx.db),
});

/**
 * Turn freedom delivery through edges on or off. Turning it on while members
 * would stop being handed their node needs `confirm` (the admin has seen the
 * preview): `edge.freedom_confirm_required` otherwise. Audited either way;
 * every mirror is rendered again (a held key's mirror gets the unavailable
 * stub, a released one its body back). The place tokens move with the switch,
 * so no cached body outlives it.
 */
export const setEdgesOnly = internalMutation({
  args: {
    on: v.boolean(),
    confirm: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { on, confirm, actorAdminId }): Promise<FreedomDeliveryState> => {
    const before = await freedomEdgesOnly(ctx.db);
    if (before === on && (await switchRow(ctx.db))) return stateOf(ctx.db);
    let withheldNodes = 0;
    let affected = false;
    if (on) {
      const pools = await freedomPools(ctx);
      withheldNodes = new Set(
        pools.flatMap((e) =>
          e.nodes.filter((n) => n.reason !== null).map((n) => `${e.backendServerId}:${n.node}`),
        ),
      ).size;
      affected = await anyMemberAffected(ctx.db, pools);
      if (affected && confirm !== true)
        throw new ConvexError({
          code: 'edge.freedom_confirm_required',
          message:
            'Some members would no longer be handed their node. Look at what it closes and confirm',
        });
    }
    await upsertSettingRow(ctx, FREEDOM_EDGES_ONLY_KEY, JSON.stringify(on), actorAdminId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.freedom.edges_only',
      targetType: 'app_settings',
      targetId: FREEDOM_EDGES_ONLY_KEY,
      payload: { on, confirmed: on && affected, withheldNodes, affected },
    });
    await scheduleMirrorRefresh(ctx);
    return stateOf(ctx.db);
  },
});

// --- the preview -------------------------------------------------------------------------------------

/** The pools as the preview action counts them (placements included: internal only). */
export const poolsForPreview = internalQuery({
  args: {},
  handler: async (ctx) => ({ on: await freedomEdgesOnly(ctx.db), pools: await freedomPools(ctx) }),
});

/** One page of the active keys of a backend in one placement: how many. */
export const countPlacementPage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    placement: v.string(),
    cursor: v.union(v.string(), v.null()),
  },
  handler: async (ctx, a) => {
    const page = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_state', (q) =>
        q
          .eq('backendServerId', a.backendServerId)
          .eq('state', 'active')
          .eq('backendPlacement', a.placement),
      )
      .paginate({ numItems: COUNT_PAGE, cursor: a.cursor });
    return { count: page.page.length, next: page.isDone ? null : page.continueCursor };
  },
});

/** One page of the active keys pinned to a node: how many, per placement. */
export const countPinnedPage = internalQuery({
  args: {
    backendServerId: v.id('backendServers'),
    nodeName: v.string(),
    cursor: v.union(v.string(), v.null()),
  },
  handler: async (ctx, a) => {
    const page = await ctx.db
      .query('subscriptions')
      .withIndex('by_backend_server_pinned', (q) =>
        q
          .eq('backendServerId', a.backendServerId)
          .eq('pinnedNode', a.nodeName)
          .eq('state', 'active'),
      )
      .paginate({ numItems: COUNT_PAGE, cursor: a.cursor });
    const byPlacement: Record<string, number> = {};
    for (const s of page.page) {
      const k = s.backendPlacement ?? '';
      byPlacement[k] = (byPlacement[k] ?? 0) + 1;
    }
    return { byPlacement, next: page.isDone ? null : page.continueCursor };
  },
});

export interface FreedomPreviewMode {
  serverSlug: string;
  mode: string;
  label: string | null;
  fronting: ModeFronting | null;
  nodes: { total: number; servable: number; withheld: number };
  withheldNodes: Array<{
    node: string;
    nodeUuid: string | null;
    enrolled: boolean;
    reason: FreedomWithheldReason;
  }>;
  /**
   * Active keys of the mode on this backend (`total`), those pinned to a
   * withheld node (`onWithheld`), and those that would get nothing: the ones
   * on withheld nodes while the mode has a node that may serve them (they move
   * there at their next refresh, so 0 here), else every key of the mode.
   */
  members: { total: number; onWithheld: number; cutOff: number; moved: number };
}

export interface FreedomPreview {
  on: boolean;
  modes: FreedomPreviewMode[];
  totals: { withheldNodes: number; affectedMembers: number; cutOffMembers: number };
  /** A count stopped at its page cap: the figures are lower bounds. */
  approximate: boolean;
}

/**
 * What turning the switch on would close, read-only: per freedom mode and
 * backend, its nodes (servable, withheld and why) and its members (on a
 * withheld node, moved, cut off). Never a placement or an address.
 */
export const preview = internalAction({
  args: {},
  handler: async (ctx): Promise<FreedomPreview> => {
    const { on, pools } = await ctx.runQuery(internal.freedomDelivery.poolsForPreview, {});
    let approximate = false;
    const countPlacement = async (sid: Id<'backendServers'>, placement: string) => {
      let total = 0;
      let cursor: string | null = null;
      for (let i = 0; i < MAX_COUNT_PAGES; i++) {
        const page: { count: number; next: string | null } = await ctx.runQuery(
          internal.freedomDelivery.countPlacementPage,
          { backendServerId: sid, placement, cursor },
        );
        total += page.count;
        cursor = page.next;
        if (!cursor) return total;
      }
      approximate = true;
      return total;
    };
    const pinnedCounts = new Map<string, Record<string, number>>();
    const countPinned = async (sid: Id<'backendServers'>, nodeName: string) => {
      const key = `${sid}:${nodeName}`;
      const known = pinnedCounts.get(key);
      if (known) return known;
      const acc: Record<string, number> = {};
      let cursor: string | null = null;
      for (let i = 0; i < MAX_COUNT_PAGES; i++) {
        const page: { byPlacement: Record<string, number>; next: string | null } =
          await ctx.runQuery(internal.freedomDelivery.countPinnedPage, {
            backendServerId: sid,
            nodeName,
            cursor,
          });
        for (const [p, n] of Object.entries(page.byPlacement)) acc[p] = (acc[p] ?? 0) + n;
        cursor = page.next;
        if (!cursor) break;
        if (i === MAX_COUNT_PAGES - 1) approximate = true;
      }
      pinnedCounts.set(key, acc);
      return acc;
    };
    const modes: FreedomPreviewMode[] = [];
    const withheldSet = new Set<string>();
    for (const e of pools) {
      const withheld = e.nodes.filter((n) => n.reason !== null);
      const servable = e.nodes.length - withheld.length;
      let total = 0;
      for (const p of e.placements) total += await countPlacement(e.backendServerId, p);
      let onWithheld = 0;
      for (const n of withheld) {
        withheldSet.add(`${e.backendServerId}:${n.node}`);
        const by = await countPinned(e.backendServerId, n.node);
        onWithheld += n.enrolled
          ? Object.values(by).reduce((x, y) => x + y, 0)
          : e.placements.reduce((x, p) => x + (by[p] ?? 0), 0);
      }
      const cutOff = servable > 0 ? 0 : Math.max(total, onWithheld);
      modes.push({
        serverSlug: e.serverSlug,
        mode: e.mode,
        label: e.label,
        fronting: e.fronting,
        nodes: { total: e.nodes.length, servable, withheld: withheld.length },
        withheldNodes: withheld.map((n) => ({
          node: n.node,
          nodeUuid: n.nodeUuid,
          enrolled: n.enrolled,
          reason: n.reason!,
        })),
        members: { total, onWithheld, cutOff, moved: servable > 0 ? onWithheld : 0 },
      });
    }
    return {
      on,
      modes,
      totals: {
        withheldNodes: withheldSet.size,
        affectedMembers: modes.reduce((x, m) => x + m.members.cutOff + m.members.moved, 0),
        cutOffMembers: modes.reduce((x, m) => x + m.members.cutOff, 0),
      },
      approximate,
    };
  },
});

// --- attention ---------------------------------------------------------------------------------------

/**
 * While the switch is on: one item per node withheld from a freedom mode's
 * members (`freedom_node_withheld`, the reason as its code), naming the
 * backend, the node and the mode, never an address. The action goes where
 * the reason is fixed: protecting the node, its origin, or the modes.
 */
export async function freedomAttention(ctx: { db: Db }): Promise<AttentionItem[]> {
  if (!(await freedomEdgesOnly(ctx.db))) return [];
  const out: AttentionItem[] = [];
  for (const e of await freedomPools(ctx)) {
    for (const n of e.nodes) {
      if (n.reason === null) continue;
      const action =
        n.reason === 'withheld_direct_mode'
          ? 'open_modes'
          : n.reason === 'withheld_no_edge'
            ? 'open_relay'
            : 'protect_node';
      out.push({
        id: `freedom_node_withheld:${e.backendServerId}:${n.node}:${e.mode}`,
        kind: 'freedom_node_withheld',
        severity: 'warning',
        relaySlug: n.relaySlug,
        relayId: null,
        edgeId: null,
        listenerKey: null,
        accountId: null,
        rotationId: null,
        code: n.reason,
        facts: {
          serverSlug: e.serverSlug,
          node: n.node,
          ...(n.nodeUuid ? { nodeUuid: n.nodeUuid } : {}),
          mode: e.mode,
          enrolled: n.enrolled,
        },
        action,
        since: e.since[n.node] ? new Date(e.since[n.node]!).toISOString() : null,
      });
    }
  }
  return out;
}
