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
import { formerNamesByName } from './lib/backend/nodeAliases';
import { resolveModeCatalog } from './lib/connectionModes';
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

/**
 * One node FCP knows serves a group of a freedom mode's pool on one backend,
 * and whether the mode's members may be handed it.
 */
export interface PoolNode {
  node: string;
  /** Its name and every name a key may still be pinned under (a rename drains pins over time). */
  pinNames: string[];
  nodeUuid: string | null;
  enrolled: boolean;
  /** The freedom groups (placements) it serves: INTERNAL, never in an admin answer. */
  placements: string[];
  /** The freedom modes it serves (an enrolled node: its own). */
  modes: string[];
  /** null: it may serve the members of those groups. */
  reason: FreedomWithheldReason | null;
  /** The origin that covers it, when one does. */
  relaySlug: string | null;
  /** When an enrolled node last changed, for the attention row. */
  since: number | null;
}

/** The freedom pools of one backend: every freedom mode (its groups and fronting here) and the nodes known to serve them. */
export interface BackendPools {
  backendServerId: Id<'backendServers'>;
  serverSlug: string;
  modes: Array<{
    mode: string;
    label: string | null;
    fronting: ModeFronting | null;
    /** INTERNAL: never in an admin answer. */
    placements: string[];
  }>;
  nodes: PoolNode[];
}

/**
 * The groups a key of which may be handed a node: one a node that may serve
 * it is known to serve. A key in any other group of a freedom mode gets
 * nothing while the switch is on (its body carries no covered node).
 */
export function servableGroups(b: BackendPools): Set<string> {
  return new Set(b.nodes.filter((n) => n.reason === null).flatMap((n) => n.placements));
}

/** Every freedom group of a backend's pools. */
function groupsOf(b: BackendPools): Set<string> {
  return new Set(b.modes.flatMap((m) => m.placements));
}

/**
 * The distinct node names active keys of a backend are pinned to: two reads
 * per name looked at, at most `2 * MAX_PINNED_NODES` names (the rest is a
 * stale tail of nodes long gone).
 */
async function pinnedNodeNames(db: Db, sid: Id<'backendServers'>): Promise<string[]> {
  const out: string[] = [];
  let after = '';
  for (let probe = 0; probe < 2 * MAX_PINNED_NODES && out.length < MAX_PINNED_NODES; probe++) {
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

/** An active key of a backend pinned under `name`, in `placement` when given (one indexed read). */
function pinnedKey(db: Db, sid: Id<'backendServers'>, name: string, placement?: string) {
  return db
    .query('subscriptions')
    .withIndex('by_backend_server_pinned', (q) => {
      const base = q.eq('backendServerId', sid).eq('pinnedNode', name).eq('state', 'active');
      return placement === undefined ? base : base.eq('backendPlacement', placement);
    })
    .first();
}

/**
 * Every freedom mode's pool on every Remnawave backend, each known node judged
 * (lib/edges/freedomDelivery.ts `withheldReason`): the enrolled nodes serving a
 * freedom mode whose gate is open (the gate already withholds the others from
 * everybody), the observed nodes serving a transport of a freedom group, and
 * the nodes active keys of a freedom group are pinned to (one indexed read per
 * pinned name and group). Read whether the switch is on or not: the preview
 * is what it WOULD withhold. Every backend is listed with every freedom mode,
 * known nodes or not: a group with keys and no known node is cut off.
 */
export async function freedomPools(ctx: { db: Db }): Promise<BackendPools[]> {
  const db = ctx.db;
  const { modes } = await resolveModeCatalog(db);
  const freedom = modes
    .filter((m) => m.family === FREEDOM_FAMILY)
    .sort((a, b) => a.id.localeCompare(b.id));
  if (freedom.length === 0) return [];
  const placements = new Map<string, string[]>(freedom.map((m) => [m.id, []]));
  for (const r of await db
    .query('modePlacements')
    .withIndex('by_backend', (q) => q.eq('backend', 'remnawave'))
    .collect())
    if (placements.has(r.modeSlug)) placements.set(r.modeSlug, poolFromConfig(r.config));
  const freedomGroups = [...new Set([...placements.values()].flat())].sort();
  const modesOfGroup = (p: string) =>
    [...placements].filter(([, pool]) => pool.includes(p)).map(([slug]) => slug);
  const servers = (await db.query('backendServers').collect())
    .filter((s) => s.backend === 'remnawave')
    .sort((a, b) => a.slug.localeCompare(b.slug));
  const out: BackendPools[] = [];
  for (const server of servers) {
    const sid = server._id;
    const setup = await db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .unique();
    const frontings = new Map((setup?.modes ?? []).map((m) => [m.slug, m.shape.fronting]));
    const groupOf = new Map((setup?.modes ?? []).map((m) => [m.slug, m.groupUuid ?? null]));
    const intents = (
      await db
        .query('panelNodeIntents')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((i) => i.state !== 'retiring' && i.state !== 'retired');
    const formers = await formerNamesByName(db, sid);
    const currentOf = new Map<string, string>();
    for (const [name, olds] of formers) for (const o of olds) currentOf.set(o, name);
    const enrolledNames = new Set(intents.map((i) => i.name));
    const enrolledUuids = new Set(intents.map((i) => i.nodeUuid).filter(Boolean));
    const known = new Map<
      string,
      {
        nodeUuid: string | null;
        enrolled: boolean;
        placements: Set<string>;
        modes: Set<string>;
        since: number | null;
      }
    >();
    const add = (name: string, nodeUuid: string | null, group: string) => {
      const k = known.get(name) ?? {
        nodeUuid,
        enrolled: false,
        placements: new Set<string>(),
        modes: new Set<string>(),
        since: null,
      };
      k.nodeUuid ??= nodeUuid;
      k.placements.add(group);
      for (const m of modesOfGroup(group)) k.modes.add(m);
      known.set(name, k);
    };
    // Enrolled nodes: their own mode, in the group the setup made for it.
    for (const i of intents) {
      if (!placements.has(i.mode) || i.delivery.disposition !== 'live' || i.maintenance) continue;
      const pool = placements.get(i.mode) ?? [];
      const group = groupOf.get(i.mode);
      known.set(i.name, {
        nodeUuid: i.nodeUuid ?? null,
        enrolled: true,
        placements: new Set(group && pool.includes(group) ? [group] : pool),
        modes: new Set([i.mode]),
        since: i.updatedAt,
      });
    }
    // Observed nodes serving a transport of a freedom group.
    const squads = (
      await db
        .query('panelSquads')
        .withIndex('by_server', (q) => q.eq('backendServerId', sid))
        .collect()
    ).filter((sq) => freedomGroups.includes(sq.squadUuid));
    for (const n of await db
      .query('panelNodes')
      .withIndex('by_server', (q) => q.eq('backendServerId', sid))
      .collect()) {
      if (n.isDisabled || enrolledNames.has(n.name) || enrolledUuids.has(n.nodeUuid)) continue;
      const served = new Set(n.activeInboundUuids);
      for (const sq of squads)
        if (sq.inboundUuids.some((u) => served.has(u))) add(n.name, n.nodeUuid, sq.squadUuid);
    }
    // Nodes active keys of a freedom group are pinned to (under any name they had).
    for (const name of await pinnedNodeNames(db, sid)) {
      const current = currentOf.get(name) ?? name;
      if (enrolledNames.has(current)) continue;
      for (const group of freedomGroups)
        if (await pinnedKey(db, sid, name, group)) add(current, null, group);
    }
    const nodes: PoolNode[] = [];
    for (const [name, k] of [...known].sort(([a], [b]) => a.localeCompare(b))) {
      const own = [...k.modes].sort();
      // An enrolled node at its own mode's layer, any other at its first mode's.
      const fronting = own[0] ? (frontings.get(own[0]) ?? null) : null;
      const protection = await protectionAt(ctx, sid, name);
      const relay = protection.bound ? await relayForBackendNode(db, sid, name) : null;
      nodes.push({
        node: name,
        pinNames: [name, ...(formers.get(name) ?? [])],
        nodeUuid: k.nodeUuid,
        enrolled: k.enrolled,
        placements: [...k.placements].sort(),
        modes: own,
        reason: withheldReason({ protection, enrolled: k.enrolled, fronting }),
        relaySlug: relay?.slug ?? null,
        since: k.since,
      });
    }
    out.push({
      backendServerId: sid,
      serverSlug: server.slug,
      modes: freedom.map((m) => ({
        mode: m.id,
        label: m.label ?? null,
        fronting: frontings.get(m.id) ?? null,
        placements: placements.get(m.id) ?? [],
      })),
      nodes,
    });
  }
  return out;
}

/**
 * Whether turning the switch on would stop handing any member their node: an
 * active key in a freedom group no servable node is known to serve, or one
 * pinned (under any name) to a withheld node. Indexed existence reads only
 * (one per group and per withheld node's name and group): what a mutation can
 * afford.
 */
async function anyMemberAffected(db: Db, pools: BackendPools[]): Promise<boolean> {
  for (const b of pools) {
    const sid = b.backendServerId;
    const servable = servableGroups(b);
    for (const p of groupsOf(b)) {
      if (servable.has(p)) continue;
      const key = await db
        .query('subscriptions')
        .withIndex('by_backend_server_state', (q) =>
          q.eq('backendServerId', sid).eq('state', 'active').eq('backendPlacement', p),
        )
        .first();
      if (key) return true;
    }
    for (const n of b.nodes) {
      if (n.reason === null) continue;
      for (const name of n.pinNames) {
        // An enrolled node's keys are held whatever their group.
        if (n.enrolled) {
          if (await pinnedKey(db, sid, name)) return true;
          continue;
        }
        for (const p of n.placements) if (await pinnedKey(db, sid, name, p)) return true;
      }
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
 * every mirror is rendered again in one full pass (`storage.drainMirrors`: a
 * held key's mirror gets the unavailable stub, a released one its body back).
 * The place tokens move with the switch, so no cached body outlives it.
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
      withheldNodes = pools.reduce(
        (x, b) => x + b.nodes.filter((n) => n.reason !== null).length,
        0,
      );
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
    // Every mirror now, not the six-hourly sweep's window: a full pass that
    // continues itself until it reached the last key.
    await ctx.scheduler.runAfter(0, internal.storage.drainMirrors, { cursor: null });
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
   * Active keys of the mode on this backend (`total`); those pinned to a
   * withheld node (`onWithheld`); those that move to a node that may serve
   * them at their next refresh (`moved`: on a withheld node, in a group a
   * servable node serves); those that get nothing (`cutOff`: every key of a
   * group no servable node is known to serve).
   */
  members: { total: number; onWithheld: number; cutOff: number; moved: number };
}

export interface FreedomPreview {
  on: boolean;
  modes: FreedomPreviewMode[];
  /** Each key counted once, whatever number of modes share its group. */
  totals: { withheldNodes: number; affectedMembers: number; cutOffMembers: number };
  /** A count stopped at its page cap: the figures are lower bounds. */
  approximate: boolean;
}

/**
 * What turning the switch on would close, read-only: per freedom mode and
 * backend, its nodes (servable, withheld and why) and its members (on a
 * withheld node, moved, cut off), judged group by group (a key's body carries
 * the nodes of its own group only). Never a group or an address.
 */
export const preview = internalAction({
  args: {},
  handler: async (ctx): Promise<FreedomPreview> => {
    const { on, pools } = await ctx.runQuery(internal.freedomDelivery.poolsForPreview, {});
    let approximate = false;
    const totals = new Map<string, number>();
    const totalOf = async (sid: Id<'backendServers'>, placement: string) => {
      const key = `${sid}:${placement}`;
      const known = totals.get(key);
      if (known !== undefined) return known;
      let total = 0;
      let cursor: string | null = null;
      for (let i = 0; i < MAX_COUNT_PAGES; i++) {
        const page: { count: number; next: string | null } = await ctx.runQuery(
          internal.freedomDelivery.countPlacementPage,
          { backendServerId: sid, placement, cursor },
        );
        total += page.count;
        cursor = page.next;
        if (!cursor) break;
        if (i === MAX_COUNT_PAGES - 1) approximate = true;
      }
      totals.set(key, total);
      return total;
    };
    const pinnedOf = async (sid: Id<'backendServers'>, nodeName: string) => {
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
      return acc;
    };
    const rows: FreedomPreviewMode[] = [];
    let withheldNodes = 0;
    let moved = 0;
    let cutOff = 0;
    for (const b of pools) {
      const sid = b.backendServerId;
      const servable = servableGroups(b);
      const groups = groupsOf(b);
      const withheld = b.nodes.filter((n) => n.reason !== null);
      withheldNodes += withheld.length;
      // Keys pinned to a withheld node, per group (each pinned name read once).
      const onWithheld = new Map<string, number>();
      for (const n of withheld)
        for (const name of n.pinNames)
          for (const [p, c] of Object.entries(await pinnedOf(sid, name)))
            if (n.enrolled || n.placements.includes(p))
              onWithheld.set(p, (onWithheld.get(p) ?? 0) + c);
      // The backend's figures, each key once: a group shared by several modes
      // is counted once; a key held only by its enrolled node's mode gets nothing.
      for (const p of groups)
        if (servable.has(p)) moved += onWithheld.get(p) ?? 0;
        else cutOff += await totalOf(sid, p);
      for (const [p, c] of onWithheld) if (!groups.has(p)) cutOff += c;
      for (const m of b.modes) {
        const nodes = b.nodes.filter((n) => n.modes.includes(m.mode));
        let total = 0;
        let mCut = 0;
        let mMoved = 0;
        let mOn = 0;
        for (const p of m.placements) {
          const t = await totalOf(sid, p);
          total += t;
          mOn += onWithheld.get(p) ?? 0;
          if (servable.has(p)) mMoved += onWithheld.get(p) ?? 0;
          else mCut += t;
        }
        if (nodes.length === 0 && total === 0) continue;
        const held = nodes.filter((n) => n.reason !== null);
        rows.push({
          serverSlug: b.serverSlug,
          mode: m.mode,
          label: m.label,
          fronting: m.fronting,
          nodes: {
            total: nodes.length,
            servable: nodes.length - held.length,
            withheld: held.length,
          },
          withheldNodes: held.map((n) => ({
            node: n.node,
            nodeUuid: n.nodeUuid,
            enrolled: n.enrolled,
            reason: n.reason!,
          })),
          members: { total, onWithheld: mOn, cutOff: mCut, moved: mMoved },
        });
      }
    }
    return {
      on,
      modes: rows,
      totals: { withheldNodes, affectedMembers: moved + cutOff, cutOffMembers: cutOff },
      approximate,
    };
  },
});

// --- attention ---------------------------------------------------------------------------------------

/**
 * While the switch is on: one item per node withheld from the freedom
 * members it serves (`freedom_node_withheld`, the reason as its code), naming
 * the backend, the node and its freedom modes, never an address. The action
 * goes where the reason is fixed: protecting the node, its origin, or the
 * modes.
 */
export async function freedomAttention(ctx: { db: Db }): Promise<AttentionItem[]> {
  if (!(await freedomEdgesOnly(ctx.db))) return [];
  const out: AttentionItem[] = [];
  for (const b of await freedomPools(ctx)) {
    for (const n of b.nodes) {
      if (n.reason === null) continue;
      const action =
        n.reason === 'withheld_direct_mode'
          ? 'open_modes'
          : n.reason === 'withheld_no_edge'
            ? 'open_relay'
            : 'protect_node';
      out.push({
        id: `freedom_node_withheld:${b.backendServerId}:${n.node}`,
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
          serverSlug: b.serverSlug,
          node: n.node,
          ...(n.nodeUuid ? { nodeUuid: n.nodeUuid } : {}),
          mode: n.modes[0] ?? null,
          modes: n.modes,
          enrolled: n.enrolled,
        },
        action,
        since: n.since ? new Date(n.since).toISOString() : null,
      });
    }
  }
  return out;
}
