/**
 * Which clients a node's REALITY transports let in (docs/edges.md § "REALITY
 * client versions"; the verdict is src/shared/contracts/realityClients.ts). A
 * transport with no `minClientVer` on Xray v26.7.11 to v26.7.28 refuses every
 * sing-box and Mihomo client while an Xray client connects, so a human test
 * with an Xray client passes and members on the others break. FCP's own
 * profile template sets `1.8.1`; a node FCP did not build (adopted, or not
 * managed at all) is read here.
 *
 * READ-ONLY toward the panel: the transport's two bounds and the node's Xray
 * version are read live (`checkTransports`). The protect plan asks before
 * anything is bought, the run's test card when it is built, and the edge
 * reconcile for every bound origin (`reobserve`), whose verdict is kept on the
 * origin (`relays.realityClients`) for attention `reality_refuses_clients`.
 * A warning everywhere: nothing is refused for it.
 */
import { v } from 'convex/values';
import type { ActionCtx } from './_generated/server';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { PROVIDERS, type BackendConfig } from './lib/backends/registry';
import { panelDigestKey } from './lib/backend/key';
import { realityClientRefusalV } from './lib/realityClients';
import {
  realityClientRefusal,
  sameRefusal,
  type RealityClientRefusal,
} from '../src/shared/contracts/realityClients';

/** One REALITY transport to judge: its key in the caller's terms, and where it is on the panel. */
export interface RealityTransportRef {
  key: string;
  profileUuid: string;
  tag: string;
}

/** A transport the panel described: what it refuses (null = sing-box and Mihomo get in). */
export interface RealityClientsCheck {
  key: string;
  tag: string;
  refusal: RealityClientRefusal | null;
}

/**
 * Judge these transports of one node from the panel now. Never throws: a
 * transport the panel could not describe (gone, no usable key, the panel did
 * not answer) is left out, and an Xray version that could not be read is
 * unknown (`core_unknown` where no `minClientVer` is set).
 */
export async function checkTransports(
  ctx: Pick<ActionCtx, 'runQuery'>,
  a: {
    backendServerId: Id<'backendServers'>;
    nodeUuid?: string;
    nodeName?: string;
    transports: readonly RealityTransportRef[];
  },
): Promise<RealityClientsCheck[]> {
  if (a.transports.length === 0) return [];
  try {
    const server = await ctx.runQuery(internal.backendServers.getById, { id: a.backendServerId });
    const provider = server ? PROVIDERS[server.backend] : undefined;
    const writes = provider?.backendWrites;
    if (!server || !provider || !writes) return [];
    const config = server.config as BackendConfig;
    const { key } = await panelDigestKey();
    let xrayVersion: string | null = null;
    try {
      const nodes = (await provider.getNodeInventory?.(config)) ?? [];
      const node =
        nodes.find((n) => !!a.nodeUuid && n.nodeUuid === a.nodeUuid) ??
        nodes.find((n) => !a.nodeUuid && !!a.nodeName && n.name === a.nodeName);
      xrayVersion = node?.xrayVersion ?? null;
    } catch {
      /* the version stays unknown */
    }
    const out: RealityClientsCheck[] = [];
    for (const t of a.transports) {
      try {
        const params = await writes.readInboundForTest(config, t.profileUuid, t.tag, key);
        if (!params) continue;
        out.push({
          key: t.key,
          tag: t.tag,
          refusal: realityClientRefusal(params.clientBounds, xrayVersion),
        });
      } catch {
        /* not described now: left out */
      }
    }
    return out;
  } catch {
    return [];
  }
}

const transportRefV = v.object({ key: v.string(), profileUuid: v.string(), tag: v.string() });

/** `checkTransports` as an action (the protect plan's seam). */
export const check = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.optional(v.string()),
    nodeName: v.optional(v.string()),
    transports: v.array(transportRefV),
  },
  handler: (ctx, a): Promise<RealityClientsCheck[]> => checkTransports(ctx, a),
});

/**
 * An origin's REALITY listeners as the panel binds them (key = listener key),
 * with the node they are on; null for an origin that is not a backend node.
 */
export const relayTransports = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.backendServerId) return null;
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    return {
      backendServerId: relay.backendServerId,
      nodeUuid: relay.origin.kind === 'panel-node' ? relay.origin.nodeUuid : undefined,
      nodeName: relay.nodeName,
      transports: listeners
        .filter((l) => !l.retired && l.security === 'reality' && !!l.panelBinding)
        .map((l) => ({
          key: l.listenerKey,
          profileUuid: l.panelBinding!.configProfileUuid,
          tag: l.panelBinding!.inboundTag,
        })),
    };
  },
});

/** Judge an origin's REALITY listeners now (by listener key; the run's test card). */
export async function checkRelay(
  ctx: Pick<ActionCtx, 'runQuery'>,
  relayId: Id<'relays'>,
  listenerKeys?: readonly string[],
): Promise<RealityClientsCheck[]> {
  const r = await ctx.runQuery(internal.edgeRealityClients.relayTransports, { relayId });
  if (!r) return [];
  const wanted = listenerKeys ? new Set(listenerKeys) : null;
  return checkTransports(ctx, {
    backendServerId: r.backendServerId,
    nodeUuid: r.nodeUuid,
    nodeName: r.nodeName,
    transports: r.transports.filter((t) => !wanted || wanted.has(t.key)),
  });
}

/** `checkRelay` as an action (the run's seam). */
export const forRelay = internalAction({
  args: { relayId: v.id('relays'), listenerKeys: v.optional(v.array(v.string())) },
  handler: (ctx, a): Promise<RealityClientsCheck[]> => checkRelay(ctx, a.relayId, a.listenerKeys),
});

const refusalRowV = v.object({
  listenerKey: v.string(),
  tag: v.string(),
  refusal: realityClientRefusalV,
});

/**
 * Keep one look's verdict on the origin (`relays.realityClients`), written only
 * when it moved. `looked` names the listeners the panel described: one it
 * could not describe this time keeps what was known of it, while it is still
 * one of the origin's REALITY listeners (`current`).
 */
export const note = internalMutation({
  args: {
    relayId: v.id('relays'),
    current: v.array(v.string()),
    looked: v.array(v.string()),
    refusals: v.array(refusalRowV),
  },
  handler: async (ctx, { relayId, current, looked, refusals }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const keep = new Set(current.filter((k) => !looked.includes(k)));
    const prev = relay.realityClients?.refusals ?? [];
    const next = [
      ...prev.filter((p) => keep.has(p.listenerKey)),
      ...refusals.map((r) => ({ listenerKey: r.listenerKey, tag: r.tag, ...r.refusal })),
    ].sort((a, b) => a.listenerKey.localeCompare(b.listenerKey));
    const same =
      next.length === prev.length &&
      next.every(
        (n, i) =>
          prev[i]!.listenerKey === n.listenerKey &&
          prev[i]!.tag === n.tag &&
          sameRefusal(prev[i], n),
      );
    if (same) return null;
    await ctx.db.patch(relayId, {
      realityClients: next.length > 0 ? { at: Date.now(), refusals: next } : undefined,
    });
    return null;
  },
});

/**
 * The edge reconcile's look (hostOps.reconcileHosts, after the direct-Host
 * check): every bound origin's REALITY listeners judged from the panel. One
 * origin that cannot be looked at never stops the others.
 */
export const reobserve = internalAction({
  args: {},
  handler: async (ctx): Promise<{ relays: number; refusing: number }> => {
    const ids = await ctx.runQuery(internal.edgeHostHides.boundRelays, {});
    const report = { relays: 0, refusing: 0 };
    for (const relayId of ids) {
      const r = await ctx.runQuery(internal.edgeRealityClients.relayTransports, { relayId });
      if (!r) continue;
      const checks = await checkTransports(ctx, r);
      const tags = new Map(r.transports.map((t) => [t.key, t.tag]));
      const refusals = checks
        .filter((c) => c.refusal !== null)
        .map((c) => ({ listenerKey: c.key, tag: tags.get(c.key) ?? c.tag, refusal: c.refusal! }));
      await ctx.runMutation(internal.edgeRealityClients.note, {
        relayId,
        current: r.transports.map((t) => t.key),
        looked: checks.map((c) => c.key),
        refusals,
      });
      report.relays++;
      if (refusals.length > 0) report.refusing++;
    }
    return report;
  },
});

/**
 * Rollback (docs/edges.md "Deploy notes"): the older schema has no
 * `relays.realityClients`, `edgeSetupRuns.testLinks[].realityClients`,
 * `panelNodes.xrayVersion` or `panelProfiles.inbounds[].realityClients`.
 */
export const clearForRollback = internalMutation({
  args: {},
  handler: async (ctx) => {
    const cleared = { relays: 0, runs: 0, nodes: 0, profiles: 0 };
    for (const relay of await ctx.db.query('relays').collect()) {
      // small operator table
      if (!relay.realityClients) continue;
      await ctx.db.patch(relay._id, { realityClients: undefined });
      cleared.relays++;
    }
    for (const run of await ctx.db.query('edgeSetupRuns').collect()) {
      if (!run.testLinks?.some((t) => t.realityClients !== undefined)) continue;
      await ctx.db.patch(run._id, {
        testLinks: run.testLinks.map(({ realityClients: _r, ...t }) => t),
      });
      cleared.runs++;
    }
    for (const node of await ctx.db.query('panelNodes').collect()) {
      if (node.xrayVersion === undefined) continue;
      await ctx.db.patch(node._id, { xrayVersion: undefined });
      cleared.nodes++;
    }
    for (const p of await ctx.db.query('panelProfiles').collect()) {
      if (!p.inbounds.some((i) => i.realityClients !== undefined)) continue;
      await ctx.db.patch(p._id, {
        inbounds: p.inbounds.map(({ realityClients: _r, ...i }) => i),
      });
      cleared.profiles++;
    }
    return cleared;
  },
});
