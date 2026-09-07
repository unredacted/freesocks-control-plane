/**
 * Relay rendering, DB half: resolve what a subscription's pinned node publishes
 * (edges, slots, profiles, the client-family rule) so the fronted /sub route,
 * the mirror refresh and the admin preview can apply the pure renderer.
 *
 * Rendering is ACTIVE for a (panel, node) pair when the global render switch is
 * on, an enabled origin exists for the node and it has at least one published
 * edge with an eligible slot/profile. `epochFor` returns the cache token the
 * /sub route stores on each cache entry: the origin's publication epoch while
 * active, null otherwise — so a cache hit is only served when nothing about the
 * published pool or the switch changed since the entry was written.
 */
import { v } from 'convex/values';
import { internalQuery } from './_generated/server';
import type { QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import {
  resolveEdgeConfig,
  RENDER_CLIENT_FAMILIES,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { effectiveRule, renderEntries } from './lib/edges/render';
import { assignEndpoints } from './lib/edges/assignment';
import type { PublishedEdge } from './lib/edges/assignment';
import { protocolUsesSni } from './lib/edges/protocols';
import type { EdgeRenderContext } from './lib/edges/renderPipeline';

const familyValidator = v.union(
  ...(RENDER_CLIENT_FAMILIES.map((f) => v.literal(f)) as [
    ReturnType<typeof v.literal>,
    ...ReturnType<typeof v.literal>[],
  ]),
);

async function relayFor(
  ctx: QueryCtx,
  backendServerId: Id<'backendServers'>,
  nodeHostname: string,
): Promise<Doc<'relays'> | null> {
  const rows = await ctx.db
    .query('relays')
    .withIndex('by_node_hostname', (q) => q.eq('nodeHostname', nodeHostname))
    .collect();
  return rows.find((r) => r.backendServerId === backendServerId) ?? null;
}

async function renderEnabled(ctx: QueryCtx): Promise<boolean> {
  const row = await ctx.db
    .query('appSettings')
    .withIndex('by_key', (q) => q.eq('key', 'edge.render.enabled'))
    .unique();
  if (!row) return false;
  try {
    return JSON.parse(row.value) === true;
  } catch {
    return false;
  }
}

/** Published edges with an eligible slot + profile, in pool order. */
export async function publishedEdgesOf(
  ctx: QueryCtx | { db: import('./_generated/server').DatabaseReader },
  origin: Doc<'relays'>,
): Promise<{ published: PublishedEdge[]; templateRemarks: string[] }> {
  const slots = await ctx.db
    .query('relaySlots')
    .withIndex('by_relay', (q) => q.eq('relayId', origin._id))
    .collect();
  const templateRemarks = slots.map((s) => s.templateHostRemark);
  const published: PublishedEdge[] = [];
  for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
    const edgeId = origin.publishedEdgeIds[i];
    if (!edgeId) continue;
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.publication !== 'published' || edge.status !== 'active') continue;
    if (!edge.addresses.v4 && !edge.addresses.v6) continue;
    const slot = slots.find((s) => s._id === edge.slotId);
    if (!slot || slot.retired || !slot.deployed) continue;
    const profile = await ctx.db.get(slot.profileId);
    if (!profile || !profile.enabled) continue;
    published.push({
      edgeId: edge._id,
      poolIndex: edge.poolIndex ?? i,
      provider: edge.provider ?? 'adopted',
      slotId: slot._id,
      slotRemark: slot.templateHostRemark,
      protocol: profile.protocol,
      edgePort: edge.listeners[0]?.edgePort ?? 443,
      addresses: { v4: edge.addresses.v4, v6: edge.addresses.v6 },
      serverNames: protocolUsesSni(profile.protocol)
        ? profile.serverNames.map((s) => ({
            sni: s.sni,
            status: s.status,
            retiredAt: s.retiredAt,
            drainUntil: s.drainUntil,
          }))
        : [],
    });
  }
  return { published, templateRemarks };
}

/**
 * Cache token for a (panel, node): the publication epoch while rendering is
 * active for it, else null. Cheap: a few point reads, no config resolve.
 */
export const epochFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeHostname: v.string() },
  handler: async (ctx, { backendServerId, nodeHostname }): Promise<number | null> => {
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, backendServerId, nodeHostname);
    if (!origin || !origin.enabled) return null;
    const { published } = await publishedEdgesOf(ctx, origin);
    return published.length > 0 ? origin.publicationEpoch : null;
  },
});

export interface SubscriptionRenderContext extends EdgeRenderContext {
  relayId: Id<'relays'>;
  renderKey: string | null;
  lastContentAt: number | null;
}

/**
 * Everything the renderer needs for one subscription + client family, or null
 * when rendering is inactive for its node (the body then passes through).
 * `nodeHostname` overrides the stored pin (the /sub route knows the node it
 * just pinned before the row is updated).
 */
export const contextForSubscription = internalQuery({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: familyValidator,
    nodeHostname: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<SubscriptionRenderContext | null> => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || !sub.backendServerId) return null;
    const node = a.nodeHostname ?? sub.pinnedNode;
    if (!node) return null;
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, sub.backendServerId, node);
    if (!origin || !origin.enabled) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    if (!cfg.render.enabled) return null;
    const { published, templateRemarks } = await publishedEdgesOf(ctx, origin);
    if (published.length === 0) return null;
    const family = a.family as RenderClientFamily;
    return {
      relayId: origin._id,
      epoch: origin.publicationEpoch,
      templateRemarks,
      published,
      rule: effectiveRule(cfg.render, cfg.render.clients[family]),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      renderKey: sub.renderKey ?? null,
      lastContentAt: sub.lastDeliveredContentAt ?? null,
    };
  },
});

/** Admin preview / endpoint view: the published pool of one origin as the renderer sees it. */
export const contextForRelay = internalQuery({
  args: { relayId: v.id('relays'), family: familyValidator },
  handler: async (ctx, a): Promise<EdgeRenderContext | null> => {
    const origin = await ctx.db.get(a.relayId);
    if (!origin) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published, templateRemarks } = await publishedEdgesOf(ctx, origin);
    const family = a.family as RenderClientFamily;
    return {
      epoch: origin.publicationEpoch,
      templateRemarks,
      published,
      rule: effectiveRule(cfg.render, cfg.render.clients[family]),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
    };
  },
});

/**
 * The member-facing nudge (account node status): whether this key has fetched
 * content since its origin last rotated, and the LABELS of the connections its
 * current subscription carries (roles + address family only, never addresses).
 */
export const memberView = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (
    ctx,
    { subscriptionId },
  ): Promise<{
    refreshSuggested: boolean;
    connections: Array<{ label: string; role: 'primary' | 'backup'; family: 'v4' | 'v6' }>;
  } | null> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub || !sub.backendServerId || !sub.pinnedNode) return null;
    if (!(await renderEnabled(ctx))) return null;
    const origin = await relayFor(ctx, sub.backendServerId, sub.pinnedNode);
    if (!origin || !origin.enabled) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const { published } = await publishedEdgesOf(ctx, origin);
    if (published.length === 0) return null;
    const refreshSuggested =
      origin.lastRotatedAt !== undefined &&
      (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt;
    let connections: Array<{ label: string; role: 'primary' | 'backup'; family: 'v4' | 'v6' }> = [];
    if (sub.renderKey) {
      const rule = effectiveRule(cfg.render, cfg.render.clients.other);
      const assigned = assignEndpoints(sub.renderKey, published, {
        now: Date.now(),
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        includeBackup: rule.includeBackup,
        subscriberLastContentAt: sub.lastDeliveredContentAt ?? null,
      });
      connections = renderEntries(assigned, rule, false).map((e) => ({
        label: e.label,
        role: e.role,
        family: e.family,
      }));
    }
    return { refreshSuggested, connections };
  },
});
