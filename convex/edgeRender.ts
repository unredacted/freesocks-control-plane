/**
 * Relay rendering, DB half: resolve what a subscription's origin publishes
 * (edges, listeners, the client-family rule) so the fronted /sub route, the
 * mirror refresh and the admin preview can apply the pure renderer, and judge
 * the EDGE-REQUIRED delivery policy.
 *
 * A subscription is edge-required when a delivery binding (relays.ts) covers
 * the node it actually resolved to or its whole backend server. For such a
 * subscription the route serves a rendered body that passed every check, or an
 * unavailable response: never the origin body, whatever switch is off.
 * `epochFor` is the cache token: the origin's publication epoch together with
 * the binding's policy version while the subscription is edge-required, null
 * for a subscription no relay covers.
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
import { capabilitiesOf } from './lib/backends/capabilities';
import {
  effectiveRule,
  renderEntries,
  type DeliveryStyle,
  type RenderMatcher,
} from './lib/edges/render';
import { assignEndpoints } from './lib/edges/assignment';
import type { PublishedEdge } from './lib/edges/assignment';
import { protocolUsesSni } from './lib/edges/protocols';
import { parseIntent } from './lib/edges/intent';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import type { EdgeRenderContext } from './lib/edges/renderPipeline';
import { deliveryBindingFor, relayForBackendNode } from './relays';
import { listenersOf } from './relayListeners';

const familyValidator = v.union(
  ...(RENDER_CLIENT_FAMILIES.map((f) => v.literal(f)) as [
    ReturnType<typeof v.literal>,
    ...ReturnType<typeof v.literal>[],
  ]),
);

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

/**
 * Whether an L7 edge's stored qualification still proves what would be RENDERED
 * for it: the binding is re-derived from the live listener/intent, exactly as
 * publication does.
 */
export async function l7QualificationCurrent(
  edge: Doc<'edges'>,
  listener: Doc<'relayListeners'> | null | undefined,
  now: number,
): Promise<boolean> {
  if (!listener) return false;
  const intent = parseIntent(edge.provisionIntent);
  if (!intent) return false;
  return (
    qualificationVerdict(
      edge.frontQualification,
      qualificationBinding({ listener, intent, params: listener.transportParams ?? {} }),
      now,
    ) === 'ok'
  );
}

export function matcherOf(l: Doc<'relayListeners'>, originAddress: string): RenderMatcher {
  return {
    listenerKey: l.listenerKey,
    rule: l.matchRule,
    legacyRemarks: (l.legacyHosts ?? []).map((h) => h.remark),
    proto: { protocol: l.protocol, streamTransport: l.streamTransport, security: l.security },
    originAddress,
    originPort: l.originPort,
  };
}

/**
 * Published edges in pool order. By default only edges with an eligible
 * listener (and an address) are returned. With `includeIneligible` every
 * published, active edge is returned and the ineligible ones (listener
 * retired, undeployed or disabled, no address, lapsed L7 proof) carry
 * `eligible:false`: they keep their pool index in the assignment modulus.
 */
export async function publishedEdgesOf(
  ctx: { db: QueryCtx['db'] },
  origin: Doc<'relays'>,
  opts: { includeIneligible?: boolean } = {},
): Promise<{ published: PublishedEdge[]; matchers: RenderMatcher[] }> {
  const listeners = await listenersOf(ctx, origin._id);
  const matchers = listeners
    .filter((l) => !l.retired && l.deployed && l.enabled)
    .map((l) => matcherOf(l, origin.originAddress));
  const published: PublishedEdge[] = [];
  const now = Date.now();
  for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
    const edgeId = origin.publishedEdgeIds[i];
    if (!edgeId) continue;
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.publication !== 'published' || edge.status !== 'active') continue;
    const listener = listeners.find((l) => l._id === edge.listenerId) ?? null;
    const hasAddress = !!edge.addresses.v4 || !!edge.addresses.v6 || !!edge.addresses.hostname;
    // An L7 front is only as good as its last PROOF.
    const l7Proven =
      (edge.layer ?? 'l4') !== 'l7' || (await l7QualificationCurrent(edge, listener, now));
    const eligible =
      hasAddress &&
      l7Proven &&
      !!listener &&
      !listener.retired &&
      listener.deployed &&
      listener.enabled;
    if (!eligible && !opts.includeIneligible) continue;
    if (!listener) continue; // no listener at all: nothing to render from
    const proto = {
      protocol: listener.protocol,
      streamTransport: listener.streamTransport,
      security: listener.security,
    };
    published.push({
      edgeId: edge._id,
      poolIndex: edge.poolIndex ?? i,
      provider: edge.provider ?? 'adopted',
      listenerId: listener._id,
      listenerKey: listener.listenerKey,
      matchRule: listener.matchRule,
      proto,
      edgePort: edge.listeners[0]?.edgePort ?? 443,
      layer: edge.layer ?? 'l4',
      addresses: {
        v4: edge.addresses.v4,
        v6: edge.addresses.v6,
        hostname: edge.addresses.hostname,
      },
      serverNames: protocolUsesSni(proto)
        ? (listener.tlsNames ?? []).map((s) => ({
            sni: s.name,
            status: s.status,
            retiredAt: s.retiredAt,
            drainUntil: s.drainUntil,
          }))
        : [],
      ...(eligible ? {} : { eligible: false }),
    });
  }
  return { published, matchers };
}

/** Delivery style of a backend: Outline hands out ONE key, a panel a subscription. */
export async function deliveryStyleOf(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
): Promise<DeliveryStyle> {
  const server = await ctx.db.get(backendServerId);
  return server && capabilitiesOf(server.backend).accessKeyDelivery ? 'single-key' : 'subscription';
}

export interface DeliveryPolicy {
  /** The subscription's resolved place is covered by an active binding. */
  required: boolean;
  bindingVersion: number | null;
  relayId: Id<'relays'> | null;
  relaySlug: string | null;
}

/**
 * The delivery policy for a subscription at the place it RESOLVED to (the node
 * the body was pinned to, or the whole server). Evaluated AFTER the fetch by
 * the route, so a first fetch with no stored pin and a pin that moved onto a
 * relay node are both classified by the node the body belongs to.
 */
export async function deliveryPolicyFor(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<DeliveryPolicy> {
  const binding = await deliveryBindingFor(ctx.db, backendServerId, nodeName);
  if (!binding) return { required: false, bindingVersion: null, relayId: null, relaySlug: null };
  const relay = await relayForBackendNode(ctx.db, backendServerId, nodeName);
  return {
    required: true,
    bindingVersion: binding.policyVersion,
    relayId: relay?._id ?? null,
    relaySlug: binding.relaySlug,
  };
}

export const deliveryPolicy = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: (ctx, { backendServerId, nodeName }) =>
    deliveryPolicyFor(ctx, backendServerId, nodeName),
});

/**
 * Cache token for a subscription's place: `<policyVersion>:<epoch>` while the
 * place is edge-required (the epoch is the relay's, or -1 when the binding has
 * no live relay), null for a place no relay covers (raw delivery, no token).
 */
export const epochFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: async (ctx, { backendServerId, nodeName }): Promise<string | null> => {
    const policy = await deliveryPolicyFor(ctx, backendServerId, nodeName);
    if (!policy.required) return null;
    const relay = policy.relayId ? await ctx.db.get(policy.relayId) : null;
    const renderOn = await renderEnabled(ctx);
    return `${policy.bindingVersion}:${relay && relay.enabled && renderOn ? relay.publicationEpoch : -1}`;
  },
});

export interface SubscriptionRenderContext extends EdgeRenderContext {
  relayId: Id<'relays'>;
  renderKey: string | null;
}

export type SubscriptionRenderDecision =
  | { kind: 'raw' }
  | { kind: 'render'; context: SubscriptionRenderContext }
  | {
      kind: 'unavailable';
      reason: 'render_disabled' | 'relay_disabled' | 'relay_missing' | 'no_render_key';
      relaySlug: string | null;
    };

/**
 * What the route must do with a fetched body for one subscription + client
 * family at the place it resolved to: pass it through (no relay covers the
 * place), render it, or refuse it (edge-required but nothing can render).
 * `nodeName` is the node the body was pinned to (the route knows it before the
 * row is updated); absent = the whole backend server.
 */
export const decideForSubscription = internalQuery({
  args: {
    subscriptionId: v.id('subscriptions'),
    family: familyValidator,
    nodeName: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<SubscriptionRenderDecision> => {
    const sub = await ctx.db.get(a.subscriptionId);
    if (!sub || !sub.backendServerId) return { kind: 'raw' };
    const node = a.nodeName ?? sub.pinnedNode ?? undefined;
    const policy = await deliveryPolicyFor(ctx, sub.backendServerId, node);
    if (!policy.required) return { kind: 'raw' };
    const relay = policy.relayId ? await ctx.db.get(policy.relayId) : null;
    if (!relay)
      return { kind: 'unavailable', reason: 'relay_missing', relaySlug: policy.relaySlug };
    if (!relay.enabled)
      return { kind: 'unavailable', reason: 'relay_disabled', relaySlug: relay.slug };
    if (!(await renderEnabled(ctx)))
      return { kind: 'unavailable', reason: 'render_disabled', relaySlug: relay.slug };
    const cfg = await resolveEdgeConfig(ctx.db);
    if (!cfg.render.enabled)
      return { kind: 'unavailable', reason: 'render_disabled', relaySlug: relay.slug };
    const family = a.family as RenderClientFamily;
    const rule = effectiveRule(cfg.render, cfg.render.clients[family]);
    // A family whose rule is off used to pass the panel body through; under
    // edge-required delivery there is no passthrough, so it is unavailable.
    if (!rule.enabled)
      return { kind: 'unavailable', reason: 'render_disabled', relaySlug: relay.slug };
    // A key that has never been rendered has no render key yet: the caller
    // mints one (`subscriptions.ensureRenderKey`) and refuses only if that fails.
    const { published, matchers } = await publishedEdgesOf(ctx, relay, { includeIneligible: true });
    return {
      kind: 'render',
      context: {
        relayId: relay._id,
        epoch: relay.publicationEpoch,
        matchers,
        published,
        rule,
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        renderKey: sub.renderKey ?? null,
        originAddress: relay.originAddress,
        deliveryStyle: await deliveryStyleOf(ctx, sub.backendServerId),
      },
    };
  },
});

/**
 * The member-facing nudge (account node status): whether this key has fetched
 * content since its origin last changed, and the LABELS of the connections its
 * last render carried (roles + address family only, never addresses). Read
 * from the persisted render snapshot: never reconstructed without the body.
 */
export const memberView = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (
    ctx,
    { subscriptionId },
  ): Promise<{
    refreshSuggested: boolean;
    /** `unknown` = the key has no render snapshot yet (labels cannot be trusted). */
    known: boolean;
    connections: Array<{ label: string; role: 'primary' | 'backup'; family: 'v4' | 'v6' | 'name' }>;
  } | null> => {
    const sub = await ctx.db.get(subscriptionId);
    if (!sub || !sub.backendServerId) return null;
    const policy = await deliveryPolicyFor(ctx, sub.backendServerId, sub.pinnedNode ?? undefined);
    if (!policy.required || !policy.relayId) return null;
    const origin = await ctx.db.get(policy.relayId);
    if (!origin || !origin.enabled) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const snap = sub.lastRender;
    const refreshSuggested =
      (snap !== undefined && snap.epoch < origin.publicationEpoch) ||
      (snap === undefined &&
        origin.lastRotatedAt !== undefined &&
        (sub.lastDeliveredContentAt ?? 0) < origin.lastRotatedAt);
    if (!snap || snap.epoch !== origin.publicationEpoch)
      return { refreshSuggested, known: false, connections: [] };
    // Rebuild the labels from the snapshot's edges only (no body needed).
    const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
    const byId = new Map(published.map((p) => [p.edgeId, p]));
    const primary = snap.primaryEdgeId ? byId.get(snap.primaryEdgeId) : undefined;
    const backup = snap.backupEdgeId ? byId.get(snap.backupEdgeId) : undefined;
    if (!primary) return { refreshSuggested: true, known: false, connections: [] };
    const rule = effectiveRule(cfg.render, cfg.render.clients.other);
    const assigned = assignEndpoints(sub.renderKey ?? '', [primary, ...(backup ? [backup] : [])], {
      now: Date.now(),
      preferDistinctProviders: cfg.render.preferDistinctProviders,
      includeBackup: rule.includeBackup && !!backup,
      canEmitV6: rule.ipv6Mode === 'both',
    });
    const connections = renderEntries(assigned, rule, false, origin.originAddress).map((e) => ({
      label: e.label,
      role: e.role,
      family: e.family,
    }));
    return { refreshSuggested, known: true, connections };
  },
});
