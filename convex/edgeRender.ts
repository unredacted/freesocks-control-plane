/**
 * Origin rendering, DB half: resolve what a subscription's origin publishes
 * (edges, listeners, the client-family rule) so the fronted /sub route, the
 * mirror refresh and the admin preview can apply the pure renderer, and judge
 * the EDGE-REQUIRED delivery policy.
 *
 * A subscription is edge-required when a delivery binding (origins.ts) covers
 * the node it actually resolved to or its whole backend server. For such a
 * subscription the route serves a rendered body that passed every check, or an
 * unavailable response: never the origin body, whatever switch is off.
 * `epochFor` is the cache token: the origin's publication epoch together with
 * the binding's policy version while the subscription is edge-required, null
 * for a subscription no origin covers.
 */
import { locationKeyOf } from './lib/edges/locations';
import { verificationListenersOf } from './lib/edges/verificationContext';
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import type { QueryCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import {
  resolveEdgeConfig,
  RENDER_CLIENT_FAMILIES,
  type RenderClientFamily,
} from './lib/edgeConfig';
import { liveCountryState } from './lib/edges/country/group';
import { ELSEWHERE, liveChoice } from './lib/memberCountry';
import { memberFamilyOf } from './lib/memberFamily';
import { resolveMemberCountryConfig } from './memberCountry';
import { capabilitiesOf } from './lib/backends/capabilities';
import {
  effectiveRule,
  renderEntries,
  type DeliveryStyle,
  type RenderMatcher,
} from './lib/edges/render';
import { assignEndpoints, endpointsFor } from './lib/edges/assignment';
import type { CountryContext, PublishedEdge } from './lib/edges/assignment';
import { protocolUsesSni } from './lib/edges/protocols';
import { parseIntent } from './lib/edges/intent';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import { needsEndpointVerification, verificationCurrent } from './lib/edges/verification';
import type { EdgeRenderContext } from './lib/edges/renderPipeline';
import { gateToken, isCandidateEdge, type NodeGate } from './lib/backend/deliveryGate';
import { nodeAddressesOf, nodeGateFor } from './nodeIntents';
import { deliveryBindingFor, relayForBackendNode } from './relays';
import { listenersOf } from './relayListeners';
import { resolveSniConfig } from './lib/sniConfig';
import { resolveWhere } from './lib/edges/sni/country';
import { freedomEdgesOnly, freedomHoldOf, type NodeProtection } from './lib/edges/freedomDelivery';
import type { EdgeLayer } from '../src/shared/contracts/edges';
import { lanesOn } from './lib/edges/lanes';
import { memberLaneOfUser } from './edgeLanes';

const familyValidator = v.union(
  ...(RENDER_CLIENT_FAMILIES.map((f) => v.literal(f)) as [
    ReturnType<typeof v.literal>,
    ...ReturnType<typeof v.literal>[],
  ]),
);

async function renderEnabled(ctx: { db: QueryCtx['db'] }): Promise<boolean> {
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
    legacyRemarks: [...(l.legacyHosts ?? []).map((h) => h.remark), ...(l.formerRemarks ?? [])],
    proto: { protocol: l.protocol, streamTransport: l.streamTransport, security: l.security },
    originAddress,
    originPort: l.originPort,
  };
}

/**
 * Which published edges a render may select (docs/servers.md "Node
 * lifecycle"). Required, never defaulted:
 *  - `member`: what members are served. Every candidate of an activation
 *    (the node gate's candidate set) is dropped: a live node's replacement
 *    never reaches a member body, a cached body or a mirror before its commit.
 *    The only context the member paths (the /sub route, mirrors, previews)
 *    can build.
 *  - `activation`: INTERNAL, the rehearsal of one activation run: exactly that
 *    run's candidate set (verified to be the node's current run), so a live
 *    node's replacement rehearses the candidates, not the committed edges. A
 *    render under it writes nothing (no binding, cache, mirror, pin or
 *    snapshot).
 */
export type EdgeSelectionContext =
  | { kind: 'member' }
  | { kind: 'activation'; activationRunId: Id<'panelActivationRuns'> };

/** The edges an activation run's rehearsal renders: null when the run is not the node's current, running one. */
async function activationCandidatesOf(
  ctx: { db: QueryCtx['db'] },
  origin: Doc<'relays'>,
  activationRunId: Id<'panelActivationRuns'>,
): Promise<Set<string> | null> {
  const run = await ctx.db.get(activationRunId);
  if (!run || run.state !== 'running') return null;
  const intent = await ctx.db.get(run.intentId);
  if (
    !intent ||
    intent.activation.currentRunId !== run._id ||
    origin.origin.kind !== 'panel-node' ||
    intent.backendServerId !== origin.backendServerId ||
    intent.name !== origin.origin.nodeName
  )
    return null;
  // The reviewed delivery snapshot when the run recorded one (what members will
  // get: the addresses go-live keeps plus the candidates), else its candidates.
  return new Set(run.delivery?.edgeIds ?? run.resources.edgeIds);
}

/**
 * Published edges in pool order, as `context` may see them. By default only
 * edges with an eligible listener (and an address) are returned. With
 * `includeIneligible` every published, active edge the context selects is
 * returned and the ineligible ones (listener retired, undeployed or disabled,
 * no address, lapsed L7 proof, L4 verification no longer current) carry
 * `eligible:false`: they keep their pool index in the assignment modulus.
 *
 * The verification condition is the publication gate's own
 * (`verificationCurrent`), applied again at render time: a listener revision
 * bump or a re-addressing after the publish leaves the edge published (an
 * operator decision) but nothing is rendered for it until it is retested
 * (attention `retest_needed`), exactly as a stale L7 proof is handled. Retiring
 * a REALITY server name is not such a bump (`nameRetireKeepsVerification`).
 */
export async function publishedEdgesOf(
  ctx: { db: QueryCtx['db'] },
  origin: Doc<'relays'>,
  context: EdgeSelectionContext,
  opts: { includeIneligible?: boolean } = {},
): Promise<{ published: PublishedEdge[]; matchers: RenderMatcher[] }> {
  // With the enrolled node's auth revision: an L4 tick binds to it.
  const listeners = await verificationListenersOf(
    ctx.db,
    origin,
    await listenersOf(ctx, origin._id),
  );
  const matchers = listeners
    .filter((l) => !l.retired && l.deployed && l.enabled)
    .map((l) => matcherOf(l, origin.originAddress));
  let selected: (edgeId: string) => boolean;
  if (context.kind === 'activation') {
    const set = await activationCandidatesOf(ctx, origin, context.activationRunId);
    // A run that is not the node's current, running one renders nothing.
    selected = (id) => !!set && set.has(id);
  } else {
    const gate =
      origin.origin.kind === 'panel-node' && origin.backendServerId
        ? await nodeGateFor(ctx, origin.backendServerId, origin.origin.nodeName)
        : null;
    selected = (id) => !gate || !isCandidateEdge(gate, id);
  }
  const published: PublishedEdge[] = [];
  const now = Date.now();
  for (let i = 0; i < origin.publishedEdgeIds.length; i++) {
    const edgeId = origin.publishedEdgeIds[i];
    if (!edgeId || !selected(edgeId as string)) continue;
    const edge = await ctx.db.get(edgeId);
    if (!edge || edge.publication !== 'published' || edge.status !== 'active') continue;
    const listener = listeners.find((l) => l._id === edge.listenerId) ?? null;
    const hasAddress = !!edge.addresses.v4 || !!edge.addresses.v6 || !!edge.addresses.hostname;
    // An L7 front is only as good as its last PROOF.
    const l7Proven =
      (edge.layer ?? 'l4') !== 'l7' || (await l7QualificationCurrent(edge, listener, now));
    // An L4 endpoint is only as good as the operator's CURRENT confirmation.
    const l4Verified =
      !needsEndpointVerification(edge) || (!!listener && verificationCurrent(edge, listener));
    const eligible =
      hasAddress &&
      l7Proven &&
      l4Verified &&
      !!listener &&
      !listener.retired &&
      listener.deployed &&
      listener.enabled;
    if (!eligible && !opts.includeIneligible) continue;
    if (!listener) continue; // no listener at all: nothing to render from
    published.push(toPublishedEdge(edge, listener, edge.poolIndex ?? i, eligible, now));
  }
  return { published, matchers };
}

/**
 * One edge as the assignment sees it. Shared by the published-pool read above
 * and the test-link builder (which renders a single candidate through a
 * transient context, never the pool).
 */
export function toPublishedEdge(
  edge: Doc<'edges'>,
  listener: Doc<'relayListeners'>,
  poolIndex: number,
  eligible: boolean,
  now = Date.now(),
): PublishedEdge {
  // The effective per-country state (edgeCountry.ts), entries past their
  // `until` already dropped: only an assignment given an `edgeCountry` reads it.
  const country = liveCountryState(edge.countryState?.byCountry, now);
  const provenIn = country.filter((c) => c.state === 'proven').map((c) => c.country);
  const blockedIn = country.filter((c) => c.state === 'blocked').map((c) => c.country);
  const proto = {
    protocol: listener.protocol,
    streamTransport: listener.streamTransport,
    security: listener.security,
  };
  return {
    edgeId: edge._id,
    poolIndex,
    provider: edge.provider ?? 'adopted',
    ...(edge.accountId ? { accountId: edge.accountId as string } : {}),
    ...(edge.provider && edge.placeKey
      ? { locationKey: locationKeyOf(edge.provider, edge.placeKey) }
      : {}),
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
          ...(s.blockedIn?.length ? { blockedIn: s.blockedIn } : {}),
          ...(s.provenIn?.length ? { provenIn: s.provenIn } : {}),
        }))
      : [],
    ...(listener.sniPick ? { sniPick: listener.sniPick } : {}),
    ...(provenIn.length > 0 ? { provenIn } : {}),
    ...(blockedIn.length > 0 ? { blockedIn } : {}),
    ...(edge.lane === 'trusted' ? { lane: 'trusted' as const } : {}),
    ...((edge.layer ?? 'l4') === 'l7' && edge.frontQualification?.ok
      ? { proofExpiresAt: edge.frontQualification.expiresAt }
      : {}),
    ...(eligible ? {} : { eligible: false }),
  };
}

/** Delivery style of a backend: Outline hands out ONE key, a backend a subscription. */
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
  /**
   * The node delivery gate at this place (docs/servers.md "Node lifecycle"):
   * closed for an enrolled node that is not live, under maintenance or
   * retiring. `gateToken` is part of every cache token so a body rendered
   * under an older gate is never served under a newer one.
   */
  gate: NodeGate;
  /**
   * Freedom modes are only served through edges (lib/edges/freedomDelivery.ts):
   * at a place no binding covers, a freedom-family key is answered
   * `node_unprotected`, and the place's token says the switch is on.
   */
  freedomEdgesOnly: boolean;
}

/**
 * The delivery policy for a subscription at the place it RESOLVED to (the node
 * the body was pinned to, or the whole server). Evaluated AFTER the fetch by
 * the route, so a first fetch with no stored pin and a pin that moved onto a
 * origin node are both classified by the node the body belongs to.
 */
export async function deliveryPolicyFor(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<DeliveryPolicy> {
  const gate = await nodeGateFor(ctx, backendServerId, nodeName);
  const edgesOnly = await freedomEdgesOnly(ctx.db);
  const binding = await deliveryBindingFor(ctx.db, backendServerId, nodeName);
  if (!binding)
    return {
      required: false,
      bindingVersion: null,
      relayId: null,
      relaySlug: null,
      gate,
      freedomEdgesOnly: edgesOnly,
    };
  const relay = await relayForBackendNode(ctx.db, backendServerId, nodeName);
  return {
    required: true,
    bindingVersion: binding.policyVersion,
    relayId: relay?._id ?? null,
    relaySlug: binding.relaySlug,
    gate,
    freedomEdgesOnly: edgesOnly,
  };
}

/**
 * What covers a node for freedom delivery (lib/edges/freedomDelivery.ts): the
 * binding the delivery policy reads at its place, and the layers of the live
 * edges the origin it renders through hands out members right now (none while
 * the origin is missing or off, or rendering is off).
 */
export async function protectionAt(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string | undefined,
): Promise<NodeProtection> {
  const binding = await deliveryBindingFor(ctx.db, backendServerId, nodeName);
  const layers = new Set<EdgeLayer>();
  if (!binding) return { bound: false, layers };
  const relay = await relayForBackendNode(ctx.db, backendServerId, nodeName);
  if (relay && relay.enabled && (await renderEnabled(ctx))) {
    const { published } = await publishedEdgesOf(ctx, relay, { kind: 'member' });
    for (const p of published) layers.add(p.layer ?? 'l4');
  }
  return { bound: true, layers };
}

export const deliveryPolicy = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: (ctx, { backendServerId, nodeName }) =>
    deliveryPolicyFor(ctx, backendServerId, nodeName),
});

/**
 * Whether a key's raw backend URL serves an edge-required place: a delivery
 * binding covers the node it is pinned to (or its whole backend). A key not
 * pinned yet (a newly issued one) may land on any node of its backend, so a
 * binding of any node there counts too.
 */
export const rawUrlEdgeRequired = internalQuery({
  args: { subscriptionId: v.id('subscriptions') },
  handler: async (ctx, { subscriptionId }): Promise<boolean> => {
    const sub = await ctx.db.get(subscriptionId);
    const sid = sub?.backendServerId;
    if (!sid) return false;
    if (await deliveryBindingFor(ctx.db, sid, sub.pinnedNode ?? undefined)) return true;
    if (sub.pinnedNode) return false;
    // One binding per bound node of this backend: operator-scale.
    const bindings = await ctx.db
      .query('edgeDeliveryBindings')
      .withIndex('by_server_node', (q) => q.eq('backendServerId', sid))
      .collect();
    return bindings.some((b) => b.state === 'active');
  },
});

/**
 * Cache token for a subscription's place: `<policyVersion>[:g<gate>]:<epoch>`
 * while the place is edge-required (the epoch is the origin's, or -1 when the
 * binding has no live origin or rendering is off), `g<gate>` for an unbound
 * place with a managed node or a closed gate, followed by `:f` (or `f` alone)
 * while freedom modes are only served through edges, null for an unbound place
 * with none of these (raw delivery).
 */
async function epochTokenFor(
  ctx: { db: QueryCtx['db'] },
  policy: DeliveryPolicy,
): Promise<{ token: string | null; relay: Doc<'relays'> | null }> {
  // A place with a managed node carries the gate in its token even under raw
  // delivery, so a gate change re-keys the cache; so does an unmanaged node an
  // open maintenance hold closes (a body cached before the hold must not be
  // served from the cache while it holds). A place with neither keeps the null
  // token (no origin, no gate: nothing to re-key on).
  const gate =
    policy.gate.disposition !== null || policy.gate.state === 'blocked'
      ? `g${gateToken(policy.gate)}`
      : null;
  if (!policy.required) {
    // Freedom modes only through edges: a freedom-family key is answered
    // nothing here, so a body cached before the switch moved never answers it.
    const parts = [...(gate ? [gate] : []), ...(policy.freedomEdgesOnly ? ['f'] : [])];
    return { token: parts.length > 0 ? parts.join(':') : null, relay: null };
  }
  const relay = policy.relayId ? await ctx.db.get(policy.relayId) : null;
  const renderOn = await renderEnabled(ctx);
  return {
    token: [
      policy.bindingVersion,
      ...(gate ? [gate] : []),
      relay && relay.enabled && renderOn ? relay.publicationEpoch : -1,
    ].join(':'),
    relay,
  };
}

export const epochFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: async (ctx, { backendServerId, nodeName }): Promise<string | null> =>
    (await epochTokenFor(ctx, await deliveryPolicyFor(ctx, backendServerId, nodeName))).token,
});

/**
 * Everything the fronted route needs about a key's place BEFORE it looks at
 * its content cache, in one read: the cache token above, and whether names
 * are judged per country there (`sensitive`) with the curated countries. A
 * cached body must not reach a request that infers a curated country when it
 * could carry a name blocked there (lib/edges/sni/country.ts). A place no live
 * origin covers renders nothing, so it has no country logic either.
 */
export const renderContextFor = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.optional(v.string()) },
  handler: async (
    ctx,
    { backendServerId, nodeName },
  ): Promise<{ token: string | null; curated: string[]; sensitive: boolean }> => {
    const policy = await deliveryPolicyFor(ctx, backendServerId, nodeName);
    const { token, relay } = await epochTokenFor(ctx, policy);
    if (!relay) return { token, curated: [], sensitive: false };
    const { curatedCountries } = await resolveSniConfig(ctx.db);
    if (curatedCountries.length === 0)
      return { token, curated: curatedCountries, sensitive: false };
    const listeners = await listenersOf(ctx, relay._id);
    const sensitive = listeners.some(
      (l) =>
        l.sniPick === 'hrw1' &&
        (l.tlsNames ?? []).some(
          (n) =>
            n.status === 'active' &&
            ((n.blockedIn?.length ?? 0) > 0 || (n.provenIn?.length ?? 0) > 0),
        ),
    );
    return { token, curated: curatedCountries, sensitive };
  },
});

export interface SubscriptionRenderContext extends EdgeRenderContext {
  relayId: Id<'relays'>;
  renderKey: string | null;
  /** The country context of a render that has no request behind it (a mirror). */
  storedWhere: CountryContext;
  /**
   * Delivery by country for a render with no request behind it (a mirror):
   * the member's own CHOICE only (a public object held by a third party is
   * never shaped by a guess), on a freedom-family key, while steering is on.
   */
  storedEdgeCountry: string | null;
  /**
   * The same mirror without a choice: edges blocked in ANY listed country go
   * last (no member data shapes it). Empty when steering is off, the key is
   * not freedom-family, or the member chose a country.
   */
  storedAvoidBlockedIn: string[];
  /** When a render last noted entries it left out on this origin (`edgeHostHides.noteWithheld`). */
  withheldNotedAt: number | null;
}

export type SubscriptionRenderDecision =
  | { kind: 'raw' }
  | { kind: 'render'; context: SubscriptionRenderContext }
  | {
      kind: 'unavailable';
      reason:
        | 'render_disabled'
        | 'relay_disabled'
        | 'relay_missing'
        | 'no_render_key'
        | 'node_gated'
        | 'policy_moved'
        | 'family_disabled'
        | 'node_unprotected';
      relaySlug: string | null;
    };

/**
 * What the route must do with a fetched body for one subscription + client
 * family at the place it resolved to: pass it through (no origin covers the
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
    // The node's gate is authoritative whatever the binding says: a body that
    // resolved to a node that is not live reaches no member.
    if (policy.gate.state === 'blocked')
      return { kind: 'unavailable', reason: 'node_gated', relaySlug: policy.relaySlug };
    if (!policy.required) {
      // Freedom modes only through edges: a freedom-family key is never handed
      // a node no binding covers (its own address), whatever the body says.
      if (policy.freedomEdgesOnly && (await freedomHoldOf(ctx.db, sub, node)))
        return { kind: 'unavailable', reason: 'node_unprotected', relaySlug: null };
      return { kind: 'raw' };
    }
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
    // A family whose rule is off used to pass the backend body through; under
    // edge-required delivery there is no passthrough, so it is unavailable
    // (its own reason, so the refusal counter tells it apart from a switch-off).
    if (!rule.enabled)
      return { kind: 'unavailable', reason: 'family_disabled', relaySlug: relay.slug };
    // A key that has never been rendered has no render key yet: the caller
    // mints one (`subscriptions.ensureRenderKey`) and refuses only if that fails.
    const { published, matchers } = await publishedEdgesOf(
      ctx,
      relay,
      { kind: 'member' },
      { includeIneligible: true },
    );
    const curated = (await resolveSniConfig(ctx.db)).curatedCountries;
    const countryCfg = await resolveMemberCountryConfig(ctx.db);
    const choice = liveChoice(sub, curated);
    const steeredKey =
      countryCfg.steer &&
      (await memberFamilyOf(ctx.db, { ...sub, pinnedNode: node ?? sub.pinnedNode })) === 'freedom';
    const storedEdgeCountry = steeredKey && choice && choice !== ELSEWHERE ? choice : null;
    return {
      kind: 'render',
      context: {
        relayId: relay._id,
        epoch: relay.publicationEpoch,
        matchers,
        published,
        rule,
        preferDistinctProviders: cfg.render.preferDistinctProviders,
        ...(relay.edgePick ? { edgePick: relay.edgePick } : {}),
        // Lanes on: the account's lane decides which addresses it may be handed.
        ...(lanesOn(relay)
          ? { memberLane: await memberLaneOfUser(ctx.db, sub.userId, Date.now()) }
          : {}),
        minProvenForExclusive: cfg.country.minProvenForExclusive,
        renderKey: sub.renderKey ?? null,
        // For a render with NO request behind it (a mirror): the member's own
        // stored answer when it is a curated country, else no country at all,
        // which selects the universal pool.
        storedWhere: resolveWhere({
          override: sub.sniRegion,
          inferred: null,
          curated,
        }).where,
        storedEdgeCountry,
        storedAvoidBlockedIn: steeredKey && !storedEdgeCountry ? curated : [],
        originAddress: relay.originAddress,
        nodeAddresses: await nodeAddressesOf(ctx, relay),
        deliveryStyle: await deliveryStyleOf(ctx, sub.backendServerId),
        withheldNotedAt: relay.withheldEntries?.at ?? null,
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
    const { published } = await publishedEdgesOf(
      ctx,
      origin,
      { kind: 'member' },
      { includeIneligible: true },
    );
    const byId = new Map(published.map((p) => [p.edgeId, p]));
    const primary = snap.primaryEdgeId ? byId.get(snap.primaryEdgeId) : undefined;
    const backup = snap.backupEdgeId ? byId.get(snap.backupEdgeId) : undefined;
    if (!primary) return { refreshSuggested: true, known: false, connections: [] };
    const rule = effectiveRule(cfg.render, cfg.render.clients.other);
    // The snapshot's roles as they were: a seed over just these two edges could
    // swap them (the member's primary would read as their backup).
    const assigned = endpointsFor(
      sub.renderKey ?? '',
      primary,
      rule.includeBackup ? (backup ?? null) : null,
      { namesPerEndpoint: rule.namesPerEndpoint, backupNames: rule.backupNames },
    );
    const connections = renderEntries(assigned, rule, false, origin.originAddress).map((e) => ({
      label: e.label,
      role: e.role,
      family: e.family,
    }));
    return { refreshSuggested, known: true, connections };
  },
});

// --- delivery by country: turning it on or off ------------------------------------------------------

/** When delivery by country was last turned on (appState); absent while it is off. */
export const STEER_SINCE_KEY = 'delivery:steerSince';

export async function steeringSince(db: QueryCtx['db']): Promise<number | null> {
  const row = await db
    .query('appState')
    .withIndex('by_key', (q) => q.eq('key', STEER_SINCE_KEY))
    .unique();
  const at = row ? Number(row.value) : NaN;
  return Number.isFinite(at) ? at : null;
}

/**
 * How long after delivery by country is turned on its detector vetoes wait:
 * one refresh interval (members' apps fetch again) plus the revalidation
 * window a held copy may still be answered from.
 */
export function steeringSettleMs(cfg: { updateIntervalHours: number }): number {
  return cfg.updateIntervalHours * 60 * 60_000 + 10 * 60_000;
}

/**
 * `delivery.country.steer` changed (appSettings.setMany): what members receive
 * changes with it, so every origin's publication epoch moves (cached bodies stop
 * matching, members are nudged to refresh) and the mirrors are refreshed; the
 * time it was turned on starts the vetoes' settle clock.
 */
export const steeringChanged = internalMutation({
  args: { on: v.boolean() },
  handler: async (ctx, { on }) => {
    const now = Date.now();
    const row = await ctx.db
      .query('appState')
      .withIndex('by_key', (q) => q.eq('key', STEER_SINCE_KEY))
      .unique();
    if (on && !row)
      await ctx.db.insert('appState', { key: STEER_SINCE_KEY, value: String(now), updatedAt: now });
    if (!on && row) await ctx.db.delete(row._id);
    let bumped = 0;
    for (const origin of await ctx.db.query('relays').collect()) {
      await ctx.db.patch(origin._id, {
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: now,
      });
      bumped++;
    }
    if (bumped > 0) await scheduleMirrorRefresh(ctx);
    return { bumped };
  },
});
