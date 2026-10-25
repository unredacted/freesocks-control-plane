/**
 * The guided setup PLAN (`POST setup-runs/plan`, read-only) and the run
 * creation that echoes it (`POST setup-runs`). Docs: docs/edges.md § "Guided
 * setup runs".
 *
 * The plan answers "what would protecting this node do" from the backend:
 *   - transports via `backends.listNodeInbounds` + the pure `mapTransportsToListeners`
 *     (the frontable ones are the required listeners, cap 8);
 *   - the node's DIRECT backend Hosts via `backends.listHosts` + `classifyDirectHosts`
 *     (covered = its transport is frontable in every format; uncovered = the
 *     operator must consent, BY UUID, to hiding it, or keep members on the
 *     direct address);
 *   - which provider accounts can front the whole required set and why not;
 *   - whether the first go-live would turn on rendering fleet-wide, and which
 *     client families' render rules are off.
 * `planHash` covers the required listener specs + the direct-Host identities +
 * the offered account ids (+ the operator fronts and a given origin); a run
 * creation must echo it (`edge.plan_stale`).
 *
 * The backend calls are reached through `planOps`, a seam the tests replace.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import type { BackendHost, BackendTransport } from './lib/backends/types';
import { MAX_DESIRED_PUBLISHED, RENDER_CLIENT_FAMILIES, resolveEdgeConfig } from './lib/edgeConfig';
import { MAX_PROVIDER_PICKS, coverTargets, requirementOf } from './lib/edges/providerSet';
import { locationKeyOf } from './lib/edges/locations';
import { mapTransportsToListeners } from './lib/edges/inboundMapping';
import { applyOriginProbes, originProbeTargets } from './edgeOriginProbe';
import type { OriginProbeOutcome } from './lib/edges/originProbe';
import {
  classifyDirectHosts,
  operatorFrontHosts,
  type DirectHostContext,
} from './lib/edges/directHosts';
import { resolveNodeNames } from './edgeHostHides';
import { sameAddress, templateHostRemark } from './lib/edges/hosts';
import { canonicalIp, isPublicIpLiteral, l4OriginProblem } from './lib/edges/ip';
import { testLinkSourceOf } from './edgeTestLinks';
import { accountsForSlot } from './lib/edges/rotation';
import {
  edgeLayerOf,
  frontsAllowed,
  originPortCarriedBy,
} from './lib/edges/providers/capabilities';
import type { EdgeProviderId } from './lib/edgeProviderIds';
import type { BackendId } from './lib/backendIds';
import { capabilitiesOf } from './lib/backends/capabilities';
import { todayKey, liveEdgesOfAccount, relayForBackendNode } from './relays';
import {
  defaultLocationOf,
  liveCountForLocation,
  locationsOfAccount,
  sizeProblemOfLocation,
} from './edgeLocations';
import { regionOffersOf } from './edgeProviderCatalog';
import { placeProblemOf } from './lib/edges/l7Place';
import { SIZE_NOT_MULTICLOUD, SIZE_NOT_MULTICLOUD_WORDS } from './lib/edges/sizeCheck';
import { SPEND_CAP_REACHED, spendOf } from './edgePlans';
import { atCap } from './lib/edges/pricing';
import { accountTested, certificateRefusalOf } from './edgeProviderAccounts';
import { checkPickOptions } from './edgeTemplates';
import { listenersOf } from './relayListeners';
import { enrolledOriginOf, nodeAddressesOf, withVerifiedIngress } from './nodeIntents';
import {
  L4_NOT_FOR_WEBSOCKET,
  l4BarredFor,
  l4BarredForAll,
  websocketNodeOf,
} from './lib/edges/websocketNode';
import { isTerminalRunState, planHashOf, slugForNode } from './lib/edges/setupRuns';
import { edgeAddressesOf } from './lib/edges/render';
import { liveEdgesOfRelay } from './lib/edges/relayGuards';
import type {
  SetupPlanAccount,
  SetupPlanInbound,
  SetupPlanSet,
  SetupPlanSnapshot,
} from './lib/edges/setupRuns';
import type { ListenerSpecInput } from './lib/edges/registration';
import type { EdgeLayer } from './lib/edges/providers/capabilities';
import { SETUP_RUN_MAX_LISTENERS } from '../src/shared/contracts/edgeCodes';
import { resolveModeCatalog } from './lib/connectionModes';
import type { RealityClientsCheck, RealityTransportRef } from './edgeRealityClients';

const MAX_REQUIRED_LISTENERS = SETUP_RUN_MAX_LISTENERS;
/** A load balancer pick for a transport no test link can be made for (`withTestLinkProblems`). */
const TEST_LINK_UNAVAILABLE = 'test_link_unavailable';

export interface PlanOps {
  listNodeInbounds(
    ctx: ActionCtx,
    a: { backendServerId: Id<'backendServers'>; nodeUuid: string },
  ): Promise<BackendTransport[]>;
  listHosts(ctx: ActionCtx, a: { backendServerId: Id<'backendServers'> }): Promise<BackendHost[]>;
  /** The origin probe for HTTP-transport transports (fills `originTransport`; lib/edges/originProbe.ts). */
  probeOrigins(
    ctx: ActionCtx,
    a: { targets: ReturnType<typeof originProbeTargets> },
  ): Promise<OriginProbeOutcome[]>;
  /** The wait before an origin that did not answer is probed again. */
  pause(ms: number): Promise<void>;
  /** Whether the panel describes a REALITY transport well enough to build its test entry. */
  synthesisReady(
    ctx: ActionCtx,
    a: { backendServerId: Id<'backendServers'>; profileUuid: string; tag: string },
  ): Promise<boolean>;
  /** Which clients the node's REALITY transports refuse (edgeRealityClients.ts; never throws). */
  realityClients(
    ctx: ActionCtx,
    a: {
      backendServerId: Id<'backendServers'>;
      nodeUuid: string;
      nodeName: string;
      transports: RealityTransportRef[];
    },
  ): Promise<RealityClientsCheck[]>;
}

const defaultPlanOps: PlanOps = {
  listNodeInbounds: (ctx, a) => ctx.runAction(internal.backends.listNodeInbounds, a),
  listHosts: (ctx, a) => ctx.runAction(internal.backends.listHosts, a),
  probeOrigins: (ctx, a) => ctx.runAction(internal.edgeOriginProbeOps.probe, a),
  pause: (ms) => new Promise((r) => setTimeout(r, ms)),
  synthesisReady: (ctx, a) => ctx.runAction(internal.edgeTestLinks.synthesisReady, a),
  realityClients: (ctx, a) => ctx.runAction(internal.edgeRealityClients.check, a),
};

let planOps: PlanOps = defaultPlanOps;

/** Looks at an origin that did not answer before the plan takes "no answer" for it. */
export const ORIGIN_PROBE_ATTEMPTS = 3;
const ORIGIN_PROBE_PAUSE_MS = 500;
/** Probe answers that a second look cannot change (the address itself rules it out). */
const PROBE_FINAL_REASONS = new Set(['no_address', 'private_address']);

/**
 * The origin probe with retries: one dropped packet or slow handshake must not
 * leave a WebSocket transport L4-only (and every CDN account unable to carry
 * it). Only the targets that got no answer are asked again.
 */
async function probeOriginsWithRetries(
  ctx: ActionCtx,
  targets: ReturnType<typeof originProbeTargets>,
): Promise<OriginProbeOutcome[]> {
  let outcomes = await planOps.probeOrigins(ctx, { targets });
  for (let attempt = 1; attempt < ORIGIN_PROBE_ATTEMPTS; attempt++) {
    const again = new Set(
      outcomes
        .filter((o) => !o.originTransport && !PROBE_FINAL_REASONS.has(o.reason ?? ''))
        .map((o) => o.listenerKey),
    );
    if (again.size === 0) break;
    await planOps.pause(ORIGIN_PROBE_PAUSE_MS);
    const next = await planOps.probeOrigins(ctx, {
      targets: targets.filter((t) => again.has(t.listenerKey)),
    });
    const byKey = new Map(next.map((o) => [o.listenerKey, o]));
    outcomes = outcomes.map((o) => byKey.get(o.listenerKey) ?? o);
  }
  return outcomes;
}

/** Test seam: replace the backend calls (null = the defaults). */
export function __setPlanOpsForTests(over: Partial<PlanOps> | null): void {
  planOps = over ? { ...defaultPlanOps, ...over } : defaultPlanOps;
}

/** Everything the plan needs from the database, in one read. */
export const planContext = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeUuid: v.string() },
  handler: (ctx, a) => planContextOf(ctx, a),
});

async function planContextOf(
  ctx: { db: QueryCtx['db'] },
  { backendServerId, nodeUuid }: { backendServerId: Id<'backendServers'>; nodeUuid: string },
) {
  {
    const server = await ctx.db.get(backendServerId);
    if (!server) throw new ConvexError({ code: 'not_found', message: 'Backend server not found' });
    const node = (
      await ctx.db
        .query('backendNodeInventory')
        .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
        .collect()
    ).find((n) => n.nodeUuid === nodeUuid);
    if (!node)
      throw new ConvexError({
        code: 'edge.node_not_found',
        message: 'The node is not in the backend inventory; refresh the node list first',
      });
    const relay = await relayForBackendNode(ctx.db, backendServerId, node.name);
    const relayListeners = relay
      ? (await listenersOf(ctx, relay._id)).filter((l) => !l.retired)
      : [];
    const cfg = await resolveEdgeConfig(ctx.db);
    // A DNS account (it holds the records of other fronts) is not offered as a
    // place to front this node unless it is set to DNS and fronting.
    const accounts = (await ctx.db.query('edgeProviderAccounts').collect()).filter(
      (a) => a.enabled && frontsAllowed(a),
    );
    const accountLive: Record<string, number> = {};
    const accountLocations: Record<
      string,
      Array<{
        id: string;
        label: string;
        placeKey: string;
        enabled: boolean;
        qualified: boolean;
        isDefault: boolean;
        live: number;
        maxLiveEdges: number | null;
        /** Why an L7 place cannot front yet (no zone, a refused check, its DNS account off). */
        placeProblem: string | null;
        /** Why a front on the account's default certificate gets none there (CAA, its wildcard). */
        certificateRefusal: string | null;
        /** The network its addresses come from (docs/edges.md "Networks"). */
        networkId: string | null;
      }>
    > = {};
    // The regions each load balancer account's key reaches that are no location
    // of it yet: a pick of one creates the location (the catalog is the menu).
    const accountRegions: Record<
      string,
      Array<{ id: string; label: string; project?: string }>
    > = {};
    const accountSpendCap: Record<string, boolean> = {};
    for (const a of accounts) {
      accountLive[a._id as string] = (await liveEdgesOfAccount(ctx.db, a._id)).filter(
        (e) => e.managed,
      ).length;
      if (typeof a.cost?.monthlyCap === 'number')
        accountSpendCap[a._id as string] = atCap(await spendOf(ctx, a));
      const dflt = await defaultLocationOf(ctx.db, a);
      const rows = [];
      for (const loc of await locationsOfAccount(ctx.db, a._id))
        rows.push({
          id: loc._id as string,
          label: loc.label,
          placeKey: loc.placeKey,
          enabled: loc.enabled,
          qualified: loc.qualified,
          isDefault: !!dflt && dflt._id === loc._id,
          live: await liveCountForLocation(ctx.db, loc),
          maxLiveEdges: loc.maxLiveEdges ?? null,
          // Why no new edge can be planned in this place (the zone itself, a
          // Scaleway location with no project to create in, or a size there
          // that takes only Scaleway's own servers).
          placeProblem:
            (await placeProblemOf(ctx.db, a, loc)) ?? (await sizeProblemOfLocation(ctx, a, loc)),
          // The certificate the account's DEFAULT could not get there (CAA, a
          // failed or foreign wildcard): a pick with its own certificate may
          // still go, so it is shown, and its pick check judges it.
          certificateRefusal: certificateRefusalOf(a, loc),
          networkId: (loc.networkId as string | undefined) ?? null,
        });
      accountLocations[a._id as string] = rows;
      accountRegions[a._id as string] = await regionOffersOf(
        ctx.db,
        a,
        rows.map((r) => r.placeKey),
      );
    }
    const runs = await ctx.db
      .query('edgeSetupRuns')
      .withIndex('by_origin', (q) =>
        q.eq('backendServerId', backendServerId).eq('nodeName', node.name),
      )
      .collect();
    const activeRun = runs.find((r) => !isTerminalRunState(r.state)) ?? null;
    const otherEnabledRelays = (
      await ctx.db
        .query('relays')
        .withIndex('by_enabled', (q) => q.eq('enabled', true))
        .collect()
    )
      .filter((r) => !relay || r._id !== relay._id)
      .map((r) => r.slug);
    // An enrolled node is planned from its intent (the origin FCP gives the
    // role and its declared ingress), never from the backend's node row: that
    // address is the MANAGEMENT one, and a loopback WebSocket behind Caddy is
    // only frontable through the ingress.
    const enrolled = await enrolledOriginOf(ctx, backendServerId, node.name);
    // A WebSocket node: no load balancer fronts its transport (lib/edges/websocketNode.ts).
    const websocketNode = await websocketNodeOf(ctx.db, {
      kind: 'panel-node',
      backendServerId,
      nodeName: node.name,
    });
    // The modes this backend serves, by transport tag, with whether members can pick them.
    const setup = await ctx.db
      .query('panelSetups')
      .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
      .unique();
    const { modes: catalog } = await resolveModeCatalog(ctx.db);
    const modes = (setup?.modes ?? []).map((m) => {
      const entry = catalog.find((c) => c.id === m.slug);
      return {
        slug: m.slug,
        tag: m.tag,
        label: entry?.label ?? null,
        enabled: entry?.enabled ?? false,
      };
    });
    return {
      backend: server.backend as string,
      node: {
        name: node.name,
        address: node.address ?? null,
        port: node.port ?? null,
      },
      enrolled,
      websocketNode,
      modes,
      relay: relay
        ? {
            id: relay._id,
            slug: relay.slug,
            setupOwned: relay.setupOwned === true,
            setupStage: relay.setupStage ?? null,
            deleting: relay.deleting === true,
            originAddress: relay.originAddress,
            nodeAddresses: await nodeAddressesOf(ctx, relay),
            edgeAddresses: edgeAddressesOf(await liveEdgesOfRelay(ctx.db, relay._id)),
            listenerKeys: relayListeners.map((l) => l.listenerKey),
            legacyHostUuids: relayListeners.flatMap((l) =>
              (l.legacyHosts ?? []).map((h) => h.uuid),
            ),
            fcpRemarks: relayListeners
              .map((l) => (l.matchRule.kind === 'remark' ? l.matchRule.remark : null))
              .filter((x): x is string => !!x),
            providerScopes: relayListeners
              .filter((l) => l.providerScope)
              .map((l) => ({ listenerKey: l.listenerKey, provider: l.providerScope!.provider })),
          }
        : null,
      accounts: accounts.map((a) => ({
        id: a._id as string,
        name: a.name,
        provider: a.provider,
        frontsTraffic: a.frontsTraffic,
        tested: accountTested(a),
        certificateRefusal: certificateRefusalOf(a),
        maxLiveEdges: a.maxLiveEdges,
        live: accountLive[a._id as string] ?? 0,
        dailyAllocationBudget: a.dailyAllocationBudget,
        allocationsToday: a.allocationsDayKey === todayKey() ? a.allocationsToday : 0,
        // At its monthly cap already: no new edge whatever it costs (the budget guard).
        spendCapReached: accountSpendCap[a._id as string] === true,
        settings: a.settings as Record<string, unknown>,
        locations: accountLocations[a._id as string] ?? [],
        regions: accountRegions[a._id as string] ?? [],
      })),
      renderEnabled: cfg.render.enabled,
      familiesDisabled: RENDER_CLIENT_FAMILIES.filter((f) => !cfg.render.clients[f].enabled),
      otherEnabledRelays,
      activeRunId: activeRun ? (activeRun._id as string) : null,
      transportNetworks: await transportNetworksOf(ctx.db, backendServerId),
    };
  }
}

/**
 * The network of each bound transport of a backend, by transport uuid
 * (docs/edges.md "Networks"): only a location on it may front the transport.
 */
async function transportNetworksOf(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const b of await db
    .query('sniInboundBindings')
    .withIndex('by_server_inbound', (q) => q.eq('backendServerId', backendServerId))
    .collect()) {
    const networkId = (await db.get(b.familyId))?.networkId;
    if (networkId) out[b.inboundUuid] = networkId as string;
  }
  return out;
}

type PlanContext = Awaited<ReturnType<typeof planContextOf>>;

/**
 * The modes the protected transports feed (an enrolled node's own mode, and
 * every mode whose transport tag is one of them) that members cannot pick.
 */
function modesOffOf(
  c: Pick<PlanContext, 'modes' | 'enrolled'>,
  required: readonly Pick<SetupPlanInbound, 'sourceTag'>[],
): Array<{ slug: string; label: string | null }> {
  const tags = new Set(required.map((i) => i.sourceTag));
  return c.modes
    .filter((m) => !m.enabled && (m.slug === c.enrolled?.mode || tags.has(m.tag)))
    .map((m) => ({ slug: m.slug, label: m.label }));
}

/**
 * One account judged for the plan. A pick need not carry every transport (a
 * set covers them between its picks): the account is compatible when it can
 * front at least one required transport, and `carries` names which. Its
 * locations are judged on their own (an untrusted one is offered: its first
 * tested address trusts it). An account with no usable location is still
 * offered when its key reaches a region that is no location yet (`regions`,
 * its catalog): picking one creates the location, untrusted like any new one.
 * With neither it cannot be picked yet (`no_location`). Capacity here is room
 * for one address; the set's own check sums what each pick gets over its
 * targets.
 */
function accountCompatibility(
  a: PlanContext['accounts'][number],
  required: SetupPlanInbound[],
  relay: PlanContext['relay'],
  websocketNode: boolean,
  l4Problem: ReturnType<typeof l4OriginProblem> = null,
): SetupPlanAccount {
  const reasons: string[] = [];
  const layer = edgeLayerOf(a.provider);
  // A load balancer forwards to the origin address, an IP: a private one is
  // out of its reach, and a name is none.
  if (layer === 'l4' && l4Problem)
    reasons.push(l4Problem === 'origin_not_ip' ? 'origin_name' : 'origin_private');
  // A front of this account could get no certificate: named first, since a
  // test alone does not fix it.
  if (a.certificateRefusal) reasons.push(a.certificateRefusal);
  else if (!a.tested) reasons.push('account_untested');
  const carries: string[] = [];
  let portOnly = false;
  let scoped = false;
  // A load balancer for a WebSocket node's transport, however its probe went.
  let barred = false;
  // A transport the account WOULD carry had the origin answered its probe:
  // `retry` when another look may answer, `final` when the address itself
  // rules it out (private or none).
  let unanswered: 'retry' | 'final' | null = null;
  for (const inb of required) {
    const spec = inb.listenerSpec as ListenerSpecInput;
    const proto = {
      protocol: spec.protocol,
      streamTransport: spec.streamTransport,
      security: spec.security,
    };
    const scope = relay?.providerScopes.find((s) => s.listenerKey === inb.listenerKey);
    if (scope && scope.provider !== a.provider) {
      scoped = true;
      continue;
    }
    if (layer === 'l4' && l4BarredFor(proto, websocketNode)) {
      barred = true;
      continue;
    }
    const eligible = accountsForSlot([a], {
      layers: inb.layers,
      proto,
      originPort: spec.originPort,
      allowL7: true,
    });
    if (eligible.length > 0) {
      carries.push(inb.listenerKey);
      continue;
    }
    if (
      inb.probeFailed &&
      !inb.layers.includes(layer) &&
      accountsForSlot([a], {
        layers: [...inb.layers, layer],
        proto,
        originPort: spec.originPort,
        allowL7: true,
      }).length > 0
    )
      unanswered =
        unanswered === 'retry' || !PROBE_FINAL_REASONS.has(inb.probeFailed) ? 'retry' : 'final';
    // The layer and the transport fit, the port does not (gRPC behind a CDN
    // is proxied to 443 only): say so, the operator moves the transport.
    if (
      accountsForSlot([a], { layers: inb.layers, proto, allowL7: true }).length > 0 &&
      !originPortCarriedBy(a.provider as EdgeProviderId, proto, spec.originPort)
    )
      portOnly = true;
  }
  if (carries.length === 0)
    reasons.push(
      scoped
        ? 'provider_mismatch'
        : barred
          ? 'l4_not_for_websocket'
          : unanswered === 'retry'
            ? 'origin_unreachable'
            : unanswered === 'final'
              ? 'origin_not_public'
              : portOnly
                ? 'origin_port_not_carried'
                : 'layer_mismatch',
    );
  // A load balancer for a WebSocket node: nothing done to the account or its
  // locations changes that, so it is the one reason given, for each of them.
  const websocketOnly = carries.length === 0 && barred && !scoped;
  // Room for one address: what a pick really gets is the set's cover, summed
  // per account and location over its targets (`setOfPicks`).
  const need = 1;
  if (a.maxLiveEdges - a.live < need) reasons.push('account_capacity_reached');
  if (a.dailyAllocationBudget !== 0 && a.dailyAllocationBudget - a.allocationsToday < need)
    reasons.push('account_budget_exhausted');
  if (a.spendCapReached) reasons.push(SPEND_CAP_REACHED);
  const locations = a.locations.map((loc) => {
    const why: string[] = [];
    if (websocketOnly) why.push('l4_not_for_websocket');
    else {
      if (!loc.enabled) why.push('location_disabled');
      if (loc.placeProblem) why.push(loc.placeProblem);
      if (loc.maxLiveEdges !== null && loc.maxLiveEdges - loc.live < need)
        why.push('location_capacity_reached');
      // Every transport the account carries is scoped to a network this place is
      // not on (docs/edges.md "Networks").
      if (
        carries.length > 0 &&
        carries.every((k) => !locationOnNetworkOf(required, k, loc.networkId))
      )
        why.push('off_network');
    }
    return {
      id: loc.id,
      label: loc.label,
      placeKey: loc.placeKey,
      isDefault: loc.isDefault,
      qualified: loc.qualified,
      compatible: why.length === 0,
      reasons: why,
      certificateRefusal: loc.certificateRefusal,
      networkId: loc.networkId,
    };
  });
  // Nothing done to a load balancer account helps a WebSocket node: no region either.
  const regions = websocketOnly ? [] : a.regions;
  if (!locations.some((l) => l.compatible) && regions.length === 0) reasons.push('no_location');
  return {
    id: a.id,
    name: a.name,
    provider: a.provider,
    layer,
    compatible: reasons.length === 0,
    reasons: websocketOnly ? ['l4_not_for_websocket'] : [...new Set(reasons)],
    locations,
    carries,
    regions,
  };
}

/**
 * What a chosen set of picks makes (docs/edges.md § "Provider sets"): the
 * requirement over the required transports (lib/edges/providerSet.ts) and its
 * cover, the fewest (transport, pick) addresses a fresh protection creates.
 * Capacity and budget are summed per account over its targets. Pure over the
 * plan; `create` refuses what it reports (uncovered, too large, a problem).
 */
/** What a run cannot be created with: a transport no pick carries, a set too large, a pick that cannot be used. */
export function refuseSet(set: SetupPlanSet): void {
  // A load balancer for a node whose address is private, or a name: it could reach nothing.
  if (set.problems.some((p) => p.reason === 'origin_private'))
    throw new ConvexError({
      code: 'edge.origin_not_public',
      message:
        "The node's address is private, so a load balancer cannot reach it. Give its public IP address",
    });
  if (set.problems.some((p) => p.reason === 'origin_name'))
    throw new ConvexError({
      code: 'edge.origin_not_ip',
      message:
        "The node's address is a name, and a load balancer forwards to an IP address. Give its public IP address",
    });
  // A load balancer address no test link could be made for: refused before it is bought.
  if (set.problems.some((p) => p.reason === TEST_LINK_UNAVAILABLE))
    throw new ConvexError({
      code: 'edge.test_link_unavailable',
      message:
        "FCP could not test a new address here: no Host dials the node at its own address, and this transport's entry cannot be built from the node",
    });
  // A load balancer picked for a WebSocket node: refused in its own words (it
  // is why its transport is left uncovered).
  if (set.problems.some((p) => p.reason.replace(/^edge\./, '') === 'l4_not_for_websocket'))
    throw new ConvexError({ code: 'edge.l4_not_for_websocket', message: L4_NOT_FOR_WEBSOCKET });
  // A load balancer size that takes only the provider's own servers: refused
  // in its own words, before anything billable exists (lib/edges/sizeCheck.ts).
  if (set.problems.some((p) => p.reason.replace(/^edge\./, '') === SIZE_NOT_MULTICLOUD))
    throw new ConvexError({
      code: `edge.${SIZE_NOT_MULTICLOUD}`,
      message: SIZE_NOT_MULTICLOUD_WORDS,
    });
  // An account these edges would take past its monthly cap (the budget guard).
  if (set.problems.some((p) => p.reason.replace(/^edge\./, '') === SPEND_CAP_REACHED))
    throw new ConvexError({
      code: `edge.${SPEND_CAP_REACHED}`,
      message: 'These addresses would take an account past its monthly spend cap',
    });
  if (set.uncovered.length > 0)
    throw new ConvexError({
      code: 'edge.set_uncovered_listener',
      message: `No picked location can carry ${set.uncovered.join(', ')}; add one that can`,
    });
  if (set.tooLarge)
    throw new ConvexError({
      code: 'edge.set_too_large',
      message: `These picks need more than ${MAX_DESIRED_PUBLISHED} addresses for one node`,
    });
  // A pick's options break a rule: refused with the option's own code and words.
  const option = set.problems.find((p) => p.reason.startsWith('edge.option_'));
  if (option)
    throw new ConvexError({ code: option.reason, message: option.detail ?? option.reason });
  if (set.problems.length > 0)
    throw new ConvexError({
      code: 'edge.account_incompatible',
      message: `A picked location cannot be used (${set.problems[0]!.reason})`,
    });
}

/** Check each pick's options (`checkPicks`) into the set: its options, or a problem. */
/** Whether no transport to protect may be fronted by a load balancer (a WebSocket node's). */
function barsLoadBalancers(
  required: ReadonlyArray<{ listenerSpec: unknown }>,
  websocketNode: boolean,
): boolean {
  return l4BarredForAll(
    required.map((i) => i.listenerSpec as ListenerSpecInput),
    websocketNode,
  );
}

/** Whether the node's transports to protect include a REALITY one. */
function servesReality(required: ReadonlyArray<{ listenerSpec: unknown }>): boolean {
  return required.some((i) => (i.listenerSpec as ListenerSpecInput).security === 'reality');
}

async function applyPickChecks(
  ctx: ActionCtx,
  set: SetupPlanSet,
  pickOptions: Record<string, unknown> | undefined,
  node: { realityL4: boolean; l4Barred: boolean },
): Promise<void> {
  const checked = await ctx.runQuery(internal.edgeSetupPlan.checkPicks, {
    picks: set.picks.map((p) => ({
      locationId: p.locationId as Id<'edgeLocations'>,
      options: pickOptions?.[p.locationId] ?? {},
    })),
    realityL4: node.realityL4,
    l4Barred: node.l4Barred,
  });
  for (const r of checked) {
    const pick = set.picks.find((p) => p.locationId === r.locationId);
    if (!pick) continue;
    // The plan already said so for this pick (its account's own reason).
    if (
      !r.ok &&
      set.problems.some((p) => p.locationId === r.locationId && `edge.${p.reason}` === r.code)
    )
      continue;
    if (r.ok && r.certificateToCheck) {
      // A certificate the location's check never covered (another authority,
      // the wildcard): the zone's CAA records are read for it now.
      const pre = await ctx.runAction(internal.edgeProviderOps.certificatePreflight, {
        accountId: r.accountId as Id<'edgeProviderAccounts'>,
        locationId: r.locationId as Id<'edgeLocations'>,
        certificate: r.certificateToCheck,
      });
      if (!pre.ok) {
        set.problems.push({
          locationId: r.locationId,
          reason: pre.code,
          ...(pre.detail ? { detail: pre.detail } : {}),
        });
        continue;
      }
    }
    if (r.ok) pick.options = r.options;
    else
      set.problems.push({
        locationId: r.locationId,
        reason: r.code,
        ...(r.issues.length > 0 ? { detail: r.issues.join('; ') } : {}),
      });
  }
}

/**
 * What the picks cost a month before anything is created (`edgePlans.costOfPicks`):
 * each pick's addresses at the size its options build, and the total. An
 * account whose cap these edges would pass is a problem of its first pick
 * (`account_spend_cap_reached`, the budget guard).
 */
async function applyPickCost(ctx: ActionCtx, set: SetupPlanSet): Promise<void> {
  const counts = new Map<string, number>();
  for (const t of set.targets) counts.set(t.locationId, (counts.get(t.locationId) ?? 0) + 1);
  const priced = await ctx.runQuery(internal.edgePlans.costOfPicks, {
    picks: set.picks.map((p) => ({
      locationId: p.locationId as Id<'edgeLocations'>,
      options: p.options ?? {},
      count: counts.get(p.locationId) ?? 0,
    })),
  });
  set.cost = { lines: priced.lines, total: priced.total };
  for (const accountId of priced.capReached) {
    const first = set.picks.find((p) => p.accountId === accountId);
    if (
      first &&
      !set.problems.some((p) => p.locationId === first.locationId && p.reason === SPEND_CAP_REACHED)
    )
      set.problems.push({ locationId: first.locationId, reason: SPEND_CAP_REACHED });
  }
}

/**
 * Each pick's provider options, checked where they will build: the values the
 * operator chose (validated for the pick's provider), with the account's
 * certificate defaults copied in (an account default only ever PREFILLS a
 * node), laid over the location's template and checked as a whole.
 */
export const checkPicks = internalQuery({
  args: {
    picks: v.array(v.object({ locationId: v.id('edgeLocations'), options: v.any() })),
    /** The node serves a REALITY transport (an HTTP health check would fail on it). */
    realityL4: v.optional(v.boolean()),
    /** No transport to protect may be fronted by a load balancer (`l4BarredForAll`): one is refused. */
    l4Barred: v.optional(v.boolean()),
  },
  handler: async (ctx, a) => {
    const out: Array<
      | {
          locationId: string;
          accountId: string;
          ok: true;
          options: Record<string, unknown>;
          certificateToCheck: Record<string, unknown> | null;
        }
      | { locationId: string; ok: false; code: string; issues: string[] }
    > = [];
    for (const p of a.picks) {
      const location = await ctx.db.get(p.locationId);
      const account = location ? await ctx.db.get(location.accountId) : null;
      if (!location || !account) {
        out.push({ locationId: p.locationId, ok: false, code: 'edge.no_location', issues: [] });
        continue;
      }
      const r = await checkPickOptions(ctx, location, account, p.options, {
        realityL4: a.realityL4,
        l4Barred: a.l4Barred,
      });
      out.push(
        r.ok
          ? {
              locationId: p.locationId,
              accountId: account._id as string,
              ok: true,
              options: r.options,
              certificateToCheck: r.certificateToCheck,
            }
          : { locationId: p.locationId, ok: false, code: r.code, issues: r.issues },
      );
    }
    return out;
  },
});

/**
 * Whether a place on `networkId` may front the transport `listenerKey`: always
 * for a transport on no network, only from its own network otherwise.
 */
function locationOnNetworkOf(
  required: readonly Pick<SetupPlanInbound, 'listenerKey' | 'networkId'>[],
  listenerKey: string,
  networkId: string | null,
): boolean {
  const scoped = required.find((r) => r.listenerKey === listenerKey)?.networkId;
  return !scoped || scoped === networkId;
}

export function setOfPicks(
  pickIds: readonly string[],
  accounts: readonly SetupPlanAccount[],
  required: readonly SetupPlanInbound[],
  usage: ReadonlyArray<{
    id: string;
    live: number;
    maxLiveEdges: number;
    dailyAllocationBudget: number;
    allocationsToday: number;
    locations: ReadonlyArray<{ id: string; live: number; maxLiveEdges: number | null }>;
  }>,
): SetupPlanSet {
  if (new Set(pickIds).size !== pickIds.length)
    throw new ConvexError({ code: 'validation', message: 'A location is picked twice' });
  if (pickIds.length === 0)
    throw new ConvexError({ code: 'validation', message: 'Pick at least one location' });
  if (pickIds.length > MAX_PROVIDER_PICKS)
    throw new ConvexError({
      code: 'edge.set_too_large',
      message: `Pick at most ${MAX_PROVIDER_PICKS} locations for one node`,
    });
  const picks: SetupPlanSet['picks'] = [];
  const problems: SetupPlanSet['problems'] = [];
  for (const id of pickIds) {
    const acct = accounts.find((a) => a.locations?.some((l) => l.id === id));
    const loc = acct?.locations?.find((l) => l.id === id);
    if (!acct || !loc)
      throw new ConvexError({
        code: 'edge.account_incompatible',
        message: 'A picked location is not one the plan offers',
      });
    picks.push({
      locationId: id,
      accountId: acct.id,
      provider: acct.provider,
      locationKey: locationKeyOf(acct.provider, loc.placeKey),
      label: loc.label,
    });
    if (!acct.compatible) problems.push({ locationId: id, reason: acct.reasons[0] ?? 'account' });
    else if (!loc.compatible)
      problems.push({ locationId: id, reason: loc.reasons[0] ?? 'location' });
  }
  const req = requirementOf(
    required.map((i) => ({
      listenerKey: i.listenerKey,
      carriers: picks
        .filter((p) => {
          const acct = accounts.find((a) => a.id === p.accountId);
          const loc = acct?.locations?.find((l) => l.id === p.locationId);
          return (
            !!acct?.carries?.includes(i.listenerKey) &&
            locationOnNetworkOf(required, i.listenerKey, loc?.networkId ?? null)
          );
        })
        .map((p) => p.locationId),
    })),
    picks.map((p) => ({
      locationId: p.locationId,
      provider: p.provider,
      locationKey: p.locationKey,
    })),
  );
  const targets = coverTargets(req, [])
    .filter((t): t is typeof t & { locationId: string } => t.locationId !== null)
    .map((t) => ({ listenerKey: t.listenerKey, locationId: t.locationId }));
  // Capacity and budget, summed per account (and per location) over its targets.
  for (const u of usage) {
    const mine = targets.filter((t) =>
      picks.some((p) => p.locationId === t.locationId && p.accountId === u.id),
    );
    if (mine.length === 0) continue;
    const first = picks.find((p) => p.accountId === u.id)!.locationId;
    if (u.maxLiveEdges - u.live < mine.length)
      problems.push({ locationId: first, reason: 'account_capacity_reached' });
    if (u.dailyAllocationBudget !== 0 && u.dailyAllocationBudget - u.allocationsToday < mine.length)
      problems.push({ locationId: first, reason: 'account_budget_exhausted' });
    for (const loc of u.locations) {
      const here = mine.filter((t) => t.locationId === loc.id).length;
      if (here > 0 && loc.maxLiveEdges !== null && loc.maxLiveEdges - loc.live < here)
        problems.push({ locationId: loc.id, reason: 'location_capacity_reached' });
    }
  }
  return {
    picks,
    targets,
    reduced: req.reduced,
    uncovered: req.uncarried,
    tooLarge: targets.length > MAX_DESIRED_PUBLISHED,
    problems,
  };
}

/**
 * The transports the operator named for a node with more than one run protects:
 * each must be a frontable transport of the plan, named once, and there must be
 * 1..MAX_REQUIRED_LISTENERS of them (`validation` otherwise). Plan order is kept.
 */
function chosenListeners(frontable: SetupPlanInbound[], keys: string[]): SetupPlanInbound[] {
  const wanted = new Set(keys);
  if (wanted.size !== keys.length)
    throw new ConvexError({ code: 'validation', message: 'listenerKeys names a transport twice' });
  if (wanted.size === 0 || wanted.size > MAX_REQUIRED_LISTENERS)
    throw new ConvexError({
      code: 'validation',
      message: `Name between 1 and ${MAX_REQUIRED_LISTENERS} transports`,
    });
  const out = frontable.filter((i) => wanted.has(i.listenerKey));
  if (out.length !== wanted.size)
    throw new ConvexError({
      code: 'validation',
      message: 'listenerKeys names a transport the plan cannot protect',
    });
  return out;
}

/** Build the snapshot for one node. Throws `not_found` / `edge.node_not_found`. */
/**
 * One step of the plan. A coded refusal passes through; anything else becomes
 * `edge.plan_step_failed` naming the step, so the admin never gets an anonymous
 * failure. Only the error's class name is quoted: messages can embed values.
 */
async function planStage<T>(doing: string, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ConvexError) throw err;
    throw new ConvexError({
      code: 'edge.plan_step_failed',
      message: `The plan stopped while ${doing} (${err instanceof Error ? err.name : 'error'}).`,
    });
  }
}

export async function buildPlan(
  ctx: ActionCtx,
  args: {
    backendServerId: Id<'backendServers'>;
    nodeUuid: string;
    listenerKeys?: string[];
    picks?: string[];
    /** Provider options per pick (location id -> values the operator chose). */
    pickOptions?: Record<string, unknown>;
    /** The public address of a node FCP does not manage (the panel may list a private one). */
    originAddress?: string;
  },
): Promise<{ plan: SetupPlanSnapshot; planHash: string }> {
  // Only the two keys: `create` hands its whole argument object here.
  const a = { backendServerId: args.backendServerId, nodeUuid: args.nodeUuid };
  const c = await ctx.runQuery(internal.edgeSetupPlan.planContext, a);
  // Whether anyone is on the node: the first page of the cohort walk is enough.
  const { cohorts } = await ctx.runQuery(internal.edgeCohorts.page, {
    backendServerId: a.backendServerId,
    nodeName: c.node.name,
    cursor: null,
  });
  const given = givenOriginOf(c, args.originAddress);
  const originSource = c.relay
    ? ('relay' as const)
    : c.enrolled
      ? ('enrolled' as const)
      : given
        ? ('given' as const)
        : ('panel' as const);
  const originAddress =
    c.relay?.originAddress ?? c.enrolled?.originAddress ?? given ?? c.node.address;
  if (!originAddress)
    throw new ConvexError({
      code: 'edge.node_address_missing',
      message: 'The backend reports no address for this node',
    });
  // A load balancer forwards to the origin, an IP: one the panel lists as a
  // private address (a node FCP does not manage is listed by its management
  // address) is out of its reach, and a name is none, so no load balancer is
  // offered for it.
  const l4Problem = l4OriginProblem(originAddress);
  const origin = {
    kind: 'panel-node' as const,
    backendServerId: a.backendServerId,
    nodeName: c.node.name,
    nodeUuid: a.nodeUuid,
  };
  const inbounds = await planStage("reading the node's transports from the backend", () =>
    planOps.listNodeInbounds(ctx, a),
  );
  const mapped = await planStage('mapping the transports to listeners', () =>
    mapTransportsToListeners(inbounds, {
      existingKeys: [],
      origin,
      ingress: c.enrolled?.ingress ?? null,
    }),
  );
  // The mapper leaves HTTP-transport transports without `originTransport` (L4
  // only); the origin probe fills it in, exactly as the transport-candidates
  // route does, so a WS / HTTP-upgrade / gRPC origin can be offered an L7 account.
  const targets = originProbeTargets(mapped.candidates, originAddress);
  // The probe handles an unreachable origin per target (asked again before
  // the plan believes it); a throw here is a fault of the probe itself, so it
  // is reported rather than hidden as "L4 only".
  const outcomes =
    targets.length > 0
      ? await planStage('probing how the origin answers HTTP transports', () =>
          probeOriginsWithRetries(ctx, targets),
        )
      : [];
  const candidates = applyOriginProbes(
    mapped.candidates,
    withVerifiedIngress(outcomes, c.enrolled),
    { websocketNode: c.websocketNode },
  );
  const planInbounds: SetupPlanInbound[] = [];
  for (const cand of candidates) {
    // A WebSocket node's transport whose origin did not answer is L7-only and
    // has no layer yet: it is still the transport to protect, so every CDN
    // account reads "could not reach the origin" rather than "cannot carry".
    const awaitingProbe =
      cand.layers.excluded.l4 === 'l4_not_for_websocket' && !!cand.probe && !cand.probe.ok;
    const frontable = (cand.layers.layers.length > 0 || awaitingProbe) && !cand.needsName;
    const networkId = cand.listenerSpec.panelBinding
      ? c.transportNetworks[cand.listenerSpec.panelBinding.configProfileInboundUuid]
      : undefined;
    planInbounds.push({
      listenerKey: cand.listenerSpec.listenerKey,
      sourceTag: cand.sourceTag,
      listenerSpec: cand.listenerSpec,
      layers: cand.layers.layers as EdgeLayer[],
      frontable,
      formats: cand.formats,
      needsName: cand.needsName,
      ...(networkId ? { networkId } : {}),
      // The origin never answered for this HTTP transport, so it stayed L4-only.
      ...(cand.probe && !cand.probe.ok ? { probeFailed: cand.probe.reason ?? 'no_answer' } : {}),
      ...(frontable
        ? {}
        : cand.needsName
          ? { reason: 'needs_names' }
          : { reason: cand.layers.excluded.l4 ?? cand.layers.excluded.l7 ?? 'no_layer' }),
    });
  }
  for (const u of mapped.unsupported) {
    planInbounds.push({
      listenerKey: '',
      sourceTag: u.tag,
      listenerSpec: null,
      layers: [],
      frontable: false,
      formats: { links: false, singbox: false, clash: false },
      needsName: false,
      reason: u.reason,
      ...(u.detail ? { detail: u.detail } : {}),
    });
  }
  const frontable = planInbounds.filter((i) => i.frontable);
  const chosen = args.listenerKeys ? chosenListeners(frontable, args.listenerKeys) : null;
  // A node with more transports than one run protects is planned as is (the
  // operator sees them all); the run takes only the ones the operator names.
  const tooManyInbounds = chosen === null && frontable.length > MAX_REQUIRED_LISTENERS;
  const required = chosen ?? frontable.slice(0, MAX_REQUIRED_LISTENERS);
  // Direct Hosts: the node's own transports are the ACTIVE ones the backend listed.
  const nodeInboundUuids = inbounds.filter((i) => i.active).map((i) => i.configProfileInboundUuid);
  const coveredInboundUuids = required
    .filter((i) => i.formats.links && i.formats.singbox && i.formats.clash)
    .map((i) => (i.listenerSpec as ListenerSpecInput).panelBinding!.configProfileInboundUuid);
  const hosts = await planStage('reading the Hosts from the backend', () =>
    planOps.listHosts(ctx, { backendServerId: a.backendServerId }),
  );
  // The address the panel lists stays the node's when the operator gave another:
  // a Host dialling it is a direct Host, never a front.
  const managementAddress =
    given && c.node.address && !sameAddress(c.node.address, originAddress) ? c.node.address : null;
  const dctx: DirectHostContext = {
    originAddress,
    alsoAddresses: [
      ...(c.relay?.nodeAddresses ?? c.enrolled?.directAddresses ?? []),
      ...(managementAddress ? [managementAddress] : []),
    ],
    nodeInboundUuids,
    fcpRemarks: [
      ...(c.relay?.fcpRemarks ?? []),
      ...required.map((i) => templateHostRemark(c.node.name, i.listenerKey)),
    ],
    legacyHostUuids: c.relay?.legacyHostUuids ?? [],
    coveredInboundUuids,
  };
  // A Host may dial the node by a name: one that resolves to the node is the node.
  const names = await planStage('resolving the names the Hosts dial', () =>
    resolveNodeNames(ctx, hosts, dctx),
  );
  const classified = classifyDirectHosts(hosts, {
    ...dctx,
    alsoAddresses: [...(dctx.alsoAddresses ?? []), ...names],
  });
  const directHosts = [
    ...classified.covered.map((h) => ({
      uuid: h.uuid,
      remark: h.remark,
      inboundUuid: h.inboundUuid,
      covered: true,
    })),
    ...classified.uncovered.map((h) => ({
      uuid: h.uuid,
      remark: h.remark,
      inboundUuid: h.inboundUuid,
      covered: false,
    })),
  ];
  // A Host on a protected transport that dials neither the node nor an edge:
  // a front the operator built by hand, which members stop getting at go-live.
  const fronts = operatorFrontHosts(hosts, {
    ...dctx,
    fcpRemarks: [
      ...(c.relay?.fcpRemarks ?? []),
      ...required.map((i) => templateHostRemark(c.node.name, i.listenerKey)),
    ],
    alsoAddresses: [...(dctx.alsoAddresses ?? []), ...names],
    edgeAddresses: c.relay?.edgeAddresses ?? [],
  }).map((h) => ({ uuid: h.uuid, remark: h.remark }));
  // Each transport's test link source: a load balancer address of one with
  // none would stop the run at its test card after the address was bought.
  for (const i of required) {
    const spec = i.listenerSpec as ListenerSpecInput;
    const source = testLinkSourceOf(
      { ...spec, panelBinding: spec.panelBinding ?? null },
      {
        backend: c.backend as BackendId,
        hosts: capabilitiesOf(c.backend as BackendId).hostManagement ? hosts : null,
        originAddress,
        ownRemarks: [
          templateHostRemark(c.node.name, i.listenerKey),
          ...(c.relay?.fcpRemarks ?? []),
        ],
      },
    );
    // An entry to build is read from the panel now, as the test link will:
    // a transport it no longer describes, or describes with no key, has none.
    const ready =
      source === 'synthesized' && spec.panelBinding
        ? await planStage("reading the transport's REALITY settings from the backend", () =>
            planOps.synthesisReady(ctx, {
              backendServerId: a.backendServerId,
              profileUuid: spec.panelBinding!.configProfileUuid,
              tag: spec.panelBinding!.inboundTag,
            }),
          )
        : source !== null;
    if (!ready) i.noTestLink = true;
  }
  // Which clients each REALITY transport lets in: one that refuses sing-box and
  // Mihomo passes a test made with an Xray client while those members break.
  // A warning on the transport (`reality_refuses_clients`); nothing is refused.
  const reality = required.filter((i) => {
    const spec = i.listenerSpec as ListenerSpecInput;
    return spec.security === 'reality' && !!spec.panelBinding;
  });
  if (reality.length > 0) {
    const checks = await planOps.realityClients(ctx, {
      backendServerId: a.backendServerId,
      nodeUuid: a.nodeUuid,
      nodeName: c.node.name,
      transports: reality.map((i) => {
        const binding = (i.listenerSpec as ListenerSpecInput).panelBinding!;
        return {
          key: i.listenerKey,
          profileUuid: binding.configProfileUuid,
          tag: binding.inboundTag,
        };
      }),
    });
    for (const check of checks) {
      const inbound = reality.find((i) => i.listenerKey === check.key);
      if (inbound && check.refusal) inbound.refusesClients = check.refusal;
    }
  }
  const accounts = c.accounts.map((acct) =>
    accountCompatibility(acct, required, c.relay, c.websocketNode, l4Problem),
  );
  const set =
    args.picks && args.picks.length > 0
      ? withTestLinkProblems(setOfPicks(args.picks, accounts, required, c.accounts), required)
      : undefined;
  if (set) {
    await applyPickChecks(ctx, set, args.pickOptions, {
      realityL4: servesReality(required),
      l4Barred: barsLoadBalancers(required, c.websocketNode),
    });
    await applyPickCost(ctx, set);
  }
  const plan: SetupPlanSnapshot = {
    backendServerId: a.backendServerId as string,
    backend: c.backend,
    nodeUuid: a.nodeUuid,
    nodeName: c.node.name,
    originAddress,
    originSource,
    originPrivate: l4Problem === 'origin_not_public',
    originName: l4Problem === 'origin_not_ip',
    ...(managementAddress ? { managementAddress } : {}),
    originDeleting: c.relay?.deleting === true,
    relaySlug: c.relay?.slug ?? slugForNode(c.node.name),
    inbounds: planInbounds,
    requiredListeners: required.map((i) => i.listenerKey),
    tooManyInbounds,
    directHosts,
    frontHosts: fronts,
    accounts,
    renderGlobal: {
      willEnable: !c.renderEnabled,
      affectedRelays: c.renderEnabled ? [] : c.otherEnabledRelays,
    },
    familiesDisabled: c.familiesDisabled,
    emptyNode: cohorts.length === 0,
    existingRelay:
      c.relay && c.relay.setupOwned && !c.relay.deleting
        ? { id: c.relay.id as string, slug: c.relay.slug, setupStage: c.relay.setupStage }
        : null,
    activeRunId: c.activeRunId,
    enrolled: !!c.enrolled,
    modesOff: modesOffOf(c, required),
    ...(set ? { set } : {}),
  };
  const offered = accounts.filter((x) => x.compatible);
  const planHash = await planHashOf({
    listenerSpecs: required.map((i) => i.listenerSpec),
    directHosts,
    accountIds: offered.map((x) => x.id),
    locationIds: offered.flatMap((x) =>
      (x.locations ?? []).filter((l) => l.compatible).map((l) => l.id),
    ),
    ...(args.picks ? { pickIds: args.picks } : {}),
    ...(set
      ? { pickOptions: Object.fromEntries(set.picks.map((p) => [p.locationId, p.options ?? {}])) }
      : {}),
    ...(given ? { givenOrigin: originAddress } : {}),
    frontHosts: fronts,
  });
  return { plan, planHash };
}

/**
 * The public address the operator gave for a node FCP does not manage, checked
 * and written the one way an IP is (`canonicalIp`: no brackets, IPv6
 * compressed): an IP, never a name (a load balancer forwards to an IP,
 * `edge.origin_not_ip`), and public (`edge.origin_not_public`); refused for an
 * enrolled node (its origin is its enrollment's) and for one whose earlier
 * origin forwards elsewhere (`edge.origin_address_locked`). Null when none was
 * given.
 */
function givenOriginOf(c: PlanContext, raw: string | undefined): string | null {
  const address = raw?.trim() ?? '';
  if (!address) return null;
  if (c.enrolled)
    throw new ConvexError({
      code: 'validation',
      message: 'FCP manages this node: it is reached at the address it enrolled with',
    });
  if (c.relay) {
    if (sameAddress(address, c.relay.originAddress)) return c.relay.originAddress;
    throw new ConvexError({
      code: 'edge.origin_address_locked',
      message:
        'An earlier setup of this node forwards to another address. Remove its protection first to use a new one',
    });
  }
  const ip = canonicalIp(address);
  if (!ip)
    throw new ConvexError({
      code: 'edge.origin_not_ip',
      message: 'Give the IP address: a load balancer forwards to an IP address, never to a name',
    });
  if (!isPublicIpLiteral(ip))
    throw new ConvexError({
      code: 'edge.origin_not_public',
      message: 'That address is private, so a provider cannot reach it. Give its public address',
    });
  return ip;
}

/**
 * A pick of a load balancer for a transport no test link can be made for (no
 * Host dials the node at its origin, and the transport's entry cannot be built)
 * is a problem of that pick: the run would stop at its test card after the
 * address was bought (`test_link_unavailable`).
 */
function withTestLinkProblems(set: SetupPlanSet, required: SetupPlanInbound[]): SetupPlanSet {
  for (const t of set.targets) {
    const pick = set.picks.find((p) => p.locationId === t.locationId);
    const inbound = required.find((i) => i.listenerKey === t.listenerKey);
    if (!pick || !inbound?.noTestLink || edgeLayerOf(pick.provider) !== 'l4') continue;
    if (
      set.problems.some((p) => p.locationId === t.locationId && p.reason === TEST_LINK_UNAVAILABLE)
    )
      continue;
    set.problems.push({ locationId: t.locationId, reason: TEST_LINK_UNAVAILABLE });
  }
  return set;
}

/**
 * `POST setup-runs/plan {backendServerId, nodeUuid, listenerKeys?, picks?}` (throttled like
 * `quarantine/inspect`). `listenerKeys` names the transports to protect when the
 * node has more than one run takes (`tooManyInbounds`); `picks` names the
 * locations to protect it from, and the plan then says what they make (`set`).
 */
export const plan = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    listenerKeys: v.optional(v.array(v.string())),
    picks: v.optional(v.array(v.string())),
    /** Provider options per pick (location id -> values). */
    pickOptions: v.optional(v.any()),
    /** The public address of a node FCP does not manage. */
    originAddress: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, a);
    return { ...plan, planHash, generatedAt: new Date().toISOString() };
  },
});

/**
 * `POST setup-runs {backendServerId, nodeUuid, picks? | accountId? | locationId?, planHash, approvedHideUuids[], keepDirect?, listenerKeys?}`:
 * re-plans (with the same `listenerKeys` and `picks` the plan was shown with),
 * refuses a stale hash (`edge.plan_stale`), an unoffered account or location
 * (`edge.account_incompatible`), too many transports without a choice
 * (`edge.too_many_inbounds`), a set that leaves a transport uncovered
 * (`edge.set_uncovered_listener`) or is too large (`edge.set_too_large`), an
 * unknown approved uuid (`validation`), then persists the run with its
 * targets and schedules its first step. One pick may also be named the old
 * way: a location, or an account (its default location).
 */
export const create = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    listenerKeys: v.optional(v.array(v.string())),
    picks: v.optional(v.array(v.id('edgeLocations'))),
    /** Provider options per pick (location id -> values), as the plan was shown with. */
    pickOptions: v.optional(v.any()),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    locationId: v.optional(v.id('edgeLocations')),
    planHash: v.string(),
    approvedHideUuids: v.array(v.string()),
    keepDirect: v.optional(v.boolean()),
    /** The public address of a node FCP does not manage, as the plan was shown with. */
    originAddress: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, {
      backendServerId: a.backendServerId,
      nodeUuid: a.nodeUuid,
      listenerKeys: a.listenerKeys,
      picks: a.picks as string[] | undefined,
      pickOptions: a.pickOptions as Record<string, unknown> | undefined,
      originAddress: a.originAddress,
    });
    // The node's earlier protection is still being removed: its origin holds
    // the node until then, so a run started now would find it taken.
    if (plan.originDeleting)
      throw new ConvexError({
        code: 'edge.origin_deleting',
        message: "The node's earlier protection is still being removed. Try again once it is gone",
      });
    if (planHash !== a.planHash)
      throw new ConvexError({
        code: 'edge.plan_stale',
        message: 'The node changed since the plan was shown; review it again',
      });
    if (plan.tooManyInbounds)
      throw new ConvexError({
        code: 'edge.too_many_inbounds',
        message: `More than ${MAX_REQUIRED_LISTENERS} frontable inbounds; use manual setup`,
      });
    if (plan.requiredListeners.length === 0)
      throw new ConvexError({
        code: 'edge.no_frontable_inbound',
        message: 'Nothing on this node can be fronted',
      });
    const uncovered = new Set(plan.directHosts.filter((h) => !h.covered).map((h) => h.uuid));
    for (const uuid of a.approvedHideUuids) {
      if (!uncovered.has(uuid))
        throw new ConvexError({
          code: 'validation',
          message: 'approvedHideUuids names a Host the plan did not show',
        });
    }
    // The set: the picks the plan was shown with, or the one pick named the old way.
    let set = plan.set;
    if (!set) {
      // The old single-location selector makes a plan with no set, so no
      // options were shown or hashed with it: options with it are refused
      // rather than dropped (name the picks instead).
      if (a.pickOptions && Object.keys(a.pickOptions as Record<string, unknown>).length > 0)
        throw new ConvexError({
          code: 'validation',
          message: 'Options for a location need the plan made with `picks`, not a single location',
        });
      const account = a.accountId
        ? plan.accounts.find((x) => x.id === (a.accountId as string))
        : plan.accounts.find((x) => x.locations?.some((l) => l.id === (a.locationId as string)));
      if (account?.reasons.includes('l4_not_for_websocket'))
        throw new ConvexError({ code: 'edge.l4_not_for_websocket', message: L4_NOT_FOR_WEBSOCKET });
      const location = a.locationId
        ? account?.locations?.find((l) => l.id === (a.locationId as string))
        : account?.locations?.find((l) => l.isDefault && l.compatible);
      if (!account || !location)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'Name a location (or an account) the plan offers',
        });
      const required = plan.inbounds.filter((i) => plan.requiredListeners.includes(i.listenerKey));
      const context = await ctx.runQuery(internal.edgeSetupPlan.planContext, {
        backendServerId: a.backendServerId,
        nodeUuid: a.nodeUuid,
      });
      set = withTestLinkProblems(
        setOfPicks([location.id], plan.accounts, required, context.accounts),
        required,
      );
      await applyPickChecks(ctx, set, undefined, {
        realityL4: servesReality(required),
        l4Barred: barsLoadBalancers(required, context.websocketNode),
      });
      plan.set = set;
    }
    refuseSet(set);
    const res: { id: Id<'edgeSetupRuns'>; stage: string } = await ctx.runMutation(
      internal.edgeSetupRuns.insert,
      {
        plan: JSON.stringify(plan),
        planHash,
        picks: set.picks.map((p) => p.locationId as Id<'edgeLocations'>),
        pickOptions: set.picks.map((p) => ({
          locationId: p.locationId as Id<'edgeLocations'>,
          options: JSON.stringify(p.options ?? {}),
        })),
        targets: set.targets.map((t) => ({
          listenerKey: t.listenerKey,
          locationId: t.locationId as Id<'edgeLocations'>,
        })),
        approvedHideUuids: a.approvedHideUuids,
        keepDirect: a.keepDirect,
        actorAdminId: a.actorAdminId,
      },
    );
    return { runId: res.id as string, stage: res.stage };
  },
});
