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
 * the offered account ids; a run creation must echo it (`edge.plan_stale`).
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
import { classifyDirectHosts } from './lib/edges/directHosts';
import { templateHostRemark } from './lib/edges/hosts';
import { accountsForSlot } from './lib/edges/rotation';
import {
  edgeLayerOf,
  frontsAllowed,
  originPortCarriedBy,
} from './lib/edges/providers/capabilities';
import type { EdgeProviderId } from './lib/edgeProviderIds';
import { todayKey, liveEdgesOfAccount, relayForBackendNode } from './relays';
import { defaultLocationOf, liveCountForLocation, locationsOfAccount } from './edgeLocations';
import { placeProblemOf } from './lib/edges/l7Place';
import { accountTested, certificateRefusalOf } from './edgeProviderAccounts';
import { checkPickOptions } from './edgeTemplates';
import { listenersOf } from './relayListeners';
import { enrolledOriginOf, withVerifiedIngress } from './nodeIntents';
import {
  L4_NOT_FOR_WEBSOCKET,
  l4BarredFor,
  l4BarredForAll,
  websocketNodeOf,
} from './lib/edges/websocketNode';
import { isTerminalRunState, planHashOf, slugForNode } from './lib/edges/setupRuns';
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

const MAX_REQUIRED_LISTENERS = SETUP_RUN_MAX_LISTENERS;

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
}

const defaultPlanOps: PlanOps = {
  listNodeInbounds: (ctx, a) => ctx.runAction(internal.backends.listNodeInbounds, a),
  listHosts: (ctx, a) => ctx.runAction(internal.backends.listHosts, a),
  probeOrigins: (ctx, a) => ctx.runAction(internal.edgeOriginProbeOps.probe, a),
  pause: (ms) => new Promise((r) => setTimeout(r, ms)),
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
      }>
    > = {};
    for (const a of accounts) {
      accountLive[a._id as string] = (await liveEdgesOfAccount(ctx.db, a._id)).filter(
        (e) => e.managed,
      ).length;
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
          // Scaleway location with no project to create in).
          placeProblem: await placeProblemOf(ctx.db, a, loc),
          // The certificate the account's DEFAULT could not get there (CAA, a
          // failed or foreign wildcard): a pick with its own certificate may
          // still go, so it is shown, and its pick check judges it.
          certificateRefusal: certificateRefusalOf(a, loc),
        });
      accountLocations[a._id as string] = rows;
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
        settings: a.settings as Record<string, unknown>,
        locations: accountLocations[a._id as string] ?? [],
      })),
      renderEnabled: cfg.render.enabled,
      familiesDisabled: RENDER_CLIENT_FAMILIES.filter((f) => !cfg.render.clients[f].enabled),
      otherEnabledRelays,
      activeRunId: activeRun ? (activeRun._id as string) : null,
    };
  }
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
 * tested address trusts it); an account with no usable location cannot be
 * picked yet. Capacity here is room for one address; the set's own check sums
 * what each pick gets over its targets.
 */
function accountCompatibility(
  a: PlanContext['accounts'][number],
  required: SetupPlanInbound[],
  relay: PlanContext['relay'],
  websocketNode: boolean,
): SetupPlanAccount {
  const reasons: string[] = [];
  const layer = edgeLayerOf(a.provider);
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
  const locations = a.locations.map((loc) => {
    const why: string[] = [];
    if (websocketOnly) why.push('l4_not_for_websocket');
    else {
      if (!loc.enabled) why.push('location_disabled');
      if (loc.placeProblem) why.push(loc.placeProblem);
      if (loc.maxLiveEdges !== null && loc.maxLiveEdges - loc.live < need)
        why.push('location_capacity_reached');
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
    };
  });
  if (!locations.some((l) => l.compatible)) reasons.push('no_location');
  return {
    id: a.id,
    name: a.name,
    provider: a.provider,
    layer,
    compatible: reasons.length === 0,
    reasons: websocketOnly ? ['l4_not_for_websocket'] : [...new Set(reasons)],
    locations,
    carries,
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
  // A load balancer picked for a WebSocket node: refused in its own words (it
  // is why its transport is left uncovered).
  if (set.problems.some((p) => p.reason.replace(/^edge\./, '') === 'l4_not_for_websocket'))
    throw new ConvexError({ code: 'edge.l4_not_for_websocket', message: L4_NOT_FOR_WEBSOCKET });
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
        .filter((p) => accounts.find((a) => a.id === p.accountId)?.carries?.includes(i.listenerKey))
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
  const originAddress = c.relay?.originAddress ?? c.enrolled?.originAddress ?? c.node.address;
  if (!originAddress)
    throw new ConvexError({
      code: 'edge.node_address_missing',
      message: 'The backend reports no address for this node',
    });
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
    planInbounds.push({
      listenerKey: cand.listenerSpec.listenerKey,
      sourceTag: cand.sourceTag,
      listenerSpec: cand.listenerSpec,
      layers: cand.layers.layers as EdgeLayer[],
      frontable,
      formats: cand.formats,
      needsName: cand.needsName,
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
  const classified = classifyDirectHosts(hosts, {
    originAddress,
    alsoAddresses: c.enrolled?.directAddresses ?? [],
    nodeInboundUuids,
    fcpRemarks: [
      ...(c.relay?.fcpRemarks ?? []),
      ...required.map((i) => templateHostRemark(c.node.name, i.listenerKey)),
    ],
    legacyHostUuids: c.relay?.legacyHostUuids ?? [],
    coveredInboundUuids,
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
  const accounts = c.accounts.map((acct) =>
    accountCompatibility(acct, required, c.relay, c.websocketNode),
  );
  const set =
    args.picks && args.picks.length > 0
      ? setOfPicks(args.picks, accounts, required, c.accounts)
      : undefined;
  if (set)
    await applyPickChecks(ctx, set, args.pickOptions, {
      realityL4: servesReality(required),
      l4Barred: barsLoadBalancers(required, c.websocketNode),
    });
  const plan: SetupPlanSnapshot = {
    backendServerId: a.backendServerId as string,
    backend: c.backend,
    nodeUuid: a.nodeUuid,
    nodeName: c.node.name,
    originAddress,
    relaySlug: c.relay?.slug ?? slugForNode(c.node.name),
    inbounds: planInbounds,
    requiredListeners: required.map((i) => i.listenerKey),
    tooManyInbounds,
    directHosts,
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
  });
  return { plan, planHash };
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
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, {
      backendServerId: a.backendServerId,
      nodeUuid: a.nodeUuid,
      listenerKeys: a.listenerKeys,
      picks: a.picks as string[] | undefined,
      pickOptions: a.pickOptions as Record<string, unknown> | undefined,
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
      set = setOfPicks([location.id], plan.accounts, required, context.accounts);
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
