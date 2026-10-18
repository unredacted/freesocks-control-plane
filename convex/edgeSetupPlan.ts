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
import { RENDER_CLIENT_FAMILIES, resolveEdgeConfig } from './lib/edgeConfig';
import { mapTransportsToListeners } from './lib/edges/inboundMapping';
import { applyOriginProbes, originProbeTargets } from './edgeOriginProbe';
import type { OriginProbeOutcome } from './lib/edges/originProbe';
import { classifyDirectHosts } from './lib/edges/directHosts';
import { templateHostRemark } from './lib/edges/hosts';
import { accountsForSlot } from './lib/edges/rotation';
import {
  EDGE_PROVIDER_CAPABILITIES,
  edgeLayerOf,
  originPortCarriedBy,
} from './lib/edges/providers/capabilities';
import type { EdgeProviderId } from './lib/edgeProviderIds';
import { todayKey, liveEdgesOfAccount, relayForBackendNode } from './relays';
import { defaultLocationOf, liveCountForLocation, locationsOfAccount } from './edgeLocations';
import { accountTested } from './edgeProviderAccounts';
import { listenersOf } from './relayListeners';
import { enrolledOriginOf, withVerifiedIngress } from './nodeIntents';
import { isTerminalRunState, planHashOf, slugForNode } from './lib/edges/setupRuns';
import type { SetupPlanAccount, SetupPlanInbound, SetupPlanSnapshot } from './lib/edges/setupRuns';
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
}

const defaultPlanOps: PlanOps = {
  listNodeInbounds: (ctx, a) => ctx.runAction(internal.backends.listNodeInbounds, a),
  listHosts: (ctx, a) => ctx.runAction(internal.backends.listHosts, a),
  probeOrigins: (ctx, a) => ctx.runAction(internal.edgeOriginProbeOps.probe, a),
};

let planOps: PlanOps = defaultPlanOps;

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
    const accounts = (await ctx.db.query('edgeProviderAccounts').collect()).filter(
      (a) => a.enabled,
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
        });
      accountLocations[a._id as string] = rows;
    }
    const cfg = await resolveEdgeConfig(ctx.db);
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
        tested: accountTested(a),
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

function accountCompatibility(
  a: PlanContext['accounts'][number],
  required: SetupPlanInbound[],
  relay: PlanContext['relay'],
): SetupPlanAccount {
  const reasons: string[] = [];
  const layer = edgeLayerOf(a.provider);
  if (!a.tested) reasons.push('account_untested');
  // The account must be able to front EVERY required listener at its layer,
  // with the provider able to carry the protocol (accountsForSlot's rule).
  for (const inb of required) {
    const spec = inb.listenerSpec as ListenerSpecInput;
    const proto = {
      protocol: spec.protocol,
      streamTransport: spec.streamTransport,
      security: spec.security,
    };
    const eligible = accountsForSlot([a], {
      layers: inb.layers,
      proto,
      originPort: spec.originPort,
      allowL7: true,
    });
    if (eligible.length === 0) {
      // The layer and the transport fit, the port does not (gRPC behind a CDN
      // is proxied to 443 only): say so, the operator moves the transport.
      const portOnly =
        accountsForSlot([a], { layers: inb.layers, proto, allowL7: true }).length > 0 &&
        !originPortCarriedBy(a.provider as EdgeProviderId, proto, spec.originPort);
      reasons.push(portOnly ? 'origin_port_not_carried' : 'layer_mismatch');
      break;
    }
  }
  if (a.maxLiveEdges - a.live < required.length) reasons.push('account_capacity_reached');
  if (
    a.dailyAllocationBudget !== 0 &&
    a.dailyAllocationBudget - a.allocationsToday < required.length
  )
    reasons.push('account_budget_exhausted');
  if (relay?.providerScopes.some((s) => s.provider !== a.provider))
    reasons.push('provider_mismatch');
  const caps = EDGE_PROVIDER_CAPABILITIES[a.provider];
  if (layer === 'l7' && caps.needsDnsAccount && !a.settings.dnsAccountId)
    reasons.push('dns_zone_missing');
  // Where the addresses would be created: every location of the account,
  // judged on its own (an untrusted one is offered: its first tested address
  // trusts it). An account with no usable location cannot be picked yet.
  const locations = a.locations.map((loc) => {
    const why: string[] = [];
    if (!loc.enabled) why.push('location_disabled');
    if (loc.maxLiveEdges !== null && loc.maxLiveEdges - loc.live < required.length)
      why.push('location_capacity_reached');
    return {
      id: loc.id,
      label: loc.label,
      placeKey: loc.placeKey,
      isDefault: loc.isDefault,
      qualified: loc.qualified,
      compatible: why.length === 0,
      reasons: why,
    };
  });
  if (!locations.some((l) => l.compatible)) reasons.push('no_location');
  return {
    id: a.id,
    name: a.name,
    provider: a.provider,
    layer,
    compatible: reasons.length === 0,
    reasons: [...new Set(reasons)],
    locations,
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
  args: { backendServerId: Id<'backendServers'>; nodeUuid: string; listenerKeys?: string[] },
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
  // The probe handles an unreachable origin per target; a throw here is a fault
  // of the probe itself, so it is reported rather than hidden as "L4 only".
  const outcomes =
    targets.length > 0
      ? await planStage('probing how the origin answers HTTP transports', () =>
          planOps.probeOrigins(ctx, { targets }),
        )
      : [];
  const candidates = applyOriginProbes(
    mapped.candidates,
    withVerifiedIngress(outcomes, c.enrolled),
  );
  const planInbounds: SetupPlanInbound[] = [];
  for (const cand of candidates) {
    const frontable = cand.layers.layers.length > 0 && !cand.needsName;
    planInbounds.push({
      listenerKey: cand.listenerSpec.listenerKey,
      sourceTag: cand.sourceTag,
      listenerSpec: cand.listenerSpec,
      layers: cand.layers.layers as EdgeLayer[],
      frontable,
      formats: cand.formats,
      needsName: cand.needsName,
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
  const accounts = c.accounts.map((acct) => accountCompatibility(acct, required, c.relay));
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
  };
  const offered = accounts.filter((x) => x.compatible);
  const planHash = await planHashOf({
    listenerSpecs: required.map((i) => i.listenerSpec),
    directHosts,
    accountIds: offered.map((x) => x.id),
    locationIds: offered.flatMap((x) =>
      (x.locations ?? []).filter((l) => l.compatible).map((l) => l.id),
    ),
  });
  return { plan, planHash };
}

/**
 * `POST setup-runs/plan {backendServerId, nodeUuid, listenerKeys?}` (throttled like
 * `quarantine/inspect`). `listenerKeys` names the transports to protect when the
 * node has more than one run takes (`tooManyInbounds`).
 */
export const plan = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    listenerKeys: v.optional(v.array(v.string())),
  },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, a);
    return { ...plan, planHash, generatedAt: new Date().toISOString() };
  },
});

/**
 * `POST setup-runs {backendServerId, nodeUuid, accountId?, locationId?, planHash, approvedHideUuids[], keepDirect?, listenerKeys?}`:
 * re-plans (with the same `listenerKeys` the plan was shown with), refuses a
 * stale hash (`edge.plan_stale`), an unoffered account or location
 * (`edge.account_incompatible`), too many transports without a choice
 * (`edge.too_many_inbounds`), an unknown approved uuid (`validation`), then
 * persists the run and schedules its first step. The pick is a location (its
 * account implied) or an account (its default location).
 */
export const create = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    listenerKeys: v.optional(v.array(v.string())),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    locationId: v.optional(v.id('edgeLocations')),
    planHash: v.string(),
    approvedHideUuids: v.array(v.string()),
    keepDirect: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, a);
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
    const res: { id: Id<'edgeSetupRuns'>; stage: string } = await ctx.runMutation(
      internal.edgeSetupRuns.insert,
      {
        plan: JSON.stringify(plan),
        planHash,
        accountId: a.accountId,
        locationId: a.locationId,
        approvedHideUuids: a.approvedHideUuids,
        keepDirect: a.keepDirect,
        actorAdminId: a.actorAdminId,
      },
    );
    return { runId: res.id as string, stage: res.stage };
  },
});
