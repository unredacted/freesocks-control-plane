/**
 * The guided setup PLAN (`POST setup-runs/plan`, read-only) and the run
 * creation that echoes it (`POST setup-runs`). Docs: docs/edges.md § "Guided
 * setup runs".
 *
 * The plan answers "what would protecting this node do" from the panel:
 *   - inbounds via `backends.listNodeInbounds` + the pure `mapInboundsToListeners`
 *     (the frontable ones are the required listeners, cap 8);
 *   - the node's DIRECT panel Hosts via `backends.listHosts` + `classifyDirectHosts`
 *     (covered = its inbound is frontable in every format; uncovered = the
 *     operator must consent, BY UUID, to hiding it, or keep members on the
 *     direct address);
 *   - which provider accounts can front the whole required set and why not;
 *   - whether the first go-live would turn on rendering fleet-wide, and which
 *     client families' render rules are off.
 * `planHash` covers the required listener specs + the direct-Host identities +
 * the offered account ids; a run creation must echo it (`edge.plan_stale`).
 *
 * The panel calls are reached through `planOps`, a seam the tests replace.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import type { BackendHost, PanelInbound } from './lib/backends/types';
import { RENDER_CLIENT_FAMILIES, resolveEdgeConfig } from './lib/edgeConfig';
import { mapInboundsToListeners } from './lib/edges/inboundMapping';
import { classifyDirectHosts } from './lib/edges/directHosts';
import { cohortsForOrigin } from './lib/edges/cohorts';
import { listenerLayers } from './lib/edges/layers';
import { templateHostRemark } from './lib/edges/hosts';
import { accountsForSlot } from './lib/edges/rotation';
import { EDGE_PROVIDER_CAPABILITIES, edgeLayerOf } from './lib/edges/providers/capabilities';
import { todayKey, liveEdgesOfAccount, relayForBackendNode } from './relays';
import { accountTested } from './edgeProviderAccounts';
import { listenersOf } from './relayListeners';
import { isTerminalRunState, planHashOf, slugForNode } from './lib/edges/setupRuns';
import type { SetupPlanAccount, SetupPlanInbound, SetupPlanSnapshot } from './lib/edges/setupRuns';
import type { ListenerSpecInput } from './lib/edges/registration';
import type { EdgeLayer } from './lib/edges/providers/capabilities';

const MAX_REQUIRED_LISTENERS = 8;

export interface PlanOps {
  listNodeInbounds(
    ctx: ActionCtx,
    a: { backendServerId: Id<'backendServers'>; nodeUuid: string },
  ): Promise<PanelInbound[]>;
  listHosts(ctx: ActionCtx, a: { backendServerId: Id<'backendServers'> }): Promise<BackendHost[]>;
}

const defaultPlanOps: PlanOps = {
  listNodeInbounds: (ctx, a) => ctx.runAction(internal.backends.listNodeInbounds, a),
  listHosts: (ctx, a) => ctx.runAction(internal.backends.listHosts, a),
};

let planOps: PlanOps = defaultPlanOps;

/** Test seam: replace the panel calls (null = the defaults). */
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
        message: 'The node is not in the panel inventory; refresh the node list first',
      });
    const relay = await relayForBackendNode(ctx.db, backendServerId, node.name);
    const relayListeners = relay
      ? (await listenersOf(ctx, relay._id)).filter((l) => !l.retired)
      : [];
    const accounts = (await ctx.db.query('edgeProviderAccounts').collect()).filter(
      (a) => a.enabled,
    );
    const accountLive: Record<string, number> = {};
    for (const a of accounts) {
      accountLive[a._id as string] = (await liveEdgesOfAccount(ctx.db, a._id)).filter(
        (e) => e.managed,
      ).length;
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
    const { cohorts, total } = await cohortsForOrigin(ctx, {
      backendServerId,
      nodeName: node.name,
    });
    return {
      backend: server.backend as string,
      node: {
        name: node.name,
        address: node.address ?? null,
        port: node.port ?? null,
      },
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
      })),
      renderEnabled: cfg.render.enabled,
      familiesDisabled: RENDER_CLIENT_FAMILIES.filter((f) => !cfg.render.clients[f].enabled),
      otherEnabledRelays,
      activeRunId: activeRun ? (activeRun._id as string) : null,
      members: { cohorts: cohorts.length, total },
    };
  }
}

type PlanContext = Awaited<ReturnType<typeof planContextOf>>;

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
    const eligible = accountsForSlot([a], {
      layers: inb.layers,
      proto: {
        protocol: spec.protocol,
        streamTransport: spec.streamTransport,
        security: spec.security,
      },
      allowL7: true,
    });
    if (eligible.length === 0) {
      reasons.push('layer_mismatch');
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
  return {
    id: a.id,
    name: a.name,
    provider: a.provider,
    layer,
    compatible: reasons.length === 0,
    reasons: [...new Set(reasons)],
  };
}

/** Build the snapshot for one node. Throws `not_found` / `edge.node_not_found`. */
export async function buildPlan(
  ctx: ActionCtx,
  args: { backendServerId: Id<'backendServers'>; nodeUuid: string },
): Promise<{ plan: SetupPlanSnapshot; planHash: string }> {
  // Only the two keys: `create` hands its whole argument object here.
  const a = { backendServerId: args.backendServerId, nodeUuid: args.nodeUuid };
  const c = await ctx.runQuery(internal.edgeSetupPlan.planContext, a);
  const originAddress = c.relay?.originAddress ?? c.node.address;
  if (!originAddress)
    throw new ConvexError({
      code: 'edge.node_address_missing',
      message: 'The panel reports no address for this node',
    });
  const origin = {
    kind: 'panel-node' as const,
    backendServerId: a.backendServerId,
    nodeName: c.node.name,
    nodeUuid: a.nodeUuid,
  };
  const inbounds = await planOps.listNodeInbounds(ctx, a);
  const mapped = await mapInboundsToListeners(inbounds, {
    existingKeys: [],
    origin,
  });
  const planInbounds: SetupPlanInbound[] = [];
  for (const cand of mapped.candidates) {
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
  const tooManyInbounds = frontable.length > MAX_REQUIRED_LISTENERS;
  const required = frontable.slice(0, MAX_REQUIRED_LISTENERS);
  // Direct Hosts: the node's own inbounds are the ACTIVE ones the panel listed.
  const nodeInboundUuids = inbounds.filter((i) => i.active).map((i) => i.configProfileInboundUuid);
  const coveredInboundUuids = required
    .filter((i) => i.formats.links && i.formats.singbox && i.formats.clash)
    .map((i) => (i.listenerSpec as ListenerSpecInput).panelBinding!.configProfileInboundUuid);
  const hosts = await planOps.listHosts(ctx, { backendServerId: a.backendServerId });
  const classified = classifyDirectHosts(hosts, {
    originAddress,
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
    emptyNode: c.members.total === 0,
    existingRelay:
      c.relay && c.relay.setupOwned && !c.relay.deleting
        ? { id: c.relay.id as string, slug: c.relay.slug, setupStage: c.relay.setupStage }
        : null,
    activeRunId: c.activeRunId,
  };
  const planHash = await planHashOf({
    listenerSpecs: required.map((i) => i.listenerSpec),
    directHosts,
    accountIds: accounts.filter((x) => x.compatible).map((x) => x.id),
  });
  return { plan, planHash };
}

/** `POST setup-runs/plan {backendServerId, nodeUuid}` (throttled like `quarantine/inspect`). */
export const plan = internalAction({
  args: { backendServerId: v.id('backendServers'), nodeUuid: v.string() },
  handler: async (ctx, a) => {
    const { plan, planHash } = await buildPlan(ctx, a);
    return { ...plan, planHash, generatedAt: new Date().toISOString() };
  },
});

/**
 * `POST setup-runs {backendServerId, nodeUuid, accountId, planHash, approvedHideUuids[], keepDirect?}`:
 * re-plans, refuses a stale hash (`edge.plan_stale`), an unoffered account
 * (`edge.account_incompatible`), too many inbounds (`edge.too_many_inbounds`),
 * an unknown approved uuid (`validation`), then persists the run and schedules
 * its first step.
 */
export const create = internalAction({
  args: {
    backendServerId: v.id('backendServers'),
    nodeUuid: v.string(),
    accountId: v.id('edgeProviderAccounts'),
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
        approvedHideUuids: a.approvedHideUuids,
        keepDirect: a.keepDirect,
        actorAdminId: a.actorAdminId,
      },
    );
    return { runId: res.id as string, stage: res.stage };
  },
});
