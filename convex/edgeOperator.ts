/**
 * Operator-facing reads for the redesigned Admin -> Edges section (docs/edges.md
 * § "Operations"): the guided setup status (origin-scoped, draft or fleet), the
 * ranked attention list, the preflight dry run, the merged timeline, the
 * quarantine resolver view, provider usage, an origin lookup by slug and the
 * delivery bindings. Everything here READS; the writes stay in their own
 * modules (edgeRotations.start, hostOps.adoptListenerHost, origins.*).
 *
 * The step logic lives in lib/edges/setupStatus.ts (pure); this module only
 * gathers facts. Nothing here returns credentials or addresses a deployment
 * uses beyond what the admin views already carry.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalQuery } from './_generated/server';
import type { ActionCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import {
  RENDER_CLIENT_FAMILIES,
  EDGE_PLUMBING,
  originPolicy,
  resolveEdgeConfig,
  type EdgeConfig,
} from './lib/edgeConfig';
import { probeSourceHealth } from './probes';
import { countryWideHolds, newEdgeBlockedIn } from './edgeCountry';
import { capabilitiesOf } from './lib/backends/capabilities';
import { readMaintenance } from './lib/edges/maintenance';
import { isTerminalPhase } from './lib/edges/rotation';
import { accountsForSlot } from './lib/edges/rotation';
import {
  edgeLayerOf,
  zoneModeGovernsOrigin,
  EDGE_PROVIDER_CAPABILITIES,
} from './lib/edges/providers/capabilities';
import { hostTargetFor, listenerLayers } from './lib/edges/layers';
import {
  protocolLabel,
  protocolNeedsTarget,
  protocolUsesSni,
  protocolIsHttpTransport,
} from './lib/edges/protocols';
import { isValidListenerCombo } from '../src/shared/contracts/edgeProtocolIds';
import { parseIntent, parseObservedSettings } from './lib/edges/intent';
import { sameAddress } from './lib/edges/hosts';
import {
  needsEndpointVerification,
  verificationCurrent,
  verificationStale,
  verificationStaleReason,
} from './lib/edges/verification';
import { verificationListenersOf } from './lib/edges/verificationContext';
import { publishedCount } from './lib/edges/pool';
import { EDGE_TEMPLATES, validateTemplateParams } from './lib/edges/providers/templates';
import { fakeShadowedIds } from './lib/edges/providers/fake';
import {
  computeSetupStatus,
  type SetupEdgeFacts,
  type SetupInput,
  type SetupStep,
} from './lib/edges/setupStatus';
import type { SetupStepId } from '../src/shared/contracts/edgeCodes';
import {
  checkPublishable,
  deliveryBindingFor,
  liveEdgesOfAccount,
  liveEdgesOfRelay,
  mapRelayAdmin,
} from './relays';
import { activeNames, hostSniOf, listenerRemark, listenersOf } from './relayListeners';
import { mapEdgeAdmin } from './edges';
import {
  mapRotationAdmin,
  collectStartBlockers,
  rotationListenerKey,
  selectionContext,
} from './edgeRotations';
import { accountTested, API_FAILING_AFTER } from './edgeProviderAccounts';
import {
  defaultLocationOf,
  effectiveTemplateOfLocation,
  liveCountForLocation,
  locationsOfAccount,
} from './edgeLocations';
import { readRefusals, REFUSAL_WINDOW_MS, REFUSALS_CRITICAL_AT } from './deliveryRefusals';
import { fleetRotationsToday, readFleetBrake } from './lib/edges/fleet';
import { modeRefOf } from './nodeIntents';
import { resolveModeCatalog } from './lib/connectionModes';
import { requiredPoolSize } from './lib/edges/poolCapacity';
import { setStateOf } from './lib/edges/setState';
import { uncoveredListeners } from './lib/edges/pool';
import { renderPreviewFor } from './edgeAdmin';
import type { RelayOrigin } from './lib/edges/origin';
import {
  ATTENTION_RANK,
  deliveryOf,
  fleetStatusOf,
  membersDarkCode,
  originStatusOf,
  type OriginStatusFacts,
  type StatusRunFacts,
} from './lib/edges/originStatus';
import { isTerminalRunState } from './lib/edges/setupRuns';

type Db = QueryCtx['db'];
type Relay = Doc<'relays'>;
type Listener = Doc<'relayListeners'>;
type Account = Doc<'edgeProviderAccounts'>;
type Edge = Doc<'edges'>;

const iso = (n: number) => new Date(n).toISOString();
const isoN = (n: number | undefined | null) => (n ? iso(n) : null);

// --- facts ---------------------------------------------------------------------------------------

/** Health freshness of a backend server (the healthcheck cron runs every 10 min). */
function backendHealthy(server: Doc<'backendServers'> | null): boolean | null {
  if (!server) return null;
  // Never checked yet (a server added since the last cron run) is unknown, not unreachable.
  if (!server.lastHealthOkAt) return null;
  return Date.now() - server.lastHealthOkAt < 60 * 60_000;
}

async function originFacts(db: Db, origin: RelayOrigin): Promise<SetupInput['origin']> {
  if (origin.kind === 'manual')
    return {
      kind: 'manual',
      backendPresent: true,
      backendHealthy: null,
      backendHostManagement: false,
      backendNodeInventory: false,
    };
  const server = await db.get(origin.backendServerId);
  const caps = server ? capabilitiesOf(server.backend) : null;
  return {
    kind: origin.kind,
    backendPresent: !!server && server.isActive,
    backendHealthy: backendHealthy(server),
    backendHostManagement: caps?.hostManagement ?? false,
    backendNodeInventory: caps?.nodeInventory ?? false,
  };
}

interface ListenerLike {
  key: string;
  proto: {
    protocol: Listener['protocol'];
    streamTransport: Listener['streamTransport'];
    security: Listener['security'];
  };
  row: Listener | null;
  draft: {
    originPort?: number;
    originTransport?: Listener['originTransport'];
    tlsNames?: string[];
  } | null;
}

function udpProviderAvailable(): boolean {
  return Object.values(EDGE_PROVIDER_CAPABILITIES).some((c) => c.udp);
}

function listenerFacts(l: ListenerLike): SetupInput['listeners'][number] {
  const like = l.row ?? {
    ...l.proto,
    originTransport: l.draft?.originTransport ?? undefined,
    tlsNames: (l.draft?.tlsNames ?? []).map((name) => ({ name, status: 'active' as const })),
  };
  const valid = isValidListenerCombo(l.proto);
  const layers = valid
    ? listenerLayers(like, { udpProviderAvailable: udpProviderAvailable() })
    : { layers: [], excluded: {} };
  const names = l.row ? activeNames(l.row).length : (l.draft?.tlsNames ?? []).length;
  return {
    key: l.key,
    label: valid
      ? protocolLabel(l.proto)
      : `${l.proto.protocol}/${l.proto.streamTransport}/${l.proto.security}`,
    validCombo: valid,
    deployed: l.row ? l.row.deployed : true,
    enabled: l.row ? l.row.enabled : true,
    retired: l.row ? l.row.retired : false,
    layers: layers.layers,
    excluded: layers.excluded,
    needsTarget: valid && protocolNeedsTarget(l.proto),
    hasTarget: !!l.row?.realityTarget || !l.row,
    usesSni: valid && protocolUsesSni(l.proto),
    activeNames: names,
    l7Only: valid && protocolIsHttpTransport(l.proto) && !layers.layers.includes('l4'),
    templateEdgeId: (l.row?.templateEdgeId as string | undefined) ?? null,
  };
}

async function accountFacts(
  ctx: { db: Db },
  accounts: Account[],
  listeners: ListenerLike[],
  dnsProvidersFront: boolean,
): Promise<SetupInput['accounts']> {
  const out: SetupInput['accounts'] = [];
  const udp = udpProviderAvailable();
  for (const a of accounts) {
    const fronts: string[] = [];
    for (const l of listeners) {
      if (!isValidListenerCombo(l.proto)) continue;
      const like = l.row ?? {
        ...l.proto,
        originTransport: l.draft?.originTransport ?? undefined,
        tlsNames: (l.draft?.tlsNames ?? []).map((name) => ({ name, status: 'active' as const })),
      };
      const layers = listenerLayers(like, { udpProviderAvailable: udp }).layers;
      const originPort = l.row?.originPort ?? l.draft?.originPort;
      if (
        accountsForSlot([a], {
          layers,
          proto: l.proto,
          originPort,
          allowL7: true,
          dnsProvidersFront,
        }).length > 0
      )
        fronts.push(l.key);
    }
    const settings = a.settings as { dnsAccountId?: string };
    let dnsAccountMissing = false;
    if (settings.dnsAccountId) {
      const dns = await ctx.db.get(settings.dnsAccountId as Id<'edgeProviderAccounts'>);
      dnsAccountMissing = !dns || !dns.enabled;
    }
    const observed = parseObservedSettings(a.observedSettings);
    const layer = edgeLayerOf(a.provider);
    // Trust is per location: the account counts as trusted when one of its
    // enabled locations is, and current when that trust was taken with what
    // the location provisions with now.
    const locations = (await locationsOfAccount(ctx.db, a._id)).filter((l) => l.enabled);
    let qualified = false;
    let qualificationCurrent = false;
    for (const loc of locations) {
      if (!loc.qualified) continue;
      qualified = true;
      const eff = await effectiveTemplateOfLocation(ctx, a, loc);
      if (loc.qualifiedTemplateHash === eff.hash) qualificationCurrent = true;
    }
    const effective = await effectiveTemplateOfLocation(ctx, a, await defaultLocationOf(ctx.db, a));
    // A stored default row that no longer validates is an invalid template
    // (resolveTemplateFor skips it silently and falls back to compiled defaults).
    let templateInvalid = false;
    const rows = await ctx.db
      .query('edgeTemplates')
      .withIndex('by_provider', (q) => q.eq('provider', a.provider))
      .collect();
    const candidate =
      (a.defaultTemplateId ? rows.find((r) => r._id === a.defaultTemplateId) : undefined) ??
      rows.find((r) => r.isDefault && r.accountId === a._id) ??
      rows.find((r) => r.isDefault && !r.accountId);
    if (candidate) {
      try {
        templateInvalid = !validateTemplateParams(a.provider, JSON.parse(candidate.params)).ok;
      } catch {
        templateInvalid = true;
      }
    }
    out.push({
      id: a._id as string,
      name: a.name,
      provider: a.provider,
      layer,
      enabled: a.enabled,
      tested: accountTested(a),
      testFailed: !!a.lastTestError,
      qualified,
      qualificationCurrent,
      frontsListeners: fronts,
      dnsAccountMissing,
      zoneModeUnknown: layer === 'l7' && zoneModeGovernsOrigin(a.provider) && !observed.zoneSslMode,
      zoneWebsocketsOff: observed.zoneWebsockets === 'off',
      templateOk: !templateInvalid && !!(effective.id || EDGE_TEMPLATES[a.provider]),
      templateInvalid,
      defaultTemplateId: (effective.id as string | null) ?? null,
    });
  }
  return out;
}

async function edgeFacts(
  ctx: { db: Db },
  relay: Relay,
  cfg: EdgeConfig,
): Promise<SetupEdgeFacts[]> {
  const edges = await liveEdgesOfRelay(ctx.db, relay._id);
  const listeners = await listenersOf(ctx, relay._id);
  const out: SetupEdgeFacts[] = [];
  for (const e of edges) {
    const listener = listeners.find((l) => l._id === e.listenerId) ?? null;
    const admin = mapEdgeAdmin(e);
    const check =
      e.status === 'active' && e.publication === 'unpublished'
        ? await checkPublishable(ctx, e, cfg.requireProviderHealth)
        : null;
    const publishable: SetupEdgeFacts['publishable'] = check
      ? check.ok
        ? { ok: true }
        : { ok: false, code: check.code ?? 'unpublishable' }
      : null;
    out.push({
      id: e._id as string,
      listenerKey: listener?.listenerKey ?? '',
      layer: (e.layer ?? edgeLayerOf(e.provider)) as 'l4' | 'l7',
      provider: e.provider ?? null,
      accountId: (e.accountId as string | undefined) ?? null,
      status: e.status,
      publication: e.publication,
      poolIndex: e.poolIndex ?? null,
      frontQualification: admin.frontQualification
        ? {
            ok: admin.frontQualification.ok,
            current: admin.frontQualification.current,
            code: admin.frontQualification.code,
          }
        : null,
      publishable,
    });
  }
  return out;
}

async function lastRotations(db: Db, relayId: Id<'relays'>) {
  const rows = await db
    .query('edgeRotations')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .order('desc')
    .take(3);
  return rows;
}

async function relayFacts(
  ctx: { db: Db },
  relay: Relay,
  cfg: EdgeConfig,
  opts: { withPreview: boolean },
): Promise<{
  relay: NonNullable<SetupInput['relay']>;
  render: SetupInput['render'];
  listeners: ListenerLike[];
}> {
  const listenerRows = await listenersOf(ctx, relay._id);
  const listeners: ListenerLike[] = listenerRows.map((l) => ({
    key: l.listenerKey,
    proto: { protocol: l.protocol, streamTransport: l.streamTransport, security: l.security },
    row: l,
    draft: null,
  }));
  const rotations = await lastRotations(ctx.db, relay._id);
  const active = relay.activeRotationId ? await ctx.db.get(relay.activeRotationId) : null;
  const lastTerminal = rotations.find((r) => isTerminalPhase(r.phase)) ?? null;
  const server = relay.backendServerId ? await ctx.db.get(relay.backendServerId) : null;
  const bindingState = await bindingStateOf(ctx.db, relay);
  const endpoints = await connectionPlanCount(ctx, relay);
  let preview: SetupInput['render']['preview'] = null;
  if (
    opts.withPreview &&
    relay.origin.kind !== 'manual' &&
    publishedCount(relay.publishedEdgeIds) > 0
  ) {
    try {
      const fam = RENDER_CLIENT_FAMILIES[0];
      const p = await renderPreviewFor(ctx, relay, fam);
      preview = {
        family: fam,
        applied: p.applied,
        reason: p.reason,
        emitted: p.emitted,
        mismatched: (p.listeners ?? []).filter((l) => l.reason === 'entry_mismatch').length,
      };
    } catch {
      preview = {
        family: RENDER_CLIENT_FAMILIES[0],
        applied: false,
        reason: 'preview_failed',
        emitted: 0,
        mismatched: 0,
      };
    }
  }
  return {
    listeners,
    render: { enabled: cfg.render.enabled, preview },
    relay: {
      id: relay._id as string,
      slug: relay.slug,
      enabled: relay.enabled,
      deleting: relay.deleting ?? false,
      quarantined: !!relay.quarantine,
      hostMode: relay.hostMode,
      autoRotate: relay.autoRotate,
      publishedCount: publishedCount(relay.publishedEdgeIds),
      rotation:
        active && !isTerminalPhase(active.phase)
          ? {
              id: active._id as string,
              kind: active.kind,
              phase: active.phase,
              terminal: false,
              outcome: active.outcome ?? null,
            }
          : null,
      lastRotation: lastTerminal
        ? {
            kind: lastTerminal.kind,
            phase: lastTerminal.phase,
            outcome: lastTerminal.outcome ?? null,
          }
        : null,
      edges: await edgeFacts(ctx, relay, cfg),
      deliveryRequired: bindingState.bound,
      foreignBinding: bindingState.foreign,
      bindingDeferred: relay.bindingDeferred === true,
      connectionPlanCount: endpoints,
      // Mirror validation is driven by the mirror refresh cron over every
      // subscription (no per-node index exists on a traffic-scaled table), so
      // the setup never counts them; the delivery card explains the refresh.
      mirrorsUnvalidated: 0,
      qualificationCredential: !!relay.qualificationUserId,
      credentialSupported: !!server && capabilitiesOf(server.backend).placement,
    },
  };
}

/** How many listeners have a template edge with an address (the connection plan rows). */
async function connectionPlanCount(ctx: { db: Db }, relay: Relay): Promise<number> {
  const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired && l.deployed);
  let n = 0;
  for (const l of listeners) {
    if (!l.templateEdgeId) continue;
    const e = await ctx.db.get(l.templateEdgeId);
    if (e && e.publication === 'published' && (e.addresses.v4 || e.addresses.hostname)) n++;
  }
  return n;
}

function configFacts(cfg: EdgeConfig): SetupInput['config'] {
  return {
    edgeEnabled: cfg.enabled,
    autoRotate: cfg.autoRotate,
    l7AutoSelect: cfg.l7.autoSelect,
    probeEnabled: cfg.probe.enabled,
    probeSourcesOn: Object.values(cfg.probe.sources).filter(Boolean).length,
    probeCountries: cfg.probe.countries.length,
  };
}

const draftValidator = v.object({
  origin: v.union(
    v.object({
      kind: v.literal('panel-node'),
      backendSlug: v.string(),
      nodeName: v.string(),
      nodeUuid: v.optional(v.union(v.string(), v.null())),
    }),
    v.object({ kind: v.literal('backend-server'), backendSlug: v.string() }),
    v.object({ kind: v.literal('manual') }),
    v.null(),
  ),
  listeners: v.optional(
    v.array(
      v.object({
        protocol: v.string(),
        streamTransport: v.string(),
        security: v.string(),
        originPort: v.optional(v.number()),
        originTransport: v.optional(v.any()),
        tlsNames: v.optional(v.array(v.string())),
      }),
    ),
  ),
});

function stepsView(steps: SetupStep[]) {
  return steps.map((s) => ({
    id: s.id,
    status: s.status,
    blockers: s.blockers,
    warnings: s.warnings,
    facts: s.facts,
  }));
}

/**
 * `GET setup-status[?origin=<slug>]` / `POST setup-status { draft }`.
 * Origin scope judges every step for THAT origin; a draft judges steps 1 to 3
 * against the intended listeners before the row exists; the fleet scope is the
 * per-step aggregation over every origin plus the origins to resume.
 */
export const setupStatus = internalQuery({
  args: { relaySlug: v.optional(v.string()), draft: v.optional(draftValidator) },
  handler: async (ctx, { relaySlug, draft }) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const accounts = await ctx.db.query('edgeProviderAccounts').collect();
    const now = iso(Date.now());
    if (relaySlug) {
      const relay = await ctx.db
        .query('relays')
        .withIndex('by_slug', (q) => q.eq('slug', relaySlug))
        .unique();
      if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
      const f = await relayFacts(ctx, relay, cfg, { withPreview: true });
      const input: SetupInput = {
        origin: await originFacts(ctx.db, relay.origin),
        listeners: f.listeners.map(listenerFacts),
        accounts: await accountFacts(ctx, accounts, f.listeners, cfg.l7.dnsProvidersFront),
        relay: f.relay,
        render: f.render,
        config: configFacts(cfg),
      };
      const r = computeSetupStatus(input);
      // What members get: the attention status's delivery plus `degraded` from
      // the sample render the rendering step just judged.
      const rendering = r.steps.find((s) => s.id === 'rendering');
      const delivery = deliveryOf({
        originKind: relay.origin.kind,
        bound: f.relay.deliveryRequired,
        foreignBinding: f.relay.foreignBinding === true,
        published: f.relay.publishedCount,
        enabled: relay.enabled,
        renderEnabled: input.render.enabled,
        renderBlockers: rendering?.blockers ?? [],
      });
      return {
        scope: 'relay' as const,
        steps: stepsView(r.steps),
        currentStep: r.currentStep,
        complete: r.complete,
        context: {
          relaySlug: relay.slug,
          relayId: relay._id as string,
          originKind: relay.origin.kind,
          backendServerId: (relay.backendServerId as string | undefined) ?? null,
          ...r.context,
        },
        resume: [],
        delivery,
        generatedAt: now,
      };
    }
    if (draft) {
      let origin: RelayOrigin | null = null;
      let backendServerId: string | null = null;
      if (draft.origin && draft.origin.kind !== 'manual') {
        const server = await ctx.db
          .query('backendServers')
          .withIndex('by_slug', (q) =>
            q.eq(
              'slug',
              draft.origin!.kind === 'manual'
                ? ''
                : (draft.origin as { backendSlug: string }).backendSlug,
            ),
          )
          .unique();
        if (server) {
          backendServerId = server._id as string;
          origin =
            draft.origin.kind === 'panel-node'
              ? {
                  kind: 'panel-node',
                  backendServerId: server._id,
                  nodeName: draft.origin.nodeName,
                  nodeUuid: draft.origin.nodeUuid ?? undefined,
                }
              : { kind: 'backend-server', backendServerId: server._id };
        }
      } else if (draft.origin?.kind === 'manual') origin = { kind: 'manual' };
      const listeners: ListenerLike[] = (draft.listeners ?? []).map((l, i) => ({
        key: `draft${i + 1}`,
        proto: {
          protocol: l.protocol as Listener['protocol'],
          streamTransport: l.streamTransport as Listener['streamTransport'],
          security: l.security as Listener['security'],
        },
        row: null,
        draft: {
          originPort: l.originPort,
          originTransport: l.originTransport as Listener['originTransport'],
          tlsNames: l.tlsNames,
        },
      }));
      const originF: SetupInput['origin'] = origin
        ? await originFacts(ctx.db, origin)
        : draft.origin && draft.origin.kind !== 'manual'
          ? {
              kind: draft.origin.kind,
              backendPresent: false,
              backendHealthy: null,
              backendHostManagement: false,
              backendNodeInventory: false,
            }
          : null;
      const input: SetupInput = {
        origin: originF,
        listeners: listeners.map(listenerFacts),
        accounts: await accountFacts(ctx, accounts, listeners, cfg.l7.dnsProvidersFront),
        relay: null,
        render: { enabled: cfg.render.enabled, preview: null },
        config: configFacts(cfg),
      };
      const r = computeSetupStatus(input);
      return {
        scope: 'draft' as const,
        steps: stepsView(r.steps),
        currentStep: r.currentStep,
        complete: false,
        context: {
          relaySlug: null,
          relayId: null,
          originKind: draft.origin?.kind ?? null,
          backendServerId,
          ...r.context,
        },
        resume: [],
        delivery: null,
        generatedAt: now,
      };
    }
    // Fleet aggregation.
    const relays = (await ctx.db.query('relays').collect()).sort((a, b) =>
      a.slug.localeCompare(b.slug),
    );
    const perRelay: Array<{ relay: Relay; result: ReturnType<typeof computeSetupStatus> }> = [];
    for (const relay of relays) {
      const f = await relayFacts(ctx, relay, cfg, { withPreview: false });
      const input: SetupInput = {
        origin: await originFacts(ctx.db, relay.origin),
        listeners: f.listeners.map(listenerFacts),
        accounts: await accountFacts(ctx, accounts, f.listeners, cfg.l7.dnsProvidersFront),
        relay: f.relay,
        render: f.render,
        config: configFacts(cfg),
      };
      perRelay.push({ relay, result: computeSetupStatus(input) });
    }
    let steps: SetupStep[];
    if (perRelay.length === 0) {
      // No origin yet: the fleet-level facts alone (accounts, templates, config).
      const input: SetupInput = {
        origin: null,
        listeners: [],
        accounts: await accountFacts(ctx, accounts, [], cfg.l7.dnsProvidersFront),
        relay: null,
        render: { enabled: cfg.render.enabled, preview: null },
        config: configFacts(cfg),
      };
      steps = computeSetupStatus(input).steps;
    } else {
      steps = perRelay[0].result.steps.map((s) => {
        const all = perRelay.map((p) => p.result.steps.find((x) => x.id === s.id)!);
        const done = all.every((x) => x.status === 'done' || x.status === 'skipped');
        const blockers = all.flatMap((x, i) =>
          x.blockers.map((b) => ({ ...b, subject: b.subject ?? perRelay[i].relay.slug })),
        );
        const warnings = all.flatMap((x, i) =>
          x.warnings.map((b) => ({ ...b, subject: b.subject ?? perRelay[i].relay.slug })),
        );
        return {
          id: s.id,
          status: done ? ('done' as const) : ('blocked' as const),
          blockers: blockers.slice(0, 20),
          warnings: warnings.slice(0, 20),
          facts: { relays: all.length, done: all.filter((x) => x.status === 'done').length },
        };
      });
    }
    const firstOpen = steps.find((s) => s.status !== 'done' && s.status !== 'skipped');
    return {
      scope: 'fleet' as const,
      steps: stepsView(steps),
      currentStep: (firstOpen?.id as SetupStepId | undefined) ?? null,
      complete: perRelay.length > 0 && perRelay.every((p) => p.result.complete),
      context: {
        relaySlug: null,
        relayId: null,
        originKind: null,
        backendServerId: null,
        accountId: null,
        templateId: null,
        listenerKey: null,
        edgeId: null,
      },
      resume: perRelay
        .filter((p) => !p.result.complete)
        .map((p) => ({
          relaySlug: p.relay.slug,
          relayId: p.relay._id as string,
          currentStep: p.result.currentStep,
          complete: p.result.complete,
        })),
      delivery: null,
      generatedAt: now,
    };
  },
});

// --- attention ------------------------------------------------------------------------------------

// The server's ranking of every attention kind, most urgent first, lives in
// lib/edges/originStatus.ts (the origin status ranks by it too); re-exported here.
export { ATTENTION_RANK };
type AttentionKind = (typeof ATTENTION_RANK)[number];

interface AttentionItem {
  id: string;
  kind: AttentionKind;
  severity: 'critical' | 'warning' | 'info';
  relaySlug: string | null;
  relayId: string | null;
  edgeId: string | null;
  listenerKey: string | null;
  accountId: string | null;
  rotationId: string | null;
  code: string | null;
  facts: Record<string, unknown>;
  action:
    | 'resolve_quarantine'
    | 'resolve_operator'
    | 'look_at_host'
    | 'open_setup'
    | 'open_relay'
    | 'open_edge'
    | 'open_account'
    | 'open_settings'
    | 'publish'
    | 'provision'
    | 'qualify_front'
    | 'rotate'
    | 'test_credentials'
    | 'verify_endpoint'
    | 'thaw'
    | 'rebalance'
    | 'require_edges'
    | 'protect_node'
    | 'open_node'
    | 'open_modes'
    | 'open_probes';
  since: string | null;
}

const RECENT_FAILURE_MS = 24 * 60 * 60_000;
/** A rotation still running after this long is stuck (its wall clock fails it later). */
export const STUCK_ROTATION_MS = 60 * 60_000;
/** A live managed edge whose provider health was not refreshed for this long (at least). */
const HEALTH_STALE_MIN_MS = 60 * 60_000;

/**
 * The enrolled nodes that wait on the operator: a FRONTED node whose machine
 * is ready and that nobody has started protecting (`node_ready_to_protect`),
 * and a node whose go-live waits for an approval (`node_awaiting_approval`:
 * tested and not approved yet, parked after a block, or a protect run parked
 * at `node_not_approved`), and a LIVE node whose connection mode is turned off
 * (`node_mode_disabled`: no member can pick it, so it serves nobody). Facts name
 * the server and the node so the row can link to them; never an address.
 */
async function nodeAttention(ctx: QueryCtx, relays: Relay[]): Promise<AttentionItem[]> {
  const out: AttentionItem[] = [];
  // Operator-scale: one row per enrolled node.
  const intents = await ctx.db.query('panelNodeIntents').collect();
  const { modes: catalog } = await resolveModeCatalog(ctx.db);
  const slugs = new Map<string, string | null>();
  for (const i of intents) {
    if (i.state === 'retiring' || i.state === 'retired') continue;
    const sid = i.backendServerId as string;
    if (!slugs.has(sid)) slugs.set(sid, (await ctx.db.get(i.backendServerId))?.slug ?? null);
    const mode = await modeRefOf(ctx, i);
    const fronted = mode.shape.fronting !== 'direct';
    const open =
      (
        await ctx.db
          .query('edgeSetupRuns')
          .withIndex('by_origin', (q) =>
            q.eq('backendServerId', i.backendServerId).eq('nodeName', i.name),
          )
          .collect()
      ).find((r) => r.state === 'running' || r.state === 'waiting' || r.state === 'needs_you') ??
      null;
    const relay =
      relays.find(
        (r) =>
          r.backendServerId === i.backendServerId &&
          r.origin.kind === 'panel-node' &&
          r.origin.nodeName === i.name,
      ) ?? null;
    const stage = i.activation.stage;
    const common = {
      relaySlug: relay?.slug ?? null,
      relayId: relay ? (relay._id as string) : null,
      edgeId: null,
      listenerKey: null,
      accountId: null,
      rotationId: null,
      facts: {
        serverSlug: slugs.get(sid) ?? null,
        nodeUuid: i.nodeUuid ?? null,
        node: i.name,
        stage,
        ...(open ? { runId: open._id as string } : {}),
      },
    };
    if (stage === 'live' && !(catalog.find((m) => m.id === mode.slug)?.enabled ?? false))
      out.push({
        ...common,
        id: `node_mode_disabled:${i._id}`,
        kind: 'node_mode_disabled',
        severity: 'warning',
        code: null,
        action: 'open_modes',
        facts: { ...common.facts, mode: mode.slug },
        since: iso(i.updatedAt),
      });
    const waitingApproval =
      stage === 'candidates_verified' ||
      stage === 'awaiting_approval' ||
      (open?.state === 'needs_you' && open.need?.code === 'node_not_approved');
    if (waitingApproval) {
      out.push({
        ...common,
        id: `node_awaiting_approval:${i._id}`,
        kind: 'node_awaiting_approval',
        severity: 'warning',
        code: open?.need?.code ?? stage,
        action: 'open_node',
        since: iso(i.updatedAt),
      });
    } else if (
      fronted &&
      stage === 'machine_ready' &&
      i.state === 'ready' &&
      !i.adopted &&
      !open &&
      !relay?.setupOwned
    ) {
      out.push({
        ...common,
        id: `node_ready_to_protect:${i._id}`,
        kind: 'node_ready_to_protect',
        severity: 'warning',
        code: null,
        action: 'protect_node',
        since: iso(i.updatedAt),
      });
    }
  }
  return out;
}

/** The delivery binding that covers an origin's node (a manual origin has none). */
async function bindingOf(db: Db, relay: Relay) {
  return relay.origin.kind !== 'manual' && relay.backendServerId
    ? deliveryBindingFor(db, relay.backendServerId, relay.nodeName ?? undefined)
    : null;
}

/**
 * Whose binding covers the origin's node. `bound`: it names this origin (its
 * members are served through it). `foreign`: it names an origin that no longer
 * exists (deleted `keep-dark`), so members get `relay_missing` whatever this
 * origin publishes. A binding naming another live origin is neither.
 */
async function bindingStateOf(
  db: Db,
  relay: Relay,
): Promise<{ binding: Doc<'edgeDeliveryBindings'> | null; bound: boolean; foreign: boolean }> {
  const binding = await bindingOf(db, relay);
  if (!binding) return { binding, bound: false, foreign: false };
  if (binding.relaySlug === relay.slug) return { binding, bound: true, foreign: false };
  const named = await db
    .query('relays')
    .withIndex('by_slug', (q) => q.eq('slug', binding.relaySlug))
    .unique();
  return { binding, bound: false, foreign: !named || named.deleting === true };
}

/**
 * The live (non-terminal) guided setup run of an origin, through the run's
 * node (`by_origin`): a node has at most one live run, always its newest. A
 * manual origin, or a backend server without a node name, has none.
 */
async function liveSetupRunOf(db: Db, relay: Relay): Promise<Doc<'edgeSetupRuns'> | null> {
  const serverId = relay.origin.kind === 'manual' ? undefined : relay.origin.backendServerId;
  const nodeName = relay.origin.kind === 'panel-node' ? relay.origin.nodeName : relay.nodeName;
  if (!serverId || !nodeName) return null;
  const rows = await db
    .query('edgeSetupRuns')
    .withIndex('by_origin', (q) => q.eq('backendServerId', serverId).eq('nodeName', nodeName))
    .order('desc')
    .take(5);
  return (
    rows.find(
      (r) => !isTerminalRunState(r.state) && (r.relayId === undefined || r.relayId === relay._id),
    ) ?? null
  );
}

/** The facts one origin's status is judged on (lib/edges/originStatus.ts), but its attention items. */
async function statusFactsOf(
  db: Db,
  relay: Relay,
  edges: Edge[],
  bindingState: { bound: boolean; foreign: boolean },
  renderEnabled: boolean,
): Promise<Omit<OriginStatusFacts, 'attention'>> {
  const pool: OriginStatusFacts['pool'][number][] = [];
  for (const id of relay.publishedEdgeIds) {
    const e = id ? edges.find((x) => x._id === id) : undefined;
    if (e) pool.push({ health: e.health, layer: e.layer ?? 'l4' });
  }
  const run = await liveSetupRunOf(db, relay);
  const runFacts: StatusRunFacts | null = run
    ? {
        id: run._id as string,
        kind: run.kind ?? null,
        stage: run.stage,
        state: run.state,
        need: run.need ?? null,
      }
    : null;
  return {
    originKind: relay.origin.kind,
    enabled: relay.enabled,
    quarantined: !!relay.quarantine,
    restore: !!relay.restore,
    deleting: relay.deleting ?? false,
    bindingDeferred: relay.bindingDeferred === true,
    setupOwned: relay.setupOwned === true,
    published: publishedCount(relay.publishedEdgeIds),
    pool,
    standbys: edges.filter((e) => e.status === 'active' && e.publication === 'unpublished').length,
    bound: bindingState.bound,
    foreignBinding: bindingState.foreign,
    renderEnabled,
    run: runFacts,
  };
}

/**
 * Server-ranked list of what needs the operator, one action per item, plus the
 * one status of every origin (`origins`, deleting ones included, slug order)
 * and the fleet headline (`fleet`), judged in lib/edges/originStatus.ts.
 */
export const attention = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const items: AttentionItem[] = [];
    const now = Date.now();
    const base = (relay: Relay) => ({
      relaySlug: relay.slug,
      relayId: relay._id as string,
      edgeId: null,
      listenerKey: null,
      accountId: null,
      rotationId: null,
      code: null,
      facts: {},
      since: null,
    });
    const relays = await ctx.db.query('relays').collect();
    // Provider health refresh: a live managed edge is described every few
    // polls; one whose health has not been refreshed for this long means the
    // refresh keeps failing (or never runs) for its account.
    const healthStaleMs = Math.max(HEALTH_STALE_MIN_MS, EDGE_PLUMBING.pollMs * 30);
    const staleByAccount = new Map<string, number>();
    // Per origin, the facts its status is judged on (after every item exists).
    const statusFacts = new Map<string, Omit<OriginStatusFacts, 'attention'>>();
    for (const relay of relays) {
      if (relay.deleting) {
        const state = await bindingStateOf(ctx.db, relay);
        const edges = await liveEdgesOfRelay(ctx.db, relay._id);
        statusFacts.set(
          relay._id as string,
          await statusFactsOf(ctx.db, relay, edges, state, cfg.render.enabled),
        );
        continue;
      }
      const edges = await liveEdgesOfRelay(ctx.db, relay._id);
      // (A quarantined origin is skipped by the refresh on purpose.)
      if (!relay.quarantine)
        for (const e of edges) {
          if (!e.managed || !e.accountId || e.status !== 'active') continue;
          if (now - (e.lastHealthAt ?? e.statusChangedAt) <= healthStaleMs) continue;
          const k = e.accountId as string;
          staleByAccount.set(k, (staleByAccount.get(k) ?? 0) + 1);
        }
      // With the enrolled node's auth revision: the endpoint ticks bind to it.
      const listeners = await verificationListenersOf(
        ctx.db,
        relay,
        await listenersOf(ctx, relay._id),
      );
      if (relay.quarantine) {
        items.push({
          ...base(relay),
          id: `quarantine:${relay._id}`,
          kind: 'quarantine',
          severity: 'critical',
          rotationId: relay.quarantine.rotationId as string,
          code: relay.quarantine.reason,
          action: 'resolve_quarantine',
          since: iso(relay.quarantine.since),
        });
      }
      for (const e of edges) {
        if (e.status === 'needs_operator') {
          items.push({
            ...base(relay),
            id: `needs_operator:${e._id}`,
            kind: 'needs_operator',
            severity: 'critical',
            edgeId: e._id as string,
            code: e.failure?.code ?? e.failure?.step ?? null,
            facts: { provider: e.provider ?? null, layer: e.layer ?? 'l4' },
            action: 'resolve_operator',
            since: iso(e.statusChangedAt),
          });
        }
      }
      for (const l of listeners) {
        const st = l.host;
        if (!st || l.retired) continue;
        const stuck =
          st.state === 'ambiguous' ||
          st.state === 'unresolved' ||
          (!!st.op && now >= st.op.expiresAt);
        if (stuck) {
          items.push({
            ...base(relay),
            id: `host_unresolved:${l._id}`,
            kind: 'host_unresolved',
            severity: st.state === 'ambiguous' ? 'critical' : 'warning',
            listenerKey: l.listenerKey,
            code: st.state,
            facts: { op: st.op?.kind ?? null, attempts: st.op?.attempts ?? 0 },
            action: 'look_at_host',
            since: isoN(st.op?.claimedAt),
          });
        }
      }
      const published = publishedCount(relay.publishedEdgeIds);
      const bindingState = await bindingStateOf(ctx.db, relay);
      const binding = bindingState.binding;
      // The one `members_dark` rule (the origin status's `dark` delivery too).
      const darkCode = membersDarkCode({
        bound: bindingState.bound,
        foreignBinding: bindingState.foreign,
        published,
        enabled: relay.enabled,
        renderEnabled: cfg.render.enabled,
      });
      if (darkCode) {
        items.push({
          ...base(relay),
          id: `members_dark:${relay._id}`,
          kind: 'members_dark',
          severity: 'critical',
          code: darkCode,
          facts: { published },
          action: 'open_setup',
          since: isoN(binding?.updatedAt),
        });
      }
      statusFacts.set(
        relay._id as string,
        await statusFactsOf(ctx.db, relay, edges, bindingState, cfg.render.enabled),
      );
      // A direct Host reappeared on a bound guided node and could not be
      // re-hidden: delivery is fail-closed (`leak_detected`) until it is hidden.
      if (relay.directHostAlert && relay.directHostAlert.hosts.length > 0) {
        items.push({
          ...base(relay),
          id: `direct_host_reappeared:${relay._id}`,
          kind: 'direct_host_reappeared',
          severity: 'critical',
          code: null,
          facts: {
            count: relay.directHostAlert.hosts.length,
            remarks: relay.directHostAlert.hosts.map((h) => h.remark),
          },
          action: 'open_relay',
          since: iso(relay.directHostAlert.at),
        });
      }
      // The restore workflow: informational, one phase per reconcile tick.
      if (relay.restore) {
        items.push({
          ...base(relay),
          id: `restore_in_progress:${relay._id}`,
          kind: 'restore_in_progress',
          severity: 'info',
          code: relay.restore.lastError ?? null,
          facts: {
            purpose: relay.restore.purpose,
            phase: relay.restore.phase,
            attempt: relay.restore.attempt,
          },
          action: 'open_relay',
          since: iso(relay.restore.startedAt),
        });
      }
      // A guided origin with something published but its binding still deferred:
      // members get the raw body until go-live claims the binding.
      if (relay.bindingDeferred && published > 0 && relay.enabled && !relay.restore) {
        items.push({
          ...base(relay),
          id: `go_live_pending:${relay._id}`,
          kind: 'go_live_pending',
          severity: 'warning',
          code: null,
          facts: { published },
          action: 'require_edges',
          since: isoN(relay.updatedAt),
        });
      }
      // A rotation running far longer than any of its steps needs: the reconcile
      // re-kicks it, and its wall clock ends it later, but the operator should
      // look now (a provider that never answers, a Host that never settles).
      if (relay.activeRotationId) {
        const rot = await ctx.db.get(relay.activeRotationId);
        if (rot && !isTerminalPhase(rot.phase) && now - rot.startedAt > STUCK_ROTATION_MS) {
          items.push({
            ...base(relay),
            id: `rotation_stuck:${rot._id}`,
            kind: 'rotation_stuck',
            severity: 'critical',
            rotationId: rot._id as string,
            code: rot.phase,
            facts: {
              kind: rot.kind,
              phase: rot.phase,
              minutes: Math.round((now - rot.startedAt) / 60_000),
            },
            action: 'open_relay',
            since: iso(rot.startedAt),
          });
        }
      }
      // Billable but idle: provider resources FCP pays for that serve nobody
      // until the operator acts (a frozen origin's edges; an edge parked for
      // an operator whose resources are still present).
      const held = relay.quarantine
        ? edges.filter((e) => e.managed && !!e.accountId)
        : edges.filter(
            (e) =>
              e.managed &&
              e.status === 'needs_operator' &&
              e.resources.some((r) => r.deleteState !== 'confirmed_gone'),
          );
      if (held.length > 0) {
        items.push({
          ...base(relay),
          id: `billable_idle:${relay._id}`,
          kind: 'billable_idle',
          severity: 'warning',
          edgeId: held.length === 1 ? (held[0]._id as string) : null,
          rotationId: relay.quarantine ? (relay.quarantine.rotationId as string) : null,
          code: relay.quarantine ? 'quarantine' : 'needs_operator',
          facts: { edges: held.length },
          action: relay.quarantine ? 'resolve_quarantine' : 'resolve_operator',
          since: relay.quarantine
            ? iso(relay.quarantine.since)
            : iso(Math.min(...held.map((e) => e.statusChangedAt))),
        });
      }
      const [last] = await lastRotations(ctx.db, relay._id);
      if (
        last &&
        (last.phase === 'failed' || last.phase === 'rolled_back') &&
        (last.finishedAt ?? last.updatedAt) > now - RECENT_FAILURE_MS
      ) {
        items.push({
          ...base(relay),
          id: `rotation_failed:${last._id}`,
          kind: 'rotation_failed',
          severity: 'warning',
          rotationId: last._id as string,
          code: last.outcome ?? last.phase,
          facts: { kind: last.kind, phase: last.phase },
          action: 'open_relay',
          since: isoN(last.finishedAt ?? last.updatedAt),
        });
      }
      for (const e of edges) {
        if (e.publication !== 'published' || (e.layer ?? 'l4') !== 'l7') continue;
        const listener = listeners.find((l) => l._id === e.listenerId) ?? null;
        const intent = parseIntent(e.provisionIntent);
        const admin = mapEdgeAdmin(e);
        if (!listener || !intent || !admin.frontQualification?.current) {
          items.push({
            ...base(relay),
            id: `qualification_lapsed:${e._id}`,
            kind: 'qualification_lapsed',
            severity: 'warning',
            edgeId: e._id as string,
            listenerKey: listener?.listenerKey ?? null,
            code: admin.frontQualification?.code ?? 'front_unqualified',
            action: 'qualify_front',
            since: admin.frontQualification?.expiresAt ?? null,
          });
        }
      }
      // Test block evidence (edgeSimulations.ts) is running on this origin: it
      // can replace an edge for real, so it is never out of sight.
      const simulations = await ctx.db
        .query('edgeBlockSimulations')
        .withIndex('by_relay_live', (q) =>
          q.eq('relayId', relay._id).eq('endedAt', undefined).gt('expiresAt', now),
        )
        .take(20);
      if (simulations.length > 0) {
        items.push({
          ...base(relay),
          edgeId: simulations[0].edgeId as string,
          id: `block_simulated:${relay._id}`,
          kind: 'block_simulated',
          severity: 'warning',
          facts: {
            count: simulations.length,
            countries: [...new Set(simulations.map((s) => s.country))],
          },
          action: 'open_relay',
          since: iso(Math.min(...simulations.map((s) => s.startedAt))),
        });
      }
      if (relay.suspicion?.state === 'suspected') {
        // A one-click replace needs ONE target: the single published edge the
        // evidence names. Anything else (no edge-level evidence, several edges)
        // is a decision for the origin page, not a blind call.
        const evidenced = [
          ...new Set(relay.suspicion.edgeEvidence.map((e) => e.edgeId as string)),
        ].filter((id) => edges.some((e) => e._id === id && e.publication === 'published'));
        const suspect = evidenced.length === 1 ? evidenced[0] : null;
        items.push({
          ...base(relay),
          edgeId: suspect,
          id: `block_suspected:${relay._id}`,
          kind: 'block_suspected',
          severity: 'warning',
          code: relay.suspicion.veto ?? null,
          facts: {
            score: relay.suspicion.score,
            hintLevel: relay.suspicion.hintLevel,
            countries: relay.suspicion.countries.map((c) => c.code),
          },
          action: suspect ? 'rotate' : 'open_relay',
          since: isoN(relay.suspicion.firstSeenAt),
        });
      }
      // Endpoint verification (lib/edges/verification.ts). Three cards, one
      // action each (`verify_endpoint` on the edge that needs the test):
      //  needs_test     critical: the origin is suspected AND its automatic
      //                 replacement was refused for want of a TESTED spare
      //                 (`edge.no_verified_spare`), or a suspected origin has
      //                 only untested L4 spares;
      //  retest_needed  warning: a published / standby L4 edge whose tick went
      //                 stale (listener revision or configuration changed);
      //  spare_untested warning: an active unpublished L4 edge never confirmed.
      const l4Edges = edges.filter((e) => e.status === 'active' && needsEndpointVerification(e));
      const listenerOf = (e: (typeof edges)[number]) =>
        listeners.find((l) => l._id === e.listenerId) ?? null;
      const untestedSpares = l4Edges.filter((e) => {
        const l = listenerOf(e);
        return e.publication === 'unpublished' && !!l && !verificationCurrent(e, l);
      });
      const replaceRefused = relay.suspicion?.lastRotateError === 'edge.no_verified_spare';
      if (relay.suspicion?.state === 'suspected' && (replaceRefused || untestedSpares.length > 0)) {
        const first = untestedSpares[0] ?? null;
        items.push({
          ...base(relay),
          id: `needs_test:${relay._id}`,
          kind: 'needs_test',
          severity: 'critical',
          edgeId: first ? (first._id as string) : null,
          listenerKey: first ? (listenerOf(first)?.listenerKey ?? null) : null,
          code: replaceRefused ? 'no_verified_spare' : 'unverified_endpoint',
          facts: { untestedSpares: untestedSpares.length },
          action: first ? 'verify_endpoint' : 'provision',
          since: isoN(relay.suspicion.firstSeenAt),
        });
      }
      for (const e of l4Edges) {
        const l = listenerOf(e);
        if (!l || l.retired) continue;
        if (verificationCurrent(e, l)) continue;
        const stale = verificationStale(e, l);
        if (e.publication === 'unpublished' && !stale) {
          items.push({
            ...base(relay),
            id: `spare_untested:${e._id}`,
            kind: 'spare_untested',
            severity: 'warning',
            edgeId: e._id as string,
            listenerKey: l.listenerKey,
            code: 'unverified_endpoint',
            facts: { publication: e.publication },
            action: 'verify_endpoint',
            since: iso(e.statusChangedAt),
          });
        } else if (stale) {
          items.push({
            ...base(relay),
            id: `retest_needed:${e._id}`,
            kind: 'retest_needed',
            severity: 'warning',
            edgeId: e._id as string,
            listenerKey: l.listenerKey,
            // `reality_key_changed` when only the node's REALITY key moved.
            code: verificationStaleReason(e, l) ?? 'verification_stale',
            facts: {
              publication: e.publication,
              verifiedRevision: e.verification?.listenerRevision ?? null,
              listenerRevision: l.revision,
            },
            action: 'verify_endpoint',
            since: isoN(e.verification?.at),
          });
        }
      }
      for (const e of edges) {
        if (e.publication !== 'published') continue;
        const unreachable = (e.reachability?.byCountry ?? []).filter(
          (c) => c.verdict === 'unreachable' && c.country !== 'XX',
        );
        if (unreachable.length > 0) {
          items.push({
            ...base(relay),
            id: `edge_unreachable:${e._id}`,
            kind: 'edge_unreachable',
            severity: 'warning',
            edgeId: e._id as string,
            code: 'unreachable',
            facts: { countries: unreachable.map((c) => c.country) },
            action: 'open_edge',
            since: isoN(e.reachability?.updatedAt),
          });
        }
      }
      // Checks from each country: a new address (active, never in use) whose
      // round finds it blocked in a checked country, before anyone relies on it.
      if (cfg.country.enabled)
        for (const e of edges) {
          const blockedIn = await newEdgeBlockedIn(ctx.db, e, cfg.probe.countries);
          if (blockedIn.length === 0) continue;
          items.push({
            ...base(relay),
            id: `new_edge_blocked_in:${e._id}`,
            kind: 'new_edge_blocked_in',
            severity: 'warning',
            edgeId: e._id as string,
            listenerKey: listenerOf(e)?.listenerKey ?? null,
            facts: { countries: blockedIn.map((b) => b.country) },
            action: 'open_edge',
            since: iso(Math.min(...blockedIn.map((b) => b.at))),
          });
        }
      // Coverage at the cap: a deployed listener has no published edge, every
      // slot is taken and no expansion can make room. Only a rebalance
      // (unpublishing a duplicate) frees a slot, and that is the operator's call.
      const setState = await setStateOf(ctx.db, relay);
      const capacity = requiredPoolSize({
        desiredPublished: relay.desiredPublished,
        publishedEdgeIds: relay.publishedEdgeIds,
        coverageListeners: setState.listeners.length,
        deficit: setState.deficit,
      });
      if (relay.enabled && capacity.blocked > 0) {
        const waiting = [...new Set(setState.targets.map((t) => t.listenerKey))];
        items.push({
          ...base(relay),
          id: `pool_rebalance:${relay._id}`,
          kind: 'pool_rebalance',
          severity: 'warning',
          listenerKey: waiting[0] ?? null,
          code: null,
          facts: { published, desired: relay.desiredPublished, uncovered: setState.deficit },
          action: 'rebalance',
          since: null,
        });
      }
      // The node's provider set: a pick that cools after a burn (no automatic
      // work goes there until it ends), and transports whose picks give no
      // backup in another failure domain (reported, never hidden).
      if (relay.enabled && relay.providerSet) {
        for (const c of relay.cooling ?? []) {
          if (c.until <= now) continue;
          const loc = await ctx.db.get(c.locationId);
          items.push({
            ...base(relay),
            id: `pick_cooling:${relay._id}:${c.locationId}`,
            kind: 'pick_cooling',
            severity: 'info',
            code: null,
            facts: {
              location: loc?.label ?? '',
              minutesLeft: Math.ceil((c.until - now) / 60_000),
            },
            action: 'open_relay',
            since: null,
          });
        }
        const reduced = setState.requirement.reduced;
        if (reduced.length > 0)
          items.push({
            ...base(relay),
            id: `reduced_resilience:${relay._id}`,
            kind: 'reduced_resilience',
            severity: 'info',
            listenerKey: reduced[0]!.listenerKey,
            code: 'one_group',
            facts: { count: reduced.length },
            action: 'open_relay',
            since: null,
          });
      }
      if (relay.enabled && published < relay.desiredPublished) {
        const idle = edges.filter((e) => e.status === 'active' && e.publication === 'unpublished');
        const standbys = idle.length;
        // The publish action names the first standby that would actually pass
        // the publish checks; with none publishable the operator is sent to the
        // origin page instead of a call that cannot run.
        let publishable: string | null = null;
        for (const e of idle) {
          if ((await checkPublishable(ctx, e, cfg.requireProviderHealth)).ok) {
            publishable = e._id as string;
            break;
          }
        }
        items.push({
          ...base(relay),
          edgeId: publishable,
          id: `pool_below_desired:${relay._id}`,
          kind: 'pool_below_desired',
          severity: published === 0 ? 'warning' : 'info',
          code: null,
          facts: { published, desired: relay.desiredPublished, standbys },
          action: publishable ? 'publish' : standbys > 0 ? 'open_relay' : 'provision',
          since: null,
        });
      }
    }
    const accounts = await ctx.db.query('edgeProviderAccounts').collect();
    for (const a of accounts) {
      // A disabled account still holds live edges that need provider calls
      // (health, destroy): its API health stays visible; the setup-oriented
      // items below are for enabled accounts only.
      // The provider's API keeps failing (timeouts, 5xx, refused credentials):
      // every rotation, health refresh and destroy on this account stalls.
      if ((a.apiFailures ?? 0) >= API_FAILING_AFTER) {
        items.push({
          id: `account_api_failing:${a._id}`,
          kind: 'account_api_failing',
          severity: 'critical',
          relaySlug: null,
          relayId: null,
          edgeId: null,
          listenerKey: null,
          accountId: a._id as string,
          rotationId: null,
          code: a.lastApiError ?? null,
          facts: { name: a.name, provider: a.provider, failures: a.apiFailures ?? 0 },
          action: 'open_account',
          since: isoN(a.apiFailingSince),
        });
      }
      // A daily budget of 0 means no limit on billable allocations; new rows
      // refuse it outside development, older ones are pointed out here.
      if (a.enabled && a.dailyAllocationBudget === 0 && process.env.ENVIRONMENT !== 'development') {
        items.push({
          id: `account_budget_unlimited:${a._id}`,
          kind: 'account_budget_unlimited',
          severity: 'warning',
          relaySlug: null,
          relayId: null,
          edgeId: null,
          listenerKey: null,
          accountId: a._id as string,
          rotationId: null,
          code: null,
          facts: { name: a.name, provider: a.provider },
          action: 'open_account',
          since: null,
        });
      }
      const stale = staleByAccount.get(a._id as string) ?? 0;
      if (stale > 0) {
        items.push({
          id: `health_stale:${a._id}`,
          kind: 'health_stale',
          severity: 'warning',
          relaySlug: null,
          relayId: null,
          edgeId: null,
          listenerKey: null,
          accountId: a._id as string,
          rotationId: null,
          code: null,
          facts: { name: a.name, provider: a.provider, edges: stale },
          action: 'open_account',
          since: null,
        });
      }
      if (!a.enabled) continue;
      if (!accountTested(a)) {
        items.push({
          id: `account_untested:${a._id}`,
          kind: 'account_untested',
          severity: a.lastTestError ? 'warning' : 'info',
          relaySlug: null,
          relayId: null,
          edgeId: null,
          listenerKey: null,
          accountId: a._id as string,
          rotationId: null,
          code: a.lastTestError ?? null,
          facts: { name: a.name, provider: a.provider },
          action: 'test_credentials',
          since: null,
        });
      } else {
        // Trust is per location: one item per enabled location not trusted yet,
        // naming the location when the account has more than one.
        const locs = (await locationsOfAccount(ctx.db, a._id)).filter((l) => l.enabled);
        for (const loc of locs) {
          if (loc.qualified) continue;
          items.push({
            id: `account_unqualified:${a._id}:${loc._id}`,
            kind: 'account_unqualified',
            severity: 'info',
            relaySlug: null,
            relayId: null,
            edgeId: null,
            listenerKey: null,
            accountId: a._id as string,
            rotationId: null,
            code: null,
            facts: {
              name: a.name,
              provider: a.provider,
              ...(locs.length > 1 ? { location: loc.label } : {}),
              locationId: loc._id as string,
            },
            action: 'open_account',
            since: null,
          });
        }
      }
    }
    // Temporary test keys whose backend delete kept failing (edgeTestCredentials.ts).
    const fleetBase = {
      relaySlug: null,
      relayId: null,
      edgeId: null,
      listenerKey: null,
      accountId: null,
      rotationId: null,
      code: null,
    };
    const failedKeys = await ctx.db
      .query('edgeTestCredentials')
      .withIndex('by_removal_expires', (q) => q.eq('removal', 'failed'))
      .take(50);
    for (const row of failedKeys) {
      const relay = relays.find((r) => r._id === row.relayId) ?? null;
      items.push({
        id: `test_key_cleanup:${row._id}`,
        kind: 'test_key_cleanup',
        severity: 'warning',
        relaySlug: relay?.slug ?? null,
        relayId: relay ? (relay._id as string) : null,
        edgeId: null,
        listenerKey: null,
        accountId: null,
        rotationId: null,
        code: row.backendUserId ? 'backend_delete_failed' : 'issuance_unobserved',
        facts: { purpose: row.purpose, attempts: row.attempts, credentialId: row._id as string },
        action: 'open_relay',
        since: iso(row.updatedAt),
      });
    }
    // The fleet guards on automatic rotation (lib/edges/fleet.ts).
    const brake = await readFleetBrake(ctx.db);
    if (brake.engaged) {
      items.push({
        ...fleetBase,
        id: 'fleet_brake',
        kind: 'fleet_brake',
        severity: 'critical',
        facts: {
          suspected: brake.suspected,
          evaluated: brake.evaluated,
          threshold: brake.threshold,
        },
        action: 'open_settings',
        since: isoN(brake.since),
      });
    }
    const fleetUsed = await fleetRotationsToday(ctx.db, now);
    // (A cap of 0 means no automatic replacement at all: nothing was "reached".)
    const fleetCap = cfg.detect.fleetRotationsPerDay;
    if (cfg.enabled && cfg.autoRotate && fleetCap > 0 && fleetUsed >= fleetCap) {
      items.push({
        ...fleetBase,
        id: 'fleet_rotation_cap',
        kind: 'fleet_rotation_cap',
        severity: 'warning',
        facts: { used: fleetUsed, cap: cfg.detect.fleetRotationsPerDay },
        action: 'open_settings',
        since: null,
      });
    }
    // Dark members, counted at the subscription route (deliveryRefusals.ts).
    const refusals = await readRefusals(ctx.db, now);
    if (refusals.total > 0) {
      const top = Object.entries(refusals.byReason).sort((x, y) => y[1] - x[1])[0];
      items.push({
        ...fleetBase,
        id: 'delivery_refusals',
        kind: 'delivery_refusals',
        severity: refusals.total >= REFUSALS_CRITICAL_AT ? 'critical' : 'warning',
        code: top?.[0] ?? null,
        facts: {
          total: refusals.total,
          byReason: refusals.byReason,
          windowMinutes: Math.round(REFUSAL_WINDOW_MS / 60_000),
        },
        action: 'open_settings',
        since: isoN(refusals.since),
      });
    }
    // A client family whose render rule is off gets nothing at all on an
    // edge-required node (there is no passthrough): its members are dark.
    const familiesOff = RENDER_CLIENT_FAMILIES.filter((f) => !cfg.render.clients[f].enabled);
    if (familiesOff.length > 0 && cfg.render.enabled) {
      const anyBound = await ctx.db
        .query('edgeDeliveryBindings')
        .filter((q) => q.eq(q.field('state'), 'active'))
        .first();
      if (anyBound) {
        items.push({
          ...fleetBase,
          id: 'family_rule_disabled',
          kind: 'family_rule_disabled',
          severity: 'warning',
          facts: { families: familiesOff },
          action: 'open_settings',
          since: null,
        });
      }
    }
    // A probe source that keeps bringing back nothing (a missing or refused
    // credential, a spent allowance): its failures are never read as blocks, so
    // every country it alone covers silently reads "not known" without this.
    for (const h of await probeSourceHealth(ctx.db, now)) {
      if (!h.failing) continue;
      items.push({
        ...fleetBase,
        id: `probe_source_failing:${h.source}`,
        kind: 'probe_source_failing',
        severity: 'warning',
        code: h.lastError,
        facts: { source: h.source, streak: h.streak, runs: h.runs, lastOkAt: isoN(h.lastOkAt) },
        action: 'open_settings',
        since: isoN(h.lastFailAt),
      });
    }
    // The country-wide guard holds new blocks in a country: most of what is
    // checked there failed at once (an outage or a probe problem, not a
    // censor), so nothing turned blocked there; the sources say which.
    if (cfg.country.enabled)
      for (const c of await countryWideHolds(
        ctx.db,
        cfg.probe.countries,
        now,
        Math.max(cfg.country.standbyRecheckHours, 1) * 60 * 60_000,
      ))
        items.push({
          ...fleetBase,
          id: `country_wide_failure:${c.country}`,
          kind: 'country_wide_failure',
          severity: 'warning',
          facts: { countries: [c.country], edges: c.edges, groups: c.groups },
          action: 'open_probes',
          since: iso(c.since),
        });
    // Enrolled nodes waiting on the operator (docs/servers.md "Node lifecycle"):
    // FCP never starts a protect run or approves on its own, it asks.
    items.push(...(await nodeAttention(ctx, relays)));
    const maintenance = await readMaintenance(ctx.db);
    if (maintenance.frozen) {
      items.push({
        id: 'maintenance_frozen',
        kind: 'maintenance_frozen',
        severity: 'info',
        relaySlug: null,
        relayId: null,
        edgeId: null,
        listenerKey: null,
        accountId: null,
        rotationId: null,
        code: maintenance.reason,
        facts: {},
        action: 'thaw',
        since: isoN(maintenance.since),
      });
    }
    items.sort(
      (x, y) =>
        ATTENTION_RANK.indexOf(x.kind) - ATTENTION_RANK.indexOf(y.kind) ||
        (x.since ?? '').localeCompare(y.since ?? '') ||
        x.id.localeCompare(y.id),
    );
    // The one status of every origin, judged on its facts and the items naming it.
    const named = new Map<string, AttentionItem[]>();
    for (const i of items) {
      if (!i.relayId) continue;
      const list = named.get(i.relayId) ?? [];
      list.push(i);
      named.set(i.relayId, list);
    }
    const origins = [];
    for (const relay of [...relays].sort((a, b) => a.slug.localeCompare(b.slug))) {
      const facts = statusFacts.get(relay._id as string);
      if (!facts) continue;
      const status = originStatusOf({
        ...facts,
        attention: (named.get(relay._id as string) ?? []).map((i) => ({
          kind: i.kind,
          severity: i.severity,
          code: i.code,
        })),
      });
      origins.push({ relayId: relay._id as string, relaySlug: relay.slug, status });
    }
    return {
      items,
      origins,
      fleet: fleetStatusOf(origins.map((o) => o.status)),
      generatedAt: iso(now),
    };
  },
});

// --- preflight -----------------------------------------------------------------------------------

const preflightArgs = {
  relayId: v.id('relays'),
  kind: v.union(
    v.literal('provision'),
    v.literal('publish'),
    v.literal('replace'),
    v.literal('test-provision'),
  ),
  edgeId: v.optional(v.id('edges')),
  listenerKey: v.optional(v.string()),
  accountId: v.optional(v.id('edgeProviderAccounts')),
  /** An explicit location (its account implied); the account's default otherwise. */
  locationId: v.optional(v.id('edgeLocations')),
  /** `replace`: an explicit spare (that one or nothing). */
  spareEdgeId: v.optional(v.id('edges')),
  templateId: v.optional(v.id('edgeTemplates')),
  /** `provision` only: false = the edge stays an unpublished spare (no standby is published instead). */
  publish: v.optional(v.boolean()),
  trigger: v.optional(
    v.union(v.literal('manual'), v.literal('detector'), v.literal('api'), v.literal('reconcile')),
  ),
};

/**
 * Dry run of a start: every guard `startRotation` applies (the first is what a
 * real start would throw), the selection the machine would make, the plan-phase
 * refusals that need no adapter, and delivery warnings. Writes nothing.
 */
export const preflight = internalQuery({
  args: preflightArgs,
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const cfg = await resolveEdgeConfig(ctx.db);
    const listeners = await listenersOf(ctx, relay._id);
    const listener = a.listenerKey
      ? (listeners.find((l) => l.listenerKey === a.listenerKey) ?? null)
      : null;
    const blockers: Array<{ code: string; detail: string | null }> = [];
    const warnings: Array<{ code: string; detail: string | null }> = [];
    if (a.listenerKey && !listener)
      blockers.push({ code: 'listener_not_found', detail: a.listenerKey });
    const isTest = a.kind === 'test-provision';
    const startArgs = {
      relayId: relay._id,
      kind: (isTest ? 'provision' : a.kind) as 'provision' | 'publish' | 'replace',
      trigger: a.trigger ?? ('manual' as const),
      targetEdgeId: a.kind === 'replace' ? a.edgeId : undefined,
      toEdgeId: a.kind === 'publish' ? a.edgeId : undefined,
      listenerId: listener?._id,
      // The same mode the provision route starts: `publish: false` keeps the
      // result a spare, so no existing standby is picked to be published.
      publishOnDone: a.kind === 'provision' && a.publish !== false,
      requestedAccountId: isTest || a.accountId ? a.accountId : undefined,
      requestedLocationId: a.locationId,
      requestedSpareEdgeId: a.kind === 'replace' ? a.spareEdgeId : undefined,
      requestedTemplateId: a.templateId,
      allowUnqualified: isTest,
    };
    if (isTest && !a.accountId && !a.locationId)
      blockers.push({ code: 'validation', detail: 'accountId is required' });
    const g = await collectStartBlockers(ctx, startArgs);
    for (const b of g.blockers)
      blockers.push({ code: b.code.replace(/^edge\./, ''), detail: b.message });
    let wouldSelect: {
      listenerKey: string | null;
      standbyEdgeId: string | null;
      accountId: string | null;
      accountName: string | null;
      locationId?: string | null;
      locationLabel?: string | null;
      provider: string | null;
      layer: 'l4' | 'l7' | null;
      templateId: string | null;
    } | null = null;
    if (a.kind !== 'publish' && !g.blockers.some((b) => b.code === 'not_found')) {
      const sel = await selectionContext(ctx, startArgs, relay, g.targetEdge, cfg);
      if (!sel.listener)
        blockers.push({ code: sel.accountFailure ?? 'no_compatible_listener', detail: null });
      else if (sel.standbyId) {
        wouldSelect = {
          listenerKey: sel.listener.listenerKey,
          standbyEdgeId: sel.standbyId as string,
          accountId: null,
          accountName: null,
          provider: null,
          layer: null,
          templateId: null,
        };
      } else if (!sel.account || !sel.template) {
        blockers.push({ code: sel.accountFailure ?? 'no_account', detail: null });
      } else {
        const acct = await ctx.db.get(sel.account.id);
        const loc = await ctx.db.get(sel.account.locationId);
        wouldSelect = {
          listenerKey: sel.listener.listenerKey,
          standbyEdgeId: null,
          accountId: sel.account.id as string,
          accountName: acct?.name ?? null,
          locationId: sel.account.locationId as string,
          locationLabel: loc?.label ?? null,
          provider: sel.account.provider,
          layer: edgeLayerOf(sel.account.provider),
          templateId: (sel.template.id as string | null) ?? null,
        };
        if (loc && !loc.qualified)
          warnings.push({ code: 'account_unqualified', detail: acct?.name ?? null });
        // Plan-phase refusals that need no adapter call.
        if (edgeLayerOf(sel.account.provider) === 'l7') {
          if (!sel.account.zoneName)
            blockers.push({ code: 'dns_zone_missing', detail: acct?.name ?? null });
          if (!sel.listener.originTransport)
            blockers.push({ code: 'origin_transport_missing', detail: sel.listener.listenerKey });
          if (zoneModeGovernsOrigin(sel.account.provider) && !sel.account.zoneSslMode)
            blockers.push({ code: 'zone_mode_unknown', detail: acct?.name ?? null });
          if (a.trigger && a.trigger !== 'manual' && !cfg.l7.autoSelect)
            warnings.push({ code: 'l7_manual_only', detail: null });
        }
      }
    }
    if (isTest) warnings.push({ code: 'unpublished_result', detail: null });
    if (!cfg.render.enabled) warnings.push({ code: 'render_disabled', detail: null });
    if (!cfg.enabled) warnings.push({ code: 'edge_disabled', detail: null });
    if (!cfg.probe.enabled) warnings.push({ code: 'probe_disabled', detail: null });
    // The same key the report route marks with (http.ts): the pepper, else the IP salt.
    if (!(process.env.EDGE_MARK_PEPPER || process.env.IP_HASH_SALT))
      warnings.push({ code: 'mark_pepper_missing', detail: null });
    if (relay.backendServerId && relay.origin.kind !== 'manual') {
      const { bound } = await bindingStateOf(ctx.db, relay);
      if (bound && publishedCount(relay.publishedEdgeIds) === 0)
        warnings.push({ code: 'members_dark', detail: relay.slug });
    }
    const seen = new Set<string>();
    const dedupe = <T extends { code: string; detail: string | null }>(xs: T[]) =>
      xs.filter((x) =>
        seen.has(`${x.code}:${x.detail}`) ? false : (seen.add(`${x.code}:${x.detail}`), true),
      );
    return {
      ok: blockers.length === 0,
      blockers: dedupe(blockers),
      warnings: dedupe(warnings),
      wouldSelect,
    };
  },
});

// --- timeline ------------------------------------------------------------------------------------

const TIMELINE_CAP = 100;

function subjectOf(
  targetType: string | undefined,
): 'relay' | 'edge' | 'rotation' | 'probe' | 'listener' | 'other' {
  switch (targetType) {
    case 'relay':
      return 'relay';
    case 'edge':
      return 'edge';
    case 'edge_rotation':
      return 'rotation';
    case 'probe_target':
      return 'probe';
    case 'relay_listener':
      return 'listener';
    default:
      return 'other';
  }
}

/** Merged audit rows for an origin: its own, its live edges', its rotations', its listeners' and its edges' probe verdicts. Newest first. */
export const timeline = internalQuery({
  args: { relayId: v.id('relays'), take: v.optional(v.number()) },
  handler: async (ctx, { relayId, take }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const cap = Math.min(Math.max(take ?? TIMELINE_CAP, 10), 300);
    const rows: Doc<'auditLog'>[] = [];
    const pull = async (targetType: string, targetId: string, n: number) => {
      const got = await ctx.db
        .query('auditLog')
        .withIndex('by_target', (q) => q.eq('targetType', targetType).eq('targetId', targetId))
        .order('desc')
        .take(n);
      rows.push(...got);
      return got.length === n;
    };
    let truncated = await pull('relay', relayId as string, 40);
    const edges = await liveEdgesOfRelay(ctx.db, relayId);
    // A subject left out by these caps is an incomplete timeline: say so.
    if (edges.length > 12) truncated = true;
    for (const e of edges.slice(0, 12)) {
      truncated = (await pull('edge', e._id as string, 12)) || truncated;
      truncated = (await pull('probe_target', `edge:${e._id as string}`, 8)) || truncated;
    }
    const listeners = await listenersOf(ctx, relayId);
    if (listeners.length > 12) truncated = true;
    for (const l of listeners.slice(0, 12))
      truncated = (await pull('relay_listener', l._id as string, 6)) || truncated;
    const rotations = await ctx.db
      .query('edgeRotations')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .order('desc')
      .take(9);
    // One extra row tells a ninth rotation exists without reading it.
    if (rotations.length > 8) truncated = true;
    for (const r of rotations.slice(0, 8)) {
      truncated = (await pull('edge_rotation', r._id as string, 10)) || truncated;
      for (const auditId of (r.auditIds ?? []).slice(-10)) {
        const row = await ctx.db.get(auditId);
        if (row) rows.push(row);
      }
    }
    const seen = new Set<string>();
    const merged = rows
      .filter((row) => (seen.has(row._id) ? false : (seen.add(row._id), true)))
      .sort((a, b) => b._creationTime - a._creationTime);
    if (merged.length > cap) truncated = true;
    return {
      entries: merged.slice(0, cap).map((row) => ({
        id: row._id as string,
        actorType: row.actorType,
        actorId: row.actorId ?? null,
        action: row.action,
        targetType: row.targetType ?? null,
        targetId: row.targetId ?? null,
        payload: row.payload ?? null,
        requestId: row.requestId ?? null,
        createdAt: iso(row._creationTime),
        subject: subjectOf(row.targetType),
      })),
      truncated,
    };
  },
});

// --- quarantine view -----------------------------------------------------------------------------

interface HostTuple {
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
}

const liveHostValidator = v.object({
  uuid: v.string(),
  remark: v.string(),
  address: v.string(),
  port: v.number(),
  sni: v.union(v.string(), v.null()),
  host: v.union(v.string(), v.null()),
  inboundUuid: v.union(v.string(), v.null()),
});

function tupleOfEdge(edge: Edge, listener: Listener): HostTuple | null {
  const port = edge.listeners[0]?.edgePort ?? 443;
  const sni = hostSniOf(listener);
  const t = hostTargetFor(
    { layer: edge.layer, addresses: edge.addresses, edgePort: port },
    {
      protocol: listener.protocol,
      streamTransport: listener.streamTransport,
      security: listener.security,
    },
    sni,
  );
  return t ? { address: t.address, port: t.port, sni: t.sni, host: t.host } : null;
}

/**
 * The COMPLETE tuple: two bindings can share address:port and differ only in
 * SNI or Host header, and the verdict recommends which one to keep.
 */
function tupleMatches(a: HostTuple | null, b: HostTuple | null): boolean {
  if (!a || !b) return false;
  const n = (x: string | null | undefined) => (x ? x.trim().toLowerCase() : '');
  return (
    sameAddress(a.address, b.address) &&
    a.port === b.port &&
    n(a.sni) === n(b.sni) &&
    n(a.host) === n(b.host)
  );
}

type LiveHost = {
  uuid: string;
  remark: string;
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
  inboundUuid: string | null;
};

export interface QuarantineViewResult {
  quarantine: { rotationId: string; since: string; reason: string } | null;
  rotation: ReturnType<typeof mapRotationAdmin> | null;
  listeners: Array<{
    listenerKey: string;
    remark: string | null;
    previous: (HostTuple & { edgeId: string | null }) | null;
    current: (HostTuple & { edgeId: string | null }) | null;
    live: (HostTuple & { uuid: string }) | null;
    match: 'previous' | 'current' | 'neither' | 'absent' | 'unknown';
  }>;
  extraHosts: Array<HostTuple & { uuid: string; remark: string }>;
  inspectedAt: string | null;
}

/**
 * The resolver's view: per listener, the binding the rotation replaced
 * (`previous`), the one it wrote (`current`), and, when the live Host list is
 * supplied (the inspect action), what the backend serves and which it matches.
 */
export const quarantineView = internalQuery({
  args: { relayId: v.id('relays'), live: v.optional(v.array(liveHostValidator)) },
  handler: async (ctx, { relayId, live }): Promise<QuarantineViewResult> => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const rotation = relay.quarantine ? await ctx.db.get(relay.quarantine.rotationId) : null;
    const listeners = (await listenersOf(ctx, relayId)).filter((l) => !l.retired);
    const toEdge = rotation?.toEdgeId ? await ctx.db.get(rotation.toEdgeId) : null;
    const prevEdge = rotation?.previousBinding
      ? await ctx.db.get(rotation.previousBinding.edgeId)
      : null;
    const claimed = new Set<string>();
    const out = [];
    for (const l of listeners) {
      const remark = listenerRemark(l);
      const legacy = (l.legacyHosts ?? []).map((h) => h.remark);
      const plan = rotation?.hostPlan.find((p) => p.listenerKey === l.listenerKey) ?? null;
      const previous: (HostTuple & { edgeId: string | null }) | null = plan
        ? {
            address: plan.oldAddress,
            port: plan.oldPort,
            sni: plan.oldSni ?? null,
            host: plan.oldHost ?? null,
            edgeId: prevEdge && prevEdge.listenerId === l._id ? (prevEdge._id as string) : null,
          }
        : prevEdge && prevEdge.listenerId === l._id
          ? {
              ...(tupleOfEdge(prevEdge, l) ?? { address: '', port: 0, sni: null, host: null }),
              edgeId: prevEdge._id as string,
            }
          : null;
      const current: (HostTuple & { edgeId: string | null }) | null =
        toEdge && toEdge.listenerId === l._id
          ? {
              ...(tupleOfEdge(toEdge, l) ?? { address: '', port: 0, sni: null, host: null }),
              edgeId: toEdge._id as string,
            }
          : null;
      let liveHost: (HostTuple & { uuid: string }) | null = null;
      let match: 'previous' | 'current' | 'neither' | 'absent' | 'unknown' = 'unknown';
      if (live) {
        const h =
          live.find((x) => x.uuid === l.host?.uuid) ??
          live.find((x) => remark !== null && x.remark === remark) ??
          live.find((x) => legacy.includes(x.remark)) ??
          null;
        if (h) {
          claimed.add(h.uuid);
          liveHost = { uuid: h.uuid, address: h.address, port: h.port, sni: h.sni, host: h.host };
          match = tupleMatches(liveHost, current)
            ? 'current'
            : tupleMatches(liveHost, previous)
              ? 'previous'
              : 'neither';
        } else match = 'absent';
      }
      out.push({ listenerKey: l.listenerKey, remark, previous, current, live: liveHost, match });
    }
    const remarks = new Set(
      listeners
        .flatMap((l) => [listenerRemark(l), ...(l.legacyHosts ?? []).map((h) => h.remark)])
        .filter((x): x is string => !!x),
    );
    const extraHosts = (live ?? [])
      .filter(
        (h) =>
          !claimed.has(h.uuid) &&
          (remarks.has(h.remark) || h.remark.startsWith(`${relay.nodeName ?? relay.slug}-relay`)),
      )
      .map((h) => ({
        uuid: h.uuid,
        remark: h.remark,
        address: h.address,
        port: h.port,
        sni: h.sni,
        host: h.host,
      }));
    return {
      quarantine: relay.quarantine
        ? {
            rotationId: relay.quarantine.rotationId as string,
            since: iso(relay.quarantine.since),
            reason: relay.quarantine.reason,
          }
        : null,
      rotation: rotation
        ? mapRotationAdmin(rotation, toEdge, await rotationListenerKey(ctx.db, rotation))
        : null,
      listeners: out,
      extraHosts,
      inspectedAt: live ? iso(Date.now()) : null,
    };
  },
});

/** Pull the live Host list from the backend and fill the resolver's live column (throttled route). */
export const quarantineInspect = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx: ActionCtx, { relayId }): Promise<QuarantineViewResult> => {
    const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!relay.backendServerId)
      throw new ConvexError({
        code: 'edge.host_not_applicable',
        message: 'this origin has no backend',
      });
    const hosts = await ctx.runAction(internal.backends.listHosts, {
      backendServerId: relay.backendServerId,
    });
    const live: LiveHost[] = hosts.map((h) => ({
      uuid: h.uuid,
      remark: h.remark,
      address: h.address,
      port: h.port,
      sni: h.sni ?? null,
      host: h.host ?? null,
      inboundUuid: h.inbound?.configProfileInboundUuid ?? null,
    }));
    return await ctx.runQuery(internal.edgeOperator.quarantineView, { relayId, live });
  },
});

// --- providers usage -----------------------------------------------------------------------------

export const providersUsage = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveEdgeConfig(ctx.db);
    const fake = fakeShadowedIds();
    const accounts = (await ctx.db.query('edgeProviderAccounts').collect()).sort(
      (a, b) => a.priority - b.priority || a.name.localeCompare(b.name),
    );
    const relays = (await ctx.db.query('relays').collect()).sort((a, b) =>
      a.slug.localeCompare(b.slug),
    );
    const perAccount = new Map<string, { published: number; standby: number; draining: number }>();
    const bump = (id: string | undefined, k: 'published' | 'standby' | 'draining') => {
      if (!id) return;
      const row = perAccount.get(id) ?? { published: 0, standby: 0, draining: 0 };
      row[k]++;
      perAccount.set(id, row);
    };
    const relayRows = [];
    const totals = {
      liveEdges: 0,
      published: 0,
      standby: 0,
      draining: 0,
      plannedIfAutoProvision: 0,
    };
    for (const r of relays) {
      const edges = await liveEdgesOfRelay(ctx.db, r._id);
      let standby = 0;
      let draining = 0;
      for (const e of edges) {
        if (e.status === 'draining' || e.publication === 'draining') {
          draining++;
          bump(e.accountId as string | undefined, 'draining');
        } else if (e.publication === 'published')
          bump(e.accountId as string | undefined, 'published');
        else if (e.status === 'active') {
          standby++;
          bump(e.accountId as string | undefined, 'standby');
        }
      }
      const published = publishedCount(r.publishedEdgeIds);
      const fillFromStandby = Math.min(standby, Math.max(0, r.desiredPublished - published));
      const provisionForPool = Math.max(0, r.desiredPublished - published - fillFromStandby);
      const standbyLeft = standby - fillFromStandby;
      const provisionForStandby = r.enabled
        ? Math.max(0, originPolicy(r, cfg).standbyPerRelay - standbyLeft)
        : 0;
      const planned = r.enabled && !r.deleting ? provisionForPool + provisionForStandby : 0;
      relayRows.push({
        id: r._id as string,
        slug: r.slug,
        desiredPublished: r.desiredPublished,
        published,
        standby,
        draining,
        plannedIfAutoProvision: planned,
      });
      totals.published += published;
      totals.standby += standby;
      totals.draining += draining;
      totals.plannedIfAutoProvision += planned;
    }
    const accountRows = [];
    for (const a of accounts) {
      const live = (await liveEdgesOfAccount(ctx.db, a._id)).filter((e) => e.managed).length;
      totals.liveEdges += live;
      const counts = perAccount.get(a._id as string) ?? { published: 0, standby: 0, draining: 0 };
      // Per location: its live edges against its own cap, and its trust.
      const locations = [];
      for (const loc of await locationsOfAccount(ctx.db, a._id))
        locations.push({
          id: loc._id as string,
          label: loc.label,
          placeKey: loc.placeKey,
          enabled: loc.enabled,
          qualified: loc.qualified,
          liveEdges: await liveCountForLocation(ctx.db, loc),
          maxLiveEdges: loc.maxLiveEdges ?? null,
        });
      accountRows.push({
        id: a._id as string,
        name: a.name,
        provider: a.provider,
        layer: edgeLayerOf(a.provider),
        enabled: a.enabled,
        qualified: locations.some((l) => l.enabled && l.qualified),
        locations,
        tested: accountTested(a),
        fake: fake.includes(a.provider),
        liveEdges: live,
        maxLiveEdges: a.maxLiveEdges,
        allocationsToday:
          a.allocationsDayKey === new Date().toISOString().slice(0, 10) ? a.allocationsToday : 0,
        dailyAllocationBudget: a.dailyAllocationBudget,
        ...counts,
      });
    }
    return { accounts: accountRows, relays: relayRows, totals, generatedAt: iso(Date.now()) };
  },
});

// --- lookups -------------------------------------------------------------------------------------

/** The full admin view of one origin by slug (the per-origin page's header; servers:read, never the register scope). */
export const relayLookup = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const relay = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    return relay ? mapRelayAdmin(relay, await resolveEdgeConfig(ctx.db)) : null;
  },
});

/** Every delivery binding with whether an origin row still claims it (a released or orphaned `keep-dark` is what the operator looks for). */
export const deliveryBindings = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query('edgeDeliveryBindings').collect();
    const out = [];
    for (const b of rows) {
      const relay = await ctx.db
        .query('relays')
        .withIndex('by_slug', (q) => q.eq('slug', b.relaySlug))
        .unique();
      out.push({
        id: b._id as string,
        backendServerId: b.backendServerId as string,
        nodeName: b.nodeName ?? null,
        relaySlug: b.relaySlug,
        relayPresent: !!relay && !relay.deleting,
        policyVersion: b.policyVersion,
        state: b.state,
        updatedAt: iso(b.updatedAt),
      });
    }
    return { bindings: out.sort((a, b) => a.relaySlug.localeCompare(b.relaySlug)) };
  },
});
