/**
 * Operator-facing reads for the redesigned Admin -> Edges section (docs/edges.md
 * § "Operations"): the guided setup status (relay-scoped, draft or fleet), the
 * ranked attention list, the preflight dry run, the merged timeline, the
 * quarantine resolver view, provider usage, a relay lookup by slug and the
 * delivery bindings. Everything here READS; the writes stay in their own
 * modules (edgeRotations.start, hostOps.adoptListenerHost, relays.*).
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
import { RENDER_CLIENT_FAMILIES, resolveEdgeConfig, type EdgeConfig } from './lib/edgeConfig';
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
import { activeNames, listenerRemark, listenersOf } from './relayListeners';
import { resolveTemplateFor } from './edgeTemplates';
import { mapEdgeAdmin } from './edges';
import { mapRotationAdmin, collectStartBlockers, selectionContext } from './edgeRotations';
import { renderPreviewFor } from './edgeAdmin';
import type { RelayOrigin } from './lib/edges/origin';

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
      if (accountsForSlot([a], { layers, proto: l.proto, allowL7: true }).length > 0)
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
    const effective = await resolveTemplateFor(
      ctx,
      a.provider,
      null,
      a.defaultTemplateId ?? null,
      a._id,
    );
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
      tested: !!a.lastTestOkAt,
      testFailed: !a.lastTestOkAt && !!a.lastTestError,
      qualified: a.qualified,
      qualificationCurrent: a.qualified && a.qualifiedTemplateHash === effective.hash,
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
  const binding = relay.backendServerId
    ? await deliveryBindingFor(ctx.db, relay.backendServerId, relay.nodeName ?? undefined)
    : null;
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
      deliveryRequired: !!binding,
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

const ROLE_PATH = '/api/v1/admin/edges/relays/by-slug/';

/** Public values the node role needs; never a token, never an address. */
function roleVars(relay: Relay, listeners: Listener[]): Record<string, string> {
  return {
    fcp_relay_slug: relay.slug,
    fcp_relay_listeners: listeners
      .filter((l) => !l.retired)
      .map((l) => l.listenerKey)
      .join(','),
    fcp_relay_register_path: `${ROLE_PATH}${encodeURIComponent(relay.slug)}`,
    fcp_relay_register_scope: 'admin:edges:register',
    fcp_relay_host_mode: relay.hostMode,
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
 * `GET setup-status[?relay=<slug>]` / `POST setup-status { draft }`.
 * Relay scope judges every step for THAT relay; a draft judges steps 1 to 3
 * against the intended listeners before the row exists; the fleet scope is the
 * per-step aggregation over every relay plus the relays to resume.
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
      if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
      const f = await relayFacts(ctx, relay, cfg, { withPreview: true });
      const input: SetupInput = {
        origin: await originFacts(ctx.db, relay.origin),
        listeners: f.listeners.map(listenerFacts),
        accounts: await accountFacts(ctx, accounts, f.listeners),
        relay: f.relay,
        render: f.render,
        config: configFacts(cfg),
      };
      const r = computeSetupStatus(input);
      const listenerRows = await listenersOf(ctx, relay._id);
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
        roleVars: roleVars(relay, listenerRows),
        resume: [],
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
        accounts: await accountFacts(ctx, accounts, listeners),
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
        roleVars: null,
        resume: [],
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
        accounts: await accountFacts(ctx, accounts, f.listeners),
        relay: f.relay,
        render: f.render,
        config: configFacts(cfg),
      };
      perRelay.push({ relay, result: computeSetupStatus(input) });
    }
    let steps: SetupStep[];
    if (perRelay.length === 0) {
      // No relay yet: the fleet-level facts alone (accounts, templates, config).
      const input: SetupInput = {
        origin: null,
        listeners: [],
        accounts: await accountFacts(ctx, accounts, []),
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
      roleVars: null,
      resume: perRelay
        .filter((p) => !p.result.complete)
        .map((p) => ({
          relaySlug: p.relay.slug,
          relayId: p.relay._id as string,
          currentStep: p.result.currentStep,
          complete: p.result.complete,
        })),
      generatedAt: now,
    };
  },
});

// --- attention ------------------------------------------------------------------------------------

const ATTENTION_RANK = [
  'quarantine',
  'needs_operator',
  'host_unresolved',
  'members_dark',
  'rotation_failed',
  'qualification_lapsed',
  'block_suspected',
  'edge_unreachable',
  'pool_below_desired',
  'account_unqualified',
  'account_untested',
  'drift',
  'maintenance_frozen',
] as const;
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
    | 'thaw';
  since: string | null;
}

const RECENT_FAILURE_MS = 24 * 60 * 60_000;

/** Server-ranked list of what needs the operator, one action per item. */
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
    for (const relay of relays) {
      if (relay.deleting) continue;
      const edges = await liveEdgesOfRelay(ctx.db, relay._id);
      const listeners = await listenersOf(ctx, relay._id);
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
      if (relay.origin.kind !== 'manual' && relay.backendServerId) {
        const binding = await deliveryBindingFor(
          ctx.db,
          relay.backendServerId,
          relay.nodeName ?? undefined,
        );
        const dark = !!binding && (published === 0 || !relay.enabled || !cfg.render.enabled);
        if (dark) {
          items.push({
            ...base(relay),
            id: `members_dark:${relay._id}`,
            kind: 'members_dark',
            severity: 'critical',
            code:
              published === 0
                ? 'empty_pool'
                : !relay.enabled
                  ? 'relay_disabled'
                  : 'render_disabled',
            facts: { published },
            action: 'open_setup',
            since: isoN(binding?.updatedAt),
          });
        }
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
      if (relay.suspicion?.state === 'suspected') {
        items.push({
          ...base(relay),
          id: `block_suspected:${relay._id}`,
          kind: 'block_suspected',
          severity: 'warning',
          code: relay.suspicion.veto ?? null,
          facts: {
            score: relay.suspicion.score,
            hintLevel: relay.suspicion.hintLevel,
            countries: relay.suspicion.countries.map((c) => c.code),
          },
          action: 'rotate',
          since: isoN(relay.suspicion.firstSeenAt),
        });
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
      if (relay.enabled && published < relay.desiredPublished) {
        const standbys = edges.filter(
          (e) => e.status === 'active' && e.publication === 'unpublished',
        ).length;
        items.push({
          ...base(relay),
          id: `pool_below_desired:${relay._id}`,
          kind: 'pool_below_desired',
          severity: published === 0 ? 'warning' : 'info',
          code: null,
          facts: { published, desired: relay.desiredPublished, standbys },
          action: standbys > 0 ? 'publish' : 'provision',
          since: null,
        });
      }
    }
    const accounts = await ctx.db.query('edgeProviderAccounts').collect();
    for (const a of accounts) {
      if (!a.enabled) continue;
      if (!a.lastTestOkAt) {
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
      } else if (!a.qualified) {
        items.push({
          id: `account_unqualified:${a._id}`,
          kind: 'account_unqualified',
          severity: 'info',
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
    }
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
    return { items, generatedAt: iso(now) };
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
  templateId: v.optional(v.id('edgeTemplates')),
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
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
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
      publishOnDone: a.kind === 'provision',
      requestedAccountId: isTest || a.accountId ? a.accountId : undefined,
      requestedTemplateId: a.templateId,
      allowUnqualified: isTest,
    };
    if (isTest && !a.accountId)
      blockers.push({ code: 'validation', detail: 'accountId is required' });
    const g = await collectStartBlockers(ctx, startArgs);
    for (const b of g.blockers)
      blockers.push({ code: b.code.replace(/^edge\./, ''), detail: b.message });
    let wouldSelect: {
      listenerKey: string | null;
      standbyEdgeId: string | null;
      accountId: string | null;
      accountName: string | null;
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
        wouldSelect = {
          listenerKey: sel.listener.listenerKey,
          standbyEdgeId: null,
          accountId: sel.account.id as string,
          accountName: acct?.name ?? null,
          provider: sel.account.provider,
          layer: edgeLayerOf(sel.account.provider),
          templateId: (sel.template.id as string | null) ?? null,
        };
        if (acct && !acct.qualified)
          warnings.push({ code: 'account_unqualified', detail: acct.name });
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
    if (!process.env.EDGE_MARK_PEPPER) warnings.push({ code: 'mark_pepper_missing', detail: null });
    if (relay.backendServerId && relay.origin.kind !== 'manual') {
      const binding = await deliveryBindingFor(
        ctx.db,
        relay.backendServerId,
        relay.nodeName ?? undefined,
      );
      if (binding && publishedCount(relay.publishedEdgeIds) === 0)
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

/** Merged audit rows for a relay: its own, its live edges', its rotations', its listeners' and its edges' probe verdicts. Newest first. */
export const timeline = internalQuery({
  args: { relayId: v.id('relays'), take: v.optional(v.number()) },
  handler: async (ctx, { relayId, take }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
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
    for (const e of edges.slice(0, 12)) {
      truncated = (await pull('edge', e._id as string, 12)) || truncated;
      truncated = (await pull('probe_target', `edge:${e._id as string}`, 8)) || truncated;
    }
    const listeners = await listenersOf(ctx, relayId);
    for (const l of listeners.slice(0, 12))
      truncated = (await pull('relay_listener', l._id as string, 6)) || truncated;
    const rotations = await ctx.db
      .query('edgeRotations')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .order('desc')
      .take(8);
    for (const r of rotations) {
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
  const sni = activeNames(listener)[0] ?? null;
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

function tupleMatches(a: HostTuple | null, b: HostTuple | null): boolean {
  if (!a || !b) return false;
  return sameAddress(a.address, b.address) && a.port === b.port;
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
 * supplied (the inspect action), what the panel serves and which it matches.
 */
export const quarantineView = internalQuery({
  args: { relayId: v.id('relays'), live: v.optional(v.array(liveHostValidator)) },
  handler: async (ctx, { relayId, live }): Promise<QuarantineViewResult> => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
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
      rotation: rotation ? mapRotationAdmin(rotation, toEdge) : null,
      listeners: out,
      extraHosts,
      inspectedAt: live ? iso(Date.now()) : null,
    };
  },
});

/** Pull the live Host list from the panel and fill the resolver's live column (throttled route). */
export const quarantineInspect = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx: ActionCtx, { relayId }): Promise<QuarantineViewResult> => {
    const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    if (!relay.backendServerId)
      throw new ConvexError({
        code: 'edge.host_not_applicable',
        message: 'this origin has no panel',
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
      const provisionForStandby = r.enabled ? Math.max(0, r.standbyPerRelay - standbyLeft) : 0;
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
      accountRows.push({
        id: a._id as string,
        name: a.name,
        provider: a.provider,
        layer: edgeLayerOf(a.provider),
        enabled: a.enabled,
        qualified: a.qualified,
        tested: !!a.lastTestOkAt,
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

/** The full admin view of one relay by slug (the per-relay page's header; servers:read, never the register scope). */
export const relayLookup = internalQuery({
  args: { slug: v.string() },
  handler: async (ctx, { slug }) => {
    const relay = await ctx.db
      .query('relays')
      .withIndex('by_slug', (q) => q.eq('slug', slug))
      .unique();
    return relay ? mapRelayAdmin(relay) : null;
  },
});

/** Every delivery binding with whether a relay row still claims it (a released or orphaned `keep-dark` is what the operator looks for). */
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
