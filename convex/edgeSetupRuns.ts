/**
 * Guided setup ("Autopilot") runs: protect a backend node with edges by walking
 * ONE authoritative stage machine (docs/edges.md § "Guided setup runs"):
 *
 *   prepare -> credential -> provision -> verify -> try_it -> publish
 *           -> hide_direct_hosts -> rehearse -> go_live -> done   (| done_unbound)
 *
 * Contract:
 *  - every stage is idempotent and re-enterable: `retry` re-enters the CURRENT
 *    stage and reuses what exists (standbys, edges, the credential);
 *  - the `step` action does one bounded unit of work per invocation and never
 *    schedules itself: the mutation that records its outcome schedules the next
 *    step (`stepVersion` fences a stale actor, exactly like the rotation machine);
 *  - a rotation the run starts is started and `expect`ed in ONE mutation; the
 *    rotation row stores `{runId, generation}` and its terminal hook
 *    (`onRotationTerminal`, scheduled by `releaseOrigin`) reports THAT stored
 *    generation. Duplicates and stale generations are no-ops;
 *  - `origins.setupOwned` is set at stage 1 and cleared ONLY by go-live (or by
 *    removal): a failed / cancelled / unbound run leaves the origin owned, so
 *    reconcile upkeep and the detector keep their hands off it. A re-protect
 *    run (`kind: 'reprotect'`, a live bound node protected again) is the
 *    exception: its node keeps serving members throughout, so any ending
 *    hands the origin back (`onSetupRunEnded`), and its cancel drops only its
 *    own candidates (`cancelReprotect`);
 *  - members keep receiving the raw origin body through stage 5; from stage 6
 *    (hides) they depend on the edge; stage 8 binds in ONE mutation after
 *    re-checking everything stage 7 rehearsed.
 *
 * The other agents' work (Host hides, restore, test links, rehearsal, the
 * qualification credential) is reached ONLY through `stageOps`, a seam the
 * tests replace (`__setStageOpsForTests`); the defaults call the internal
 * functions by name.
 */
import { verificationListenersOf } from './lib/edges/verificationContext';
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { upsertSettingRow } from './appSettings';
import {
  EDGE_KEYS,
  RENDER_CLIENT_FAMILIES,
  EDGE_PLUMBING,
  resolveEdgeConfig,
  type EdgeConfig,
} from './lib/edgeConfig';
import {
  collectStartBlockers,
  edgeFitsPick,
  publicationApproval,
  selectionContext,
  startRotation,
} from './edgeRotations';
import {
  claimDeliveryBinding,
  deliveryBindingFor,
  liveEdgesOfRelay,
  refreshTemplateEdges,
  relayForBackendNode,
  scheduleMirrorRefresh,
  unpublishFromPool,
} from './relays';
import { releaseTestCredentialsOf } from './edgeTestCredentials';
import { isCandidateEdge } from './lib/backend/deliveryGate';
import { assertNoRelayPanelClaim, assertNoRotationOrQuarantine } from './lib/edges/relayGuards';
import {
  confirmEndpoint,
  edgePortsOf,
  internalRunsOf,
  rungRowOf,
  rungRunOf,
} from './edgeVerification';
import { listenersOf } from './relayListeners';
import { accountTested, certificateRefusalFor } from './edgeProviderAccounts';
import { isTerminalPhase, withProviderAnswer } from './lib/edges/rotation';
import { admitted, assertAdmission } from './lib/edges/maintenance';
import { defaultLocationOf } from './edgeLocations';
import {
  needsEndpointVerification,
  verificationBinding,
  verificationCurrent,
  verificationStaleReason,
} from './lib/edges/verification';
import { outsideCheckFor } from './lib/edges/verifyRung';
import { probeStaleAfterMs } from './lib/edges/scoring';
import { literalFamilies } from './lib/edges/probes/types';
import {
  edgeLayerOf,
  frontsAllowed,
  providerHealthSatisfies,
} from './lib/edges/providers/capabilities';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import { parseIntent } from './lib/edges/intent';
import { fnv1a64Hex, listenerConfigHash, validateListenerSpec } from './lib/edges/registration';
import type { ListenerSpecInput } from './lib/edges/registration';
import { MAX_DESIRED_PUBLISHED } from './lib/edgeConfig';
import { publishedCount } from './lib/edges/pool';
import {
  MAX_OBSERVATION_AGE_MS,
  MAX_REHEARSAL_ATTEMPTS,
  appendRunEvent,
  cancelDeletesRelay,
  cancelRestores,
  canonicalJson,
  isTerminalRunState,
  nextStage,
  vectorsEqual,
  type SetupPlanAccount,
  type SetupPlanSnapshot,
  type SetupVector,
} from './lib/edges/setupRuns';
import { SETUP_RUN_STAGES, type SetupRunStage } from '../src/shared/contracts/edgeCodes';
import type { HideResult, HideStatus } from './edgeHostHides';
import type { RehearsalResult } from './edgeRehearsal';
import type { TestLinkResult } from './edgeTestLinks';
import type { ReapplyOutcome } from './lib/edges/providers/types';
import {
  activatingRunFor,
  activationVectorFor,
  blockActivation,
  promoteCandidate,
} from './nodeActivation';
import { isDirect, modeEntry, modeSlug, nodeGateFor } from './nodeIntents';
import { setupReady } from './backendSetup';
import { runningRenameOf } from './lib/backend/nodeAliases';
import { MAX_PROVIDER_PICKS, coverTargets, requirementOf } from './lib/edges/providerSet';
import { checkPickOptions, relayHasReality } from './edgeTemplates';
import { parseOptionValues } from './lib/edges/providers/options';
import { carries, setStateOf } from './lib/edges/setState';
import { L4_NOT_FOR_WEBSOCKET, l4BarredForAll, websocketNodeOf } from './lib/edges/websocketNode';
import { locationKeyOf } from './lib/edges/locations';
import type { EdgeProviderId } from './lib/edgeProviderIds';

type Run = Doc<'edgeSetupRuns'>;

/** The (account, location) the run creates its addresses in: its first pick. */
export function runPick(r: Pick<Run, 'picks'>): {
  accountId: Id<'edgeProviderAccounts'> | null;
  locationId: Id<'edgeLocations'> | null;
} {
  const p = r.picks?.[0];
  return p
    ? { accountId: p.accountId, locationId: p.locationId }
    : { accountId: null, locationId: null };
}

/** Every pick of the run, in set order (never empty: a run without picks has one unknown). */
export function runPicks(r: Pick<Run, 'picks'>): Array<{
  accountId: Id<'edgeProviderAccounts'> | null;
  locationId: Id<'edgeLocations'> | null;
  /** The pick's provider options (JSON); absent = a pick from before options. */
  options?: string;
}> {
  if (r.picks && r.picks.length > 0)
    return r.picks.map((p) => ({
      accountId: p.accountId,
      locationId: p.locationId,
      ...(p.options !== undefined ? { options: p.options } : {}),
    }));
  return [runPick(r)];
}

/** The (account, location) of one target: its own location's pick, else the run's first. */
function pickOfTarget(
  r: Pick<Run, 'picks'>,
  entry: Pick<RunListener, 'locationId'>,
): { accountId: Id<'edgeProviderAccounts'> | null; locationId: Id<'edgeLocations'> | null } {
  const all = runPicks(r);
  return (
    (entry.locationId ? all.find((p) => p.locationId === entry.locationId) : undefined) ?? all[0]!
  );
}

/** A run plan's offer of one location (the run was given that location; nothing else is judged). */
function planLocationOf(
  loc: Doc<'edgeLocations'>,
): NonNullable<SetupPlanAccount['locations']>[number] {
  return {
    id: loc._id as string,
    label: loc.label,
    placeKey: loc.placeKey,
    isDefault: true,
    qualified: loc.qualified,
    compatible: true,
    reasons: [],
  };
}

/** A location of the account (the named one, else its default), or null. */
async function pickLocationOf(
  db: QueryCtx['db'],
  account: Doc<'edgeProviderAccounts'>,
  locationId: Id<'edgeLocations'> | null | undefined,
): Promise<Doc<'edgeLocations'> | null> {
  const loc = locationId ? await db.get(locationId) : await defaultLocationOf(db, account);
  return loc && loc.accountId === account._id ? loc : null;
}
type Relay = Doc<'relays'>;
type Edge = Doc<'edges'>;
type Listener = Doc<'relayListeners'>;
type RunListener = Run['listeners'][number];

/** How long stage 4 waits for outside evidence before it asks the operator. */
const VERIFY_TIMEOUT_MS = 15 * 60_000;

/**
 * The two cards stage 4 stops on for one address, answered alike: the address
 * is unreachable, or a country's first round finds it blocked there.
 */
const unreachableNeed = (code: string | undefined) =>
  code === 'address_unreachable' || code === 'blocked_in';
/** A run whose scheduled step never ran (crashed action) is re-kicked after this. */
const STALE_KICK_GRACE_MS = 30_000;
const STALE_STARTED_MS = 10 * 60_000;
/** Edge statuses that count as "this listener has a live candidate". */
const LIVE_CANDIDATE: ReadonlySet<string> = new Set([
  'planning',
  'provisioning',
  'verifying',
  'active',
]);

// --- validators shared by the mutations ------------------------------------------------------------

const stageV = v.union(...SETUP_RUN_STAGES.map((s) => v.literal(s)));
const stateV = v.union(
  v.literal('running'),
  v.literal('waiting'),
  v.literal('needs_you'),
  v.literal('done'),
  v.literal('done_unbound'),
  v.literal('failed'),
  v.literal('cancelled'),
);
const verifyV = v.union(
  v.literal('pending'),
  v.literal('partial'),
  v.literal('verified'),
  v.literal('unreachable'),
);
const runListenerV = v.object({
  listenerKey: v.string(),
  locationId: v.optional(v.id('edgeLocations')),
  layer: v.union(v.literal('l4'), v.literal('l7')),
  edgeId: v.optional(v.id('edges')),
  verify: verifyV,
  published: v.boolean(),
  probeRequestedAt: v.optional(v.number()),
  proofRequestedAt: v.optional(v.number()),
  recheckSince: v.optional(v.number()),
  reappliedEdgeId: v.optional(v.id('edges')),
  notChecked: v.optional(v.array(v.union(v.literal(4), v.literal(6)))),
});
const testLinkV = v.object({
  edgeId: v.id('edges'),
  listenerKey: v.string(),
  link: v.string(),
  format: v.string(),
  method: v.union(v.literal('test_link'), v.literal('named_connection')),
  binding: v.object({
    endpoint: v.string(),
    listenerRevision: v.number(),
    configHash: v.string(),
    issuedAt: v.number(),
  }),
});
const rehearsalV = v.object({
  at: v.number(),
  attempts: v.number(),
  vector: v.object({
    listenerRevisions: v.record(v.string(), v.number()),
    renderConfigHash: v.string(),
    publicationEpoch: v.number(),
    qualificationEvidenceIds: v.array(v.string()),
    activation: v.optional(
      v.union(
        v.null(),
        v.object({
          runId: v.string(),
          machineRevision: v.number(),
          configRevision: v.string(),
          authRevision: v.union(v.string(), v.null()),
          deliveryRevision: v.string(),
        }),
      ),
    ),
  }),
  hostsObservation: v.object({ at: v.number(), version: v.number(), hash: v.string() }),
  darkCohortKeys: v.array(v.string()),
});
const eventV = v.object({
  level: v.union(v.literal('info'), v.literal('warn'), v.literal('error')),
  code: v.string(),
  detail: v.optional(v.string()),
});

// --- the seam to the other subsystems --------------------------------------------------------------

type QueryRunner = { runQuery: ActionCtx['runQuery'] };
/** What saving an address again did; `not_offered` when its provider has nothing to save again. */
export type ReapplyResult = ReapplyOutcome | { status: 'skipped'; code: 'not_offered' };

export interface StageOps {
  ensureCredential(
    ctx: ActionCtx,
    a: { relayId: Id<'relays'>; purpose: 'qualification' | 'rehearsal' },
  ): Promise<{ ok: boolean; code?: string; reused: boolean }>;
  requestVerificationProbes(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<void>;
  /** Save an address's configuration again, unchanged (edgeProviderOps.reapply). */
  reapplyEdge(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<ReapplyResult>;
  runFrontProof(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<{ ok: boolean; code: string | null }>;
  buildTestLink(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<TestLinkResult>;
  hideHosts(
    ctx: ActionCtx,
    a: { relayId: Id<'relays'>; runId: Id<'edgeSetupRuns'>; approvedUuids: string[] },
  ): Promise<HideResult>;
  hideStatus(ctx: QueryRunner, relayId: Id<'relays'>): Promise<HideStatus>;
  rehearse(
    ctx: ActionCtx,
    a: {
      relayId: Id<'relays'>;
      darkCohortKeys: string[];
      /** An enrolled node's activation: the rehearsal renders exactly its candidates. */
      activationRunId?: Id<'panelActivationRuns'>;
    },
  ): Promise<RehearsalResult>;
  vectorNow(ctx: QueryRunner, relayId: Id<'relays'>): Promise<SetupVector>;
  restoreStart(
    ctx: ActionCtx,
    a: {
      relayId: Id<'relays'>;
      purpose: 'cancel_setup' | 'release_requirement' | 'delete_relay';
      actorAdminId?: Id<'adminUsers'>;
      darkCohortKeys?: string[];
    },
  ): Promise<void>;
}

const defaultOps: StageOps = {
  ensureCredential: (ctx, a) => ctx.runAction(internal.relayQualification.ensure, a),
  requestVerificationProbes: async (ctx, edgeId) => {
    await ctx.runMutation(internal.probes.requestProbes, {
      target: { kind: 'edge', ref: edgeId as string },
      trigger: 'qualification',
    });
  },
  reapplyEdge: async (ctx, edgeId) => {
    const edge = await ctx.runQuery(internal.edges.get, { id: edgeId });
    if (!edge?.accountId || !edge.managed) return { status: 'skipped', code: 'not_offered' };
    return ctx.runAction(internal.edgeProviderOps.reapply, {
      accountId: edge.accountId,
      edgeId,
      ledger: { steps: edge.steps, resources: edge.resources },
    });
  },
  runFrontProof: (ctx, edgeId) => ctx.runAction(internal.frontQualifyOps.run, { edgeId }),
  buildTestLink: (ctx, edgeId) => ctx.runAction(internal.edgeTestLinks.build, { edgeId }),
  hideHosts: (ctx, a) => ctx.runAction(internal.edgeHostHides.hide, a),
  hideStatus: (ctx, relayId) => ctx.runQuery(internal.edgeHostHides.status, { relayId }),
  rehearse: (ctx, a) => ctx.runAction(internal.edgeRehearsal.run, a),
  vectorNow: async (ctx, relayId) => {
    const v = await ctx.runQuery(internal.edgeRehearsal.vectorNow, { relayId });
    if (!v) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    return v;
  },
  restoreStart: async (ctx, a) => {
    await ctx.runMutation(internal.edgeRestore.start, a);
  },
};

let ops: StageOps = defaultOps;

/** Test seam: replace any of the subsystem calls (null = the defaults). */
export function __setStageOpsForTests(over: Partial<StageOps> | null): void {
  ops = over ? { ...defaultOps, ...over } : defaultOps;
}

// --- small helpers ------------------------------------------------------------------------------------

function parsePlan(run: Run): SetupPlanSnapshot {
  return JSON.parse(run.plan) as SetupPlanSnapshot;
}

function errCode(err: unknown): { code: string; message: string } {
  if (err instanceof ConvexError) {
    const d = err.data as { code?: string; message?: string } | string;
    if (typeof d === 'string') return { code: d.slice(0, 80), message: d };
    return { code: d.code ?? 'error', message: d.message ?? d.code ?? 'error' };
  }
  return { code: 'error', message: err instanceof Error ? err.message : String(err) };
}

async function scheduleStep(ctx: MutationCtx, runId: Id<'edgeSetupRuns'>, delayMs: number) {
  const run = await ctx.db.get(runId);
  if (!run) return;
  await ctx.scheduler.runAfter(delayMs, internal.edgeSetupRuns.step, {
    runId,
    stepVersion: run.stepVersion,
  });
  await ctx.db.patch(runId, { nextStepAt: Date.now() + delayMs });
}

async function guard(
  ctx: MutationCtx,
  runId: Id<'edgeSetupRuns'>,
  stepVersion: number,
): Promise<Run | null> {
  const r = await ctx.db.get(runId);
  if (!r || r.stepVersion !== stepVersion || isTerminalRunState(r.state)) return null;
  return r;
}

async function auditRun(
  ctx: MutationCtx,
  run: Run,
  action: string,
  payload: Record<string, unknown>,
  actorAdminId?: Id<'adminUsers'>,
) {
  await writeAuditLog(ctx, {
    actorType: actorAdminId ? 'admin' : 'system',
    actorId: actorAdminId ?? undefined,
    action,
    targetType: 'relay',
    targetId: run.relayId ?? undefined,
    payload: { relaySlug: run.relaySlug, runId: run._id, ...payload },
  });
}

/** The enrolled node a run protects, as the admin projection names it (null = unmanaged). */
export interface RunEnrolled {
  slug: string;
  intentId: string;
  stage: string;
}

/** What a listener carries, from the plan, so the CMS names it in words (never its key). */
function transportOf(plan: SetupPlanSnapshot, listenerKey: string) {
  const spec = plan.inbounds.find((i) => i.listenerKey === listenerKey)?.listenerSpec as
    | { protocol?: string; streamTransport?: string; security?: string; originPort?: number }
    | null
    | undefined;
  return spec?.protocol && spec.streamTransport && spec.security
    ? {
        protocol: spec.protocol,
        streamTransport: spec.streamTransport,
        security: spec.security,
        originPort: spec.originPort ?? null,
      }
    : null;
}

/** The admin projection (`GET setup-runs/{id}`); never the plan's addresses beyond the origin the operator typed. */
export function mapRunAdmin(r: Run, enrolled: RunEnrolled | null = null) {
  const plan = parsePlan(r);
  return {
    id: r._id as string,
    enrolled,
    activationRunId: (r.activationRunId as string | undefined) ?? null,
    relayId: (r.relayId as string | undefined) ?? null,
    relaySlug: r.relaySlug,
    backendServerId: r.backendServerId as string,
    nodeName: r.nodeName,
    nodeUuid: r.nodeUuid,
    accountId: (runPick(r).accountId as string | null) ?? '',
    locationId: (runPick(r).locationId as string | null) ?? null,
    stage: r.stage,
    state: r.state,
    need: r.need
      ? {
          code: r.need.code,
          detail: r.need.detail ?? null,
          providerAnswer: r.need.providerAnswer ?? null,
        }
      : null,
    generation: r.generation,
    planRevision: r.planRevision,
    keepDirect: r.keepDirect === true,
    kind: r.kind ?? ('protect' as const),
    // One line per target: a transport has one address per pick of its set.
    listeners: r.listeners.map((l) => ({
      listenerKey: l.listenerKey,
      locationId: (l.locationId as string | undefined) ?? null,
      layer: l.layer,
      edgeId: (l.edgeId as string | undefined) ?? null,
      verify: l.verify,
      published: l.published,
      notChecked: l.notChecked ?? [],
      transport: transportOf(plan, l.listenerKey),
    })),
    // The set's picks, with the plan's words for them.
    picks: runPicks(r).map((p) => {
      const shown = plan.set?.picks.find((x) => x.locationId === (p.locationId as string | null));
      const account = plan.accounts.find((a) => a.id === (p.accountId as string | null));
      return {
        locationId: (p.locationId as string | null) ?? null,
        accountId: (p.accountId as string | null) ?? null,
        accountName: account?.name ?? null,
        provider: account?.provider ?? shown?.provider ?? null,
        label:
          shown?.label ??
          account?.locations?.find((l) => l.id === (p.locationId as string | null))?.label ??
          null,
      };
    }),
    reduced: plan.set?.reduced ?? [],
    testLinks: (r.testLinks ?? []).map((t) => ({
      edgeId: t.edgeId as string,
      listenerKey: t.listenerKey,
      link: t.link,
      format: t.format,
      method: t.method,
      binding: {
        endpoint: t.binding.endpoint,
        listenerRevision: t.binding.listenerRevision,
        configHash: t.binding.configHash,
        issuedAt: new Date(t.binding.issuedAt).toISOString(),
      },
    })),
    testedEndpoints: (r.testedEndpoints ?? []).map((t) => ({
      edgeId: t.edgeId as string,
      listenerKey: t.listenerKey,
      endpoint: t.endpoint,
      at: new Date(t.at).toISOString(),
    })),
    reviewDelta: r.reviewDelta ?? [],
    rehearsal: r.rehearsal
      ? {
          at: new Date(r.rehearsal.at).toISOString(),
          attempts: r.rehearsal.attempts,
          hostsObservationAt: new Date(r.rehearsal.hostsObservation.at).toISOString(),
          darkCohortKeys: r.rehearsal.darkCohortKeys,
        }
      : null,
    plan: {
      requiredListeners: plan.requiredListeners,
      directHosts: plan.directHosts,
      renderGlobal: plan.renderGlobal,
      familiesDisabled: plan.familiesDisabled,
      emptyNode: plan.emptyNode,
      // The accounts the plan judged: `retry {accountId}` accepts only a
      // compatible one, so a "choose another account" card offers only these.
      accounts: plan.accounts.map((a) => ({
        id: a.id,
        name: a.name,
        provider: a.provider,
        compatible: a.compatible,
        carries: a.carries ?? null,
        locations: (a.locations ?? []).map((l) => ({
          id: l.id,
          label: l.label,
          compatible: l.compatible,
        })),
      })),
    },
    approvedHideUuids: r.approvedHideUuids,
    events: r.events.slice(-20).map((e) => ({
      at: new Date(e.at).toISOString(),
      level: e.level,
      code: e.code,
      detail: e.detail ?? null,
    })),
    startedAt: new Date(r.startedAt).toISOString(),
    attemptStartedAt: new Date(r.attemptStartedAt ?? r.startedAt).toISOString(),
    updatedAt: new Date(r.updatedAt).toISOString(),
    finishedAt: r.finishedAt ? new Date(r.finishedAt).toISOString() : null,
  };
}

// --- reads --------------------------------------------------------------------------------------------

export const get = internalQuery({
  args: { id: v.id('edgeSetupRuns') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

/**
 * The enrolled node behind a run (docs/servers.md "Node lifecycle"): the
 * approval card at `node_not_approved` calls the Servers routes with it.
 */
async function enrolledOf(
  ctx: { db: QueryCtx['db'] },
  r: Run,
  slugs: Map<string, string | null> = new Map(),
): Promise<RunEnrolled | null> {
  const intent = await ctx.db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) =>
      q.eq('backendServerId', r.backendServerId).eq('name', r.nodeName),
    )
    .unique();
  if (!intent) return null;
  const key = r.backendServerId as string;
  if (!slugs.has(key)) slugs.set(key, (await ctx.db.get(r.backendServerId))?.slug ?? null);
  const slug = slugs.get(key);
  if (!slug) return null;
  return { slug, intentId: intent._id as string, stage: intent.activation.stage };
}

/**
 * Whether a run's node is an ENROLLED node fronted by edges: its members can
 * only ever be served through the edges (docs/servers.md "Node lifecycle"),
 * so "keep them on the direct address" does not exist for it.
 */
async function frontedEnrolled(
  ctx: { db: QueryCtx['db'] },
  backendServerId: Id<'backendServers'>,
  nodeName: string,
): Promise<boolean> {
  const intent = await ctx.db
    .query('panelNodeIntents')
    .withIndex('by_server_name', (q) =>
      q.eq('backendServerId', backendServerId).eq('name', nodeName),
    )
    .unique();
  if (!intent) return false;
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .unique();
  if (!setupReady(setup)) return true;
  try {
    return !isDirect(modeEntry(setup, modeSlug(intent)).shape);
  } catch {
    // A mode the setup no longer lists fails closed: treated as fronted.
    return true;
  }
}

const refuseKeepDirect = (): never => {
  throw new ConvexError({
    code: 'edge.keep_direct_enrolled',
    message:
      'An enrolled node fronted by edges has no direct address to keep members on; remove protection instead',
  });
};

export const getForAdmin = internalQuery({
  args: { id: v.id('edgeSetupRuns') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r ? mapRunAdmin(r, await enrolledOf(ctx, r)) : null;
  },
});

/** Non-terminal runs first, then the most recent terminal ones (bounded). */
export const listForAdmin = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out: Run[] = [];
    for (const state of ['running', 'waiting', 'needs_you'] as const) {
      out.push(
        ...(await ctx.db
          .query('edgeSetupRuns')
          .withIndex('by_state', (q) => q.eq('state', state))
          .order('desc')
          .take(50)),
      );
    }
    for (const state of ['done', 'done_unbound', 'failed', 'cancelled'] as const) {
      out.push(
        ...(await ctx.db
          .query('edgeSetupRuns')
          .withIndex('by_state', (q) => q.eq('state', state))
          .order('desc')
          .take(10)),
      );
    }
    const slugs = new Map<string, string | null>();
    const runs = [];
    for (const r of out) runs.push(mapRunAdmin(r, await enrolledOf(ctx, r, slugs)));
    return { runs, generatedAt: new Date().toISOString() };
  },
});

/** The non-terminal run of an origin, if any (one per origin by construction). */
export async function activeRunForOrigin(
  db: QueryCtx['db'],
  backendServerId: Id<'backendServers'>,
  nodeName: string,
): Promise<Run | null> {
  const rows = await db
    .query('edgeSetupRuns')
    .withIndex('by_origin', (q) =>
      q.eq('backendServerId', backendServerId).eq('nodeName', nodeName),
    )
    .collect();
  return rows.find((r) => !isTerminalRunState(r.state)) ?? null;
}

/**
 * The local version vector stage 7 records and stage 8 compares: every
 * non-retired listener's revision, the render configuration, the publication
 * epoch and the identity of every current L7 proof. Pure over the rows.
 */
export async function localVectorFor(
  ctx: { db: QueryCtx['db'] },
  relayId: Id<'relays'>,
): Promise<SetupVector> {
  const relay = await ctx.db.get(relayId);
  const cfg = await resolveEdgeConfig(ctx.db);
  const listeners = (await listenersOf(ctx, relayId)).filter((l) => !l.retired);
  const listenerRevisions: Record<string, number> = {};
  for (const l of listeners) listenerRevisions[l.listenerKey] = l.revision;
  const qualificationEvidenceIds: string[] = [];
  for (const e of await liveEdgesOfRelay(ctx.db, relayId)) {
    if (e.publication !== 'published' || (e.layer ?? edgeLayerOf(e.provider)) !== 'l7') continue;
    if (e.frontQualification?.ok)
      qualificationEvidenceIds.push(`${e._id}:${e.frontQualification.checkedAt}`);
  }
  return {
    listenerRevisions,
    renderConfigHash: fnv1a64Hex(canonicalJson(cfg.render)),
    publicationEpoch: relay?.publicationEpoch ?? 0,
    qualificationEvidenceIds,
    activation: relay ? await activationVectorFor(ctx, relay) : null,
  };
}

export const localVector = internalQuery({
  args: { relayId: v.id('relays') },
  handler: (ctx, { relayId }) => localVectorFor(ctx, relayId),
});

/**
 * Stage 4's outside check of one L4 address (lib/edges/verifyRung.ts
 * `outsideCheckFor`): the reachability rows, the newest runs of every source
 * (in flight or settled) and the internal shape runs, per address family.
 */
export const outsideCheck = internalQuery({
  args: {
    edgeId: v.id('edges'),
    /** A fresh check ("Check again", a re-apply): only evidence from this time on counts. */
    since: v.optional(v.number()),
    /** When the stage asked for its own round (absent before it has). */
    roundSince: v.optional(v.number()),
    /** The stage's wait is over: a run still in flight is not waited for. */
    final: v.optional(v.boolean()),
  },
  handler: async (ctx, { edgeId, since, roundSince, final }) => {
    const gone = {
      verdict: 'unreachable' as const,
      notChecked: [] as Array<4 | 6>,
      blockedIn: [] as string[],
      providerHealthy: false,
    };
    const edge = await ctx.db.get(edgeId);
    if (!edge) return gone;
    const listener = await ctx.db.get(edge.listenerId);
    if (!listener) return gone;
    const cfg = await resolveEdgeConfig(ctx.db);
    const fresh = (at: number | undefined) => since === undefined || (at ?? 0) >= since;
    const reach = await ctx.db
      .query('probeReachability')
      .withIndex('by_target_country', (q) => q.eq('targetKind', 'edge').eq('targetRef', edgeId))
      .collect();
    // The shape check's own runs (their own index range: controls and extra
    // rounds can never push them out of the window), and the newest runs of
    // every source for what is still in flight.
    const runs = new Map<string, Doc<'probeRuns'>>();
    for (const r of await internalRunsOf(ctx.db, edgeId)) runs.set(r._id, r);
    for (const r of await ctx.db
      .query('probeRuns')
      .withIndex('by_target_requested', (q) =>
        q.eq('targetKind', 'edge').eq('targetRef', edgeId as string),
      )
      .order('desc')
      .take(50))
      runs.set(r._id, r);
    const providerHealthy = providerHealthSatisfies(
      edge.provider,
      edge.health,
      cfg.requireProviderHealth,
    );
    // Every listed country is read on its own: a refusal from listed countries
    // alone, while the address works from elsewhere, is a block there
    // (`blocked_in`), unless the node's other addresses fail there too (the
    // vantages there, or the protocol, are the problem: not this address).
    const now = Date.now();
    const staleAfterMs = probeStaleAfterMs(cfg.probe);
    const siblings = (await liveEdgesOfRelay(ctx.db, edge.relayId)).filter((e) => e._id !== edgeId);
    const siblingsFailIn = cfg.probe.countries.filter((country) => {
      const seen = siblings.flatMap((e) =>
        (e.reachability?.byCountry ?? []).filter(
          (c) => c.country === country && c.verdict !== 'unknown' && now - c.lastAt <= staleAfterMs,
        ),
      );
      return seen.length > 0 && seen.every((c) => c.verdict === 'unreachable');
    });
    const check = outsideCheckFor(listener, {
      families: literalFamilies(edge.addresses, cfg.render.ipv6Mode !== 'off'),
      providerHealthy,
      reachability: reach.filter((r) => fresh(r.updatedAt)).map(rungRowOf),
      probeRuns: [...runs.values()].filter((r) => fresh(r.requestedAt)).map(rungRunOf),
      agreementVantages: cfg.probe.agreementVantages,
      ports: edgePortsOf(edge),
      ...(roundSince !== undefined ? { roundSince } : {}),
      final: final === true,
      listed: cfg.probe.countries,
      siblingsFailIn,
    });
    return {
      verdict: check.verdict,
      notChecked: check.notChecked,
      blockedIn: check.blockedIn,
      providerHealthy,
    };
  },
});

/** Whether a probe run of the address is still requested or running (its newest 50). */
export const probesInFlight = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const recent = await ctx.db
      .query('probeRuns')
      .withIndex('by_target_requested', (q) =>
        q.eq('targetKind', 'edge').eq('targetRef', edgeId as string),
      )
      .order('desc')
      .take(50);
    return recent.some((r) => r.status === 'requested' || r.status === 'running');
  },
});

/** What the stages need to know about the origin in one read. */
export const relayContext = internalQuery({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const run = await ctx.db.get(runId);
    if (!run?.relayId) return null;
    const relay = await ctx.db.get(run.relayId);
    if (!relay) return null;
    // With the enrolled node's auth revision: an L4 tick binds to it.
    const listeners = (
      await verificationListenersOf(ctx.db, relay, await listenersOf(ctx, relay._id))
    ).filter((l) => !l.retired);
    const edges = await liveEdgesOfRelay(ctx.db, relay._id);
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    // The edges built with what this run's pick at their location asks for:
    // only those may be reused (an earlier generation's standby or a spare
    // built for other choices is not this node's).
    const fitsPick: string[] = [];
    for (const e of edges)
      if (
        await edgeFitsPick(
          ctx,
          { setupRun: { runId: run._id, generation: run.generation } },
          relay,
          e,
        )
      )
        fitsPick.push(e._id as string);
    return {
      relay,
      listeners,
      edges,
      fitsPick,
      cfg,
      frontedEnrolled: await frontedEnrolled(ctx, run.backendServerId, run.nodeName),
      // Keyed by the target's edge: a transport may have one address per pick.
      verification: Object.fromEntries(
        run.listeners
          .filter((rl) => !!rl.edgeId)
          .map((rl) => {
            const l = listeners.find((x) => x.listenerKey === rl.listenerKey);
            const e = edges.find((x) => x._id === rl.edgeId);
            return [
              rl.edgeId as string,
              {
                current: !!l && !!e && (!needsEndpointVerification(e) || verificationCurrent(e, l)),
                // Stale only because the enrolled node's REALITY key moved.
                keyChanged:
                  !!l &&
                  !!e &&
                  needsEndpointVerification(e) &&
                  verificationStaleReason(e, l) === 'reality_key_changed',
                proofOk: !!e && l7ProofCurrent(e, l ?? null, now),
                // In the pool, on a listener whose FCP Host exists (its template
                // edge). A live node's replacement joins the pool beside the
                // committed template without moving the Host pointer.
                published: !!l && !!e && !!l.templateEdgeId && e.publication === 'published',
                live: !!e && LIVE_CANDIDATE.has(e.status),
              },
            ];
          }),
      ) as Record<
        string,
        {
          current: boolean;
          keyChanged: boolean;
          proofOk: boolean;
          published: boolean;
          live: boolean;
        }
      >,
    };
  },
});

/** A target's verification facts (its edge's), or undefined while it has no edge. */
function vOf<V>(
  c: { verification: Record<string, V> },
  entry: Pick<RunListener, 'edgeId'>,
): V | undefined {
  return entry.edgeId ? c.verification[entry.edgeId as string] : undefined;
}

/** A target's identity: its transport and its pick (a transport has one address per pick). */
export function targetKeyOf(entry: Pick<RunListener, 'listenerKey' | 'locationId'>): string {
  return `${entry.listenerKey}@${(entry.locationId as string | undefined) ?? ''}`;
}

function l7ProofCurrent(e: Edge, l: Listener | null, now: number): boolean {
  if ((e.layer ?? edgeLayerOf(e.provider)) !== 'l7') return true;
  const intent = parseIntent(e.provisionIntent);
  if (!l || !intent) return false;
  return (
    qualificationVerdict(
      e.frontQualification,
      qualificationBinding({ listener: l, intent, params: l.transportParams ?? {} }),
      now,
    ) === 'ok'
  );
}

// --- writes: insert, transitions ----------------------------------------------------------------------

/**
 * Insert a run (`POST setup-runs`, after the plan action validated the hash and
 * the account). An origin a previous run left `setupOwned` is reused: the new
 * run (generation 1 of its own row) resumes at the origin's recorded stage.
 */
export const insert = internalMutation({
  args: {
    plan: v.string(),
    planHash: v.string(),
    /** The set's picks (locations), in set order, and the targets the plan's cover asked for. */
    picks: v.optional(v.array(v.id('edgeLocations'))),
    /** Each pick's provider options (JSON), as the plan showed them. */
    pickOptions: v.optional(
      v.array(v.object({ locationId: v.id('edgeLocations'), options: v.string() })),
    ),
    targets: v.optional(
      v.array(v.object({ listenerKey: v.string(), locationId: v.id('edgeLocations') })),
    ),
    /** One pick the old way: an account (its default location) or a location. */
    accountId: v.optional(v.id('edgeProviderAccounts')),
    locationId: v.optional(v.id('edgeLocations')),
    approvedHideUuids: v.array(v.string()),
    keepDirect: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    // New work: held while the edges maintenance switch is on (checked here,
    // in the mutation that persists the run, never only in the action before it).
    await assertAdmission(ctx.db, 'setup.start');
    const plan = JSON.parse(a.plan) as SetupPlanSnapshot;
    const backendServerId = plan.backendServerId as Id<'backendServers'>;
    const active = await activeRunForOrigin(ctx.db, backendServerId, plan.nodeName);
    if (active)
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run already owns this node',
      });
    // A rename moves every reference to the node's name: nothing new is keyed
    // to it until it is done.
    if (
      await runningRenameOf(ctx.db, backendServerId, {
        nodeUuid: plan.nodeUuid,
        name: plan.nodeName,
      })
    )
      throw new ConvexError({
        code: 'edge.panel_op_running',
        message: 'This node is being renamed; wait for it to finish',
      });
    // The picks: the set the plan was shown with, or one pick the old way.
    let pickIds = a.picks ?? [];
    if (pickIds.length === 0) {
      const named = a.locationId ? await ctx.db.get(a.locationId) : null;
      if (a.locationId && !named)
        throw new ConvexError({ code: 'not_found', message: 'Location not found' });
      const accountId = a.accountId ?? named?.accountId;
      if (!accountId)
        throw new ConvexError({ code: 'validation', message: 'Name an account or a location' });
      const account = await ctx.db.get(accountId);
      if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
      const location = await pickLocationOf(ctx.db, account, a.locationId);
      if (!location)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'The account has no such location',
        });
      pickIds = [location._id];
    }
    const picks: Array<{ location: Doc<'edgeLocations'>; account: Doc<'edgeProviderAccounts'> }> =
      [];
    for (const id of pickIds) {
      const location = await ctx.db.get(id);
      const account = location ? await ctx.db.get(location.accountId) : null;
      if (!location || !account)
        throw new ConvexError({ code: 'not_found', message: 'Location not found' });
      const offered = plan.accounts.find((x) => x.id === (account._id as string));
      const offeredLocation = offered?.locations?.find((l) => l.id === (location._id as string));
      if (!offered?.compatible || (offered.locations && !offeredLocation?.compatible))
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'An account cannot front this node from that location',
        });
      picks.push({ location, account });
    }
    // The run's targets: the plan's cover, else (the old single pick) every
    // required transport on that one location.
    const targets =
      a.targets ??
      plan.requiredListeners.map((listenerKey) => ({
        listenerKey,
        locationId: picks[0]!.location._id,
      }));
    for (const t of targets)
      if (!picks.some((p) => p.location._id === t.locationId))
        throw new ConvexError({
          code: 'validation',
          message: 'A target names a location not picked',
        });
    if (a.keepDirect === true && (await frontedEnrolled(ctx, backendServerId, plan.nodeName)))
      refuseKeepDirect();
    const now = Date.now();
    let relayId: Id<'relays'> | undefined;
    let stage: SetupRunStage = 'prepare';
    let slug = plan.relaySlug;
    if (plan.existingRelay) {
      const relay = await ctx.db.get(plan.existingRelay.id as Id<'relays'>);
      if (relay && relay.setupOwned && !relay.deleting) {
        // The origin's listeners must still be what the new plan discovered:
        // a transport added, removed or changed on the backend since the previous
        // run would otherwise resume at a stage that never provisions, tests
        // or hides for it. Refused rather than reconciled in place.
        await assertPlanMatchesRelay(ctx, relay, plan);
        relayId = relay._id;
        slug = relay.slug;
        const recorded = relay.setupStage as SetupRunStage | undefined;
        stage =
          recorded && (SETUP_RUN_STAGES as readonly string[]).includes(recorded)
            ? recorded
            : 'credential';
        // The new run's listeners hold no edge yet, and only publish (through
        // provision, which takes the origin's own edges back) can give them
        // one: a stage past it (hiding, the rehearsal, go-live, or a finished
        // run) would wait on addresses it never attached. It resumes at publish.
        if (STAGE_INDEX[stage] > STAGE_INDEX.publish) stage = 'publish';
      }
    }
    const layerOf = (locationId: Id<'edgeLocations'>) =>
      edgeLayerOf(picks.find((p) => p.location._id === locationId)!.account.provider);
    const id = await ctx.db.insert('edgeSetupRuns', {
      relayId,
      relaySlug: slug,
      backendServerId,
      nodeName: plan.nodeName,
      nodeUuid: plan.nodeUuid,
      picks: picks.map((p) => {
        const options = a.pickOptions?.find((x) => x.locationId === p.location._id)?.options;
        return {
          locationId: p.location._id,
          accountId: p.account._id,
          ...(options !== undefined ? { options } : {}),
        };
      }),
      plan: JSON.stringify(plan),
      planHash: a.planHash,
      planRevision: 1,
      approvedHideUuids: a.approvedHideUuids,
      keepDirect: a.keepDirect === true ? true : undefined,
      stage,
      state: 'running',
      generation: 1,
      stepVersion: 1,
      listeners: targets.map((t) => ({
        listenerKey: t.listenerKey,
        locationId: t.locationId,
        layer: layerOf(t.locationId),
        verify: 'pending' as const,
        published: false,
      })),
      stageEnteredAt: now,
      events: [{ at: now, level: 'info', code: 'started', detail: `stage ${stage}` }],
      actorAdminId: a.actorAdminId,
      startedAt: now,
      updatedAt: now,
    });
    const run = (await ctx.db.get(id))!;
    await auditRun(
      ctx,
      run,
      'edge.setup_run.started',
      {
        stage,
        listeners: plan.requiredListeners.length,
        accountName: picks[0]!.account.name,
        provider: picks[0]!.account.provider,
        picks: picks.length,
        targets: targets.length,
        approvedHides: a.approvedHideUuids.length,
        keepDirect: a.keepDirect === true,
      },
      a.actorAdminId,
    );
    await scheduleStep(ctx, id, 0);
    return { id, stage };
  },
});

/**
 * The one transition mutation the step action reports through. Guarded by
 * `stepVersion`; bumps it; records the event; audits a `needs_you` and a
 * terminal failure; mirrors the stage onto `origins.setupStage`; schedules the
 * next step when asked (`scheduleMs`), else leaves the run waiting for a hook
 * or the operator.
 */
export const transition = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    stepVersion: v.number(),
    stage: v.optional(stageV),
    state: stateV,
    need: v.optional(
      v.union(v.object({ code: v.string(), detail: v.optional(v.string()) }), v.null()),
    ),
    event: v.optional(eventV),
    listeners: v.optional(v.array(runListenerV)),
    testLinks: v.optional(v.union(v.array(testLinkV), v.null())),
    reviewDelta: v.optional(v.array(v.object({ uuid: v.string(), remark: v.string() }))),
    rehearsal: v.optional(rehearsalV),
    relayId: v.optional(v.id('relays')),
    relaySlug: v.optional(v.string()),
    scheduleMs: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.runId, a.stepVersion);
    if (!r) return { ok: false as const };
    const now = Date.now();
    const stage = a.stage ?? r.stage;
    const terminal = isTerminalRunState(a.state);
    const patch: Partial<Run> = {
      stage,
      state: a.state,
      stepVersion: r.stepVersion + 1,
      updatedAt: now,
      nextStepAt: undefined,
      ...(a.need === null ? { need: undefined } : a.need ? { need: a.need } : {}),
      ...(a.listeners ? { listeners: a.listeners } : {}),
      ...(a.testLinks === null
        ? { testLinks: undefined }
        : a.testLinks
          ? { testLinks: a.testLinks }
          : {}),
      ...(a.reviewDelta ? { reviewDelta: a.reviewDelta } : {}),
      ...(a.rehearsal ? { rehearsal: a.rehearsal } : {}),
      ...(a.relayId ? { relayId: a.relayId } : {}),
      ...(a.relaySlug ? { relaySlug: a.relaySlug } : {}),
      ...(stage !== r.stage ? { stageEnteredAt: now } : {}),
      ...(terminal ? { finishedAt: now, expect: undefined } : {}),
      events: a.event ? appendRunEvent(r.events, { at: now, ...a.event }) : r.events,
    };
    if (a.state !== 'needs_you' && a.need === undefined) patch.need = undefined;
    await ctx.db.patch(r._id, patch);
    const relayId = a.relayId ?? r.relayId;
    if (relayId && stage !== r.stage) {
      const relay = await ctx.db.get(relayId);
      if (relay?.setupOwned) await ctx.db.patch(relayId, { setupStage: stage, updatedAt: now });
    }
    const after = (await ctx.db.get(r._id))!;
    if (a.state === 'needs_you' && a.need) {
      await auditRun(ctx, after, 'edge.setup_run.needs_operator', { stage, code: a.need.code });
    }
    if (a.state === 'failed') {
      await auditRun(ctx, after, 'edge.setup_run.finished', {
        outcome: 'failed',
        stage,
        code: a.need?.code ?? a.event?.code ?? 'failed',
        verdicts: verdictsOf(after),
      });
    }
    if (a.state === 'done_unbound') {
      await auditRun(ctx, after, 'edge.setup_run.finished', {
        outcome: 'unbound',
        stage,
        verdicts: verdictsOf(after),
      });
    }
    if (a.state === 'failed' || a.state === 'done_unbound')
      await onSetupRunEnded(ctx, r, r.generation);
    if (a.scheduleMs !== undefined && !terminal && a.state !== 'needs_you')
      await scheduleStep(ctx, r._id, a.scheduleMs);
    return { ok: true as const };
  },
});

/**
 * Every terminal writer of a setup run calls this with the row as it read it
 * BEFORE its write and the generation it is ending. A run that ends without
 * going live leaves the node's activation with nothing to publish its
 * candidate: the activation is blocked and the node parks where it can be
 * approved again. Only the activation this run is bound to (both links agree,
 * it is still the node's current run) and only for the run's CURRENT
 * generation: a late hook of an older attempt or an older run is a no-op.
 *
 * A re-protect run (`kind: 'reprotect'`) also hands the live origin back here:
 * its node never stopped serving the committed delivery, so a run that ends
 * without going live clears `setupOwned` (upkeep and the detector protect the
 * node again). A first protection keeps its origin owned, as before.
 */
export async function onSetupRunEnded(
  ctx: MutationCtx,
  setupRun: Run,
  endingGeneration: number,
  code = 'servers.setup_run_ended',
): Promise<void> {
  // The generation is read from the row as it stands (every writer that moves
  // the generation calls this BEFORE its write): a hook for an attempt that
  // was already replaced does nothing.
  const current = await ctx.db.get(setupRun._id);
  if (!current || endingGeneration !== current.generation) return;
  if (current.kind === 'reprotect') await releaseReprotectOrigin(ctx, current);
  if (!current.activationRunId) return;
  const act = await ctx.db.get(current.activationRunId);
  if (!act || act.setupRunId !== current._id || act.state !== 'running') return;
  const intent = await ctx.db.get(act.intentId);
  if (!intent || intent.activation.currentRunId !== act._id) return;
  await blockActivation(ctx, act, code);
}

/**
 * A re-protect run that ended without going live gives the live origin back,
 * and the room it made for its new addresses (`restoreReprotectPool`).
 */
async function releaseReprotectOrigin(ctx: MutationCtx, run: Run): Promise<void> {
  if (!run.relayId) return;
  const relay = await ctx.db.get(run.relayId);
  if (!relay) return;
  await restoreReprotectPool(ctx, run, relay);
  if (!relay.setupOwned && relay.setupStage === undefined) return;
  await ctx.db.patch(relay._id, {
    setupOwned: undefined,
    setupStage: undefined,
    updatedAt: Date.now(),
  });
}

/**
 * Room for a re-protect's new addresses. Each one is published BESIDE what
 * members already hold, so a full pool would keep every candidate a standby
 * (`pool_full_standby`) and the run could never go live. The pool is widened
 * to what is published, plus one slot per target of the run that has no
 * published address yet, plus the slots the coverage deficit reserves
 * (`allocatePoolIndex`). The run's own targets are TEMPORARY room above the
 * cap (MAX_DESIRED_PUBLISHED): any set that fits the steady state can be
 * protected again; past that `edge.reprotect_no_room`. Go-live retires the
 * replaced addresses and gives the room back (`retireReplacedEdges`), and so
 * does a run that ends without going live.
 */
async function ensureReprotectRoom(
  ctx: MutationCtx,
  relay: Relay,
  newAddresses: number,
): Promise<void> {
  // Coverage listeners with no template edge hold their reserved slots.
  const uncovered = (await listenersOf(ctx, relay._id)).filter(
    (l) => l.deployed && l.enabled && !l.retired && !l.templateEdgeId,
  ).length;
  const needed = publishedCount(relay.publishedEdgeIds) + newAddresses + uncovered;
  if (needed <= relay.desiredPublished) return;
  if (needed > MAX_DESIRED_PUBLISHED + newAddresses)
    throw new ConvexError({
      code: 'edge.reprotect_no_room',
      message: `This origin has no room for a new address per transport (at most ${MAX_DESIRED_PUBLISHED} in use); remove an address first`,
    });
  await ctx.db.patch(relay._id, { desiredPublished: needed, updatedAt: Date.now() });
}

/**
 * The pool size a re-protect found, back (never below what is published now).
 * The surviving edges are compacted first: a new address published into the
 * widened slot would otherwise sit above the restored size with a hole below
 * it, and that hole would admit a publication past the size (two published in
 * a pool of one).
 */
async function restoreReprotectPool(ctx: MutationCtx, run: Run, relay: Relay): Promise<void> {
  const before = parsePlan(run).reprotect?.desiredBefore;
  if (before === undefined) return;
  await compactPool(ctx, relay._id);
  const fresh = (await ctx.db.get(relay._id)) ?? relay;
  const desired = Math.max(before, publishedCount(fresh.publishedEdgeIds));
  if (fresh.desiredPublished !== desired)
    await ctx.db.patch(relay._id, { desiredPublished: desired, updatedAt: Date.now() });
}

/**
 * Close the holes of a published pool: the published edges move down to
 * indexes 0..n-1 in their order (each edge's `poolIndex` with them), the epoch
 * is bumped so no render keyed to the old layout is reused, and the template
 * edges follow. A pool without holes is left alone.
 */
async function compactPool(ctx: MutationCtx, relayId: Id<'relays'>): Promise<void> {
  const relay = await ctx.db.get(relayId);
  if (!relay) return;
  const ids = relay.publishedEdgeIds.filter((e): e is Id<'edges'> => !!e);
  if (ids.length === relay.publishedEdgeIds.length) return;
  const now = Date.now();
  for (let i = 0; i < ids.length; i++) {
    const e = await ctx.db.get(ids[i]!);
    if (e && e.poolIndex !== i) await ctx.db.patch(e._id, { poolIndex: i, updatedAt: now });
  }
  await ctx.db.patch(relayId, {
    publishedEdgeIds: ids,
    publicationEpoch: relay.publicationEpoch + 1,
    updatedAt: now,
  });
  await refreshTemplateEdges(ctx, relay);
  await scheduleMirrorRefresh(ctx);
}

/**
 * Go-live of a re-protect: the new addresses take the places of the ones they
 * replace. Every other published edge on a run transport is drained (members
 * move at their next refresh, as after a Replace) once that transport's new
 * address is published; a transport whose new address is not published keeps
 * what it has. Then the pool size is given back.
 */
async function retireReplacedEdges(ctx: MutationCtx, run: Run, relay: Relay): Promise<number> {
  const keep = new Set(run.listeners.map((l) => l.edgeId).filter((e): e is Id<'edges'> => !!e));
  const listeners = await listenersOf(ctx, relay._id);
  const retire: Edge[] = [];
  const seen = new Set<string>();
  for (const entry of run.listeners) {
    const l = listeners.find((x) => x.listenerKey === entry.listenerKey && !x.retired);
    const fresh = entry.edgeId ? await ctx.db.get(entry.edgeId) : null;
    if (!l || !fresh || fresh.publication !== 'published') continue;
    for (const id of relay.publishedEdgeIds) {
      if (!id || keep.has(id)) continue;
      const e = await ctx.db.get(id);
      if (e && e.listenerId === l._id && e.publication === 'published' && !seen.has(id)) {
        seen.add(id);
        retire.push(e);
      }
    }
  }
  for (const e of retire) await unpublishFromPool(ctx, relay, e, {});
  await restoreReprotectPool(ctx, run, relay);
  return retire.length;
}

/**
 * The provider set a run leaves the node with: its picks in order, an `add`
 * re-protect's after the picks the node already had. A pick already in the
 * set keeps its `addedAt`.
 */
function providerSetAfter(relay: Relay, r: Run, now: number): NonNullable<Relay['providerSet']> {
  const before = relay.providerSet ?? [];
  const add = parsePlan(r).reprotect?.mode === 'add';
  const out: NonNullable<Relay['providerSet']> = add ? [...before] : [];
  for (const p of runPicks(r)) {
    if (!p.locationId) continue;
    const kept = before.find((x) => x.locationId === p.locationId);
    // A pick the run names takes the run's options (an `add` re-protect may
    // change them for a pick the node already had); one without keeps its own.
    const options = p.options ?? kept?.options;
    const entry = {
      locationId: p.locationId,
      addedAt: kept?.addedAt ?? now,
      ...(options !== undefined ? { options } : {}),
    };
    const at = out.findIndex((x) => x.locationId === p.locationId);
    if (at >= 0) out[at] = entry;
    else out.push(entry);
  }
  return out;
}

function verdictsOf(run: Run): string {
  const many = new Set(run.listeners.map((l) => l.locationId ?? '')).size > 1;
  return run.listeners.map((l) => `${many ? targetKeyOf(l) : l.listenerKey}:${l.verify}`).join(',');
}

/** The step action stamps its start so `listStale` can tell "never started" from "started and hung". */
export const markStepStarted = internalMutation({
  args: { runId: v.id('edgeSetupRuns'), stepVersion: v.number() },
  handler: async (ctx, { runId, stepVersion }) => {
    const r = await ctx.db.get(runId);
    if (!r || r.stepVersion !== stepVersion) return null;
    await ctx.db.patch(runId, { stepStartedAt: Date.now() });
    return null;
  },
});

/**
 * Stage 3 / stage 5: start the rotation for ONE listener AND record `expect`
 * in the same transaction (atomic by construction: a crash between the two is
 * impossible). A start refusal maps to the run's own words: busy / concurrency
 * wait and poll, maintenance asks the operator, anything else fails the stage
 * with the rotation code.
 */
export const startStageRotation = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    stepVersion: v.number(),
    kind: v.union(v.literal('provision'), v.literal('publish')),
    listenerKey: v.string(),
    /** The target's pick (a transport has one address per pick). */
    locationId: v.optional(v.id('edgeLocations')),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.runId, a.stepVersion);
    if (!r || !r.relayId) return { ok: false as const, code: 'stale' };
    const listener = (await listenersOf(ctx, r.relayId)).find(
      (l) => l.listenerKey === a.listenerKey && !l.retired,
    );
    const entry =
      r.listeners.find(
        (l) =>
          l.listenerKey === a.listenerKey &&
          (l.locationId ?? null) === (a.locationId ?? null) &&
          (a.kind === 'publish' ? !l.published : !l.edgeId),
      ) ?? r.listeners.find((l) => l.listenerKey === a.listenerKey);
    if (!listener || !entry) return { ok: false as const, code: 'listener_not_found' };
    const now = Date.now();
    const next = r.stepVersion + 1;
    // An enrolled node's edge reaches members only under the node's approval
    // (docs/servers.md "Node lifecycle"). Checked HERE, in the same
    // transaction as the start: an approval that already landed admits the
    // publish, one that has not parks the run for it (never a failure), and
    // the approval wakes exactly this run.
    if (a.kind === 'publish' && entry.edgeId) {
      const relay = await ctx.db.get(r.relayId);
      const edge = await ctx.db.get(entry.edgeId);
      if (relay && edge) {
        const approval = await publicationApproval(ctx, relay, edge);
        if (approval.kind === 'refused')
          return parkForApproval(ctx, r, approval.code, a.listenerKey);
      }
    }
    try {
      const { rotationId } = await startRotation(ctx, {
        relayId: r.relayId,
        kind: a.kind,
        trigger: 'api',
        listenerId: listener._id,
        ...(a.kind === 'provision'
          ? {
              requestedAccountId: pickOfTarget(r, entry).accountId ?? undefined,
              requestedLocationId:
                entry.locationId ?? pickOfTarget(r, entry).locationId ?? undefined,
              allowUnqualified: true,
              publishOnDone: false,
            }
          : { toEdgeId: entry.edgeId, admission: 'setup.complete' as const }),
        setupRun: { runId: r._id, generation: r.generation },
        actorAdminId: r.actorAdminId,
        reason: `setup:${a.kind}:${a.listenerKey}`,
      });
      await ctx.db.patch(r._id, {
        expect: { rotationId, generation: r.generation },
        state: 'waiting',
        need: undefined,
        stepVersion: next,
        nextStepAt: undefined,
        events: appendRunEvent(r.events, {
          at: now,
          level: 'info',
          code: `${a.kind}_started`,
          detail: `${a.listenerKey} rotation ${rotationId}`,
        }),
        updatedAt: now,
      });
      return { ok: true as const, rotationId };
    } catch (err) {
      const { code, message } = errCode(err);
      if (code === 'edge.busy' || code === 'edge.concurrency') {
        await ctx.db.patch(r._id, {
          state: 'waiting',
          stepVersion: next,
          events: appendRunEvent(r.events, {
            at: now,
            level: 'info',
            code: 'waiting',
            detail: code,
          }),
          updatedAt: now,
        });
        await scheduleStep(ctx, r._id, EDGE_PLUMBING.pollMs);
        return { ok: false as const, code };
      }
      // The node's approval moved between the check above and the start (or a
      // rotation refused for its own approval reasons): park, never fail.
      if (NODE_APPROVAL_CODES.has(code)) return parkForApproval(ctx, r, code, a.listenerKey);
      const need =
        code === 'edge.maintenance'
          ? { code: 'maintenance' }
          : code === 'edge.quarantined'
            ? { code: 'quarantined' }
            : { code: 'provider_failed', detail: code };
      const state =
        code === 'edge.maintenance' || code === 'edge.quarantined' ? 'needs_you' : 'failed';
      await ctx.db.patch(r._id, {
        state,
        need,
        stepVersion: next,
        nextStepAt: undefined,
        ...(state === 'failed' ? { finishedAt: now } : {}),
        events: appendRunEvent(r.events, {
          at: now,
          level: 'error',
          code: `${a.kind}_refused`,
          detail: `${a.listenerKey}: ${code} ${message}`.slice(0, 200),
        }),
        updatedAt: now,
      });
      const after = (await ctx.db.get(r._id))!;
      if (state === 'needs_you')
        await auditRun(ctx, after, 'edge.setup_run.needs_operator', {
          stage: r.stage,
          code: need.code,
        });
      else {
        await auditRun(ctx, after, 'edge.setup_run.finished', {
          outcome: 'failed',
          stage: r.stage,
          code,
          verdicts: verdictsOf(after),
        });
        await onSetupRunEnded(ctx, r, r.generation);
      }
      return { ok: false as const, code };
    }
  },
});

/** Refusals that are the NODE's approval, not the provider's: a setup run parks on them. */
const NODE_APPROVAL_CODES: ReadonlySet<string> = new Set([
  'servers.node_not_approved',
  'servers.maintenance_open',
  'servers.maintenance_required',
  'servers.node_retiring',
  'servers.review_stale',
]);

/**
 * Park a run at publish until the node's approval (`needs_you`
 * `node_not_approved`, the detail is the node's stage): nothing is published,
 * the standbys stay as they are, and `approve` wakes this run.
 */
async function parkForApproval(
  ctx: MutationCtx,
  r: Run,
  code: string,
  listenerKey: string,
): Promise<{ ok: false; code: string }> {
  const now = Date.now();
  const intentOf = () =>
    ctx.db
      .query('panelNodeIntents')
      .withIndex('by_server_name', (q) =>
        q.eq('backendServerId', r.backendServerId).eq('name', r.nodeName),
      )
      .unique();
  // The node's running activation (this run's own) refused the publication:
  // the candidate no longer fits what was approved. It is blocked, so the node
  // parks where a fresh approval can be given, and that approval wakes this run.
  const before = await intentOf();
  const act = before?.activation.currentRunId
    ? await ctx.db.get(before.activation.currentRunId)
    : null;
  if (
    act &&
    act.state === 'running' &&
    act.setupRunId === r._id &&
    code !== 'servers.node_not_approved'
  )
    await blockActivation(ctx, act, code);
  const intent = await intentOf();
  const need = { code: 'node_not_approved', detail: intent?.activation.stage ?? code };
  await ctx.db.patch(r._id, {
    state: 'needs_you',
    need,
    expect: undefined,
    stepVersion: r.stepVersion + 1,
    nextStepAt: undefined,
    events: appendRunEvent(r.events, {
      at: now,
      level: 'info',
      code: 'publish_held',
      detail: `${listenerKey}: ${code}`,
    }),
    updatedAt: now,
  });
  await auditRun(ctx, (await ctx.db.get(r._id))!, 'edge.setup_run.needs_operator', {
    stage: r.stage,
    code: need.code,
  });
  return { ok: false, code };
}

/**
 * The terminal hook `releaseOrigin` schedules for a rotation carrying
 * `setupRun`. Acts ONLY when the run still expects exactly this rotation under
 * exactly this generation and is waiting on it; everything else (a duplicate
 * delivery, a rotation of an older generation, a run that moved on) is a no-op.
 */
export const onRotationTerminal = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    rotationId: v.id('edgeRotations'),
    generation: v.number(),
  },
  handler: async (ctx, { runId, rotationId, generation }) => {
    const r = await ctx.db.get(runId);
    if (!r || isTerminalRunState(r.state)) return { acted: false as const, reason: 'terminal' };
    if (!r.expect || r.expect.rotationId !== rotationId || r.expect.generation !== generation)
      return { acted: false as const, reason: 'not_expected' };
    if (r.state !== 'waiting') return { acted: false as const, reason: 'not_waiting' };
    const rot = await ctx.db.get(rotationId);
    if (!rot || !isTerminalPhase(rot.phase))
      return { acted: false as const, reason: 'not_terminal' };
    const now = Date.now();
    const next = r.stepVersion + 1;
    const key = rot.listenerId ? ((await ctx.db.get(rot.listenerId))?.listenerKey ?? null) : null;
    // A provision fills the target of its listener AND its location (a
    // transport has one address per pick); a publish, the target of its edge.
    const entryIdx =
      rot.kind === 'publish'
        ? r.listeners.findIndex((l) => !!rot.toEdgeId && l.edgeId === rot.toEdgeId)
        : (() => {
            const want = (rot.requestedLocationId as string | undefined) ?? null;
            const exact = r.listeners.findIndex(
              (l) => l.listenerKey === key && !l.edgeId && (l.locationId ?? null) === want,
            );
            return exact >= 0
              ? exact
              : r.listeners.findIndex((l) => l.listenerKey === key && !l.edgeId);
          })();
    const listeners = r.listeners.map((l) => ({ ...l }));
    const base = { expect: undefined, stepVersion: next, updatedAt: now };
    const outcome = rot.outcome ?? rot.phase;
    if (rot.phase === 'done' && rot.kind === 'provision' && rot.toEdgeId && entryIdx >= 0) {
      listeners[entryIdx].edgeId = rot.toEdgeId;
      listeners[entryIdx].verify = 'pending';
      listeners[entryIdx].notChecked = undefined;
      await ctx.db.patch(runId, {
        ...base,
        listeners,
        state: 'running',
        events: appendRunEvent(r.events, {
          at: now,
          level: 'info',
          code: 'provisioned',
          detail: `${key} -> ${rot.toEdgeId}`,
        }),
      });
      await scheduleStep(ctx, runId, 0);
      return { acted: true as const, reason: 'provisioned' };
    }
    if (
      rot.phase === 'done' &&
      rot.kind === 'publish' &&
      entryIdx >= 0 &&
      outcome === 'published'
    ) {
      listeners[entryIdx].published = true;
      await ctx.db.patch(runId, {
        ...base,
        listeners,
        state: 'running',
        events: appendRunEvent(r.events, {
          at: now,
          level: 'info',
          code: 'published',
          detail: key ?? '',
        }),
      });
      await scheduleStep(ctx, runId, 0);
      return { acted: true as const, reason: 'published' };
    }
    // Anything else is an interruption at this stage. A create the provider
    // refused brings its words along (the edge's `failure.detail`, redacted and
    // scrubbed of its names), so the sheet can say why.
    const created = rot.createdEdgeId ? await ctx.db.get(rot.createdEdgeId) : null;
    const providerAnswer = created?.failure?.detail;
    const need =
      rot.phase === 'done' && rot.kind === 'publish'
        ? { code: 'coverage_incomplete', detail: `${key}: ${outcome}` }
        : rot.phase === 'quarantined'
          ? { code: 'quarantined', detail: rot.events.at(-1)?.detail }
          : {
              code: 'provider_failed',
              detail: `${key ?? ''}: ${outcome}`.trim(),
              ...(providerAnswer ? { providerAnswer } : {}),
            };
    const state = need.code === 'provider_failed' ? 'failed' : 'needs_you';
    await ctx.db.patch(runId, {
      ...base,
      state,
      need,
      ...(state === 'failed' ? { finishedAt: now } : {}),
      events: appendRunEvent(r.events, {
        at: now,
        level: 'error',
        code: `rotation_${rot.phase}`,
        detail: withProviderAnswer(
          `${key ?? ''}: ${outcome}`.trim(),
          need.code === 'provider_failed' ? providerAnswer : undefined,
        ),
      }),
    });
    const after = (await ctx.db.get(runId))!;
    if (state === 'needs_you')
      await auditRun(ctx, after, 'edge.setup_run.needs_operator', {
        stage: r.stage,
        code: need.code,
      });
    else {
      await auditRun(ctx, after, 'edge.setup_run.finished', {
        outcome: 'failed',
        stage: r.stage,
        code: outcome,
        verdicts: verdictsOf(after),
      });
      await onSetupRunEnded(ctx, r, generation);
    }
    return { acted: true as const, reason: need.code };
  },
});

// --- the step action ---------------------------------------------------------------------------------

export const step = internalAction({
  args: { runId: v.id('edgeSetupRuns'), stepVersion: v.number() },
  handler: async (ctx, { runId, stepVersion }): Promise<null> => {
    const run = await ctx.runQuery(internal.edgeSetupRuns.get, { id: runId });
    if (!run || run.stepVersion !== stepVersion) return null;
    if (isTerminalRunState(run.state) || run.state === 'needs_you') return null;
    await ctx.runMutation(internal.edgeSetupRuns.markStepStarted, { runId, stepVersion });
    try {
      switch (run.stage) {
        case 'prepare':
          return await stagePrepare(ctx, run);
        case 'credential':
          return await stageCredential(ctx, run);
        case 'provision':
          return await stageProvision(ctx, run);
        case 'verify':
          return await stageVerify(ctx, run);
        case 'try_it':
          return await stageTryIt(ctx, run);
        case 'publish':
          return await stagePublish(ctx, run);
        case 'hide_direct_hosts':
          return await stageHide(ctx, run);
        case 'rehearse':
          return await stageRehearse(ctx, run);
        case 'go_live':
          return await stageGoLive(ctx, run);
        case 'done':
          return null;
      }
    } catch (err) {
      const { code, message } = errCode(err);
      await ctx.runMutation(internal.edgeSetupRuns.transition, {
        runId,
        stepVersion: run.stepVersion,
        state: 'failed',
        need: { code: 'provider_failed', detail: code },
        event: { level: 'error', code: 'step_error', detail: `${code}: ${message}`.slice(0, 200) },
      });
      return null;
    }
    return null;
  },
});

interface TransitionArgs {
  stage?: SetupRunStage;
  state: Run['state'];
  need?: { code: string; detail?: string } | null;
  event?: { level: 'info' | 'warn' | 'error'; code: string; detail?: string };
  listeners?: RunListener[];
  testLinks?: Run['testLinks'] | null;
  reviewDelta?: Array<{ uuid: string; remark: string }>;
  rehearsal?: NonNullable<Run['rehearsal']>;
  relayId?: Id<'relays'>;
  relaySlug?: string;
  scheduleMs?: number;
}

/** Shorthand: the run's own transition mutation. */
async function tr(ctx: ActionCtx, run: Run, a: TransitionArgs): Promise<null> {
  await ctx.runMutation(internal.edgeSetupRuns.transition, {
    runId: run._id,
    stepVersion: run.stepVersion,
    ...a,
  });
  return null;
}

async function advance(ctx: ActionCtx, run: Run, patch: Partial<TransitionArgs> = {}) {
  const stage = nextStage(run.stage);
  if (!stage) return null;
  return tr(ctx, run, {
    stage,
    state: 'running',
    need: null,
    event: { level: 'info', code: 'stage', detail: stage },
    scheduleMs: 0,
    ...patch,
  });
}

async function needsYou(
  ctx: ActionCtx,
  run: Run,
  code: string,
  detail?: string,
  patch: Partial<TransitionArgs> = {},
) {
  return tr(ctx, run, {
    state: 'needs_you',
    need: { code, ...(detail ? { detail } : {}) },
    event: { level: 'warn', code: 'needs_you', detail: `${code}${detail ? `: ${detail}` : ''}` },
    ...patch,
  });
}

async function waitPoll(ctx: ActionCtx, run: Run, cfg: EdgeConfig, detail: string, patch = {}) {
  return tr(ctx, run, {
    state: 'waiting',
    event: { level: 'info', code: 'waiting', detail },
    scheduleMs: EDGE_PLUMBING.pollMs,
    ...patch,
  });
}

// --- stage 1: prepare -----------------------------------------------------------------------------------

async function stagePrepare(ctx: ActionCtx, run: Run): Promise<null> {
  const plan = parsePlan(run);
  const ctxRow = await ctx.runQuery(internal.edgeSetupRuns.prepareContext, { runId: run._id });
  if (!ctxRow.admitted) return needsYou(ctx, run, 'maintenance');
  // Every pick of the run: its account present, tested, enabled, its location
  // switched on, and the plan still offering it.
  for (const p of ctxRow.picks) {
    if (!p.account) return needsYou(ctx, run, 'account_incompatible', 'account_not_found');
    // A front of this account could get no certificate (CAA forbids its CA,
    // its shared wildcard failed): another account, or a fix in the zone.
    if (p.certificateRefusal)
      return needsYou(ctx, run, 'account_incompatible', p.certificateRefusal);
    if (!p.accountTested) return needsYou(ctx, run, 'account_untested');
    if (!p.accountEnabled) return needsYou(ctx, run, 'account_incompatible', 'account_disabled');
    if (!p.location) return needsYou(ctx, run, 'account_incompatible', 'location_not_found');
    const offered = plan.accounts.find((a) => a.id === p.accountId);
    if (!offered?.compatible)
      return needsYou(ctx, run, 'account_incompatible', offered?.reasons[0] ?? 'not_offered');
  }
  if (ctxRow.picks.length === 0)
    return needsYou(ctx, run, 'account_incompatible', 'account_not_found');
  let relayId = run.relayId;
  let relaySlug = run.relaySlug;
  if (!relayId) {
    // An origin a previous run left owned is reused; any other origin on the node refuses.
    if (ctxRow.existingRelay) {
      if (!ctxRow.existingRelay.setupOwned)
        return tr(ctx, run, {
          state: 'failed',
          need: { code: 'provider_failed', detail: 'edge.node_already_bound' },
          event: { level: 'error', code: 'node_already_bound' },
        });
      relayId = ctxRow.existingRelay.id;
      relaySlug = ctxRow.existingRelay.slug;
    } else {
      const specs = plan.inbounds
        .filter((i) => plan.requiredListeners.includes(i.listenerKey))
        .map((i) => i.listenerSpec as ListenerSpecInput);
      // Room for every target (a transport may get one address per pick).
      const desired = Math.min(
        MAX_DESIRED_PUBLISHED,
        Math.max(
          ctxRow.desiredPublishedDefault,
          plan.requiredListeners.length,
          run.listeners.length,
        ),
      );
      let slug = plan.relaySlug;
      let created: { id: Id<'relays'> } | null = null;
      for (let attempt = 0; attempt < 3 && !created; attempt++) {
        try {
          created = await ctx.runMutation(internal.relays.create, {
            slug,
            origin: {
              kind: 'panel-node',
              backendServerId: run.backendServerId,
              nodeName: run.nodeName,
              nodeUuid: run.nodeUuid,
            },
            originAddress: plan.originAddress,
            listeners: specs as never,
            autoRotate: true,
            desiredPublished: desired,
            deferBinding: true,
            setupOwned: true,
            actorAdminId: run.actorAdminId,
          });
        } catch (err) {
          const { code } = errCode(err);
          if (code === 'conflict') {
            slug = `${plan.relaySlug}-${attempt + 2}`;
            continue;
          }
          if (code === 'edge.maintenance') return needsYou(ctx, run, 'maintenance');
          return tr(ctx, run, {
            state: 'failed',
            need: { code: 'provider_failed', detail: code },
            event: { level: 'error', code: 'relay_create_failed', detail: code },
          });
        }
      }
      if (!created)
        return tr(ctx, run, {
          state: 'failed',
          need: { code: 'provider_failed', detail: 'conflict' },
          event: { level: 'error', code: 'relay_create_failed', detail: 'slug conflict' },
        });
      relayId = created.id;
      relaySlug = slug;
    }
  }
  // Each target's layer is its pick's provider's.
  const layerOf = (locationId: Id<'edgeLocations'> | undefined) => {
    const p = ctxRow.picks.find((x) => x.locationId === (locationId ?? null)) ?? ctxRow.picks[0]!;
    return edgeLayerOf(p.account!.provider);
  };
  return advance(ctx, run, {
    relayId,
    relaySlug,
    listeners: run.listeners.map((l) => ({ ...l, layer: layerOf(l.locationId) })),
    event: { level: 'info', code: 'prepared', detail: relaySlug },
  });
}

export const prepareContext = internalQuery({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const run = (await ctx.db.get(runId))!;
    const picks = [];
    for (const pick of runPicks(run)) {
      const account = pick.accountId ? await ctx.db.get(pick.accountId) : null;
      const location = account ? await pickLocationOf(ctx.db, account, pick.locationId) : null;
      picks.push({
        accountId: (pick.accountId as string | null) ?? null,
        locationId: (location?._id as Id<'edgeLocations'> | undefined) ?? pick.locationId ?? null,
        account: account ? { provider: account.provider, name: account.name } : null,
        location: location && location.enabled ? { id: location._id, label: location.label } : null,
        accountTested: !!account && accountTested(account),
        // With the pick's own certificate (a pick from before options: the
        // account's defaults, live).
        certificateRefusal: account
          ? certificateRefusalFor(
              account,
              location,
              pick.options !== undefined ? parseOptionValues(pick.options) : null,
            )
          : null,
        accountEnabled: !!account && account.enabled,
      });
    }
    const cfg = await resolveEdgeConfig(ctx.db);
    const existing = run.relayId
      ? await ctx.db.get(run.relayId)
      : await relayForBackendNode(ctx.db, run.backendServerId, run.nodeName);
    return {
      admitted: await admitted(ctx.db),
      picks,
      desiredPublishedDefault: cfg.desiredPublishedDefault,
      existingRelay: existing
        ? {
            id: existing._id,
            slug: existing.slug,
            setupOwned: existing.setupOwned === true && !existing.deleting,
          }
        : null,
    };
  },
});

// --- stage 2: credential --------------------------------------------------------------------------------

async function stageCredential(ctx: ActionCtx, run: Run): Promise<null> {
  const plan = parsePlan(run);
  const anyL7 = run.listeners.some((l) => l.layer === 'l7');
  if (plan.emptyNode && plan.backend === 'outline')
    return needsYou(ctx, run, 'use_manual_setup', 'outline_empty');
  const needed = anyL7 || (plan.emptyNode && plan.backend !== 'outline');
  if (needed && run.relayId) {
    const res = await ops.ensureCredential(ctx, {
      relayId: run.relayId,
      purpose: anyL7 ? 'qualification' : 'rehearsal',
    });
    if (!res.ok) return needsYou(ctx, run, 'choose_mode', res.code ?? 'credential');
  }
  return advance(ctx, run);
}

// --- stage 3: provision ---------------------------------------------------------------------------------

async function stageProvision(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await ctx.runQuery(internal.edgeSetupRuns.relayContext, { runId: run._id });
  if (!c)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  if (c.relay.activeRotationId) {
    const active = await ctx.runQuery(internal.edgeRotations.get, { id: c.relay.activeRotationId });
    if (active && !isTerminalPhase(active.phase))
      return waitPoll(ctx, run, c.cfg, 'rotation running');
  }
  // Reuse what exists: a live unpublished edge on the listener (an earlier
  // generation's standby, a spare) counts; a failed / destroyed one does not.
  // A re-protect reuses only its OWN candidate: the committed edges members
  // hold and any spare stay what they are, and every candidate is a fresh
  // address with a fresh test link (after a REALITY key change, a retest of a
  // committed address could not be proven by a named connection).
  const reprotect = run.kind === 'reprotect';
  // Each target reuses at most one edge, and no edge serves two targets.
  const taken = new Set(
    run.listeners
      .filter(
        (l) => l.edgeId && c.edges.some((e) => e._id === l.edgeId && LIVE_CANDIDATE.has(e.status)),
      )
      .map((l) => l.edgeId as string),
  );
  const listeners = run.listeners.map((l) => {
    const row = c.listeners.find((x) => x.listenerKey === l.listenerKey);
    const own = l.edgeId ? c.edges.find((e) => e._id === l.edgeId) : undefined;
    if (own && LIVE_CANDIDATE.has(own.status)) return { ...l };
    const pick = pickOfTarget(run, l);
    const reuse =
      row && !reprotect
        ? c.edges.find(
            (e) =>
              !taken.has(e._id as string) &&
              e.listenerId === row._id &&
              LIVE_CANDIDATE.has(e.status) &&
              (e.publication === 'unpublished' || e.publication === 'published') &&
              e.accountId === pick.accountId &&
              // The same place: an address in another location of the account is not this pick's.
              (!(l.locationId ?? pick.locationId) ||
                (e.locationId ?? null) === (l.locationId ?? pick.locationId)) &&
              // Built with what the pick asks for (its options).
              c.fitsPick.includes(e._id as string),
          )
        : undefined;
    if (reuse) taken.add(reuse._id as string);
    return { ...l, edgeId: reuse?._id, verify: 'pending' as const, notChecked: undefined };
  });
  const missing = listeners.find((l) => !l.edgeId);
  if (!missing) return advance(ctx, run, { listeners });
  // Persist the reuse first (fenced), then start ONE rotation for the first missing listener.
  await ctx.runMutation(internal.edgeSetupRuns.transition, {
    runId: run._id,
    stepVersion: run.stepVersion,
    state: 'running',
    listeners,
    event: { level: 'info', code: 'provision', detail: missing.listenerKey },
  });
  const fresh = await ctx.runQuery(internal.edgeSetupRuns.get, { id: run._id });
  if (!fresh) return null;
  await ctx.runMutation(internal.edgeSetupRuns.startStageRotation, {
    runId: run._id,
    stepVersion: fresh.stepVersion,
    kind: 'provision',
    listenerKey: missing.listenerKey,
    ...(missing.locationId ? { locationId: missing.locationId } : {}),
  });
  return null;
}

// --- stage 4: verify -------------------------------------------------------------------------------------

async function stageVerify(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await ctx.runQuery(internal.edgeSetupRuns.relayContext, { runId: run._id });
  if (!c)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  const now = Date.now();
  const listeners = run.listeners.map((l) => ({ ...l }));
  let waiting: string | null = null;
  for (const l of listeners) {
    if (l.verify !== 'pending') continue;
    if (!l.edgeId) return tr(ctx, run, { stage: 'provision', state: 'running', scheduleMs: 0 });
    if (l.layer === 'l7') {
      if (vOf(c, l)?.proofOk) {
        l.verify = 'verified';
        continue;
      }
      const proof = await ops.runFrontProof(ctx, l.edgeId);
      l.proofRequestedAt = now;
      if (proof.ok) {
        l.verify = 'verified';
        continue;
      }
      if (proof.code === 'no_qualification_credential' || proof.code === 'placement')
        return needsYou(ctx, run, 'choose_mode', proof.code, { listeners });
      // The proof could not run: the front itself may be fine.
      if (proof.code === 'test_account_used_up')
        return needsYou(ctx, run, 'test_account_used_up', undefined, { listeners });
      l.verify = 'unreachable';
      return needsYou(
        ctx,
        run,
        'address_unreachable',
        `${l.listenerKey}:${proof.code ?? 'front_failed'}`,
        {
          listeners,
        },
      );
    }
    // A fresh check ("Check again", a re-apply) starts once the earlier
    // check's runs have all landed: a verdict one of them brought in after
    // `recheckSince` would count as fresh. It counts from its own request.
    if (l.recheckSince !== undefined && !l.probeRequestedAt) {
      if (await ctx.runQuery(internal.edgeSetupRuns.probesInFlight, { edgeId: l.edgeId })) {
        waiting = waiting ?? l.listenerKey;
        continue;
      }
      l.recheckSince = now;
    }
    // Per-country checks (edgeCountry.ts): this stage asks for the address's
    // round from every checked country ITSELF, before the rung is looked at:
    // evidence already on record (a reused spare, background probes) may make
    // the rung `partial`, and that must not skip the country check. The round
    // is waited for (at most `edge.country.preUseWaitMinutes`; unknown never
    // holds the run), and one that finds the address blocked somewhere while
    // the controls reach it asks before going live: try another address, or
    // use this one anyway.
    const pu = await ctx.runQuery(internal.edgeCountry.preUse, {
      edgeId: l.edgeId,
      since: (l.probeRequestedAt ?? now) - 1000,
    });
    if (pu.enabled) {
      if (!l.probeRequestedAt) {
        await ops.requestVerificationProbes(ctx, l.edgeId);
        l.probeRequestedAt = now;
        waiting = waiting ?? l.listenerKey;
        continue;
      }
      const clock = pu.requestedAt ?? l.probeRequestedAt;
      if (pu.state !== 'settled' && now - clock < pu.waitMs) {
        waiting = waiting ?? l.listenerKey;
        continue;
      }
      if (pu.blockedIn.length > 0) {
        l.verify = 'unreachable';
        return needsYou(ctx, run, 'blocked_in', `${l.listenerKey}:${pu.blockedIn.join(',')}`, {
          listeners,
        });
      }
    }
    // Per address family (lib/edges/verifyRung.ts `outsideCheckFor`): only a
    // real refusal is `unreachable`; a family no source could test passes as
    // not checked, and the operator's own test link still comes first.
    const overdue =
      l.probeRequestedAt !== undefined && now - l.probeRequestedAt > VERIFY_TIMEOUT_MS;
    const check = await ctx.runQuery(internal.edgeSetupRuns.outsideCheck, {
      edgeId: l.edgeId,
      ...(l.recheckSince !== undefined ? { since: l.recheckSince } : {}),
      ...(l.probeRequestedAt !== undefined ? { roundSince: l.probeRequestedAt } : {}),
      final: overdue,
    });
    if (check.verdict === 'passed') {
      l.verify = 'partial';
      l.notChecked = check.notChecked.length > 0 ? check.notChecked : undefined;
      continue;
    }
    if (check.verdict === 'blocked_in') {
      // Born blocked in a listed country while it works from elsewhere: asked
      // like a country round's block, with no re-apply (saving the same
      // configuration again never unblocks an address in a country).
      l.verify = 'unreachable';
      return needsYou(ctx, run, 'blocked_in', `${l.listenerKey}:${check.blockedIn.join(',')}`, {
        listeners,
      });
    }
    if (check.verdict === 'unreachable') {
      // Once per address, before the run asks: its configuration saved again
      // (a provider can accept a change and never apply it), then a fresh check.
      if (l.reappliedEdgeId !== l.edgeId) {
        const event = await reapplyOnce(ctx, l, now);
        if (event)
          return tr(ctx, run, {
            state: 'waiting',
            event,
            listeners,
            scheduleMs: EDGE_PLUMBING.pollMs,
          });
      }
      l.verify = 'unreachable';
      return needsYou(ctx, run, 'address_unreachable', l.listenerKey, { listeners });
    }
    if (!l.probeRequestedAt) {
      await ops.requestVerificationProbes(ctx, l.edgeId);
      l.probeRequestedAt = now;
    } else if (overdue) {
      // Past the wait nothing in flight holds the check: only the provider's
      // own health does (or an address with no family to probe).
      l.verify = 'unreachable';
      return needsYou(
        ctx,
        run,
        'address_unreachable',
        `${l.listenerKey}:${check.providerHealthy ? 'timeout' : 'provider_health'}`,
        { listeners },
      );
    }
    waiting = waiting ?? l.listenerKey;
  }
  if (waiting) return waitPoll(ctx, run, c.cfg, `probes ${waiting}`, { listeners });
  return advance(ctx, run, { listeners });
}

/**
 * The one retry an unreachable new address gets before stage 4 asks
 * (`EdgeProvider.reapply`): its configuration saved again, unchanged, then a
 * fresh outside check that counts only evidence from now on. Marks the entry
 * (`reappliedEdgeId`) whatever happens, so it is never tried twice. Returns the
 * run event to log, or null when nothing could change and the run asks now
 * (no such step at the provider, nothing to save, a load balancer that will
 * not apply anything).
 */
async function reapplyOnce(
  ctx: ActionCtx,
  l: RunListener,
  now: number,
): Promise<{ level: 'info'; code: 'reapplied'; detail: string } | null> {
  if (!l.edgeId) return null;
  l.reappliedEdgeId = l.edgeId;
  let note: string;
  try {
    const res = await ops.reapplyEdge(ctx, l.edgeId);
    // Still applying an earlier change: nothing was sent, but a fresh check is
    // worth its once as much as after a save.
    if (res.status === 'skipped' && res.code !== 'lb_busy') return null;
    note = res.status === 'sent' ? (res.settled ? '' : 'still applying') : res.code;
  } catch (err) {
    // Whether it went out is unknown: the fresh check tells.
    note = errCode(err).code;
  }
  l.probeRequestedAt = undefined;
  l.recheckSince = now;
  return {
    level: 'info',
    code: 'reapplied',
    detail: note ? `${l.listenerKey}: ${note}` : l.listenerKey,
  };
}

// --- stage 4b: try it -----------------------------------------------------------------------------------

/** Build the `try_it` card: one test link per L4 endpoint that lacks a CURRENT confirmation. */
async function pendingTestLinks(
  ctx: ActionCtx,
  run: Run,
  c: NonNullable<Awaited<ReturnType<typeof relayContextOf>>>,
): Promise<NonNullable<Run['testLinks']>> {
  const links: NonNullable<Run['testLinks']> = [];
  for (const l of run.listeners) {
    if (l.layer !== 'l4' || !l.edgeId) continue;
    if (vOf(c, l)?.current) continue;
    const edge = c.edges.find((e) => e._id === l.edgeId);
    if (!edge) continue;
    if (edge.publication === 'published') {
      // An already-published address is retested by its named connection.
      const b = await ctx.runQuery(internal.edgeVerification.binding, { edgeId: l.edgeId });
      if (!b) continue;
      links.push({
        edgeId: l.edgeId,
        listenerKey: l.listenerKey,
        link: '',
        format: 'named_connection',
        method: 'named_connection',
        binding: {
          endpoint: b.endpoint,
          listenerRevision: b.listenerRevision,
          configHash: b.configHash,
          issuedAt: Date.now(),
        },
      });
      continue;
    }
    const t = await ops.buildTestLink(ctx, l.edgeId);
    links.push({
      edgeId: l.edgeId,
      listenerKey: l.listenerKey,
      link: t.link,
      format: t.format,
      method: 'test_link',
      binding: {
        endpoint: t.binding.endpoint,
        listenerRevision: t.binding.listenerRevision,
        configHash: t.binding.configHash,
        issuedAt: Date.parse(t.binding.issuedAt),
      },
    });
  }
  return links;
}

async function relayContextOf(ctx: ActionCtx, run: Run) {
  return ctx.runQuery(internal.edgeSetupRuns.relayContext, { runId: run._id });
}

/**
 * The test links come from the origin's test account, which is reset first
 * when it is used up (edgeTestCredentials.ensure -> relayQualification.keepUsable).
 * A reset that failed is the card's reason (`test_account_used_up`, retried by
 * "Try again"), never a link that cannot connect and never a failed run.
 */
function testAccountUsedUp(err: unknown): boolean {
  return errCode(err).code === 'edge.test_account_used_up';
}

async function stageTryIt(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await relayContextOf(ctx, run);
  if (!c)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  let links: NonNullable<Run['testLinks']>;
  try {
    links = await pendingTestLinks(ctx, run, c);
  } catch (err) {
    if (testAccountUsedUp(err)) return needsYou(ctx, run, 'test_account_used_up');
    throw err;
  }
  if (links.length === 0) {
    const listeners = run.listeners.map((l) =>
      l.layer === 'l4' && vOf(c, l)?.current ? { ...l, verify: 'verified' as const } : l,
    );
    return advance(ctx, run, { listeners, testLinks: null });
  }
  return needsYou(ctx, run, 'try_it', tryItDetail(run, c, links.length), { testLinks: links });
}

/**
 * The `try_it` card's detail: `reality_key_changed` when every address to try
 * again was ticked before and only the node's REALITY key moved since (the
 * card says so in words), else the count.
 */
function tryItDetail(
  run: Run,
  c: { verification: Record<string, { current: boolean; keyChanged: boolean }> },
  count: number,
): string {
  const pending = run.listeners.filter((l) => l.layer === 'l4' && !vOf(c, l)?.current);
  return pending.length > 0 && pending.every((l) => vOf(c, l)?.keyChanged)
    ? 'reality_key_changed'
    : `${count} endpoint(s)`;
}

// --- stage 5: publish -----------------------------------------------------------------------------------

async function stagePublish(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await relayContextOf(ctx, run);
  if (!c)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  if (c.relay.quarantine) return needsYou(ctx, run, 'quarantined', c.relay.quarantine.reason);
  if (c.relay.activeRotationId) {
    const active = await ctx.runQuery(internal.edgeRotations.get, { id: c.relay.activeRotationId });
    if (active && !isTerminalPhase(active.phase))
      return waitPoll(ctx, run, c.cfg, 'rotation running');
  }
  const listeners = run.listeners.map((l) => ({
    ...l,
    published: vOf(c, l)?.published === true,
  }));
  const target = listeners.find((l) => !l.published);
  if (!target) {
    // An enrolled fronted node has no direct address to keep (refused at create and resume).
    if (run.keepDirect && !c.frontedEnrolled)
      return tr(ctx, run, {
        stage: 'done',
        state: 'done_unbound',
        listeners,
        event: {
          level: 'info',
          code: 'done_unbound',
          detail: 'kept members on the direct address',
        },
      });
    return advance(ctx, run, { listeners });
  }
  if (!target.edgeId)
    return tr(ctx, run, { stage: 'provision', state: 'running', listeners, scheduleMs: 0 });
  if (target.layer === 'l4' && !vOf(c, target)?.current) {
    // The gate would refuse it: back to the card rather than a doomed start.
    return tr(ctx, run, { stage: 'try_it', state: 'running', listeners, scheduleMs: 0 });
  }
  await ctx.runMutation(internal.edgeSetupRuns.transition, {
    runId: run._id,
    stepVersion: run.stepVersion,
    state: 'running',
    listeners,
    event: { level: 'info', code: 'publish', detail: target.listenerKey },
  });
  const fresh = await ctx.runQuery(internal.edgeSetupRuns.get, { id: run._id });
  if (!fresh) return null;
  await ctx.runMutation(internal.edgeSetupRuns.startStageRotation, {
    runId: run._id,
    stepVersion: fresh.stepVersion,
    kind: 'publish',
    listenerKey: target.listenerKey,
    ...(target.locationId ? { locationId: target.locationId } : {}),
  });
  return null;
}

// --- stage 6: hide the direct Hosts ----------------------------------------------------------------

async function stageHide(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await relayContextOf(ctx, run);
  if (!c || !run.relayId)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  // Before any Host is hidden: every L4 endpoint must still be confirmed for
  // the configuration it holds now (a listener change since the tick returns
  // it to the card).
  const stale = run.listeners.filter((l) => l.layer === 'l4' && !vOf(c, l)?.current);
  if (stale.length > 0) {
    let links: NonNullable<Run['testLinks']>;
    try {
      links = await pendingTestLinks(ctx, run, c);
    } catch (err) {
      if (testAccountUsedUp(err)) return needsYou(ctx, run, 'test_account_used_up');
      throw err;
    }
    const detail = stale.every((l) => vOf(c, l)?.keyChanged)
      ? 'reality_key_changed'
      : `retest ${stale.map((l) => l.listenerKey).join(',')}`;
    return needsYou(ctx, run, 'try_it', detail, { testLinks: links });
  }
  const res = await ops.hideHosts(ctx, {
    relayId: run.relayId,
    runId: run._id,
    approvedUuids: run.approvedHideUuids,
  });
  if (res.reviewChanged.length > 0)
    return needsYou(ctx, run, 'review_changed', `${res.reviewChanged.length} host(s)`, {
      reviewDelta: res.reviewChanged.map((h) => ({ uuid: h.uuid, remark: h.remark })),
    });
  if (res.failed > 0) return needsYou(ctx, run, 'hide_failed', `${res.failed} host(s)`);
  if (res.pending > 0 || res.state === 'pending') {
    // A row the reconcile pass gave up on (retry cap, or a Host repointed under
    // the write) still reads as pending here; the ledger's own status knows.
    const status = await ops.hideStatus(ctx as unknown as QueryRunner, run.relayId);
    if (status.failed > 0) return needsYou(ctx, run, 'hide_failed', `${status.failed} host(s)`);
    return waitPoll(ctx, run, c.cfg, `hides pending ${res.pending}`);
  }
  return advance(ctx, run, {
    event: { level: 'info', code: 'hosts_hidden', detail: `${res.hidden} host(s)` },
  });
}

// --- stage 7: rehearse -------------------------------------------------------------------------------

async function stageRehearse(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await relayContextOf(ctx, run);
  if (!c || !run.relayId)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  const disabled = RENDER_CLIENT_FAMILIES.filter((f) => !c.cfg.render.clients[f].enabled);
  if (disabled.length > 0) return needsYou(ctx, run, 'family_disabled', disabled[0]);
  const attempts = (run.rehearsal?.attempts ?? 0) + 1;
  // An enrolled node's activation records what members will get after the
  // commit (the delivery snapshot); the rehearsal renders exactly that.
  if (run.activationRunId)
    await ctx.runMutation(internal.edgeSetupRuns.recordDeliverySnapshot, { runId: run._id });
  // An enrolled node rehearses ITS activation's candidates (the edges the
  // commit will promote), never the committed edges members hold now.
  const res = await ops.rehearse(ctx, {
    relayId: run.relayId,
    darkCohortKeys: run.rehearsal?.darkCohortKeys ?? [],
    ...(run.activationRunId ? { activationRunId: run.activationRunId } : {}),
  });
  if (res.familiesDisabled.length > 0)
    return needsYou(ctx, run, 'family_disabled', res.familiesDisabled[0]);
  // The activation this run was approved for is no longer the node's running
  // one (superseded, blocked): nothing can be proven until the next approval,
  // which wakes the run here.
  if (res.failures.some((f) => f.reason === 'activation_superseded'))
    return needsYou(ctx, run, 'node_not_approved', 'servers.run_superseded');
  if (res.proofsExpired.length > 0) {
    // Re-run the expired proofs, then rehearse again (bounded).
    for (const edgeId of res.proofsExpired) await ops.runFrontProof(ctx, edgeId as Id<'edges'>);
    if (attempts >= MAX_REHEARSAL_ATTEMPTS)
      return needsYou(ctx, run, 'rehearsal_failed', 'proof_expired');
    return tr(ctx, run, {
      state: 'running',
      rehearsal: rehearsalRecord(res, attempts, run),
      event: { level: 'warn', code: 'proof_rerun', detail: `${res.proofsExpired.length}` },
      scheduleMs: 0,
    });
  }
  if (!res.ok) {
    // An APPROVED dark cohort: the operator consented to hiding the Hosts of an
    // unsupported-only transport set, so a member group whose whole body went
    // with them now receives nothing FCP can serve. That cohort is excluded
    // from the `serve` requirement (plan 1.6) instead of blocking go-live for
    // everyone else; it is derived from the bodies themselves, after the
    // hides, never guessed from mode group membership. Any other failure stays a
    // failure.
    const dark = approvedDarkCohorts(res, run);
    if (dark.length > 0 && attempts < MAX_REHEARSAL_ATTEMPTS)
      return tr(ctx, run, {
        state: 'running',
        rehearsal: {
          ...rehearsalRecord(res, attempts, run),
          darkCohortKeys: [...(run.rehearsal?.darkCohortKeys ?? []), ...dark],
        },
        event: { level: 'warn', code: 'dark_cohorts', detail: dark.join(',') },
        scheduleMs: 0,
      });
    // Every failure is a body whose backup sits in its primary's failure
    // domain although another is on offer: the run parks for the operator
    // (more addresses of its own would not change the assignment; it never
    // loops through provisioning).
    if (res.failures.length > 0 && res.failures.every((f) => f.reason === 'resilience_short')) {
      const f = res.failures[0]!;
      return needsYou(ctx, run, 'resilience_short', `${f.cohortKey}/${f.format}`, {
        rehearsal: rehearsalRecord(res, attempts, run),
      });
    }
    const f = res.failures[0];
    return needsYou(
      ctx,
      run,
      'rehearsal_failed',
      f ? `${f.cohortKey}/${f.format}: ${f.reason}` : 'no_serve',
      {
        rehearsal: rehearsalRecord(res, attempts, run),
      },
    );
  }
  // Bodies with no backup in another failure domain are reported, with why.
  const reduced = [...new Set((res.reduced ?? []).map((r) => r.reason))];
  return advance(ctx, run, {
    rehearsal: rehearsalRecord(res, attempts, run),
    event: {
      level: 'info',
      code: 'rehearsed',
      detail: `attempt ${attempts}${reduced.length > 0 ? `; reduced: ${reduced.join(',')}` : ''}`,
    },
  });
}

/** Stages at which the run may still switch provider accounts (nothing published yet). */
const SWITCHABLE_STAGES = new Set<SetupRunStage>([
  'prepare',
  'credential',
  'provision',
  'verify',
  'try_it',
]);
const STAGE_INDEX = Object.fromEntries(SETUP_RUN_STAGES.map((s, i) => [s, i])) as Record<
  SetupRunStage,
  number
>;

/**
 * A reused (still setup-owned) origin must carry exactly the listeners the new
 * plan discovered, at the same configuration: the required keys must exist,
 * non-retired, with the canonical hash of the plan's spec, and the origin must
 * hold no extra deployed listener the plan no longer lists. Otherwise
 * `edge.plan_changed`: the operator removes protection and starts again.
 */
async function assertPlanMatchesRelay(
  ctx: { db: QueryCtx['db'] },
  relay: Relay,
  plan: SetupPlanSnapshot,
): Promise<void> {
  const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired);
  const byKey = new Map(listeners.map((l) => [l.listenerKey, l]));
  const origin = relay.origin;
  const changed: string[] = [];
  for (const key of plan.requiredListeners) {
    const inbound = plan.inbounds.find((i) => i.listenerKey === key);
    const existing = byKey.get(key);
    if (!inbound || !existing) {
      changed.push(key);
      continue;
    }
    let hash: string;
    try {
      hash = listenerConfigHash(
        validateListenerSpec(inbound.listenerSpec as ListenerSpecInput, { origin }),
      );
    } catch {
      changed.push(key);
      continue;
    }
    if (hash !== existing.configHash) changed.push(key);
  }
  for (const l of listeners) {
    if (l.deployed && l.enabled && !plan.requiredListeners.includes(l.listenerKey))
      changed.push(l.listenerKey);
  }
  if (changed.length > 0)
    throw new ConvexError({
      code: 'edge.plan_changed',
      message: `The node's transports changed since this origin was set up (${[...new Set(changed)].join(', ')}); remove protection and start again`,
    });
}

/** Body outcomes that mean "nothing is left to serve", the signature of a hidden-out cohort. */
const DARK_BODY_REASONS = new Set(['empty_body', 'no_match', 'empty_pool']);

/**
 * Cohorts whose EVERY failure says their body is empty of anything FCP can
 * serve, on a run whose operator approved hiding uncovered Hosts. Exported for
 * the unit test; pure.
 */
export function approvedDarkCohorts(
  res: Pick<RehearsalResult, 'failures' | 'formats'>,
  run: Pick<Run, 'approvedHideUuids' | 'rehearsal'>,
): string[] {
  if (run.approvedHideUuids.length === 0 || res.formats.length === 0) return [];
  const already = new Set(run.rehearsal?.darkCohortKeys ?? []);
  const byCohort = new Map<string, { allDark: boolean; formats: Set<string> }>();
  for (const f of res.failures) {
    if (f.cohortKey === 'credential') return [];
    const cur = byCohort.get(f.cohortKey) ?? { allDark: true, formats: new Set<string>() };
    cur.allDark = cur.allDark && DARK_BODY_REASONS.has(f.reason);
    cur.formats.add(f.format);
    byCohort.set(f.cohortKey, cur);
  }
  // Dark = EVERY rehearsed format of the cohort failed for a dark reason. A
  // cohort whose links body is empty while its sing-box body still renders is
  // a real failure, not a dark cohort.
  const wanted = new Set(res.formats);
  const dark = [...byCohort.entries()]
    .filter(
      ([k, v]) => v.allDark && !already.has(k) && [...wanted].every((fmt) => v.formats.has(fmt)),
    )
    .map(([k]) => k);
  // Only when EVERY failing cohort is dark: a genuine failure elsewhere still stops the run.
  return dark.length === byCohort.size ? dark : [];
}

function rehearsalRecord(
  res: RehearsalResult,
  attempts: number,
  run: Run,
): NonNullable<Run['rehearsal']> {
  return {
    at: res.hostsObservation.observedAt,
    attempts,
    vector: res.vector,
    hostsObservation: {
      at: res.hostsObservation.observedAt,
      version: res.hostsObservation.version,
      hash: res.hostsObservation.listingHash,
    },
    darkCohortKeys: run.rehearsal?.darkCohortKeys ?? [],
  };
}

/**
 * The reviewed delivery snapshot of the activation this run is bound to: the
 * addresses members are served now that go-live keeps (every one for an
 * `add`; for a first protection or a `replace_all`, those on transports the
 * run does not touch, since go-live retires the others) plus the run's
 * candidates. Promotion
 * commits exactly it (`promoteCandidate`); the rehearsal renders it. A run not
 * bound to the node's current, running activation records nothing.
 */
export const recordDeliverySnapshot = internalMutation({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const r = await ctx.db.get(runId);
    if (!r?.activationRunId || !r.relayId) return null;
    const act = await ctx.db.get(r.activationRunId);
    if (!act || act.state !== 'running' || act.setupRunId !== r._id) return null;
    const intent = await ctx.db.get(act.intentId);
    if (!intent || intent.activation.currentRunId !== act._id) return null;
    const candidates = r.listeners
      .map((l) => l.edgeId as string | undefined)
      .filter((e): e is string => !!e);
    const add = parsePlan(r).reprotect?.mode === 'add';
    const touched = new Set(
      (await listenersOf(ctx, r.relayId))
        .filter((l) => r.listeners.some((x) => x.listenerKey === l.listenerKey))
        .map((l) => l._id as string),
    );
    // What members are served now: the origin's published, active edges that
    // no activation holds back (an address published since the last commit
    // under its approval counts too).
    const relay = await ctx.db.get(r.relayId);
    const gate = await nodeGateFor(ctx, r.backendServerId, r.nodeName);
    const kept: string[] = [];
    for (const id of relay?.publishedEdgeIds ?? []) {
      if (!id || candidates.includes(id as string) || isCandidateEdge(gate, id as string)) continue;
      const e = await ctx.db.get(id);
      if (!e || e.publication !== 'published' || e.status !== 'active') continue;
      if (!add && touched.has(e.listenerId as string)) continue;
      kept.push(id as string);
    }
    await ctx.db.patch(act._id, {
      delivery: { edgeIds: [...kept, ...candidates] },
      updatedAt: Date.now(),
    });
    return null;
  },
});

// --- stage 8: go live -------------------------------------------------------------------------------------

async function stageGoLive(ctx: ActionCtx, run: Run): Promise<null> {
  const res = await ctx.runMutation(internal.edgeSetupRuns.goLive, {
    runId: run._id,
    stepVersion: run.stepVersion,
  });
  if (res.ok || res.code === 'stale') return null;
  // The mutation already moved the run (back to 7 / 6, or to the card).
  return null;
}

/**
 * ONE mutation: every check stage 7 rehearsed, re-derived from the live rows,
 * then the binding. A failed check sends the run back (rehearse / hides / the
 * try_it card) instead of binding on stale evidence.
 */
export const goLive = internalMutation({
  args: { runId: v.id('edgeSetupRuns'), stepVersion: v.number() },
  handler: async (ctx, { runId, stepVersion }) => {
    const r = await guard(ctx, runId, stepVersion);
    if (!r || !r.relayId) return { ok: false as const, code: 'stale' };
    const now = Date.now();
    const next = r.stepVersion + 1;
    const back = async (stage: SetupRunStage, code: string, detail?: string) => {
      await ctx.db.patch(runId, {
        stage,
        state: 'running',
        stepVersion: next,
        stageEnteredAt: now,
        events: appendRunEvent(r.events, { at: now, level: 'warn', code, detail }),
        updatedAt: now,
      });
      const relay = await ctx.db.get(r.relayId!);
      if (relay?.setupOwned) await ctx.db.patch(relay._id, { setupStage: stage, updatedAt: now });
      await scheduleStep(ctx, runId, 0);
      return { ok: false as const, code };
    };
    const need = async (code: string, detail?: string) => {
      await ctx.db.patch(runId, {
        state: 'needs_you',
        need: { code, detail },
        stepVersion: next,
        nextStepAt: undefined,
        events: appendRunEvent(r.events, {
          at: now,
          level: 'warn',
          code: 'needs_you',
          detail: `${code}: ${detail ?? ''}`,
        }),
        updatedAt: now,
      });
      await auditRun(ctx, (await ctx.db.get(runId))!, 'edge.setup_run.needs_operator', {
        stage: 'go_live',
        code,
      });
      return { ok: false as const, code };
    };
    const relay = await ctx.db.get(r.relayId);
    if (!relay || relay.deleting) return need('provider_failed', 'relay_missing');
    if (!relay.enabled) return need('provider_failed', 'relay_disabled');
    if (relay.quarantine) return need('quarantined', relay.quarantine.reason);
    // A restore workflow (a cancel, a delete) is taking the origin back to
    // direct delivery: binding it now would serve members what it removes.
    if (relay.restore) return need('provider_failed', 'restore_in_progress');
    if (relay.activeRotationId) {
      const rot = await ctx.db.get(relay.activeRotationId);
      if (rot && !isTerminalPhase(rot.phase)) return back('rehearse', 'rotation_running');
    }
    if (!r.rehearsal) return back('rehearse', 'no_rehearsal');
    // The Host observation is the FINAL listing of stage 7: younger than 60 s.
    if (r.rehearsal.hostsObservation.at < now - MAX_OBSERVATION_AGE_MS)
      return back('rehearse', 'observation_stale');
    // The local version vector must be the one stage 7 rehearsed.
    const nowVector = await ops.vectorNow(ctx as unknown as QueryRunner, relay._id);
    if (!vectorsEqual(nowVector, r.rehearsal.vector)) return back('rehearse', 'vector_drift');
    // No FCP Host operation claimed on the origin; every required listener
    // published by its own edge; L7 proofs current; L4 confirmations current
    // (bound to the enrolled node's auth revision too).
    const listeners = (
      await verificationListenersOf(ctx.db, relay, await listenersOf(ctx, relay._id))
    ).filter((l) => !l.retired);
    if (listeners.some((l) => l.host?.op)) return back('rehearse', 'host_op_claimed');
    for (const entry of r.listeners) {
      const l = listeners.find((x) => x.listenerKey === entry.listenerKey);
      const e = entry.edgeId ? await ctx.db.get(entry.edgeId) : null;
      if (!l || !e || !l.templateEdgeId || e.publication !== 'published')
        return back('publish', 'not_published', entry.listenerKey);
      if (entry.layer === 'l7') {
        if (!e.frontQualification?.ok || e.frontQualification.expiresAt <= now)
          return back('rehearse', 'proof_expired', entry.listenerKey);
        if (!l7ProofCurrent(e, l, now)) return back('rehearse', 'proof_stale', entry.listenerKey);
      } else if (needsEndpointVerification(e) && !verificationCurrent(e, l)) {
        // A listener or address change since the tick: the endpoint goes back
        // to the card (the try_it stage rebuilds it as a named-connection
        // retest of the published address), then stages 5-8 run again.
        return back('try_it', 'retest_needed', entry.listenerKey);
      }
    }
    // Every hide row settled, none outstanding.
    const hides = await ops.hideStatus(ctx as unknown as QueryRunner, relay._id);
    if (hides.outstanding > 0 || hides.unresolved > 0)
      return back('hide_direct_hosts', 'hides_unsettled');
    // Rendering on (turned on here if off, audited), then the binding.
    const cfg = await resolveEdgeConfig(ctx.db);
    let renderEnabled = false;
    if (!cfg.render.enabled) {
      await upsertSettingRow(ctx, EDGE_KEYS['render.enabled'], 'true', r.actorAdminId);
      renderEnabled = true;
      // Like a render.* config change: every enabled origin re-keys its cache.
      const others = await ctx.db
        .query('relays')
        .withIndex('by_enabled', (q) => q.eq('enabled', true))
        .collect();
      for (const o of others) {
        if (o._id === relay._id) continue;
        await ctx.db.patch(o._id, { publicationEpoch: o.publicationEpoch + 1, updatedAt: now });
      }
      await scheduleMirrorRefresh(ctx);
      await writeAuditLog(ctx, {
        actorType: r.actorAdminId ? 'admin' : 'system',
        actorId: r.actorAdminId ?? undefined,
        action: 'edge.render.enabled_by_setup',
        targetType: 'app_settings',
        payload: { relaySlug: relay.slug, runId: r._id, affectedRelays: others.length - 1 },
      });
    }
    // An enrolled node goes live through its delivery commit, in this same
    // transaction (docs/servers.md "Node lifecycle"): no independent go-live
    // exists while its activation is unapproved, blocked or superseded.
    if (relay.origin.kind === 'panel-node' && relay.backendServerId) {
      const act = await activatingRunFor(ctx, relay.backendServerId, relay.origin.nodeName);
      if (act) {
        const edgeIds = r.listeners.map((l) => l.edgeId).filter((e): e is Id<'edges'> => !!e);
        if (act.run) {
          if (r.activationRunId && act.run._id !== r.activationRunId)
            return need('node_not_approved', 'servers.run_superseded');
          const p = await promoteCandidate(ctx, act.run, { edgeIds });
          // What members would keep moved since the rehearsal: rehearse again
          // for a new snapshot (never a block: nothing about the approval changed).
          if (!p.ok && p.code === 'servers.delivery_changed')
            return back('rehearse', 'delivery_changed');
          if (!p.ok) {
            // An obligation of the node still in flight settles by itself: go-live is tried again.
            if (p.code === 'servers.obligation_unresolved') {
              await ctx.db.patch(runId, {
                state: 'waiting',
                stepVersion: next,
                events: appendRunEvent(r.events, {
                  at: now,
                  level: 'info',
                  code: 'waiting',
                  detail: p.code,
                }),
                updatedAt: now,
              });
              await scheduleStep(ctx, runId, EDGE_PLUMBING.pollMs);
              return { ok: false as const, code: p.code };
            }
            // Anything else means the approved candidate cannot go live as it
            // stands: it is blocked, the node parks for a fresh approval (the
            // review names why), and that approval's wake re-runs the rehearsal.
            await blockActivation(ctx, act.run, p.code);
            return need('node_not_approved', p.code);
          }
        } else {
          // No activation running: a re-protected LIVE node binds without a
          // promotion only when every edge fits what members were approved
          // for; anything else waits for a review and an approval.
          for (const id of edgeIds) {
            const e = await ctx.db.get(id);
            const admission = e ? await publicationApproval(ctx, relay, e) : null;
            if (admission?.kind !== 'committed')
              return need('node_not_approved', act.intent.activation.stage);
          }
        }
      }
    }
    await claimDeliveryBinding(ctx, relay);
    // A re-protect's new addresses take the places of the ones they replace
    // (`replace_all`); an `add` keeps every address and only gives back room.
    let retired = 0;
    if (r.kind === 'reprotect') {
      if (parsePlan(r).reprotect?.mode === 'add') await restoreReprotectPool(ctx, r, relay);
      else retired = await retireReplacedEdges(ctx, r, relay);
    }
    await ctx.db.patch(relay._id, {
      setupOwned: undefined,
      setupStage: undefined,
      // The consented dark cohorts outlive the run: a later restore (remove
      // protection, release the requirement) must skip them or never pass.
      darkCohortKeys: r.rehearsal?.darkCohortKeys ?? [],
      // The node's provider set: the run's picks (an `add` joins them to the
      // set it had). Automatic work stays inside it from now on.
      providerSet: providerSetAfter(relay, r, now),
      updatedAt: now,
    });
    const verified = r.listeners.map((l) => ({
      ...l,
      verify:
        l.layer === 'l7'
          ? ('verified' as const)
          : l.verify === 'pending'
            ? ('partial' as const)
            : l.verify,
      published: true,
    }));
    await ctx.db.patch(runId, {
      stage: 'done',
      state: 'done',
      need: undefined,
      expect: undefined,
      listeners: verified,
      testLinks: undefined,
      stepVersion: next,
      nextStepAt: undefined,
      finishedAt: now,
      events: appendRunEvent(r.events, {
        at: now,
        level: 'info',
        code: 'live',
        ...(retired > 0 ? { detail: `${retired} replaced address(es) draining` } : {}),
      }),
      updatedAt: now,
    });
    const after = (await ctx.db.get(runId))!;
    await auditRun(ctx, after, 'edge.setup_run.go_live', {
      listeners: verified.length,
      renderEnabled,
    });
    await auditRun(ctx, after, 'edge.setup_run.finished', {
      outcome: 'live',
      stage: 'done',
      verdicts: verdictsOf(after),
    });
    return { ok: true as const, code: 'live' };
  },
});

// --- the node's approval wakes the run --------------------------------------------------------------

/**
 * Re-enter a run that waits for the operator under a NEW generation (a
 * rotation hook or a wake of the old attempt becomes a no-op), at `stage`.
 * Shared by `resume` and the approval wake.
 */
async function reenterStage(
  ctx: MutationCtx,
  r: Run,
  a: {
    stage: SetupRunStage;
    events: Array<{ at: number; level: 'info' | 'warn' | 'error'; code: string; detail?: string }>;
    patch?: Partial<Run>;
  },
): Promise<void> {
  const now = Date.now();
  let events = r.events;
  for (const e of a.events) events = appendRunEvent(events, e);
  await ctx.db.patch(r._id, {
    ...a.patch,
    stage: a.stage,
    state: 'running',
    need: undefined,
    expect: undefined,
    generation: r.generation + 1,
    stepVersion: r.stepVersion + 1,
    ...(a.stage !== r.stage ? { stageEnteredAt: now } : {}),
    events,
    updatedAt: now,
  });
  if (a.stage !== r.stage && r.relayId) {
    const relay = await ctx.db.get(r.relayId);
    if (relay?.setupOwned) await ctx.db.patch(relay._id, { setupStage: a.stage, updatedAt: now });
  }
  await scheduleStep(ctx, r._id, 0);
}

/**
 * Scheduled by the node's approval with the setup run's generation as the
 * approval read it. Acts only when that run is still at that generation,
 * still waiting for this approval, bound to this activation, and the
 * activation is still the node's current one; anything else (a retry since,
 * a newer approval, a superseded run) is a no-op. A run past its publish
 * returns to the rehearsal: a new approval is a new candidate, and an old
 * rehearsal never satisfies it.
 */
export const wakeForApproval = internalMutation({
  args: {
    setupRunId: v.id('edgeSetupRuns'),
    activationRunId: v.id('panelActivationRuns'),
    generation: v.number(),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.setupRunId);
    if (!r || isTerminalRunState(r.state)) return { acted: false as const, reason: 'terminal' };
    if (r.generation !== a.generation) return { acted: false as const, reason: 'generation' };
    if (r.state !== 'needs_you' || r.need?.code !== 'node_not_approved')
      return { acted: false as const, reason: 'not_waiting' };
    if (r.activationRunId !== a.activationRunId)
      return { acted: false as const, reason: 'not_bound' };
    const act = await ctx.db.get(a.activationRunId);
    if (!act || act.state !== 'running' || act.setupRunId !== r._id)
      return { acted: false as const, reason: 'activation_not_running' };
    const intent = await ctx.db.get(act.intentId);
    if (!intent || intent.activation.currentRunId !== act._id)
      return { acted: false as const, reason: 'superseded' };
    const now = Date.now();
    const stage: SetupRunStage = STAGE_INDEX[r.stage] > STAGE_INDEX.rehearse ? 'rehearse' : r.stage;
    await reenterStage(ctx, r, {
      stage,
      events: [{ at: now, level: 'info', code: 'approved', detail: `back at ${stage}` }],
      patch: { rehearsal: undefined },
    });
    return { acted: true as const, reason: stage };
  },
});

// --- operator verbs: retry / continue / cancel ------------------------------------------------------

/**
 * Re-enter the CURRENT stage under a new generation (the old rotation's hook
 * becomes a no-op), reusing everything that exists. Options answer the card's
 * secondary buttons: `tryAnotherAddress` destroys the unreachable standby and
 * re-provisions that listener only (at `try_it`, `edgeId` names the one line
 * that does not work; without it every unconfirmed line is replaced), and
 * only when the replacement could start now: otherwise nothing is cancelled
 * (`edge.replacement_cannot_start`, `assertReplacementCanStart`);
 * `checkAgain` checks the same unreachable address afresh (only evidence from
 * now on counts) and goes on if it now passes;
 * `acceptPartial` goes on with the rung as it is; `accountId` names another
 * compatible account and `locationId` another location (of it, or of the
 * run's account): the run's pick.
 */
export const retry = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    tryAnotherAddress: v.optional(v.boolean()),
    edgeId: v.optional(v.id('edges')),
    checkAgain: v.optional(v.boolean()),
    acceptPartial: v.optional(v.boolean()),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    locationId: v.optional(v.id('edgeLocations')),
    /** Replace one pick of the run's set (before its addresses are published). */
    replacePick: v.optional(v.object({ from: v.id('edgeLocations'), to: v.id('edgeLocations') })),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.runId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (r.state === 'done' || r.state === 'done_unbound' || r.state === 'cancelled')
      throw new ConvexError({ code: 'edge.setup_run_finished', message: 'The run is finished' });
    if (r.state === 'running' || r.state === 'waiting')
      throw new ConvexError({ code: 'edge.setup_run_busy', message: 'The run is still working' });
    // A failed re-protect gave its live origin back: the retry claims it again,
    // only while the node is still live behind it and nothing else owns it.
    const reclaim = r.kind === 'reprotect' && r.state === 'failed';
    if (reclaim) await assertReprotectReclaimable(ctx, r);
    else if (r.state === 'failed') await assertStillTheNodesRun(ctx, r);
    const now = Date.now();
    let stage = r.stage;
    let listeners = r.listeners.map((l) => ({ ...l }));
    let picks = r.picks;
    if (a.accountId || a.locationId || a.replacePick) {
      const plan = parsePlan(r);
      const current = runPicks(r);
      // Which pick goes: the named one, else the run's only pick.
      const from =
        (a.replacePick?.from as Id<'edgeLocations'> | undefined) ??
        (current.length === 1 ? current[0]!.locationId : null);
      if (!from || !current.some((p) => p.locationId === from))
        throw new ConvexError({
          code: 'validation',
          message: 'Name the pick to replace (replacePick.from)',
        });
      const toId = (a.replacePick?.to as Id<'edgeLocations'> | undefined) ?? a.locationId;
      const named = toId ? await ctx.db.get(toId) : null;
      if (toId && !named)
        throw new ConvexError({ code: 'not_found', message: 'Location not found' });
      const accountId =
        a.accountId ?? named?.accountId ?? current.find((p) => p.locationId === from)!.accountId;
      const offered = plan.accounts.find((x) => x.id === (accountId as string | null));
      const account = accountId ? await ctx.db.get(accountId) : null;
      // A WebSocket node switches to no load balancer when none of its
      // transports may be fronted by one (lib/edges/websocketNode.ts): the plan
      // said so, or (a re-protect run's set) the node's listeners do.
      const relay = r.relayId ? await ctx.db.get(r.relayId) : null;
      if (
        offered?.reasons.includes('l4_not_for_websocket') ||
        (account &&
          edgeLayerOf(account.provider) === 'l4' &&
          relay &&
          l4BarredForAll(
            (await listenersOf(ctx, relay._id)).filter((l) => !l.retired),
            await websocketNodeOf(ctx.db, relay.origin),
          ))
      )
        throw new ConvexError({ code: 'edge.l4_not_for_websocket', message: L4_NOT_FOR_WEBSOCKET });
      if (!offered?.compatible)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'Not a compatible account',
        });
      if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
      const location = await pickLocationOf(ctx.db, account, toId);
      const offeredLocation = location
        ? offered.locations?.find((l) => l.id === (location._id as string))
        : null;
      if (!location || (offered.locations && !offeredLocation?.compatible))
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'Not a compatible location',
        });
      const moving = listeners.filter((l) => (l.locationId ?? from) === from);
      if (location._id !== from) {
        if (current.some((p) => p.locationId === location._id))
          throw new ConvexError({ code: 'validation', message: 'That location is already picked' });
        // Switching a pick only while none of its addresses is published: a
        // candidate of the old pick (its layer, its bill, its region) is
        // cancelled, never re-labelled.
        if (!SWITCHABLE_STAGES.has(r.stage) || moving.some((l) => l.published))
          throw new ConvexError({
            code: current.length === 1 ? 'edge.account_switch_late' : 'edge.pick_switch_late',
            message: 'A pick can only change before its addresses are published',
          });
        picks = current.map((p) =>
          p.locationId === from
            ? { locationId: location._id, accountId: account._id }
            : { locationId: p.locationId!, accountId: p.accountId! },
        );
        // The new set's cover, from scratch, as a fresh run would have it (the
        // old assignment could leave a transport without a backup elsewhere):
        // a line the new cover keeps stays with its address and its tick, a
        // new target joins, a published line stays, the rest go.
        const accountOf = (id: string) => plan.accounts.find((x) => x.id === id);
        const info = picks.map((p) => {
          const own = p.accountId === account._id;
          const acct = accountOf(p.accountId as string);
          const provider = own ? account.provider : (acct?.provider ?? '');
          const placeKey =
            p.locationId === location._id
              ? location.placeKey
              : (acct?.locations?.find((l) => l.id === (p.locationId as string))?.placeKey ??
                (p.locationId as string));
          const carriesKeys = own ? (offered.carries ?? null) : (acct?.carries ?? null);
          return {
            locationId: p.locationId as string,
            provider,
            locationKey: locationKeyOf(provider, placeKey),
            carries: carriesKeys,
          };
        });
        const req = requirementOf(
          plan.requiredListeners.map((k) => ({
            listenerKey: k,
            carriers: info
              .filter((p) => !p.carries || p.carries.includes(k))
              .map((p) => p.locationId),
          })),
          info.map((p) => ({
            locationId: p.locationId,
            provider: p.provider,
            locationKey: p.locationKey,
          })),
        );
        if (req.uncarried.length > 0)
          throw new ConvexError({
            code: 'edge.set_uncovered_listener',
            message: `No location of the new set carries ${req.uncarried.join(', ')}`,
          });
        const layerOf = (locationId: string) =>
          edgeLayerOf(
            (info.find((p) => p.locationId === locationId)?.provider ??
              account.provider) as EdgeProviderId,
          );
        const next: RunListener[] = [];
        for (const t of coverTargets(req, [])) {
          if (!t.locationId) continue;
          const existing = listeners.find(
            (l) =>
              l.listenerKey === t.listenerKey &&
              (l.locationId as string | undefined) === t.locationId &&
              l.locationId !== from,
          );
          next.push(
            existing ?? {
              listenerKey: t.listenerKey,
              locationId: t.locationId as Id<'edgeLocations'>,
              layer: layerOf(t.locationId),
              verify: 'pending' as const,
              published: false,
            },
          );
        }
        for (const l of listeners) if (l.published && !next.includes(l)) next.push(l);
        for (const l of listeners) {
          if (next.includes(l) || !l.edgeId) continue;
          const e = await ctx.db.get(l.edgeId);
          if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
            await ctx.db.patch(e._id, {
              status: 'cancelled',
              statusChangedAt: now,
              updatedAt: now,
            });
        }
        listeners = next;
        if (STAGE_INDEX[r.stage] > STAGE_INDEX.provision) stage = 'provision';
      }
    }
    // The target the run stopped on: the one stage 4 marked unreachable.
    const failed = listeners.find((l) => l.verify === 'unreachable') ?? null;
    if (a.edgeId && !(a.tryAnotherAddress && r.need?.code === 'try_it'))
      throw new ConvexError({
        code: 'validation',
        message: 'edgeId names a line of the try-it card only',
      });
    if (a.edgeId && !listeners.some((l) => l.layer === 'l4' && l.edgeId === a.edgeId))
      throw new ConvexError({ code: 'validation', message: 'Not an address this run is testing' });
    if (a.checkAgain && !(unreachableNeed(r.need?.code) && failed))
      throw new ConvexError({
        code: 'validation',
        message: 'Check again answers an address the outside check stopped on',
      });
    // The entries whose address "Doesn't work" / "Try another address" cancels.
    const replaced: RunListener[] = [];
    if (a.tryAnotherAddress && r.need?.code === 'try_it') {
      // "Doesn't work": the named line's candidate (or, without a name, every
      // L4 candidate the operator has NOT confirmed) is destroyed and
      // provisioned again; a confirmed one is kept, its tick stands.
      for (const entry of listeners) {
        if (entry.layer !== 'l4' || !entry.edgeId) continue;
        if (a.edgeId && entry.edgeId !== a.edgeId) continue;
        const e = await ctx.db.get(entry.edgeId);
        if (e?.verification?.rung === 'verified') {
          if (a.edgeId)
            throw new ConvexError({
              code: 'validation',
              message: 'That address was already confirmed to work',
            });
          continue;
        }
        if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
          await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
        entry.edgeId = undefined;
        entry.verify = 'pending';
        entry.probeRequestedAt = undefined;
        entry.proofRequestedAt = undefined;
        entry.recheckSince = undefined;
        entry.notChecked = undefined;
        replaced.push(entry);
      }
      stage = 'provision';
    } else if (a.tryAnotherAddress && unreachableNeed(r.need?.code) && failed) {
      const entry = failed;
      if (entry?.edgeId) {
        const e = await ctx.db.get(entry.edgeId);
        if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
          await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
        entry.edgeId = undefined;
        entry.verify = 'pending';
        entry.probeRequestedAt = undefined;
        entry.proofRequestedAt = undefined;
        entry.recheckSince = undefined;
        entry.notChecked = undefined;
        replaced.push(entry);
      }
      stage = 'provision';
    } else if (a.checkAgain && failed) {
      // The same address, a fresh outside check: an L4 address counts only
      // evidence from now on (stage 4 waits for the earlier runs to land
      // first), an L7 front runs its proof again.
      failed.verify = 'pending';
      failed.probeRequestedAt = undefined;
      failed.proofRequestedAt = undefined;
      failed.recheckSince = now;
      failed.notChecked = undefined;
    } else if (a.acceptPartial && unreachableNeed(r.need?.code) && failed) {
      failed.verify = 'partial';
    } else if (r.stage === 'verify') {
      for (const l of listeners) if (l.verify === 'unreachable') l.verify = 'pending';
    }
    // A replacement that could not start now loses nothing: this throws, and
    // the cancel above rolls back with the rest of the retry.
    for (const entry of replaced)
      await assertReplacementCanStart(ctx, { ...r, picks }, entry, listeners);
    // Re-entering a stage that provisions is new work: held by a freeze. A
    // run at the card or past it keeps finishing what it was admitted for.
    if (STAGE_INDEX[stage] <= STAGE_INDEX.provision) await assertAdmission(ctx.db, 'setup.start');
    await ctx.db.patch(r._id, {
      stage,
      state: 'running',
      need: undefined,
      expect: undefined,
      testLinks: undefined,
      generation: r.generation + 1,
      stepVersion: r.stepVersion + 1,
      listeners,
      ...(picks !== r.picks ? { picks } : {}),
      ...(stage !== r.stage ? { stageEnteredAt: now } : {}),
      attemptStartedAt: now,
      finishedAt: undefined,
      events: appendRunEvent(r.events, {
        at: now,
        level: 'info',
        code: 'retry',
        detail: `generation ${r.generation + 1} at ${stage}`,
      }),
      updatedAt: now,
    });
    if (reclaim && r.relayId) {
      const relay = await ctx.db.get(r.relayId);
      if (relay) {
        let missing = 0;
        for (const l of listeners) {
          const e = l.edgeId ? await ctx.db.get(l.edgeId) : null;
          if (!e || e.publication !== 'published') missing++;
        }
        await ensureReprotectRoom(ctx, relay, missing);
      }
      await ctx.db.patch(r.relayId, { setupOwned: true, setupStage: stage, updatedAt: now });
    }
    await scheduleStep(ctx, r._id, 0);
    return { ok: true as const, generation: r.generation + 1, stage };
  },
});

/** Start refusals the provision stage rides out (it waits and polls), never a reason to keep. */
const REPLACEMENT_WAITS: ReadonlySet<string> = new Set(['edge.busy', 'edge.concurrency']);

/**
 * Whether the provision that replaces `entry`'s address could start now, read
 * in the SAME transaction as the cancel of the old address (so it sees the
 * slot that cancel frees): the rotation's own start guards (maintenance, a
 * quarantine, a restore) and its selection for the entry's pick (the
 * account's daily budget, its live cap, the location's cap, the account
 * switched off or untested...). A refusal throws
 * `edge.replacement_cannot_start` with the reason, and the whole retry rolls
 * back: the old address stays on the card, nothing is cancelled. Nothing is
 * started when the stage would reuse a live address of the same pick instead
 * (a protect run's spare), so then there is nothing to check. A replacement
 * that starts and fails later (the provider) still costs the old address.
 */
async function assertReplacementCanStart(
  ctx: MutationCtx,
  r: Run,
  entry: RunListener,
  listeners: RunListener[],
): Promise<void> {
  if (!r.relayId) return;
  const listener = (await listenersOf(ctx, r.relayId)).find(
    (l) => l.listenerKey === entry.listenerKey && !l.retired,
  );
  // The stage itself stops on a listener that is gone.
  if (!listener) return;
  const pick = pickOfTarget(r, entry);
  const locationId = entry.locationId ?? pick.locationId ?? undefined;
  if (r.kind !== 'reprotect') {
    const held = new Set(listeners.map((l) => l.edgeId as string | undefined).filter(Boolean));
    const reusable = (await liveEdgesOfRelay(ctx.db, r.relayId)).some(
      (e) =>
        !held.has(e._id as string) &&
        e.listenerId === listener._id &&
        LIVE_CANDIDATE.has(e.status) &&
        (e.publication === 'unpublished' || e.publication === 'published') &&
        e.accountId === pick.accountId &&
        (!locationId || (e.locationId ?? null) === locationId),
    );
    if (reusable) return;
  }
  // Exactly what the provision stage would start (startStageRotation).
  const args = {
    relayId: r.relayId,
    kind: 'provision' as const,
    trigger: 'api' as const,
    listenerId: listener._id,
    requestedAccountId: pick.accountId ?? undefined,
    requestedLocationId: locationId,
    allowUnqualified: true,
    publishOnDone: false,
    setupRun: { runId: r._id, generation: r.generation + 1 },
  };
  const refuse = (reason: string): never => {
    throw new ConvexError({ code: 'edge.replacement_cannot_start', message: reason });
  };
  const g = await collectStartBlockers(ctx, args);
  const blocker = g.blockers.find((b) => !REPLACEMENT_WAITS.has(b.code));
  if (blocker) refuse(blocker.message);
  if (!g.origin || !g.cfg) return;
  const sel = await selectionContext(ctx, args, g.origin, null, g.cfg);
  const failure = !sel.listener
    ? (sel.accountFailure ?? 'no_compatible_listener')
    : !sel.standbyId && (!sel.account || !sel.template)
      ? (sel.accountFailure ?? 'no_account')
      : null;
  if (failure) refuse(reasonWords(failure));
}

/** A selection failure code as a short reason (`account_budget_exhausted` -> "Account budget exhausted"). */
function reasonWords(code: string): string {
  const words = code.replace(/_/g, ' ');
  return words[0]!.toUpperCase() + words.slice(1);
}

/**
 * A failed re-protect may claim its origin again only while the origin still
 * exists, still binds the node (members are served through it), is not being
 * deleted, quarantined or restored, and no other run or setup owns it.
 */
async function assertReprotectReclaimable(ctx: MutationCtx, r: Run): Promise<void> {
  const relay = r.relayId ? await ctx.db.get(r.relayId) : null;
  if (!relay || relay.deleting)
    throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
  const active = await activeRunForOrigin(ctx.db, r.backendServerId, r.nodeName);
  if (relay.setupOwned || (active && active._id !== r._id))
    throw new ConvexError({
      code: 'edge.setup_run_active',
      message: 'A setup run already owns this node',
    });
  if (!relay.enabled)
    throw new ConvexError({ code: 'edge.relay_disabled', message: 'Enable the origin first' });
  if (relay.quarantine)
    throw new ConvexError({ code: 'edge.quarantined', message: 'Resolve the quarantine first' });
  if (relay.restore)
    throw new ConvexError({
      code: 'edge.restore_in_progress',
      message: 'A restore workflow is running on this origin',
    });
  if (!(await admitted(ctx.db)))
    throw new ConvexError({ code: 'edge.maintenance', message: 'Edges are in maintenance' });
  // A rename or a server change moving the listeners under the run: wait.
  await assertNoRelayPanelClaim(ctx.db, relay);
  if (!(await boundToRelay(ctx, relay)))
    throw new ConvexError({
      code: 'edge.reprotect_not_bound',
      message: 'The node is no longer live behind this origin',
    });
}

/**
 * A failed run is tried again only while it is still the node's run: no run of
 * the node is newer or still open, and its origin (once it has one) is still
 * owned by a setup and serves no member. A newer run that took the half set
 * up origin over, or went live on it, supersedes this one: trying the old run
 * again would put two runs on one origin, and cancelling it would then delete
 * or restore the live origin.
 */
async function assertStillTheNodesRun(ctx: MutationCtx, r: Run): Promise<void> {
  const runs = await ctx.db
    .query('edgeSetupRuns')
    .withIndex('by_origin', (q) =>
      q.eq('backendServerId', r.backendServerId).eq('nodeName', r.nodeName),
    )
    .collect();
  const newer = runs.some(
    (x) => x._id !== r._id && (x._creationTime > r._creationTime || !isTerminalRunState(x.state)),
  );
  const relay = r.relayId ? await ctx.db.get(r.relayId) : null;
  if (newer || (relay && (!relay.setupOwned || (await servesMembers(ctx, relay)))))
    throw new ConvexError({
      code: 'edge.setup_run_superseded',
      message: 'A newer setup run took this node over; open that run or start a new one',
    });
}

/** Whether a delivery binding names this origin (deferred or not): members depend on it. */
async function servesMembers(ctx: { db: QueryCtx['db'] }, relay: Relay): Promise<boolean> {
  if (!relay.backendServerId) return false;
  const binding = await deliveryBindingFor(ctx.db, relay.backendServerId, relay.nodeName);
  return !!binding && binding.relaySlug === relay.slug;
}

/** Whether the node's members are served through THIS origin (its delivery binding is active). */
export async function boundToRelay(ctx: { db: QueryCtx['db'] }, relay: Relay): Promise<boolean> {
  if (relay.bindingDeferred || !relay.backendServerId) return false;
  const binding = await deliveryBindingFor(ctx.db, relay.backendServerId, relay.nodeName);
  return !!binding && binding.relaySlug === relay.slug;
}

/**
 * Resume an interruption with what the operator answered:
 *  - `confirmations[]` (try_it): each tick is forwarded to
 *    `edgeVerification.confirm` (the server recomputes the binding and refuses
 *    a stale one with `edge.verification_stale`; the card is then rebuilt);
 *  - `approvedHideUuids[]` (review_changed): the new consent replaces the old
 *    (planRevision bump) and stage 6 runs again;
 *  - `keepDirect` (review_changed): finish unbound;
 *  - nothing: re-enter the stage (the operator fixed something outside).
 */
export const resume = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    confirmations: v.optional(
      v.array(
        v.object({
          edgeId: v.id('edges'),
          endpoint: v.string(),
          listenerRevision: v.number(),
          configHash: v.string(),
        }),
      ),
    ),
    approvedHideUuids: v.optional(v.array(v.string())),
    keepDirect: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.runId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (isTerminalRunState(r.state))
      throw new ConvexError({ code: 'edge.setup_run_finished', message: 'The run is finished' });
    if (r.state !== 'needs_you')
      throw new ConvexError({ code: 'edge.setup_run_busy', message: 'The run is still working' });
    const now = Date.now();
    const events: Array<{
      at: number;
      level: 'info' | 'warn' | 'error';
      code: string;
      detail?: string;
    }> = [];
    let listeners = r.listeners.map((l) => ({ ...l }));
    let stage = r.stage;
    let planRevision = r.planRevision;
    let approved = r.approvedHideUuids;
    let keepDirect = r.keepDirect;
    let testedEndpoints = r.testedEndpoints ?? [];
    let finishUnbound = false;
    let accountTrusted = false;
    if (a.confirmations && a.confirmations.length > 0) {
      if (r.need?.code !== 'try_it')
        throw new ConvexError({ code: 'validation', message: 'The run is not waiting for a test' });
      for (const c of a.confirmations) {
        const link = (r.testLinks ?? []).find((t) => t.edgeId === c.edgeId);
        if (!link)
          throw new ConvexError({
            code: 'validation',
            message: 'Not an endpoint this run is testing',
          });
        const res = await confirmEndpoint(ctx, {
          edgeId: c.edgeId,
          endpoint: c.endpoint,
          listenerRevision: c.listenerRevision,
          configHash: c.configHash,
          method: link.method,
          actorAdminId: a.actorAdminId,
        });
        accountTrusted = accountTrusted || res.accountTrusted;
        const entry = listeners.find((l) => l.edgeId === c.edgeId);
        if (entry) entry.verify = 'verified';
        testedEndpoints = [
          ...testedEndpoints.filter((t) => t.edgeId !== c.edgeId),
          { edgeId: c.edgeId, listenerKey: link.listenerKey, endpoint: c.endpoint, at: now },
        ];
        events.push({
          at: now,
          level: 'info',
          code: 'endpoint_confirmed',
          detail: link.listenerKey,
        });
      }
      // The stage re-runs: every remaining L4 endpoint is re-checked and the
      // card rebuilt for the ones still pending; the stage advances on its own
      // once every line is ticked.
    } else if (a.approvedHideUuids) {
      if (r.need?.code !== 'review_changed')
        throw new ConvexError({
          code: 'validation',
          message: 'The run is not waiting for a review',
        });
      // The submitted set REPLACES the consent, exactly. Withdrawing a Host that
      // the ledger already disabled cannot be honoured silently (the run never
      // re-enables a Host on its own): refused with a code that points at the
      // one path that does, Remove protection.
      approved = [...new Set(a.approvedHideUuids)];
      const withdrawn = r.approvedHideUuids.filter((u) => !approved.includes(u));
      if (withdrawn.length > 0 && r.relayId) {
        const rows = await ctx.db
          .query('edgeHostHides')
          .withIndex('by_relay', (q) => q.eq('relayId', r.relayId!))
          .collect(); // one row per direct Host of one node: operator-scale
        const hidden = rows.filter(
          (h) =>
            withdrawn.includes(h.hostUuid) &&
            h.intent === 'disable' &&
            (h.state === 'confirmed' || h.state === 'written' || h.state === 'unresolved'),
        );
        if (hidden.length > 0)
          throw new ConvexError({
            code: 'edge.consent_withdrawn_hidden',
            message: `${hidden.length} host(s) are already hidden; use Remove protection to put them back`,
          });
      }
      planRevision = r.planRevision + 1;
      events.push({
        at: now,
        level: 'info',
        code: 'consent_replaced',
        detail: `revision ${planRevision}`,
      });
    } else if (a.keepDirect) {
      if (r.need?.code !== 'review_changed')
        throw new ConvexError({
          code: 'validation',
          message: 'The run is not waiting for a review',
        });
      if (await frontedEnrolled(ctx, r.backendServerId, r.nodeName)) refuseKeepDirect();
      keepDirect = true;
      finishUnbound = true;
    } else {
      events.push({ at: now, level: 'info', code: 'resume', detail: r.stage });
    }
    if (finishUnbound) {
      await onSetupRunEnded(ctx, r, r.generation);
      await ctx.db.patch(r._id, {
        stage: 'done',
        state: 'done_unbound',
        need: undefined,
        expect: undefined,
        keepDirect: true,
        finishedAt: now,
        stepVersion: r.stepVersion + 1,
        generation: r.generation + 1,
        events: appendRunEvent(r.events, { at: now, level: 'info', code: 'done_unbound' }),
        updatedAt: now,
      });
      const after = (await ctx.db.get(r._id))!;
      await auditRun(ctx, after, 'edge.setup_run.finished', {
        outcome: 'unbound',
        stage: r.stage,
        verdicts: verdictsOf(after),
      });
      return { ok: true as const, state: 'done_unbound' as const, accountTrusted };
    }
    await reenterStage(ctx, r, {
      stage,
      events,
      patch: {
        listeners,
        approvedHideUuids: approved,
        planRevision,
        keepDirect,
        testedEndpoints,
        reviewDelta: undefined,
      },
    });
    return { ok: true as const, state: 'running' as const, accountTrusted };
  },
});

/**
 * Cancel: before stage 5 nothing was published, so the origin is deleted
 * `restore-direct` (which cancels the live rotation, drains the standbys for
 * the reconcile destroy and lets the origin delete remove the credential);
 * stages 5-7 (and a go-live waiting for a fresh approval) keep the published
 * edges and run the restore workflow (`edgeRestore.start`, purpose
 * `cancel_setup`), unless the origin never reached members (nothing
 * published, no Host hidden, not bound: a run parked at publish, say), which
 * is deleted like an earlier cancel, so the node can be protected afresh
 * instead of being left half set up; after go-live there is no cancel. A re-protect run
 * (`kind: 'reprotect'`) drops only its own candidates instead, in one
 * mutation (`cancelReprotect`): the live node keeps what members have.
 *
 * What happens is decided in ONE mutation that re-reads the run and fences
 * its scheduled step (`decideCancel`): a go-live that committed first refuses
 * the cancel, and one still due finds its step version moved. The delete or
 * the restore then takes the origin (either refuses a go-live from then on),
 * and only after it does is the run marked cancelled: a cleanup refused
 * meanwhile leaves the run open, so the cancel can be pressed again (and its
 * step is re-kicked if it is not). An origin that is live (no setup owns it,
 * or a binding names it) is never deleted or restored: the cancel then only
 * ends the run.
 */
export const cancel = internalAction({
  args: { runId: v.id('edgeSetupRuns'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (
    ctx,
    { runId, actorAdminId },
  ): Promise<{ ok: true; disposition: CancelDisposition }> => {
    const r = await ctx.runQuery(internal.edgeSetupRuns.get, { id: runId });
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (r.kind === 'reprotect')
      return ctx.runMutation(internal.edgeSetupRuns.cancelReprotect, { runId, actorAdminId });
    const d = await ctx.runMutation(internal.edgeSetupRuns.decideCancel, { runId });
    if (d.relayId && d.disposition === 'deleted') {
      await ctx.runMutation(internal.relays.requestDelete, {
        id: d.relayId,
        disposition: 'restore-direct',
        actorAdminId,
      });
    } else if (d.relayId && d.disposition === 'restore') {
      await ops.restoreStart(ctx, {
        relayId: d.relayId,
        purpose: 'cancel_setup',
        actorAdminId,
        darkCohortKeys: d.darkCohortKeys,
      });
    }
    // A temporary test credential minted for this run expires now rather than
    // at its 24 h TTL (the sweep removes it; an origin delete releases too).
    if (d.relayId)
      await ctx.runMutation(internal.edgeTestCredentials.releaseForRelay, { relayId: d.relayId });
    await ctx.runMutation(internal.edgeSetupRuns.markCancelled, {
      runId,
      disposition: d.disposition,
      actorAdminId,
    });
    return { ok: true as const, disposition: d.disposition };
  },
});

export type CancelDisposition = 'deleted' | 'restore' | 'candidates' | 'none';

/**
 * The deciding half of a cancel: re-read, still cancellable, and what happens
 * to its origin judged from the rows as they are now. The run's step version
 * moves, so a go-live already scheduled can no longer land before the cleanup.
 */
export const decideCancel = internalMutation({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (
    ctx,
    { runId },
  ): Promise<{
    disposition: 'deleted' | 'restore' | 'none';
    relayId: Id<'relays'> | null;
    darkCohortKeys: string[];
  }> => {
    const r = await ctx.db.get(runId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (r.kind === 'reprotect')
      throw new ConvexError({
        code: 'validation',
        message: 'A re-protect run cancels its own way',
      });
    assertCancellable(r);
    const parkedAtGoLive = r.stage === 'go_live' && r.state === 'needs_you';
    const relay = r.relayId ? await ctx.db.get(r.relayId) : null;
    let disposition: 'deleted' | 'restore' | 'none' = 'none';
    if (relay && relay.setupOwned && !(await servesMembers(ctx, relay))) {
      if (cancelDeletesRelay(r.stage)) disposition = 'deleted';
      else if (cancelRestores(r.stage) || parkedAtGoLive)
        disposition = (await originEverServed(ctx.db, relay)) ? 'restore' : 'deleted';
    }
    await ctx.db.patch(runId, { stepVersion: r.stepVersion + 1, updatedAt: Date.now() });
    return {
      disposition,
      relayId: relay?._id ?? null,
      darkCohortKeys: r.rehearsal?.darkCohortKeys ?? [],
    };
  },
});

/**
 * Whether an origin ever reached members: an edge of it was published (now or
 * before), it hid a direct Host, or a delivery binding names it. One that
 * never did has nothing to restore and nothing worth keeping.
 */
async function originEverServed(db: QueryCtx['db'], relay: Relay): Promise<boolean> {
  if (relay.publishedEdgeIds.some(Boolean)) return true;
  const hide = await db
    .query('edgeHostHides')
    .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
    .first();
  if (hide) return true;
  const edges = await db
    .query('edges')
    .withIndex('by_relay_status', (q) => q.eq('relayId', relay._id))
    .collect();
  if (edges.some((e) => e.publishedAt !== undefined || e.publication !== 'unpublished'))
    return true;
  return servesMembers({ db }, relay);
}

/**
 * Cancel is refused once the run is finished or binding: after go-live there
 * is no cancel. A run waiting at go-live for a fresh approval (its candidate
 * went stale) has bound nothing yet: it cancels like stages 5-7.
 */
function assertCancellable(r: Run): void {
  const parkedAtGoLive = r.stage === 'go_live' && r.state === 'needs_you';
  if (
    isTerminalRunState(r.state) ||
    (r.stage === 'go_live' && !parkedAtGoLive) ||
    r.stage === 'done'
  )
    throw new ConvexError({
      code: 'edge.setup_run_finished',
      message: 'The run is past the point of cancellation',
    });
}

/** The end of a cancel, once its origin was taken care of (`cancel`). */
export const markCancelled = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    disposition: v.union(v.literal('deleted'), v.literal('restore'), v.literal('none')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { runId, disposition, actorAdminId }) => {
    const r = await ctx.db.get(runId);
    if (!r || isTerminalRunState(r.state)) return null;
    await markRunCancelled(ctx, r, disposition, actorAdminId);
    return null;
  },
});

/** The end of every cancel: the end hook (THIS attempt), the terminal write, the audit. */
async function markRunCancelled(
  ctx: MutationCtx,
  r: Run,
  disposition: CancelDisposition,
  actorAdminId: Id<'adminUsers'> | undefined,
): Promise<void> {
  const now = Date.now();
  // Read before the generation moves: the hook ends THIS attempt.
  await onSetupRunEnded(ctx, r, r.generation, 'servers.setup_run_cancelled');
  await ctx.db.patch(r._id, {
    state: 'cancelled',
    expect: undefined,
    testLinks: undefined,
    finishedAt: now,
    nextStepAt: undefined,
    stepVersion: r.stepVersion + 1,
    generation: r.generation + 1,
    events: appendRunEvent(r.events, {
      at: now,
      level: 'warn',
      code: 'cancelled',
      detail: disposition,
    }),
    updatedAt: now,
  });
  await auditRun(
    ctx,
    (await ctx.db.get(r._id))!,
    'edge.setup_run.cancelled',
    { stage: r.stage, disposition },
    actorAdminId,
  );
}

/**
 * Cancel a re-protect run: drop ONLY its own candidates, in one mutation. The
 * live node keeps its committed delivery (the binding, the committed edges,
 * the open gate); nothing is deleted or restored. Refused while a rotation
 * runs on the origin (`edge.busy`: nothing changed, cancel again in a moment).
 *  - an unpublished candidate is cancelled (the reconcile destroys it, like
 *    retry's "try another address");
 *  - a published CANDIDATE (one the node's gate keeps from members) leaves the
 *    pool to drain;
 *  - an edge published under the committed approval is live delivery already
 *    and stays.
 * Then the common end: the bound activation is blocked, the origin is given
 * back (`setupOwned` cleared), the test credential expires now.
 */
export const cancelReprotect = internalMutation({
  args: { runId: v.id('edgeSetupRuns'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { runId, actorAdminId }) => {
    const r = await ctx.db.get(runId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (r.kind !== 'reprotect')
      throw new ConvexError({ code: 'validation', message: 'Not a re-protect run' });
    assertCancellable(r);
    const relay = r.relayId ? await ctx.db.get(r.relayId) : null;
    if (relay) {
      if (relay.activeRotationId) {
        const rot = await ctx.db.get(relay.activeRotationId);
        if (rot && !isTerminalPhase(rot.phase))
          throw new ConvexError({
            code: 'edge.busy',
            message: 'A rotation is running on this origin; cancel again in a moment',
          });
      }
      // The run's candidates: every listener's edge, plus what a provision it
      // was still waiting on produced (its hook may not have landed yet).
      const ids = new Set<Id<'edges'>>();
      for (const l of r.listeners) if (l.edgeId) ids.add(l.edgeId);
      if (r.expect) {
        const rot = await ctx.db.get(r.expect.rotationId);
        if (rot?.kind === 'provision' && rot.toEdgeId) ids.add(rot.toEdgeId);
      }
      const gate =
        relay.origin.kind === 'panel-node' && relay.backendServerId
          ? await nodeGateFor(ctx, relay.backendServerId, relay.origin.nodeName)
          : null;
      const drop: Edge[] = [];
      const unpublish: Edge[] = [];
      for (const id of ids) {
        const e = await ctx.db.get(id);
        if (!e || e.relayId !== relay._id) continue;
        if (e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status)) drop.push(e);
        else if (e.publication !== 'published') continue;
        // A candidate members never got goes; so does an address of this run
        // a committed admission published beside the transport's existing
        // ones (every edge here is the run's own: a re-protect reuses none).
        // Only an address that is the transport's last served one stays.
        else if (gate && isCandidateEdge(gate, e._id as string)) unpublish.push(e);
        else if (await servedBesides(ctx, relay, e, ids)) unpublish.push(e);
      }
      // The pool guard of every unpublish (quarantine, restore, a backend
      // claim), checked before anything is written.
      if (unpublish.length > 0) await assertNoRotationOrQuarantine(ctx.db, relay);
      const now = Date.now();
      for (const e of drop)
        await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
      for (const e of unpublish)
        await unpublishFromPool(ctx, relay, e, actorAdminId ? { actorAdminId } : {});
      // A temporary test credential minted for this run expires now.
      await releaseTestCredentialsOf(ctx, relay._id);
    }
    await markRunCancelled(ctx, r, 'candidates', actorAdminId);
    return { ok: true as const, disposition: 'candidates' as const };
  },
});

/**
 * Whether the edge's transport keeps another published address that is not
 * the run's own (`runEdges`): only then does dropping it leave members served.
 */
async function servedBesides(
  ctx: { db: QueryCtx['db'] },
  relay: Relay,
  edge: Edge,
  runEdges: ReadonlySet<Id<'edges'>>,
): Promise<boolean> {
  for (const id of relay.publishedEdgeIds) {
    if (!id || id === edge._id || runEdges.has(id)) continue;
    const other = await ctx.db.get(id);
    if (other && other.listenerId === edge.listenerId && other.publication === 'published')
      return true;
  }
  return false;
}

// --- require-edges (the only other path to the binding) --------------------------------------------

/**
 * `POST origins/{id}/require-edges`: apply the SAME activation policy to a
 * deferred origin (a run that finished unbound, a failed run whose edges the
 * operator published by hand): every published L4 edge without a current
 * confirmation goes through the `try_it` card first (the response returns the
 * pending endpoints instead of binding), then stages 7-8 verbatim. Never a
 * shortcut: `claimDeliveryBinding` is reached only through stage 8.
 */
export const requireEdges = internalMutation({
  args: {
    relayId: v.id('relays'),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    locationId: v.optional(v.id('edgeLocations')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, accountId, locationId, actorAdminId }) => {
    // New work: held while the edges maintenance switch is on.
    await assertAdmission(ctx.db, 'setup.start');
    const relay = await ctx.db.get(relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!relay.bindingDeferred)
      throw new ConvexError({
        code: 'edge.not_deferred',
        message: 'The origin already binds its origin',
      });
    if (!relay.enabled)
      throw new ConvexError({ code: 'edge.relay_disabled', message: 'Enable the origin first' });
    if (relay.quarantine)
      throw new ConvexError({ code: 'edge.quarantined', message: 'Resolve the quarantine first' });
    if (relay.activeRotationId) {
      const rot = await ctx.db.get(relay.activeRotationId);
      if (rot && !isTerminalPhase(rot.phase))
        throw new ConvexError({ code: 'edge.busy', message: 'A rotation is running' });
    }
    if (!relay.backendServerId || !relay.nodeName)
      throw new ConvexError({
        code: 'edge.origin_kind_locked',
        message: 'Only a backend-node origin',
      });
    const active = await activeRunForOrigin(ctx.db, relay.backendServerId, relay.nodeName);
    if (active)
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run owns this node',
      });
    const listeners = (
      await verificationListenersOf(ctx.db, relay, await listenersOf(ctx, relayId))
    ).filter((l) => !l.retired && l.deployed && l.enabled);
    const edges = await liveEdgesOfRelay(ctx.db, relayId);
    const entries: RunListener[] = [];
    const pending: Array<{
      edgeId: string;
      listenerKey: string;
      endpoint: string;
      listenerRevision: number;
      configHash: string;
    }> = [];
    const now = Date.now();
    const testLinks: NonNullable<Run['testLinks']> = [];
    for (const l of listeners) {
      const e = l.templateEdgeId ? edges.find((x) => x._id === l.templateEdgeId) : undefined;
      if (!e || e.publication !== 'published')
        throw new ConvexError({
          code: 'edge.coverage_incomplete',
          message: `Listener ${l.listenerKey} has no published edge`,
        });
      const layer = e.layer ?? edgeLayerOf(e.provider);
      const current = layer === 'l7' ? l7ProofCurrent(e, l, now) : verificationCurrent(e, l);
      entries.push({
        listenerKey: l.listenerKey,
        ...(e.locationId ? { locationId: e.locationId } : {}),
        layer,
        edgeId: e._id,
        verify: current ? 'verified' : layer === 'l7' ? 'pending' : 'partial',
        published: true,
      });
      if (layer === 'l4' && !current) {
        const b = verificationBinding(e, l);
        if (b) {
          pending.push({ edgeId: e._id as string, ...b });
          testLinks.push({
            edgeId: e._id,
            listenerKey: l.listenerKey,
            link: '',
            format: 'named_connection',
            method: 'named_connection',
            binding: {
              endpoint: b.endpoint,
              listenerRevision: b.listenerRevision,
              configHash: b.configHash,
              issuedAt: now,
            },
          });
        }
      }
    }
    // The picks: the named location (or account), else the node's provider set,
    // else the places the origin's template edges are served from.
    const named = locationId ? await ctx.db.get(locationId) : null;
    const pickRows: Array<{
      location: Doc<'edgeLocations'>;
      account: Doc<'edgeProviderAccounts'>;
    }> = [];
    const addPick = async (loc: Doc<'edgeLocations'> | null) => {
      if (!loc || pickRows.some((p) => p.location._id === loc._id)) return;
      const acct = await ctx.db.get(loc.accountId);
      if (acct) pickRows.push({ location: loc, account: acct });
    };
    if (named || accountId) {
      const account =
        (accountId ? await ctx.db.get(accountId) : null) ??
        (named ? await ctx.db.get(named.accountId) : null);
      if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
      const location = await pickLocationOf(ctx.db, account, named?._id);
      if (!location)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'The account has no such location',
        });
      await addPick(location);
    } else if (relay.providerSet) {
      for (const p of relay.providerSet) await addPick(await ctx.db.get(p.locationId));
    } else {
      for (const l of listeners) {
        const e = l.templateEdgeId ? edges.find((x) => x._id === l.templateEdgeId) : undefined;
        if (e?.locationId) await addPick(await ctx.db.get(e.locationId));
      }
      if (pickRows.length === 0) {
        const withAccount = edges.find((e) => e.accountId);
        const account = withAccount?.accountId ? await ctx.db.get(withAccount.accountId) : null;
        if (account) await addPick(await pickLocationOf(ctx.db, account, undefined));
      }
    }
    if (pickRows.length === 0)
      throw new ConvexError({
        code: 'validation',
        message: 'accountId is required for this origin',
      });
    const accountsOfPlan = new Map<string, SetupPlanAccount>();
    for (const p of pickRows) {
      const row = accountsOfPlan.get(p.account._id as string) ?? {
        id: p.account._id as string,
        name: p.account.name,
        provider: p.account.provider,
        layer: edgeLayerOf(p.account.provider),
        compatible: true,
        reasons: [],
        locations: [],
      };
      row.locations = [...(row.locations ?? []), planLocationOf(p.location)];
      accountsOfPlan.set(row.id, row);
    }
    const plan: SetupPlanSnapshot = {
      backendServerId: relay.backendServerId as string,
      backend: '',
      nodeUuid: relay.origin.kind === 'panel-node' ? (relay.origin.nodeUuid ?? '') : '',
      nodeName: relay.nodeName,
      originAddress: relay.originAddress,
      relaySlug: relay.slug,
      inbounds: [],
      requiredListeners: entries.map((e) => e.listenerKey),
      tooManyInbounds: false,
      directHosts: [],
      accounts: [...accountsOfPlan.values()],
      renderGlobal: { willEnable: false, affectedRelays: [] },
      familiesDisabled: [],
      emptyNode: false,
      existingRelay: {
        id: relay._id as string,
        slug: relay.slug,
        setupStage: relay.setupStage ?? null,
      },
      activeRunId: null,
    };
    // An origin left deferred by a cancel or a released requirement has its direct
    // Hosts back: the run re-enters at the Host review / hide stage, never
    // straight at the rehearsal (those origin entries would be `leak_detected`).
    const stage: SetupRunStage = pending.length > 0 ? 'try_it' : 'hide_direct_hosts';
    const id = await ctx.db.insert('edgeSetupRuns', {
      relayId,
      relaySlug: relay.slug,
      backendServerId: relay.backendServerId,
      nodeName: relay.nodeName,
      nodeUuid: plan.nodeUuid,
      picks: pickRows.map((p) => {
        const options = relay.providerSet?.find((x) => x.locationId === p.location._id)?.options;
        return {
          locationId: p.location._id,
          accountId: p.account._id,
          ...(options !== undefined ? { options } : {}),
        };
      }),
      plan: JSON.stringify(plan),
      planHash: '',
      planRevision: 1,
      approvedHideUuids: [],
      stage,
      state: pending.length > 0 ? 'needs_you' : 'running',
      need:
        pending.length > 0
          ? { code: 'try_it', detail: `${pending.length} endpoint(s)` }
          : undefined,
      generation: 1,
      stepVersion: 1,
      listeners: entries,
      testLinks: pending.length > 0 ? testLinks : undefined,
      stageEnteredAt: now,
      events: [{ at: now, level: 'info', code: 'require_edges', detail: stage }],
      actorAdminId,
      startedAt: now,
      updatedAt: now,
    });
    if (!relay.setupOwned)
      await ctx.db.patch(relayId, { setupOwned: true, setupStage: stage, updatedAt: now });
    const run = (await ctx.db.get(id))!;
    await auditRun(
      ctx,
      run,
      'edge.setup_run.started',
      {
        stage,
        listeners: entries.length,
        accountName: pickRows[0]!.account.name,
        provider: pickRows[0]!.account.provider,
        picks: pickRows.length,
        approvedHides: 0,
        keepDirect: false,
      },
      actorAdminId,
    );
    if (pending.length === 0) await scheduleStep(ctx, id, 0);
    return { runId: id, stage, state: run.state, pending };
  },
});

// --- re-protect a live node (its own run kind) ----------------------------------------------------

/**
 * `POST relays/{id}/reprotect`: protect a LIVE, bound enrolled node again from
 * its node page. A run of kind `reprotect` on the origin as it stands (the
 * synthetic plan reads the relay's own rows, like `requireEdges`): the
 * committed delivery stays (binding, committed edges, open gate) while the run
 * provisions FRESH candidates on every listener members are served through,
 * shows their test links, and publishes them under the node's admission rules
 * (`committed` within the approved shape binds without a new approval;
 * otherwise the run parks at `node_not_approved` and the approval makes them
 * isolated candidates until go-live promotes them). The origin is owned while
 * the run lasts (upkeep and the detector keep off); a cancel drops only the
 * candidates (`cancelReprotect`) and a failure hands the live origin back
 * (`onSetupRunEnded`).
 */
export const reprotect = internalMutation({
  args: {
    relayId: v.id('relays'),
    /** `replace_all` (fresh addresses everywhere, the old ones drain) or `add` (only what a larger set lacks). */
    mode: v.optional(v.union(v.literal('replace_all'), v.literal('add'))),
    /** `add`: the locations joining the node's set. */
    addPicks: v.optional(v.array(v.id('edgeLocations'))),
    /** Provider options per pick (location id -> values); a pick not named keeps its own. */
    pickOptions: v.optional(v.any()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: (ctx, a) => startReprotect(ctx, a),
});

/** The re-protect start (`reprotect`, and a set edit that adds a pick to a live enrolled node). */
export async function startReprotect(
  ctx: MutationCtx,
  {
    relayId,
    actorAdminId,
    addPicks,
    pickOptions,
    ...rest
  }: {
    relayId: Id<'relays'>;
    mode?: 'replace_all' | 'add';
    addPicks?: Id<'edgeLocations'>[];
    pickOptions?: Record<string, unknown>;
    actorAdminId?: Id<'adminUsers'>;
  },
): Promise<{ runId: Id<'edgeSetupRuns'>; stage: SetupRunStage }> {
  {
    const mode = rest.mode ?? (addPicks && addPicks.length > 0 ? 'add' : 'replace_all');
    const relay = await ctx.db.get(relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!(await boundToRelay(ctx, relay)))
      throw new ConvexError({
        code: 'edge.reprotect_not_bound',
        message: 'The node is not live behind this origin yet; protect it or take it live first',
      });
    const backendServerId = relay.backendServerId;
    const nodeName = relay.origin.kind === 'panel-node' ? relay.origin.nodeName : null;
    const intent =
      backendServerId && nodeName
        ? await ctx.db
            .query('panelNodeIntents')
            .withIndex('by_server_name', (q) =>
              q.eq('backendServerId', backendServerId).eq('name', nodeName),
            )
            .unique()
        : null;
    if (!backendServerId || !nodeName || !intent)
      throw new ConvexError({
        code: 'edge.reprotect_not_enrolled',
        message: 'Only an enrolled node is protected again from here',
      });
    if (relay.setupOwned || (await activeRunForOrigin(ctx.db, backendServerId, nodeName)))
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run already owns this node',
      });
    if (!relay.enabled)
      throw new ConvexError({ code: 'edge.relay_disabled', message: 'Enable the origin first' });
    if (relay.quarantine)
      throw new ConvexError({ code: 'edge.quarantined', message: 'Resolve the quarantine first' });
    if (relay.restore)
      throw new ConvexError({
        code: 'edge.restore_in_progress',
        message: 'A restore workflow is running on this origin',
      });
    if (relay.activeRotationId) {
      const rot = await ctx.db.get(relay.activeRotationId);
      if (rot && !isTerminalPhase(rot.phase))
        throw new ConvexError({ code: 'edge.busy', message: 'A rotation is running' });
    }
    if (!(await admitted(ctx.db)))
      throw new ConvexError({ code: 'edge.maintenance', message: 'Edges are in maintenance' });
    // A node rename or a server change moving this origin's listeners: its
    // rotations would be refused mid-run (`edge.panel_op_running`), so wait.
    await assertNoRelayPanelClaim(ctx.db, relay);
    // What the committed delivery serves: every deployed, enabled listener with
    // a published template edge.
    const served: Array<{ listener: Listener; template: Edge }> = [];
    for (const l of await listenersOf(ctx, relayId)) {
      if (l.retired || !l.deployed || !l.enabled || !l.templateEdgeId) continue;
      const e = await ctx.db.get(l.templateEdgeId);
      if (e && e.relayId === relayId && e.publication === 'published')
        served.push({ listener: l, template: e });
    }
    if (served.length === 0)
      throw new ConvexError({
        code: 'edge.coverage_incomplete',
        message: 'No listener of this origin is served by a published edge',
      });
    // The picks: the node's provider set (what members are served from), plus
    // the new ones an `add` brings; without a set, the locations its served
    // edges come from.
    const servedLocations = [
      ...new Set(
        served.map((x) => x.template.locationId).filter((l): l is Id<'edgeLocations'> => !!l),
      ),
    ];
    const base = relay.providerSet?.map((p) => p.locationId) ?? servedLocations;
    const pickIds = [...base, ...(addPicks ?? []).filter((p) => !base.includes(p))];
    if (mode === 'add' && pickIds.length === base.length)
      throw new ConvexError({ code: 'validation', message: 'Name a location to add' });
    if (pickIds.length > MAX_PROVIDER_PICKS)
      throw new ConvexError({
        code: 'edge.set_too_large',
        message: `A node is protected from at most ${MAX_PROVIDER_PICKS} locations`,
      });
    const pickRows: Array<{
      location: Doc<'edgeLocations'>;
      account: Doc<'edgeProviderAccounts'>;
    }> = [];
    // A WebSocket node takes no new load balancer when none of its served
    // transports may be fronted by one (lib/edges/websocketNode.ts); one it
    // already has is left as it is and carries nothing new.
    const websocketNode = await websocketNodeOf(ctx.db, relay.origin);
    const l4Barred = l4BarredForAll(
      served.map((x) => x.listener),
      websocketNode,
    );
    for (const id of pickIds) {
      const location = await ctx.db.get(id);
      const account = location ? await ctx.db.get(location.accountId) : null;
      if (account && l4Barred && !base.includes(id) && edgeLayerOf(account.provider) === 'l4')
        throw new ConvexError({ code: 'edge.l4_not_for_websocket', message: L4_NOT_FOR_WEBSOCKET });
      if (!location || !account || !account.enabled || !accountTested(account) || !location.enabled)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message:
            'A location this node is protected from is missing, switched off, or its account is disabled or untested',
        });
      if (!frontsAllowed(account))
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message:
            'A location this node is protected from belongs to a DNS account set to DNS only, which fronts no traffic',
        });
      pickRows.push({ location, account });
    }
    if (pickRows.length === 0)
      throw new ConvexError({
        code: 'edge.account_incompatible',
        message: 'No location to protect this node from',
      });
    // Each pick's provider options: the ones the operator gives now (checked
    // where they build), else what the node's set already holds for it.
    const optionsOfPick = new Map<string, string>();
    const realityL4 = await relayHasReality(ctx.db, relay._id);
    for (const p of pickRows) {
      const key = p.location._id as string;
      const given = pickOptions?.[key];
      // A load balancer a WebSocket node already had: given nothing new (new
      // options for it are refused below).
      const kept = l4Barred && edgeLayerOf(p.account.provider) === 'l4';
      if (given !== undefined) {
        const r = await checkPickOptions(ctx, p.location, p.account, given, {
          realityL4,
          l4Barred,
        });
        if (!r.ok) throw new ConvexError({ code: r.code, message: r.issues.join('; ') || r.code });
        optionsOfPick.set(key, JSON.stringify(r.options));
        continue;
      }
      const entry = relay.providerSet?.find((x) => x.locationId === p.location._id);
      if (entry) {
        // A pick the node already had keeps what it has (the deploy copied the
        // account's certificate into one from before options).
        if (entry.options !== undefined) optionsOfPick.set(key, entry.options);
        continue;
      }
      if (kept) continue;
      // A pick joining now starts from the account's defaults, copied in, and
      // is refused now (as given options are) when what it inherits cannot be
      // built there, rather than failing later in the rotation.
      const r = await checkPickOptions(ctx, p.location, p.account, {}, { realityL4, l4Barred });
      if (!r.ok) throw new ConvexError({ code: r.code, message: r.issues.join('; ') || r.code });
      optionsOfPick.set(key, JSON.stringify(r.options));
    }
    // The requirement over the served transports, and its cover: fresh targets
    // over the whole of it (`replace_all`: the new addresses take the old
    // ones' places at go-live), or what the larger set still lacks given what
    // is published (`add`: nothing is retired).
    const picks = pickRows.map((p) => ({
      locationId: p.location._id as string,
      provider: p.account.provider,
      locationKey: locationKeyOf(p.account.provider, p.location.placeKey),
    }));
    const carriersOf = (l: Listener) =>
      pickRows.filter((p) => carries(p, l, { websocketNode })).map((p) => p.location._id as string);
    const req = requirementOf(
      served.map((x) => ({
        listenerKey: x.listener.listenerKey,
        carriers: carriersOf(x.listener),
      })),
      picks,
    );
    if (req.uncarried.length > 0)
      throw new ConvexError({
        code: 'edge.set_uncovered_listener',
        message: `No location of this node can carry ${req.uncarried.join(', ')}`,
      });
    const state = mode === 'add' ? await setStateOf(ctx.db, relay) : null;
    const targets = coverTargets(req, state?.published ?? [])
      .filter((t): t is typeof t & { locationId: string } => t.locationId !== null)
      .map((t) => ({
        listenerKey: t.listenerKey,
        locationId: t.locationId as Id<'edgeLocations'>,
      }));
    if (targets.length === 0)
      throw new ConvexError({
        code: 'validation',
        message: 'Nothing to add: the node already has an address in every location it needs',
      });
    const requiredListeners = [...new Set(targets.map((t) => t.listenerKey))];
    const nodeUuid = relay.origin.kind === 'panel-node' ? (relay.origin.nodeUuid ?? '') : '';
    // Room for the run's own targets beside what members hold (temporary room
    // above the cap, given back at go-live or when the run ends).
    const desiredBefore = relay.desiredPublished;
    await ensureReprotectRoom(ctx, relay, targets.length);
    const layerOf = (locationId: Id<'edgeLocations'>) =>
      edgeLayerOf(pickRows.find((p) => p.location._id === locationId)!.account.provider);
    const accounts = new Map<string, SetupPlanAccount>();
    for (const p of pickRows) {
      const row = accounts.get(p.account._id as string) ?? {
        id: p.account._id as string,
        name: p.account.name,
        provider: p.account.provider,
        layer: edgeLayerOf(p.account.provider),
        compatible: true,
        reasons: [],
        locations: [],
        carries: served
          .filter((x) => carries(p, x.listener, { websocketNode }))
          .map((x) => x.listener.listenerKey),
      };
      row.locations = [...(row.locations ?? []), planLocationOf(p.location)];
      accounts.set(row.id, row);
    }
    const plan: SetupPlanSnapshot = {
      backendServerId: backendServerId as string,
      backend: '',
      nodeUuid,
      nodeName,
      originAddress: relay.originAddress,
      relaySlug: relay.slug,
      inbounds: [],
      requiredListeners,
      tooManyInbounds: false,
      directHosts: [],
      accounts: [...accounts.values()],
      renderGlobal: { willEnable: false, affectedRelays: [] },
      familiesDisabled: [],
      emptyNode: false,
      existingRelay: { id: relay._id as string, slug: relay.slug, setupStage: null },
      activeRunId: null,
      enrolled: true,
      reprotect: { desiredBefore, mode },
      set: {
        picks: pickRows.map((p) => ({
          locationId: p.location._id as string,
          accountId: p.account._id as string,
          provider: p.account.provider,
          locationKey: locationKeyOf(p.account.provider, p.location.placeKey),
          label: p.location.label,
          ...(optionsOfPick.has(p.location._id as string)
            ? { options: parseOptionValues(optionsOfPick.get(p.location._id as string)) }
            : {}),
        })),
        targets: targets.map((t) => ({ listenerKey: t.listenerKey, locationId: t.locationId })),
        reduced: req.reduced,
        uncovered: [],
        tooLarge: false,
        problems: [],
      },
    };
    const stage: SetupRunStage = 'prepare';
    const now = Date.now();
    const id = await ctx.db.insert('edgeSetupRuns', {
      relayId,
      relaySlug: relay.slug,
      backendServerId,
      nodeName,
      nodeUuid,
      picks: pickRows.map((p) => {
        const options = optionsOfPick.get(p.location._id as string);
        return {
          locationId: p.location._id,
          accountId: p.account._id,
          ...(options !== undefined ? { options } : {}),
        };
      }),
      plan: JSON.stringify(plan),
      planHash: '',
      planRevision: 1,
      approvedHideUuids: [],
      kind: 'reprotect',
      stage,
      state: 'running',
      generation: 1,
      stepVersion: 1,
      // No edge yet: every candidate is provisioned fresh.
      listeners: targets.map((t) => ({
        listenerKey: t.listenerKey,
        locationId: t.locationId,
        layer: layerOf(t.locationId),
        verify: 'pending' as const,
        published: false,
      })),
      stageEnteredAt: now,
      events: [{ at: now, level: 'info', code: 'reprotect', detail: `stage ${stage}` }],
      actorAdminId,
      startedAt: now,
      updatedAt: now,
    });
    // The fence: only this run's own rotations touch the pool while it runs.
    await ctx.db.patch(relayId, { setupOwned: true, setupStage: stage, updatedAt: now });
    const run = (await ctx.db.get(id))!;
    await auditRun(
      ctx,
      run,
      'edge.setup_run.started',
      {
        stage,
        kind: 'reprotect',
        mode,
        listeners: requiredListeners.length,
        accountName: pickRows[0]!.account.name,
        provider: pickRows[0]!.account.provider,
        picks: pickRows.length,
        targets: targets.length,
        approvedHides: 0,
        keepDirect: false,
      },
      actorAdminId,
    );
    await scheduleStep(ctx, id, 0);
    return { runId: id, stage };
  }
}

// --- reconcile: crash safety ------------------------------------------------------------------------

/**
 * Runs whose scheduled step never ran (crashed action) or whose expected
 * rotation already ended without the hook landing. Same rule as the rotation
 * `listStale`: overdue and never started, or started too long ago.
 */
export const listStale = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const out: Array<{
      runId: Id<'edgeSetupRuns'>;
      kind: 'rekick' | 'hook';
      rotationId?: Id<'edgeRotations'>;
      generation?: number;
    }> = [];
    for (const state of ['running', 'waiting'] as const) {
      const rows = await ctx.db
        .query('edgeSetupRuns')
        .withIndex('by_state', (q) =>
          q.eq('state', state).lt('updatedAt', now - STALE_KICK_GRACE_MS),
        )
        .take(50);
      for (const r of rows) {
        if (r.expect) {
          const rot = await ctx.db.get(r.expect.rotationId);
          if (rot && isTerminalPhase(rot.phase))
            out.push({
              runId: r._id,
              kind: 'hook',
              rotationId: rot._id,
              generation: r.expect.generation,
            });
          continue;
        }
        if (r.nextStepAt === undefined || r.nextStepAt >= now - STALE_KICK_GRACE_MS) continue;
        const started = r.stepStartedAt !== undefined && r.stepStartedAt >= r.nextStepAt;
        if (!started || r.stepStartedAt! < now - STALE_STARTED_MS)
          out.push({ runId: r._id, kind: 'rekick' });
      }
    }
    return out;
  },
});

export const rekick = internalMutation({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const r = await ctx.db.get(runId);
    if (!r || isTerminalRunState(r.state) || r.state === 'needs_you') return null;
    const now = Date.now();
    await ctx.db.patch(runId, {
      stepVersion: r.stepVersion + 1,
      stepStartedAt: undefined,
      events: appendRunEvent(r.events, { at: now, level: 'warn', code: 'rekicked' }),
      updatedAt: now,
    });
    await scheduleStep(ctx, runId, 0);
    return null;
  },
});

/** Called by the reconcile cron: re-kick stale runs, re-fire missed terminal hooks. */
export async function setupRunsPass(ctx: ActionCtx): Promise<{ rekicked: number; hooked: number }> {
  const stale = await ctx.runQuery(internal.edgeSetupRuns.listStale, { now: Date.now() });
  let rekicked = 0;
  let hooked = 0;
  for (const s of stale) {
    if (s.kind === 'rekick') {
      await ctx.runMutation(internal.edgeSetupRuns.rekick, { runId: s.runId });
      rekicked++;
    } else if (s.rotationId && s.generation !== undefined) {
      await ctx.runMutation(internal.edgeSetupRuns.onRotationTerminal, {
        runId: s.runId,
        rotationId: s.rotationId,
        generation: s.generation,
      });
      hooked++;
    }
  }
  return { rekicked, hooked };
}
