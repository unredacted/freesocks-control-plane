/**
 * Guided setup ("Autopilot") runs: protect a panel node with edges by walking
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
 *  - `relays.setupOwned` is set at stage 1 and cleared ONLY by go-live (or by
 *    removal): a failed / cancelled / unbound run leaves the relay owned, so
 *    reconcile upkeep and the detector keep their hands off it;
 *  - members keep receiving the raw origin body through stage 5; from stage 6
 *    (hides) they depend on the edge; stage 8 binds in ONE mutation after
 *    re-checking everything stage 7 rehearsed.
 *
 * The other agents' work (Host hides, restore, test links, rehearsal, the
 * qualification credential) is reached ONLY through `stageOps`, a seam the
 * tests replace (`__setStageOpsForTests`); the defaults call the internal
 * functions by name.
 */
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
  edgeMs,
  resolveEdgeConfig,
  type EdgeConfig,
} from './lib/edgeConfig';
import { startRotation } from './edgeRotations';
import {
  claimDeliveryBinding,
  liveEdgesOfRelay,
  relayForBackendNode,
  scheduleMirrorRefresh,
} from './relays';
import { confirmEndpoint } from './edgeVerification';
import { listenersOf } from './relayListeners';
import { accountTested } from './edgeProviderAccounts';
import { isTerminalPhase } from './lib/edges/rotation';
import { admitted } from './lib/edges/maintenance';
import {
  needsEndpointVerification,
  verificationBinding,
  verificationCurrent,
} from './lib/edges/verification';
import { partialRungFor } from './lib/edges/verifyRung';
import { edgeLayerOf, providerHealthSatisfies } from './lib/edges/providers/capabilities';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import { parseIntent } from './lib/edges/intent';
import { fnv1a64Hex, listenerConfigHash, validateListenerSpec } from './lib/edges/registration';
import type { ListenerSpecInput } from './lib/edges/registration';
import { MAX_DESIRED_PUBLISHED } from './lib/edgeConfig';
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
  type SetupPlanSnapshot,
  type SetupVector,
} from './lib/edges/setupRuns';
import { SETUP_RUN_STAGES, type SetupRunStage } from '../src/shared/contracts/edgeCodes';
import type { HideResult, HideStatus } from './edgeHostHides';
import type { RehearsalResult } from './edgeRehearsal';
import type { TestLinkResult } from './edgeTestLinks';
import { activatingRunFor, promoteCandidate } from './panelActivation';

type Run = Doc<'edgeSetupRuns'>;
type Relay = Doc<'relays'>;
type Edge = Doc<'edges'>;
type Listener = Doc<'relayListeners'>;
type RunListener = Run['listeners'][number];

/** How long stage 4 waits for outside evidence before it asks the operator. */
const VERIFY_TIMEOUT_MS = 15 * 60_000;
/** A run whose scheduled step never ran (crashed action) is re-kicked after this. */
const STALE_KICK_GRACE_MS = 30_000;
const STALE_STARTED_MS = 10 * 60_000;
/** Edge statuses that count as "this listener has a live candidate". */
const LIVE_CANDIDATE: ReadonlySet<string> = new Set([
  'planning',
  'provisioning',
  'verifying',
  'standby',
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
  layer: v.union(v.literal('l4'), v.literal('l7')),
  edgeId: v.optional(v.id('edges')),
  verify: verifyV,
  published: v.boolean(),
  probeRequestedAt: v.optional(v.number()),
  proofRequestedAt: v.optional(v.number()),
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

export interface StageOps {
  ensureCredential(
    ctx: ActionCtx,
    a: { relayId: Id<'relays'>; purpose: 'qualification' | 'rehearsal' },
  ): Promise<{ ok: boolean; code?: string; reused: boolean }>;
  requestVerificationProbes(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<void>;
  runFrontProof(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<{ ok: boolean; code: string | null }>;
  buildTestLink(ctx: ActionCtx, edgeId: Id<'edges'>): Promise<TestLinkResult>;
  hideHosts(
    ctx: ActionCtx,
    a: { relayId: Id<'relays'>; runId: Id<'edgeSetupRuns'>; approvedUuids: string[] },
  ): Promise<HideResult>;
  hideStatus(ctx: QueryRunner, relayId: Id<'relays'>): Promise<HideStatus>;
  rehearse(
    ctx: ActionCtx,
    a: { relayId: Id<'relays'>; darkCohortKeys: string[] },
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
  runFrontProof: (ctx, edgeId) => ctx.runAction(internal.frontQualifyOps.run, { edgeId }),
  buildTestLink: (ctx, edgeId) => ctx.runAction(internal.edgeTestLinks.build, { edgeId }),
  hideHosts: (ctx, a) => ctx.runAction(internal.edgeHostHides.hide, a),
  hideStatus: (ctx, relayId) => ctx.runQuery(internal.edgeHostHides.status, { relayId }),
  rehearse: (ctx, a) => ctx.runAction(internal.edgeRehearsal.run, a),
  vectorNow: async (ctx, relayId) => {
    const v = await ctx.runQuery(internal.edgeRehearsal.vectorNow, { relayId });
    if (!v) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
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

/** The admin projection (`GET setup-runs/{id}`); never the plan's addresses beyond the origin the operator typed. */
export function mapRunAdmin(r: Run) {
  const plan = parsePlan(r);
  return {
    id: r._id as string,
    relayId: (r.relayId as string | undefined) ?? null,
    relaySlug: r.relaySlug,
    backendServerId: r.backendServerId as string,
    nodeName: r.nodeName,
    nodeUuid: r.nodeUuid,
    accountId: r.accountId as string,
    stage: r.stage,
    state: r.state,
    need: r.need ? { code: r.need.code, detail: r.need.detail ?? null } : null,
    generation: r.generation,
    planRevision: r.planRevision,
    keepDirect: r.keepDirect === true,
    listeners: r.listeners.map((l) => ({
      listenerKey: l.listenerKey,
      layer: l.layer,
      edgeId: (l.edgeId as string | undefined) ?? null,
      verify: l.verify,
      published: l.published,
    })),
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
    updatedAt: new Date(r.updatedAt).toISOString(),
    finishedAt: r.finishedAt ? new Date(r.finishedAt).toISOString() : null,
  };
}

// --- reads --------------------------------------------------------------------------------------------

export const get = internalQuery({
  args: { id: v.id('edgeSetupRuns') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

export const getForAdmin = internalQuery({
  args: { id: v.id('edgeSetupRuns') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    return r ? mapRunAdmin(r) : null;
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
    return { runs: out.map(mapRunAdmin), generatedAt: new Date().toISOString() };
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

export const activeForOrigin = internalQuery({
  args: { backendServerId: v.id('backendServers'), nodeName: v.string() },
  handler: (ctx, a) => activeRunForOrigin(ctx.db, a.backendServerId, a.nodeName),
});

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
  };
}

export const localVector = internalQuery({
  args: { relayId: v.id('relays') },
  handler: (ctx, { relayId }) => localVectorFor(ctx, relayId),
});

/**
 * The `partial` rung of an L4 standby from the probe evidence on record
 * (lib/edges/verifyRung.ts): outside reachability rows + the newest internal
 * shape run. `verified` is never produced here.
 */
export const rungFor = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return 'unreachable' as const;
    const listener = await ctx.db.get(edge.listenerId);
    if (!listener) return 'unreachable' as const;
    const cfg = await resolveEdgeConfig(ctx.db);
    const reach = await ctx.db
      .query('probeReachability')
      .withIndex('by_target_country', (q) => q.eq('targetKind', 'edge').eq('targetRef', edgeId))
      .collect();
    const runs = await ctx.db
      .query('probeRuns')
      .withIndex('by_target_requested', (q) => q.eq('targetKind', 'edge').eq('targetRef', edgeId))
      .order('desc')
      .take(30);
    return partialRungFor(listener, {
      providerHealthy: providerHealthSatisfies(
        edge.provider,
        edge.health,
        cfg.requireProviderHealth,
      ),
      reachability: reach.map((r) => ({
        country: r.country,
        source: r.source,
        verdict: r.verdict,
        port: r.port,
      })),
      probeRuns: runs.map((r) => ({
        source: r.source,
        status: r.status,
        probeProtocol: r.probeProtocol,
        results: r.results,
        requestedAt: r.requestedAt,
      })),
      agreementVantages: cfg.probe.agreementVantages,
    });
  },
});

/** What the stages need to know about the relay in one read. */
export const relayContext = internalQuery({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const run = await ctx.db.get(runId);
    if (!run?.relayId) return null;
    const relay = await ctx.db.get(run.relayId);
    if (!relay) return null;
    const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired);
    const edges = await liveEdgesOfRelay(ctx.db, relay._id);
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    return {
      relay,
      listeners,
      edges,
      cfg,
      verification: Object.fromEntries(
        run.listeners.map((rl) => {
          const l = listeners.find((x) => x.listenerKey === rl.listenerKey);
          const e = rl.edgeId ? edges.find((x) => x._id === rl.edgeId) : undefined;
          return [
            rl.listenerKey,
            {
              current: !!l && !!e && (!needsEndpointVerification(e) || verificationCurrent(e, l)),
              proofOk: !!e && l7ProofCurrent(e, l ?? null, now),
              published: !!l && !!e && l.templateEdgeId === e._id && e.publication === 'published',
              live: !!e && LIVE_CANDIDATE.has(e.status),
            },
          ];
        }),
      ) as Record<
        string,
        { current: boolean; proofOk: boolean; published: boolean; live: boolean }
      >,
    };
  },
});

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
 * the account). A relay a previous run left `setupOwned` is reused: the new
 * run (generation 1 of its own row) resumes at the relay's recorded stage.
 */
export const insert = internalMutation({
  args: {
    plan: v.string(),
    planHash: v.string(),
    accountId: v.id('edgeProviderAccounts'),
    approvedHideUuids: v.array(v.string()),
    keepDirect: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const plan = JSON.parse(a.plan) as SetupPlanSnapshot;
    const backendServerId = plan.backendServerId as Id<'backendServers'>;
    const active = await activeRunForOrigin(ctx.db, backendServerId, plan.nodeName);
    if (active)
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run already owns this node',
      });
    const account = await ctx.db.get(a.accountId);
    if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
    const offered = plan.accounts.find((x) => x.id === (a.accountId as string));
    if (!offered?.compatible)
      throw new ConvexError({
        code: 'edge.account_incompatible',
        message: 'The account cannot front this node',
      });
    const now = Date.now();
    let relayId: Id<'relays'> | undefined;
    let stage: SetupRunStage = 'prepare';
    let slug = plan.relaySlug;
    if (plan.existingRelay) {
      const relay = await ctx.db.get(plan.existingRelay.id as Id<'relays'>);
      if (relay && relay.setupOwned && !relay.deleting) {
        // The relay's listeners must still be what the new plan discovered:
        // an inbound added, removed or changed on the panel since the previous
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
        // A recorded terminal stage resumes at go_live (the relay is still owned).
        if (stage === 'done') stage = 'go_live';
      }
    }
    const layer = edgeLayerOf(account.provider);
    const id = await ctx.db.insert('edgeSetupRuns', {
      relayId,
      relaySlug: slug,
      backendServerId,
      nodeName: plan.nodeName,
      nodeUuid: plan.nodeUuid,
      accountId: a.accountId,
      plan: a.plan,
      planHash: a.planHash,
      planRevision: 1,
      approvedHideUuids: a.approvedHideUuids,
      keepDirect: a.keepDirect === true ? true : undefined,
      stage,
      state: 'running',
      generation: 1,
      stepVersion: 1,
      listeners: plan.requiredListeners.map((listenerKey) => ({
        listenerKey,
        layer,
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
        accountName: account.name,
        provider: account.provider,
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
 * terminal failure; mirrors the stage onto `relays.setupStage`; schedules the
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
    if (a.scheduleMs !== undefined && !terminal && a.state !== 'needs_you')
      await scheduleStep(ctx, r._id, a.scheduleMs);
    return { ok: true as const };
  },
});

function verdictsOf(run: Run): string {
  return run.listeners.map((l) => `${l.listenerKey}:${l.verify}`).join(',');
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
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.runId, a.stepVersion);
    if (!r || !r.relayId) return { ok: false as const, code: 'stale' };
    const listener = (await listenersOf(ctx, r.relayId)).find(
      (l) => l.listenerKey === a.listenerKey && !l.retired,
    );
    const entry = r.listeners.find((l) => l.listenerKey === a.listenerKey);
    if (!listener || !entry) return { ok: false as const, code: 'listener_not_found' };
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    const next = r.stepVersion + 1;
    try {
      const { rotationId } = await startRotation(ctx, {
        relayId: r.relayId,
        kind: a.kind,
        trigger: 'api',
        listenerId: listener._id,
        ...(a.kind === 'provision'
          ? {
              requestedAccountId: r.accountId,
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
        await scheduleStep(ctx, r._id, edgeMs.poll(cfg));
        return { ok: false as const, code };
      }
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
      else
        await auditRun(ctx, after, 'edge.setup_run.finished', {
          outcome: 'failed',
          stage: r.stage,
          code,
          verdicts: verdictsOf(after),
        });
      return { ok: false as const, code };
    }
  },
});

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
    const entryIdx = r.listeners.findIndex((l) => l.listenerKey === key);
    const listeners = r.listeners.map((l) => ({ ...l }));
    const base = { expect: undefined, stepVersion: next, updatedAt: now };
    const outcome = rot.outcome ?? rot.phase;
    if (rot.phase === 'done' && rot.kind === 'provision' && rot.toEdgeId && entryIdx >= 0) {
      listeners[entryIdx].edgeId = rot.toEdgeId;
      listeners[entryIdx].verify = 'pending';
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
    // Anything else is an interruption at this stage.
    const need =
      rot.phase === 'done' && rot.kind === 'publish'
        ? { code: 'coverage_incomplete', detail: `${key}: ${outcome}` }
        : rot.phase === 'quarantined'
          ? { code: 'quarantined', detail: rot.events.at(-1)?.detail }
          : { code: 'provider_failed', detail: `${key ?? ''}: ${outcome}`.trim() };
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
        detail: `${key ?? ''}: ${outcome}`.trim(),
      }),
    });
    const after = (await ctx.db.get(runId))!;
    if (state === 'needs_you')
      await auditRun(ctx, after, 'edge.setup_run.needs_operator', {
        stage: r.stage,
        code: need.code,
      });
    else
      await auditRun(ctx, after, 'edge.setup_run.finished', {
        outcome: 'failed',
        stage: r.stage,
        code: outcome,
        verdicts: verdictsOf(after),
      });
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
    scheduleMs: edgeMs.poll(cfg),
    ...patch,
  });
}

// --- stage 1: prepare -----------------------------------------------------------------------------------

async function stagePrepare(ctx: ActionCtx, run: Run): Promise<null> {
  const plan = parsePlan(run);
  const ctxRow = await ctx.runQuery(internal.edgeSetupRuns.prepareContext, { runId: run._id });
  if (!ctxRow.admitted) return needsYou(ctx, run, 'maintenance');
  if (!ctxRow.account) return needsYou(ctx, run, 'account_incompatible', 'account_not_found');
  if (!ctxRow.accountTested) return needsYou(ctx, run, 'account_untested');
  if (!ctxRow.accountEnabled) return needsYou(ctx, run, 'account_incompatible', 'account_disabled');
  const offered = plan.accounts.find((a) => a.id === (run.accountId as string));
  if (!offered?.compatible)
    return needsYou(ctx, run, 'account_incompatible', offered?.reasons[0] ?? 'not_offered');
  let relayId = run.relayId;
  let relaySlug = run.relaySlug;
  if (!relayId) {
    // A relay a previous run left owned is reused; any other relay on the node refuses.
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
      const desired = Math.min(
        MAX_DESIRED_PUBLISHED,
        Math.max(ctxRow.desiredPublishedDefault, plan.requiredListeners.length),
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
  const layer = edgeLayerOf(ctxRow.account.provider);
  return advance(ctx, run, {
    relayId,
    relaySlug,
    listeners: run.listeners.map((l) => ({ ...l, layer })),
    event: { level: 'info', code: 'prepared', detail: relaySlug },
  });
}

export const prepareContext = internalQuery({
  args: { runId: v.id('edgeSetupRuns') },
  handler: async (ctx, { runId }) => {
    const run = (await ctx.db.get(runId))!;
    const account = await ctx.db.get(run.accountId);
    const cfg = await resolveEdgeConfig(ctx.db);
    const existing = run.relayId
      ? await ctx.db.get(run.relayId)
      : await relayForBackendNode(ctx.db, run.backendServerId, run.nodeName);
    return {
      admitted: await admitted(ctx.db),
      account: account ? { provider: account.provider, name: account.name } : null,
      accountTested: !!account && accountTested(account),
      accountEnabled: !!account && account.enabled,
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
  const listeners = run.listeners.map((l) => {
    const row = c.listeners.find((x) => x.listenerKey === l.listenerKey);
    const own = l.edgeId ? c.edges.find((e) => e._id === l.edgeId) : undefined;
    if (own && LIVE_CANDIDATE.has(own.status)) return { ...l };
    const reuse = row
      ? c.edges.find(
          (e) =>
            e.listenerId === row._id &&
            LIVE_CANDIDATE.has(e.status) &&
            (e.publication === 'unpublished' || e.publication === 'published') &&
            e.accountId === run.accountId,
        )
      : undefined;
    return { ...l, edgeId: reuse?._id, verify: 'pending' as const };
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
      if (c.verification[l.listenerKey]?.proofOk) {
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
    const rung = await ctx.runQuery(internal.edgeSetupRuns.rungFor, { edgeId: l.edgeId });
    if (rung === 'partial') {
      l.verify = 'partial';
      continue;
    }
    if (rung === 'unreachable') {
      l.verify = 'unreachable';
      return needsYou(ctx, run, 'address_unreachable', l.listenerKey, { listeners });
    }
    if (!l.probeRequestedAt) {
      await ops.requestVerificationProbes(ctx, l.edgeId);
      l.probeRequestedAt = now;
    } else if (now - l.probeRequestedAt > VERIFY_TIMEOUT_MS) {
      l.verify = 'unreachable';
      return needsYou(ctx, run, 'address_unreachable', `${l.listenerKey}:timeout`, { listeners });
    }
    waiting = waiting ?? l.listenerKey;
  }
  if (waiting) return waitPoll(ctx, run, c.cfg, `probes ${waiting}`, { listeners });
  return advance(ctx, run, { listeners });
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
    if (c.verification[l.listenerKey]?.current) continue;
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

async function stageTryIt(ctx: ActionCtx, run: Run): Promise<null> {
  const c = await relayContextOf(ctx, run);
  if (!c)
    return tr(ctx, run, {
      state: 'failed',
      need: { code: 'provider_failed', detail: 'relay_missing' },
    });
  const links = await pendingTestLinks(ctx, run, c);
  if (links.length === 0) {
    const listeners = run.listeners.map((l) =>
      l.layer === 'l4' && c.verification[l.listenerKey]?.current
        ? { ...l, verify: 'verified' as const }
        : l,
    );
    return advance(ctx, run, { listeners, testLinks: null });
  }
  return needsYou(ctx, run, 'try_it', `${links.length} endpoint(s)`, { testLinks: links });
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
    published: c.verification[l.listenerKey]?.published === true,
  }));
  const target = listeners.find((l) => !l.published);
  if (!target) {
    if (run.keepDirect)
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
  if (target.layer === 'l4' && !c.verification[target.listenerKey]?.current) {
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
  const stale = run.listeners.filter(
    (l) => l.layer === 'l4' && !c.verification[l.listenerKey]?.current,
  );
  if (stale.length > 0) {
    const links = await pendingTestLinks(ctx, run, c);
    return needsYou(ctx, run, 'try_it', `retest ${stale.map((l) => l.listenerKey).join(',')}`, {
      testLinks: links,
    });
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
  const res = await ops.rehearse(ctx, {
    relayId: run.relayId,
    darkCohortKeys: run.rehearsal?.darkCohortKeys ?? [],
  });
  if (res.familiesDisabled.length > 0)
    return needsYou(ctx, run, 'family_disabled', res.familiesDisabled[0]);
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
    // unsupported-only inbound set, so a member group whose whole body went
    // with them now receives nothing FCP can serve. That cohort is excluded
    // from the `serve` requirement (plan 1.6) instead of blocking go-live for
    // everyone else; it is derived from the bodies themselves, after the
    // hides, never guessed from squad membership. Any other failure stays a
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
  return advance(ctx, run, {
    rehearsal: rehearsalRecord(res, attempts, run),
    event: { level: 'info', code: 'rehearsed', detail: `attempt ${attempts}` },
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
 * A reused (still setup-owned) relay must carry exactly the listeners the new
 * plan discovered, at the same configuration: the required keys must exist,
 * non-retired, with the canonical hash of the plan's spec, and the relay must
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
      message: `The node's inbounds changed since this relay was set up (${[...new Set(changed)].join(', ')}); remove protection and start again`,
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
    // No FCP Host operation claimed on the relay; every required listener
    // published by its own edge; L7 proofs current; L4 confirmations current.
    const listeners = (await listenersOf(ctx, relay._id)).filter((l) => !l.retired);
    if (listeners.some((l) => l.host?.op)) return back('rehearse', 'host_op_claimed');
    for (const entry of r.listeners) {
      const l = listeners.find((x) => x.listenerKey === entry.listenerKey);
      const e = entry.edgeId ? await ctx.db.get(entry.edgeId) : null;
      if (!l || !e || l.templateEdgeId !== e._id || e.publication !== 'published')
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
      // Like a render.* config change: every enabled relay re-keys its cache.
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
        if (!act.run) return need('node_not_approved', act.intent.activation.stage);
        const edgeIds = r.listeners.map((l) => l.edgeId).filter((e): e is Id<'edges'> => !!e);
        const p = await promoteCandidate(ctx, act.run, { edgeIds });
        if (!p.ok) return need('node_not_approved', p.code);
      }
    }
    await claimDeliveryBinding(ctx, relay);
    await ctx.db.patch(relay._id, {
      setupOwned: undefined,
      setupStage: undefined,
      // The consented dark cohorts outlive the run: a later restore (remove
      // protection, release the requirement) must skip them or never pass.
      darkCohortKeys: r.rehearsal?.darkCohortKeys ?? [],
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
      events: appendRunEvent(r.events, { at: now, level: 'info', code: 'live' }),
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

// --- operator verbs: retry / continue / cancel ------------------------------------------------------

/**
 * Re-enter the CURRENT stage under a new generation (the old rotation's hook
 * becomes a no-op), reusing everything that exists. Options answer the card's
 * secondary buttons: `tryAnotherAddress` destroys the unreachable standby and
 * re-provisions that listener only; `acceptPartial` goes on with the rung as
 * it is; `accountId` names another compatible account.
 */
export const retry = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    tryAnotherAddress: v.optional(v.boolean()),
    acceptPartial: v.optional(v.boolean()),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.runId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (r.state === 'done' || r.state === 'done_unbound' || r.state === 'cancelled')
      throw new ConvexError({ code: 'edge.setup_run_finished', message: 'The run is finished' });
    if (r.state === 'running' || r.state === 'waiting')
      throw new ConvexError({ code: 'edge.setup_run_busy', message: 'The run is still working' });
    const now = Date.now();
    let stage = r.stage;
    let listeners = r.listeners.map((l) => ({ ...l }));
    if (a.accountId) {
      const plan = parsePlan(r);
      const offered = plan.accounts.find((x) => x.id === (a.accountId as string));
      if (!offered?.compatible)
        throw new ConvexError({
          code: 'edge.account_incompatible',
          message: 'Not a compatible account',
        });
      const account = await ctx.db.get(a.accountId);
      if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
      const layer = edgeLayerOf(account.provider);
      if (a.accountId !== r.accountId) {
        // Switching accounts only while nothing is published: a candidate of
        // the old account (its layer, its bill) is cancelled, never re-labelled,
        // and provisioning starts over for that listener.
        if (!SWITCHABLE_STAGES.has(r.stage))
          throw new ConvexError({
            code: 'edge.account_switch_late',
            message: 'The account can only change before anything is published',
          });
        for (const entry of listeners) {
          if (!entry.edgeId) continue;
          const e = await ctx.db.get(entry.edgeId);
          if (e && e.accountId === a.accountId) continue;
          if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
            await ctx.db.patch(e._id, {
              status: 'cancelled',
              statusChangedAt: now,
              updatedAt: now,
            });
          entry.edgeId = undefined;
          entry.verify = 'pending';
          entry.probeRequestedAt = undefined;
          entry.proofRequestedAt = undefined;
        }
        if (STAGE_INDEX[r.stage] > STAGE_INDEX.provision) stage = 'provision';
      }
      listeners = listeners.map((l) => ({ ...l, layer }));
    }
    const failedKey = r.need?.detail?.split(':')[0] ?? null;
    if (a.tryAnotherAddress && r.need?.code === 'try_it') {
      // "One of them does not work": every L4 candidate the operator has NOT
      // confirmed is destroyed and provisioned again (the card does not say
      // which line failed; a confirmed one is kept, its tick stands).
      for (const entry of listeners) {
        if (entry.layer !== 'l4' || !entry.edgeId) continue;
        const e = await ctx.db.get(entry.edgeId);
        if (e?.verification?.rung === 'verified') continue;
        if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
          await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
        entry.edgeId = undefined;
        entry.verify = 'pending';
        entry.probeRequestedAt = undefined;
        entry.proofRequestedAt = undefined;
      }
      stage = 'provision';
    } else if (a.tryAnotherAddress && r.need?.code === 'address_unreachable' && failedKey) {
      const entry = listeners.find((l) => l.listenerKey === failedKey);
      if (entry?.edgeId) {
        const e = await ctx.db.get(entry.edgeId);
        if (e && e.publication === 'unpublished' && LIVE_CANDIDATE.has(e.status))
          await ctx.db.patch(e._id, { status: 'cancelled', statusChangedAt: now, updatedAt: now });
        entry.edgeId = undefined;
        entry.verify = 'pending';
        entry.probeRequestedAt = undefined;
        entry.proofRequestedAt = undefined;
      }
      stage = 'provision';
    } else if (a.acceptPartial && r.need?.code === 'address_unreachable' && failedKey) {
      const entry = listeners.find((l) => l.listenerKey === failedKey);
      if (entry) entry.verify = 'partial';
    } else if (r.stage === 'verify') {
      for (const l of listeners) if (l.verify === 'unreachable') l.verify = 'pending';
    }
    await ctx.db.patch(r._id, {
      stage,
      state: 'running',
      need: undefined,
      expect: undefined,
      testLinks: undefined,
      generation: r.generation + 1,
      stepVersion: r.stepVersion + 1,
      listeners,
      ...(a.accountId ? { accountId: a.accountId } : {}),
      ...(stage !== r.stage ? { stageEnteredAt: now } : {}),
      finishedAt: undefined,
      events: appendRunEvent(r.events, {
        at: now,
        level: 'info',
        code: 'retry',
        detail: `generation ${r.generation + 1} at ${stage}`,
      }),
      updatedAt: now,
    });
    await scheduleStep(ctx, r._id, 0);
    return { ok: true as const, generation: r.generation + 1, stage };
  },
});

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
        const entry = listeners.find((l) => l.listenerKey === link.listenerKey);
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
      keepDirect = true;
      finishUnbound = true;
    } else {
      events.push({ at: now, level: 'info', code: 'resume', detail: r.stage });
    }
    if (finishUnbound) {
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
    let evs = r.events;
    for (const e of events) evs = appendRunEvent(evs, e);
    await ctx.db.patch(r._id, {
      stage,
      state: 'running',
      need: undefined,
      expect: undefined,
      listeners,
      approvedHideUuids: approved,
      planRevision,
      keepDirect,
      testedEndpoints,
      reviewDelta: undefined,
      generation: r.generation + 1,
      stepVersion: r.stepVersion + 1,
      events: evs,
      updatedAt: now,
    });
    await scheduleStep(ctx, r._id, 0);
    return { ok: true as const, state: 'running' as const, accountTrusted };
  },
});

/**
 * Cancel: before stage 5 nothing was published, so the relay is deleted
 * `restore-direct` (which cancels the live rotation, drains the standbys for
 * the reconcile destroy and lets the relay delete remove the credential);
 * stages 5-7 keep the published edges and run the restore workflow
 * (`edgeRestore.start`, purpose `cancel_setup`); after go-live there is no
 * cancel.
 */
export const cancel = internalAction({
  args: { runId: v.id('edgeSetupRuns'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { runId, actorAdminId }) => {
    const r = await ctx.runQuery(internal.edgeSetupRuns.get, { id: runId });
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Run not found' });
    if (isTerminalRunState(r.state) || r.stage === 'go_live' || r.stage === 'done')
      throw new ConvexError({
        code: 'edge.setup_run_finished',
        message: 'The run is past the point of cancellation',
      });
    let disposition: 'deleted' | 'restore' | 'none' = 'none';
    if (r.relayId && cancelDeletesRelay(r.stage)) {
      await ctx.runMutation(internal.relays.requestDelete, {
        id: r.relayId,
        disposition: 'restore-direct',
        actorAdminId,
      });
      disposition = 'deleted';
    } else if (r.relayId && cancelRestores(r.stage)) {
      await ops.restoreStart(ctx, {
        relayId: r.relayId,
        purpose: 'cancel_setup',
        actorAdminId,
        darkCohortKeys: r.rehearsal?.darkCohortKeys ?? [],
      });
      disposition = 'restore';
    }
    // A temporary test credential minted for this run expires now rather than
    // at its 24 h TTL (the sweep removes it; a relay delete releases too).
    if (r.relayId)
      await ctx.runMutation(internal.edgeTestCredentials.releaseForRelay, { relayId: r.relayId });
    await ctx.runMutation(internal.edgeSetupRuns.markCancelled, {
      runId,
      disposition,
      actorAdminId,
    });
    return { ok: true as const, disposition };
  },
});

export const markCancelled = internalMutation({
  args: {
    runId: v.id('edgeSetupRuns'),
    disposition: v.union(v.literal('deleted'), v.literal('restore'), v.literal('none')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { runId, disposition, actorAdminId }) => {
    const r = await ctx.db.get(runId);
    if (!r || isTerminalRunState(r.state)) return null;
    const now = Date.now();
    await ctx.db.patch(runId, {
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
      (await ctx.db.get(runId))!,
      'edge.setup_run.cancelled',
      { stage: r.stage, disposition },
      actorAdminId,
    );
    return null;
  },
});

// --- require-edges (the only other path to the binding) --------------------------------------------

/**
 * `POST relays/{id}/require-edges`: apply the SAME activation policy to a
 * deferred relay (a run that finished unbound, a failed run whose edges the
 * operator published by hand): every published L4 edge without a current
 * confirmation goes through the `try_it` card first (the response returns the
 * pending endpoints instead of binding), then stages 7-8 verbatim. Never a
 * shortcut: `claimDeliveryBinding` is reached only through stage 8.
 */
export const requireEdges = internalMutation({
  args: {
    relayId: v.id('relays'),
    accountId: v.optional(v.id('edgeProviderAccounts')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, accountId, actorAdminId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay || relay.deleting)
      throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    if (!relay.bindingDeferred)
      throw new ConvexError({
        code: 'edge.not_deferred',
        message: 'The relay already binds its origin',
      });
    if (!relay.enabled)
      throw new ConvexError({ code: 'edge.relay_disabled', message: 'Enable the relay first' });
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
        message: 'Only a panel-node relay',
      });
    const active = await activeRunForOrigin(ctx.db, relay.backendServerId, relay.nodeName);
    if (active)
      throw new ConvexError({
        code: 'edge.setup_run_active',
        message: 'A setup run owns this node',
      });
    const listeners = (await listenersOf(ctx, relayId)).filter(
      (l) => !l.retired && l.deployed && l.enabled,
    );
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
    const account =
      (accountId ? await ctx.db.get(accountId) : null) ??
      (await (async () => {
        const withAccount = edges.find((e) => e.accountId);
        return withAccount?.accountId ? ctx.db.get(withAccount.accountId) : null;
      })());
    if (!account)
      throw new ConvexError({
        code: 'validation',
        message: 'accountId is required for this relay',
      });
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
      accounts: [
        {
          id: account._id as string,
          name: account.name,
          provider: account.provider,
          layer: edgeLayerOf(account.provider),
          compatible: true,
          reasons: [],
        },
      ],
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
    // A relay left deferred by a cancel or a released requirement has its direct
    // Hosts back: the run re-enters at the Host review / hide stage, never
    // straight at the rehearsal (those origin entries would be `leak_detected`).
    const stage: SetupRunStage = pending.length > 0 ? 'try_it' : 'hide_direct_hosts';
    const id = await ctx.db.insert('edgeSetupRuns', {
      relayId,
      relaySlug: relay.slug,
      backendServerId: relay.backendServerId,
      nodeName: relay.nodeName,
      nodeUuid: plan.nodeUuid,
      accountId: account._id,
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
        accountName: account.name,
        provider: account.provider,
        approvedHides: 0,
        keepDirect: false,
      },
      actorAdminId,
    );
    if (pending.length === 0) await scheduleStep(ctx, id, 0);
    return { runId: id, stage, state: run.state, pending };
  },
});

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
