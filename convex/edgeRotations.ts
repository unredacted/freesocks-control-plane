/**
 * Relay ROTATION machine: the only path that provisions, publishes and replaces
 * edges with a template-Host flip. One rotation row per run; the origin holds
 * at most one active rotation.
 *
 *   select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
 *                                                           ↘ rolling_back → rolled_back | quarantined
 *   (failed / cancelled from the early phases)
 *
 * Contract (see docs/edges.md):
 *  - every DB change is an isolate mutation guarded by `stepVersion`; the `step`
 *    action (isolate) does one bounded unit of work per invocation and NEVER
 *    schedules itself: the mutation that records its outcome schedules the next
 *    step (mutation scheduling is transactional), and the reconcile cron re-kicks
 *    a rotation whose `nextStepAt` went stale (crashed action).
 *  - every external write (provider step, Host PATCH) is bracketed by an
 *    operation claim on the edge / rotation; an unsettled claim is re-observed
 *    (discover / list Hosts) before anything allocating or destroying runs again.
 *  - Hosts are observe-then-write: the plan is captured from the live list at the
 *    start of the flip; a planned Host that disappears or changes inbound is
 *    `hosts_changed`, which rolls back, never converges.
 *  - a rollback that cannot converge QUARANTINES the origin; nothing bypasses it.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, MutationCtx, QueryCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { sanitizeAuditPayload, writeAuditLog, type AuditEntry } from './lib/audit';
import { randomHex } from './lib/crypto';
import { resolveEdgeConfig, edgeMs, type EdgeConfig } from './lib/edgeConfig';
import {
  checkPublishable,
  liveEdgesOfAccount,
  liveEdgesOfRelay,
  poolListenersOf,
  refreshTemplateEdges,
  scheduleMirrorRefresh,
  todayKey,
} from './relays';
import { insertPlannedEdge } from './edges';
import { accountTested, dayKey } from './edgeProviderAccounts';
import { edgeResourceName } from './lib/edges/accountSettings';
import {
  matchSlotHosts,
  planFromMatches,
  diffHosts,
  rollbackTargetFor,
  sameAddress,
  type HostTarget,
} from './lib/edges/hosts';
import type { BackendHost } from './lib/backends/types';
import { allocatePoolIndex, withEdgeAt, withoutEdge } from './lib/edges/pool';
import { resolveTemplateFor } from './edgeTemplates';
import {
  appendEvent,
  isTerminalPhase,
  progressPercent,
  pickStandby,
  pickAccount,
  pickAccountAny,
  pickSlot,
  accountsForSlot,
  l7SelectionAllowed,
  CANCELLABLE_PHASES,
  ROLLBACK_ON_CANCEL_PHASES,
  ROTATION_PHASES,
  TERMINAL_PHASES,
  type RotationEvent,
} from './lib/edges/rotation';
import {
  protocolIsHttpTransport,
  protocolTransport,
  protocolUsesSni,
  type ListenerProto,
} from './lib/edges/protocols';
import { hostTargetFor, listenerLayers, zoneModeCarriesOrigin } from './lib/edges/layers';
import { activeNames, listenerRemark, listenersOf } from './relayListeners';
// The freshness window the DETECTOR scores on is the one this gate accepts
// evidence on: one rule, imported, never a second copy of "two intervals".
import { probeStaleAfterMs } from './lib/edges/scoring';
import { edgeHostnameFor } from './lib/edges/hostname';
import { publishAddressOf, hasPublishableAddress } from './lib/edges/ip';
import { verificationCurrent } from './lib/edges/verification';
import {
  buildProvisionIntent,
  IntentError,
  parseIntent,
  parseObservedSettings,
  type ProvisionIntent,
} from './lib/edges/intent';
import { qualificationBinding, qualificationVerdict } from './lib/edges/frontCheck/binding';
import {
  edgeLayerOf,
  providerHealthSatisfies,
  zoneModeGovernsOrigin,
} from './lib/edges/providers/capabilities';
import type {
  StepOutcome,
  Discovery,
  EdgeDescription,
  ResourceStep,
} from './lib/edges/providers/types';
import { admitted, assertAdmission } from './lib/edges/maintenance';

type Rotation = Doc<'edgeRotations'>;
type Edge = Doc<'edges'>;
type Origin = Doc<'relays'>;
type Phase = Rotation['phase'];

const MAX_STEP_RETRIES = 3;
const STALE_KICK_GRACE_MS = 30_000;
/** A step whose action began this long ago and never recorded an outcome is stale (Convex kills actions well before). */
const STALE_STARTED_MS = 10 * 60_000;
/** Unexpected throws in `step` before the run is failed / quarantined. */
export const MAX_STEP_ERRORS = 30;
/** Audit rows remembered per rotation (the trail also reads rows targeting the rotation itself). */
const MAX_AUDIT_IDS = 200;

/**
 * Every audit row a rotation produces goes through here: the allowlist is
 * applied exactly as in `writeAuditLog`, and the row id is remembered on the
 * rotation so `rotationAuditTrail` is complete instead of "the newest N rows".
 */
async function auditRotation(
  ctx: MutationCtx,
  rotationId: Id<'edgeRotations'>,
  entry: AuditEntry,
): Promise<void> {
  const { payload, ...rest } = entry;
  const id = await ctx.db.insert('auditLog', {
    ...rest,
    payload: sanitizeAuditPayload(entry.action, payload),
  });
  const r = await ctx.db.get(rotationId);
  if (!r) return;
  const ids = [...(r.auditIds ?? []), id];
  await ctx.db.patch(rotationId, {
    auditIds: ids.length > MAX_AUDIT_IDS ? ids.slice(ids.length - MAX_AUDIT_IDS) : ids,
  });
}

// --- row-field readers (with the event-log fallback for rows created before the fields) ----

/** Whether a forward Host write was ever CLAIMED (the panel may hold it even without a settle). */
function forwardWriteAttempted(r: Rotation): boolean {
  if (r.forwardWriteAttempted !== undefined) return r.forwardWriteAttempted;
  return !!r.flippedAt || r.events.some((e) => e.code === 'host_forward_written');
}

/** Whether the Host plan was captured from the live list (an empty captured plan is final). */
function hostPlanCaptured(r: Rotation): boolean {
  if (r.hostPlanCaptured !== undefined) return r.hostPlanCaptured;
  return r.hostPlan.length > 0 || r.events.some((e) => e.code === 'host_plan');
}

// --- admin mapping -----------------------------------------------------------------------

/** Whether a cancel request would be accepted now (`requestCancel`'s own rule, so the CMS never guesses). */
export function isCancellable(r: Pick<Rotation, 'phase' | 'cancelRequested'>): boolean {
  if (isTerminalPhase(r.phase) || r.cancelRequested) return false;
  return r.phase !== 'confirming' && r.phase !== 'finalizing' && r.phase !== 'rolling_back';
}

/** The key of the listener a run is for (null when it has none or the row is gone). */
export async function rotationListenerKey(
  db: QueryCtx['db'],
  r: Pick<Rotation, 'listenerId'>,
): Promise<string | null> {
  if (!r.listenerId) return null;
  return (await db.get(r.listenerId))?.listenerKey ?? null;
}

export function mapRotationAdmin(
  r: Rotation,
  edge: Edge | null,
  listenerKey: string | null = null,
) {
  const needsHostFlip =
    r.hostPlan.length > 0 || (r.previousBinding?.poolIndex === 0 && r.kind === 'replace');
  return {
    id: r._id as string,
    relayId: r.relayId as string,
    kind: r.kind,
    trigger: r.trigger,
    burn: r.burn,
    force: r.force,
    targetEdgeId: (r.targetEdgeId as string | undefined) ?? null,
    toEdgeId: (r.toEdgeId as string | undefined) ?? null,
    phase: r.phase,
    terminal: isTerminalPhase(r.phase),
    stepVersion: r.stepVersion,
    cancelRequested: r.cancelRequested,
    cancellable: isCancellable(r),
    listenerKey,
    outcome: r.outcome ?? null,
    reason: r.reason ?? null,
    steps: (edge?.steps ?? []).map((s) => ({
      stepId: s.stepId,
      kind: s.kind,
      state: s.state,
      startedAt: s.startedAt ? new Date(s.startedAt).toISOString() : null,
      finishedAt: s.finishedAt ? new Date(s.finishedAt).toISOString() : null,
    })),
    progress: {
      done: (edge?.steps ?? []).filter((s) => s.state === 'done').length,
      total: edge?.steps.length ?? 0,
      percent: progressPercent({
        phase: r.phase,
        stepStates: edge?.steps.map((s) => s.state),
        needsHostFlip,
      }),
    },
    events: r.events.map((e) => ({
      ...e,
      at: new Date(e.at).toISOString(),
      detail: e.detail ?? null,
    })),
    edge: edge
      ? {
          id: edge._id as string,
          provider: edge.provider ?? null,
          addresses: { v4: edge.addresses.v4 ?? null, v6: edge.addresses.v6 ?? null },
          health: edge.health,
          status: edge.status,
        }
      : null,
    hostPlanSize: r.hostPlan.length,
    flipAttempts: r.flipAttempts,
    rollbackAttempts: r.rollbackAttempts,
    startedAt: new Date(r.startedAt).toISOString(),
    provisionedAt: r.provisionedAt ? new Date(r.provisionedAt).toISOString() : null,
    flippedAt: r.flippedAt ? new Date(r.flippedAt).toISOString() : null,
    finishedAt: r.finishedAt ? new Date(r.finishedAt).toISOString() : null,
    updatedAt: new Date(r.updatedAt).toISOString(),
  };
}

// --- reads --------------------------------------------------------------------------------

export const get = internalQuery({
  args: { id: v.id('edgeRotations') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

export const getForAdmin = internalQuery({
  args: { id: v.id('edgeRotations') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    const edge = r.toEdgeId ? await ctx.db.get(r.toEdgeId) : null;
    return {
      ...mapRotationAdmin(r, edge, await rotationListenerKey(ctx.db, r)),
      audit: await rotationAuditTrail(ctx, r),
    };
  },
});

/**
 * Every audit row this rotation produced, oldest first: rows targeting the
 * rotation itself, plus the rows the run remembered by id (`auditIds`: the
 * operator's request, publish/unpublish, rotated, burned, quarantine and its
 * resolution). Rows created before `auditIds` existed fall back to scanning the
 * relay's and edges' newest rows for a matching `rotationId` payload
 * (`auditLog.payload` is untyped, so it cannot be indexed).
 */
async function rotationAuditTrail(ctx: QueryCtx, r: Rotation) {
  const id = r._id as string;
  const own = await ctx.db
    .query('auditLog')
    .withIndex('by_target', (q) => q.eq('targetType', 'edge_rotation').eq('targetId', id))
    .order('desc')
    .take(100);
  const related: Array<Doc<'auditLog'>> = [];
  if (r.auditIds) {
    for (const auditId of r.auditIds) {
      const row = await ctx.db.get(auditId);
      if (row) related.push(row);
    }
  } else {
    const scan = async (targetType: string, targetId: string, take: number) => {
      const rows = await ctx.db
        .query('auditLog')
        .withIndex('by_target', (q) => q.eq('targetType', targetType).eq('targetId', targetId))
        .order('desc')
        .take(take);
      for (const row of rows) {
        const p = row.payload as { rotationId?: unknown } | undefined;
        if (p && typeof p === 'object' && p.rotationId === id) related.push(row);
      }
    };
    await scan('relay', r.relayId as string, 300);
    for (const e of [r.toEdgeId, r.targetEdgeId]) if (e) await scan('edge', e as string, 100);
  }
  const seen = new Set<string>();
  const all = [...own, ...related]
    .filter((row) => (seen.has(row._id) ? false : (seen.add(row._id), true)))
    .sort((a, b) => a._creationTime - b._creationTime);
  return all.map((row) => ({
    id: row._id as string,
    actorType: row.actorType,
    actorId: row.actorId ?? null,
    action: row.action,
    targetType: row.targetType ?? null,
    targetId: row.targetId ?? null,
    payload: row.payload ?? null,
    requestId: row.requestId ?? null,
    createdAt: new Date(row._creationTime).toISOString(),
  }));
}

export const listByRelay = internalQuery({
  args: { relayId: v.id('relays'), take: v.optional(v.number()) },
  handler: async (ctx, { relayId, take }) => {
    const rows = await ctx.db
      .query('edgeRotations')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .order('desc')
      .take(Math.min(take ?? 20, 100));
    const out = [];
    for (const r of rows)
      out.push(
        mapRotationAdmin(
          r,
          r.toEdgeId ? await ctx.db.get(r.toEdgeId) : null,
          await rotationListenerKey(ctx.db, r),
        ),
      );
    return out;
  },
});

export async function countActiveRotations(ctx: {
  db: import('./_generated/server').DatabaseReader;
}): Promise<number> {
  let n = 0;
  for (const phase of ROTATION_PHASES) {
    if ((TERMINAL_PHASES as readonly string[]).includes(phase)) continue;
    const rows = await ctx.db
      .query('edgeRotations')
      .withIndex('by_phase', (q) => q.eq('phase', phase))
      .take(200);
    n += rows.length;
  }
  return n;
}

/**
 * A rotation is stale when its step was scheduled more than the grace ago AND
 * never started (`stepStartedAt` predates the schedule), or when it started
 * more than STALE_STARTED_MS ago without recording an outcome (a crashed or
 * killed action). Rows without `stepStartedAt` (older runs) count as not started.
 */
export function isStaleRotation(
  r: Pick<Rotation, 'nextStepAt' | 'stepStartedAt'>,
  now: number,
): boolean {
  if (r.nextStepAt === undefined || r.nextStepAt >= now - STALE_KICK_GRACE_MS) return false;
  const started = r.stepStartedAt !== undefined && r.stepStartedAt >= r.nextStepAt;
  if (!started) return true;
  return r.stepStartedAt! < now - STALE_STARTED_MS;
}

/** Non-terminal rotations whose next step is overdue (crashed action): reconcile re-kicks them. */
export const listStale = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const out: Id<'edgeRotations'>[] = [];
    for (const phase of ROTATION_PHASES) {
      if ((TERMINAL_PHASES as readonly string[]).includes(phase)) continue;
      const rows = await ctx.db
        .query('edgeRotations')
        .withIndex('by_phase', (q) =>
          q.eq('phase', phase).lt('nextStepAt', now - STALE_KICK_GRACE_MS),
        )
        .take(50);
      for (const r of rows) if (isStaleRotation(r, now)) out.push(r._id);
    }
    return out;
  },
});

// --- start / cancel -----------------------------------------------------------------------

async function scheduleStep(ctx: MutationCtx, rotationId: Id<'edgeRotations'>, delayMs: number) {
  await ctx.scheduler.runAfter(delayMs, internal.edgeRotations.step, { rotationId });
  await ctx.db.patch(rotationId, { nextStepAt: Date.now() + delayMs });
}

const startArgs = {
  relayId: v.id('relays'),
  kind: v.union(v.literal('provision'), v.literal('publish'), v.literal('replace')),
  trigger: v.union(
    v.literal('manual'),
    v.literal('detector'),
    v.literal('api'),
    v.literal('reconcile'),
  ),
  burn: v.optional(v.boolean()),
  force: v.optional(v.boolean()),
  /** Waives ONLY the affected-country evidence gate (audited); never the transport proof. */
  forceGeoEvidence: v.optional(v.boolean()),
  targetEdgeId: v.optional(v.id('edges')),
  toEdgeId: v.optional(v.id('edges')),
  listenerId: v.optional(v.id('relayListeners')),
  publishOnDone: v.optional(v.boolean()),
  /** The explicit bootstrap provision (`test-provision`): a named account (+ template); may be unqualified. */
  requestedAccountId: v.optional(v.id('edgeProviderAccounts')),
  requestedTemplateId: v.optional(v.id('edgeTemplates')),
  allowUnqualified: v.optional(v.boolean()),
  reason: v.optional(v.string()),
  actorAdminId: v.optional(v.id('adminUsers')),
  /** The guided setup run starting this rotation (+ its generation, reported by the terminal hook). */
  setupRun: v.optional(v.object({ runId: v.id('edgeSetupRuns'), generation: v.number() })),
  /** `setup.complete`: a setup run finishing admitted work; passes a maintenance freeze (needs `setupRun`). */
  admission: v.optional(v.literal('setup.complete')),
};

export interface StartRotationArgs {
  relayId: Id<'relays'>;
  kind: 'provision' | 'publish' | 'replace';
  trigger: 'manual' | 'detector' | 'api' | 'reconcile';
  burn?: boolean;
  force?: boolean;
  forceGeoEvidence?: boolean;
  targetEdgeId?: Id<'edges'>;
  toEdgeId?: Id<'edges'>;
  listenerId?: Id<'relayListeners'>;
  publishOnDone?: boolean;
  requestedAccountId?: Id<'edgeProviderAccounts'>;
  requestedTemplateId?: Id<'edgeTemplates'>;
  allowUnqualified?: boolean;
  reason?: string;
  actorAdminId?: Id<'adminUsers'>;
  setupRun?: { runId: Id<'edgeSetupRuns'>; generation: number };
  admission?: 'setup.complete';
}

/** One reason a start is refused: the code `startRotation` throws (`edge.*`, `validation`, `not_found`) + its message. */
export interface StartBlocker {
  code: string;
  message: string;
}

/**
 * Every guard `startRotation` applies, evaluated WITHOUT throwing and without
 * writing: the preflight returns them all, a real start throws the first. The
 * order here IS the order the start checks in (a test pins that the first
 * blocker equals the thrown code). A check that depends on an earlier one that
 * failed is skipped rather than reported twice.
 */
export async function collectStartBlockers(
  ctx: { db: QueryCtx['db'] },
  a: StartRotationArgs,
  opts: { now?: number } = {},
): Promise<{
  blockers: StartBlocker[];
  origin: Origin | null;
  cfg: EdgeConfig | null;
  targetEdge: Edge | null;
  listenerId: Id<'relayListeners'> | undefined;
}> {
  const blockers: StartBlocker[] = [];
  const push = (code: string, message: string) => blockers.push({ code, message });
  const origin = await ctx.db.get(a.relayId);
  if (!origin) {
    push('not_found', 'Origin not found');
    return { blockers, origin: null, cfg: null, targetEdge: null, listenerId: a.listenerId };
  }
  const cfg = await resolveEdgeConfig(ctx.db);
  const now = opts.now ?? Date.now();
  const force = a.force ?? false;
  // Admission gate: a start of ANY kind is new work; completion paths (step,
  // rekick, rollback, cancel, unpublish, destroy) never route through here.
  if (!(await admitted(ctx.db))) push('edge.maintenance', 'Edges are in maintenance');
  if (origin.quarantine) push('edge.quarantined', 'Origin is quarantined; resolve it first');
  // A restore workflow's raw-body checks assume the pool holds still: no start
  // of any kind while it runs (the same rule every pool / listener write applies).
  if (origin.restore)
    push('edge.restore_in_progress', 'A restore workflow is running on this origin');
  // A guided setup owns the relay until go-live: only the run's own starts
  // (`setupRun`) touch its pool; a manual publish / replace / burn meanwhile
  // would change the endpoint under the run's hides and rehearsal.
  if (origin.setupOwned && !a.setupRun)
    push('edge.setup_owned', 'A guided setup owns this origin; let it finish or cancel it');
  if (origin.deleting) push('edge.deleting', 'Origin is being deleted');
  if (origin.activeRotationId) {
    const active = await ctx.db.get(origin.activeRotationId);
    if (active && !isTerminalPhase(active.phase))
      push('edge.busy', 'A rotation is already running');
  }
  if (a.trigger === 'detector' && !(cfg.enabled && cfg.autoRotate && origin.autoRotate)) {
    push('edge.auto_rotate_disabled', 'Automatic rotation is not enabled for this origin');
  }
  if ((await countActiveRotations(ctx)) >= cfg.maxConcurrentRotations) {
    push('edge.concurrency', 'Too many rotations in flight');
  }
  let targetEdge: Edge | null = null;
  let listenerId: Id<'relayListeners'> | undefined = a.listenerId;
  if (a.kind === 'replace') {
    if (!a.targetEdgeId) push('validation', 'targetEdgeId is required');
    else {
      targetEdge = await ctx.db.get(a.targetEdgeId);
      if (
        !targetEdge ||
        targetEdge.relayId !== a.relayId ||
        targetEdge.publication !== 'published'
      ) {
        push('edge.target_not_published', 'The target edge is not published on this origin');
        targetEdge = null;
      }
    }
    if (targetEdge) {
      if (origin.hostMode === 'operator' && (await isTemplateEdge(ctx, targetEdge)) && !force) {
        push(
          'edge.hosts_operator_managed',
          'The operator manages this relay\u2019s panel Hosts; replacing a template edge needs force',
        );
      }
    }
    if (!force) {
      if (origin.cooldownUntil && origin.cooldownUntil > now)
        push('edge.cooldown', 'Origin is cooling down');
      const today = todayKey(now);
      const used = origin.rotationsDayKey === today ? origin.rotationsToday : 0;
      if (used >= origin.maxRotationsPerDay) push('edge.daily_cap', 'Daily rotation cap reached');
    }
    if (targetEdge) listenerId = targetEdge.listenerId;
    // Replacing an L4 edge switches ONLY to an already-tested spare: a freshly
    // provisioned L4 candidate could never pass the publication gate (an L4
    // endpoint needs the operator's own confirmation, lib/edges/verification.ts),
    // so a replace that would have to provision is refused here instead of
    // paying for a doomed candidate. An L7 replace keeps its proof-based path.
    // Not waived by `force`: verification is evidence, not a guard. When the
    // listener can be fronted at L7 and the selection may pick an L7 account,
    // the replacement may be a NEW front proven by its own session, so the
    // start is not refused; an L4 pick then lands as an untested spare
    // (`unverified_standby` in applyPublish), never in the pool.
    if (targetEdge && (targetEdge.layer ?? edgeLayerOf(targetEdge.provider)) !== 'l7') {
      const targetListener = await ctx.db.get(targetEdge.listenerId);
      const couldGoL7 =
        !!targetListener &&
        listenerLayers(targetListener).layers.includes('l7') &&
        (a.trigger === 'manual' || l7SelectionAllowed(cfg));
      if (!couldGoL7 && !(await verifiedSpareFor(ctx, origin, targetEdge, cfg))) {
        push(
          'edge.no_verified_spare',
          'No tested spare address exists for this listener; test a spare first',
        );
      }
    }
  }
  if (a.kind === 'publish') {
    if (!a.toEdgeId) push('validation', 'toEdgeId is required');
    else {
      const to = await ctx.db.get(a.toEdgeId);
      if (!to || to.relayId !== a.relayId) push('not_found', 'Edge not found on this origin');
      else {
        const check = await checkPublishable(ctx, to, false);
        if (!check.ok) push(`edge.${check.code}`, `Edge cannot be published: ${check.code}`);
        listenerId = to.listenerId;
      }
    }
  }
  if (a.kind === 'provision' && a.requestedAccountId && !a.listenerId) {
    push('validation', 'listenerId is required for an explicit account');
  }
  if (listenerId) {
    const listener = await ctx.db.get(listenerId);
    if (!listener || listener.relayId !== a.relayId || listener.retired) {
      push(
        'edge.listener_not_found',
        'The requested listener does not exist on this relay or is retired',
      );
    } else {
      // A name-free HTTP-transport listener is usable: behind an L7 front the
      // member presents the edge HOSTNAME. It is only L4 that needs one of the
      // listener's own names, and `listenerLayers` already excludes L4 for it.
      const usable =
        listener.deployed &&
        listener.enabled &&
        (!protocolUsesSni(listener) ||
          protocolIsHttpTransport(listener) ||
          activeNames(listener).length > 0);
      if (!usable) {
        push(
          'edge.listener_unusable',
          'The listener is not deployed, is disabled, or has no server name',
        );
      }
      // An L7-ONLY listener cannot be answered automatically while the L7 gate
      // is off: the run would have nothing compatible to pick, and silently
      // routing it to an L4 account would front a plaintext origin with a raw
      // forwarder. The veto is explicit so the operator sees why nothing happened.
      if (a.trigger === 'detector') {
        const layers = listenerLayers(listener).layers;
        if (layers.length === 1 && layers[0] === 'l7' && !l7SelectionAllowed(cfg)) {
          push(
            'edge.l7_auto_select_disabled',
            'Automatic selection of L7 edges is disabled; publish this listener by hand',
          );
        }
      }
    }
  }
  // A new CDN hostname is not a new frontend IP (shared anycast), so repeated
  // automatic L7 replacements on one relay are bounded per day.
  if (a.trigger === 'detector' && a.kind === 'replace' && targetEdge && !force) {
    if ((targetEdge.layer ?? 'l4') === 'l7') {
      const used =
        origin.l7ReplacementsDayKey === todayKey(now) ? (origin.l7ReplacementsToday ?? 0) : 0;
      if (used >= cfg.l7.maxSameProviderReplacementsPerDay) {
        push('edge.l7_replacement_cap', 'Daily cap on L7 replacements for this relay reached');
      }
    }
  }
  return { blockers, origin, cfg, targetEdge, listenerId };
}

export const start = internalMutation({
  args: startArgs,
  handler: (ctx, a) => startRotation(ctx, a),
});

/**
 * Whether the target's listener holds a spare the machine could switch to
 * WITHOUT provisioning: an active, unpublished edge on the same listener that
 * passes the whole publication gate (for an L4 edge that includes a current
 * operator confirmation). Read-only; the selection applies the same rule
 * through `standbyEligible`.
 */
async function verifiedSpareFor(
  ctx: { db: QueryCtx['db'] },
  origin: Origin,
  targetEdge: Edge,
  cfg: EdgeConfig,
): Promise<boolean> {
  const edges = await liveEdgesOfRelay(ctx.db, origin._id);
  for (const e of edges) {
    if (e._id === targetEdge._id || e.listenerId !== targetEdge.listenerId) continue;
    if (e.status !== 'active' || e.publication !== 'unpublished') continue;
    // The same health rule `pickStandby` applies (an observe-only import with
    // no provider is not a candidate the selection would take).
    if (!providerHealthSatisfies(e.provider, e.health, cfg.requireProviderHealth)) continue;
    if ((await checkPublishable(ctx, e, cfg.requireProviderHealth)).ok) return true;
  }
  return false;
}

/**
 * The publication gate's verification rule applied to a standby candidate: an
 * L7 edge is judged by its proof at publish time; an L4 edge is a candidate
 * only with a CURRENT operator confirmation (an untested spare is never picked
 * over provisioning, and never published by a rotation).
 */
function standbyEligible(edge: Edge, listener: Doc<'relayListeners'> | undefined): boolean {
  if ((edge.layer ?? edgeLayerOf(edge.provider)) === 'l7') return true;
  return !!listener && verificationCurrent(edge, listener);
}

/** Whether some listener's panel Host / plan points at this edge. */
async function isTemplateEdge(ctx: { db: QueryCtx['db'] }, edge: Edge): Promise<boolean> {
  const listener = await ctx.db.get(edge.listenerId);
  return !!listener && listener.templateEdgeId === edge._id;
}

/**
 * Whether publishing `to` (replacing `target`, when given) must flip the panel
 * Host: FCP owns the Hosts AND `to` becomes its listener's template edge (the
 * listener has none yet, or its current one is the edge being replaced).
 */
async function needsHostFlipFor(
  ctx: { db: MutationCtx['db'] },
  origin: Origin,
  to: Edge,
  target: Edge | null,
): Promise<boolean> {
  if (origin.hostMode !== 'fcp') return false;
  const listener = await ctx.db.get(to.listenerId);
  if (!listener) return false;
  if (!listener.templateEdgeId) return true;
  if (listener.templateEdgeId === to._id) return true;
  return !!target && listener.templateEdgeId === target._id;
}

/**
 * The ONLY way a rotation row comes into being (the `start` mutation and the
 * reconcile cron's standby publish both call this): every guard — quarantine,
 * deleting, one rotation per origin, the global concurrency cap, publishability,
 * slot usability — applies to every caller.
 */
export async function startRotation(
  ctx: MutationCtx,
  a: StartRotationArgs,
): Promise<{ rotationId: Id<'edgeRotations'> }> {
  const now = Date.now();
  const force = a.force ?? false;
  const g = await collectStartBlockers(ctx, a, { now });
  // A guided setup run finishing admitted work (its stage-5 publish, `setupRun`
  // + `admission: 'setup.complete'`) maps the maintenance refusal through the
  // completion kind: `assertAdmission` admits it while frozen, so the blocker
  // is dropped and the other guards still apply. Any other start keeps the
  // refusal (and its dated message).
  const setupCompletion = a.admission === 'setup.complete' && !!a.setupRun;
  let blockers = g.blockers;
  if (setupCompletion && blockers.some((b) => b.code === 'edge.maintenance')) {
    await assertAdmission(ctx.db, 'setup.complete');
    blockers = blockers.filter((b) => b.code !== 'edge.maintenance');
  }
  if (blockers.length > 0) {
    const first = blockers[0];
    // The maintenance gate throws its own (dated) message.
    if (first.code === 'edge.maintenance') await assertAdmission(ctx.db, 'rotation.start');
    throw new ConvexError({ code: first.code, message: first.message });
  }
  const origin = g.origin!;
  const listenerId = g.listenerId;
  const id = await ctx.db.insert('edgeRotations', {
    relayId: a.relayId,
    kind: a.kind,
    trigger: a.trigger,
    burn: a.burn ?? false,
    force,
    forceGeoEvidence: a.forceGeoEvidence === true ? true : undefined,
    publishOnDone: a.kind === 'provision' ? (a.publishOnDone ?? false) : undefined,
    targetEdgeId: a.targetEdgeId,
    toEdgeId: a.kind === 'publish' ? a.toEdgeId : undefined,
    listenerId,
    requestedAccountId: a.kind === 'provision' ? a.requestedAccountId : undefined,
    requestedTemplateId: a.kind === 'provision' ? a.requestedTemplateId : undefined,
    allowUnqualified: a.kind === 'provision' && a.allowUnqualified ? true : undefined,
    setupRun: a.setupRun,
    viaStandby: a.kind === 'publish' ? true : undefined,
    phase: 'select',
    stepVersion: 1,
    cancelRequested: false,
    reason: a.reason?.slice(0, 200),
    hostPlan: [],
    hostPlanCaptured: false,
    forwardWriteAttempted: false,
    flipAttempts: 0,
    rollbackAttempts: 0,
    pollAttempts: 0,
    stepErrors: 0,
    auditIds: [],
    events: [{ at: now, level: 'info', code: 'started', detail: `${a.kind} (${a.trigger})` }],
    actorAdminId: a.actorAdminId,
    startedAt: now,
    updatedAt: now,
  });
  const today = todayKey(now);
  await ctx.db.patch(a.relayId, {
    activeRotationId: id,
    ...(a.kind === 'replace'
      ? {
          rotationsDayKey: today,
          rotationsToday: (origin.rotationsDayKey === today ? origin.rotationsToday : 0) + 1,
        }
      : {}),
    updatedAt: now,
  });
  if (a.kind === 'provision' && a.allowUnqualified && a.requestedAccountId) {
    // The explicit bootstrap provision: audited by name, never by credential.
    const account = await ctx.db.get(a.requestedAccountId);
    const listener = listenerId ? await ctx.db.get(listenerId) : null;
    await auditRotation(ctx, id, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.edge.test_provision',
      targetType: 'relay',
      targetId: a.relayId,
      payload: {
        slug: origin.slug,
        listenerKey: listener?.listenerKey,
        accountName: account?.name,
        provider: account?.provider,
        rotationId: id,
      },
    });
  } else {
    await auditRotation(ctx, id, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action:
        a.kind === 'replace'
          ? a.burn
            ? 'admin.edge.burn'
            : 'admin.edge.rotate'
          : a.kind === 'publish'
            ? 'admin.edge.publish'
            : 'admin.edge.provision',
      targetType: 'relay',
      targetId: a.relayId,
      payload: {
        slug: origin.slug,
        trigger: a.trigger,
        force,
        forceGeoEvidence: a.forceGeoEvidence === true,
        rotationId: id,
        edgeId: a.kind === 'publish' ? a.toEdgeId : undefined,
      },
    });
  }
  await scheduleStep(ctx, id, 0);
  return { rotationId: id };
}

/**
 * Reconcile: a non-terminal rotation whose next step never ran (crashed action).
 * Bumps the step version so a stale actor that is somehow still alive has every
 * later write ignored by `guard` (fencing), then schedules a fresh step.
 */
export const rekick = internalMutation({
  args: { rotationId: v.id('edgeRotations') },
  handler: async (ctx, { rotationId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r || isTerminalPhase(r.phase)) return null;
    const now = Date.now();
    await ctx.db.patch(rotationId, {
      stepVersion: r.stepVersion + 1,
      stepStartedAt: undefined,
      events: appendEvent(r.events, { at: now, level: 'warn', code: 'rekicked' }),
      updatedAt: now,
    });
    await scheduleStep(ctx, rotationId, 0);
    return null;
  },
});

/** The step action stamps its start so `listStale` can tell "never started" from "started and hung". */
export const markStepStarted = internalMutation({
  args: { rotationId: v.id('edgeRotations'), stepVersion: v.number() },
  handler: async (ctx, { rotationId, stepVersion }) => {
    const r = await ctx.db.get(rotationId);
    if (!r || r.stepVersion !== stepVersion || isTerminalPhase(r.phase)) return null;
    await ctx.db.patch(rotationId, { stepStartedAt: Date.now() });
    return null;
  },
});

export const requestCancel = internalMutation({
  args: { rotationId: v.id('edgeRotations'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { rotationId, actorAdminId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Rotation not found' });
    if (isTerminalPhase(r.phase)) return { ok: true as const, phase: r.phase, deferred: false };
    if (r.phase === 'confirming' || r.phase === 'finalizing') {
      throw new ConvexError({
        code: 'edge.too_late',
        message: 'The rotation is past the point of cancellation',
      });
    }
    const now = Date.now();
    const origin = await ctx.db.get(r.relayId);
    if (r.phase === 'rolling_back') {
      // A rollback is never aborted half-way (the panel Host must land on the
      // previous binding), but the request is RECORDED and audited so the
      // operator is not locked out silently: the rollback finishes on its own
      // (rolled_back) or parks the origin (quarantined) within its attempt caps.
      await ctx.db.patch(rotationId, {
        cancelRequested: true,
        events: appendEvent(r.events, {
          at: now,
          level: 'warn',
          code: 'cancel_requested',
          detail: 'recorded; a rollback completes or quarantines, it is not aborted',
        }),
        updatedAt: now,
      });
      await auditRotation(ctx, rotationId, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'admin.edge.cancel',
        targetType: 'relay',
        targetId: r.relayId,
        payload: { slug: origin?.slug ?? '', rotationId, deferred: true },
      });
      return { ok: true as const, phase: r.phase, deferred: true };
    }
    await ctx.db.patch(rotationId, {
      cancelRequested: true,
      events: appendEvent(r.events, { at: now, level: 'warn', code: 'cancel_requested' }),
      updatedAt: now,
    });
    await auditRotation(ctx, rotationId, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.edge.cancel',
      targetType: 'relay',
      targetId: r.relayId,
      payload: { slug: origin?.slug ?? '', rotationId, deferred: false },
    });
    await scheduleStep(ctx, rotationId, 0);
    return { ok: true as const, phase: r.phase, deferred: false };
  },
});

// --- transitions ---------------------------------------------------------------------------

const advanceEvent = v.union(
  v.object({ type: v.literal('selected'), toEdgeId: v.id('edges'), viaStandby: v.boolean() }),
  v.object({
    type: v.literal('progress'),
    delayMs: v.number(),
    detail: v.optional(v.string()),
    countPoll: v.optional(v.boolean()),
    countError: v.optional(v.boolean()),
  }),
  v.object({ type: v.literal('provisioned') }),
  v.object({ type: v.literal('verified') }),
  v.object({ type: v.literal('host_converged'), flipped: v.number() }),
  v.object({ type: v.literal('reflip') }),
  v.object({ type: v.literal('confirmed') }),
  v.object({
    type: v.literal('fail'),
    code: v.string(),
    detail: v.optional(v.string()),
    rollback: v.boolean(),
  }),
  v.object({ type: v.literal('rolled_back') }),
  v.object({ type: v.literal('quarantine'), reason: v.string() }),
  v.object({ type: v.literal('cancelled') }),
);

async function guard(
  ctx: MutationCtx,
  rotationId: Id<'edgeRotations'>,
  stepVersion: number,
): Promise<Rotation | null> {
  const r = await ctx.db.get(rotationId);
  if (!r || r.stepVersion !== stepVersion || isTerminalPhase(r.phase)) return null;
  return r;
}

/**
 * Every terminal transition passes through here (the 5 call sites: failed,
 * rolled_back, quarantined, cancelled, done). A rotation a guided setup run
 * started reports its outcome to the run through the terminal hook, carrying
 * the generation STORED on the rotation row: a run retried since then ignores
 * it (edgeSetupRuns.onRotationTerminal). Scheduled from the same transaction,
 * so a terminal rotation never goes unreported.
 */
async function releaseOrigin(ctx: MutationCtx, r: Rotation, patch: Partial<Origin> = {}) {
  const origin = await ctx.db.get(r.relayId);
  if (origin) {
    await ctx.db.patch(r.relayId, {
      ...(origin.activeRotationId === r._id ? { activeRotationId: undefined } : {}),
      ...patch,
      updatedAt: Date.now(),
    });
  }
  if (r.setupRun) {
    await ctx.scheduler.runAfter(0, internal.edgeSetupRuns.onRotationTerminal, {
      runId: r.setupRun.runId,
      rotationId: r._id,
      generation: r.setupRun.generation,
    });
  }
}

async function auditFailure(
  ctx: MutationCtx,
  r: Rotation,
  phase: Phase,
  outcome: string,
  code: string,
) {
  const origin = await ctx.db.get(r.relayId);
  await auditRotation(ctx, r._id, {
    actorType: 'system',
    action: 'edge.rotation_failed',
    targetType: 'edge_rotation',
    targetId: r._id,
    payload: {
      relaySlug: origin?.slug ?? '',
      trigger: r.trigger,
      phase,
      outcome,
      step: phase,
      code,
    },
  });
}

/**
 * The new edge this rotation created (never a pre-existing standby / publish
 * target). Read from the row (`createdEdgeId` / `viaStandby`); rows created
 * before those fields existed fall back to the event log.
 */
function createdEdgeId(r: Rotation): Id<'edges'> | null {
  if (r.createdEdgeId) return r.createdEdgeId;
  if (r.viaStandby !== undefined) return r.viaStandby ? null : (r.toEdgeId ?? null);
  if (!r.toEdgeId) return null;
  if (r.kind === 'publish') return null;
  return r.events.some((e) => e.code === 'selected_standby') ? null : r.toEdgeId;
}

/**
 * Give an allocation back when a provision failed BEFORE any provider call
 * (nothing was created, so the day's budget was not spent). Only when every
 * step is still pending and the ledger is empty; same-day only.
 */
async function refundAllocation(ctx: MutationCtx, edge: Edge): Promise<boolean> {
  if (!edge.accountId) return false;
  if (edge.resources.length > 0) return false;
  if (edge.steps.some((s) => s.state !== 'pending' || s.attempt > 0 || s.startedAt)) return false;
  const acct = await ctx.db.get(edge.accountId);
  if (!acct || acct.allocationsDayKey !== dayKey() || acct.allocationsToday <= 0) return false;
  await ctx.db.patch(acct._id, {
    allocationsToday: acct.allocationsToday - 1,
    updatedAt: Date.now(),
  });
  return true;
}

/**
 * Put `edgeId` at `index` of the published pool. An UNEXPECTED occupant (not
 * the edge itself) is evicted explicitly — unpublished, audited with this
 * rotation's id, returned so the caller can list it as a standby — rather than
 * silently overwritten.
 */
async function placeAt(
  ctx: MutationCtx,
  origin: Origin,
  published: readonly (Id<'edges'> | null)[],
  index: number,
  edgeId: Id<'edges'>,
  rotationId: Id<'edgeRotations'>,
  now: number,
): Promise<{ published: (Id<'edges'> | null)[]; evicted: Id<'edges'> | null }> {
  const occupant = published[index] ?? null;
  if (!occupant || occupant === edgeId) {
    return { published: withEdgeAt(published, index, edgeId), evicted: null };
  }
  const occ = await ctx.db.get(occupant);
  if (occ && occ.publication === 'published') {
    await ctx.db.patch(occ._id, {
      publication: 'unpublished',
      poolIndex: undefined,
      updatedAt: now,
    });
  }
  await auditRotation(ctx, rotationId, {
    actorType: 'system',
    action: 'edge.unpublished',
    targetType: 'edge',
    targetId: occupant,
    payload: {
      relaySlug: origin.slug,
      edgeId: occupant,
      poolIndex: index,
      epoch: origin.publicationEpoch + 1,
      rotationId,
    },
  });
  return {
    published: withEdgeAt(withoutEdge(published, occupant), index, edgeId),
    evicted: occ && occ.status !== 'destroyed' ? occupant : null,
  };
}

export const advance = internalMutation({
  args: { rotationId: v.id('edgeRotations'), stepVersion: v.number(), event: advanceEvent },
  handler: async (ctx, { rotationId, stepVersion, event }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return { ok: false as const };
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    const next = stepVersion + 1;
    const ev = (level: RotationEvent['level'], code: string, detail?: string) =>
      appendEvent(r.events, { at: now, level, code, detail });
    const poll = edgeMs.poll(cfg);
    switch (event.type) {
      case 'selected': {
        await ctx.db.patch(rotationId, {
          toEdgeId: event.toEdgeId,
          viaStandby: event.viaStandby,
          createdEdgeId: event.viaStandby ? undefined : event.toEdgeId,
          phase: event.viaStandby ? 'verifying' : 'provisioning',
          stepVersion: next,
          events: ev('info', event.viaStandby ? 'selected_standby' : 'selected_provision'),
          updatedAt: now,
        });
        if (!event.viaStandby)
          await ctx.db.patch(event.toEdgeId, {
            status: 'provisioning',
            statusChangedAt: now,
            updatedAt: now,
          });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const };
      }
      case 'progress': {
        await ctx.db.patch(rotationId, {
          stepVersion: next,
          pollAttempts: event.countPoll ? r.pollAttempts + 1 : r.pollAttempts,
          stepErrors: event.countError ? (r.stepErrors ?? 0) + 1 : r.stepErrors,
          events: event.detail
            ? ev(event.countError ? 'warn' : 'info', 'progress', event.detail)
            : r.events,
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, event.delayMs);
        return { ok: true as const };
      }
      case 'provisioned': {
        if (r.toEdgeId)
          await ctx.db.patch(r.toEdgeId, {
            status: 'verifying',
            statusChangedAt: now,
            updatedAt: now,
          });
        await ctx.db.patch(rotationId, {
          phase: 'verifying',
          stepVersion: next,
          pollAttempts: 0,
          provisionedAt: now,
          events: ev('info', 'provisioned'),
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const };
      }
      case 'verified': {
        if (r.toEdgeId) {
          const e = await ctx.db.get(r.toEdgeId);
          if (e && e.status !== 'active')
            await ctx.db.patch(r.toEdgeId, {
              status: 'active',
              statusChangedAt: now,
              updatedAt: now,
            });
        }
        await ctx.db.patch(rotationId, {
          phase: 'publishing',
          stepVersion: next,
          events: ev('info', 'verified'),
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const };
      }
      case 'host_converged': {
        await ctx.db.patch(rotationId, {
          phase: 'confirming',
          stepVersion: next,
          flippedAt: event.flipped > 0 ? now : r.flippedAt,
          events: ev('info', 'hosts_converged', `${event.flipped} host(s)`),
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, poll);
        return { ok: true as const };
      }
      case 'reflip': {
        await ctx.db.patch(rotationId, {
          phase: 'host_flipping',
          stepVersion: next,
          events: ev('warn', 'hosts_drifted_reflip'),
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const };
      }
      case 'confirmed': {
        await ctx.db.patch(rotationId, {
          phase: 'finalizing',
          stepVersion: next,
          events: ev('info', 'confirmed'),
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const };
      }
      case 'fail': {
        if (event.rollback) {
          await ctx.db.patch(rotationId, {
            phase: 'rolling_back',
            stepVersion: next,
            outcome: event.code,
            events: ev('error', event.code, event.detail),
            updatedAt: now,
          });
          await scheduleStep(ctx, rotationId, 0);
          return { ok: true as const };
        }
        const created = createdEdgeId(r);
        let refunded = false;
        if (created) {
          const e = await ctx.db.get(created);
          if (e && !['needs_operator', 'destroyed'].includes(e.status)) {
            // The template changed under a provision that had not called the
            // provider yet: nothing exists, so the day's allocation is given back.
            if (event.code === 'template_changed') refunded = await refundAllocation(ctx, e);
            await ctx.db.patch(created, {
              status: 'failed',
              statusChangedAt: now,
              failure: { step: r.phase, code: event.code },
              updatedAt: now,
            });
          }
        }
        await ctx.db.patch(rotationId, {
          phase: 'failed',
          stepVersion: next,
          outcome: event.code,
          finishedAt: now,
          nextStepAt: undefined,
          events: appendEvent(ev('error', event.code, event.detail), {
            at: now,
            level: 'info',
            code: refunded ? 'allocation_refunded' : 'failed',
          }),
          updatedAt: now,
        });
        await releaseOrigin(ctx, r);
        await auditFailure(ctx, r, r.phase, 'failed', event.code);
        return { ok: true as const };
      }
      case 'rolled_back': {
        await ctx.db.patch(rotationId, {
          phase: 'rolled_back',
          stepVersion: next,
          finishedAt: now,
          nextStepAt: undefined,
          events: ev('warn', 'rolled_back'),
          updatedAt: now,
        });
        await releaseOrigin(ctx, r);
        const origin = await ctx.db.get(r.relayId);
        await auditRotation(ctx, r._id, {
          actorType: 'system',
          action: 'edge.rolled_back',
          targetType: 'edge_rotation',
          targetId: r._id,
          payload: { relaySlug: origin?.slug ?? '', hosts: r.hostPlan.length },
        });
        await auditFailure(ctx, r, 'rolling_back', 'rolled_back', r.outcome ?? 'unknown');
        return { ok: true as const };
      }
      case 'quarantine': {
        await ctx.db.patch(rotationId, {
          phase: 'quarantined',
          stepVersion: next,
          finishedAt: now,
          nextStepAt: undefined,
          events: ev('error', 'quarantined', event.reason),
          updatedAt: now,
        });
        if (r.toEdgeId) {
          const e = await ctx.db.get(r.toEdgeId);
          if (e && e.status !== 'destroyed')
            await ctx.db.patch(r.toEdgeId, {
              status: 'quarantined',
              statusChangedAt: now,
              updatedAt: now,
            });
        }
        await releaseOrigin(ctx, r, {
          quarantine: { rotationId, since: now, reason: event.reason },
        });
        const origin = await ctx.db.get(r.relayId);
        await auditRotation(ctx, r._id, {
          actorType: 'system',
          action: 'edge.quarantined',
          targetType: 'relay',
          targetId: r.relayId,
          payload: { relaySlug: origin?.slug ?? '', rotationId, reason: event.reason },
        });
        return { ok: true as const };
      }
      case 'cancelled': {
        const created = createdEdgeId(r);
        if (created) {
          const e = await ctx.db.get(created);
          if (e && !['destroyed', 'needs_operator'].includes(e.status)) {
            await ctx.db.patch(created, {
              status: 'cancelled',
              statusChangedAt: now,
              updatedAt: now,
            });
          }
        }
        await ctx.db.patch(rotationId, {
          phase: 'cancelled',
          stepVersion: next,
          outcome: 'cancelled',
          finishedAt: now,
          nextStepAt: undefined,
          events: ev('warn', 'cancelled'),
          updatedAt: now,
        });
        await releaseOrigin(ctx, r);
        return { ok: true as const };
      }
    }
  },
});

/** Commit a fresh-provision selection: reserves capacity/budget + inserts the planned edge. */
export const commitSelection = internalMutation({
  args: {
    rotationId: v.id('edgeRotations'),
    stepVersion: v.number(),
    listenerId: v.id('relayListeners'),
    accountId: v.id('edgeProviderAccounts'),
    templateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    templateHash: v.string(),
    nameNonce: v.string(),
    listeners: v.array(
      v.object({
        edgePort: v.number(),
        originAddress: v.string(),
        originPort: v.number(),
        transport: v.optional(v.union(v.literal('tcp'), v.literal('udp'))),
      }),
    ),
    steps: v.array(
      v.object({
        id: v.string(),
        kind: v.string(),
        resourceName: v.string(),
        discoverability: v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
      }),
    ),
    /** The EFFECTIVE rendered template params (adapter defaults applied), frozen into the intent. */
    templateParams: v.optional(v.any()),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const, code: 'stale' as const };
    const origin = await ctx.db.get(r.relayId);
    const account = await ctx.db.get(a.accountId);
    const listener = await ctx.db.get(a.listenerId);
    if (!origin || !account || !listener) return { ok: false as const, code: 'missing' as const };
    const layer = edgeLayerOf(account.provider);
    // Freeze the intent HERE, before any provider call: from this point on, an
    // operator editing the account's zone, its DNS account, the TLS
    // configuration or the template no longer moves this edge. Everything the
    // remaining steps, discovery, describe and destroy need is on the row.
    let provisionIntent: ProvisionIntent | null = null;
    if (layer === 'l7') {
      const dnsAccountId = (account.settings as { dnsAccountId?: string }).dnsAccountId;
      const dnsAccount = dnsAccountId
        ? await ctx.db.get(dnsAccountId as Id<'edgeProviderAccounts'>)
        : null;
      if (dnsAccountId && !dnsAccount)
        return { ok: false as const, code: 'dns_account_missing' as const };
      // A disabled DNS account stops NEW allocations (reconciliation and
      // destroy keep working through it, which is why this is the only gate).
      if (dnsAccount && !dnsAccount.enabled)
        return { ok: false as const, code: 'dns_account_disabled' as const };
      try {
        provisionIntent = buildProvisionIntent({
          account: {
            id: account._id as string,
            provider: account.provider,
            settings: account.settings as Record<string, unknown>,
            observedSettings: parseObservedSettings(account.observedSettings),
          },
          dnsAccount: dnsAccount
            ? {
                id: dnsAccount._id as string,
                provider: dnsAccount.provider,
                settings: dnsAccount.settings as Record<string, unknown>,
                observedSettings: parseObservedSettings(dnsAccount.observedSettings),
              }
            : null,
          specName: edgeResourceName(origin.slug, a.nameNonce),
          templateParams: (a.templateParams as Record<string, unknown>) ?? {},
          templateHash: a.templateHash,
          listener,
        });
      } catch (err) {
        return {
          ok: false as const,
          code: err instanceof IntentError ? err.code : 'intent_failed',
        };
      }
    }
    let inserted: { id: Id<'edges'>; name: string };
    try {
      inserted = await insertPlannedEdge(ctx, {
        relayId: r.relayId,
        listenerId: a.listenerId,
        accountId: a.accountId,
        templateId: a.templateId,
        templateHash: a.templateHash,
        listeners: a.listeners,
        steps: a.steps,
        nameNonce: a.nameNonce,
        layer,
        provisionIntent,
      });
    } catch (err) {
      const code =
        err instanceof ConvexError
          ? String((err.data as { code?: string }).code ?? 'insert_failed')
          : 'insert_failed';
      return { ok: false as const, code };
    }
    const now = Date.now();
    await ctx.db.patch(a.rotationId, {
      toEdgeId: inserted.id,
      createdEdgeId: inserted.id,
      viaStandby: false,
      phase: 'provisioning',
      stepVersion: a.stepVersion + 1,
      events: appendEvent(r.events, {
        at: now,
        level: 'info',
        code: 'selected_provision',
        detail: inserted.name,
      }),
      updatedAt: now,
    });
    await ctx.db.patch(inserted.id, {
      status: 'provisioning',
      statusChangedAt: now,
      updatedAt: now,
    });
    await scheduleStep(ctx, a.rotationId, 0);
    return { ok: true as const, edgeId: inserted.id };
  },
});

/**
 * Publishing: swap the published pool in ONE transaction. Replace keeps the
 * target's pool index (the old edge goes to draining); provision/publish take
 * the lowest free index. Decides whether a template-Host flip follows.
 */
export const applyPublish = internalMutation({
  args: { rotationId: v.id('edgeRotations'), stepVersion: v.number() },
  handler: async (ctx, { rotationId, stepVersion }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r || !r.toEdgeId) return { ok: false as const, code: 'stale' as const };
    const cfg = await resolveEdgeConfig(ctx.db);
    const origin = await ctx.db.get(r.relayId);
    const to = await ctx.db.get(r.toEdgeId);
    if (!origin || !to) return { ok: false as const, code: 'missing' as const };
    const now = Date.now();
    const next = stepVersion + 1;
    let published = origin.publishedEdgeIds;
    let poolIndex: number | null = null;
    let previousBinding: Rotation['previousBinding'] = undefined;
    if (r.kind === 'provision' && !r.publishOnDone) {
      // Standby provision: verified, paid for, deliberately not rendered — it is
      // finalized whatever its publishability right now (a profile disabled
      // mid-run must not destroy a freshly provisioned edge).
      await ctx.db.patch(rotationId, {
        phase: 'finalizing',
        stepVersion: next,
        events: appendEvent(r.events, { at: now, level: 'info', code: 'standby' }),
        updatedAt: now,
      });
      await ctx.db.patch(r.relayId, {
        standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id],
        updatedAt: now,
      });
      await scheduleStep(ctx, rotationId, 0);
      return { ok: true as const, poolIndex: null, needsHostFlip: false };
    }
    const check = await checkPublishable(ctx, to, cfg.requireProviderHealth);
    if (!check.ok && check.code === 'unverified_endpoint' && !r.viaStandby) {
      // A freshly provisioned L4 edge is paid for and healthy but not yet
      // confirmed by the operator: keep it as a SPARE (attention
      // `spare_untested`) rather than failing the run and destroying it. The
      // target of a replace stays published.
      await ctx.db.patch(rotationId, {
        phase: 'finalizing',
        stepVersion: next,
        events: appendEvent(r.events, { at: now, level: 'warn', code: 'unverified_standby' }),
        updatedAt: now,
      });
      await ctx.db.patch(r.relayId, {
        standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id],
        updatedAt: now,
      });
      await scheduleStep(ctx, rotationId, 0);
      return { ok: true as const, poolIndex: null, needsHostFlip: false };
    }
    if (!check.ok) return { ok: false as const, code: check.code ?? 'not_publishable' };
    if (r.kind === 'replace') {
      const target = r.targetEdgeId ? await ctx.db.get(r.targetEdgeId) : null;
      if (!target || target.publication !== 'published' || target.poolIndex === undefined)
        return { ok: false as const, code: 'target_gone' as const };
      poolIndex = target.poolIndex;
      previousBinding = {
        edgeId: target._id,
        listenerId: target.listenerId,
        poolIndex,
      };
      await ctx.db.patch(target._id, {
        publication: 'draining',
        status: 'draining',
        poolIndex: undefined,
        drainUntil: now + edgeMs.drain(cfg),
        statusChangedAt: now,
        updatedAt: now,
      });
      published = withoutEdge(published, target._id);
    } else {
      // Reserved allocation: a free slot is held for a listener with no
      // template edge; an extra copy for a covered listener stays a standby.
      const alloc = allocatePoolIndex(
        published,
        origin.desiredPublished,
        to.listenerId,
        await poolListenersOf(ctx.db, r.relayId),
      );
      if ('refused' in alloc) {
        // Pool full (or its free slots reserved): keep the edge as a standby and finish.
        await ctx.db.patch(rotationId, {
          phase: 'finalizing',
          stepVersion: next,
          events: appendEvent(r.events, {
            at: now,
            level: 'warn',
            code: alloc.refused === 'pool_full' ? 'pool_full_standby' : 'pool_reserved_standby',
          }),
          updatedAt: now,
        });
        await ctx.db.patch(r.relayId, {
          standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id],
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const, poolIndex: null, needsHostFlip: false };
      }
      poolIndex = alloc.index;
    }
    await ctx.db.patch(to._id, {
      publication: 'published',
      poolIndex,
      publishedAt: now,
      updatedAt: now,
    });
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(r.relayId, {
      publishedEdgeIds: withEdgeAt(published, poolIndex, to._id),
      standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== to._id),
      publicationEpoch: epoch,
      updatedAt: now,
    });
    await auditRotation(ctx, rotationId, {
      actorType: 'system',
      action: 'edge.published',
      targetType: 'edge',
      targetId: to._id,
      payload: { relaySlug: origin.slug, edgeId: to._id, poolIndex, epoch, rotationId },
    });
    if (previousBinding) {
      await auditRotation(ctx, rotationId, {
        actorType: 'system',
        action: 'edge.unpublished',
        targetType: 'edge',
        targetId: previousBinding.edgeId,
        payload: {
          relaySlug: origin.slug,
          edgeId: previousBinding.edgeId,
          poolIndex,
          epoch,
          rotationId,
        },
      });
    }
    // Each listener's template edge follows the pool it now describes, BEFORE
    // the flip decision reads it: a stale pointer (at a drained edge) would
    // otherwise let a replace of the real template edge skip the Host flip.
    await refreshTemplateEdges(ctx, origin);
    const needsHostFlip = await needsHostFlipFor(
      ctx,
      origin,
      to,
      r.kind === 'replace' && r.targetEdgeId ? await ctx.db.get(r.targetEdgeId) : null,
    );
    await ctx.db.patch(rotationId, {
      phase: needsHostFlip ? 'host_flipping' : 'finalizing',
      stepVersion: next,
      previousBinding,
      events: appendEvent(r.events, {
        at: now,
        level: 'info',
        code: 'published',
        detail: `pool index ${poolIndex}${needsHostFlip ? ', panel Host flip follows' : origin.hostMode === 'operator' ? ', Host left to the operator' : origin.hostMode === 'none' ? ', no panel Host' : ''}`,
      }),
      updatedAt: now,
    });
    await scheduleStep(ctx, rotationId, 0);
    return { ok: true as const, poolIndex, needsHostFlip };
  },
});

/** Persist the observed Host plan (captured once, at the start of the flip). */
export const setHostPlan = internalMutation({
  args: {
    rotationId: v.id('edgeRotations'),
    stepVersion: v.number(),
    hostPlan: v.array(
      v.object({
        listenerKey: v.optional(v.string()),
        uuid: v.string(),
        oldAddress: v.string(),
        oldPort: v.number(),
        inboundUuid: v.optional(v.string()),
        // Version 2 also captured the previous SNI / Host header, so a rollback
        // can restore the whole tuple, clears included. A plan without it is a
        // LEGACY one (rotation in flight at deploy time): its historical names
        // are unknown, and unknown is never written back as "clear".
        snapshotVersion: v.optional(v.number()),
        oldSni: v.optional(v.union(v.string(), v.null())),
        oldHost: v.optional(v.union(v.string(), v.null())),
      }),
    ),
    listenerId: v.id('relayListeners'),
    templateHostUuid: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(a.rotationId, {
      hostPlan: a.hostPlan,
      hostPlanCaptured: true,
      stepVersion: a.stepVersion + 1,
      events: appendEvent(r.events, {
        at: now,
        level: 'info',
        code: 'host_plan',
        detail: `${a.hostPlan.length} host(s)`,
      }),
      updatedAt: now,
    });
    if (a.templateHostUuid) {
      // The plan found the listener's Host on the panel: it is present and, if
      // FCP had not created it, adopted.
      const l = await ctx.db.get(a.listenerId);
      if (l)
        await ctx.db.patch(a.listenerId, {
          host: {
            ...(l.host ?? { state: 'present' as const }),
            state: 'present',
            uuid: a.templateHostUuid,
            ownership: l.host?.ownership ?? 'adopted',
            op: undefined,
          },
          updatedAt: now,
        });
    }
    await scheduleStep(ctx, a.rotationId, 0);
    return { ok: true as const, stepVersion: a.stepVersion + 1 };
  },
});

/** Claim the single in-flight Host write; counts flip / rollback attempts against their caps. */
export const claimHostOp = internalMutation({
  args: {
    rotationId: v.id('edgeRotations'),
    stepVersion: v.number(),
    hostUuid: v.string(),
    direction: v.union(v.literal('forward'), v.literal('rollback')),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const, code: 'stale' as const };
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    if (r.currentOp && r.currentOp.expiresAt > now)
      return { ok: false as const, code: 'op_busy' as const };
    const attempts = a.direction === 'forward' ? r.flipAttempts + 1 : r.rollbackAttempts + 1;
    const cap = a.direction === 'forward' ? cfg.maxFlipAttempts : cfg.maxRollbackAttempts;
    if (attempts > cap) return { ok: false as const, code: 'max_attempts' as const };
    const op = {
      opId: randomHex(8),
      kind: 'host_write' as const,
      hostUuid: a.hostUuid,
      direction: a.direction,
      attempt: attempts,
      claimedAt: now,
      expiresAt: now + edgeMs.opClaim(cfg),
    };
    await ctx.db.patch(a.rotationId, {
      currentOp: op,
      // Set with the claim, not the settle: a PATCH that lands but times out
      // before its settle still counts as "the panel may hold the new address".
      ...(a.direction === 'forward'
        ? { flipAttempts: attempts, forwardWriteAttempted: true }
        : { rollbackAttempts: attempts }),
      updatedAt: now,
    });
    return { ok: true as const, opId: op.opId };
  },
});

export const settleHostOp = internalMutation({
  args: {
    rotationId: v.id('edgeRotations'),
    opId: v.string(),
    ok: v.boolean(),
    detail: v.optional(v.string()),
  },
  handler: async (ctx, a) => {
    const r = await ctx.db.get(a.rotationId);
    if (!r || !r.currentOp || r.currentOp.opId !== a.opId) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(a.rotationId, {
      currentOp: undefined,
      events: appendEvent(r.events, {
        at: now,
        level: a.ok ? 'info' : 'warn',
        code: a.ok
          ? `host_${r.currentOp.direction}_written`
          : `host_${r.currentOp.direction}_write_failed`,
        detail: a.detail,
      }),
      updatedAt: now,
    });
    return { ok: true as const };
  },
});

/**
 * Rollback, DB half (idempotent): restore the complete previous binding
 * (previous edge back to published at its pool index; the new edge back to an
 * unpublished standby). Host writes follow in the step action.
 */
export const applyRollbackBinding = internalMutation({
  args: { rotationId: v.id('edgeRotations') },
  handler: async (ctx, { rotationId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r) return { ok: false as const };
    const origin = await ctx.db.get(r.relayId);
    if (!origin) return { ok: false as const };
    const now = Date.now();
    let published = origin.publishedEdgeIds;
    let changed = false;
    if (r.toEdgeId) {
      const to = await ctx.db.get(r.toEdgeId);
      if (to && to.publication === 'published') {
        await ctx.db.patch(to._id, {
          publication: 'unpublished',
          poolIndex: undefined,
          updatedAt: now,
        });
        published = withoutEdge(published, to._id);
        changed = true;
      }
    }
    let evicted: Id<'edges'> | null = null;
    if (r.previousBinding) {
      const prev = await ctx.db.get(r.previousBinding.edgeId);
      if (prev && prev.status !== 'destroyed' && prev.publication !== 'published') {
        await ctx.db.patch(prev._id, {
          publication: 'published',
          status: 'active',
          poolIndex: r.previousBinding.poolIndex,
          drainUntil: undefined,
          statusChangedAt: now,
          updatedAt: now,
        });
        const placed = await placeAt(
          ctx,
          origin,
          published,
          r.previousBinding.poolIndex,
          prev._id,
          rotationId,
          now,
        );
        published = placed.published;
        evicted = placed.evicted;
        changed = true;
      }
    }
    if (changed) {
      const standbys = origin.standbyEdgeIds.filter((e) => e !== r.toEdgeId && e !== evicted);
      if (r.toEdgeId) standbys.push(r.toEdgeId);
      if (evicted) standbys.push(evicted);
      await ctx.db.patch(r.relayId, {
        publishedEdgeIds: published,
        standbyEdgeIds: standbys,
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: now,
      });
      await refreshTemplateEdges(ctx, origin);
      const latest = (await ctx.db.get(rotationId)) ?? r;
      await ctx.db.patch(rotationId, {
        events: appendEvent(
          evicted
            ? appendEvent(latest.events, {
                at: now,
                level: 'warn',
                code: 'occupant_evicted',
                detail: `pool index ${r.previousBinding?.poolIndex ?? '?'}`,
              })
            : latest.events,
          { at: now, level: 'warn', code: 'binding_restored' },
        ),
        updatedAt: now,
      });
      await scheduleMirrorRefresh(ctx);
    }
    return { ok: true as const, changed };
  },
});

export const finalize = internalMutation({
  args: { rotationId: v.id('edgeRotations'), stepVersion: v.number() },
  handler: async (ctx, { rotationId, stepVersion }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return { ok: false as const };
    const cfg = await resolveEdgeConfig(ctx.db);
    const origin = await ctx.db.get(r.relayId);
    if (!origin) return { ok: false as const };
    const now = Date.now();
    const to = r.toEdgeId ? await ctx.db.get(r.toEdgeId) : null;
    let from: Edge | null = null;
    if (r.kind === 'replace' && r.targetEdgeId) {
      from = await ctx.db.get(r.targetEdgeId);
      if (from && from.status !== 'destroyed') {
        await ctx.db.patch(from._id, {
          publication: 'draining',
          status: 'draining',
          drainUntil: now + (r.burn ? edgeMs.burnedDrain(cfg) : edgeMs.drain(cfg)),
          ...(r.burn ? { burnedAt: now } : {}),
          statusChangedAt: from.status === 'draining' ? from.statusChangedAt : now,
          updatedAt: now,
        });
      }
    }
    const published = to?.publication === 'published';
    await ctx.db.patch(rotationId, {
      phase: 'done',
      stepVersion: stepVersion + 1,
      outcome: published ? 'published' : 'standby',
      finishedAt: now,
      nextStepAt: undefined,
      events: appendEvent(r.events, { at: now, level: 'info', code: 'done' }),
      updatedAt: now,
    });
    // A detector-triggered L7 replacement that SUCCEEDED on the same provider
    // counts against the relay's daily bound exactly like a blocked one: the
    // new hostname very probably resolves to the same shared anycast frontend,
    // so a censor that blocked the address is not answered by it. A
    // replacement that moved to another provider, or to another layer, is a
    // genuinely new frontend address and is not counted.
    const sameProviderL7 =
      r.trigger === 'detector' &&
      r.kind === 'replace' &&
      !!from &&
      !!to &&
      (from.layer ?? 'l4') === 'l7' &&
      (to.layer ?? 'l4') === 'l7' &&
      !!from.provider &&
      from.provider === to.provider;
    const today = todayKey(now);
    const usedToday = origin.l7ReplacementsDayKey === today ? (origin.l7ReplacementsToday ?? 0) : 0;
    await releaseOrigin(ctx, r, {
      ...(sameProviderL7
        ? { l7ReplacementsDayKey: today, l7ReplacementsToday: usedToday + 1 }
        : {}),
      ...(r.kind === 'replace'
        ? { lastRotatedAt: now, cooldownUntil: now + origin.cooldownMs }
        : {}),
      // Standby bookkeeping for a provision that did not publish. Only an edge
      // that could actually be published later belongs on the list: a destroyed
      // or failed one would sit there forever and be offered to every
      // `autoPublishStandby` pass, which then refuses it again.
      ...(to && !published
        ? {
            standbyEdgeIds:
              to.status === 'active' || to.status === 'standby'
                ? [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id]
                : origin.standbyEdgeIds.filter((e) => e !== to._id),
          }
        : {}),
    });
    if (r.kind === 'replace') {
      await auditRotation(ctx, r._id, {
        actorType: 'system',
        action: 'edge.rotated',
        targetType: 'relay',
        targetId: r.relayId,
        payload: {
          relaySlug: origin.slug,
          trigger: r.trigger,
          kind: r.kind,
          fromProvider: from?.provider ?? null,
          toProvider: to?.provider ?? null,
          fromEdgeId: from?._id ?? null,
          toEdgeId: to?._id ?? null,
          poolIndex: to?.poolIndex ?? null,
          hostsFlipped: r.hostPlan.length,
          durationMs: now - r.startedAt,
          rotationId: r._id,
        },
      });
      if (r.burn && from) {
        await auditRotation(ctx, r._id, {
          actorType: 'system',
          action: 'edge.burned',
          targetType: 'edge',
          targetId: from._id,
          payload: {
            relaySlug: origin.slug,
            trigger: r.trigger,
            edgeId: from._id,
            rotationId: r._id,
          },
        });
      }
    }
    if (published && cfg.refreshMirrorsAfterFlip) {
      await ctx.scheduler.runAfter(0, internal.storage.refreshActiveMirrors, {});
    }
    return { ok: true as const };
  },
});

export const resolveQuarantine = internalMutation({
  args: {
    relayId: v.id('relays'),
    keep: v.union(v.literal('current'), v.literal('previous')),
    /** The operator's justification (short; audited). */
    reason: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, keep, reason, actorAdminId }) => {
    const origin = await ctx.db.get(relayId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!origin.quarantine) return { ok: true as const };
    const rotation = await ctx.db.get(origin.quarantine.rotationId);
    const now = Date.now();
    const standbys = [...origin.standbyEdgeIds];
    const standbyAdd = (id: Id<'edges'> | null) => {
      if (id && !standbys.includes(id)) standbys.push(id);
    };
    const standbyDrop = (id: Id<'edges'>) => {
      const i = standbys.indexOf(id);
      if (i >= 0) standbys.splice(i, 1);
    };
    if (keep === 'previous' && rotation) {
      // DB half of the rollback; the operator has fixed the panel Hosts by hand.
      let published = origin.publishedEdgeIds;
      if (rotation.toEdgeId) {
        const to = await ctx.db.get(rotation.toEdgeId);
        if (to && to.status !== 'destroyed') {
          await ctx.db.patch(to._id, {
            publication: 'unpublished',
            status: 'active',
            poolIndex: undefined,
            statusChangedAt: now,
            updatedAt: now,
          });
          published = withoutEdge(published, to._id);
          standbyAdd(to._id);
        }
      }
      if (rotation.previousBinding) {
        const prev = await ctx.db.get(rotation.previousBinding.edgeId);
        if (prev && prev.status !== 'destroyed') {
          await ctx.db.patch(prev._id, {
            publication: 'published',
            status: 'active',
            poolIndex: rotation.previousBinding.poolIndex,
            drainUntil: undefined,
            statusChangedAt: now,
            updatedAt: now,
          });
          const placed = await placeAt(
            ctx,
            origin,
            published,
            rotation.previousBinding.poolIndex,
            prev._id,
            rotation._id,
            now,
          );
          published = placed.published;
          standbyAdd(placed.evicted);
          standbyDrop(prev._id);
        }
      }
      await ctx.db.patch(relayId, {
        publishedEdgeIds: published,
        standbyEdgeIds: standbys,
        updatedAt: now,
      });
    } else if (rotation?.toEdgeId) {
      // Keep the CURRENT edge: the rolling_back pass already restored the
      // previous binding in the DB (previous published, new unpublished), so
      // this is the inverse — the operator aligned the panel Host with the new
      // edge by hand, and FCP's pool must say the same: new edge published at
      // the saved pool index, previous edge draining.
      const to = await ctx.db.get(rotation.toEdgeId);
      if (to && to.status !== 'destroyed') {
        const cfg = await resolveEdgeConfig(ctx.db);
        let published = origin.publishedEdgeIds;
        const poolIndex = rotation.previousBinding?.poolIndex ?? to.poolIndex ?? 0;
        // The new edge must still be publishable (slot deployed, profile enabled
        // with a name to present, provider/account match, health): the check runs
        // on the edge as it will be — active and unpublished — since the
        // quarantine itself parked its status.
        if (!(to.publication === 'published' && to.poolIndex === poolIndex)) {
          const check = await checkPublishable(
            ctx,
            { ...to, status: 'active', publication: 'unpublished' },
            cfg.requireProviderHealth,
          );
          if (!check.ok) {
            throw new ConvexError({
              code: `edge.${check.code}`,
              message: `The current edge cannot be kept: ${check.code}`,
            });
          }
        }
        if (rotation.previousBinding && rotation.previousBinding.edgeId !== to._id) {
          const prev = await ctx.db.get(rotation.previousBinding.edgeId);
          if (prev && prev.status !== 'destroyed') {
            await ctx.db.patch(prev._id, {
              publication: 'draining',
              status: 'draining',
              poolIndex: undefined,
              drainUntil: now + (rotation.burn ? edgeMs.burnedDrain(cfg) : edgeMs.drain(cfg)),
              ...(rotation.burn ? { burnedAt: now } : {}),
              statusChangedAt: now,
              updatedAt: now,
            });
            published = withoutEdge(published, prev._id);
            standbyDrop(prev._id);
          }
        }
        await ctx.db.patch(to._id, {
          publication: 'published',
          status: 'active',
          poolIndex,
          publishedAt: to.publishedAt ?? now,
          drainUntil: undefined,
          statusChangedAt: now,
          updatedAt: now,
        });
        const placed = await placeAt(ctx, origin, published, poolIndex, to._id, rotation._id, now);
        published = placed.published;
        standbyAdd(placed.evicted);
        standbyDrop(to._id);
        await ctx.db.patch(relayId, {
          publishedEdgeIds: published,
          standbyEdgeIds: standbys,
          lastRotatedAt: now,
          updatedAt: now,
        });
      }
    }
    await ctx.db.patch(relayId, {
      quarantine: undefined,
      publicationEpoch: origin.publicationEpoch + 1,
      updatedAt: now,
    });
    await refreshTemplateEdges(ctx, origin);
    if (rotation) {
      const latest = (await ctx.db.get(rotation._id)) ?? rotation;
      await ctx.db.patch(rotation._id, {
        outcome: `quarantine_resolved:${keep}`,
        events: appendEvent(latest.events, {
          at: now,
          level: 'info',
          code: 'quarantine_resolved',
          detail: keep,
        }),
        updatedAt: now,
      });
    }
    const entry: AuditEntry = {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.quarantine_resolved',
      targetType: 'relay',
      targetId: relayId,
      payload: {
        relaySlug: origin.slug,
        keep,
        rotationId: rotation?._id ?? null,
        reason: reason?.slice(0, 200),
      },
    };
    if (rotation) await auditRotation(ctx, rotation._id, entry);
    else await writeAuditLog(ctx, entry);
    await scheduleMirrorRefresh(ctx);
    return { ok: true as const };
  },
});

// --- L7 gate state -------------------------------------------------------------------------

/**
 * Whether the L7 front is proven for what THIS rotation would publish, and
 * which countries (if any) must additionally be shown to reach it. The binding
 * is re-derived from the live slot/profile/intent, so a configuration written
 * while the session ran is not silently accepted as proof.
 */
export const l7GateState = internalQuery({
  args: { rotationId: v.id('edgeRotations'), edgeId: v.id('edges') },
  handler: async (ctx, { rotationId, edgeId }) => {
    const r = await ctx.db.get(rotationId);
    const edge = await ctx.db.get(edgeId);
    if (!r || !edge) return null;
    const listener = await ctx.db.get(edge.listenerId);
    const intent = parseIntent(edge.provisionIntent);
    const q = edge.frontQualification;
    const qualified =
      !!listener &&
      !!intent &&
      qualificationVerdict(
        q,
        qualificationBinding({ listener, intent, params: listener.transportParams ?? {} }),
        Date.now(),
      ) === 'ok';
    // Evidence is required only for a replacement the DETECTOR asked for: a
    // manual or reconcile run has no "affected countries" to answer to.
    const needsGeoEvidence = r.trigger === 'detector' && r.forceGeoEvidence !== true;
    const relay = await ctx.db.get(r.relayId);
    const evidence = relay?.suspicion?.edgeEvidence ?? [];
    const target = r.targetEdgeId;
    const countries = new Set<string>();
    for (const e of evidence) {
      if (target && e.edgeId !== target) continue;
      for (const c of e.countries) countries.add(c);
    }
    return {
      qualified,
      qualificationCode: q?.code ?? (q?.ok === false ? 'failed' : null),
      needsGeoEvidence,
      affectedCountries: [...countries],
    };
  },
});

/**
 * The stored per-country verdicts for an edge, WITH their freshness. `absent` =
 * no row yet (nothing measured); `stale` = a row older than the detector's
 * freshness window (two probe intervals), which says nothing about the edge now
 * and is therefore never accepted as evidence in either direction. The caller
 * asks for a fresh round instead.
 */
export const edgeReachability = internalQuery({
  args: { edgeId: v.id('edges'), countries: v.array(v.string()) },
  handler: async (
    ctx,
    { edgeId, countries },
  ): Promise<Array<{ country: string; verdict: string; lastAt: number | null }>> => {
    const edge = await ctx.db.get(edgeId);
    const cfg = await resolveEdgeConfig(ctx.db);
    const rows = edge?.reachability?.byCountry ?? [];
    const now = Date.now();
    const staleAfter = probeStaleAfterMs(cfg.probe);
    return countries.map((country) => {
      const row = rows.find((c) => c.country === country);
      if (!row) return { country, verdict: 'absent', lastAt: null };
      const fresh = now - row.lastAt <= staleAfter;
      return { country, verdict: fresh ? row.verdict : 'stale', lastAt: row.lastAt };
    });
  },
});

/**
 * Count one same-provider L7 replacement against the relay's daily bound.
 * Minting another CDN hostname does not guarantee a different frontend IP, so
 * a block that survives the replacement must not turn into an allocation loop.
 */
export const countL7Replacement = internalMutation({
  args: { rotationId: v.id('edgeRotations') },
  handler: async (ctx, { rotationId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r) return null;
    const origin = await ctx.db.get(r.relayId);
    if (!origin) return null;
    const today = todayKey();
    const used = origin.l7ReplacementsDayKey === today ? (origin.l7ReplacementsToday ?? 0) : 0;
    await ctx.db.patch(origin._id, {
      l7ReplacementsDayKey: today,
      l7ReplacementsToday: used + 1,
      updatedAt: Date.now(),
    });
    return null;
  },
});

// --- step context ------------------------------------------------------------------------------

export const stepContext = internalQuery({
  args: { rotationId: v.id('edgeRotations') },
  handler: async (ctx, { rotationId }) => {
    const rotation = await ctx.db.get(rotationId);
    if (!rotation) return null;
    const origin = await ctx.db.get(rotation.relayId);
    if (!origin) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const toEdge = rotation.toEdgeId ? await ctx.db.get(rotation.toEdgeId) : null;
    const targetEdge = rotation.targetEdgeId ? await ctx.db.get(rotation.targetEdgeId) : null;
    const listenerId = toEdge?.listenerId ?? targetEdge?.listenerId ?? null;
    const listener = listenerId ? await ctx.db.get(listenerId) : null;
    const prevEdge = rotation.previousBinding
      ? await ctx.db.get(rotation.previousBinding.edgeId)
      : null;
    let selection: SelectionContext | null = null;
    if (rotation.phase === 'select')
      selection = await selectionContext(ctx, rotation, origin, targetEdge, cfg);
    return { rotation, origin, cfg, toEdge, targetEdge, listener, prevEdge, selection };
  },
});

/** What selection needs to know about the run (a rotation row satisfies it; the preflight builds one). */
export interface SelectionRequest {
  kind: 'provision' | 'publish' | 'replace';
  trigger: 'manual' | 'detector' | 'api' | 'reconcile';
  listenerId?: Id<'relayListeners'>;
  reason?: string;
  publishOnDone?: boolean;
  requestedAccountId?: Id<'edgeProviderAccounts'>;
  requestedTemplateId?: Id<'edgeTemplates'>;
  allowUnqualified?: boolean;
}

export interface SelectionContext {
  listener: Doc<'relayListeners'> | null;
  standbyId: Id<'edges'> | null;
  account: {
    id: Id<'edgeProviderAccounts'>;
    provider: string;
    defaultTemplateId: Id<'edgeTemplates'> | null;
    /** L7: the DNS zone the hostname is minted under (this account's, or its DNS account's). */
    zoneName: string | null;
    /** L7: the zone's OBSERVED encryption mode (null = the account was never tested). */
    zoneSslMode: string | null;
  } | null;
  accountFailure: string | null;
  template: {
    id: Id<'edgeTemplates'> | null;
    params: Record<string, unknown>;
    hash: string;
  } | null;
}

export async function selectionContext(
  ctx: { db: QueryCtx['db'] },
  rotation: SelectionRequest,
  origin: Origin,
  targetEdge: Edge | null,
  cfg: EdgeConfig,
): Promise<SelectionContext> {
  const edges = await liveEdgesOfRelay(ctx.db, origin._id);
  const publishedProviders = edges
    .filter((e) => e.publication === 'published' && e.provider)
    .map((e) => e.provider as string);
  const slotRows = await listenersOf(ctx, origin._id);
  let slot: Doc<'relayListeners'> | null = null;
  // A requested slot (the row field; `reason` carried it before the field
  // existed) is binding: a retired or vanished one FAILS the run instead of
  // silently falling back to another slot.
  const requestedSlotId: string | null =
    (rotation.listenerId as string | undefined) ??
    (rotation.reason?.startsWith('slot:') ? rotation.reason.slice(5) : null);
  if (rotation.kind === 'replace' && targetEdge)
    slot = slotRows.find((s) => s._id === targetEdge.listenerId) ?? null;
  else if (requestedSlotId) {
    slot = slotRows.find((s) => (s._id as string) === requestedSlotId && !s.retired) ?? null;
    if (!slot)
      return {
        listener: null,
        standbyId: null,
        account: null,
        accountFailure: 'listener_not_found',
        template: null,
      };
  }
  if (!slot) {
    const pick = pickSlot(
      slotRows.map((s) => ({
        slotId: s._id,
        slotKey: s.listenerKey,
        proto: protoOf(s),
        provider: s.providerScope?.provider ?? '',
        deployed: s.deployed,
        retired: s.retired,
        profileEnabled: s.enabled,
        activeSnis: activeNames(s).length,
      })),
      publishedProviders,
      cfg.render.preferDistinctProviders,
      origin.providerPreference ?? null,
    );
    slot = pick ? (slotRows.find((s) => s._id === pick.slotId) ?? null) : null;
  }
  if (!slot)
    return {
      listener: null,
      standbyId: null,
      account: null,
      accountFailure: 'no_compatible_listener',
      template: null,
    };
  const listener = slot;
  const standby = pickStandby(
    edges.map((e) => ({
      id: e._id,
      slotId: e.listenerId,
      provider: e.provider ?? null,
      accountId: e.accountId ?? null,
      status: e.status,
      publication: e.publication,
      health: e.health,
      // An untested L4 spare is not a candidate (lib/edges/verification.ts).
      hasAddress:
        hasPublishableAddress(e) &&
        standbyEligible(
          e,
          slotRows.find((s) => s._id === e.listenerId),
        ),
    })),
    slot._id,
    publishedProviders,
    targetEdge?._id ?? null,
    cfg.requireProviderHealth,
    (listener.providerScope?.accountId as Id<'edgeProviderAccounts'> | undefined) ?? null,
  );
  if (standby && (rotation.kind === 'replace' || rotation.publishOnDone)) {
    return {
      listener,
      standbyId: standby.id as Id<'edges'>,
      account: null,
      accountFailure: null,
      template: null,
    };
  }
  // Which LAYERS the complete client-to-origin chain allows in front of this
  // slot, and which providers can carry its protocol at all. An account that
  // cannot front the slot is not a candidate: picking it would provision an edge
  // that `checkPublishable` would then refuse (`layer_mismatch` /
  // `protocol_not_carried`) after the provider had already been paid.
  const layers = listenerLayers(listener).layers;
  // Every trigger except an operator's own request is "automatic" for the L7
  // gate: an unproven front must not reach members because a cron or the
  // detector chose it.
  const allowL7 = rotation.trigger === 'manual' || l7SelectionAllowed(cfg);
  const eligibleAccounts = accountsForSlot(
    (await ctx.db.query('edgeProviderAccounts').collect()).filter((a) => a.enabled),
    { layers, proto: protoOf(listener), allowL7 },
  );
  const accounts = eligibleAccounts;
  const failure = (code: string): SelectionContext => ({
    listener,
    standbyId: null,
    account: null,
    accountFailure: code,
    template: null,
  });
  if (rotation.requestedAccountId) {
    // The explicit bootstrap path: the operator named the account. It must be
    // enabled, tested and able to front this listener; qualification is waived
    // only when the request says so (the result is then never published).
    const a = await ctx.db.get(rotation.requestedAccountId);
    if (!a) return failure('account_not_found');
    if (!a.enabled) return failure('account_disabled');
    if (!accountTested(a)) return failure('account_untested');
    if (!eligibleAccounts.some((e) => e._id === a._id)) return failure('account_incompatible');
    if (!a.qualified && !rotation.allowUnqualified) return failure('no_qualified_account');
    if (listener.providerScope?.accountId && a._id !== listener.providerScope.accountId)
      return failure('account_mismatch');
    const live = (await liveEdgesOfAccount(ctx.db, a._id)).filter((e) => e.managed).length;
    if (live >= a.maxLiveEdges) return failure('account_capacity_reached');
    const today = a.allocationsDayKey === todayKey() ? a.allocationsToday : 0;
    if (a.dailyAllocationBudget !== 0 && today >= a.dailyAllocationBudget)
      return failure('account_budget_exhausted');
    const template = await resolveTemplateFor(
      ctx,
      a.provider,
      rotation.requestedTemplateId ?? null,
      a.defaultTemplateId ?? null,
      a._id,
    );
    if (rotation.requestedTemplateId && template.id !== rotation.requestedTemplateId)
      return failure('template_not_found');
    return { listener, standbyId: null, ...(await describeAccount(ctx, a)), template };
  }
  if (accounts.length === 0) {
    return failure(layers.length === 0 ? 'no_compatible_layer' : 'no_account_for_layer');
  }
  const candidates = [];
  for (const a of accounts) {
    // An account-scoped profile provisions from that account only.
    if (listener.providerScope?.accountId && a._id !== listener.providerScope.accountId) continue;
    // Same rule as the insert-time capacity check: observe-only edges were not
    // provisioned by FCP and never consume its allocation.
    const live = (await liveEdgesOfAccount(ctx.db, a._id)).filter((e) => e.managed).length;
    candidates.push({
      id: a._id as string,
      provider: a.provider,
      qualified: a.qualified,
      priority: a.priority,
      dailyAllocationBudget: a.dailyAllocationBudget,
      allocationsToday: a.allocationsDayKey === todayKey() ? a.allocationsToday : 0,
      maxLiveEdges: a.maxLiveEdges,
      liveEdges: live,
    });
  }
  // A provider-scoped profile binds the slot to that network; an unscoped one
  // takes the best qualified account of any provider.
  const picked = listener.providerScope?.provider
    ? pickAccount(candidates, listener.providerScope.provider)
    : pickAccountAny(
        candidates,
        publishedProviders,
        cfg.render.preferDistinctProviders,
        origin.providerPreference ?? null,
      );
  if (!picked.ok)
    return {
      listener,
      standbyId: null,
      account: null,
      accountFailure: picked.code,
      template: null,
    };
  const account = accounts.find((a) => (a._id as string) === picked.account.id)!;
  const template = await resolveTemplateFor(
    ctx,
    account.provider,
    null,
    account.defaultTemplateId ?? null,
    account._id,
  );
  return { listener, standbyId: null, ...(await describeAccount(ctx, account)), template };
}

/** The selection's view of an account, with the DNS zone facts an L7 plan needs. */
async function describeAccount(
  ctx: { db: QueryCtx['db'] },
  account: Doc<'edgeProviderAccounts'>,
): Promise<Pick<SelectionContext, 'account' | 'accountFailure'>> {
  // The zone the hostname will be minted under: the account's own (a provider
  // that hosts its DNS) or the referenced DNS account's.
  const settings = account.settings as { zoneName?: string; dnsAccountId?: string };
  let zoneName = settings.zoneName ?? null;
  // The zone's encryption mode is observed on the account that HOSTS the zone
  // (a provider that hosts its own DNS: itself; otherwise the DNS account).
  let zoneHost = account;
  if (!zoneName && settings.dnsAccountId) {
    const dns = await ctx.db.get(settings.dnsAccountId as Id<'edgeProviderAccounts'>);
    zoneName = (dns?.settings as { zoneName?: string } | undefined)?.zoneName ?? null;
    if (dns) zoneHost = dns;
  }
  return {
    account: {
      id: account._id,
      provider: account.provider,
      defaultTemplateId: account.defaultTemplateId ?? null,
      zoneName,
      zoneSslMode: parseObservedSettings(zoneHost.observedSettings).zoneSslMode ?? null,
    },
    accountFailure: null,
  };
}

// --- the step action ---------------------------------------------------------------------------

type Ctx = NonNullable<Awaited<ReturnType<typeof stepContextHandler>>>;
async function stepContextHandler(ctx: ActionCtx, rotationId: Id<'edgeRotations'>) {
  return ctx.runQuery(internal.edgeRotations.stepContext, { rotationId });
}

/**
 * The provider-facing spec; `transport` rides along so a udp slot is refused
 * before any call. For an L7 edge the hostname and the origin transport come
 * from the FROZEN intent, never from the account or the slot as they are now:
 * an operator edit mid-rotation must not make the adapter create one resource
 * and then look for another.
 */
function specOf(edge: Edge) {
  const intent = parseIntent(edge.provisionIntent);
  return {
    name: edge.name,
    listeners: edge.listeners.map((l) => ({
      edgePort: l.edgePort,
      members: [{ address: l.originAddress, port: l.originPort }],
      ...(l.transport ? { transport: l.transport } : {}),
    })),
    ...(intent ? { hostname: intent.hostname, originTransport: intent.originTransport } : {}),
  };
}

/**
 * The template the remaining steps run with. An L7 edge uses the params frozen
 * in its intent (the template row may have been edited since), plus
 * `zoneSslMode`, which the adapter reads as an extra parameter: the zone's
 * encryption mode decides the default origin port, and following a live change
 * would silently repoint an edge that was planned against the old mode.
 */
function templateParamsOf(edge: Edge, fallback: Record<string, unknown>): Record<string, unknown> {
  const intent = parseIntent(edge.provisionIntent);
  if (!intent) return fallback;
  return {
    ...intent.templateParams,
    ...(intent.zoneSslMode ? { zoneSslMode: intent.zoneSslMode } : {}),
  };
}

/**
 * The EXTERNAL lock a step needs, or null. `claimOp` serialises work on one
 * edge; a step that rewrites something several edges share needs more. A
 * Cloudflare origin rule is one rule inside the ZONE's rule set: two edges
 * bootstrapping that rule set at once would each read it and each write it
 * back, and the second write would drop the first rule. The key is the zone, so
 * every account row pointing at that zone serialises on it.
 */
export function stepLockKey(edge: Edge, stepKind: string): string | null {
  if (stepKind !== 'create_origin_rule') return null;
  const intent = parseIntent(edge.provisionIntent);
  return intent?.zoneId ? `cloudflare-zone:${intent.zoneId}` : null;
}

/** The lock a Fastly shared-service teardown serialises on (one service, several adopted domains). */
export function sharedTeardownLockKey(edge: Edge): string | null {
  const serviceId = edge.sharedTeardown?.serviceId;
  return serviceId ? `fastly-service:${serviceId}` : null;
}

function resourceStepOf(s: Edge['steps'][number]): ResourceStep {
  return {
    id: s.stepId,
    kind: s.kind as ResourceStep['kind'],
    resourceName: s.resourceName,
    discoverability: s.discoverability ?? 'by_name',
  };
}

/**
 * Code + short detail of a thrown error. Provider ops cross the action boundary
 * as `ConvexError<EdgeProviderOpsFailure>` (edgeProviderOps.ts), so the code,
 * HTTP status and retry/timeout flags are read from `err.data`; a plain Error
 * (a panel call, a mutation refusal) contributes only its body-free message.
 */
function errCode(err: unknown): {
  code: string;
  detail: string;
  status?: number;
  retryable: boolean;
  timedOut: boolean;
} {
  if (err instanceof ConvexError) {
    const d = err.data as
      | {
          code?: string;
          message?: string;
          status?: number;
          retryable?: boolean;
          timedOut?: boolean;
        }
      | string;
    if (typeof d === 'string')
      return { code: 'error', detail: d.slice(0, 120), retryable: false, timedOut: false };
    return {
      code: d.code ?? 'error',
      detail: `${d.status ?? ''} ${d.message ?? ''}`.trim().slice(0, 120),
      status: d.status,
      retryable: d.retryable === true,
      timedOut: d.timedOut === true,
    };
  }
  const m = err instanceof Error ? err.message : String(err);
  return { code: 'error', detail: m.slice(0, 120), retryable: false, timedOut: false };
}

export const step = internalAction({
  args: { rotationId: v.id('edgeRotations') },
  handler: async (ctx, { rotationId }): Promise<null> => {
    const c = await stepContextHandler(ctx, rotationId);
    if (!c || isTerminalPhase(c.rotation.phase)) return null;
    const { rotation: r, cfg } = c;
    const sv = r.stepVersion;
    await ctx.runMutation(internal.edgeRotations.markStepStarted, { rotationId, stepVersion: sv });
    const adv = (event: Parameters<typeof advanceCall>[3]) =>
      advanceCall(ctx, rotationId, sv, event);
    // Cancel handling first.
    if (r.cancelRequested) {
      if ((CANCELLABLE_PHASES as readonly string[]).includes(r.phase)) {
        await adv({ type: 'cancelled' });
        return null;
      }
      if ((ROLLBACK_ON_CANCEL_PHASES as readonly string[]).includes(r.phase)) {
        await adv({ type: 'fail', code: 'cancelled', rollback: true });
        return null;
      }
    }
    // Bounded retries: a run that exceeds its wall clock or keeps throwing must
    // end somewhere. Early phases fail; publishing / flipping roll back; once
    // the panel may hold the new binding (confirming / rolling back) the
    // origin is quarantined with the reason spelled out.
    // (A rollback the wall clock itself triggered must be allowed to run: in
    // `rolling_back` only the error budget + the Host attempt caps apply.)
    const now = Date.now();
    const cap =
      r.phase !== 'rolling_back' && now - r.startedAt > edgeMs.maxRotation(cfg)
        ? 'rotation_timeout'
        : (r.stepErrors ?? 0) >= MAX_STEP_ERRORS
          ? 'step_errors_exhausted'
          : null;
    if (cap) {
      if ((ROLLBACK_ON_CANCEL_PHASES as readonly string[]).includes(r.phase)) {
        await adv({ type: 'fail', code: cap, rollback: true });
      } else if (['confirming', 'finalizing', 'rolling_back'].includes(r.phase)) {
        if (r.phase === 'rolling_back')
          await ctx.runMutation(internal.edgeRotations.applyRollbackBinding, {
            rotationId: r._id,
          });
        await adv({
          type: 'quarantine',
          reason: `${cap} during ${r.phase} (${Math.round((now - r.startedAt) / 60_000)} min, ${r.stepErrors ?? 0} step errors)`,
        });
      } else {
        await adv({ type: 'fail', code: cap, rollback: false });
      }
      return null;
    }
    try {
      switch (r.phase) {
        case 'select':
          await phaseSelect(ctx, c);
          return null;
        case 'provisioning':
          await phaseProvisioning(ctx, c);
          return null;
        case 'verifying':
          await phaseVerifying(ctx, c);
          return null;
        case 'publishing': {
          const res = await ctx.runMutation(internal.edgeRotations.applyPublish, {
            rotationId,
            stepVersion: sv,
          });
          if (!res.ok && res.code !== 'stale')
            await adv({ type: 'fail', code: res.code, rollback: false });
          return null;
        }
        case 'host_flipping':
          await phaseHostFlip(ctx, c);
          return null;
        case 'confirming':
          await phaseConfirming(ctx, c);
          return null;
        case 'finalizing':
          await ctx.runMutation(internal.edgeRotations.finalize, { rotationId, stepVersion: sv });
          return null;
        case 'rolling_back':
          await phaseRollingBack(ctx, c);
          return null;
        default:
          return null;
      }
    } catch (err) {
      // An unexpected throw must not strand the rotation: record and retry after
      // a poll. Counted (`stepErrors`) so the cap above ends a run that keeps throwing.
      const { code, detail } = errCode(err);
      await adv({
        type: 'progress',
        delayMs: edgeMs.poll(cfg),
        detail: `step error: ${code} ${detail}`.trim(),
        countPoll: true,
        countError: true,
      });
      return null;
    }
  },
});

async function advanceCall(
  ctx: ActionCtx,
  rotationId: Id<'edgeRotations'>,
  stepVersion: number,
  event:
    | { type: 'selected'; toEdgeId: Id<'edges'>; viaStandby: boolean }
    | {
        type: 'progress';
        delayMs: number;
        detail?: string;
        countPoll?: boolean;
        countError?: boolean;
      }
    | { type: 'provisioned' }
    | { type: 'verified' }
    | { type: 'host_converged'; flipped: number }
    | { type: 'reflip' }
    | { type: 'confirmed' }
    | { type: 'fail'; code: string; detail?: string; rollback: boolean }
    | { type: 'rolled_back' }
    | { type: 'quarantine'; reason: string }
    | { type: 'cancelled' },
) {
  return ctx.runMutation(internal.edgeRotations.advance, { rotationId, stepVersion, event });
}

async function phaseSelect(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, origin, selection } = c;
  const sv = r.stepVersion;
  if (r.kind === 'publish' && r.toEdgeId) {
    await advanceCall(ctx, r._id, sv, { type: 'selected', toEdgeId: r.toEdgeId, viaStandby: true });
    return;
  }
  if (!selection || !selection.listener) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: selection?.accountFailure ?? 'no_compatible_listener',
      rollback: false,
    });
    return;
  }
  if (selection.standbyId) {
    await advanceCall(ctx, r._id, sv, {
      type: 'selected',
      toEdgeId: selection.standbyId,
      viaStandby: true,
    });
    return;
  }
  if (!selection.account || !selection.template) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: selection.accountFailure ?? 'no_account',
      rollback: false,
    });
    return;
  }
  const nonce = randomHex(4);
  const name = edgeResourceName(origin.slug, nonce);
  const listeners = [
    {
      edgePort: 443,
      originAddress: origin.originAddress,
      originPort: selection.listener.originPort,
      transport: protocolTransport(selection.listener),
    },
  ];
  // An L7 edge's hostname is minted HERE, from the resource name and the zone,
  // by the same deterministic function `buildProvisionIntent` uses when it
  // freezes the intent one mutation later: the plan and the intent therefore
  // name the same host without either having to persist it first.
  const fail = (code: string, detail?: string) =>
    advanceCall(ctx, r._id, sv, { type: 'fail', code, detail, rollback: false });
  let hostname: string | undefined;
  const originTransport = selection.listener.originTransport ?? undefined;
  // The zone's mode describes the origin leg only when the front IS the zone's
  // proxy; for any other CDN the referenced zone merely holds unproxied CNAMEs.
  const zoneModeApplies = zoneModeGovernsOrigin(selection.account.provider);
  const zoneSslMode = zoneModeApplies ? (selection.account.zoneSslMode ?? undefined) : undefined;
  if (edgeLayerOf(selection.account.provider) === 'l7') {
    if (!selection.account.zoneName) return void (await fail('dns_zone_missing'));
    if (!originTransport) return void (await fail('origin_transport_missing'));
    // The zone's encryption mode is OBSERVED, never entered: an untested
    // account cannot be planned against, and a mode that cannot carry the
    // slot's origin transport is refused before anything is allocated.
    if (zoneModeApplies) {
      if (!zoneSslMode) return void (await fail('zone_mode_unknown'));
      if (!zoneModeCarriesOrigin(zoneSslMode, originTransport))
        return void (await fail('origin_tls_mismatch'));
    }
    const tpl = selection.template.params as { labelLength?: number; labelPrefix?: string };
    try {
      hostname = edgeHostnameFor(name, selection.account.zoneName, {
        labelLength: typeof tpl.labelLength === 'number' ? tpl.labelLength : 12,
        labelPrefix: tpl.labelPrefix,
      });
    } catch {
      return void (await fail('hostname_invalid'));
    }
  }
  const spec = {
    name,
    listeners: listeners.map((l) => ({
      edgePort: l.edgePort,
      members: [{ address: l.originAddress, port: l.originPort }],
      ...(l.transport ? { transport: l.transport } : {}),
    })),
    ...(hostname ? { hostname, originTransport } : {}),
  };
  // The EFFECTIVE params (adapter schema defaults applied, placeholders
  // rendered) are what the intent freezes, so a later step never needs the
  // template row again.
  let effectiveParams: Record<string, unknown>;
  try {
    effectiveParams = await ctx.runAction(internal.edgeProviderOps.effectiveTemplate, {
      accountId: selection.account.id,
      spec,
      templateParams: selection.template.params,
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await fail(`plan_failed:${code}`, detail);
    return;
  }
  let steps: ResourceStep[];
  try {
    steps = await ctx.runAction(internal.edgeProviderOps.planProvision, {
      accountId: selection.account.id,
      spec,
      templateParams: selection.template.params,
      proto: protoOf(selection.listener),
      ...(zoneSslMode ? { zoneSslMode } : {}),
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: `plan_failed:${code}`,
      detail,
      rollback: false,
    });
    return;
  }
  const res = await ctx.runMutation(internal.edgeRotations.commitSelection, {
    rotationId: r._id,
    stepVersion: sv,
    listenerId: selection.listener._id,
    accountId: selection.account.id,
    templateId: selection.template.id,
    templateHash: selection.template.hash,
    nameNonce: nonce,
    listeners,
    templateParams: effectiveParams,
    steps: steps.map((s) => ({
      id: s.id,
      kind: s.kind,
      resourceName: s.resourceName,
      discoverability: s.discoverability,
    })),
  });
  if (!res.ok && res.code !== 'stale')
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: res.code, rollback: false });
}

async function phaseProvisioning(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge } = c;
  const sv = r.stepVersion;
  const poll = edgeMs.poll(cfg);
  if (!edge || !edge.accountId) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'edge_missing', rollback: false });
    return;
  }
  const now = Date.now();
  if (edge._creationTime + edgeMs.provisionTimeout(cfg) < now) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'provision_timeout', rollback: false });
    return;
  }
  // The template must not change under a running provision.
  const tpl = await ctx.runQuery(internal.edgeTemplates.resolveForProvision, {
    provider: edge.provider!,
    templateId: edge.templateId ?? null,
    accountDefaultId: null,
    // Account-scoped templates resolve only for their own account.
    accountId: edge.accountId,
  });
  if (tpl.hash !== edge.templateHash) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'template_changed', rollback: false });
    return;
  }
  const ledger = { steps: edge.steps, resources: edge.resources };
  const accountId = edge.accountId;
  const pending = edge.steps.find((s) => s.state !== 'done');
  if (!pending) {
    // Every step done: describe until the LB is active with an IPv4.
    let desc: EdgeDescription;
    try {
      desc = await ctx.runAction(internal.edgeProviderOps.describe, {
        accountId,
        ledger,
        edgeId: edge._id,
      });
    } catch (err) {
      const { code, detail } = errCode(err);
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: `describe failed: ${code} ${detail}`.trim(),
        countPoll: true,
      });
      return;
    }
    await ctx.runMutation(internal.edges.recordDescribe, {
      edgeId: edge._id,
      state: desc.state,
      addresses: desc.addresses,
      health: desc.health,
      resources: desc.resources,
      readiness: desc.readiness,
    });
    if (desc.state === 'error' || desc.state === 'gone') {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: `provider_${desc.state}`,
        detail: desc.code,
        rollback: false,
      });
      return;
    }
    // The address to wait for is the one this edge's LAYER publishes: an L7
    // front never reports an IPv4 of its own.
    if (
      desc.state === 'active' &&
      hasPublishableAddress({ layer: edge.layer, addresses: desc.addresses })
    ) {
      await advanceCall(ctx, r._id, sv, { type: 'provisioned' });
      return;
    }
    await advanceCall(ctx, r._id, sv, { type: 'progress', delayMs: poll, countPoll: true });
    return;
  }
  const step = resourceStepOf(pending);
  const spec = specOf(edge);
  const settle = (opId: string, patch: Parameters<typeof settleEdgeOp>[3]) =>
    settleEdgeOp(ctx, edge._id, opId, patch);
  const claim = async (kind: 'provision_step' | 'poll_step' | 'discover') =>
    ctx.runMutation(internal.edges.claimOp, {
      edgeId: edge._id,
      kind,
      target: pending.stepId,
      claimMs: edgeMs.opClaim(cfg),
    });

  const applyOutcome = async (opId: string, out: StepOutcome) => {
    if (out.status === 'done') {
      await settle(opId, {
        stepPatch: { stepId: pending.stepId, state: 'done', opRef: null, finished: true },
        addResources: out.resources,
        addresses: out.addresses,
        status: 'provisioning',
      });
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: 0,
        detail: `step ${pending.stepId} done`,
      });
    } else if (out.status === 'requested') {
      await settle(opId, {
        stepPatch: { stepId: pending.stepId, state: 'requested', opRef: out.opRef, started: true },
        addResources: out.resources,
      });
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: `step ${pending.stepId} requested`,
      });
    } else {
      // `partial` means the call REACHED the provider and created some children
      // before failing, so the step HAS started: without the flag a lost
      // `startedAt` would leave discovery with no reference time and its settle
      // floor unprovable (the same hole R1 closed for the claim).
      await settle(opId, {
        stepPatch: { stepId: pending.stepId, state: 'unresolved', started: true },
        addResources: out.resources,
        failure: { step: pending.stepId, code: out.code },
      });
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: `step ${pending.stepId} partial: ${out.code ?? ''}`.trim(),
        countPoll: true,
      });
    }
  };

  switch (pending.state) {
    case 'pending': {
      const cl = await claim('provision_step');
      if (!cl.ok) {
        if (cl.code === 'edge.op_unsettled') {
          await ctx.runMutation(internal.edges.patchEdge, {
            edgeId: edge._id,
            stepStates: [{ stepId: pending.stepId, state: 'unresolved' }],
          });
        }
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: cl.code,
          countPoll: true,
        });
        return;
      }
      // A step that rewrites a SHARED external object takes the external lock
      // too. A busy lock is simply a wait; an expired unsettled one means its
      // previous holder's write is still unknown, so nothing may touch the
      // shared object until that holder re-observes it.
      const lockKey = stepLockKey(edge, pending.kind);
      if (lockKey) {
        const lk = await ctx.runMutation(internal.edges.claimExternalLock, {
          key: lockKey,
          edgeId: edge._id,
          opId: cl.opId,
          ttlMs: edgeMs.opClaim(cfg),
        });
        if (!lk.ok) {
          await settle(cl.opId, {});
          await advanceCall(ctx, r._id, sv, {
            type: 'progress',
            delayMs: poll,
            detail: lk.code,
            countPoll: true,
          });
          return;
        }
      }
      const releaseLock = async () => {
        if (lockKey)
          await ctx.runMutation(internal.edges.settleExternalLock, { key: lockKey, opId: cl.opId });
      };
      let out: StepOutcome;
      try {
        out = await ctx.runAction(internal.edgeProviderOps.runStep, {
          accountId,
          spec,
          templateParams: templateParamsOf(edge, tpl.params),
          step,
          ledger,
          edgeId: edge._id,
          proto: c.listener ? protoOf(c.listener) : undefined,
        });
      } catch (err) {
        // The lock is deliberately NOT released: the write's outcome is
        // unknown, and the discovery pass that resolves it releases it.
        const { code, detail } = errCode(err);
        await settle(cl.opId, {
          stepPatch: { stepId: pending.stepId, state: 'unresolved', started: true },
          failure: { step: pending.stepId, code },
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: `step ${pending.stepId} threw: ${code} ${detail}`.trim(),
          countPoll: true,
        });
        return;
      }
      // A known outcome (done / requested) releases the shared object; a
      // `partial` leaves it half-written, so the lock is held until discovery.
      if (out.status !== 'partial') await releaseLock();
      await applyOutcome(cl.opId, out);
      return;
    }
    case 'requested': {
      const cl = await claim('poll_step');
      if (!cl.ok) {
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: cl.code,
          countPoll: true,
        });
        return;
      }
      let out: StepOutcome;
      try {
        out = await ctx.runAction(internal.edgeProviderOps.pollStep, {
          accountId,
          step,
          opRef: pending.opRef ?? '',
          ledger,
          edgeId: edge._id,
        });
      } catch (err) {
        const { code, detail } = errCode(err);
        await settle(cl.opId, {
          stepPatch: { stepId: pending.stepId, state: 'unresolved' },
          failure: { step: pending.stepId, code },
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: `poll ${pending.stepId} threw: ${code} ${detail}`.trim(),
          countPoll: true,
        });
        return;
      }
      await applyOutcome(cl.opId, out);
      return;
    }
    case 'unresolved': {
      const cl = await claim('discover');
      if (!cl.ok) {
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: cl.code,
          countPoll: true,
        });
        return;
      }
      // Attempts live on the step (each pass settles the claim; adapters need
      // ≥2 quiet looks before `confirmed_absent`).
      const discoverAttempt = (pending.discoverAttempts ?? 0) + 1;
      // Once discovery ANSWERS, the shared object's state is known again, so the
      // lock a lost write left behind is released here (whatever opId held it).
      const discoveryLockKey = stepLockKey(edge, pending.kind);
      const releaseAfterDiscovery = async () => {
        if (discoveryLockKey)
          await ctx.runMutation(internal.edges.releaseExternalLocksOf, {
            edgeId: edge._id,
            keys: [discoveryLockKey],
          });
      };
      let disc: Discovery;
      try {
        disc = await ctx.runAction(internal.edgeProviderOps.discover, {
          accountId,
          spec,
          step,
          ledger,
          attempt: discoverAttempt,
          edgeId: edge._id,
          // A lost settle can leave the step unstamped; the claim time (and
          // failing that the edge's creation) is the oldest moment the request
          // could have left, so the settle floor is measured from there.
          stepStartedAt: pending.startedAt ?? edge.currentOp?.claimedAt ?? edge._creationTime,
        });
      } catch (err) {
        const { code, detail } = errCode(err);
        await settle(cl.opId, {});
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: `discover ${pending.stepId} threw: ${code} ${detail}`.trim(),
          countPoll: true,
        });
        return;
      }
      if (disc.status === 'found') {
        await releaseAfterDiscovery();
        await settle(cl.opId, {
          stepPatch: { stepId: pending.stepId, state: 'done', opRef: null, finished: true },
          addResources: disc.resources,
          addresses: disc.addresses,
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: 0,
          detail: `step ${pending.stepId} recovered`,
        });
        return;
      }
      if (disc.status === 'confirmed_absent') {
        await releaseAfterDiscovery();
        const attempt = pending.attempt + 1;
        if (attempt > MAX_STEP_RETRIES) {
          await settle(cl.opId, {
            stepPatch: { stepId: pending.stepId, state: 'needs_operator', attempt },
          });
          await advanceCall(ctx, r._id, sv, {
            type: 'fail',
            code: 'step_retries_exhausted',
            detail: pending.stepId,
            rollback: false,
          });
          return;
        }
        // Nothing was created: safe to run the step again.
        await settle(cl.opId, {
          stepPatch: { stepId: pending.stepId, state: 'pending', opRef: null, attempt },
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: 0,
          detail: `step ${pending.stepId} absent, retry ${attempt}`,
        });
        return;
      }
      if (disc.status === 'ambiguous') {
        await releaseAfterDiscovery();
        await settle(cl.opId, {
          stepPatch: { stepId: pending.stepId, state: 'ambiguous' },
          addResources: disc.candidates.map((x) => ({ ...x, ownership: 'adopted' as const })),
          status: 'needs_operator',
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: 'ambiguous_resource',
          detail: pending.stepId,
          rollback: false,
        });
        return;
      }
      // unresolved
      await settle(cl.opId, {
        stepPatch: {
          stepId: pending.stepId,
          state: pending.state,
          discoverAttempts: discoverAttempt,
        },
      });
      if ((pending.startedAt ?? edge._creationTime) + edgeMs.discoveryTimeout(cfg) < now) {
        await ctx.runMutation(internal.edges.patchEdge, {
          edgeId: edge._id,
          status: 'needs_operator',
          stepStates: [{ stepId: pending.stepId, state: 'needs_operator' }],
        });
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: 'discovery_timeout',
          detail: pending.stepId,
          rollback: false,
        });
        return;
      }
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: `step ${pending.stepId} still unresolved`,
        countPoll: true,
      });
      return;
    }
    default:
      // ambiguous / needs_operator: an operator decides.
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: `step_${pending.state}`,
        detail: pending.stepId,
        rollback: false,
      });
      return;
  }
}

async function settleEdgeOp(
  ctx: ActionCtx,
  edgeId: Id<'edges'>,
  opId: string,
  patch: {
    stepPatch?: {
      stepId: string;
      state: string;
      opRef?: string | null;
      attempt?: number;
      discoverAttempts?: number;
      started?: boolean;
      finished?: boolean;
    };
    addResources?: Array<{
      kind: string;
      resourceId: string;
      ownership: 'created' | 'adopted';
      meta?: unknown;
    }>;
    addresses?: { v4?: string; v6?: string };
    status?: string;
    failure?: { step: string; code?: string; status?: number };
  },
) {
  await ctx.runMutation(internal.edges.settleOp, { edgeId, opId, ...patch });
}

async function phaseVerifying(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge, origin } = c;
  const sv = r.stepVersion;
  if (!edge) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'edge_missing', rollback: false });
    return;
  }
  if (edge.managed && edge.accountId) {
    let desc: EdgeDescription;
    try {
      desc = await ctx.runAction(internal.edgeProviderOps.describe, {
        accountId: edge.accountId,
        ledger: { steps: edge.steps, resources: edge.resources },
        edgeId: edge._id,
      });
    } catch (err) {
      const { code, detail } = errCode(err);
      if (r.pollAttempts + 1 >= cfg.verifyAttempts) {
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: 'verify_timeout',
          detail: `${code} ${detail}`.trim(),
          rollback: false,
        });
        return;
      }
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: edgeMs.poll(cfg),
        detail: `describe failed: ${code}`,
        countPoll: true,
      });
      return;
    }
    await ctx.runMutation(internal.edges.recordDescribe, {
      edgeId: edge._id,
      state: desc.state,
      addresses: desc.addresses,
      health: desc.health,
      resources: desc.resources,
      readiness: desc.readiness,
    });
    if (desc.state === 'gone' || desc.state === 'error') {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: `provider_${desc.state}`,
        detail: desc.code,
        rollback: false,
      });
      return;
    }
    // The address to verify is the one this LAYER publishes: an L7 front has a
    // hostname and no IPv4 of its own.
    const merged = {
      v4: desc.addresses.v4 ?? edge.addresses.v4,
      v6: desc.addresses.v6 ?? edge.addresses.v6,
      hostname: desc.addresses.hostname ?? edge.addresses.hostname,
    };
    const publishAddress = publishAddressOf({ layer: edge.layer, addresses: merged });
    // A provider without member health never answers `online`: `unknown` is enough from it.
    const healthy = providerHealthSatisfies(edge.provider, desc.health, cfg.requireProviderHealth);
    if (!(desc.state === 'active' && publishAddress && healthy)) {
      if (r.pollAttempts + 1 >= cfg.verifyAttempts) {
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: 'verify_timeout',
          detail: `state=${desc.state} health=${desc.health}`,
          rollback: false,
        });
        return;
      }
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: edgeMs.poll(cfg),
        detail: `waiting: state=${desc.state} health=${desc.health}`,
        countPoll: true,
      });
      return;
    }
    // Whatever the layer, what members would be sent to must not be the node
    // itself: publishing that would hand every subscriber the origin.
    if (sameAddress(publishAddress, origin.originAddress)) {
      await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'edge_is_origin', rollback: false });
      return;
    }
    // An L7 front answers DNS and serves a certificate long before it carries
    // the transport: provider readiness is not publishability. Require an
    // authenticated end-to-end session through the deployed transport and,
    // for a replacement the detector asked for, evidence from the countries
    // that reported the block.
    if ((edge.layer ?? 'l4') === 'l7') {
      const gate = await l7VerifyGate(ctx, c, edge);
      if (gate.kind === 'fail') {
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: gate.code,
          detail: gate.detail,
          rollback: false,
        });
        return;
      }
      if (gate.kind === 'wait') {
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: edgeMs.poll(cfg),
          detail: gate.detail,
          countPoll: true,
        });
        return;
      }
    }
  } else if (!hasPublishableAddress(edge)) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'no_address', rollback: false });
    return;
  }
  await advanceCall(ctx, r._id, sv, { type: 'verified' });
}

type VerifyGate =
  | { kind: 'ok' }
  | { kind: 'wait'; detail: string }
  | { kind: 'fail'; code: string; detail?: string };

/**
 * The L7 publishability gate, run inside `verifying` (and once more in
 * `confirming` for its geographic half):
 *
 *  1. the transport proof: one authenticated session through the front,
 *     bounded and run at most once per poll; a throw is a poll failure, not a
 *     verdict;
 *  2. for a DETECTOR-triggered replacement, probes of the new hostname from
 *     every country the evidence named. `reachable` everywhere proceeds; any
 *     `unreachable` fails (`replacement_blocked`, counted against the relay's
 *     same-provider day bound, because a new hostname on the same CDN is often
 *     the same anycast frontend); anything else (timeout, `unknown`, `mixed`)
 *     fails `qualification_inconclusive`. An unknown result is never a success.
 *
 * A manual publish may waive ONLY step 2 with an audited `forceGeoEvidence`.
 */
async function l7VerifyGate(ctx: ActionCtx, c: Ctx, edge: Edge): Promise<VerifyGate> {
  const { rotation: r, cfg } = c;
  try {
    await ctx.runAction(internal.frontQualifyOps.run, { edgeId: edge._id });
  } catch (err) {
    // The session could not be RUN (the action threw): that is a poll failure,
    // never a verdict about the front.
    const { code, detail } = errCode(err);
    if (r.pollAttempts + 1 >= cfg.verifyAttempts)
      return {
        kind: 'fail',
        code: 'front_qualification_failed',
        detail: `${code} ${detail}`.trim(),
      };
    return { kind: 'wait', detail: `front qualification threw: ${code}` };
  }
  const state = await ctx.runQuery(internal.edgeRotations.l7GateState, {
    rotationId: r._id,
    edgeId: edge._id,
  });
  if (!state) return { kind: 'fail', code: 'edge_missing' };
  if (!state.qualified) {
    if (r.pollAttempts + 1 >= cfg.verifyAttempts)
      return {
        kind: 'fail',
        code: 'front_unqualified',
        detail: state.qualificationCode ?? undefined,
      };
    return { kind: 'wait', detail: `front not qualified: ${state.qualificationCode ?? 'pending'}` };
  }
  if (!state.needsGeoEvidence) return { kind: 'ok' };
  return geoEvidenceGate(ctx, c, edge, state.affectedCountries);
}

/** The affected-country half, shared by `verifying` and the `confirming` re-check. */
async function geoEvidenceGate(
  ctx: ActionCtx,
  c: Ctx,
  edge: Edge,
  countries: readonly string[],
): Promise<VerifyGate> {
  const { rotation: r, cfg } = c;
  if (countries.length === 0)
    // The detector named no country: there is nothing to prove reachable, and
    // an empty proof is not a proof.
    return { kind: 'fail', code: 'qualification_inconclusive', detail: 'no affected country' };
  const verdicts = await ctx.runQuery(internal.edgeRotations.edgeReachability, {
    edgeId: edge._id,
    countries: [...countries],
  });
  if (verdicts.some((v) => v.verdict === 'unreachable')) {
    await ctx.runMutation(internal.edgeRotations.countL7Replacement, { rotationId: r._id });
    return {
      kind: 'fail',
      code: 'replacement_blocked',
      detail: verdicts
        .filter((v) => v.verdict === 'unreachable')
        .map((v) => v.country)
        .join(','),
    };
  }
  if (verdicts.every((v) => v.verdict === 'reachable')) return { kind: 'ok' };
  // Still waiting: request the round once, then poll until the timeout.
  const waitedMs = Date.now() - (r.provisionedAt ?? r.startedAt);
  if (waitedMs > cfg.l7.qualifyTimeoutMinutes * 60_000)
    return {
      kind: 'fail',
      code: 'qualification_inconclusive',
      detail: verdicts.map((v) => `${v.country}:${v.verdict}`).join(','),
    };
  // Nothing measured, or nothing measured RECENTLY: a verdict older than the
  // freshness window is not evidence about this hostname now, so the round is
  // requested and the gate waits for it rather than passing on a stale
  // `reachable` (which is exactly how a blocked replacement would slip out).
  if (verdicts.every((v) => v.verdict === 'absent' || v.verdict === 'stale')) {
    try {
      await ctx.runMutation(internal.probes.requestProbes, {
        target: { kind: 'edge', ref: edge._id as string },
        trigger: 'qualification',
      });
    } catch (err) {
      // A budget refusal is not a verdict either; the next poll retries.
      const { code } = errCode(err);
      return { kind: 'wait', detail: `probe request: ${code}` };
    }
  }
  return { kind: 'wait', detail: 'awaiting affected-country evidence' };
}

async function listHosts(ctx: ActionCtx, origin: Origin): Promise<BackendHost[]> {
  return ctx.runAction(internal.backends.listHosts, { backendServerId: panelServerId(origin) });
}

/**
 * The FULL Host tuple the flip must land: address, port, SNI and Host header,
 * from the single source `hostTargetFor`. Writing only address/port would leave
 * a stale name behind whenever the layer changes (an L4 IP front replaced by an
 * L7 hostname front or back), so members would present the previous layer's SNI
 * to the new one. `null` in the tuple means CLEAR the field.
 */
function flipTargetFor(edge: Edge, listener: Doc<'relayListeners'> | null): HostTarget | null {
  if (!listener) return null;
  const selectedSni = activeNames(listener)[0] ?? null;
  return hostTargetFor(
    {
      layer: edge.layer,
      addresses: edge.addresses,
      edgePort: edge.listeners[0]?.edgePort ?? 443,
    },
    protoOf(listener),
    selectedSni,
  );
}

function protoOf(l: ListenerProto): ListenerProto {
  return { protocol: l.protocol, streamTransport: l.streamTransport, security: l.security };
}

/** The panel behind a relay whose Hosts FCP manages (a panel-node origin). */
function panelServerId(origin: Origin): Id<'backendServers'> {
  if (!origin.backendServerId) throw new Error('relay has no panel');
  return origin.backendServerId;
}

async function phaseHostFlip(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge, origin, listener: slot } = c;
  const sv = r.stepVersion;
  const poll = edgeMs.poll(cfg);
  if (!edge || !hasPublishableAddress(edge) || !slot) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: 'flip_context_missing',
      rollback: true,
    });
    return;
  }
  if (origin.hostMode !== 'fcp') {
    if (origin.hostMode === 'operator' && r.kind === 'replace' && !r.force) {
      // The flip was decided with FCP-managed Hosts at publish time; an operator
      // took them over since. Replacing the template edge without a Host write
      // would leave the panel pointing at the old edge: roll back rather than
      // "converge".
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'hosts_operator_managed',
        detail: 'hostMode changed to operator during the rotation',
        rollback: true,
      });
      return;
    }
    // No panel Host at all (Outline, manual), or the operator writes it.
    await advanceCall(ctx, r._id, sv, { type: 'host_converged', flipped: 0 });
    return;
  }
  const remark = listenerRemark(slot);
  if (!remark) {
    // An address-matched listener has no panel Host to flip.
    await advanceCall(ctx, r._id, sv, { type: 'host_converged', flipped: 0 });
    return;
  }
  let hosts: BackendHost[];
  try {
    hosts = await listHosts(ctx, origin);
  } catch (err) {
    const { code, detail } = errCode(err);
    if (r.flipAttempts + 1 > cfg.maxFlipAttempts) {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'panel_unreachable',
        detail: `${code} ${detail}`.trim(),
        rollback: true,
      });
      return;
    }
    // Count the attempt through a claim-free progress; the cap is enforced above.
    await ctx.runMutation(internal.edgeRotations.bumpFlipAttempts, {
      rotationId: r._id,
      stepVersion: sv,
      detail: `list hosts failed: ${code}`,
    });
    return;
  }
  const target = flipTargetFor(edge, slot);
  if (!target) {
    // The edge lost the address (or the listener the name) the flip needs.
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: 'flip_context_missing',
      rollback: true,
    });
    return;
  }
  if (!hostPlanCaptured(r)) {
    const matches = matchSlotHosts(
      hosts,
      [{ slotId: slot._id, slotKey: slot.listenerKey, templateHostRemark: remark }],
      origin.originAddress,
    );
    const m = matches[0];
    if (m.duplicates > 0) {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'host_duplicates',
        detail: remark,
        rollback: true,
      });
      return;
    }
    if (m.leaks) {
      // The template Host points at the origin itself: writing it would keep the
      // node exposed, and an empty plan would "converge" without a flip. Fail
      // and roll back; the operator repairs the Host by hand.
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'host_leaks_origin',
        detail: remark,
        rollback: true,
      });
      return;
    }
    if (!m.host) {
      // No panel Host yet: FCP owns the Hosts, so it CREATES this listener's
      // Host at the target through the Host state machine (persisted intent,
      // discovery after an uncertain outcome; convex/hostOps.ts). The plan is
      // then empty: the Host is born at the target, nothing to flip.
      const created = await ctx.runAction(internal.hostOps.ensureListenerHost, {
        listenerId: slot._id,
        target: {
          address: target.address,
          port: target.port,
          sni: target.sni ?? null,
          host: target.host ?? null,
        },
      });
      if (created.state !== 'present') {
        if (created.state === 'ambiguous' || created.state === 'failed') {
          await advanceCall(ctx, r._id, sv, {
            type: 'fail',
            code: created.state === 'ambiguous' ? 'host_ambiguous' : 'host_create_failed',
            detail: created.detail,
            rollback: true,
          });
          return;
        }
        // creating / unresolved: wait for discovery to settle it.
        await advanceCall(ctx, r._id, sv, {
          type: 'progress',
          delayMs: poll,
          detail: `host ${created.state}`,
        });
        return;
      }
      await ctx.runMutation(internal.edgeRotations.setHostPlan, {
        rotationId: r._id,
        stepVersion: sv,
        hostPlan: [],
        listenerId: slot._id,
        templateHostUuid: created.uuid ?? null,
      });
      return;
    }
    // Already at the target (e.g. a re-kick after the write landed) still goes through the plan.
    await ctx.runMutation(internal.edgeRotations.setHostPlan, {
      rotationId: r._id,
      stepVersion: sv,
      hostPlan: planFromMatches(matches).map((e) => ({ ...e, listenerKey: slot.listenerKey })),
      listenerId: slot._id,
      templateHostUuid: m.host.uuid,
    });
    return;
  }
  if (r.hostPlan.length === 0) {
    await advanceCall(ctx, r._id, sv, { type: 'host_converged', flipped: 0 });
    return;
  }
  const diff = diffHosts(hosts, r.hostPlan, target);
  if (diff.hostsChanged) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: 'hosts_changed',
      detail: `${diff.missing.length} missing, ${diff.changedInbound.length} rebound`,
      rollback: true,
    });
    return;
  }
  if (diff.converged) {
    await advanceCall(ctx, r._id, sv, { type: 'host_converged', flipped: r.hostPlan.length });
    return;
  }
  const entry = diff.needsWrite[0];
  const cl = await ctx.runMutation(internal.edgeRotations.claimHostOp, {
    rotationId: r._id,
    stepVersion: sv,
    hostUuid: entry.uuid,
    direction: 'forward',
  });
  if (!cl.ok) {
    if (cl.code === 'max_attempts') {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'flip_attempts_exhausted',
        rollback: true,
      });
      return;
    }
    if (cl.code === 'op_busy')
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: 'host op busy',
      });
    return;
  }
  try {
    await ctx.runAction(internal.backends.updateHost, {
      backendServerId: panelServerId(origin),
      uuid: entry.uuid,
      address: target.address,
      port: target.port,
      // Undefined stays undefined (leave the field); null clears it.
      ...(target.sni !== undefined ? { sni: target.sni } : {}),
      ...(target.host !== undefined ? { host: target.host } : {}),
    });
    await ctx.runMutation(internal.edgeRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: true,
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await ctx.runMutation(internal.edgeRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: false,
      detail: `${code} ${detail}`.trim(),
    });
  }
  // Re-observe on the next pass (claimHostOp bumped the stepVersion? no: it did not; advance does).
  await advanceCall(ctx, r._id, sv, { type: 'progress', delayMs: 0 });
}

/** A panel-unreachable pass during a flip: count it against the cap and retry after a poll. */
export const bumpFlipAttempts = internalMutation({
  args: { rotationId: v.id('edgeRotations'), stepVersion: v.number(), detail: v.string() },
  handler: async (ctx, { rotationId, stepVersion, detail }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    const field =
      r.phase === 'rolling_back'
        ? { rollbackAttempts: r.rollbackAttempts + 1 }
        : { flipAttempts: r.flipAttempts + 1 };
    await ctx.db.patch(rotationId, {
      ...field,
      stepVersion: stepVersion + 1,
      events: appendEvent(r.events, { at: now, level: 'warn', code: 'panel_unreachable', detail }),
      updatedAt: now,
    });
    await scheduleStep(ctx, rotationId, edgeMs.poll(cfg));
    return null;
  },
});

async function phaseConfirming(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge, origin, listener } = c;
  const sv = r.stepVersion;
  // The affected countries are asked ONCE MORE after the flip: the front is now
  // the one members actually receive, so a block that only shows up under real
  // traffic still rolls the rotation back instead of standing.
  if (edge && (edge.layer ?? 'l4') === 'l7') {
    const state = await ctx.runQuery(internal.edgeRotations.l7GateState, {
      rotationId: r._id,
      edgeId: edge._id,
    });
    if (state?.needsGeoEvidence && state.affectedCountries.length > 0) {
      const verdicts = await ctx.runQuery(internal.edgeRotations.edgeReachability, {
        edgeId: edge._id,
        countries: state.affectedCountries,
      });
      if (verdicts.some((v) => v.verdict === 'unreachable')) {
        await advanceCall(ctx, r._id, sv, {
          type: 'fail',
          code: 'replacement_blocked',
          detail: verdicts
            .filter((v) => v.verdict === 'unreachable')
            .map((v) => v.country)
            .join(','),
          rollback: true,
        });
        return;
      }
    }
  }
  const confirmTarget = edge ? flipTargetFor(edge, listener) : null;
  if (r.hostPlan.length === 0 || !confirmTarget) {
    await advanceCall(ctx, r._id, sv, { type: 'confirmed' });
    return;
  }
  let hosts: BackendHost[];
  try {
    hosts = await listHosts(ctx, origin);
  } catch (err) {
    // The panel is down after the Host write: bounded like the flip itself.
    // Past the cap the rotation rolls back (itself bounded → quarantine).
    const { code, detail } = errCode(err);
    if (r.flipAttempts + 1 > cfg.maxFlipAttempts) {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'panel_unreachable',
        detail: `confirm: ${code} ${detail}`.trim(),
        rollback: true,
      });
      return;
    }
    await ctx.runMutation(internal.edgeRotations.bumpFlipAttempts, {
      rotationId: r._id,
      stepVersion: sv,
      detail: `confirm: list hosts failed: ${code}`,
    });
    return;
  }
  const diff = diffHosts(hosts, r.hostPlan, confirmTarget);
  if (diff.hostsChanged) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'hosts_changed', rollback: true });
    return;
  }
  if (!diff.converged) {
    await advanceCall(ctx, r._id, sv, { type: 'reflip' });
    return;
  }
  await advanceCall(ctx, r._id, sv, { type: 'confirmed' });
}

async function phaseRollingBack(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, origin } = c;
  const sv = r.stepVersion;
  const poll = edgeMs.poll(cfg);
  await ctx.runMutation(internal.edgeRotations.applyRollbackBinding, { rotationId: r._id });
  if (r.hostPlan.length === 0 || !forwardWriteAttempted(r)) {
    // No forward Host write was ever claimed: the DB restore is the whole
    // rollback. (A claimed write whose settle was lost is NOT a shortcut: the
    // panel may hold the new address, so it is re-observed below.)
    await advanceCall(ctx, r._id, sv, { type: 'rolled_back' });
    return;
  }
  let hosts: BackendHost[];
  try {
    hosts = await listHosts(ctx, origin);
  } catch (err) {
    const { code, detail } = errCode(err);
    if (r.rollbackAttempts + 1 > cfg.maxRollbackAttempts) {
      await advanceCall(ctx, r._id, sv, {
        type: 'quarantine',
        reason: `panel unreachable during rollback: ${code} ${detail}`.trim(),
      });
      return;
    }
    await ctx.runMutation(internal.edgeRotations.bumpFlipAttempts, {
      rotationId: r._id,
      stepVersion: sv,
      detail: `rollback: list hosts failed: ${code}`,
    });
    return;
  }
  // Drift is judged by the SAME predicate the flip uses (`diffHosts`), entry by
  // entry: the inline check here used to accept a planned Host that had LOST its
  // inbound binding (`h.inbound` null), which the flip treats as drift, so a
  // rollback could keep writing to a Host the role had detached.
  let pendingEntry: Rotation['hostPlan'][number] | null = null;
  for (const p of r.hostPlan) {
    const want = rollbackTargetFor(p);
    const d = diffHosts(hosts, [p], want);
    if (d.hostsChanged) {
      await advanceCall(ctx, r._id, sv, {
        type: 'quarantine',
        reason: 'a planned Host vanished or was rebound during rollback',
      });
      return;
    }
    if (d.needsWrite.length > 0) {
      pendingEntry = p;
      break;
    }
  }
  if (!pendingEntry) {
    await advanceCall(ctx, r._id, sv, { type: 'rolled_back' });
    return;
  }
  const rollbackTarget = rollbackTargetFor(pendingEntry);
  const cl = await ctx.runMutation(internal.edgeRotations.claimHostOp, {
    rotationId: r._id,
    stepVersion: sv,
    hostUuid: pendingEntry.uuid,
    direction: 'rollback',
  });
  if (!cl.ok) {
    if (cl.code === 'max_attempts') {
      await advanceCall(ctx, r._id, sv, {
        type: 'quarantine',
        reason: 'rollback attempts exhausted',
      });
      return;
    }
    if (cl.code === 'op_busy')
      await advanceCall(ctx, r._id, sv, {
        type: 'progress',
        delayMs: poll,
        detail: 'host op busy',
      });
    return;
  }
  try {
    await ctx.runAction(internal.backends.updateHost, {
      backendServerId: panelServerId(origin),
      uuid: pendingEntry.uuid,
      address: rollbackTarget.address,
      port: rollbackTarget.port,
      // A legacy plan leaves these undefined: its historical SNI/Host are
      // UNKNOWN, and unknown must never be written back as "clear".
      ...(rollbackTarget.sni !== undefined ? { sni: rollbackTarget.sni } : {}),
      ...(rollbackTarget.host !== undefined ? { host: rollbackTarget.host } : {}),
    });
    await ctx.runMutation(internal.edgeRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: true,
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await ctx.runMutation(internal.edgeRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: false,
      detail: `${code} ${detail}`.trim(),
    });
  }
  await advanceCall(ctx, r._id, sv, { type: 'progress', delayMs: 0 });
}
