/**
 * Relay ROTATION machine: the only path that provisions, publishes and replaces
 * edges with a template-Host flip. One rotation row per run; the origin holds
 * at most one active rotation.
 *
 *   select → provisioning → verifying → publishing → host_flipping → confirming → finalizing → done
 *                                                           ↘ rolling_back → rolled_back | quarantined
 *   (failed / cancelled from the early phases)
 *
 * Contract (see docs/relays.md):
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
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { resolveRelayConfig, relayMs, type RelayConfig } from './lib/relayConfig';
import { checkPublishable, todayKey } from './relayOrigins';
import { insertPlannedEdge } from './relayEdges';
import { edgeResourceName } from './lib/relays/accountSettings';
import { matchSlotHosts, planFromMatches, diffHosts, sameAddress } from './lib/relays/hosts';
import type { BackendHost } from './lib/backends/types';
import { nextFreePoolIndex, withEdgeAt, withoutEdge } from './lib/relays/pool';
import {
  appendEvent,
  isTerminalPhase,
  progressPercent,
  pickStandby,
  pickAccount,
  pickSlot,
  CANCELLABLE_PHASES,
  ROLLBACK_ON_CANCEL_PHASES,
  ROTATION_PHASES,
  TERMINAL_PHASES,
  type RotationEvent,
} from './lib/relays/rotation';
import type {
  StepOutcome,
  Discovery,
  EdgeDescription,
  ResourceStep,
} from './lib/relays/providers/types';

type Rotation = Doc<'relayRotations'>;
type Edge = Doc<'relayEdges'>;
type Origin = Doc<'relayOrigins'>;
type Phase = Rotation['phase'];

const MAX_STEP_RETRIES = 3;
const STALE_KICK_GRACE_MS = 30_000;

// --- admin mapping -----------------------------------------------------------------------

export function mapRotationAdmin(r: Rotation, edge: Edge | null) {
  const needsHostFlip =
    r.hostPlan.length > 0 || (r.previousBinding?.poolIndex === 0 && r.kind === 'replace');
  return {
    id: r._id as string,
    originId: r.originId as string,
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
  args: { id: v.id('relayRotations') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

export const getForAdmin = internalQuery({
  args: { id: v.id('relayRotations') },
  handler: async (ctx, { id }) => {
    const r = await ctx.db.get(id);
    if (!r) return null;
    const edge = r.toEdgeId ? await ctx.db.get(r.toEdgeId) : null;
    return mapRotationAdmin(r, edge);
  },
});

export const listByOrigin = internalQuery({
  args: { originId: v.id('relayOrigins'), take: v.optional(v.number()) },
  handler: async (ctx, { originId, take }) => {
    const rows = await ctx.db
      .query('relayRotations')
      .withIndex('by_origin', (q) => q.eq('originId', originId))
      .order('desc')
      .take(Math.min(take ?? 20, 100));
    const out = [];
    for (const r of rows)
      out.push(mapRotationAdmin(r, r.toEdgeId ? await ctx.db.get(r.toEdgeId) : null));
    return out;
  },
});

async function countActiveRotations(ctx: {
  db: import('./_generated/server').DatabaseReader;
}): Promise<number> {
  let n = 0;
  for (const phase of ROTATION_PHASES) {
    if ((TERMINAL_PHASES as readonly string[]).includes(phase)) continue;
    const rows = await ctx.db
      .query('relayRotations')
      .withIndex('by_phase', (q) => q.eq('phase', phase))
      .take(200);
    n += rows.length;
  }
  return n;
}

/** Non-terminal rotations whose next step is overdue (crashed action): reconcile re-kicks them. */
export const listStale = internalQuery({
  args: { now: v.number() },
  handler: async (ctx, { now }) => {
    const out: Id<'relayRotations'>[] = [];
    for (const phase of ROTATION_PHASES) {
      if ((TERMINAL_PHASES as readonly string[]).includes(phase)) continue;
      const rows = await ctx.db
        .query('relayRotations')
        .withIndex('by_phase', (q) =>
          q.eq('phase', phase).lt('nextStepAt', now - STALE_KICK_GRACE_MS),
        )
        .take(50);
      for (const r of rows) out.push(r._id);
    }
    return out;
  },
});

// --- start / cancel -----------------------------------------------------------------------

async function scheduleStep(ctx: MutationCtx, rotationId: Id<'relayRotations'>, delayMs: number) {
  await ctx.scheduler.runAfter(delayMs, internal.relayRotations.step, { rotationId });
  await ctx.db.patch(rotationId, { nextStepAt: Date.now() + delayMs });
}

export const start = internalMutation({
  args: {
    originId: v.id('relayOrigins'),
    kind: v.union(v.literal('provision'), v.literal('publish'), v.literal('replace')),
    trigger: v.union(
      v.literal('manual'),
      v.literal('detector'),
      v.literal('api'),
      v.literal('reconcile'),
    ),
    burn: v.optional(v.boolean()),
    force: v.optional(v.boolean()),
    targetEdgeId: v.optional(v.id('relayEdges')),
    toEdgeId: v.optional(v.id('relayEdges')),
    slotId: v.optional(v.id('relayOriginSlots')),
    publishOnDone: v.optional(v.boolean()),
    reason: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const origin = await ctx.db.get(a.originId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    const cfg = await resolveRelayConfig(ctx.db);
    const now = Date.now();
    const force = a.force ?? false;
    if (origin.quarantine)
      throw new ConvexError({
        code: 'relay.quarantined',
        message: 'Origin is quarantined; resolve it first',
      });
    if (origin.deleting)
      throw new ConvexError({ code: 'relay.deleting', message: 'Origin is being deleted' });
    if (origin.activeRotationId) {
      const active = await ctx.db.get(origin.activeRotationId);
      if (active && !isTerminalPhase(active.phase))
        throw new ConvexError({ code: 'relay.busy', message: 'A rotation is already running' });
    }
    if (a.trigger === 'detector' && !(cfg.enabled && cfg.autoRotate && origin.autoRotate)) {
      throw new ConvexError({
        code: 'relay.auto_rotate_disabled',
        message: 'Automatic rotation is not enabled for this origin',
      });
    }
    if ((await countActiveRotations(ctx)) >= cfg.maxConcurrentRotations) {
      throw new ConvexError({ code: 'relay.concurrency', message: 'Too many rotations in flight' });
    }
    let targetEdge: Edge | null = null;
    let slotId: Id<'relayOriginSlots'> | undefined = a.slotId;
    if (a.kind === 'replace') {
      if (!a.targetEdgeId)
        throw new ConvexError({ code: 'validation', message: 'targetEdgeId is required' });
      targetEdge = await ctx.db.get(a.targetEdgeId);
      if (
        !targetEdge ||
        targetEdge.originId !== a.originId ||
        targetEdge.publication !== 'published'
      ) {
        throw new ConvexError({
          code: 'relay.target_not_published',
          message: 'The target edge is not published on this origin',
        });
      }
      if (targetEdge.poolIndex === 0 && !origin.hostManaged) {
        throw new ConvexError({
          code: 'relay.hosts_unmanaged',
          message: 'This origin does not let FCP manage the template Host',
        });
      }
      if (!force) {
        if (origin.cooldownUntil && origin.cooldownUntil > now)
          throw new ConvexError({ code: 'relay.cooldown', message: 'Origin is cooling down' });
        const today = todayKey(now);
        const used = origin.rotationsDayKey === today ? origin.rotationsToday : 0;
        if (used >= origin.maxRotationsPerDay)
          throw new ConvexError({ code: 'relay.daily_cap', message: 'Daily rotation cap reached' });
      }
      slotId = targetEdge.slotId;
    }
    if (a.kind === 'publish') {
      if (!a.toEdgeId)
        throw new ConvexError({ code: 'validation', message: 'toEdgeId is required' });
      const to = await ctx.db.get(a.toEdgeId);
      if (!to || to.originId !== a.originId)
        throw new ConvexError({ code: 'not_found', message: 'Edge not found on this origin' });
      const check = await checkPublishable(ctx, to, false);
      if (!check.ok)
        throw new ConvexError({
          code: `relay.${check.code}`,
          message: `Edge cannot be published: ${check.code}`,
        });
      slotId = to.slotId;
    }
    if (slotId) {
      const slot = await ctx.db.get(slotId);
      const profile = slot ? await ctx.db.get(slot.profileId) : null;
      if (
        !slot ||
        slot.retired ||
        !slot.deployed ||
        !profile?.enabled ||
        !profile.serverNames.some((s) => s.status === 'active')
      ) {
        throw new ConvexError({
          code: 'relay.no_compatible_profile',
          message: 'The slot has no enabled profile with an active server name',
        });
      }
    }
    const id = await ctx.db.insert('relayRotations', {
      originId: a.originId,
      kind: a.kind,
      trigger: a.trigger,
      burn: a.burn ?? false,
      force,
      publishOnDone: a.kind === 'provision' ? (a.publishOnDone ?? false) : undefined,
      targetEdgeId: a.targetEdgeId,
      toEdgeId: a.kind === 'publish' ? a.toEdgeId : undefined,
      phase: 'select',
      stepVersion: 1,
      cancelRequested: false,
      reason: a.reason?.slice(0, 200) ?? (slotId ? `slot:${slotId}` : undefined),
      hostPlan: [],
      flipAttempts: 0,
      rollbackAttempts: 0,
      pollAttempts: 0,
      events: [{ at: now, level: 'info', code: 'started', detail: `${a.kind} (${a.trigger})` }],
      actorAdminId: a.actorAdminId,
      startedAt: now,
      updatedAt: now,
    });
    const today = todayKey(now);
    await ctx.db.patch(a.originId, {
      activeRotationId: id,
      ...(a.kind === 'replace'
        ? {
            rotationsDayKey: today,
            rotationsToday: (origin.rotationsDayKey === today ? origin.rotationsToday : 0) + 1,
          }
        : {}),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action:
        a.kind === 'replace'
          ? a.burn
            ? 'admin.relay.origin.burn'
            : 'admin.relay.origin.rotate'
          : 'admin.relay.origin.provision',
      targetType: 'relay_origin',
      targetId: a.originId,
      payload: { slug: origin.slug, trigger: a.trigger, force },
    });
    await scheduleStep(ctx, id, 0);
    return { rotationId: id };
  },
});

/** Reconcile: a non-terminal rotation whose next step never ran (crashed action). */
export const rekick = internalMutation({
  args: { rotationId: v.id('relayRotations') },
  handler: async (ctx, { rotationId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r || isTerminalPhase(r.phase)) return null;
    const now = Date.now();
    await ctx.db.patch(rotationId, {
      events: appendEvent(r.events, { at: now, level: 'warn', code: 'rekicked' }),
      updatedAt: now,
    });
    await scheduleStep(ctx, rotationId, 0);
    return null;
  },
});

export const requestCancel = internalMutation({
  args: { rotationId: v.id('relayRotations'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { rotationId, actorAdminId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r) throw new ConvexError({ code: 'not_found', message: 'Rotation not found' });
    if (isTerminalPhase(r.phase)) return { ok: true as const, phase: r.phase };
    if (r.phase === 'confirming' || r.phase === 'finalizing' || r.phase === 'rolling_back') {
      throw new ConvexError({
        code: 'relay.too_late',
        message: 'The rotation is past the point of cancellation',
      });
    }
    const now = Date.now();
    await ctx.db.patch(rotationId, {
      cancelRequested: true,
      events: appendEvent(r.events, { at: now, level: 'warn', code: 'cancel_requested' }),
      updatedAt: now,
    });
    const origin = await ctx.db.get(r.originId);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'admin.relay.origin.cancel',
      targetType: 'relay_origin',
      targetId: r.originId,
      payload: { slug: origin?.slug ?? '' },
    });
    await scheduleStep(ctx, rotationId, 0);
    return { ok: true as const, phase: r.phase };
  },
});

// --- transitions ---------------------------------------------------------------------------

const advanceEvent = v.union(
  v.object({ type: v.literal('selected'), toEdgeId: v.id('relayEdges'), viaStandby: v.boolean() }),
  v.object({
    type: v.literal('progress'),
    delayMs: v.number(),
    detail: v.optional(v.string()),
    countPoll: v.optional(v.boolean()),
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
  rotationId: Id<'relayRotations'>,
  stepVersion: number,
): Promise<Rotation | null> {
  const r = await ctx.db.get(rotationId);
  if (!r || r.stepVersion !== stepVersion || isTerminalPhase(r.phase)) return null;
  return r;
}

async function releaseOrigin(ctx: MutationCtx, r: Rotation, patch: Partial<Origin> = {}) {
  const origin = await ctx.db.get(r.originId);
  if (!origin) return;
  await ctx.db.patch(r.originId, {
    ...(origin.activeRotationId === r._id ? { activeRotationId: undefined } : {}),
    ...patch,
    updatedAt: Date.now(),
  });
}

async function auditFailure(
  ctx: MutationCtx,
  r: Rotation,
  phase: Phase,
  outcome: string,
  code: string,
) {
  const origin = await ctx.db.get(r.originId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'relay.rotation_failed',
    targetType: 'relay_rotation',
    targetId: r._id,
    payload: {
      originSlug: origin?.slug ?? '',
      trigger: r.trigger,
      phase,
      outcome,
      step: phase,
      code,
    },
  });
}

/** The new edge this rotation created (never a pre-existing standby / publish target). */
function createdEdgeId(r: Rotation): Id<'relayEdges'> | null {
  if (!r.toEdgeId) return null;
  if (r.kind === 'publish') return null;
  return r.events.some((e) => e.code === 'selected_standby') ? null : r.toEdgeId;
}

export const advance = internalMutation({
  args: { rotationId: v.id('relayRotations'), stepVersion: v.number(), event: advanceEvent },
  handler: async (ctx, { rotationId, stepVersion, event }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return { ok: false as const };
    const cfg = await resolveRelayConfig(ctx.db);
    const now = Date.now();
    const next = stepVersion + 1;
    const ev = (level: RotationEvent['level'], code: string, detail?: string) =>
      appendEvent(r.events, { at: now, level, code, detail });
    const poll = relayMs.poll(cfg);
    switch (event.type) {
      case 'selected': {
        await ctx.db.patch(rotationId, {
          toEdgeId: event.toEdgeId,
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
          events: event.detail ? ev('info', 'progress', event.detail) : r.events,
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
        if (created) {
          const e = await ctx.db.get(created);
          if (e && !['needs_operator', 'destroyed'].includes(e.status)) {
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
          events: ev('error', event.code, event.detail),
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
        const origin = await ctx.db.get(r.originId);
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.rolled_back',
          targetType: 'relay_rotation',
          targetId: r._id,
          payload: { originSlug: origin?.slug ?? '', hosts: r.hostPlan.length },
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
        const origin = await ctx.db.get(r.originId);
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.quarantined',
          targetType: 'relay_origin',
          targetId: r.originId,
          payload: { originSlug: origin?.slug ?? '', rotationId, reason: event.reason },
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
    rotationId: v.id('relayRotations'),
    stepVersion: v.number(),
    slotId: v.id('relayOriginSlots'),
    accountId: v.id('relayProviderAccounts'),
    templateId: v.optional(v.union(v.id('relayEdgeTemplates'), v.null())),
    templateHash: v.string(),
    nameNonce: v.string(),
    listeners: v.array(
      v.object({ edgePort: v.number(), originAddress: v.string(), originPort: v.number() }),
    ),
    steps: v.array(
      v.object({
        id: v.string(),
        kind: v.string(),
        resourceName: v.string(),
        discoverability: v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
      }),
    ),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const, code: 'stale' as const };
    let inserted: { id: Id<'relayEdges'>; name: string };
    try {
      inserted = await insertPlannedEdge(ctx, {
        originId: r.originId,
        slotId: a.slotId,
        accountId: a.accountId,
        templateId: a.templateId,
        templateHash: a.templateHash,
        listeners: a.listeners,
        steps: a.steps,
        nameNonce: a.nameNonce,
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
  args: { rotationId: v.id('relayRotations'), stepVersion: v.number() },
  handler: async (ctx, { rotationId, stepVersion }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r || !r.toEdgeId) return { ok: false as const, code: 'stale' as const };
    const cfg = await resolveRelayConfig(ctx.db);
    const origin = await ctx.db.get(r.originId);
    const to = await ctx.db.get(r.toEdgeId);
    if (!origin || !to) return { ok: false as const, code: 'missing' as const };
    const now = Date.now();
    const next = stepVersion + 1;
    const check = await checkPublishable(ctx, to, cfg.requireProviderHealth);
    if (!check.ok) return { ok: false as const, code: check.code ?? 'not_publishable' };
    let published = origin.publishedEdgeIds;
    let poolIndex: number | null = null;
    let previousBinding: Rotation['previousBinding'] = undefined;
    if (r.kind === 'provision' && !r.publishOnDone) {
      // Standby provision: verified, paid for, deliberately not rendered.
      await ctx.db.patch(rotationId, {
        phase: 'finalizing',
        stepVersion: next,
        events: appendEvent(r.events, { at: now, level: 'info', code: 'standby' }),
        updatedAt: now,
      });
      await ctx.db.patch(r.originId, {
        standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id],
        updatedAt: now,
      });
      await scheduleStep(ctx, rotationId, 0);
      return { ok: true as const, poolIndex: null, needsHostFlip: false };
    }
    if (r.kind === 'replace') {
      const target = r.targetEdgeId ? await ctx.db.get(r.targetEdgeId) : null;
      if (!target || target.publication !== 'published' || target.poolIndex === undefined)
        return { ok: false as const, code: 'target_gone' as const };
      poolIndex = target.poolIndex;
      const slot = await ctx.db.get(target.slotId);
      previousBinding = {
        edgeId: target._id,
        slotId: target.slotId,
        profileId: slot?.profileId ?? (await ctx.db.get(to.slotId))!.profileId,
        poolIndex,
      };
      await ctx.db.patch(target._id, {
        publication: 'draining',
        status: 'draining',
        poolIndex: undefined,
        drainUntil: now + relayMs.drain(cfg),
        statusChangedAt: now,
        updatedAt: now,
      });
      published = withoutEdge(published, target._id);
    } else {
      poolIndex = nextFreePoolIndex(published, origin.desiredPublished);
      if (poolIndex === null) {
        // Pool full: keep the edge as a standby and finish.
        await ctx.db.patch(rotationId, {
          phase: 'finalizing',
          stepVersion: next,
          events: appendEvent(r.events, { at: now, level: 'warn', code: 'pool_full_standby' }),
          updatedAt: now,
        });
        await ctx.db.patch(r.originId, {
          standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id],
          updatedAt: now,
        });
        await scheduleStep(ctx, rotationId, 0);
        return { ok: true as const, poolIndex: null, needsHostFlip: false };
      }
    }
    await ctx.db.patch(to._id, {
      publication: 'published',
      poolIndex,
      publishedAt: now,
      updatedAt: now,
    });
    const epoch = origin.publicationEpoch + 1;
    await ctx.db.patch(r.originId, {
      publishedEdgeIds: withEdgeAt(published, poolIndex, to._id),
      standbyEdgeIds: origin.standbyEdgeIds.filter((e) => e !== to._id),
      publicationEpoch: epoch,
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.edge.published',
      targetType: 'relay_edge',
      targetId: to._id,
      payload: { originSlug: origin.slug, edgeId: to._id, poolIndex, epoch },
    });
    if (previousBinding) {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.edge.unpublished',
        targetType: 'relay_edge',
        targetId: previousBinding.edgeId,
        payload: { originSlug: origin.slug, edgeId: previousBinding.edgeId, poolIndex, epoch },
      });
    }
    const needsHostFlip = poolIndex === 0 && origin.hostManaged;
    await ctx.db.patch(rotationId, {
      phase: needsHostFlip ? 'host_flipping' : 'finalizing',
      stepVersion: next,
      previousBinding,
      events: appendEvent(r.events, {
        at: now,
        level: 'info',
        code: 'published',
        detail: `pool index ${poolIndex}${needsHostFlip ? ', template Host flip follows' : poolIndex === 0 ? ', Host left to the operator (hostManaged=false)' : ''}`,
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
    rotationId: v.id('relayRotations'),
    stepVersion: v.number(),
    hostPlan: v.array(
      v.object({
        uuid: v.string(),
        oldAddress: v.string(),
        oldPort: v.number(),
        inboundUuid: v.optional(v.string()),
      }),
    ),
    slotId: v.id('relayOriginSlots'),
    templateHostUuid: v.optional(v.union(v.string(), v.null())),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(a.rotationId, {
      hostPlan: a.hostPlan,
      stepVersion: a.stepVersion + 1,
      events: appendEvent(r.events, {
        at: now,
        level: 'info',
        code: 'host_plan',
        detail: `${a.hostPlan.length} host(s)`,
      }),
      updatedAt: now,
    });
    if (a.templateHostUuid !== undefined)
      await ctx.db.patch(a.slotId, {
        templateHostUuid: a.templateHostUuid ?? undefined,
        updatedAt: now,
      });
    await scheduleStep(ctx, a.rotationId, 0);
    return { ok: true as const, stepVersion: a.stepVersion + 1 };
  },
});

/** Claim the single in-flight Host write; counts flip / rollback attempts against their caps. */
export const claimHostOp = internalMutation({
  args: {
    rotationId: v.id('relayRotations'),
    stepVersion: v.number(),
    hostUuid: v.string(),
    direction: v.union(v.literal('forward'), v.literal('rollback')),
  },
  handler: async (ctx, a) => {
    const r = await guard(ctx, a.rotationId, a.stepVersion);
    if (!r) return { ok: false as const, code: 'stale' as const };
    const cfg = await resolveRelayConfig(ctx.db);
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
      expiresAt: now + relayMs.opClaim(cfg),
    };
    await ctx.db.patch(a.rotationId, {
      currentOp: op,
      ...(a.direction === 'forward' ? { flipAttempts: attempts } : { rollbackAttempts: attempts }),
      updatedAt: now,
    });
    return { ok: true as const, opId: op.opId };
  },
});

export const settleHostOp = internalMutation({
  args: {
    rotationId: v.id('relayRotations'),
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
  args: { rotationId: v.id('relayRotations') },
  handler: async (ctx, { rotationId }) => {
    const r = await ctx.db.get(rotationId);
    if (!r) return { ok: false as const };
    const origin = await ctx.db.get(r.originId);
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
        published = withEdgeAt(published, r.previousBinding.poolIndex, prev._id);
        changed = true;
      }
    }
    if (changed) {
      await ctx.db.patch(r.originId, {
        publishedEdgeIds: published,
        standbyEdgeIds: r.toEdgeId
          ? [...origin.standbyEdgeIds.filter((e) => e !== r.toEdgeId), r.toEdgeId]
          : origin.standbyEdgeIds,
        publicationEpoch: origin.publicationEpoch + 1,
        updatedAt: now,
      });
      await ctx.db.patch(rotationId, {
        events: appendEvent(r.events, { at: now, level: 'warn', code: 'binding_restored' }),
        updatedAt: now,
      });
    }
    return { ok: true as const, changed };
  },
});

export const finalize = internalMutation({
  args: { rotationId: v.id('relayRotations'), stepVersion: v.number() },
  handler: async (ctx, { rotationId, stepVersion }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return { ok: false as const };
    const cfg = await resolveRelayConfig(ctx.db);
    const origin = await ctx.db.get(r.originId);
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
          drainUntil: now + (r.burn ? relayMs.burnedDrain(cfg) : relayMs.drain(cfg)),
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
    await releaseOrigin(ctx, r, {
      ...(r.kind === 'replace'
        ? { lastRotatedAt: now, cooldownUntil: now + origin.cooldownMs }
        : {}),
      // Standby bookkeeping for a provision that did not publish.
      ...(to && !published
        ? { standbyEdgeIds: [...origin.standbyEdgeIds.filter((e) => e !== to._id), to._id] }
        : {}),
    });
    if (r.kind === 'replace') {
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.rotated',
        targetType: 'relay_origin',
        targetId: r.originId,
        payload: {
          originSlug: origin.slug,
          trigger: r.trigger,
          kind: r.kind,
          fromProvider: from?.provider ?? null,
          toProvider: to?.provider ?? null,
          fromEdgeId: from?._id ?? null,
          toEdgeId: to?._id ?? null,
          poolIndex: to?.poolIndex ?? null,
          hostsFlipped: r.hostPlan.length,
          durationMs: now - r.startedAt,
        },
      });
      if (r.burn && from) {
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.burned',
          targetType: 'relay_edge',
          targetId: from._id,
          payload: { originSlug: origin.slug, trigger: r.trigger, edgeId: from._id },
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
    originId: v.id('relayOrigins'),
    keep: v.union(v.literal('current'), v.literal('previous')),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { originId, keep, actorAdminId }) => {
    const origin = await ctx.db.get(originId);
    if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!origin.quarantine) return { ok: true as const };
    const rotation = await ctx.db.get(origin.quarantine.rotationId);
    const now = Date.now();
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
          published = withEdgeAt(published, rotation.previousBinding.poolIndex, prev._id);
        }
      }
      await ctx.db.patch(originId, { publishedEdgeIds: published, updatedAt: now });
    } else if (rotation?.toEdgeId) {
      const to = await ctx.db.get(rotation.toEdgeId);
      if (to && to.status === 'quarantined')
        await ctx.db.patch(to._id, { status: 'active', statusChangedAt: now, updatedAt: now });
    }
    await ctx.db.patch(originId, {
      quarantine: undefined,
      publicationEpoch: origin.publicationEpoch + 1,
      updatedAt: now,
    });
    if (rotation)
      await ctx.db.patch(rotation._id, {
        outcome: `quarantine_resolved:${keep}`,
        events: appendEvent(rotation.events, {
          at: now,
          level: 'info',
          code: 'quarantine_resolved',
          detail: keep,
        }),
        updatedAt: now,
      });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.quarantine_resolved',
      targetType: 'relay_origin',
      targetId: originId,
      payload: { originSlug: origin.slug, keep },
    });
    return { ok: true as const };
  },
});

// --- step context ------------------------------------------------------------------------------

export const stepContext = internalQuery({
  args: { rotationId: v.id('relayRotations') },
  handler: async (ctx, { rotationId }) => {
    const rotation = await ctx.db.get(rotationId);
    if (!rotation) return null;
    const origin = await ctx.db.get(rotation.originId);
    if (!origin) return null;
    const cfg = await resolveRelayConfig(ctx.db);
    const toEdge = rotation.toEdgeId ? await ctx.db.get(rotation.toEdgeId) : null;
    const targetEdge = rotation.targetEdgeId ? await ctx.db.get(rotation.targetEdgeId) : null;
    const slotId = toEdge?.slotId ?? targetEdge?.slotId ?? null;
    const slot = slotId ? await ctx.db.get(slotId) : null;
    const profile = slot ? await ctx.db.get(slot.profileId) : null;
    const prevEdge = rotation.previousBinding
      ? await ctx.db.get(rotation.previousBinding.edgeId)
      : null;
    let selection: SelectionContext | null = null;
    if (rotation.phase === 'select')
      selection = await selectionContext(ctx, rotation, origin, targetEdge, cfg);
    return { rotation, origin, cfg, toEdge, targetEdge, slot, profile, prevEdge, selection };
  },
});

interface SelectionContext {
  slot: Doc<'relayOriginSlots'> | null;
  profile: Doc<'relayCamouflageProfiles'> | null;
  standbyId: Id<'relayEdges'> | null;
  account: {
    id: Id<'relayProviderAccounts'>;
    defaultTemplateId: Id<'relayEdgeTemplates'> | null;
  } | null;
  accountFailure: string | null;
  template: {
    id: Id<'relayEdgeTemplates'> | null;
    params: Record<string, unknown>;
    hash: string;
  } | null;
}

async function selectionContext(
  ctx: QueryCtx,
  rotation: Rotation,
  origin: Origin,
  targetEdge: Edge | null,
  cfg: RelayConfig,
): Promise<SelectionContext> {
  const edges = await ctx.db
    .query('relayEdges')
    .withIndex('by_origin_status', (q) => q.eq('originId', origin._id))
    .collect();
  const publishedProviders = edges
    .filter((e) => e.publication === 'published' && e.provider)
    .map((e) => e.provider as string);
  const slotRows = await ctx.db
    .query('relayOriginSlots')
    .withIndex('by_origin', (q) => q.eq('originId', origin._id))
    .collect();
  const profiles = new Map<string, Doc<'relayCamouflageProfiles'>>();
  for (const s of slotRows) {
    const p = await ctx.db.get(s.profileId);
    if (p) profiles.set(s._id, p);
  }
  let slot: Doc<'relayOriginSlots'> | null = null;
  if (rotation.kind === 'replace' && targetEdge)
    slot = slotRows.find((s) => s._id === targetEdge.slotId) ?? null;
  else if (rotation.reason?.startsWith('slot:'))
    slot = slotRows.find((s) => (s._id as string) === rotation.reason!.slice(5)) ?? null;
  if (!slot) {
    const pick = pickSlot(
      slotRows.map((s) => {
        const p = profiles.get(s._id);
        return {
          slotId: s._id,
          slotKey: s.slotKey,
          provider: p?.provider ?? '',
          deployed: s.deployed,
          retired: s.retired,
          profileEnabled: p?.enabled ?? false,
          activeSnis: p?.serverNames.filter((n) => n.status === 'active').length ?? 0,
        };
      }),
      publishedProviders,
      cfg.render.preferDistinctProviders,
      origin.providerPreference ?? null,
    );
    slot = pick ? (slotRows.find((s) => s._id === pick.slotId) ?? null) : null;
  }
  const profile = slot ? (profiles.get(slot._id) ?? null) : null;
  if (!slot || !profile)
    return {
      slot,
      profile,
      standbyId: null,
      account: null,
      accountFailure: 'no_compatible_profile',
      template: null,
    };
  const standby = pickStandby(
    edges.map((e) => ({
      id: e._id,
      slotId: e.slotId,
      provider: e.provider ?? null,
      status: e.status,
      publication: e.publication,
      health: e.health,
      hasV4: !!e.addresses.v4,
    })),
    slot._id,
    publishedProviders,
    targetEdge?._id ?? null,
    cfg.requireProviderHealth,
  );
  if (standby && (rotation.kind === 'replace' || rotation.publishOnDone)) {
    return {
      slot,
      profile,
      standbyId: standby.id as Id<'relayEdges'>,
      account: null,
      accountFailure: null,
      template: null,
    };
  }
  const accounts = await ctx.db.query('relayProviderAccounts').collect();
  const candidates = [];
  for (const a of accounts) {
    if (!a.enabled) continue;
    const live = (
      await ctx.db
        .query('relayEdges')
        .withIndex('by_account_status', (q) => q.eq('accountId', a._id))
        .collect()
    ).filter((e) => e.status !== 'destroyed').length;
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
  const picked = pickAccount(candidates, profile.provider);
  if (!picked.ok)
    return {
      slot,
      profile,
      standbyId: null,
      account: null,
      accountFailure: picked.code,
      template: null,
    };
  const account = accounts.find((a) => (a._id as string) === picked.account.id)!;
  const { resolveTemplateFor } = await import('./relayEdgeTemplates');
  const template = await resolveTemplateFor(
    ctx,
    profile.provider,
    null,
    account.defaultTemplateId ?? null,
  );
  return {
    slot,
    profile,
    standbyId: null,
    account: { id: account._id, defaultTemplateId: account.defaultTemplateId ?? null },
    accountFailure: null,
    template,
  };
}

// --- the step action ---------------------------------------------------------------------------

type Ctx = NonNullable<Awaited<ReturnType<typeof stepContextHandler>>>;
async function stepContextHandler(ctx: ActionCtx, rotationId: Id<'relayRotations'>) {
  return ctx.runQuery(internal.relayRotations.stepContext, { rotationId });
}

function specOf(edge: Edge) {
  return {
    name: edge.name,
    listeners: edge.listeners.map((l) => ({
      edgePort: l.edgePort,
      members: [{ address: l.originAddress, port: l.originPort }],
    })),
  };
}

function resourceStepOf(s: Edge['steps'][number]): ResourceStep {
  return {
    id: s.stepId,
    kind: s.kind as ResourceStep['kind'],
    resourceName: s.resourceName,
    discoverability: s.discoverability ?? 'by_name',
  };
}

function errCode(err: unknown): { code: string; detail: string } {
  if (err instanceof ConvexError) {
    const d = err.data as { code?: string; message?: string } | string;
    if (typeof d === 'string') return { code: 'error', detail: d.slice(0, 120) };
    return { code: d.code ?? 'error', detail: (d.message ?? '').slice(0, 120) };
  }
  const m = err instanceof Error ? err.message : String(err);
  // Provider errors are typed with a meta code and never carry bodies/URLs.
  const meta = (err as { meta?: { code?: string; status?: number } }).meta;
  return { code: meta?.code ?? 'error', detail: `${meta?.status ?? ''} ${m}`.trim().slice(0, 120) };
}

export const step = internalAction({
  args: { rotationId: v.id('relayRotations') },
  handler: async (ctx, { rotationId }): Promise<null> => {
    const c = await stepContextHandler(ctx, rotationId);
    if (!c || isTerminalPhase(c.rotation.phase)) return null;
    const { rotation: r, cfg } = c;
    const sv = r.stepVersion;
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
          const res = await ctx.runMutation(internal.relayRotations.applyPublish, {
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
          await ctx.runMutation(internal.relayRotations.finalize, { rotationId, stepVersion: sv });
          return null;
        case 'rolling_back':
          await phaseRollingBack(ctx, c);
          return null;
        default:
          return null;
      }
    } catch (err) {
      // An unexpected throw must not strand the rotation: record and retry after a poll.
      const { code, detail } = errCode(err);
      await adv({
        type: 'progress',
        delayMs: relayMs.poll(cfg),
        detail: `step error: ${code} ${detail}`.trim(),
        countPoll: true,
      });
      return null;
    }
  },
});

async function advanceCall(
  ctx: ActionCtx,
  rotationId: Id<'relayRotations'>,
  stepVersion: number,
  event:
    | { type: 'selected'; toEdgeId: Id<'relayEdges'>; viaStandby: boolean }
    | { type: 'progress'; delayMs: number; detail?: string; countPoll?: boolean }
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
  return ctx.runMutation(internal.relayRotations.advance, { rotationId, stepVersion, event });
}

async function phaseSelect(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, origin, selection } = c;
  const sv = r.stepVersion;
  if (r.kind === 'publish' && r.toEdgeId) {
    await advanceCall(ctx, r._id, sv, { type: 'selected', toEdgeId: r.toEdgeId, viaStandby: true });
    return;
  }
  if (!selection || !selection.slot || !selection.profile) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: 'no_compatible_profile',
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
    { edgePort: 443, originAddress: origin.originAddress, originPort: selection.slot.originPort },
  ];
  const spec = {
    name,
    listeners: listeners.map((l) => ({
      edgePort: l.edgePort,
      members: [{ address: l.originAddress, port: l.originPort }],
    })),
  };
  let steps: ResourceStep[];
  try {
    steps = await ctx.runAction(internal.relayProviderOps.planProvision, {
      accountId: selection.account.id,
      spec,
      templateParams: selection.template.params,
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
  const res = await ctx.runMutation(internal.relayRotations.commitSelection, {
    rotationId: r._id,
    stepVersion: sv,
    slotId: selection.slot._id,
    accountId: selection.account.id,
    templateId: selection.template.id,
    templateHash: selection.template.hash,
    nameNonce: nonce,
    listeners,
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
  const poll = relayMs.poll(cfg);
  if (!edge || !edge.accountId) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'edge_missing', rollback: false });
    return;
  }
  const now = Date.now();
  if (edge._creationTime + relayMs.provisionTimeout(cfg) < now) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'provision_timeout', rollback: false });
    return;
  }
  // The template must not change under a running provision.
  const tpl = await ctx.runQuery(internal.relayEdgeTemplates.resolveForProvision, {
    provider: edge.provider!,
    templateId: edge.templateId ?? null,
    accountDefaultId: null,
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
      desc = await ctx.runAction(internal.relayProviderOps.describe, { accountId, ledger });
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
    await ctx.runMutation(internal.relayEdges.recordDescribe, {
      edgeId: edge._id,
      state: desc.state,
      addresses: desc.addresses,
      health: desc.health,
      resources: desc.resources,
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
    if (desc.state === 'active' && desc.addresses.v4) {
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
    ctx.runMutation(internal.relayEdges.claimOp, {
      edgeId: edge._id,
      kind,
      target: pending.stepId,
      claimMs: relayMs.opClaim(cfg),
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
      await settle(opId, {
        stepPatch: { stepId: pending.stepId, state: 'unresolved' },
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
        if (cl.code === 'relay.op_unsettled') {
          await ctx.runMutation(internal.relayEdges.patchEdge, {
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
      let out: StepOutcome;
      try {
        out = await ctx.runAction(internal.relayProviderOps.runStep, {
          accountId,
          spec,
          templateParams: tpl.params,
          step,
          ledger,
        });
      } catch (err) {
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
        out = await ctx.runAction(internal.relayProviderOps.pollStep, {
          accountId,
          step,
          opRef: pending.opRef ?? '',
          ledger,
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
      let disc: Discovery;
      try {
        disc = await ctx.runAction(internal.relayProviderOps.discover, {
          accountId,
          spec,
          step,
          ledger,
          attempt: cl.attempt,
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
      await settle(cl.opId, {});
      if ((pending.startedAt ?? edge._creationTime) + relayMs.discoveryTimeout(cfg) < now) {
        await ctx.runMutation(internal.relayEdges.patchEdge, {
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
  edgeId: Id<'relayEdges'>,
  opId: string,
  patch: {
    stepPatch?: {
      stepId: string;
      state: string;
      opRef?: string | null;
      attempt?: number;
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
  await ctx.runMutation(internal.relayEdges.settleOp, { edgeId, opId, ...patch });
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
      desc = await ctx.runAction(internal.relayProviderOps.describe, {
        accountId: edge.accountId,
        ledger: { steps: edge.steps, resources: edge.resources },
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
        delayMs: relayMs.poll(cfg),
        detail: `describe failed: ${code}`,
        countPoll: true,
      });
      return;
    }
    await ctx.runMutation(internal.relayEdges.recordDescribe, {
      edgeId: edge._id,
      state: desc.state,
      addresses: desc.addresses,
      health: desc.health,
      resources: desc.resources,
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
    const v4 = desc.addresses.v4 ?? edge.addresses.v4;
    const healthy = !cfg.requireProviderHealth || desc.health === 'online';
    if (!(desc.state === 'active' && v4 && healthy)) {
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
        delayMs: relayMs.poll(cfg),
        detail: `waiting: state=${desc.state} health=${desc.health}`,
        countPoll: true,
      });
      return;
    }
    if (sameAddress(v4, origin.originAddress)) {
      await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'edge_is_origin', rollback: false });
      return;
    }
  } else if (!edge.addresses.v4) {
    await advanceCall(ctx, r._id, sv, { type: 'fail', code: 'no_ipv4', rollback: false });
    return;
  }
  await advanceCall(ctx, r._id, sv, { type: 'verified' });
}

async function listHosts(ctx: ActionCtx, origin: Origin): Promise<BackendHost[]> {
  return ctx.runAction(internal.backends.listHosts, { backendServerId: origin.backendServerId });
}

async function phaseHostFlip(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge, origin, slot } = c;
  const sv = r.stepVersion;
  const poll = relayMs.poll(cfg);
  if (!edge?.addresses.v4 || !slot) {
    await advanceCall(ctx, r._id, sv, {
      type: 'fail',
      code: 'flip_context_missing',
      rollback: true,
    });
    return;
  }
  if (!origin.hostManaged) {
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
    await ctx.runMutation(internal.relayRotations.bumpFlipAttempts, {
      rotationId: r._id,
      stepVersion: sv,
      detail: `list hosts failed: ${code}`,
    });
    return;
  }
  const target = { address: edge.addresses.v4, port: edge.listeners[0]?.edgePort ?? 443 };
  if (r.hostPlan.length === 0 && !r.events.some((e) => e.code === 'host_plan')) {
    const matches = matchSlotHosts(
      hosts,
      [{ slotId: slot._id, slotKey: slot.slotKey, templateHostRemark: slot.templateHostRemark }],
      origin.originAddress,
    );
    const m = matches[0];
    if (m.duplicates > 0) {
      await advanceCall(ctx, r._id, sv, {
        type: 'fail',
        code: 'host_duplicates',
        detail: slot.templateHostRemark,
        rollback: true,
      });
      return;
    }
    if (!m.host || m.leaks) {
      // No template Host to flip (bootstrap: the role creates it from publishedEndpoints[0]).
      await ctx.runMutation(internal.relayRotations.setHostPlan, {
        rotationId: r._id,
        stepVersion: sv,
        hostPlan: [],
        slotId: slot._id,
        templateHostUuid: m.host && !m.leaks ? m.host.uuid : null,
      });
      return;
    }
    // Already at the target (e.g. a re-kick after the write landed) still goes through the plan.
    await ctx.runMutation(internal.relayRotations.setHostPlan, {
      rotationId: r._id,
      stepVersion: sv,
      hostPlan: planFromMatches(matches),
      slotId: slot._id,
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
  const cl = await ctx.runMutation(internal.relayRotations.claimHostOp, {
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
      backendServerId: origin.backendServerId,
      uuid: entry.uuid,
      address: target.address,
      port: target.port,
    });
    await ctx.runMutation(internal.relayRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: true,
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await ctx.runMutation(internal.relayRotations.settleHostOp, {
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
  args: { rotationId: v.id('relayRotations'), stepVersion: v.number(), detail: v.string() },
  handler: async (ctx, { rotationId, stepVersion, detail }) => {
    const r = await guard(ctx, rotationId, stepVersion);
    if (!r) return null;
    const cfg = await resolveRelayConfig(ctx.db);
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
    await scheduleStep(ctx, rotationId, relayMs.poll(cfg));
    return null;
  },
});

async function phaseConfirming(ctx: ActionCtx, c: Ctx) {
  const { rotation: r, cfg, toEdge: edge, origin } = c;
  const sv = r.stepVersion;
  if (r.hostPlan.length === 0 || !edge?.addresses.v4) {
    await advanceCall(ctx, r._id, sv, { type: 'confirmed' });
    return;
  }
  let hosts: BackendHost[];
  try {
    hosts = await listHosts(ctx, origin);
  } catch (err) {
    const { code } = errCode(err);
    await advanceCall(ctx, r._id, sv, {
      type: 'progress',
      delayMs: relayMs.poll(cfg),
      detail: `confirm: list hosts failed: ${code}`,
      countPoll: true,
    });
    return;
  }
  const diff = diffHosts(hosts, r.hostPlan, {
    address: edge.addresses.v4,
    port: edge.listeners[0]?.edgePort ?? 443,
  });
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
  const poll = relayMs.poll(cfg);
  await ctx.runMutation(internal.relayRotations.applyRollbackBinding, { rotationId: r._id });
  if (
    r.hostPlan.length === 0 ||
    (!r.flippedAt && !r.events.some((e) => e.code === 'host_forward_written'))
  ) {
    // Nothing was written to the panel: the DB restore is the whole rollback.
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
    await ctx.runMutation(internal.relayRotations.bumpFlipAttempts, {
      rotationId: r._id,
      stepVersion: sv,
      detail: `rollback: list hosts failed: ${code}`,
    });
    return;
  }
  const byUuid = new Map(hosts.map((h) => [h.uuid, h]));
  let pendingEntry: Rotation['hostPlan'][number] | null = null;
  for (const p of r.hostPlan) {
    const h = byUuid.get(p.uuid);
    if (
      !h ||
      (p.inboundUuid && h.inbound && h.inbound.configProfileInboundUuid !== p.inboundUuid)
    ) {
      await advanceCall(ctx, r._id, sv, {
        type: 'quarantine',
        reason: 'a planned Host vanished or was rebound during rollback',
      });
      return;
    }
    if (!(sameAddress(h.address, p.oldAddress) && h.port === p.oldPort)) {
      pendingEntry = p;
      break;
    }
  }
  if (!pendingEntry) {
    await advanceCall(ctx, r._id, sv, { type: 'rolled_back' });
    return;
  }
  const cl = await ctx.runMutation(internal.relayRotations.claimHostOp, {
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
      backendServerId: origin.backendServerId,
      uuid: pendingEntry.uuid,
      address: pendingEntry.oldAddress,
      port: pendingEntry.oldPort,
    });
    await ctx.runMutation(internal.relayRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: true,
    });
  } catch (err) {
    const { code, detail } = errCode(err);
    await ctx.runMutation(internal.relayRotations.settleHostOp, {
      rotationId: r._id,
      opId: cl.opId,
      ok: false,
      detail: `${code} ${detail}`.trim(),
    });
  }
  await advanceCall(ctx, r._id, sv, { type: 'progress', delayMs: 0 });
}
