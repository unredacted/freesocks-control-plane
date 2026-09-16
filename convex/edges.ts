/**
 * Relay EDGE rows: one provider load balancer each. This module owns the row
 * mutations the rotation machine and the reconcile cron drive:
 *
 *  - `insertPlanned` reserves capacity + budget and inserts the row in ONE
 *    transaction (a reservation and its edge commit together);
 *  - `claimOp` / `settleOp` bracket every external provider call so two actions
 *    can never perform the same allocating/destroying call at once, and an
 *    unsettled op blocks opposing work until it is re-observed;
 *  - ledger patches (`applyStepOutcome`, `applyDiscovery`, `recordDescribe`,
 *    `setResourceDeleteState`) record every child resource before anything else
 *    happens.
 *
 * The reconcile cron itself lives in edgeReconcile.ts (it needs the Node
 * provider actions and the rotation machine).
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { randomHex } from './lib/crypto';
import { reserveAllocation } from './edgeProviderAccounts';
import { edgeResourceName } from './lib/edges/accountSettings';
import { dropEdgeFromPool, liveEdgesOfAccount } from './relays';
import { EDGE_LIVE_STATUSES } from './lib/edges/pool';
import type { ProvisionIntent } from './lib/edges/intent';

/** Consecutive `gone` describes before the pool drop + status transition act. */
export const GONE_OBSERVATIONS_REQUIRED = 2;
/**
 * Consecutive `active` describes that OMIT a known address before it is
 * dropped. Same reasoning as GONE: one truncated or narrowed answer must not
 * stop a published edge from rendering.
 */
export const ADDRESS_LOSS_OBSERVATIONS_REQUIRED = 2;

/**
 * The terminal row shape: every large blob (the live snapshot) is cleared so a
 * destroyed edge costs nothing to keep until the retention sweep removes it.
 */
export function destroyedPatch(now: number): Partial<Edge> {
  return {
    status: 'destroyed',
    publication: 'unpublished',
    poolIndex: undefined,
    currentOp: undefined,
    liveSnapshot: undefined,
    liveAt: undefined,
    destroyConfirm: undefined,
    goneObservations: undefined,
    addressLossObservations: undefined,
    destroyedAt: now,
    statusChangedAt: now,
    updatedAt: now,
  };
}

type Edge = Doc<'edges'>;
type Step = Edge['steps'][number];
type Resource = Edge['resources'][number];

/** Re-exported for the callers that iterate statuses (the single list lives in lib/edges/pool.ts). */
export const LIVE_STATUSES = EDGE_LIVE_STATUSES;

const childResource = v.object({
  kind: v.string(),
  resourceId: v.string(),
  ownership: v.union(v.literal('created'), v.literal('adopted')),
  meta: v.optional(v.any()),
});
const addresses = v.object({
  v4: v.optional(v.string()),
  v6: v.optional(v.string()),
  /** L7: the fronted hostname, the only address its members receive. */
  hostname: v.optional(v.string()),
});

/** Ledger view for the provider actions (steps + resources only). */
export function ledgerOf(edge: Edge): { steps: Edge['steps']; resources: Edge['resources'] } {
  return { steps: edge.steps, resources: edge.resources };
}

/** True when the reconcile cron must settle this edge before anything else. */
export function isDiscoverable(edge: Edge, now: number): boolean {
  if (edge.status === 'destroyed') return false;
  if (edge.currentOp && edge.currentOp.expiresAt < now) return true;
  return edge.steps.some((s) => s.state === 'requested' || s.state === 'unresolved');
}

export function edgeProgress(edge: Edge): { done: number; total: number; percent: number } {
  const total = edge.steps.length;
  const done = edge.steps.filter((s) => s.state === 'done').length;
  return { done, total, percent: total === 0 ? 0 : Math.round((done / total) * 100) };
}

export function mapEdgeAdmin(e: Edge) {
  return {
    id: e._id as string,
    relayId: e.relayId as string,
    slotId: e.slotId as string,
    accountId: (e.accountId as string | undefined) ?? null,
    templateId: (e.templateId as string | undefined) ?? null,
    templateHash: e.templateHash ?? null,
    provider: e.provider ?? null,
    managed: e.managed,
    name: e.name,
    steps: e.steps.map((s) => ({
      stepId: s.stepId,
      kind: s.kind,
      state: s.state,
      attempt: s.attempt,
      startedAt: s.startedAt ? new Date(s.startedAt).toISOString() : null,
      finishedAt: s.finishedAt ? new Date(s.finishedAt).toISOString() : null,
    })),
    resources: e.resources.map((r) => ({
      stepId: r.stepId,
      kind: r.kind,
      resourceId: r.resourceId,
      ownership: r.ownership,
      deleteState: r.deleteState,
    })),
    currentOp: e.currentOp
      ? {
          opId: e.currentOp.opId,
          kind: e.currentOp.kind,
          target: e.currentOp.target,
          attempt: e.currentOp.attempt,
          claimedAt: new Date(e.currentOp.claimedAt).toISOString(),
          expiresAt: new Date(e.currentOp.expiresAt).toISOString(),
        }
      : null,
    listeners: e.listeners,
    addresses: {
      v4: e.addresses.v4 ?? null,
      v6: e.addresses.v6 ?? null,
      hostname: e.addresses.hostname ?? null,
    },
    layer: e.layer ?? 'l4',
    readiness: e.readiness
      ? {
          dns: e.readiness.dns,
          certificate: e.readiness.certificate,
          front: e.readiness.front,
          checkedAt: new Date(e.readiness.checkedAt).toISOString(),
        }
      : null,
    // The binding itself stays server-side (ids + hashes). `current` is the
    // cheap display answer: passing, unexpired and taken against the hostname
    // the edge now carries. The authoritative gate re-derives the WHOLE binding
    // inside the publishing mutation (relays.checkPublishable), which can also
    // see a slot or profile write this view cannot.
    frontQualification: e.frontQualification
      ? {
          ok: e.frontQualification.ok,
          code: e.frontQualification.code ?? null,
          checkedAt: new Date(e.frontQualification.checkedAt).toISOString(),
          expiresAt: new Date(e.frontQualification.expiresAt).toISOString(),
          current:
            e.frontQualification.ok &&
            e.frontQualification.expiresAt > Date.now() &&
            e.frontQualification.binding.hostname === (e.addresses.hostname ?? ''),
        }
      : null,
    publication: e.publication,
    poolIndex: e.poolIndex ?? null,
    publishedAt: e.publishedAt ? new Date(e.publishedAt).toISOString() : null,
    status: e.status,
    statusChangedAt: new Date(e.statusChangedAt).toISOString(),
    health: e.health,
    lastHealthAt: e.lastHealthAt ? new Date(e.lastHealthAt).toISOString() : null,
    liveAt: e.liveAt ? new Date(e.liveAt).toISOString() : null,
    reachability: e.reachability
      ? {
          byCountry: e.reachability.byCountry.map((c) => ({
            ...c,
            lastAt: new Date(c.lastAt).toISOString(),
          })),
          updatedAt: new Date(e.reachability.updatedAt).toISOString(),
        }
      : null,
    destroyAttempts: e.destroyAttempts,
    failure: e.failure ?? null,
    burnedAt: e.burnedAt ? new Date(e.burnedAt).toISOString() : null,
    drainUntil: e.drainUntil ? new Date(e.drainUntil).toISOString() : null,
    destroyedAt: e.destroyedAt ? new Date(e.destroyedAt).toISOString() : null,
    progress: edgeProgress(e),
    createdAt: new Date(e._creationTime).toISOString(),
    updatedAt: new Date(e.updatedAt).toISOString(),
  };
}

// --- reads ----------------------------------------------------------------------------

export const get = internalQuery({
  args: { id: v.id('edges') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

export const listByRelay = internalQuery({
  args: { relayId: v.id('relays') },
  handler: (ctx, { relayId }) =>
    ctx.db
      .query('edges')
      .withIndex('by_relay_status', (q) => q.eq('relayId', relayId))
      .collect(),
});

export const listByRelayForAdmin = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) =>
    (
      await ctx.db
        .query('edges')
        .withIndex('by_relay_status', (q) => q.eq('relayId', relayId))
        .collect()
    )
      .sort(
        (a, b) => (a.poolIndex ?? 99) - (b.poolIndex ?? 99) || b._creationTime - a._creationTime,
      )
      .map(mapEdgeAdmin),
});

export const getForAdmin = internalQuery({
  args: { id: v.id('edges') },
  handler: async (ctx, { id }) => {
    const e = await ctx.db.get(id);
    return e ? mapEdgeAdmin(e) : null;
  },
});

/** Edges in one status, oldest status change first (bounded). */
export const listByStatus = internalQuery({
  args: { status: v.string(), take: v.number() },
  handler: (ctx, { status, take }) =>
    ctx.db
      .query('edges')
      .withIndex('by_status', (q) => q.eq('status', status as Edge['status']))
      .take(take),
});

/** All non-destroyed edges (small, admin-managed table) for the reconcile cron. */
export const listLive = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out: Edge[] = [];
    for (const status of LIVE_STATUSES) {
      const rows = await ctx.db
        .query('edges')
        .withIndex('by_status', (q) => q.eq('status', status))
        .take(500);
      out.push(...rows);
    }
    return out;
  },
});

/**
 * Live edge count per account (the `maxLiveEdges` capacity gate), excluding
 * destroyed rows AND observe-only ones: an unmanaged edge was not provisioned
 * by FCP, is never destroyed by FCP and costs the account nothing FCP decided
 * to spend, so counting it would shrink the account's usable capacity for good.
 */
export async function liveCountForAccount(
  ctx: { db: import('./_generated/server').DatabaseReader },
  accountId: Id<'edgeProviderAccounts'>,
): Promise<number> {
  const rows = await liveEdgesOfAccount(ctx.db, accountId);
  return rows.filter((e) => e.managed).length;
}

// --- writes ---------------------------------------------------------------------------

export interface PlannedEdgeInput {
  relayId: Id<'relays'>;
  slotId: Id<'relaySlots'>;
  accountId: Id<'edgeProviderAccounts'>;
  templateId?: Id<'edgeTemplates'> | null;
  templateHash: string;
  listeners: Array<{
    edgePort: number;
    originAddress: string;
    originPort: number;
    transport?: 'tcp' | 'udp';
  }>;
  steps: Array<{
    id: string;
    kind: string;
    resourceName: string;
    discoverability?: 'by_name' | 'by_tag' | 'none';
  }>;
  nameNonce?: string;
  /** L7 only: the frozen intent + its layer (lib/edges/intent.ts). */
  layer?: 'l4' | 'l7';
  provisionIntent?: ProvisionIntent | null;
}

/**
 * Reserve capacity + one allocation and insert the planned edge, atomically
 * (shared by the mutation below and the rotation machine's selection commit).
 * Throws typed codes: relay.capacity, relay.budget.
 */
export async function insertPlannedEdge(
  ctx: { db: import('./_generated/server').DatabaseWriter },
  a: PlannedEdgeInput,
): Promise<{ id: Id<'edges'>; name: string }> {
  const [origin, account] = await Promise.all([ctx.db.get(a.relayId), ctx.db.get(a.accountId)]);
  if (!origin) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
  if (!account) throw new ConvexError({ code: 'not_found', message: 'Account not found' });
  const live = await liveCountForAccount(ctx, a.accountId);
  if (live >= account.maxLiveEdges) {
    throw new ConvexError({ code: 'edge.capacity', message: 'Account is at its live-edge cap' });
  }
  if (!(await reserveAllocation(ctx, a.accountId))) {
    throw new ConvexError({
      code: 'edge.budget',
      message: 'Account allocation budget exhausted for today',
    });
  }
  const now = Date.now();
  const name = edgeResourceName(origin.slug, a.nameNonce ?? randomHex(4));
  const id = await ctx.db.insert('edges', {
    relayId: a.relayId,
    slotId: a.slotId,
    accountId: a.accountId,
    templateId: a.templateId ?? undefined,
    templateHash: a.templateHash,
    provider: account.provider,
    managed: true,
    name,
    steps: a.steps.map((s) => ({
      stepId: s.id,
      kind: s.kind,
      resourceName: s.resourceName,
      discoverability: s.discoverability,
      state: 'pending' as const,
      attempt: 0,
    })),
    resources: [],
    listeners: a.listeners,
    addresses: {},
    layer: a.layer ?? 'l4',
    // Frozen here and never recomputed: every later step, discovery, describe
    // and destroy reads this instead of the account settings or the template.
    provisionIntent: a.provisionIntent ? JSON.stringify(a.provisionIntent) : undefined,
    publication: 'unpublished',
    status: 'planning',
    statusChangedAt: now,
    health: 'unknown',
    destroyAttempts: 0,
    updatedAt: now,
  });
  return { id, name };
}

export const insertPlanned = internalMutation({
  args: {
    relayId: v.id('relays'),
    slotId: v.id('relaySlots'),
    accountId: v.id('edgeProviderAccounts'),
    templateId: v.optional(v.union(v.id('edgeTemplates'), v.null())),
    templateHash: v.string(),
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
        discoverability: v.optional(
          v.union(v.literal('by_name'), v.literal('by_tag'), v.literal('none')),
        ),
      }),
    ),
    nameNonce: v.optional(v.string()),
    layer: v.optional(v.union(v.literal('l4'), v.literal('l7'))),
    provisionIntent: v.optional(v.any()),
  },
  handler: (ctx, a) =>
    insertPlannedEdge(ctx, {
      ...a,
      provisionIntent: (a.provisionIntent as ProvisionIntent | undefined) ?? null,
    }),
});

/**
 * Claim the single in-flight external operation on an edge. Refuses while an
 * unexpired op is open. An EXPIRED op may be replaced only by an observing op
 * (`discover` / `poll_step`), never by another allocating/destroying call: the
 * unknown outcome must be read back first.
 */
export const claimOp = internalMutation({
  args: {
    edgeId: v.id('edges'),
    kind: v.union(
      v.literal('provision_step'),
      v.literal('poll_step'),
      v.literal('discover'),
      v.literal('destroy_step'),
    ),
    target: v.string(),
    claimMs: v.number(),
  },
  handler: async (ctx, { edgeId, kind, target, claimMs }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    const now = Date.now();
    if (edge.currentOp) {
      if (edge.currentOp.expiresAt > now)
        return { ok: false as const, code: 'edge.op_busy' as const };
      if (kind === 'provision_step' || kind === 'destroy_step')
        return { ok: false as const, code: 'edge.op_unsettled' as const };
    }
    const prevAttempt = edge.currentOp?.target === target ? edge.currentOp.attempt : 0;
    const op = {
      opId: randomHex(8),
      kind,
      target,
      attempt: prevAttempt + 1,
      claimedAt: now,
      expiresAt: now + claimMs,
    };
    // A provision step's `startedAt` is stamped WITH THE CLAIM, not with its
    // settle: the request is about to leave, and a lost settle would otherwise
    // leave discovery without a reference time. Discovery's settle floor
    // ("has enough time passed that an empty listing proves absence?") is
    // measured from it, so an unstamped step would let a slow compound create
    // be re-run seconds later and allocate a second, orphaned resource.
    const stamped =
      kind === 'provision_step' && edge.steps.some((s) => s.stepId === target && !s.startedAt);
    await ctx.db.patch(edgeId, {
      currentOp: op,
      ...(stamped
        ? { steps: edge.steps.map((s) => (s.stepId === target ? { ...s, startedAt: now } : s)) }
        : {}),
      updatedAt: now,
    });
    return { ok: true as const, opId: op.opId, attempt: op.attempt };
  },
});

/** Release the op (only by its holder) and apply the observed outcome. */
export const settleOp = internalMutation({
  args: {
    edgeId: v.id('edges'),
    opId: v.string(),
    stepPatch: v.optional(
      v.object({
        stepId: v.string(),
        state: v.string(),
        opRef: v.optional(v.union(v.string(), v.null())),
        attempt: v.optional(v.number()),
        /** Consecutive unresolved discovery passes; `finished`/`done` resets it. */
        discoverAttempts: v.optional(v.number()),
        started: v.optional(v.boolean()),
        finished: v.optional(v.boolean()),
      }),
    ),
    addResources: v.optional(v.array(childResource)),
    addresses: v.optional(addresses),
    status: v.optional(v.string()),
    health: v.optional(v.string()),
    failure: v.optional(
      v.object({ step: v.string(), code: v.optional(v.string()), status: v.optional(v.number()) }),
    ),
    resourceDeleteState: v.optional(
      v.array(v.object({ resourceId: v.string(), deleteState: v.string() })),
    ),
  },
  handler: async (ctx, a) => {
    const edge = await ctx.db.get(a.edgeId);
    if (!edge) return { ok: false as const };
    if (!edge.currentOp || edge.currentOp.opId !== a.opId) return { ok: false as const };
    const now = Date.now();
    const patch: Partial<Edge> = { currentOp: undefined, updatedAt: now };
    if (a.stepPatch) {
      patch.steps = edge.steps.map((s) =>
        s.stepId === a.stepPatch!.stepId
          ? {
              ...s,
              state: a.stepPatch!.state as Step['state'],
              opRef: a.stepPatch!.opRef === null ? undefined : (a.stepPatch!.opRef ?? s.opRef),
              attempt: a.stepPatch!.attempt ?? s.attempt,
              discoverAttempts:
                a.stepPatch!.discoverAttempts ??
                (a.stepPatch!.state === 'done' || a.stepPatch!.state === 'pending'
                  ? undefined
                  : s.discoverAttempts),
              startedAt: a.stepPatch!.started ? (s.startedAt ?? now) : s.startedAt,
              finishedAt: a.stepPatch!.finished ? now : s.finishedAt,
            }
          : s,
      );
    }
    if (a.addResources && a.addResources.length > 0) {
      const known = new Set(edge.resources.map((r) => `${r.kind}:${r.resourceId}`));
      const stepId = a.stepPatch?.stepId ?? 'describe';
      const added: Resource[] = [];
      for (const r of a.addResources) {
        const key = `${r.kind}:${r.resourceId}`;
        if (known.has(key)) continue;
        known.add(key);
        added.push({
          stepId,
          kind: r.kind,
          resourceId: r.resourceId,
          ownership: r.ownership,
          deleteState: 'present',
          meta: r.meta !== undefined ? JSON.stringify(r.meta) : undefined,
        });
      }
      patch.resources = [...edge.resources, ...added];
    }
    if (a.addresses)
      patch.addresses = {
        v4: a.addresses.v4 ?? edge.addresses.v4,
        v6: a.addresses.v6 ?? edge.addresses.v6,
        hostname: a.addresses.hostname ?? edge.addresses.hostname,
      };
    if (a.status && a.status !== edge.status) {
      patch.status = a.status as Edge['status'];
      patch.statusChangedAt = now;
      if (a.status === 'destroyed') Object.assign(patch, destroyedPatch(now));
    }
    if (a.health) {
      patch.health = a.health as Edge['health'];
      patch.lastHealthAt = now;
    }
    if (a.failure) patch.failure = a.failure;
    if (a.resourceDeleteState) {
      const map = new Map(
        a.resourceDeleteState.map((r) => [r.resourceId, r.deleteState as Resource['deleteState']]),
      );
      patch.resources = (patch.resources ?? edge.resources).map((r) =>
        map.has(r.resourceId) ? { ...r, deleteState: map.get(r.resourceId)! } : r,
      );
    }
    await ctx.db.patch(a.edgeId, patch);
    return { ok: true as const };
  },
});

/** Status / publication changes outside an op (the rotation machine's advance path). */
export const patchEdge = internalMutation({
  args: {
    edgeId: v.id('edges'),
    status: v.optional(v.string()),
    publication: v.optional(v.string()),
    poolIndex: v.optional(v.union(v.number(), v.null())),
    drainUntil: v.optional(v.union(v.number(), v.null())),
    burnedAt: v.optional(v.number()),
    failure: v.optional(
      v.object({ step: v.string(), code: v.optional(v.string()), status: v.optional(v.number()) }),
    ),
    destroyAttemptsDelta: v.optional(v.number()),
    /** Consecutive unresolved confirms for the destroy walk's current resource (null = clear). */
    destroyConfirm: v.optional(
      v.union(v.object({ resourceId: v.string(), attempts: v.number() }), v.null()),
    ),
    stepStates: v.optional(v.array(v.object({ stepId: v.string(), state: v.string() }))),
    liveSnapshot: v.optional(v.string()),
    reachability: v.optional(v.any()),
  },
  handler: async (ctx, a) => {
    const edge = await ctx.db.get(a.edgeId);
    if (!edge) return null;
    const now = Date.now();
    const patch: Partial<Edge> = { updatedAt: now };
    if (a.status && a.status !== edge.status) {
      patch.status = a.status as Edge['status'];
      patch.statusChangedAt = now;
      if (a.status === 'destroyed') Object.assign(patch, destroyedPatch(now));
    }
    if (a.destroyConfirm !== undefined) patch.destroyConfirm = a.destroyConfirm ?? undefined;
    if (a.publication) patch.publication = a.publication as Edge['publication'];
    if (a.poolIndex !== undefined) patch.poolIndex = a.poolIndex ?? undefined;
    if (a.drainUntil !== undefined) patch.drainUntil = a.drainUntil ?? undefined;
    if (a.burnedAt !== undefined) patch.burnedAt = a.burnedAt;
    if (a.failure) patch.failure = a.failure;
    if (a.destroyAttemptsDelta)
      patch.destroyAttempts = edge.destroyAttempts + a.destroyAttemptsDelta;
    if (a.stepStates) {
      const m = new Map(a.stepStates.map((s) => [s.stepId, s.state as Step['state']]));
      patch.steps = edge.steps.map((s) =>
        m.has(s.stepId) ? { ...s, state: m.get(s.stepId)! } : s,
      );
    }
    if (a.liveSnapshot !== undefined) {
      patch.liveSnapshot = a.liveSnapshot.slice(0, 200_000);
      patch.liveAt = now;
    }
    if (a.reachability !== undefined) patch.reachability = a.reachability as Edge['reachability'];
    await ctx.db.patch(a.edgeId, patch);
    return null;
  },
});

/**
 * Record a describe() result: addresses, health, and any newly visible child
 * resources. A `gone` state is acted on only after GONE_OBSERVATIONS_REQUIRED
 * consecutive gone describes (an auth-shaped 404 or one blip must not drop a
 * published edge); when it acts, the pool drop + epoch bump happen in THIS
 * mutation together with the status transition, never in a second one.
 * Returns whether the edge was dropped from the published pool.
 */
const readinessState = v.union(
  v.literal('ready'),
  v.literal('pending'),
  v.literal('failed'),
  v.literal('unknown'),
);

/** The `front` readiness dimension: only a current, passing qualification is `ready`. */
function frontReadiness(edge: Edge, now: number): 'ready' | 'pending' | 'failed' | 'unknown' {
  const q = edge.frontQualification;
  if (!q) return 'unknown';
  if (!q.ok) return 'failed';
  return q.expiresAt > now ? 'ready' : 'pending';
}

export const recordDescribe = internalMutation({
  args: {
    edgeId: v.id('edges'),
    state: v.string(),
    addresses,
    health: v.string(),
    resources: v.optional(v.array(childResource)),
    /** L7 adapters only: the DNS + certificate dimensions they can observe. */
    readiness: v.optional(v.object({ dns: readinessState, certificate: readinessState })),
  },
  handler: async (ctx, a) => {
    const edge = await ctx.db.get(a.edgeId);
    if (!edge) return null;
    const now = Date.now();
    const known = new Set(edge.resources.map((r) => `${r.kind}:${r.resourceId}`));
    const added: Resource[] = [];
    for (const r of a.resources ?? []) {
      const key = `${r.kind}:${r.resourceId}`;
      if (known.has(key)) continue;
      known.add(key);
      added.push({
        stepId: 'describe',
        kind: r.kind,
        resourceId: r.resourceId,
        ownership: r.ownership,
        deleteState: 'present',
        meta: r.meta !== undefined ? JSON.stringify(r.meta) : undefined,
      });
    }
    // An ACTIVE describe is authoritative for the address set: a family the
    // provider no longer returns (detached floating IP, dropped v6) must stop
    // rendering. Pending/gone/unknown states keep the last known addresses
    // (still allocating, or kept for the ledger).
    //
    // Losing an address is as consequential as losing the whole edge (it stops
    // rendering and can unpublish it), so it takes the same TWO consecutive
    // observations a `gone` transition does: a single narrowed credential, a
    // truncated listing or one API blip must not wipe a published address. The
    // first such describe only counts; the second applies it.
    const known4 = edge.addresses.v4;
    const known6 = edge.addresses.v6;
    const knownName = edge.addresses.hostname;
    const losesAddress =
      a.state === 'active' &&
      ((!!known4 && !a.addresses.v4) ||
        (!!known6 && !a.addresses.v6) ||
        (!!knownName && !a.addresses.hostname));
    const addressLossObservations = losesAddress ? (edge.addressLossObservations ?? 0) + 1 : 0;
    const applyLoss = addressLossObservations >= ADDRESS_LOSS_OBSERVATIONS_REQUIRED;
    const keepKnown = losesAddress && !applyLoss;
    const addressesNext =
      a.state === 'active' && !keepKnown
        ? { v4: a.addresses.v4, v6: a.addresses.v6, hostname: a.addresses.hostname }
        : {
            v4: a.addresses.v4 ?? known4,
            v6: a.addresses.v6 ?? known6,
            hostname: a.addresses.hostname ?? knownName,
          };
    let resources = added.length > 0 ? [...edge.resources, ...added] : edge.resources;
    let transition: Partial<Edge> = {};
    const gone = a.state === 'gone' && edge.status !== 'destroyed';
    const goneObservations = gone ? (edge.goneObservations ?? 0) + 1 : 0;
    let dropped = false;
    let acted = false;
    if (gone && goneObservations >= GONE_OBSERVATIONS_REQUIRED) {
      const origin = await ctx.db.get(edge.relayId);
      // Nothing bypasses a quarantine, not even a drift drop: keep counting and
      // act once the operator has resolved it.
      if (origin && !origin.quarantine) {
        acted = true;
        // The load balancer itself is gone; its ledger entry is settled. Anything
        // else still `present` (a floating IP, a delegated address) is billable
        // and must go through the destroy path — only then is the edge destroyed.
        resources = resources.map((r) =>
          r.kind === 'lb' ? { ...r, deleteState: 'confirmed_gone' as const } : r,
        );
        const leftovers = resources.some((r) => r.deleteState !== 'confirmed_gone');
        transition = leftovers
          ? {
              status: 'destroying',
              destroyAttempts: 0,
              currentOp: undefined,
              statusChangedAt: now,
              publication: 'unpublished',
              poolIndex: undefined,
            }
          : destroyedPatch(now);
        // Same transaction: out of the pool / standby list, epoch bumped, audited.
        const r = await dropEdgeFromPool(ctx, origin, edge, { reason: 'provider_gone' });
        dropped = r.inPool && r.dropped;
      }
    }
    await ctx.db.patch(a.edgeId, {
      addresses: addressesNext,
      health: a.health as Edge['health'],
      lastHealthAt: now,
      ...(resources !== edge.resources ? { resources } : {}),
      goneObservations: acted || !gone ? undefined : goneObservations,
      addressLossObservations: keepKnown ? addressLossObservations : undefined,
      // `front` is not the adapter's to judge (DNS existence is not a working
      // front): it follows the stored end-to-end qualification.
      ...(a.readiness
        ? {
            readiness: {
              dns: a.readiness.dns,
              certificate: a.readiness.certificate,
              front: frontReadiness(edge, now),
              checkedAt: now,
            },
          }
        : {}),
      ...transition,
      updatedAt: now,
    });
    return {
      dropped,
      goneObservations: acted ? 0 : goneObservations,
      acted,
      addressLossObservations: keepKnown ? addressLossObservations : 0,
    };
  },
});

// --- external locks ---------------------------------------------------------------------
//
// `claimOp` serialises work on ONE edge. Some provider writes touch something
// SEVERAL edges share: a zone's rulesets, a service's version chain. Two edges
// provisioning at once would each read the shared object, each write it, and the
// second would silently replace the first's change. `externalLocks` is the claim
// on the shared thing, with the same unknown-outcome discipline as `currentOp`:
// an EXPIRED, unsettled lock is not stolen: the holder must re-observe what its
// write did first, so the second edge waits rather than writing over a result
// nobody has read.

/** How an expired lock surfaces to the caller (the rotation logs it and retries). */
export const LOCK_UNSETTLED = 'edge.lock_unsettled' as const;

export const claimExternalLock = internalMutation({
  args: {
    key: v.string(),
    edgeId: v.id('edges'),
    opId: v.string(),
    ttlMs: v.number(),
  },
  handler: async (ctx, { key, edgeId, opId, ttlMs }) => {
    const now = Date.now();
    const existing = await ctx.db
      .query('externalLocks')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (existing) {
      // The holder re-entering its own claim extends it (one edge, one op).
      if (existing.holderEdgeId === edgeId) {
        await ctx.db.patch(existing._id, { opId, claimedAt: now, expiresAt: now + ttlMs });
        return { ok: true as const, opId };
      }
      if (existing.expiresAt > now) return { ok: false as const, code: 'edge.lock_busy' as const };
      // Expired and never settled: the previous holder's outcome is UNKNOWN.
      // Blocking here is the whole point: its discovery pass settles the lock.
      return { ok: false as const, code: LOCK_UNSETTLED };
    }
    await ctx.db.insert('externalLocks', {
      key,
      holderEdgeId: edgeId,
      opId,
      claimedAt: now,
      expiresAt: now + ttlMs,
    });
    return { ok: true as const, opId };
  },
});

/** Release a lock; only its holder (by opId) may, so a stale actor cannot free it. */
export const settleExternalLock = internalMutation({
  args: { key: v.string(), opId: v.string() },
  handler: async (ctx, { key, opId }) => {
    const row = await ctx.db
      .query('externalLocks')
      .withIndex('by_key', (q) => q.eq('key', key))
      .unique();
    if (!row || row.opId !== opId) return { ok: false as const };
    await ctx.db.delete(row._id);
    return { ok: true as const };
  },
});

/**
 * Release every lock an edge holds, whatever their opId: used when the edge's
 * own op is settled after a lost response (the outcome has been re-observed, so
 * the shared object is safe for the next writer) and when it is destroyed.
 */
export const releaseExternalLocksOf = internalMutation({
  args: { edgeId: v.id('edges'), keys: v.optional(v.array(v.string())) },
  handler: async (ctx, { edgeId, keys }) => {
    let released = 0;
    for (const key of keys ?? []) {
      const row = await ctx.db
        .query('externalLocks')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (row && row.holderEdgeId === edgeId) {
        await ctx.db.delete(row._id);
        released++;
      }
    }
    return { released };
  },
});
