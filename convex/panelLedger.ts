/**
 * The operations ledger for panel writes (server management). The ONLY writer
 * of `panelOps` and `panelClaims`. Rules (lib/panel/ops.ts):
 *
 *  - an op and ALL its claims are inserted in one mutation, before anything is
 *    sent; a key someone else holds refuses the whole op;
 *  - an op is sent AT MOST ONCE (`markSent` refuses a second attempt), so a
 *    create whose answer was lost is never repeated: it is settled by LOOKING;
 *  - claims are released only through `applyLook` / `recordOutcome` when
 *    `claimsReleasable` says so, or through a recorded `recover`. There is no
 *    timed release and no abandonment;
 *  - other workflows reject a held claim in the reverse direction
 *    (`assertNoPanelClaim`), and the op's own follow-up work passes that same
 *    guard by OWNERSHIP (op id + generation + phase + exact claim coverage),
 *    never by a bypass flag.
 */
import { ConvexError, v } from 'convex/values';
import type { DatabaseReader } from './_generated/server';
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { capabilitiesOf } from './lib/backends/capabilities';
import type { PanelObservedHost, PanelObservedSquad } from './lib/backends/types';
import { upsertObservedHosts, upsertObservedSquads } from './panelObserve';
import {
  GONE_LOOKS_REQUIRED,
  asyncWorkFinished,
  claimsReleasable,
  displayState,
  fieldsMatch,
  hostsMatchingIdentity,
  type RequestOutcome,
} from './lib/panel/ops';
import { resolveServerConfig } from './lib/serverConfig';

type Op = Doc<'panelOps'>;

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};

// --- the guard other workflows call -------------------------------------------------------------

export interface PanelOpOwner {
  opId: Id<'panelOps'>;
  generation: number;
}

/**
 * Refuse while any of `keys` is claimed by a panel op. With `owner`, pass ONLY
 * when EVERY key has a claim row and each belongs to that op at that
 * generation: a missing required claim fails (it does not pass by vacuity), so
 * an op cannot do its follow-up work after losing, or never taking, a claim.
 */
export async function assertNoPanelClaim(
  db: DatabaseReader,
  backendServerId: Id<'backendServers'>,
  keys: readonly string[],
  owner?: PanelOpOwner,
): Promise<void> {
  for (const key of keys) {
    const claim = await db
      .query('panelClaims')
      .withIndex('by_server_key', (q) => q.eq('backendServerId', backendServerId).eq('key', key))
      .unique();
    if (!owner) {
      if (claim) refuse('servers.op_running', 'A server change is still running on this item');
      continue;
    }
    if (!claim || claim.opId !== owner.opId || claim.generation !== owner.generation)
      refuse('servers.claim_not_held', 'This step does not hold the claim it needs');
  }
}

// --- claim ------------------------------------------------------------------------------------------

export interface ClaimArgs {
  backendServerId: Id<'backendServers'>;
  kind: Op['kind'];
  verb: Op['verb'];
  label: string;
  objectUuid?: string;
  identity?: string;
  claimKeys: string[];
  intent: unknown;
  postcondition: unknown;
  /** Nodes whose application work the panel will queue behind this write. */
  asyncNodeUuids?: string[];
  actorAdminId?: Id<'adminUsers'>;
}

/** The gates every management write passes, in the claiming transaction. */
export async function assertWritable(ctx: MutationCtx, backendServerId: Id<'backendServers'>) {
  const cfg = await resolveServerConfig(ctx.db);
  if (!cfg.manage.enabled)
    refuse('servers.manage_disabled', 'Server changes are switched off in Servers settings');
  const server = await ctx.db.get(backendServerId);
  if (!server) return refuse('not_found', 'Backend server not found');
  if (!capabilitiesOf(server.backend).panelWrites)
    refuse('servers.unsupported_backend', 'This backend type cannot be managed here');
  // FCP writes a backend it has set up or adopted (docs/servers.md "Setting up
  // a backend"); nothing else writes one. The setup run itself is the one
  // caller admitted before the row is ready (it creates what the row records).
  const setup = await ctx.db
    .query('panelSetups')
    .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
    .unique();
  if (!setup) refuse('servers.not_set_up', 'Set up this backend in Servers first');
  return server;
}

/** Insert the op and every claim, or refuse the whole thing. */
export async function claimOp(ctx: MutationCtx, a: ClaimArgs): Promise<Id<'panelOps'>> {
  await assertWritable(ctx, a.backendServerId);
  const keys = [...new Set(a.claimKeys)];
  for (const key of keys) {
    const held = await ctx.db
      .query('panelClaims')
      .withIndex('by_server_key', (q) => q.eq('backendServerId', a.backendServerId).eq('key', key))
      .unique();
    if (!held) continue;
    const holder = await ctx.db.get(held.opId);
    if (holder && holder.request === 'uncertain' && holder.panelState === 'unobserved')
      refuse(
        'servers.op_uncertain',
        `An earlier change to ${holder.label} has an unknown outcome and must be settled first`,
      );
    refuse('servers.op_running', 'Another change is still running on this item');
  }
  const now = Date.now();
  const opId = await ctx.db.insert('panelOps', {
    backendServerId: a.backendServerId,
    kind: a.kind,
    verb: a.verb,
    generation: 1,
    claimKeys: keys,
    label: a.label,
    objectUuid: a.objectUuid,
    identity: a.identity,
    intent: JSON.stringify(a.intent),
    postcondition: JSON.stringify(a.postcondition),
    request: 'pending',
    panelState: 'unobserved',
    asyncEffect: a.asyncNodeUuids && a.asyncNodeUuids.length > 0 ? 'pending' : 'none',
    asyncNodes: a.asyncNodeUuids?.map((nodeUuid) => ({ nodeUuid, before: null })),
    open: true,
    quietLooks: 0,
    actorAdminId: a.actorAdminId,
    createdAt: now,
    updatedAt: now,
  });
  for (const key of keys)
    await ctx.db.insert('panelClaims', {
      backendServerId: a.backendServerId,
      key,
      opId,
      generation: 1,
      claimedAt: now,
    });
  return opId;
}

async function release(ctx: MutationCtx, op: Op, patch: Partial<Op>) {
  const claims = await ctx.db
    .query('panelClaims')
    .withIndex('by_op', (q) => q.eq('opId', op._id))
    .collect();
  for (const c of claims) await ctx.db.delete(c._id);
  await ctx.db.patch(op._id, {
    ...patch,
    open: false,
    settledAt: Date.now(),
    updatedAt: Date.now(),
  });
}

// --- the run: send once ---------------------------------------------------------------------------

export const getForRun = internalQuery({
  args: { opId: v.id('panelOps') },
  handler: async (ctx, { opId }) => ctx.db.get(opId),
});

/**
 * Record that the ONE attempt is about to be sent, with the node clocks read
 * just before it. Refuses when an attempt was already recorded: whatever
 * happened to it, it is never sent again.
 */
export const markSent = internalMutation({
  args: {
    opId: v.id('panelOps'),
    attemptId: v.string(),
    asyncNodes: v.optional(
      v.array(v.object({ nodeUuid: v.string(), before: v.union(v.string(), v.null()) })),
    ),
  },
  handler: async (ctx, { opId, attemptId, asyncNodes }) => {
    const op = await ctx.db.get(opId);
    if (!op || !op.open) return { send: false as const };
    if (op.attemptId) return { send: false as const };
    await ctx.db.patch(opId, {
      attemptId,
      sentAt: Date.now(),
      ...(asyncNodes ? { asyncNodes } : {}),
      updatedAt: Date.now(),
    });
    return { send: true as const };
  },
});

export const recordOutcome = internalMutation({
  args: {
    opId: v.id('panelOps'),
    request: v.union(
      v.literal('rejected_pre_mutation'),
      v.literal('acknowledged'),
      v.literal('uncertain'),
    ),
    objectUuid: v.optional(v.string()),
    errorCode: v.optional(v.string()),
  },
  handler: async (ctx, { opId, request, objectUuid, errorCode }) => {
    const op = await ctx.db.get(opId);
    if (!op || !op.open) return null;
    const next = {
      request: request as RequestOutcome,
      ...(objectUuid ? { objectUuid } : {}),
      ...(errorCode ? { errorCode } : {}),
    };
    if (request === 'rejected_pre_mutation') {
      await release(ctx, op, next);
      await audit(ctx, { ...op, ...next }, 'refused');
    } else await ctx.db.patch(opId, { ...next, updatedAt: Date.now() });
    return null;
  },
});

/**
 * A create whose identity ALREADY exists on the panel before anything was
 * sent: exactly one match is adopted (no call is made), several are left to
 * the operator. Either way the op never sends.
 */
export const settleWithoutSending = internalMutation({
  args: {
    opId: v.id('panelOps'),
    outcome: v.union(v.literal('adopted'), v.literal('duplicate')),
    objectUuid: v.optional(v.string()),
  },
  handler: async (ctx, { opId, outcome, objectUuid }) => {
    const op = await ctx.db.get(opId);
    if (!op || !op.open || op.attemptId) return null;
    if (outcome === 'adopted') {
      const next = {
        request: 'acknowledged' as const,
        panelState: 'observed' as const,
        objectUuid,
        errorCode: 'servers.adopted_existing',
      };
      await own(ctx, { ...op, ...next });
      await release(ctx, op, next);
      await audit(ctx, { ...op, ...next }, 'adopted');
    } else {
      const next = {
        request: 'rejected_pre_mutation' as const,
        errorCode: 'servers.duplicate_object',
      };
      await release(ctx, op, next);
      await audit(ctx, { ...op, ...next }, 'refused');
    }
    return null;
  },
});

// --- settle by looking ---------------------------------------------------------------------------------

const observedHost = v.object({
  hostUuid: v.string(),
  remark: v.string(),
  address: v.string(),
  port: v.number(),
  sni: v.union(v.string(), v.null()),
  host: v.union(v.string(), v.null()),
  path: v.union(v.string(), v.null()),
  alpn: v.union(v.string(), v.null()),
  fingerprint: v.union(v.string(), v.null()),
  securityLayer: v.union(v.string(), v.null()),
  isDisabled: v.boolean(),
  isHidden: v.boolean(),
  tag: v.union(v.string(), v.null()),
  viewPosition: v.union(v.number(), v.null()),
  configProfileUuid: v.union(v.string(), v.null()),
  configProfileInboundUuid: v.union(v.string(), v.null()),
  nodeUuids: v.array(v.string()),
});
const observedProfile = v.object({
  changeToken: v.string(),
  /** tag -> inbound uuid as read now. */
  inboundUuids: v.record(v.string(), v.string()),
});
const observedSquad = v.object({
  squadUuid: v.string(),
  name: v.string(),
  inboundUuids: v.array(v.string()),
  membersCount: v.union(v.number(), v.null()),
});

/**
 * One look at the panel, taken AFTER the attempt. Decides whether the
 * postcondition is seen and whether queued node work is done, and releases the
 * claims only when `claimsReleasable` allows it. A create that matches SEVERAL
 * rows is never adopted: it stays fenced for the operator.
 */
export const applyLook = internalMutation({
  args: {
    opId: v.id('panelOps'),
    hosts: v.optional(v.array(observedHost)),
    squads: v.optional(v.array(observedSquad)),
    profile: v.optional(observedProfile),
    nodes: v.optional(
      v.array(
        v.object({
          nodeUuid: v.string(),
          lastStatusChange: v.union(v.string(), v.null()),
          isDisabled: v.boolean(),
          // Present for node ops, which are settled against the node row itself.
          name: v.optional(v.string()),
          address: v.optional(v.union(v.string(), v.null())),
          port: v.optional(v.union(v.number(), v.null())),
          countryCode: v.optional(v.union(v.string(), v.null())),
          configProfileUuid: v.optional(v.union(v.string(), v.null())),
          activeInboundUuids: v.optional(v.array(v.string())),
        }),
      ),
    ),
  },
  handler: async (ctx, { opId, hosts, squads, profile, nodes }) => {
    const op = await ctx.db.get(opId);
    if (!op || !op.open) return { open: false };
    // A look only means something once the attempt exists (or was never needed).
    if (op.request === 'pending') return { open: true };
    const expected = JSON.parse(op.postcondition) as Record<string, unknown>;
    const patch: Partial<Op> = { lastLookAt: Date.now() };
    let seen = op.panelState === 'observed';
    let objectUuid = op.objectUuid;

    if (!seen) {
      if (op.kind === 'host' && hosts) {
        if (op.verb === 'create') {
          const matches = hostsMatchingIdentity(hosts, op.identity ?? '');
          if (matches.length === 1) {
            seen = true;
            objectUuid = matches[0].hostUuid;
          } else if (matches.length > 1) patch.errorCode = 'servers.duplicate_object';
        } else if (op.verb === 'delete') {
          const gone = !hosts.some((h) => h.hostUuid === op.objectUuid);
          patch.quietLooks = gone ? op.quietLooks + 1 : 0;
          seen = gone && patch.quietLooks >= GONE_LOOKS_REQUIRED;
        } else if (op.verb === 'reorder') {
          const want = expected.order as { hostUuid: string; viewPosition: number }[];
          seen = want.every(
            (w) => hosts.find((h) => h.hostUuid === w.hostUuid)?.viewPosition === w.viewPosition,
          );
        } else
          seen = fieldsMatch(
            hosts.find((h) => h.hostUuid === op.objectUuid),
            expected,
          );
      }
      if (op.kind === 'profile' && profile) {
        // The whole config, key material included, is what the token covers:
        // equal tokens mean the edit landed AND nothing else moved.
        seen = profile.changeToken === expected.expectedToken;
        // The panel keeps an inbound's uuid while tag and protocol hold. If one
        // moved anyway, every binding to it (listeners, Hosts, squads) is stale:
        // say so loudly rather than carry on as if nothing happened.
        const before = (expected.inboundUuids ?? {}) as Record<string, string>;
        if (
          seen &&
          Object.entries(before).some(([tag, uuid]) => profile.inboundUuids[tag] !== uuid)
        )
          patch.errorCode = 'servers.inbound_uuid_changed';
      }
      if (op.kind === 'node' && nodes) {
        if (op.verb === 'create') {
          const matches = nodes.filter((n) => n.name === op.identity);
          if (matches.length === 1) {
            seen = true;
            objectUuid = matches[0].nodeUuid;
          } else if (matches.length > 1) patch.errorCode = 'servers.duplicate_object';
        } else if (op.verb === 'delete') {
          const gone = !nodes.some((n) => n.nodeUuid === op.objectUuid);
          patch.quietLooks = gone ? op.quietLooks + 1 : 0;
          seen = gone && patch.quietLooks >= GONE_LOOKS_REQUIRED;
        } else
          // update / enable / disable / restart: the named fields of the row. A
          // restart names none, so the row alone never settles it: its evidence
          // is the node's own clock, below.
          seen = fieldsMatch(
            nodes.find((n) => n.nodeUuid === op.objectUuid) as Record<string, unknown> | undefined,
            expected,
          );
      }
      if (op.kind === 'squad' && squads) {
        if (op.verb === 'create') {
          const matches = squads.filter((s) => s.name === op.identity);
          if (matches.length === 1) {
            seen = true;
            objectUuid = matches[0].squadUuid;
          } else if (matches.length > 1) patch.errorCode = 'servers.duplicate_object';
        } else if (op.verb === 'delete') {
          const gone = !squads.some((s) => s.squadUuid === op.objectUuid);
          patch.quietLooks = gone ? op.quietLooks + 1 : 0;
          seen = gone && patch.quietLooks >= GONE_LOOKS_REQUIRED;
        } else
          seen = fieldsMatch(
            squads.find((s) => s.squadUuid === op.objectUuid),
            expected,
          );
      }
    }
    if (seen) {
      patch.panelState = 'observed';
      patch.objectUuid = objectUuid;
    }
    // Reading the changed row never finishes the queued node work: that is its own fact.
    let asyncEffect = op.asyncEffect;
    if (seen && asyncEffect === 'pending' && nodes && asyncWorkFinished(op.asyncNodes ?? [], nodes))
      asyncEffect = 'complete';
    patch.asyncEffect = asyncEffect;

    const next = { ...op, ...patch } as Op;
    // Bring the bound listeners back in step as soon as the result is seen, in
    // THIS transaction: it either happens with the observation or not at all,
    // and a later look simply tries again. It runs under the op's own claims.
    if (seen && op.kind === 'profile' && op.panelState !== 'observed')
      await bridgeProfilePatch(ctx, next);
    if (claimsReleasable(next)) {
      await own(ctx, next);
      await syncCache(ctx, next, hosts, squads);
      await release(ctx, op, patch);
      await audit(ctx, next, 'done');
      return { open: false };
    }
    await ctx.db.patch(opId, { ...patch, updatedAt: Date.now() });
    return { open: true };
  },
});

/**
 * After a profile edit is SEEN on the panel, the relay listeners bound to the
 * touched inbounds follow. Ownership, not a bypass: the op must hold the claim
 * on every relay it is about to touch, exactly.
 *
 *  - a new TARGET is descriptive state of the listener: it is updated, and the
 *    listener's `revision` moves, so every L4 endpoint confirmation on it is
 *    due a retest (the material an operator tested against changed);
 *  - new SERVER NAMES are NOT activated here. The panel listing a name does not
 *    mean the node accepts it (measured), so a name reaches members only
 *    through a path that proves acceptance. Removed names were refused at claim
 *    time while a listener still handed them out, so nothing is left to retire.
 */
async function bridgeProfilePatch(ctx: MutationCtx, op: Op) {
  const expected = JSON.parse(op.postcondition) as {
    targets?: Record<string, { address: string; port: number }>;
    relayIds?: string[];
    inboundUuids?: Record<string, string>;
  };
  const relayIds = (expected.relayIds ?? []) as Id<'relays'>[];
  if (relayIds.length === 0) return;
  await assertNoPanelClaim(
    ctx.db,
    op.backendServerId,
    relayIds.map((r) => `relay:${r}`),
    { opId: op._id, generation: op.generation },
  );
  const targets = expected.targets ?? {};
  for (const relayId of relayIds) {
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    for (const l of listeners) {
      if (l.retired || !l.panelBinding) continue;
      const tag = Object.entries(expected.inboundUuids ?? {}).find(
        ([, uuid]) => uuid === l.panelBinding!.configProfileInboundUuid,
      )?.[0];
      const target = tag ? targets[tag] : undefined;
      if (!target) continue;
      if (l.realityTarget?.address === target.address && l.realityTarget?.port === target.port)
        continue;
      await ctx.db.patch(l._id, {
        realityTarget: target,
        revision: l.revision + 1,
        updatedAt: Date.now(),
      });
    }
  }
}

/**
 * The page shows the result at once instead of waiting for the next scheduled
 * look. The same replace-the-instance's-rows step the observation makes, so
 * the two writers of the cache cannot disagree on a row's shape.
 */
async function syncCache(
  ctx: MutationCtx,
  op: Op,
  hosts?: readonly PanelObservedHost[],
  squads?: readonly PanelObservedSquad[],
) {
  const now = Date.now();
  if (op.kind === 'host' && hosts) await upsertObservedHosts(ctx, op.backendServerId, hosts, now);
  if (op.kind === 'squad' && squads)
    await upsertObservedSquads(ctx, op.backendServerId, squads, now);
}

/** Ownership follows the settled op: a create is owned, a delete leaves a tombstone. */
async function own(ctx: MutationCtx, op: Op) {
  if (op.verb !== 'create' && op.verb !== 'delete') return;
  const kind = op.kind;
  const now = Date.now();
  const byUuid = op.objectUuid
    ? await ctx.db
        .query('panelOwnership')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', op.backendServerId).eq('panelUuid', op.objectUuid),
        )
        .collect()
    : [];
  const existing = byUuid.find((r) => r.kind === kind);
  const identity = op.identity ?? op.label;
  if (op.verb === 'create') {
    if (existing)
      await ctx.db.patch(existing._id, {
        state: 'owned',
        lookup: [...new Set([...existing.lookup, identity])],
        updatedAt: now,
      });
    else
      await ctx.db.insert('panelOwnership', {
        backendServerId: op.backendServerId,
        kind,
        identity,
        lookup: [identity],
        panelUuid: op.objectUuid,
        state: 'owned',
        since: now,
        updatedAt: now,
      });
    return;
  }
  // delete: keep every identity the object had, so recreation by name is refused too.
  if (existing)
    await ctx.db.patch(existing._id, {
      state: 'tombstoned',
      lookup: [...new Set([...existing.lookup, identity])],
      updatedAt: now,
    });
  else
    await ctx.db.insert('panelOwnership', {
      backendServerId: op.backendServerId,
      kind,
      identity,
      lookup: [identity],
      panelUuid: op.objectUuid,
      state: 'tombstoned',
      since: now,
      updatedAt: now,
    });
}

async function audit(
  ctx: MutationCtx,
  op: Op,
  outcome: 'done' | 'refused' | 'adopted' | 'recovered',
) {
  const server = await ctx.db.get(op.backendServerId);
  await writeAuditLog(ctx, {
    actorType: 'admin',
    actorId: op.actorAdminId ?? undefined,
    action: `servers.${op.kind}.${op.verb}`,
    targetType: 'panel_op',
    targetId: op._id,
    payload: {
      backendSlug: server?.slug ?? '',
      label: op.label,
      outcome,
      ...(op.errorCode ? { code: op.errorCode } : {}),
    },
  });
}

// --- crash recovery + reads ------------------------------------------------------------------------

/**
 * An op that never recorded an attempt SENT nothing (the claim and the send
 * are separate steps): it is released as never sent. One that recorded an
 * attempt but no outcome was interrupted mid-call: its outcome is unknown.
 */
export const sweepInterrupted = internalMutation({
  args: { olderThanMs: v.number() },
  handler: async (ctx, { olderThanMs }) => {
    const cutoff = Date.now() - olderThanMs;
    const open = await ctx.db
      .query('panelOps')
      .withIndex('by_open', (q) => q.eq('open', true))
      .collect();
    const toLook: Id<'panelOps'>[] = [];
    const released: Id<'panelOps'>[] = [];
    for (const op of open) {
      if (op.request === 'pending' && op.updatedAt < cutoff) {
        if (!op.attemptId) {
          const next = {
            request: 'rejected_pre_mutation' as const,
            errorCode: 'servers.never_sent',
          };
          await release(ctx, op, next);
          await audit(ctx, { ...op, ...next }, 'refused');
          released.push(op._id);
          continue;
        }
        await ctx.db.patch(op._id, { request: 'uncertain', updatedAt: Date.now() });
      }
      if (op.request !== 'pending' || op.attemptId) toLook.push(op._id);
    }
    return { toLook, released };
  },
});

/**
 * The recorded recovery of an attempt whose outcome cannot be observed. ALL
 * three conditions must be attested by name, and a read made after them must
 * have been taken (`freshReadAt`, supplied by the action that just looked).
 * "The panel was restarted" is not one of the conditions: queued work survives
 * a restart.
 */
export const recover = internalMutation({
  args: {
    opId: v.id('panelOps'),
    credentialsRevoked: v.boolean(),
    noInFlightExecutor: v.boolean(),
    queueDrained: v.boolean(),
    freshReadAt: v.number(),
    note: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const op = await ctx.db.get(a.opId);
    if (!op) return refuse('not_found', 'Operation not found');
    if (!op.open) return refuse('conflict', 'This operation is already settled');
    if (op.request === 'pending' && !op.attemptId)
      return refuse('conflict', 'This operation has not been sent; it will be released by itself');
    if (!a.credentialsRevoked || !a.noInFlightExecutor || !a.queueDrained)
      return refuse(
        'servers.recovery_incomplete',
        'Every condition must hold before an unknown outcome can be released',
      );
    const recovery = {
      credentialsRevoked: true,
      noInFlightExecutor: true,
      queueDrained: true,
      freshReadAt: a.freshReadAt,
      note: a.note?.slice(0, 500),
      byAdminId: a.actorAdminId,
      at: Date.now(),
    };
    const next = { recovery, errorCode: 'servers.recovered' };
    await release(ctx, op, next);
    await audit(ctx, { ...op, ...next }, 'recovered');
    return { ok: true as const };
  },
});

export function mapOp(op: Op) {
  return {
    id: op._id as string,
    kind: op.kind,
    verb: op.verb,
    label: op.label,
    state: displayState(op),
    request: op.request,
    panelState: op.panelState,
    asyncEffect: op.asyncEffect,
    open: op.open,
    errorCode: op.errorCode ?? null,
    createdAt: new Date(op.createdAt).toISOString(),
    settledAt: op.settledAt ? new Date(op.settledAt).toISOString() : null,
    recovered: !!op.recovery,
  };
}

export const view = internalQuery({
  args: { opId: v.id('panelOps') },
  handler: async (ctx, { opId }) => {
    const op = await ctx.db.get(opId);
    if (!op) return refuse('not_found', 'Operation not found');
    return mapOp(op);
  },
});

export const listForServer = internalQuery({
  args: { backendServerId: v.id('backendServers') },
  handler: async (ctx, { backendServerId }) =>
    (
      await ctx.db
        .query('panelOps')
        .withIndex('by_server', (q) => q.eq('backendServerId', backendServerId))
        .order('desc')
        .take(50)
    ).map(mapOp),
});
