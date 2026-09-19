/**
 * Relay LISTENERS: one port the origin answers on, what it speaks (protocol /
 * stream transport / security, src/shared/contracts/edgeProtocolIds.ts), the
 * names and REALITY target the renderer needs, how the renderer finds its
 * entry in a subscription body, and, for a panel origin, the inbound it maps
 * to and the panel Host FCP owns for it. Edges bind to one listener.
 *
 * Replaces the former slot + protocol-profile pair (a profile's names, target
 * and provider scope now live on the listener; fleet-wide name retirement is
 * one mutation over every listener carrying the name).
 *
 * Idempotency and ownership rules: lib/edges/registration.ts.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery, type MutationCtx } from './_generated/server';
import type { DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { edgeMs, MAX_DESIRED_PUBLISHED, resolveEdgeConfig } from './lib/edgeConfig';
import { listenerProtoFields } from './lib/edgeProtocolIds';
import { edgeProviderIdValidator } from './lib/edgeProviderIds';
import { listenerLayers } from './lib/edges/layers';
import { assertAdmission } from './lib/edges/maintenance';
import { ensurePoolCapacity } from './lib/edges/poolCapacity';
import {
  assertNoMatchOverlap,
  diffListeners,
  listenerConfigHash,
  mergeNames,
  normalizeName,
  validateListenerSpec,
  type CanonicalListener,
  type ListenerName,
  type ListenerSpecInput,
} from './lib/edges/registration';
import {
  assertNoRelayPanelClaim,
  assertNoRotationOrQuarantine,
  bumpEpochAndRefresh,
  liveEdgesOfRelay,
} from './lib/edges/relayGuards';
import { protocolLabel, protocolUsesSni } from './lib/edges/protocols';
import { nameRetireKeepsVerification } from './lib/edges/verification';

export type Listener = Doc<'relayListeners'>;

// --- validators shared with relays.ts (the registration body) --------------------------------

export const originTransportValidator = v.object({
  scheme: v.union(v.literal('http'), v.literal('https')),
  certPublic: v.boolean(),
  certNames: v.array(v.string()),
  acceptsHostHeader: v.union(v.literal('any'), v.literal('names')),
});

export const transportParamsValidator = v.object({
  path: v.optional(v.string()),
  host: v.optional(v.string()),
  serviceName: v.optional(v.string()),
  upgradeToken: v.optional(v.string()),
  /** XHTTP mode (checked against `XHTTP_MODES` by `validateListenerSpec`). */
  mode: v.optional(v.string()),
});

export const matchRuleValidator = v.union(
  v.object({ kind: v.literal('remark'), remark: v.string() }),
  v.object({ kind: v.literal('address') }),
  v.object({ kind: v.literal('whole-body') }),
);

export const panelBindingValidator = v.object({
  inboundTag: v.string(),
  configProfileUuid: v.string(),
  configProfileInboundUuid: v.string(),
});

/** One listener as a registration body (role PUT or admin form) carries it. */
export const listenerSpecValidator = v.object({
  listenerKey: v.string(),
  ...listenerProtoFields,
  originPort: v.number(),
  tlsNames: v.optional(v.union(v.array(v.string()), v.null())),
  realityTarget: v.optional(v.union(v.object({ address: v.string(), port: v.number() }), v.null())),
  transportParams: v.optional(v.union(transportParamsValidator, v.null())),
  originTransport: v.optional(v.union(originTransportValidator, v.null())),
  panelBinding: v.optional(v.union(panelBindingValidator, v.null())),
  matchRule: v.optional(v.union(matchRuleValidator, v.null())),
  providerScope: v.optional(
    v.union(
      v.object({
        provider: edgeProviderIdValidator,
        accountId: v.optional(v.id('edgeProviderAccounts')),
      }),
      v.null(),
    ),
  ),
  deployed: v.optional(v.boolean()),
});

// --- reads ---------------------------------------------------------------------------------

export async function listenersOf(
  ctx: { db: DatabaseReader },
  relayId: Id<'relays'>,
): Promise<Listener[]> {
  return ctx.db
    .query('relayListeners')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .collect();
}

export async function listenerByKey(
  ctx: { db: DatabaseReader },
  relayId: Id<'relays'>,
  listenerKey: string,
): Promise<Listener | null> {
  return ctx.db
    .query('relayListeners')
    .withIndex('by_relay_key', (q) => q.eq('relayId', relayId).eq('listenerKey', listenerKey))
    .unique();
}

/** The template Host remark a listener owns (null = no panel Host). */
export function listenerRemark(l: Listener): string | null {
  return l.matchRule.kind === 'remark' ? l.matchRule.remark : null;
}

export function activeNames(l: Pick<Listener, 'tlsNames'>): string[] {
  return (l.tlsNames ?? []).filter((n) => n.status === 'active').map((n) => n.name);
}

/**
 * THE one server name written to a listener's panel Host, used for probes, and
 * shown as "the" name of an endpoint. It is what a member gets who copies a raw
 * config from the panel (no per-member selection happens there) and what every
 * fallback uses, so it must be the safest name there is: the first active name
 * that is not known blocked in any curated country, else simply the first
 * active one. Stored order, so it only moves when that name leaves.
 */
export function hostSniOf(l: Pick<Listener, 'tlsNames'>): string | null {
  const active = (l.tlsNames ?? []).filter((n) => n.status === 'active');
  return (active.find((n) => !n.blockedIn || n.blockedIn.length === 0) ?? active[0])?.name ?? null;
}

export function mapListenerAdmin(l: Listener, opts: { udpProviderAvailable?: boolean } = {}) {
  const layers = listenerLayers(l, { udpProviderAvailable: opts.udpProviderAvailable });
  return {
    id: l._id as string,
    relayId: l.relayId as string,
    listenerKey: l.listenerKey,
    protocol: l.protocol,
    streamTransport: l.streamTransport,
    security: l.security,
    label: protocolLabel(l),
    transport: l.transport,
    originPort: l.originPort,
    tlsNames: (l.tlsNames ?? []).map((n) => ({
      name: n.name,
      status: n.status,
      retiredAt: n.retiredAt ? new Date(n.retiredAt).toISOString() : null,
      drainUntil: n.drainUntil ? new Date(n.drainUntil).toISOString() : null,
      retiredBy: n.retiredBy ?? null,
    })),
    realityTarget: l.realityTarget ?? null,
    transportParams: l.transportParams ?? null,
    originTransport: l.originTransport ?? null,
    providerScope: l.providerScope
      ? {
          provider: l.providerScope.provider,
          accountId: (l.providerScope.accountId as string | undefined) ?? null,
        }
      : null,
    matchRule: l.matchRule,
    panelBinding: l.panelBinding ?? null,
    host: l.host
      ? {
          state: l.host.state,
          uuid: l.host.uuid ?? null,
          ownership: l.host.ownership ?? null,
          pendingOp: l.host.op ? { kind: l.host.op.kind, attempts: l.host.op.attempts } : null,
        }
      : null,
    legacyHosts: (l.legacyHosts ?? []).map((h) => ({ uuid: h.uuid, remark: h.remark })),
    templateEdgeId: (l.templateEdgeId as string | undefined) ?? null,
    templateHostRemark: listenerRemark(l),
    source: l.source,
    layers: layers.layers,
    excluded: layers.excluded,
    enabled: l.enabled,
    deployed: l.deployed,
    deployedAt: l.deployedAt ? new Date(l.deployedAt).toISOString() : null,
    retired: l.retired,
    revision: l.revision,
    namesRevision: l.namesRevision ?? 0,
    sniPick: l.sniPick ?? null,
    updatedAt: new Date(l.updatedAt).toISOString(),
  };
}

export const listByRelay = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const rows = await listenersOf(ctx, relayId);
    return rows
      .map((l) => mapListenerAdmin(l))
      .sort((a, b) => a.listenerKey.localeCompare(b.listenerKey));
  },
});

export const get = internalQuery({
  args: { id: v.id('relayListeners') },
  handler: (ctx, { id }) => ctx.db.get(id),
});

// --- writes: registration diff (shared by the role PUT and the admin form) -----------------

function specToRow(
  relay: Doc<'relays'>,
  spec: CanonicalListener,
  names: ListenerName[],
  source: 'role' | 'admin',
  now: number,
  existing?: Listener,
): Omit<Listener, '_id' | '_creationTime'> {
  return {
    relayId: relay._id,
    listenerKey: spec.listenerKey,
    protocol: spec.protocol,
    streamTransport: spec.streamTransport,
    security: spec.security,
    transport: spec.transport,
    originPort: spec.originPort,
    tlsNames: spec.tlsNames.length > 0 || names.length > 0 ? names : undefined,
    realityTarget: spec.realityTarget,
    transportParams: spec.transportParams,
    originTransport: spec.originTransport
      ? { ...spec.originTransport, certNames: [...spec.originTransport.certNames] }
      : undefined,
    providerScope: spec.providerScope
      ? {
          provider: spec.providerScope.provider as Doc<'edgeProviderAccounts'>['provider'],
          accountId: spec.providerScope.accountId as Id<'edgeProviderAccounts'> | undefined,
        }
      : undefined,
    matchRule: spec.matchRule,
    panelBinding: spec.panelBinding,
    host: existing?.host,
    legacyHosts: existing?.legacyHosts,
    templateEdgeId: existing?.templateEdgeId,
    source,
    configHash: listenerConfigHash(spec),
    enabled: existing?.enabled ?? true,
    deployed: spec.deployed,
    deployedAt: existing?.deployedAt ?? (spec.deployed ? now : undefined),
    retired: false,
    revision: (existing?.revision ?? 0) + 1,
    updatedAt: now,
  };
}

export interface ApplyRegistrationResult {
  created: string[];
  updated: string[];
  unchanged: string[];
  retired: string[];
  /** Body keys that named a listener another source owns (refused, not applied). */
  owned: string[];
  /** Names a role body wanted active that an admin retired (kept retired). */
  blockedNames: string[];
  /** Anything material changed (epoch bumped, mirrors refreshed). */
  changed: boolean;
}

/**
 * Apply a registration body's listeners to a relay: create, update (material
 * change only), leave unchanged, and prune the caller's own listeners the body
 * omits. One epoch bump for the whole body when anything changed. Throws
 * `edge.listener_in_use` when a rebind / prune would strand a non-destroyed
 * edge, `edge.listener_key_owned` when the body names another source's key,
 * `edge.match_rule_overlap` when the resulting rule set is ambiguous.
 */
export async function applyRegistration(
  ctx: MutationCtx,
  relay: Doc<'relays'>,
  inputs: ListenerSpecInput[],
  source: 'role' | 'admin',
  opts: { prune: boolean; actorAdminId?: Id<'adminUsers'> },
): Promise<ApplyRegistrationResult> {
  // A server change that is bringing this relay's listeners back in step owns them meanwhile.
  await assertNoRelayPanelClaim(ctx.db, relay);
  const specs = inputs.map((s) => validateListenerSpec(s, { origin: relay.origin }));
  const existing = await listenersOf(ctx, relay._id);
  const diff = diffListeners(existing, specs, source, opts.prune);
  if (diff.owned.length > 0)
    throw new ConvexError({
      code: 'edge.listener_key_owned',
      message: `listener key(s) owned by another source: ${diff.owned.join(', ')}`,
    });
  // The resulting rule set must be unambiguous.
  const after = [
    ...existing
      .filter(
        (l) =>
          !l.retired &&
          !diff.prune.includes(l) &&
          !diff.update.some((u) => u.existing._id === l._id),
      )
      .map((l) => ({
        listenerKey: l.listenerKey,
        originPort: l.originPort,
        matchRule: l.matchRule,
      })),
    ...diff.update.map((u) => ({
      listenerKey: u.spec.listenerKey,
      originPort: u.spec.originPort,
      matchRule: u.spec.matchRule,
    })),
    ...diff.create.map((c) => ({
      listenerKey: c.listenerKey,
      originPort: c.originPort,
      matchRule: c.matchRule,
    })),
  ];
  assertNoMatchOverlap(after);
  // The pool can cover at most MAX_DESIRED_PUBLISHED listeners (one published
  // slot each), so a body that would leave MORE deployed, enabled listeners
  // than that is refused here, where the operator can act on it, instead of
  // being clamped silently by `ensurePoolCapacity`. Judged on the resulting set
  // and only when the count grows: a pre-existing excess is not made worse.
  const coverageBefore = existing.filter((l) => !l.retired && l.deployed && l.enabled).length;
  const coverageAfter =
    existing.filter(
      (l) =>
        !l.retired &&
        l.deployed &&
        l.enabled &&
        !diff.prune.includes(l) &&
        !diff.update.some((u) => u.existing._id === l._id),
    ).length +
    diff.update.filter((u) => u.spec.deployed && u.existing.enabled).length +
    diff.create.filter((c) => c.deployed).length;
  if (coverageAfter > MAX_DESIRED_PUBLISHED && coverageAfter > coverageBefore)
    throw new ConvexError({
      code: 'edge.listener_cap',
      message: `a relay can carry at most ${MAX_DESIRED_PUBLISHED} deployed, enabled listeners (this body would leave ${coverageAfter}); retire or disable one first`,
    });

  const material = diff.create.length + diff.update.length + diff.prune.length > 0;
  if (material) await assertNoRotationOrQuarantine(ctx.db, relay);
  const live = material ? await liveEdgesOfRelay(ctx.db, relay._id) : [];
  const cfg = await resolveEdgeConfig(ctx.db);
  const drainMs = edgeMs.sniDrain(cfg);
  const now = Date.now();
  const result: ApplyRegistrationResult = {
    created: [],
    updated: [],
    unchanged: [],
    retired: [],
    owned: [],
    blockedNames: [],
    changed: false,
  };

  for (const spec of diff.create) {
    const names: ListenerName[] = spec.tlsNames.map((n) => ({
      name: n,
      status: 'active' as const,
    }));
    await ctx.db.insert('relayListeners', specToRow(relay, spec, names, source, now));
    result.created.push(spec.listenerKey);
  }
  for (const { existing: ex, spec } of diff.update) {
    const rebound =
      ex.protocol !== spec.protocol ||
      ex.streamTransport !== spec.streamTransport ||
      ex.security !== spec.security ||
      ex.originPort !== spec.originPort ||
      (ex.panelBinding?.configProfileInboundUuid ?? null) !==
        (spec.panelBinding?.configProfileInboundUuid ?? null);
    if (rebound || ex.retired) {
      const users = live.filter((e) => e.listenerId === ex._id);
      if (users.length > 0)
        throw new ConvexError({
          code: 'edge.listener_in_use',
          message: `${users.length} edge(s) still use listener ${ex.listenerKey}; destroy them before rebinding its protocol, inbound or port`,
        });
    }
    const merged = mergeNames(ex.tlsNames ?? [], spec.tlsNames, source, now, drainMs);
    result.blockedNames.push(...merged.blocked);
    const row = specToRow(relay, spec, merged.next, source, now, ex);
    // A change that keeps the binding but moves the listener out of a LAYER its
    // live edges sit on (an origin transport going from HTTPS to plaintext
    // drops L4; removing it drops L7) would keep handing members an endpoint
    // that can no longer reach the listener: refused while such edges exist.
    if (!rebound) {
      // Judged on the transport alone (the names as they were): retiring names
      // has its own drain and must not be refused here.
      const still = listenerLayers({ ...row, tlsNames: ex.tlsNames }).layers;
      const stranded = live.filter(
        (e) => e.listenerId === ex._id && !still.includes(e.layer ?? 'l4'),
      );
      if (stranded.length > 0)
        throw new ConvexError({
          code: 'edge.listener_in_use',
          message: `${stranded.length} edge(s) front listener ${ex.listenerKey} on a layer this change no longer allows; destroy them before changing its origin transport`,
        });
    }
    // A re-bound inbound gets a NEW panel Host; forget the old one.
    if (rebound && ex.host) row.host = { state: 'absent' };
    await ctx.db.patch(ex._id, {
      ...row,
      deployedAt: rebound || !ex.deployed ? now : ex.deployedAt,
    });
    result.updated.push(spec.listenerKey);
    if (merged.retired.length > 0)
      await scheduleNameDrain(ctx, ex._id, merged.retired, now + drainMs);
  }
  for (const { existing: ex } of diff.unchanged) result.unchanged.push(ex.listenerKey);
  for (const ex of diff.prune) {
    const users = live.filter((e) => e.listenerId === ex._id);
    if (users.length > 0)
      throw new ConvexError({
        code: 'edge.listener_in_use',
        message: `${users.length} edge(s) still use listener ${ex.listenerKey}; destroy them before removing it`,
      });
    await ctx.db.patch(ex._id, {
      retired: true,
      deployed: false,
      revision: ex.revision + 1,
      updatedAt: now,
    });
    result.retired.push(ex.listenerKey);
  }
  result.changed = material;
  if (material) await bumpEpochAndRefresh(ctx, relay);
  return result;
}

// --- admin CRUD --------------------------------------------------------------------------

/** Admin-created or admin-edited listener (source `admin`; never pruned by the role). */
export const upsert = internalMutation({
  args: {
    relayId: v.id('relays'),
    spec: listenerSpecValidator,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, spec, actorAdminId }) => {
    await assertAdmission(ctx.db, 'registration');
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const r = await applyRegistration(ctx, relay, [spec as ListenerSpecInput], 'admin', {
      prune: false,
      actorAdminId,
    });
    const row = await listenerByKey(ctx, relayId, spec.listenerKey);
    // A new or re-deployed listener needs a published slot of its own.
    const capacity = await ensurePoolCapacity(ctx, (await ctx.db.get(relayId))!);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.upsert',
      targetType: 'relay_listener',
      targetId: row?._id,
      payload: {
        relaySlug: relay.slug,
        listenerKey: spec.listenerKey,
        created: r.created.length > 0,
      },
    });
    return {
      id: row!._id,
      created: r.created.length > 0,
      changed: r.changed || capacity.to !== capacity.from,
      templateHostRemark: row ? listenerRemark(row) : null,
      warnings: capacity.raised ? ['edge.pool_raised'] : [],
    };
  },
});

export const retire = internalMutation({
  args: {
    relayId: v.id('relays'),
    listenerKey: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { relayId, listenerKey, actorAdminId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const l = await listenerByKey(ctx, relayId, listenerKey);
    if (!l || l.retired) return { ok: true as const };
    await assertNoRotationOrQuarantine(ctx.db, relay);
    // ANY non-destroyed edge (a standby included) bound to the listener blocks
    // the retire: it would otherwise orphan the edge.
    const users = (await liveEdgesOfRelay(ctx.db, relayId)).filter((e) => e.listenerId === l._id);
    if (users.length > 0)
      throw new ConvexError({
        code: 'edge.listener_in_use',
        message: `${users.length} edge(s) still use listener ${listenerKey}; destroy them first`,
      });
    if (l.host && l.host.state !== 'absent' && l.host.ownership === 'fcp')
      throw new ConvexError({
        code: 'edge.host_present',
        message:
          'Delete the listener’s panel Host first (or it will be removed by the Host cleanup)',
      });
    await ctx.db.patch(l._id, {
      retired: true,
      deployed: false,
      revision: l.revision + 1,
      updatedAt: Date.now(),
    });
    await bumpEpochAndRefresh(ctx, relay);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.retire',
      targetType: 'relay_listener',
      targetId: l._id,
      payload: { relaySlug: relay.slug, listenerKey },
    });
    return { ok: true as const };
  },
});

export const setEnabled = internalMutation({
  args: {
    id: v.id('relayListeners'),
    enabled: v.boolean(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, enabled, actorAdminId }) => {
    const l = await ctx.db.get(id);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    if (l.enabled === enabled) return { ok: true as const };
    await assertNoRotationOrQuarantine(ctx.db, relay);
    await ctx.db.patch(id, { enabled, revision: l.revision + 1, updatedAt: Date.now() });
    await bumpEpochAndRefresh(ctx, relay);
    // Re-enabling a deployed listener needs a published slot of its own.
    if (enabled) await ensurePoolCapacity(ctx, (await ctx.db.get(relay._id))!);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.update',
      targetType: 'relay_listener',
      targetId: id,
      payload: { relaySlug: relay.slug, listenerKey: l.listenerKey, enabled },
    });
    return { ok: true as const };
  },
});

// --- server names ---------------------------------------------------------------------------

async function scheduleNameDrain(
  ctx: MutationCtx,
  listenerId: Id<'relayListeners'>,
  names: string[],
  drainUntil: number,
) {
  if (names.length === 0) return;
  await ctx.scheduler.runAt(drainUntil, internal.relayListeners.onNameDrainElapsed, {
    id: listenerId,
    names,
  });
}

/** Scheduled at a retirement's drainUntil: bump + refresh if any name is still retired with an elapsed drain. */
export const onNameDrainElapsed = internalMutation({
  args: { id: v.id('relayListeners'), names: v.array(v.string()) },
  handler: async (ctx, { id, names }) => {
    const l = await ctx.db.get(id);
    if (!l) return null;
    const now = Date.now();
    const elapsed = (l.tlsNames ?? []).some(
      (n) =>
        names.includes(n.name) &&
        n.status === 'retired' &&
        n.drainUntil !== undefined &&
        n.drainUntil <= now,
    );
    if (elapsed) {
      const relay = await ctx.db.get(l.relayId);
      if (relay) await bumpEpochAndRefresh(ctx, relay);
    }
    return null;
  },
});

async function retireOn(
  ctx: MutationCtx,
  l: Listener,
  relay: Doc<'relays'>,
  targets: Set<string>,
  by: 'admin' | 'role',
  now: number,
  drainMs: number,
  /** `allowLast`: the caller has decided that no name is better than these (a burn). */
  opts: { allowLast?: boolean } = {},
): Promise<string[]> {
  const retiring: string[] = [];
  const next = (l.tlsNames ?? []).map((n) => {
    if (targets.has(n.name) && n.status === 'active') {
      retiring.push(n.name);
      return {
        name: n.name,
        status: 'retired' as const,
        retiredAt: now,
        drainUntil: now + drainMs,
        retiredBy: by,
      };
    }
    return n;
  });
  if (retiring.length === 0) return [];
  // A listener that presents names keeps at least one, unless it is L7-only
  // (the hostname is then the name) or the caller burns a name known blocked:
  // a listener with no active name renders nothing (its members get the
  // edge-required 503, not a name that fails), which is the lesser harm.
  const l7Only = l.originTransport?.scheme === 'http';
  if (!l7Only && !opts.allowLast && !next.some((n) => n.status === 'active'))
    throw new ConvexError({
      code: 'conflict',
      message: `listener ${l.listenerKey} keeps at least one active server name`,
    });
  // A REALITY retire keeps the operator's endpoint confirmation (see
  // nameRetireKeepsVerification); everything else is a material revision bump.
  await ctx.db.patch(l._id, {
    tlsNames: next,
    ...(nameRetireKeepsVerification(l)
      ? { namesRevision: (l.namesRevision ?? 0) + 1 }
      : { revision: l.revision + 1 }),
    updatedAt: now,
  });
  await scheduleNameDrain(ctx, l._id, retiring, now + drainMs);
  await bumpEpochAndRefresh(ctx, relay);
  return retiring;
}

/**
 * Family names that left their family (burned, retired, or no longer served by
 * the target) leave the relays too, with the normal drain. Two rules:
 *
 *  - `keepLast`: a name that merely stopped qualifying never takes a relay's
 *    LAST active name with it. A relay with one doubtful name still serves its
 *    members; a relay with none serves nobody. A burn passes `false`: a name
 *    known blocked is worse than no name.
 *  - a relay that is rotating, restoring, quarantined or being changed by
 *    Servers is skipped and counted, never forced.
 *
 * When the name that goes is the one the panel Host carries, the Host follows
 * (`hostOps.resyncSni`).
 */
export async function retireFamilyNames(
  ctx: MutationCtx,
  names: readonly string[],
  opts: { keepLast: boolean; by: 'admin' },
): Promise<{ listeners: number; retired: number; skipped: number; kept: number }> {
  const targets = new Set(names);
  const out = { listeners: 0, retired: 0, skipped: 0, kept: 0 };
  if (targets.size === 0) return out;
  const cfg = await resolveEdgeConfig(ctx.db);
  const now = Date.now();
  for (const l of await ctx.db.query('relayListeners').collect()) {
    if (l.retired) continue;
    const hit = (l.tlsNames ?? []).filter((n) => n.status === 'active' && targets.has(n.name));
    if (hit.length === 0) continue;
    const relay = await ctx.db.get(l.relayId);
    if (!relay) continue;
    try {
      await assertNoRotationOrQuarantine(ctx.db, relay);
    } catch {
      out.skipped++;
      continue;
    }
    const active = activeNames(l);
    let mine = new Set(hit.map((n) => n.name));
    if (opts.keepLast && active.every((n) => mine.has(n))) {
      // Keep the safest of them handed out.
      const keep = hostSniOf(l) ?? active[0];
      mine = new Set([...mine].filter((n) => n !== keep));
      out.kept++;
    }
    if (mine.size === 0) continue;
    const before = hostSniOf(l);
    try {
      const retired = await retireOn(ctx, l, relay, mine, opts.by, now, edgeMs.sniDrain(cfg), {
        allowLast: !opts.keepLast,
      });
      out.listeners++;
      out.retired += retired.length;
    } catch (e) {
      // Only the listener's own "keeps at least one name" refusal is a kept
      // name; anything else is a fault and must surface.
      if (e instanceof ConvexError && (e.data as { code?: string }).code === 'conflict') {
        out.kept++;
        continue;
      }
      throw e;
    }
    const after = await ctx.db.get(l._id);
    if (after && before !== hostSniOf(after) && after.host?.uuid && relay.hostMode === 'fcp')
      await ctx.scheduler.runAfter(0, internal.hostOps.resyncSni, { listenerId: l._id });
  }
  return out;
}

export const retireName = internalMutation({
  args: {
    id: v.id('relayListeners'),
    names: v.array(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, names, actorAdminId }) => {
    const l = await ctx.db.get(id);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const cfg = await resolveEdgeConfig(ctx.db);
    const targets = new Set(names.map(normalizeName).filter((n): n is string => !!n));
    const retired = await retireOn(
      ctx,
      l,
      relay,
      targets,
      'admin',
      Date.now(),
      edgeMs.sniDrain(cfg),
    );
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.name.retire',
      targetType: 'relay_listener',
      targetId: id,
      payload: { relaySlug: relay.slug, listenerKey: l.listenerKey, count: retired.length },
    });
    return { ok: true as const, retired: retired.length };
  },
});

/**
 * Fleet-wide retirement of a burned name: every listener on every relay that
 * carries it, in ONE transaction, so it can never half-apply. A relay that is
 * rotating or quarantined refuses the whole call (the operator resolves that
 * first; nothing is retired anywhere).
 */
export const retireNameEverywhere = internalMutation({
  args: { name: v.string(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { name, actorAdminId }) => {
    const n = normalizeName(name);
    if (!n) throw new ConvexError({ code: 'validation', message: 'invalid server name' });
    const relays = await ctx.db.query('relays').collect(); // small operator table
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    const touched: Array<{ relay: Doc<'relays'>; listener: Listener }> = [];
    for (const relay of relays) {
      for (const l of await listenersOf(ctx, relay._id)) {
        if (l.retired) continue;
        if ((l.tlsNames ?? []).some((x) => x.name === n && x.status === 'active')) {
          await assertNoRotationOrQuarantine(ctx.db, relay);
          touched.push({ relay, listener: l });
        }
      }
    }
    let count = 0;
    for (const { relay, listener } of touched) {
      count += (
        await retireOn(ctx, listener, relay, new Set([n]), 'admin', now, edgeMs.sniDrain(cfg))
      ).length;
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.name.retire',
      targetType: 'relay_listener',
      payload: { count, everywhere: true },
    });
    return { ok: true as const, retired: count, listeners: touched.length };
  },
});

export const reactivateName = internalMutation({
  args: {
    id: v.id('relayListeners'),
    names: v.array(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, names, actorAdminId }) => {
    // Reactivating a name is new configuration, not unwinding: refused while frozen
    // (retiring one stays admitted).
    await assertAdmission(ctx.db, 'registration');
    const l = await ctx.db.get(id);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await assertNoRotationOrQuarantine(ctx.db, relay);
    const targets = new Set(names.map(normalizeName).filter((n): n is string => !!n));
    let count = 0;
    const next = (l.tlsNames ?? []).map((n) => {
      if (targets.has(n.name) && n.status === 'retired') {
        count++;
        return { name: n.name, status: 'active' as const };
      }
      return n;
    });
    if (count > 0) {
      await ctx.db.patch(id, { tlsNames: next, revision: l.revision + 1, updatedAt: Date.now() });
      await bumpEpochAndRefresh(ctx, relay);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.name.reactivate',
      targetType: 'relay_listener',
      targetId: id,
      payload: { relaySlug: relay.slug, listenerKey: l.listenerKey, count },
    });
    return { ok: true as const, reactivated: count };
  },
});

/**
 * Choose how this listener picks one server name per subscriber. `hrw1` is
 * what a listener whose name list is meant to GROW needs (the legacy PRF
 * reshuffles nearly everyone when a name is appended); `null` returns to the
 * legacy PRF. Switching moves subscribers to a different one of the names the
 * node already accepts, so connectivity is unaffected, but every member gets a
 * changed config at their next refresh: it is an explicit, audited operator
 * action and never a side effect. Not a material change (nothing about the
 * path, the keys or the accepted names moves), so `revision` is untouched.
 */
export const setSniPick = internalMutation({
  args: {
    id: v.id('relayListeners'),
    version: v.union(v.literal('hrw1'), v.null()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, version, actorAdminId }) => {
    await assertAdmission(ctx.db, 'registration');
    const l = await ctx.db.get(id);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    await assertNoRotationOrQuarantine(ctx.db, relay);
    if (!protocolUsesSni(l))
      throw new ConvexError({
        code: 'conflict',
        message: `listener ${l.listenerKey} presents no server name`,
      });
    const changed = (l.sniPick ?? null) !== version;
    if (changed) {
      await ctx.db.patch(id, {
        sniPick: version ?? undefined,
        namesRevision: (l.namesRevision ?? 0) + 1,
        updatedAt: Date.now(),
      });
      await bumpEpochAndRefresh(ctx, relay);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.listener.sni_pick',
      targetType: 'relay_listener',
      targetId: id,
      payload: { relaySlug: relay.slug, listenerKey: l.listenerKey, version: version ?? 'legacy' },
    });
    return { ok: true as const, changed, sniPick: version };
  },
});

// --- template edge / host bookkeeping used by the rotation machine -------------------------

/** Record which published edge this listener's Host and plans point at. */
export const setTemplateEdge = internalMutation({
  args: { id: v.id('relayListeners'), edgeId: v.union(v.id('edges'), v.null()) },
  handler: async (ctx, { id, edgeId }) => {
    const l = await ctx.db.get(id);
    if (!l) return null;
    await ctx.db.patch(id, { templateEdgeId: edgeId ?? undefined, updatedAt: Date.now() });
    return null;
  },
});
