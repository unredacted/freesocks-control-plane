/**
 * Server-name rollouts: a family's names go onto its panel inbound, and reach
 * members only after each NODE has proven it accepts them.
 *
 * Order, and why:
 *
 *   ADD     panel first  ->  panel confirmed (a read-back)  ->  per node: an
 *           AUTHENTICATED session with a test link  ->  only then is the name
 *           handed to that node's members.
 *   REMOVE  the reverse: a name leaves the relays first (with its drain), and
 *           stays on the panel for as long as any relay hands it out or it is
 *           still draining (`planAllowlist` retains it); a later rollout drops it.
 *
 * A panel read-back proves the PANEL holds a name. It says nothing about a node
 * (measured: with a node held off the panel, the panel lists the name, a plain
 * TLS handshake with it completes, and no member can connect). So acceptance is
 * a RECEIPT: an operator connects through one of the node's verified edges with
 * an isolated test link that presents the name. One receipt proves that name on
 * that node. If the name is a WITNESS (this inbound has never listed it
 * before), a node that authenticates it must be running the generation that
 * introduced it, so the same receipt proves the whole generation there.
 *
 * Activation does not move the listener's `revision`: acceptance was proven, so
 * the operator's endpoint confirmation still describes the path (C7 of the
 * design: lib/edges/verification.ts).
 */
import { ConvexError, v } from 'convex/values';
import {
  internalAction,
  internalMutation,
  internalQuery,
  type MutationCtx,
} from './_generated/server';
import { internal } from './_generated/api';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { bumpEpochAndRefresh } from './lib/edges/relayGuards';
import { planAllowlist } from './lib/edges/sni/family';
import { verificationBinding, verificationCurrent } from './lib/edges/verification';
import { resolveSniConfig } from './lib/sniConfig';

const refuse = (code: string, message: string): never => {
  throw new ConvexError({ code, message });
};
const actor = { actorAdminId: v.optional(v.id('adminUsers')) };
const RECEIPT_TTL_MS = 60 * 60_000;

/** Non-retired listeners bound to this inbound, with their relay. */
async function boundListeners(ctx: { db: MutationCtx['db'] }, b: Doc<'sniInboundBindings'>) {
  const relays = await ctx.db
    .query('relays')
    .withIndex('by_backend_server', (q) => q.eq('backendServerId', b.backendServerId))
    .collect();
  const out: { relay: Doc<'relays'>; listener: Doc<'relayListeners'> }[] = [];
  for (const relay of relays) {
    const listeners = await ctx.db
      .query('relayListeners')
      .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
      .collect();
    for (const listener of listeners)
      if (!listener.retired && listener.panelBinding?.configProfileInboundUuid === b.inboundUuid)
        out.push({ relay, listener });
  }
  return out;
}

/** What the next rollout of a binding would write, and what it would add and drop. */
export const plan = internalQuery({
  args: { bindingId: v.id('sniInboundBindings') },
  handler: async (ctx, { bindingId }) => {
    const b = await ctx.db.get(bindingId);
    if (!b) return refuse('not_found', 'No such binding');
    const cfg = await resolveSniConfig(ctx.db);
    if (!cfg.enabled) refuse('edge.sni.disabled', 'Server-name families are switched off');
    const family = await ctx.db.get(b.familyId);
    if (!family || !family.enabled)
      return refuse('edge.sni.disabled', 'This family is switched off');
    const profile = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server_uuid', (q) =>
        q.eq('backendServerId', b.backendServerId).eq('profileUuid', b.profileUuid),
      )
      .unique();
    const onPanel =
      profile?.inbounds.find((i) => i.inboundUuid === b.inboundUuid)?.reality?.serverNames ?? null;
    if (!onPanel)
      return refuse('servers.unknown_inbound', 'The inbound is not on the panel. Refresh Servers');
    const names = await ctx.db
      .query('sniNames')
      .withIndex('by_family_seq', (q) => q.eq('familyId', family._id))
      .collect();
    // A name stays on the panel for as long as a relay hands it out or it is
    // still draining, whoever it belongs to and whatever its family says now.
    const now = Date.now();
    const inUse = new Set<string>();
    for (const { listener } of await boundListeners(ctx as never, b))
      for (const n of listener.tlsNames ?? [])
        if (n.status === 'active' || (n.drainUntil !== undefined && n.drainUntil > now))
          inUse.add(n.name);
    const retained = onPanel.filter((n) => inUse.has(n));
    const planned = planAllowlist(
      names.map((n) => ({
        name: n.name,
        seq: n.seq,
        status: n.status,
        qualified: n.qualification.state === 'ok',
      })),
      retained,
    );
    const before = new Set(onPanel);
    const after = new Set(planned.names);
    const added = planned.names.filter((n) => !before.has(n));
    // A witness has never been listed by this inbound, under any binding.
    let witness: string | undefined;
    for (const name of added) {
      const seen = await ctx.db
        .query('sniInboundNameHistory')
        .withIndex('by_inbound_name', (q) =>
          q
            .eq('backendServerId', b.backendServerId)
            .eq('inboundUuid', b.inboundUuid)
            .eq('name', name),
        )
        .unique();
      if (!seen) {
        witness = name;
        break;
      }
    }
    return {
      backendServerId: b.backendServerId,
      profileUuid: b.profileUuid,
      inboundTag: b.inboundTag,
      generation: b.generation + 1,
      names: planned.names,
      added,
      removed: onPanel.filter((n) => !after.has(n)),
      witness: witness ?? null,
      overflow: planned.overflow,
      changed: added.length > 0 || onPanel.some((n) => !after.has(n)),
    };
  },
});

export const begin = internalMutation({
  args: {
    bindingId: v.id('sniInboundBindings'),
    generation: v.number(),
    names: v.array(v.string()),
    added: v.array(v.string()),
    removed: v.array(v.string()),
    witness: v.optional(v.string()),
    expectedToken: v.string(),
    opId: v.id('panelOps'),
  },
  handler: async (ctx, a) => {
    const b = await ctx.db.get(a.bindingId);
    if (!b) return refuse('not_found', 'No such binding');
    if (a.generation !== b.generation + 1) refuse('conflict', 'Another rollout got there first');
    // A newer generation supersedes whatever was still waiting for proof.
    const earlier = await ctx.db
      .query('sniRollouts')
      .withIndex('by_binding', (q) => q.eq('bindingId', a.bindingId))
      .collect();
    const now = Date.now();
    for (const r of earlier)
      if (r.phase === 'writing' || r.phase === 'panel_confirmed')
        await ctx.db.patch(r._id, { phase: 'superseded', updatedAt: now });
    await ctx.db.patch(b._id, { generation: a.generation, updatedAt: now });
    return ctx.db.insert('sniRollouts', {
      bindingId: a.bindingId,
      backendServerId: b.backendServerId,
      generation: a.generation,
      names: a.names,
      added: a.added,
      removed: a.removed,
      witness: a.witness,
      expectedToken: a.expectedToken,
      opId: a.opId,
      phase: 'writing',
      startedAt: now,
      updatedAt: now,
    });
  },
});

/** Follow the panel op: confirmed when its result was SEEN on the panel, failed when it was refused. */
export const sync = internalMutation({
  args: { rolloutId: v.id('sniRollouts') },
  handler: async (ctx, { rolloutId }) => {
    const r = await ctx.db.get(rolloutId);
    if (!r || r.phase !== 'writing' || !r.opId) return r?.phase ?? null;
    const op = await ctx.db.get(r.opId);
    if (!op) return r.phase;
    const now = Date.now();
    if (op.request === 'rejected_pre_mutation') {
      await ctx.db.patch(r._id, { phase: 'failed', errorCode: op.errorCode, updatedAt: now });
      return 'failed';
    }
    if (op.panelState !== 'observed') return r.phase;
    const b = await ctx.db.get(r.bindingId);
    if (b) {
      await ctx.db.patch(b._id, { panelConfirmedGeneration: r.generation, updatedAt: now });
      // From now on these names HAVE been listed by this inbound.
      for (const name of r.added) {
        const seen = await ctx.db
          .query('sniInboundNameHistory')
          .withIndex('by_inbound_name', (q) =>
            q
              .eq('backendServerId', b.backendServerId)
              .eq('inboundUuid', b.inboundUuid)
              .eq('name', name),
          )
          .unique();
        if (!seen)
          await ctx.db.insert('sniInboundNameHistory', {
            backendServerId: b.backendServerId,
            inboundUuid: b.inboundUuid,
            name,
            firstSeenGeneration: r.generation,
          });
      }
    }
    // The ledger SAW the profile hold this generation's token. Reflect that in
    // the read cache now, rather than at its next scheduled refresh: receipts
    // are checked against it.
    if (b) {
      const cached = await ctx.db
        .query('panelProfiles')
        .withIndex('by_server_uuid', (q) =>
          q.eq('backendServerId', b.backendServerId).eq('profileUuid', b.profileUuid),
        )
        .unique();
      if (cached)
        await ctx.db.patch(cached._id, {
          changeToken: r.expectedToken,
          inbounds: cached.inbounds.map((i) =>
            i.inboundUuid === b.inboundUuid && i.reality
              ? { ...i, reality: { ...i.reality, serverNames: r.names } }
              : i,
          ),
        });
    }
    await ctx.db.patch(r._id, { phase: 'panel_confirmed', updatedAt: now });
    return 'panel_confirmed';
  },
});

/**
 * Push a binding's allowlist: plan, preview against the live panel, claim and
 * write through the operations ledger (the ONE path that may edit a managed
 * inbound), then follow it. Members get nothing from this; see `issueReceipt`.
 */
export const start = internalAction({
  args: { bindingId: v.id('sniInboundBindings'), ...actor },
  handler: async (
    ctx,
    { bindingId, actorAdminId },
  ): Promise<{
    rolloutId: Id<'sniRollouts'> | null;
    phase: string;
    added: number;
    removed: number;
  }> => {
    const p = await ctx.runQuery(internal.sniRollouts.plan, { bindingId });
    if (!p.changed) return { rolloutId: null, phase: 'nothing_to_change', added: 0, removed: 0 };
    const ops = [
      { op: 'setRealityServerNames' as const, inboundTag: p.inboundTag, names: p.names },
    ];
    const preview = await ctx.runAction(internal.panelWrites.previewProfilePatch, {
      backendServerId: p.backendServerId,
      profileUuid: p.profileUuid,
      ops,
    });
    if (!preview.changed)
      return { rolloutId: null, phase: 'nothing_to_change', added: 0, removed: 0 };
    const { opId } = await ctx.runMutation(internal.panelWrites.requestProfilePatch, {
      backendServerId: p.backendServerId,
      profileUuid: p.profileUuid,
      ops,
      baseToken: preview.baseToken,
      expectedToken: preview.expectedToken,
      inboundUuids: preview.inboundUuids,
      sniRollout: true,
      actorAdminId,
    });
    const rolloutId = await ctx.runMutation(internal.sniRollouts.begin, {
      bindingId,
      generation: p.generation,
      names: p.names,
      added: p.added,
      removed: p.removed,
      witness: p.witness ?? undefined,
      expectedToken: preview.expectedToken,
      opId,
    });
    await ctx.runAction(internal.panelWrites.run, { opId });
    const phase = await ctx.runMutation(internal.sniRollouts.sync, { rolloutId });
    return {
      rolloutId,
      phase: phase ?? 'writing',
      added: p.added.length,
      removed: p.removed.length,
    };
  },
});

// --- acceptance ------------------------------------------------------------------------------------------

/** Validate a receipt request and answer what the test link must present. */
export const receiptContext = internalQuery({
  args: { rolloutId: v.id('sniRollouts'), edgeId: v.id('edges'), sni: v.optional(v.string()) },
  handler: async (ctx, { rolloutId, edgeId, sni }) => {
    const r = await ctx.db.get(rolloutId);
    if (!r) return refuse('not_found', 'No such rollout');
    if (r.phase !== 'panel_confirmed')
      refuse(
        'edge.sni.rollout_not_confirmed',
        'The panel has not been seen to hold these names yet',
      );
    const b = await ctx.db.get(r.bindingId);
    if (!b || b.generation !== r.generation)
      return refuse('edge.sni.superseded', 'A newer rollout replaced this one');
    const edge = await ctx.db.get(edgeId);
    const listener = edge ? await ctx.db.get(edge.listenerId) : null;
    if (!edge || !listener) return refuse('not_found', 'Edge not found');
    if (listener.panelBinding?.configProfileInboundUuid !== b.inboundUuid)
      refuse('validation', 'That edge does not front this inbound');
    // The proof rides on an endpoint an operator already confirmed: an
    // untested edge would make a failure ambiguous (the name, or the path?).
    if (!verificationCurrent(edge, listener))
      refuse(
        'edge.unverified_endpoint',
        'Test this address first, then prove the names through it',
      );
    const name = sni ?? r.witness ?? r.added[0];
    if (!name || !r.names.includes(name))
      return refuse('validation', 'That name is not part of this rollout');
    const binding = verificationBinding(edge, listener)!;
    return {
      sni: name,
      isWitness: name === r.witness,
      generation: r.generation,
      expectedToken: r.expectedToken,
      relayId: edge.relayId,
      listenerId: listener._id,
      binding,
    };
  },
});

export const recordReceipt = internalMutation({
  args: {
    rolloutId: v.id('sniRollouts'),
    generation: v.number(),
    relayId: v.id('relays'),
    listenerId: v.id('relayListeners'),
    edgeId: v.id('edges'),
    sni: v.string(),
    isWitness: v.boolean(),
    expectedToken: v.string(),
    endpoint: v.string(),
    listenerRevision: v.number(),
    configHash: v.string(),
    ...actor,
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    return ctx.db.insert('sniAcceptanceReceipts', {
      ...a,
      evidenceKind: 'operator_test_link',
      state: 'issued',
      issuedAt: now,
      expiresAt: now + RECEIPT_TTL_MS,
    });
  },
});

/** A test link presenting ONE name of the rollout, and the receipt that waits for the operator's tick. */
export const issueReceipt = internalAction({
  args: {
    rolloutId: v.id('sniRollouts'),
    edgeId: v.id('edges'),
    sni: v.optional(v.string()),
    ...actor,
  },
  handler: async (
    ctx,
    a,
  ): Promise<{
    receiptId: Id<'sniAcceptanceReceipts'>;
    link: string;
    sni: string;
    isWitness: boolean;
  }> => {
    const c = await ctx.runQuery(internal.sniRollouts.receiptContext, {
      rolloutId: a.rolloutId,
      edgeId: a.edgeId,
      sni: a.sni,
    });
    const built = await ctx.runAction(internal.edgeTestLinks.build, {
      edgeId: a.edgeId,
      candidateSni: c.sni,
    });
    const receiptId = await ctx.runMutation(internal.sniRollouts.recordReceipt, {
      rolloutId: a.rolloutId,
      generation: c.generation,
      relayId: c.relayId,
      listenerId: c.listenerId,
      edgeId: a.edgeId,
      sni: c.sni,
      isWitness: c.isWitness,
      expectedToken: c.expectedToken,
      endpoint: c.binding.endpoint,
      listenerRevision: c.binding.listenerRevision,
      configHash: c.binding.configHash,
      actorAdminId: a.actorAdminId,
    });
    return { receiptId, link: built.link, sni: c.sni, isWitness: c.isWitness };
  },
});

/**
 * The operator connected with the test link. Everything the receipt is bound to
 * is derived again from the live rows; any difference voids it. Then the name
 * (or, for a witness, every name of the generation) is handed to THIS node's
 * members, and only this node's.
 */
export const confirmReceipt = internalMutation({
  args: { receiptId: v.id('sniAcceptanceReceipts'), ...actor },
  handler: async (ctx, { receiptId, actorAdminId }) => {
    const rc = await ctx.db.get(receiptId);
    if (!rc) return refuse('not_found', 'No such receipt');
    if (rc.state !== 'issued') refuse('conflict', 'This test link was already used or has lapsed');
    const now = Date.now();
    const voidAs = async (state: 'expired' | 'superseded', code: string, message: string) => {
      await ctx.db.patch(rc._id, { state });
      return refuse(code, message);
    };
    if (now > rc.expiresAt)
      return voidAs('expired', 'edge.sni.receipt_expired', 'This test link lapsed. Get a new one');
    const r = await ctx.db.get(rc.rolloutId);
    const b = r ? await ctx.db.get(r.bindingId) : null;
    if (!r || !b || r.phase !== 'panel_confirmed' || b.generation !== rc.generation)
      return voidAs('superseded', 'edge.sni.superseded', 'A newer rollout replaced this one');
    // The panel must still hold exactly the config this generation wrote.
    const profile = await ctx.db
      .query('panelProfiles')
      .withIndex('by_server_uuid', (q) =>
        q.eq('backendServerId', b.backendServerId).eq('profileUuid', b.profileUuid),
      )
      .unique();
    if (!profile || profile.changeToken !== rc.expectedToken)
      return voidAs(
        'superseded',
        'edge.sni.profile_moved',
        'The profile changed since this rollout. Roll out again',
      );
    const edge = await ctx.db.get(rc.edgeId);
    const listener = await ctx.db.get(rc.listenerId);
    const relay = await ctx.db.get(rc.relayId);
    if (!edge || !listener || !relay || listener.retired)
      return voidAs('superseded', 'edge.sni.binding_changed', 'The edge or its listener changed');
    const live = verificationBinding(edge, listener);
    if (
      !live ||
      !verificationCurrent(edge, listener) ||
      live.endpoint !== rc.endpoint ||
      live.listenerRevision !== rc.listenerRevision ||
      live.configHash !== rc.configHash
    )
      return voidAs(
        'superseded',
        'edge.sni.binding_changed',
        'The address changed since the link was made',
      );

    // What this proof covers: the one name, or for a witness the generation.
    const family = await ctx.db
      .query('sniNames')
      .withIndex('by_family_seq', (q) => q.eq('familyId', b.familyId))
      .collect();
    const usable = new Set(
      family
        .filter((n) => n.status === 'active' && n.qualification.state === 'ok')
        .map((n) => n.name),
    );
    const proven = (rc.isWitness ? r.names : [rc.sni]).filter((n) => usable.has(n));
    const existing = listener.tlsNames ?? [];
    const next = existing.map((n) =>
      proven.includes(n.name) && n.status !== 'active'
        ? { name: n.name, status: 'active' as const, origin: 'family' as const }
        : n,
    );
    const have = new Set(existing.map((n) => n.name));
    // Appended in the rollout's own order, never re-sorted.
    for (const name of proven)
      if (!have.has(name)) next.push({ name, status: 'active', origin: 'family' });
    const wasActive = new Set(existing.filter((n) => n.status === 'active').map((n) => n.name));
    const activated = proven.filter((n) => !wasActive.has(n)).length;
    await ctx.db.patch(listener._id, {
      tlsNames: next,
      // A growing list needs the growth-stable selection.
      sniPick: 'hrw1',
      namesRevision: (listener.namesRevision ?? 0) + 1,
      updatedAt: now,
    });
    await ctx.db.patch(rc._id, { state: 'confirmed', confirmedAt: now, actorAdminId });
    if (activated > 0) await bumpEpochAndRefresh(ctx, relay);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'edge.sni.names.accepted',
      targetType: 'relay_listener',
      targetId: listener._id,
      payload: {
        relaySlug: relay.slug,
        listenerKey: listener.listenerKey,
        generation: rc.generation,
        count: activated,
        witness: rc.isWitness,
      },
    });
    return { ok: true as const, activated, witness: rc.isWitness };
  },
});

/** Where a rollout stands, node by node. */
export const status = internalQuery({
  args: { rolloutId: v.id('sniRollouts') },
  handler: async (ctx, { rolloutId }) => {
    const r = await ctx.db.get(rolloutId);
    if (!r) return refuse('not_found', 'No such rollout');
    const b = await ctx.db.get(r.bindingId);
    const receipts = await ctx.db
      .query('sniAcceptanceReceipts')
      .withIndex('by_rollout', (q) => q.eq('rolloutId', rolloutId))
      .collect();
    const nodes = b
      ? (await boundListeners(ctx as never, b)).map(({ relay, listener }) => {
          const active = new Set(
            (listener.tlsNames ?? []).filter((n) => n.status === 'active').map((n) => n.name),
          );
          return {
            relaySlug: relay.slug,
            listenerKey: listener.listenerKey,
            proven: r.names.filter((n) => active.has(n)).length,
            pending: r.names.filter((n) => !active.has(n)).length,
            generationProven: receipts.some(
              (x) => x.listenerId === listener._id && x.state === 'confirmed' && x.isWitness,
            ),
          };
        })
      : [];
    return {
      id: r._id as string,
      generation: r.generation,
      phase: r.phase,
      errorCode: r.errorCode ?? null,
      added: r.added.length,
      removed: r.removed.length,
      hasWitness: !!r.witness,
      nodes,
    };
  },
});
