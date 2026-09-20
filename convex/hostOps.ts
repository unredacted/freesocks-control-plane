/**
 * Backend Host operations for origin listeners whose Hosts FCP owns (hostMode
 * `fcp`), as a PERSISTED STATE MACHINE (`relayListeners.host`, docs/edges.md
 * § "Host ownership"):
 *
 *   absent ─create→ creating ─ok→ present
 *                     └─uncertain→ unresolved ─discover(one match)→ present
 *                                              ─discover(several)→ ambiguous (needs_operator)
 *                                              ─discover(none, settled)→ absent (a create may run again)
 *   present ─delete→ deleting ─read-back gone→ absent
 *                     └─uncertain→ unresolved ─discover→ present | absent
 *
 * Rules:
 *  - the INTENDED tuple (remark, address, port, sni, host, transport uuid) is
 *    persisted BEFORE any call, and discovery matches a Host on remark AND
 *    transport uuid AND address:port, never remark alone;
 *  - after an uncertain CREATE an empty listing never authorises a retry: the
 *    op stays `unresolved` until the backend's settle floor passed AND two
 *    quiet looks were taken (`discoverySettleMs`-style), only then `absent`;
 *  - finding one matching Host settles a create; it never confirms a delete:
 *    a delete is confirmed only by a read-back in which the uuid is gone;
 *  - an expired, unsettled op blocks further Host writes for the listener
 *    (`edge.host_op_unsettled`) until re-observed;
 *  - an `adopted` Host (the operator's) is never deleted by FCP.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import { sameAddress } from './lib/edges/hosts';
import type { BackendHost } from './lib/backends/types';
import { hostSniOf, listenerRemark } from './relayListeners';

/** How long a Host op claim lives before it counts as unsettled (shared with the hide ledger). */
export const HOST_OP_TTL_MS = 60_000;
/** Quiet looks + wall clock a listing must show nothing before a create is `absent` again. */
export const HOST_SETTLE_LOOKS = 2;
export const HOST_SETTLE_MS = 2 * 60_000;

export type HostState = NonNullable<Doc<'relayListeners'>['host']>;
export type HostIntent = NonNullable<HostState['intended']>;

export interface HostTargetInput {
  address: string;
  port: number;
  sni: string | null;
  host: string | null;
}

const targetValidator = v.object({
  address: v.string(),
  port: v.number(),
  sni: v.union(v.string(), v.null()),
  host: v.union(v.string(), v.null()),
});

function sameOptional(a: string | null | undefined, b: string | null | undefined): boolean {
  const n = (x: string | null | undefined) =>
    x === undefined || x === null || x === '' ? null : x.trim().toLowerCase();
  return n(a) === n(b);
}

/** A live Host is the intended one when remark, transport AND address:port agree. */
export function matchesIntent(h: BackendHost, intent: HostIntent): boolean {
  return (
    h.remark === intent.remark &&
    (h.inbound?.configProfileInboundUuid ?? '').toLowerCase() ===
      intent.inboundUuid.toLowerCase() &&
    sameAddress(h.address, intent.address) &&
    h.port === intent.port
  );
}

/** Whether a present Host is at the intended tuple (sni/host too). */
export function atIntent(h: BackendHost, intent: HostIntent): boolean {
  return (
    matchesIntent(h, intent) && sameOptional(h.sni, intent.sni) && sameOptional(h.host, intent.host)
  );
}

// --- isolate half: claims and state transitions ------------------------------------------------

export const context = internalQuery({
  args: { listenerId: v.id('relayListeners') },
  handler: async (ctx, { listenerId }) => {
    const l = await ctx.db.get(listenerId);
    if (!l) return null;
    const relay = await ctx.db.get(l.relayId);
    if (!relay) return null;
    return { listener: l, relay };
  },
});

/**
 * Claim a create: persist the intent + op BEFORE any call. Refused while an
 * unsettled op exists (expired or not: `edge.host_op_unsettled`), while a Host
 * is already present (`present`), or while the state is `ambiguous`.
 */
export const claimCreate = internalMutation({
  args: { listenerId: v.id('relayListeners'), target: targetValidator },
  handler: async (ctx, { listenerId, target }) => {
    const l = await ctx.db.get(listenerId);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay || relay.hostMode !== 'fcp')
      throw new ConvexError({
        code: 'edge.host_mode_unsupported',
        message: 'FCP does not own this origin’s Hosts',
      });
    const remark = listenerRemark(l);
    if (!remark || !l.panelBinding)
      throw new ConvexError({
        code: 'edge.host_not_applicable',
        message: 'listener has no backend Host',
      });
    const st = l.host ?? { state: 'absent' as const };
    if (st.state === 'present' && st.uuid)
      return { claimed: false as const, state: 'present' as const, uuid: st.uuid };
    if (st.state === 'ambiguous') return { claimed: false as const, state: 'ambiguous' as const };
    if (st.op) {
      // Unsettled: expired or not, nothing else may write until it is re-observed.
      return { claimed: false as const, state: 'unresolved' as const, opId: st.op.opId };
    }
    if (st.state === 'unresolved' || st.state === 'creating' || st.state === 'deleting')
      return { claimed: false as const, state: 'unresolved' as const };
    const now = Date.now();
    const intended: HostIntent = {
      remark,
      address: target.address,
      port: target.port,
      sni: target.sni,
      host: target.host,
      inboundUuid: l.panelBinding.configProfileInboundUuid,
    };
    const opId = randomHex(8);
    await ctx.db.patch(listenerId, {
      host: {
        state: 'creating',
        ownership: 'fcp',
        intended,
        op: { kind: 'create', opId, claimedAt: now, expiresAt: now + HOST_OP_TTL_MS, attempts: 1 },
      },
      updatedAt: now,
    });
    return { claimed: true as const, opId, intended, backendServerId: relay.backendServerId! };
  },
});

/** The create call answered with a uuid: present. */
export const settleCreated = internalMutation({
  args: { listenerId: v.id('relayListeners'), opId: v.string(), uuid: v.string() },
  handler: async (ctx, { listenerId, opId, uuid }) => {
    const l = await ctx.db.get(listenerId);
    if (!l?.host || l.host.op?.opId !== opId) return { ok: false as const };
    const relay = await ctx.db.get(l.relayId);
    await ctx.db.patch(listenerId, {
      host: { ...l.host, state: 'present', uuid, ownership: 'fcp', op: undefined },
      updatedAt: Date.now(),
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.host.created',
      targetType: 'relay_listener',
      targetId: listenerId,
      payload: { relaySlug: relay?.slug ?? '', listenerKey: l.listenerKey },
    });
    return { ok: true as const };
  },
});

/**
 * Re-observe a Host the ledger calls `present` against the live listing. The
 * backend is the truth: a Host deleted or lost there must not be reported present
 * from the database (a rotation would confirm an EMPTY plan and finish with no
 * Host pointing members at the published edge). Outcomes:
 *  - the uuid is listed → present;
 *  - the uuid is gone but exactly ONE Host carries the listener's remark and
 *    transport → that Host takes its place (re-created out of band);
 *  - several such Hosts → ambiguous (an operator decides);
 *  - none → absent, audited `origin.host.lost`, and a create may run.
 */
export const reobservePresent = internalMutation({
  args: {
    listenerId: v.id('relayListeners'),
    uuid: v.string(),
    hosts: v.array(
      v.object({
        uuid: v.string(),
        remark: v.string(),
        address: v.string(),
        port: v.number(),
        sni: v.optional(v.union(v.string(), v.null())),
        host: v.optional(v.union(v.string(), v.null())),
        inboundUuid: v.optional(v.union(v.string(), v.null())),
      }),
    ),
  },
  handler: async (ctx, { listenerId, uuid, hosts }) => {
    const l = await ctx.db.get(listenerId);
    // The state moved since the caller read it: report what is there now.
    if (!l?.host || l.host.state !== 'present' || l.host.uuid !== uuid || l.host.op)
      return { state: l?.host?.state ?? ('absent' as const), uuid: l?.host?.uuid };
    if (hosts.some((h) => h.uuid === uuid)) return { state: 'present' as const, uuid };
    const remark = listenerRemark(l);
    const inbound = l.panelBinding?.configProfileInboundUuid.toLowerCase();
    const same = hosts.filter(
      (h) => h.remark === remark && (h.inboundUuid ?? '').toLowerCase() === inbound,
    );
    const relay = await ctx.db.get(l.relayId);
    const now = Date.now();
    if (same.length === 1) {
      await ctx.db.patch(listenerId, {
        host: { ...l.host, uuid: same[0].uuid },
        updatedAt: now,
      });
      return { state: 'present' as const, uuid: same[0].uuid };
    }
    if (same.length > 1) {
      await ctx.db.patch(listenerId, {
        host: { ...l.host, state: 'ambiguous', uuid: undefined },
        updatedAt: now,
      });
      return { state: 'ambiguous' as const, uuid: undefined };
    }
    await ctx.db.patch(listenerId, {
      host: { state: 'absent', intended: l.host.intended },
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'relay.host.lost',
      targetType: 'relay_listener',
      targetId: listenerId,
      payload: { relaySlug: relay?.slug ?? '', listenerKey: l.listenerKey },
    });
    return { state: 'absent' as const, uuid: undefined };
  },
});

/** The call's outcome is unknown: park as unresolved, keep the op (fenced by opId). */
export const markUnresolved = internalMutation({
  args: { listenerId: v.id('relayListeners'), opId: v.string() },
  handler: async (ctx, { listenerId, opId }) => {
    const l = await ctx.db.get(listenerId);
    if (!l?.host || l.host.op?.opId !== opId) return null;
    await ctx.db.patch(listenerId, {
      host: { ...l.host, state: 'unresolved', op: { ...l.host.op, lastLookAt: undefined } },
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * Apply a discovery look at the live Host list to an unresolved op.
 *  - create: one Host matching the intent → present (settles); several →
 *    ambiguous; none → another quiet look, and only after the settle floor
 *    AND enough looks → absent (op cleared, a create may run again).
 *  - delete: the uuid gone → absent (confirmed); still there → present with
 *    the op kept (the delete is re-issued by the next ensure/delete call).
 */
export const applyDiscovery = internalMutation({
  args: {
    listenerId: v.id('relayListeners'),
    opId: v.string(),
    hosts: v.array(
      v.object({
        uuid: v.string(),
        remark: v.string(),
        address: v.string(),
        port: v.number(),
        sni: v.optional(v.union(v.string(), v.null())),
        host: v.optional(v.union(v.string(), v.null())),
        inboundUuid: v.optional(v.union(v.string(), v.null())),
      }),
    ),
  },
  handler: async (ctx, { listenerId, opId, hosts }) => {
    const l = await ctx.db.get(listenerId);
    if (!l?.host?.op || l.host.op.opId !== opId) return { state: l?.host?.state ?? 'absent' };
    const relay = await ctx.db.get(l.relayId);
    const now = Date.now();
    const st = l.host;
    const op = st.op!;
    if (op.kind === 'delete') {
      const stillThere = st.uuid ? hosts.some((h) => h.uuid === st.uuid) : false;
      if (!stillThere) {
        await ctx.db.patch(listenerId, {
          host: {
            state: 'absent',
            ownership: undefined,
            uuid: undefined,
            intended: undefined,
            op: undefined,
          },
          updatedAt: now,
        });
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.host.deleted',
          targetType: 'relay_listener',
          targetId: listenerId,
          payload: { relaySlug: relay?.slug ?? '', listenerKey: l.listenerKey },
        });
        return { state: 'absent' as const };
      }
      await ctx.db.patch(listenerId, {
        host: { ...st, state: 'present', op: { ...op, lastLookAt: now } },
        updatedAt: now,
      });
      return { state: 'present' as const };
    }
    // create
    const intent = st.intended;
    if (!intent) {
      await ctx.db.patch(listenerId, { host: { state: 'absent' }, updatedAt: now });
      return { state: 'absent' as const };
    }
    const matches = hosts.filter((h) =>
      matchesIntent(
        {
          uuid: h.uuid,
          remark: h.remark,
          address: h.address,
          port: h.port,
          sni: h.sni,
          host: h.host,
          isDisabled: false,
          inbound: h.inboundUuid
            ? { configProfileUuid: '', configProfileInboundUuid: h.inboundUuid }
            : null,
        },
        intent,
      ),
    );
    if (matches.length === 1) {
      await ctx.db.patch(listenerId, {
        host: { ...st, state: 'present', uuid: matches[0].uuid, ownership: 'fcp', op: undefined },
        updatedAt: now,
      });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.host.created',
        targetType: 'relay_listener',
        targetId: listenerId,
        payload: { relaySlug: relay?.slug ?? '', listenerKey: l.listenerKey, discovered: true },
      });
      return { state: 'present' as const };
    }
    if (matches.length > 1) {
      await ctx.db.patch(listenerId, {
        host: { ...st, state: 'ambiguous', op: undefined },
        updatedAt: now,
      });
      return { state: 'ambiguous' as const };
    }
    // Nothing found: a quiet look. Only after the floor AND enough looks is it absent.
    const looks = (op.attempts ?? 1) > 0 ? (st.op?.lastLookAt ? 2 : 1) : 1;
    const settled = now - op.claimedAt >= HOST_SETTLE_MS && looks >= HOST_SETTLE_LOOKS;
    if (settled) {
      await ctx.db.patch(listenerId, {
        host: {
          state: 'absent',
          ownership: undefined,
          uuid: undefined,
          intended: undefined,
          op: undefined,
        },
        updatedAt: now,
      });
      return { state: 'absent' as const };
    }
    await ctx.db.patch(listenerId, {
      host: { ...st, state: 'unresolved', op: { ...op, lastLookAt: now } },
      updatedAt: now,
    });
    return { state: 'unresolved' as const };
  },
});

/** Claim a delete of an FCP-owned present Host. */
export const claimDelete = internalMutation({
  args: { listenerId: v.id('relayListeners') },
  handler: async (ctx, { listenerId }) => {
    const l = await ctx.db.get(listenerId);
    if (!l?.host) return { claimed: false as const, state: 'absent' as const };
    const relay = await ctx.db.get(l.relayId);
    const st = l.host;
    if (st.state === 'absent') return { claimed: false as const, state: 'absent' as const };
    if (st.ownership === 'adopted') {
      // The operator's Host: released, never deleted.
      await ctx.db.patch(listenerId, { host: { state: 'absent' }, updatedAt: Date.now() });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'relay.host.released',
        targetType: 'relay_listener',
        targetId: listenerId,
        payload: { relaySlug: relay?.slug ?? '', listenerKey: l.listenerKey },
      });
      return { claimed: false as const, state: 'absent' as const };
    }
    if (st.op && st.op.kind === 'create')
      return { claimed: false as const, state: 'unresolved' as const };
    if (!st.uuid) return { claimed: false as const, state: st.state };
    const now = Date.now();
    const opId = randomHex(8);
    await ctx.db.patch(listenerId, {
      host: {
        ...st,
        state: 'deleting',
        op: {
          kind: 'delete',
          opId,
          claimedAt: now,
          expiresAt: now + HOST_OP_TTL_MS,
          attempts: (st.op?.attempts ?? 0) + 1,
        },
      },
      updatedAt: now,
    });
    return {
      claimed: true as const,
      opId,
      uuid: st.uuid,
      backendServerId: relay?.backendServerId ?? null,
    };
  },
});

// --- Node half: the calls ------------------------------------------------------------------------

async function listPanelHosts(ctx: ActionCtx, backendServerId: Id<'backendServers'>) {
  const hosts: BackendHost[] = await ctx.runAction(internal.backends.listHosts, {
    backendServerId,
  });
  return hosts.map((h) => ({
    uuid: h.uuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni ?? null,
    host: h.host ?? null,
    inboundUuid: h.inbound?.configProfileInboundUuid ?? null,
  }));
}

export interface EnsureResult {
  state: 'present' | 'creating' | 'unresolved' | 'ambiguous' | 'failed';
  uuid?: string;
  detail?: string;
}

/**
 * Make sure the listener's Host exists at `target`: returns `present` (+uuid)
 * when it does, runs a create when the state allows one, discovers after an
 * uncertain outcome. Never creates while an op is unsettled.
 */
export const ensureListenerHost = internalAction({
  args: { listenerId: v.id('relayListeners'), target: targetValidator },
  handler: async (ctx, { listenerId, target }): Promise<EnsureResult> => {
    const c = await ctx.runQuery(internal.hostOps.context, { listenerId });
    if (!c) return { state: 'failed', detail: 'listener_missing' };
    const serverId = c.relay.backendServerId;
    if (!serverId) return { state: 'failed', detail: 'no_panel' };
    // An unsettled op is re-observed first.
    if (c.listener.host?.op) {
      const hosts = await listPanelHosts(ctx, serverId);
      const r = await ctx.runMutation(internal.hostOps.applyDiscovery, {
        listenerId,
        opId: c.listener.host.op.opId,
        hosts,
      });
      if (r.state === 'present') {
        const again = await ctx.runQuery(internal.hostOps.context, { listenerId });
        return { state: 'present', uuid: again?.listener.host?.uuid };
      }
      return { state: r.state === 'absent' ? 'creating' : (r.state as EnsureResult['state']) };
    }
    // A Host the ledger calls present is verified against the backend before it
    // is accepted: never `present` from the database alone.
    const known = c.listener.host;
    if (known?.state === 'present' && known.uuid) {
      let hosts: Awaited<ReturnType<typeof listPanelHosts>>;
      try {
        hosts = await listPanelHosts(ctx, serverId);
      } catch (err) {
        // Unknown is not present: the caller retries instead of confirming blind.
        return { state: 'unresolved', detail: err instanceof Error ? err.name : 'error' };
      }
      const seen = await ctx.runMutation(internal.hostOps.reobservePresent, {
        listenerId,
        uuid: known.uuid,
        hosts,
      });
      if (seen.state === 'present') return { state: 'present', uuid: seen.uuid };
      if (seen.state !== 'absent') return { state: seen.state as EnsureResult['state'] };
      // absent: fall through to a fresh create.
    }
    const claim = await ctx.runMutation(internal.hostOps.claimCreate, { listenerId, target });
    if (!claim.claimed) {
      if (claim.state === 'present') return { state: 'present', uuid: claim.uuid };
      return { state: claim.state as EnsureResult['state'] };
    }
    try {
      const { uuid } = await ctx.runAction(internal.backends.createHost, {
        backendServerId: claim.backendServerId,
        remark: claim.intended.remark,
        address: claim.intended.address,
        port: claim.intended.port,
        sni: claim.intended.sni,
        host: claim.intended.host,
        inbound: {
          configProfileUuid: c.listener.panelBinding!.configProfileUuid,
          configProfileInboundUuid: c.listener.panelBinding!.configProfileInboundUuid,
        },
      });
      await ctx.runMutation(internal.hostOps.settleCreated, { listenerId, opId: claim.opId, uuid });
      return { state: 'present', uuid };
    } catch (err) {
      // Unknown outcome: the backend may have created it. Park and discover later.
      await ctx.runMutation(internal.hostOps.markUnresolved, { listenerId, opId: claim.opId });
      return { state: 'unresolved', detail: err instanceof Error ? err.name : 'error' };
    }
  },
});

/**
 * Delete the listener's FCP-owned Host, confirmed ONLY by a read-back in which
 * the uuid is gone. Returns the resulting state.
 */
export const deleteListenerHost = internalAction({
  args: { listenerId: v.id('relayListeners') },
  handler: async (ctx, { listenerId }): Promise<{ state: string }> => {
    const claim = await ctx.runMutation(internal.hostOps.claimDelete, { listenerId });
    if (!claim.claimed) return { state: claim.state };
    if (!claim.backendServerId) return { state: 'failed' };
    try {
      await ctx.runAction(internal.backends.deleteHost, {
        backendServerId: claim.backendServerId,
        uuid: claim.uuid,
      });
    } catch {
      // Uncertain; the read-back below decides.
    }
    const hosts = await listPanelHosts(ctx, claim.backendServerId);
    const r = await ctx.runMutation(internal.hostOps.applyDiscovery, {
      listenerId,
      opId: claim.opId,
      hosts,
    });
    return { state: r.state };
  },
});

/**
 * Reconcile pass: re-observe every unresolved Host op (all origins), delete the
 * FCP-owned Hosts of retired listeners and deleting origins, then the
 * direct-Host ledger (convex/edgeHostHides.ts): settle its unsettled rows by
 * observation and re-observe the direct Hosts of bound guided origins (a
 * reappeared covered / approved one is re-hidden, any other raises attention
 * `direct_host_reappeared`; both suppressed while a restore workflow runs).
 */
// --- the Host follows its server name -------------------------------------------------------------

/**
 * What a resync would write: only for an FCP-owned Host that is settled
 * (`present`, no op in flight) whose recorded server name is no longer the one
 * the listener would choose (`hostSniOf`). A Host mid-create or mid-delete is
 * left to its own machine; a rotation writes the new tuple by itself.
 */
export const resyncSniContext = internalQuery({
  args: { listenerId: v.id('relayListeners') },
  handler: async (ctx, { listenerId }) => {
    const l = await ctx.db.get(listenerId);
    if (!l || l.retired) return null;
    const relay = await ctx.db.get(l.relayId);
    if (!relay || relay.hostMode !== 'fcp' || !relay.backendServerId) return null;
    if (relay.activeRotationId || relay.restore || relay.quarantine) return null;
    const host = l.host;
    if (!host || host.state !== 'present' || host.op || !host.uuid || !host.intended) return null;
    const sni = hostSniOf(l);
    if (!sni || host.intended.sni === sni || host.intended.sni === null) return null;
    return {
      backendServerId: relay.backendServerId,
      uuid: host.uuid,
      address: host.intended.address,
      port: host.intended.port,
      sni,
      revision: l.revision,
    };
  },
});

export const recordResyncedSni = internalMutation({
  args: { listenerId: v.id('relayListeners'), uuid: v.string(), sni: v.string() },
  handler: async (ctx, { listenerId, uuid, sni }) => {
    const l = await ctx.db.get(listenerId);
    // Only if the Host is still the one that was written to, and still settled.
    if (!l?.host || l.host.uuid !== uuid || l.host.state !== 'present' || !l.host.intended)
      return null;
    await ctx.db.patch(listenerId, {
      host: { ...l.host, intended: { ...l.host.intended, sni } },
      updatedAt: Date.now(),
    });
    return null;
  },
});

/**
 * The name a listener's backend Host carries was retired: write the listener's
 * next choice onto the Host, address and port unchanged. A member who copies a
 * raw config from the backend gets this name, so it must not stay a retired one.
 * Best effort: a failure leaves the Host as it was, and the next run (a
 * rotation, or the next retire) writes it.
 */
export const resyncSni = internalAction({
  args: { listenerId: v.id('relayListeners') },
  handler: async (ctx, { listenerId }): Promise<{ written: boolean }> => {
    const c = await ctx.runQuery(internal.hostOps.resyncSniContext, { listenerId });
    if (!c) return { written: false };
    try {
      await ctx.runAction(internal.backends.updateHost, {
        backendServerId: c.backendServerId,
        uuid: c.uuid,
        address: c.address,
        port: c.port,
        sni: c.sni,
      });
    } catch {
      return { written: false };
    }
    await ctx.runMutation(internal.hostOps.recordResyncedSni, {
      listenerId,
      uuid: c.uuid,
      sni: c.sni,
    });
    return { written: true };
  },
});

export const reconcileHosts = internalAction({
  args: {},
  handler: async (ctx): Promise<{ looked: number; deleted: number }> => {
    const pending = await ctx.runQuery(internal.hostOps.pendingListeners, {});
    let looked = 0;
    let deleted = 0;
    for (const p of pending) {
      if (p.kind === 'discover') {
        const hosts = await listPanelHosts(ctx, p.backendServerId);
        await ctx.runMutation(internal.hostOps.applyDiscovery, {
          listenerId: p.listenerId,
          opId: p.opId,
          hosts,
        });
        looked++;
      } else {
        const r = await ctx.runAction(internal.hostOps.deleteListenerHost, {
          listenerId: p.listenerId,
        });
        if (r.state === 'absent') deleted++;
      }
    }
    // The direct-Host ledger (its own counters live in its own reports).
    try {
      await ctx.runAction(internal.edgeHostHides.settle, {});
    } catch (err) {
      console.warn(`[edge-reconcile] hide ledger: ${err instanceof Error ? err.name : 'error'}`);
    }
    try {
      await ctx.runAction(internal.edgeHostHides.reobserveDirect, {});
    } catch (err) {
      console.warn(`[edge-reconcile] direct hosts: ${err instanceof Error ? err.name : 'error'}`);
    }
    return { looked, deleted };
  },
});

/** Listeners with an unresolved Host op, or a present FCP Host that must go (retired / origin deleting). */
export const pendingListeners = internalQuery({
  args: {},
  handler: async (ctx) => {
    const out: Array<
      | {
          kind: 'discover';
          listenerId: Id<'relayListeners'>;
          opId: string;
          backendServerId: Id<'backendServers'>;
        }
      | { kind: 'delete'; listenerId: Id<'relayListeners'> }
    > = [];
    const relays = await ctx.db.query('relays').collect(); // small operator table
    for (const relay of relays) {
      if (relay.hostMode !== 'fcp' && !relay.deleting) continue;
      if (!relay.backendServerId) continue;
      const listeners = await ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .collect();
      for (const l of listeners) {
        const st = l.host;
        if (!st) continue;
        if (st.op && Date.now() >= st.op.expiresAt) {
          out.push({
            kind: 'discover',
            listenerId: l._id,
            opId: st.op.opId,
            backendServerId: relay.backendServerId,
          });
          continue;
        }
        if (st.state === 'present' && st.ownership === 'fcp' && (l.retired || relay.deleting))
          out.push({ kind: 'delete', listenerId: l._id });
      }
    }
    return out;
  },
});

// --- operator adoption (hostMode handoff) --------------------------------------------------------

/**
 * Take over an operator-created backend Host for a listener (the `operator` ->
 * `fcp` handoff, docs/edges.md § "Host ownership"). The named Host must exist
 * on the backend, carry the listener's transport uuid AND dial a published edge of
 * that listener (`edge.host_adopt_mismatch` otherwise). Never by remark guessing.
 * Ownership becomes `adopted`; FCP updates it on flips from then on and never
 * deletes it. A Host whose remark differs from the listener's is remembered as
 * a legacy remark so the renderer keeps matching the bodies members already hold.
 */
export const adoptHost = internalMutation({
  args: {
    listenerId: v.id('relayListeners'),
    host: v.object({
      uuid: v.string(),
      remark: v.string(),
      address: v.string(),
      port: v.number(),
      sni: v.union(v.string(), v.null()),
      host: v.union(v.string(), v.null()),
      inboundUuid: v.union(v.string(), v.null()),
    }),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { listenerId, host, actorAdminId }) => {
    const l = await ctx.db.get(listenerId);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const relay = await ctx.db.get(l.relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!l.panelBinding)
      throw new ConvexError({
        code: 'edge.host_not_applicable',
        message: 'listener has no backend transport to adopt a Host for',
      });
    if (l.host?.op)
      throw new ConvexError({
        code: 'edge.host_op_unsettled',
        message: 'a Host operation is still unsettled on this listener',
      });
    if (
      (host.inboundUuid ?? '').toLowerCase() !==
      l.panelBinding.configProfileInboundUuid.toLowerCase()
    )
      throw new ConvexError({
        code: 'edge.host_adopt_mismatch',
        message: 'the Host does not point at this listener’s transport',
      });
    // Dials a published edge of THIS listener.
    let dials: Id<'edges'> | null = null;
    for (const edgeId of relay.publishedEdgeIds) {
      if (!edgeId) continue;
      const e = await ctx.db.get(edgeId);
      if (!e || e.listenerId !== l._id || e.publication !== 'published') continue;
      const addresses = [e.addresses.v4, e.addresses.v6, e.addresses.hostname].filter(
        (x): x is string => !!x,
      );
      const portOk = e.listeners.some((x) => x.edgePort === host.port);
      if (portOk && addresses.some((a) => sameAddress(a, host.address))) {
        dials = e._id;
        break;
      }
    }
    if (!dials)
      throw new ConvexError({
        code: 'edge.host_adopt_mismatch',
        message: 'the Host does not dial a published edge of this listener',
      });
    const now = Date.now();
    const remark = listenerRemark(l);
    const legacy = l.legacyHosts ?? [];
    const addLegacy =
      remark !== null &&
      host.remark !== remark &&
      !legacy.some((h) => h.uuid === host.uuid || h.remark === host.remark);
    await ctx.db.patch(listenerId, {
      host: {
        state: 'present',
        uuid: host.uuid,
        ownership: 'adopted',
        intended: {
          remark: host.remark,
          address: host.address,
          port: host.port,
          sni: host.sni,
          host: host.host,
          inboundUuid: l.panelBinding.configProfileInboundUuid,
        },
        op: undefined,
      },
      ...(addLegacy ? { legacyHosts: [...legacy, { uuid: host.uuid, remark: host.remark }] } : {}),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'relay.host.adopted',
      targetType: 'relay_listener',
      targetId: listenerId,
      payload: { relaySlug: relay.slug, listenerKey: l.listenerKey },
    });
    return {
      ok: true as const,
      listenerKey: l.listenerKey,
      host: { uuid: host.uuid, ownership: 'adopted' as const },
    };
  },
});

/** Look the named Host up on the backend, then adopt it (the CMS action). */
export const adoptListenerHost = internalAction({
  args: {
    relayId: v.id('relays'),
    listenerKey: v.string(),
    hostUuid: v.string(),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (
    ctx,
    { relayId, listenerKey, hostUuid, actorAdminId },
  ): Promise<{
    ok: true;
    listenerKey: string;
    host: { uuid: string; ownership: 'adopted' };
  }> => {
    const relay = await ctx.runQuery(internal.relays.get, { id: relayId });
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    if (!relay.backendServerId)
      throw new ConvexError({
        code: 'edge.host_not_applicable',
        message: 'this origin has no backend',
      });
    const listeners = await ctx.runQuery(internal.relayListeners.listByRelay, { relayId });
    const l = listeners.find((x) => x.listenerKey === listenerKey && !x.retired);
    if (!l) throw new ConvexError({ code: 'not_found', message: 'Listener not found' });
    const hosts = await listPanelHosts(ctx, relay.backendServerId);
    const host = hosts.find((h) => h.uuid === hostUuid.trim());
    if (!host)
      throw new ConvexError({
        code: 'edge.host_not_found',
        message: 'the backend lists no Host with that uuid',
      });
    return await ctx.runMutation(internal.hostOps.adoptHost, {
      listenerId: l.id as Id<'relayListeners'>,
      host,
      ...(actorAdminId ? { actorAdminId } : {}),
    });
  },
});
