/**
 * The direct-Host hide LEDGER (docs/edges.md § "Direct-Host hides and the
 * restore workflow"): a guided setup hides a node's direct Hosts (the panel
 * entries that still hand the node's own address to members) once its edges
 * serve, so that from then on members depend on the edge; the restore workflow
 * (convex/edgeRestore.ts) re-enables them.
 *
 * Protocol per Host (the row exists BEFORE every write):
 *
 *   re-observe (listHosts) -> row `intended` {observed tuple, opId, lease}
 *   -> backends.setHostDisabled(uuid, true) -> `written`
 *   -> read-back isDisabled === true -> `confirmed`
 *
 * A row that holds an `opId` is POSSIBLY written (the call may have reached
 * the panel) and is settled only by observation: disabled -> `confirmed`;
 * gone -> `released`; still enabled -> `unresolved`, and only after the settle
 * floor (`HOST_SETTLE_MS`) AND two quiet looks (`HOST_SETTLE_LOOKS`) have
 * passed since the lease expired is it settled: RELEASED inside a restore
 * workflow (nothing was written, nothing is reversed), RETRIED by the reconcile
 * pass otherwise (bounded by `HIDE_MAX_ATTEMPTS`; then `failed`). A lease
 * expiry alone never releases or reverses anything; a disable that lands late
 * is caught by the next look. No opposing write is issued while any row of the
 * relay is unsettled.
 *
 * Every direct-Host write on a relay is refused while `relays.restore` is set.
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx, DatabaseReader } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import { randomHex } from './lib/crypto';
import type { BackendHost } from './lib/backends/types';
import {
  classifyDirectHosts,
  isDirectHost,
  listingHash,
  observedTuple,
  sameTuple,
  toDirectHost,
  type DirectHost,
  type DirectHostContext,
} from './lib/edges/directHosts';
import { relayRemarkRegex, sameAddress } from './lib/edges/hosts';
import { deliveryBindingFor } from './relays';
import { listenerRemark, listenersOf } from './relayListeners';
import { HOST_OP_TTL_MS, HOST_SETTLE_LOOKS, HOST_SETTLE_MS } from './hostOps';

/** Disable retries the reconcile pass issues for one Host before it counts as failed. */
export const HIDE_MAX_ATTEMPTS = 6;

export type HideRow = Doc<'edgeHostHides'>;

const UNSETTLED = new Set<HideRow['state']>(['intended', 'written', 'unresolved']);

export function isUnsettled(row: Pick<HideRow, 'state' | 'opId'>): boolean {
  return UNSETTLED.has(row.state);
}

const observedValidator = v.object({
  remark: v.string(),
  address: v.string(),
  port: v.number(),
  sni: v.union(v.string(), v.null()),
  host: v.union(v.string(), v.null()),
  inboundUuid: v.union(v.string(), v.null()),
  isDisabled: v.boolean(),
});

const liveHostValidator = v.object({
  uuid: v.string(),
  remark: v.string(),
  address: v.string(),
  port: v.number(),
  sni: v.optional(v.union(v.string(), v.null())),
  host: v.optional(v.union(v.string(), v.null())),
  isDisabled: v.boolean(),
  inbound: v.optional(
    v.union(
      v.object({ configProfileUuid: v.string(), configProfileInboundUuid: v.string() }),
      v.null(),
    ),
  ),
});

// --- the pure judgement of one look -----------------------------------------------------------

export type LookMode = 'readback' | 'settle' | 'reconcile';

export interface LookVerdict {
  /** The state to persist (null = nothing changes). */
  state: HideRow['state'] | null;
  releasedReason?: string;
  /** Quiet looks after the lease expired, when the row stays unsettled. */
  quietLooks?: number;
  /** The caller should re-issue the write (a new claim on the same row). */
  retry: boolean;
}

/**
 * What one observation of the live Host means for a row.
 *  - a `disable` row: disabled -> confirmed; gone -> released; enabled -> wait
 *    until the lease expired, then quiet looks, then (settled) released in a
 *    restore workflow (`settle`) or retried by the reconcile pass;
 *  - a `restore` row: enabled -> released (`restored`); gone -> released;
 *    disabled -> wait, then settled -> retried (the enable is re-issued).
 * `readback` is the look taken right after the write: it never settles.
 */
export function judgeLook(
  row: Pick<HideRow, 'intent' | 'state' | 'opId' | 'expiresAt' | 'quietLooks' | 'attempt'>,
  live: { isDisabled: boolean } | null,
  now: number,
  mode: LookMode,
): LookVerdict {
  if (row.state === 'confirmed' || row.state === 'released') return { state: null, retry: false };
  if (!live) return { state: 'released', releasedReason: 'gone', retry: false };
  const wanted = row.intent === 'disable';
  if (live.isDisabled === wanted) {
    return wanted
      ? { state: 'confirmed', retry: false }
      : { state: 'released', releasedReason: 'restored', retry: false };
  }
  // The Host is not in the wanted state.
  if (!row.opId) return { state: 'released', releasedReason: 'never_written', retry: false };
  const expiresAt = row.expiresAt ?? 0;
  if (mode === 'readback' || now < expiresAt) return { state: null, retry: false };
  // The lease expired: a quiet look. Settled only past the floor AND enough looks.
  const quietLooks = (row.quietLooks ?? 0) + 1;
  const settled = now - expiresAt >= HOST_SETTLE_MS && quietLooks >= HOST_SETTLE_LOOKS;
  if (!settled) return { state: 'unresolved', quietLooks, retry: false };
  if (wanted && mode === 'settle')
    return { state: 'released', releasedReason: 'settled', quietLooks, retry: false };
  // Retry (a disable under reconcile, or an enable in the restore phase).
  if (row.attempt >= HIDE_MAX_ATTEMPTS) return { state: 'unresolved', quietLooks, retry: false };
  return { state: 'unresolved', quietLooks, retry: true };
}

// --- isolate half ------------------------------------------------------------------------------

export interface HideContext {
  relay: Doc<'relays'>;
  backendServerId: Id<'backendServers'>;
  nodeName: string | null;
  /** Deployed, enabled, non-retired listeners with a panel inbound. */
  listenerInboundUuids: string[];
  fcpRemarks: string[];
  legacyHostUuids: string[];
  bound: boolean;
}

async function hideContext(
  ctx: { db: DatabaseReader },
  relay: Doc<'relays'>,
): Promise<HideContext | null> {
  if (!relay.backendServerId) return null;
  const listeners = await listenersOf(ctx, relay._id);
  const live = listeners.filter((l) => !l.retired && l.deployed && l.enabled && l.panelBinding);
  const fcpRemarks = listeners.map((l) => listenerRemark(l)).filter((r): r is string => !!r);
  const legacyHostUuids = listeners.flatMap((l) => (l.legacyHosts ?? []).map((h) => h.uuid));
  const binding = await deliveryBindingFor(
    ctx.db,
    relay.backendServerId,
    relay.nodeName ?? undefined,
  );
  return {
    relay,
    backendServerId: relay.backendServerId,
    nodeName: relay.nodeName ?? null,
    listenerInboundUuids: live.map((l) => l.panelBinding!.configProfileInboundUuid),
    fcpRemarks,
    legacyHostUuids,
    bound: !!binding && binding.relaySlug === relay.slug,
  };
}

export const context = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<HideContext | null> => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    return hideContext(ctx, relay);
  },
});

async function rowsOfRelay(db: DatabaseReader, relayId: Id<'relays'>): Promise<HideRow[]> {
  return db
    .query('edgeHostHides')
    .withIndex('by_relay', (q) => q.eq('relayId', relayId))
    .collect(); // one row per direct Host of one node: operator-scale
}

export interface HideStatus {
  outstanding: number;
  confirmed: number;
  unresolved: number;
  /** Rows at the retry cap and still not in the wanted state. */
  failed: number;
  rows: Array<{
    id: string;
    hostUuid: string;
    remark: string;
    intent: HideRow['intent'];
    state: HideRow['state'];
    attempt: number;
    runId: string | null;
    releasedReason: string | null;
  }>;
}

export async function hideStatusOf(db: DatabaseReader, relayId: Id<'relays'>): Promise<HideStatus> {
  const rows = await rowsOfRelay(db, relayId);
  const disables = rows.filter((r) => r.intent === 'disable');
  return {
    outstanding: rows.filter((r) => isUnsettled(r)).length,
    confirmed: disables.filter((r) => r.state === 'confirmed').length,
    unresolved: rows.filter((r) => r.state === 'unresolved').length,
    failed: rows.filter((r) => isUnsettled(r) && r.attempt >= HIDE_MAX_ATTEMPTS).length,
    rows: rows.map((r) => ({
      id: r._id as string,
      hostUuid: r.hostUuid,
      remark: r.observed.remark,
      intent: r.intent,
      state: r.state,
      attempt: r.attempt,
      runId: r.runId ?? null,
      releasedReason: r.releasedReason ?? null,
    })),
  };
}

export const status = internalQuery({
  args: { relayId: v.id('relays') },
  handler: (ctx, { relayId }): Promise<HideStatus> => hideStatusOf(ctx.db, relayId),
});

/** Rows the settle pass must re-observe, across every relay (or one). */
export const pendingRows = internalQuery({
  args: { relayId: v.optional(v.id('relays')) },
  handler: async (ctx, { relayId }) => {
    const rows = relayId
      ? await rowsOfRelay(ctx.db, relayId)
      : await ctx.db.query('edgeHostHides').collect(); // operator-scale ledger
    const out: Array<{
      rowId: Id<'edgeHostHides'>;
      relayId: Id<'relays'>;
      backendServerId: Id<'backendServers'>;
      inRestore: boolean;
    }> = [];
    const restoreOf = new Map<string, boolean>();
    for (const r of rows) {
      if (!isUnsettled(r)) continue;
      if (!restoreOf.has(r.relayId as string)) {
        const relay = await ctx.db.get(r.relayId);
        restoreOf.set(r.relayId as string, !!relay?.restore);
      }
      out.push({
        rowId: r._id,
        relayId: r.relayId,
        backendServerId: r.backendServerId,
        inRestore: restoreOf.get(r.relayId as string) ?? false,
      });
    }
    return out;
  },
});

/**
 * Claim a write on one Host: insert the `intended` row (or re-claim an
 * unsettled row for a retry) with the observed tuple, an opId and a lease.
 * Refused while the relay's restore workflow runs (for a `disable`), while
 * another row of the same Host on this relay is unsettled, and when a
 * `confirmed` disable already covers it.
 */
export const claim = internalMutation({
  args: {
    relayId: v.id('relays'),
    runId: v.optional(v.string()),
    backendServerId: v.id('backendServers'),
    hostUuid: v.string(),
    observed: observedValidator,
    intent: v.union(v.literal('disable'), v.literal('restore')),
    /** Retry: the unsettled row to re-claim (attempt + 1) instead of inserting. */
    retryRowId: v.optional(v.id('edgeHostHides')),
  },
  handler: async (ctx, a) => {
    const relay = await ctx.db.get(a.relayId);
    if (!relay) return { claimed: false as const, state: 'relay_missing' as const };
    if (a.intent === 'disable' && relay.restore)
      return { claimed: false as const, state: 'restore_in_progress' as const };
    const now = Date.now();
    const opId = randomHex(8);
    if (a.retryRowId) {
      const row = await ctx.db.get(a.retryRowId);
      if (!row || !isUnsettled(row) || row.attempt >= HIDE_MAX_ATTEMPTS)
        return { claimed: false as const, state: (row?.state ?? 'released') as HideRow['state'] };
      await ctx.db.patch(row._id, {
        state: 'intended',
        opId,
        attempt: row.attempt + 1,
        claimedAt: now,
        expiresAt: now + HOST_OP_TTL_MS,
        quietLooks: 0,
        lastLookAt: undefined,
        updatedAt: now,
      });
      return { claimed: true as const, rowId: row._id, opId };
    }
    const rows = (await rowsOfRelay(ctx.db, a.relayId)).filter((r) => r.hostUuid === a.hostUuid);
    const open = rows.find((r) => isUnsettled(r));
    if (open) return { claimed: false as const, state: open.state, rowId: open._id };
    const confirmed = rows.filter((r) => r.intent === 'disable' && r.state === 'confirmed');
    if (a.intent === 'disable' && confirmed.length > 0) {
      // Still disabled: nothing to write. Observed ENABLED again (someone
      // re-enabled it): the old row no longer describes the panel; release it
      // and let a fresh claim record the re-hide.
      if (a.observed.isDisabled) return { claimed: false as const, state: 'confirmed' as const };
      for (const r of confirmed)
        await ctx.db.patch(r._id, {
          state: 'released',
          releasedReason: 'reappeared',
          updatedAt: now,
        });
    }
    const rowId = await ctx.db.insert('edgeHostHides', {
      relayId: a.relayId,
      ...(a.runId ? { runId: a.runId } : {}),
      backendServerId: a.backendServerId,
      hostUuid: a.hostUuid,
      observed: a.observed,
      intent: a.intent,
      state: 'intended',
      opId,
      attempt: 1,
      claimedAt: now,
      expiresAt: now + HOST_OP_TTL_MS,
      quietLooks: 0,
      updatedAt: now,
    });
    return { claimed: true as const, rowId, opId };
  },
});

export const markWritten = internalMutation({
  args: { rowId: v.id('edgeHostHides'), opId: v.string() },
  handler: async (ctx, { rowId, opId }) => {
    const row = await ctx.db.get(rowId);
    if (!row || row.opId !== opId || row.state !== 'intended') return null;
    await ctx.db.patch(rowId, { state: 'written', updatedAt: Date.now() });
    return null;
  },
});

/** The call's outcome is unknown (thrown): the row is possibly written. */
export const markUnresolved = internalMutation({
  args: { rowId: v.id('edgeHostHides'), opId: v.string() },
  handler: async (ctx, { rowId, opId }) => {
    const row = await ctx.db.get(rowId);
    if (!row || row.opId !== opId || !isUnsettled(row)) return null;
    await ctx.db.patch(rowId, { state: 'unresolved', updatedAt: Date.now() });
    return null;
  },
});

/** Apply one look at the live Host (null = gone) to a row; see `judgeLook`. */
export const applyLook = internalMutation({
  args: {
    rowId: v.id('edgeHostHides'),
    live: v.union(liveHostValidator, v.null()),
    mode: v.union(v.literal('readback'), v.literal('settle'), v.literal('reconcile')),
  },
  handler: async (ctx, { rowId, live, mode }) => {
    const row = await ctx.db.get(rowId);
    if (!row) return { state: 'released' as const, retry: false };
    const now = Date.now();
    const verdict = judgeLook(row, live, now, mode);
    const patch: Partial<HideRow> = { lastLookAt: now, updatedAt: now };
    if (verdict.quietLooks !== undefined) patch.quietLooks = verdict.quietLooks;
    if (verdict.state) {
      patch.state = verdict.state;
      if (verdict.state === 'confirmed') patch.confirmedAt = now;
      if (verdict.state === 'released') patch.releasedReason = verdict.releasedReason;
      if (verdict.state === 'confirmed' || verdict.state === 'released') patch.opId = undefined;
    }
    await ctx.db.patch(rowId, patch);
    // A restore that landed (or whose Host is gone) also closes the disable row it reverses.
    if (
      row.intent === 'restore' &&
      verdict.state === 'released' &&
      verdict.releasedReason !== 'settled'
    ) {
      const parents = (await rowsOfRelay(ctx.db, row.relayId)).filter(
        (r) => r.hostUuid === row.hostUuid && r.intent === 'disable' && r.state === 'confirmed',
      );
      for (const p of parents)
        await ctx.db.patch(p._id, {
          state: 'released',
          releasedReason: verdict.releasedReason,
          updatedAt: now,
        });
    }
    return { state: verdict.state ?? row.state, retry: verdict.retry };
  },
});

/** Release a confirmed disable row WITHOUT a write (the administrator changed or removed the Host). */
export const releaseWithoutWrite = internalMutation({
  args: { rowId: v.id('edgeHostHides'), reason: v.string() },
  handler: async (ctx, { rowId, reason }) => {
    const row = await ctx.db.get(rowId);
    if (!row || row.state !== 'confirmed') return null;
    await ctx.db.patch(rowId, {
      state: 'released',
      releasedReason: reason,
      opId: undefined,
      updatedAt: Date.now(),
    });
    return null;
  },
});

export const recordHidden = internalMutation({
  args: {
    relayId: v.id('relays'),
    runId: v.optional(v.string()),
    remarks: v.array(v.string()),
    rehidden: v.optional(v.boolean()),
  },
  handler: async (ctx, { relayId, runId, remarks, rehidden }) => {
    const relay = await ctx.db.get(relayId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.host.hidden',
      targetType: 'relay',
      targetId: relayId,
      payload: {
        relaySlug: relay?.slug ?? '',
        count: remarks.length,
        remarks,
        runId: runId ?? null,
        rehidden: rehidden ?? false,
      },
    });
    return null;
  },
});

export const setDirectHostAlert = internalMutation({
  args: {
    relayId: v.id('relays'),
    hosts: v.array(
      v.object({
        uuid: v.string(),
        remark: v.string(),
        inboundUuid: v.union(v.string(), v.null()),
      }),
    ),
  },
  handler: async (ctx, { relayId, hosts }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) return null;
    const now = Date.now();
    if (hosts.length === 0) {
      if (relay.directHostAlert)
        await ctx.db.patch(relayId, { directHostAlert: undefined, updatedAt: now });
      return null;
    }
    const same =
      relay.directHostAlert &&
      relay.directHostAlert.hosts.length === hosts.length &&
      relay.directHostAlert.hosts.every((h) => hosts.some((x) => x.uuid === h.uuid));
    if (!same) {
      await ctx.db.patch(relayId, { directHostAlert: { at: now, hosts }, updatedAt: now });
      await writeAuditLog(ctx, {
        actorType: 'system',
        action: 'edge.host.reappeared',
        targetType: 'relay',
        targetId: relayId,
        payload: {
          relaySlug: relay.slug,
          count: hosts.length,
          remarks: hosts.map((h) => h.remark),
        },
      });
    }
    return null;
  },
});

/** Relays the reconcile direct-Host check looks at: bound, guided (hide rows), not deleting, no restore. */
export const boundGuidedRelays = internalQuery({
  args: {},
  handler: async (ctx): Promise<Id<'relays'>[]> => {
    const relays = await ctx.db.query('relays').collect(); // small operator table
    const out: Id<'relays'>[] = [];
    for (const relay of relays) {
      if (relay.deleting || relay.restore || !relay.enabled || !relay.backendServerId) continue;
      const anyRow = await ctx.db
        .query('edgeHostHides')
        .withIndex('by_relay', (q) => q.eq('relayId', relay._id))
        .first();
      if (!anyRow) continue;
      const binding = await deliveryBindingFor(
        ctx.db,
        relay.backendServerId,
        relay.nodeName ?? undefined,
      );
      if (!binding || binding.relaySlug !== relay.slug) continue;
      out.push(relay._id);
    }
    return out;
  },
});

// --- Node half: the calls ------------------------------------------------------------------------

export async function listPanelHosts(
  ctx: ActionCtx,
  backendServerId: Id<'backendServers'>,
): Promise<BackendHost[]> {
  return ctx.runAction(internal.backends.listHosts, { backendServerId });
}

function liveOf(h: BackendHost | undefined) {
  if (!h) return null;
  return {
    uuid: h.uuid,
    remark: h.remark,
    address: h.address,
    port: h.port,
    sni: h.sni ?? null,
    host: h.host ?? null,
    isDisabled: h.isDisabled,
    inbound: h.inbound ?? null,
  };
}

/**
 * The node's inbound set for classification: what the caller knows (the plan's
 * discovered inbounds), plus the listeners' own inbounds, plus the inbound of
 * every Host that dials the origin address (the address IS the node, so a Host
 * pointing at it belongs to the node whatever inbound it sits on). No panel
 * inbound discovery is needed here.
 */
function nodeInbounds(
  c: HideContext,
  hosts: readonly BackendHost[],
  known: string[] | undefined,
): string[] {
  const set = new Set(c.listenerInboundUuids.map((u) => u.toLowerCase()));
  if (known) for (const u of known) set.add(u.toLowerCase());
  for (const h of hosts) {
    const inbound = h.inbound?.configProfileInboundUuid;
    if (inbound && sameAddress(h.address, c.relay.originAddress)) set.add(inbound.toLowerCase());
  }
  return [...set];
}

export function directContextOf(
  c: HideContext,
  nodeInboundUuids: string[],
  extraFcpRemarks: string[] = [],
): DirectHostContext {
  return {
    originAddress: c.relay.originAddress,
    nodeInboundUuids,
    fcpRemarks: [...c.fcpRemarks, ...extraFcpRemarks],
    legacyHostUuids: c.legacyHostUuids,
    coveredInboundUuids: c.listenerInboundUuids,
  };
}

/** FCP's relay-convention remarks on this node, from a listing (`<node>-relay-<key>`). */
function conventionRemarks(hosts: readonly BackendHost[], nodeName: string | null): string[] {
  if (!nodeName) return [];
  const re = relayRemarkRegex(nodeName);
  return hosts.map((h) => h.remark).filter((r) => re.test(r));
}

export type WriteOutcome = 'confirmed' | 'pending' | 'failed' | 'skipped';

/**
 * One Host through the protocol: claim -> write -> read-back. `retryRowId`
 * re-claims an unsettled row. Returns what the row is after the read-back.
 */
export async function writeHostBit(
  ctx: ActionCtx,
  a: {
    relayId: Id<'relays'>;
    runId?: string;
    backendServerId: Id<'backendServers'>;
    host: BackendHost;
    intent: 'disable' | 'restore';
    retryRowId?: Id<'edgeHostHides'>;
  },
): Promise<WriteOutcome> {
  const claim = await ctx.runMutation(internal.edgeHostHides.claim, {
    relayId: a.relayId,
    ...(a.runId ? { runId: a.runId } : {}),
    backendServerId: a.backendServerId,
    hostUuid: a.host.uuid,
    observed: observedTuple(a.host),
    intent: a.intent,
    ...(a.retryRowId ? { retryRowId: a.retryRowId } : {}),
  });
  if (!claim.claimed) {
    if (claim.state === 'confirmed') return 'skipped';
    if (claim.state === 'restore_in_progress' || claim.state === 'relay_missing') return 'failed';
    return 'pending';
  }
  try {
    await ctx.runAction(internal.backends.setHostDisabled, {
      backendServerId: a.backendServerId,
      uuid: a.host.uuid,
      disabled: a.intent === 'disable',
    });
    await ctx.runMutation(internal.edgeHostHides.markWritten, {
      rowId: claim.rowId,
      opId: claim.opId,
    });
  } catch {
    await ctx.runMutation(internal.edgeHostHides.markUnresolved, {
      rowId: claim.rowId,
      opId: claim.opId,
    });
  }
  // Read-back: the panel is the truth; the echoed row is never trusted.
  let hosts: BackendHost[];
  try {
    hosts = await listPanelHosts(ctx, a.backendServerId);
  } catch {
    return 'pending';
  }
  const r = await ctx.runMutation(internal.edgeHostHides.applyLook, {
    rowId: claim.rowId,
    live: liveOf(hosts.find((h) => h.uuid === a.host.uuid)),
    mode: 'readback',
  });
  if (a.intent === 'disable') return r.state === 'confirmed' ? 'confirmed' : 'pending';
  return r.state === 'released' ? 'confirmed' : 'pending';
}

export interface HideResult {
  state: 'confirmed' | 'pending' | 'failed';
  hidden: number;
  pending: number;
  failed: number;
  reviewChanged: Array<{ uuid: string; remark: string }>;
}

/**
 * Hide every covered direct Host of the relay's node plus the approved
 * uncovered ones (by uuid). An uncovered Host that is NOT approved is reported
 * in `reviewChanged` and left alone. Refused while a restore workflow runs.
 */
export const hide = internalAction({
  args: {
    relayId: v.id('relays'),
    runId: v.optional(v.string()),
    approvedUuids: v.array(v.string()),
    /** The node's inbound uuids when the caller already discovered them (the plan). */
    nodeInboundUuids: v.optional(v.array(v.string())),
  },
  handler: async (ctx, a): Promise<HideResult> => {
    const c = await ctx.runQuery(internal.edgeHostHides.context, { relayId: a.relayId });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    if (c.relay.restore)
      throw new ConvexError({
        code: 'edge.restore_in_progress',
        message: 'a restore workflow is running on this relay',
      });
    const hosts = await listPanelHosts(ctx, c.backendServerId);
    const inbounds = nodeInbounds(c, hosts, a.nodeInboundUuids);
    const dctx = directContextOf(c, inbounds, conventionRemarks(hosts, c.nodeName));
    const { covered, uncovered } = classifyDirectHosts(hosts, dctx);
    const approved = new Set(a.approvedUuids);
    const targets: DirectHost[] = [...covered, ...uncovered.filter((h) => approved.has(h.uuid))];
    const reviewChanged = uncovered
      .filter((h) => !approved.has(h.uuid))
      .map((h) => ({ uuid: h.uuid, remark: h.remark }));
    let hidden = 0;
    let pending = 0;
    let failed = 0;
    const remarks: string[] = [];
    for (const d of targets) {
      const host = hosts.find((h) => h.uuid === d.uuid)!;
      const out = await writeHostBit(ctx, {
        relayId: a.relayId,
        runId: a.runId,
        backendServerId: c.backendServerId,
        host,
        intent: 'disable',
      });
      if (out === 'confirmed') {
        hidden++;
        remarks.push(d.remark);
      } else if (out === 'pending') pending++;
      else if (out === 'failed') failed++;
    }
    if (remarks.length > 0)
      await ctx.runMutation(internal.edgeHostHides.recordHidden, {
        relayId: a.relayId,
        ...(a.runId ? { runId: a.runId } : {}),
        remarks,
      });
    return {
      state: failed > 0 ? 'failed' : pending > 0 ? 'pending' : 'confirmed',
      hidden,
      pending,
      failed,
      reviewChanged,
    };
  },
});

/**
 * Re-observe every unsettled row (all relays, or one): confirmed / released /
 * a quiet look, and, once settled, a retry (reconcile) or a release (restore).
 */
export const settle = internalAction({
  args: { relayId: v.optional(v.id('relays')) },
  handler: async (
    ctx,
    { relayId },
  ): Promise<{ looked: number; confirmed: number; released: number; retried: number }> => {
    const pending = await ctx.runQuery(internal.edgeHostHides.pendingRows, {
      ...(relayId ? { relayId } : {}),
    });
    const report = { looked: 0, confirmed: 0, released: 0, retried: 0 };
    const listings = new Map<string, BackendHost[]>();
    for (const p of pending) {
      let hosts = listings.get(p.backendServerId as string);
      if (!hosts) {
        try {
          hosts = await listPanelHosts(ctx, p.backendServerId);
        } catch {
          continue; // unknown is not an observation
        }
        listings.set(p.backendServerId as string, hosts);
      }
      const row = await ctx.runQuery(internal.edgeHostHides.row, { rowId: p.rowId });
      if (!row) continue;
      const live = hosts.find((h) => h.uuid === row.hostUuid);
      const r = await ctx.runMutation(internal.edgeHostHides.applyLook, {
        rowId: p.rowId,
        live: liveOf(live),
        mode: p.inRestore ? 'settle' : 'reconcile',
      });
      report.looked++;
      if (r.state === 'confirmed') report.confirmed++;
      if (r.state === 'released') report.released++;
      if (r.retry && live) {
        const out = await writeHostBit(ctx, {
          relayId: p.relayId,
          backendServerId: p.backendServerId,
          host: live,
          intent: row.intent,
          retryRowId: p.rowId,
        });
        report.retried++;
        if (out === 'confirmed') report.confirmed++;
      }
    }
    return report;
  },
});

export const row = internalQuery({
  args: { rowId: v.id('edgeHostHides') },
  handler: (ctx, { rowId }) => ctx.db.get(rowId),
});

/**
 * A fresh listing of this node's direct + FCP Hosts (with `isDisabled`),
 * hashed, for the rehearsal's observation boundary and the run's final look.
 */
export const observe = internalAction({
  args: { relayId: v.id('relays'), nodeInboundUuids: v.optional(v.array(v.string())) },
  handler: async (
    ctx,
    a,
  ): Promise<{
    listingHash: string;
    observedAt: number;
    direct: { covered: DirectHost[]; uncovered: DirectHost[] };
  }> => {
    const c = await ctx.runQuery(internal.edgeHostHides.context, { relayId: a.relayId });
    if (!c) throw new ConvexError({ code: 'not_found', message: 'Relay not found' });
    const hosts = await listPanelHosts(ctx, c.backendServerId);
    const inbounds = nodeInbounds(c, hosts, a.nodeInboundUuids);
    const dctx = directContextOf(c, inbounds, conventionRemarks(hosts, c.nodeName));
    return {
      listingHash: await listingHash(hosts, dctx),
      observedAt: Date.now(),
      direct: classifyDirectHosts(hosts, dctx),
    };
  },
});

/**
 * The reconcile check for BOUND guided relays (the observation boundary's
 * "caught afterwards"): a direct Host that reappeared is re-hidden when it is
 * covered by a listener or was approved before (a hide row exists for it);
 * otherwise attention `direct_host_reappeared` is raised. Suppressed while the
 * relay's restore workflow runs (`boundGuidedRelays` excludes it).
 */
export const reobserveDirect = internalAction({
  args: {},
  handler: async (ctx): Promise<{ relays: number; rehidden: number; alerted: number }> => {
    const ids = await ctx.runQuery(internal.edgeHostHides.boundGuidedRelays, {});
    const report = { relays: 0, rehidden: 0, alerted: 0 };
    for (const relayId of ids) {
      const c = await ctx.runQuery(internal.edgeHostHides.context, { relayId });
      if (!c || c.relay.restore) continue;
      let hosts: BackendHost[];
      try {
        hosts = await listPanelHosts(ctx, c.backendServerId);
      } catch {
        continue;
      }
      report.relays++;
      const st = await ctx.runQuery(internal.edgeHostHides.status, { relayId });
      const approved = new Set(
        st.rows.filter((r) => r.intent === 'disable').map((r) => r.hostUuid),
      );
      const known = nodeInbounds(c, hosts, undefined);
      const dctx = directContextOf(c, known, conventionRemarks(hosts, c.nodeName));
      const enabledDirect = hosts.filter((h) => !h.isDisabled && isDirectHost(h, dctx));
      const covered = new Set(c.listenerInboundUuids.map((u) => u.toLowerCase()));
      const alerts: Array<{ uuid: string; remark: string; inboundUuid: string | null }> = [];
      const remarks: string[] = [];
      for (const h of enabledDirect) {
        const d = toDirectHost(h);
        if (covered.has(d.inboundUuid.toLowerCase()) || approved.has(h.uuid)) {
          const out = await writeHostBit(ctx, {
            relayId,
            backendServerId: c.backendServerId,
            host: h,
            intent: 'disable',
          });
          if (out === 'confirmed') {
            report.rehidden++;
            remarks.push(h.remark);
          } else if (out === 'failed')
            alerts.push({ uuid: h.uuid, remark: h.remark, inboundUuid: d.inboundUuid });
        } else alerts.push({ uuid: h.uuid, remark: h.remark, inboundUuid: d.inboundUuid || null });
      }
      if (remarks.length > 0)
        await ctx.runMutation(internal.edgeHostHides.recordHidden, {
          relayId,
          remarks,
          rehidden: true,
        });
      await ctx.runMutation(internal.edgeHostHides.setDirectHostAlert, { relayId, hosts: alerts });
      if (alerts.length > 0) report.alerted++;
    }
    return report;
  },
});

/**
 * The restore phase's work on ONE confirmed disable row: re-observe; still
 * disabled at the observed tuple -> re-enable through a `restore` row; changed
 * or gone -> released without a write. Returns whether the row is now closed.
 */
export async function restoreOne(
  ctx: ActionCtx,
  a: { row: HideRow; hosts: readonly BackendHost[] },
): Promise<'released' | 'pending'> {
  const live = a.hosts.find((h) => h.uuid === a.row.hostUuid);
  if (!live) {
    await ctx.runMutation(internal.edgeHostHides.releaseWithoutWrite, {
      rowId: a.row._id,
      reason: 'gone',
    });
    return 'released';
  }
  if (!live.isDisabled || !sameTuple(live, a.row.observed)) {
    await ctx.runMutation(internal.edgeHostHides.releaseWithoutWrite, {
      rowId: a.row._id,
      reason: 'changed',
    });
    return 'released';
  }
  const out = await writeHostBit(ctx, {
    relayId: a.row.relayId,
    backendServerId: a.row.backendServerId,
    host: live,
    intent: 'restore',
  });
  return out === 'confirmed' ? 'released' : 'pending';
}
