/**
 * The persisted RESTORE workflow (`origins.restore`; docs/edges.md § "Direct-Host
 * hides and the restore workflow"): the one way a guided origin stops depending
 * on its edges without an outage FCP would have caused itself.
 *
 *   freeze -> settle -> verify_fcp_raw -> release_binding -> restore -> verify_direct -> finish
 *
 *  1. freeze: no new direct-Host disable writes on the origin (every hide path
 *     checks `origins.restore`); waits for a running rotation to end.
 *  2. settle: every outstanding hide row reaches `confirmed` or `released` by
 *     OBSERVATION (edgeHostHides.settle in `settle` mode). A claimed row is
 *     possibly written; a lease expiry alone never releases it.
 *  3. verify_fcp_raw (bound origins only): the RAW backend body of each non-dark
 *     cohort carries at least one FCP entry and no origin-address entry: what
 *     members receive the moment the binding is released is usable as-is.
 *  4. release_binding: the delivery binding is released WHILE the origin stays
 *     enabled and its edges published. A direct Host is never re-enabled while
 *     the origin is bound: the renderer would answer `leak_detected` for every
 *     member.
 *  5. restore: each `confirmed` disable row is re-observed; still disabled at
 *     the observed tuple -> re-enabled through a `restore` row (read-back
 *     confirmed); changed or removed by an administrator -> released untouched.
 *  6. verify_direct: the raw body of each non-dark cohort carries an
 *     origin-address entry again.
 *  7. finish, by purpose: `cancel_setup` retains the origin (`setupOwned` +
 *     `bindingDeferred`, edges published); `release_requirement` retains
 *     everything and leaves the origin re-activatable (`bindingDeferred`);
 *     `delete_relay` runs the deletion body only now.
 *
 * One phase advances per `step` (the reconcile cron drives it every tick); a
 * phase that cannot advance records `attempt` + `lastError` and is retried.
 * The raw checks fetch through the same subscription fetch path the sub route
 * uses (no render).
 */
import { ConvexError, v } from 'convex/values';
import { internalAction, internalMutation, internalQuery } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { internal } from './_generated/api';
import { writeAuditLog } from './lib/audit';
import type { BackendHost } from './lib/backends/types';
import { isTerminalPhase } from './lib/edges/rotation';
import { relayRemarkRegex, sameAddress } from './lib/edges/hosts';
import { decodeLinkList, remarkOf } from './lib/edges/render/links';
import { parseProxyUri } from './lib/edges/render/uri';
import { cohortReportForRelay } from './lib/edges/cohorts';
import { startRestoreWorkflow, type RestorePhase, type RestorePurpose } from './lib/edges/restore';
import { applyDeleteBody, deliveryBindingFor } from './relays';
import { assertNoRelayPanelClaim, scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { listenerRemark, listenersOf } from './relayListeners';
import { listPanelHosts, restoreOne, type HideRow } from './edgeHostHides';

// --- the pure raw-body judgement -----------------------------------------------------------------

export interface RawBodyContext {
  originAddress: string;
  /** Listener remarks + adopted legacy remarks. */
  fcpRemarks: string[];
  nodeName: string | null;
  /** Published edge addresses (v4, v6, hostname). */
  edgeAddresses: string[];
}

export interface RawBodyVerdict {
  entries: number;
  fcp: number;
  direct: number;
  /** The body could not be read as a link list (or was empty). */
  unreadable: boolean;
}

/**
 * Count the FCP entries (by remark or edge address) and the ORIGIN entries (by
 * address) of a raw link-list body. Every proxy line counts; nothing is rewritten.
 */
export function judgeRawBody(body: string, ctx: RawBodyContext): RawBodyVerdict {
  const decoded = decodeLinkList(body);
  if (!decoded) return { entries: 0, fcp: 0, direct: 0, unreadable: true };
  const re = ctx.nodeName ? relayRemarkRegex(ctx.nodeName) : null;
  let entries = 0;
  let fcp = 0;
  let direct = 0;
  for (const line of decoded.lines) {
    const u = parseProxyUri(line);
    if (!u) continue;
    entries++;
    if (sameAddress(u.host, ctx.originAddress)) {
      direct++;
      continue;
    }
    const remark = remarkOf(line);
    const byRemark =
      remark !== null && (ctx.fcpRemarks.includes(remark) || (re?.test(remark) ?? false));
    const byAddress = ctx.edgeAddresses.some((a) => sameAddress(a, u.host));
    if (byRemark || byAddress) fcp++;
  }
  return { entries, fcp, direct, unreadable: entries === 0 };
}

// --- isolate half ------------------------------------------------------------------------------

export const start = internalMutation({
  args: {
    relayId: v.id('relays'),
    purpose: v.union(
      v.literal('cancel_setup'),
      v.literal('release_requirement'),
      v.literal('delete_relay'),
    ),
    actorAdminId: v.optional(v.id('adminUsers')),
    darkCohortKeys: v.optional(v.array(v.string())),
    force: v.optional(v.boolean()),
  },
  handler: async (ctx, { relayId, purpose, actorAdminId, darkCohortKeys, force }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay) throw new ConvexError({ code: 'not_found', message: 'Origin not found' });
    await assertNoRelayPanelClaim(ctx.db, relay);
    await startRestoreWorkflow(ctx, relay, {
      purpose,
      ...(actorAdminId ? { actorAdminId } : {}),
      ...(darkCohortKeys ? { darkCohortKeys } : {}),
      ...(force !== undefined ? { force } : {}),
    });
    return { ok: true as const, phase: 'freeze' as const };
  },
});

export interface RestoreContext {
  relay: Doc<'relays'>;
  restore: NonNullable<Doc<'relays'>['restore']>;
  bound: boolean;
  rotationRunning: boolean;
  raw: RawBodyContext;
  cohorts: Array<{
    key: string;
    subscriptionId: Id<'subscriptions'>;
    backend: Doc<'subscriptions'>['backend'];
    backendServerId: Id<'backendServers'> | null;
    backendShortId: string;
    subscriptionUrl: string;
    excludeNode: string | null;
  }>;
  cohortTotal: number;
  /** Confirmed disable rows still to restore, and unsettled rows of either intent. */
  confirmedDisables: HideRow[];
  unsettled: number;
}

export const context = internalQuery({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<RestoreContext | null> => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.restore) return null;
    const listeners = await listenersOf(ctx, relayId);
    const fcpRemarks = [
      ...listeners.map((l) => listenerRemark(l)).filter((r): r is string => !!r),
      ...listeners.flatMap((l) => (l.legacyHosts ?? []).map((h) => h.remark)),
    ];
    const edgeAddresses: string[] = [];
    for (const edgeId of relay.publishedEdgeIds) {
      if (!edgeId) continue;
      const e = await ctx.db.get(edgeId);
      if (!e) continue;
      for (const a of [e.addresses.v4, e.addresses.v6, e.addresses.hostname])
        if (a) edgeAddresses.push(a);
    }
    let bound = false;
    if (relay.backendServerId) {
      const b = await deliveryBindingFor(
        ctx.db,
        relay.backendServerId,
        relay.nodeName ?? undefined,
      );
      bound = !!b && b.relaySlug === relay.slug;
    }
    let rotationRunning = false;
    if (relay.activeRotationId) {
      const rot = await ctx.db.get(relay.activeRotationId);
      rotationRunning = !!rot && !isTerminalPhase(rot.phase);
    }
    const report = await cohortReportForRelay(ctx, relay);
    const cohorts: RestoreContext['cohorts'] = [];
    for (const c of report.cohorts) {
      const sub = await ctx.db.get(c.subscriptionId);
      if (!sub) continue;
      cohorts.push({
        key: c.key,
        subscriptionId: sub._id,
        backend: sub.backend,
        backendServerId: sub.backendServerId ?? null,
        backendShortId: sub.backendShortId,
        subscriptionUrl: sub.subscriptionUrl,
        excludeNode: sub.excludeNode ?? null,
      });
    }
    const rows = await ctx.db
      .query('edgeHostHides')
      .withIndex('by_relay', (q) => q.eq('relayId', relayId))
      .collect();
    return {
      relay,
      restore: relay.restore,
      bound,
      rotationRunning,
      raw: {
        originAddress: relay.originAddress,
        fcpRemarks,
        nodeName: relay.nodeName ?? null,
        edgeAddresses,
      },
      cohorts,
      cohortTotal: report.total,
      confirmedDisables: rows.filter((r) => r.intent === 'disable' && r.state === 'confirmed'),
      unsettled: rows.filter((r) => ['intended', 'written', 'unresolved'].includes(r.state)).length,
    };
  },
});

/** Move the workflow from `from` to `to` (fenced: a stale step changes nothing). */
export const advance = internalMutation({
  args: {
    relayId: v.id('relays'),
    from: v.string(),
    to: v.optional(v.string()),
    error: v.optional(v.string()),
  },
  handler: async (ctx, { relayId, from, to, error }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.restore || relay.restore.phase !== from) return { ok: false as const };
    const now = Date.now();
    await ctx.db.patch(relayId, {
      restore: {
        ...relay.restore,
        ...(to ? { phase: to as RestorePhase, attempt: 0, lastError: undefined } : {}),
        ...(!to ? { attempt: relay.restore.attempt + 1, lastError: error } : {}),
        updatedAt: now,
      },
      updatedAt: now,
    });
    return { ok: true as const };
  },
});

/**
 * Phase 4: release the origin's delivery binding while the origin stays enabled
 * and its edges published (raw delivery of the FCP-Host bodies from here on).
 * `release_requirement` also defers the binding so `require-edges` can re-apply
 * the full activation policy later.
 */
export const releaseBinding = internalMutation({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.restore || relay.restore.phase !== 'release_binding') return { released: false };
    let released = false;
    if (relay.backendServerId) {
      const b = await deliveryBindingFor(
        ctx.db,
        relay.backendServerId,
        relay.nodeName ?? undefined,
      );
      if (b && b.relaySlug === relay.slug) {
        await ctx.db.patch(b._id, {
          state: 'released',
          policyVersion: b.policyVersion + 1,
          updatedAt: Date.now(),
        });
        released = true;
        await writeAuditLog(ctx, {
          actorType: 'system',
          action: 'relay.delivery.released',
          targetType: 'relay',
          targetId: relayId,
          payload: { relaySlug: relay.slug },
        });
        // The place serves raw again: replace the mirrors' rendered objects now.
        await scheduleMirrorRefresh(ctx);
      }
    }
    const now = Date.now();
    await ctx.db.patch(relayId, {
      restore: {
        ...relay.restore,
        phase: 'restore',
        attempt: 0,
        lastError: undefined,
        updatedAt: now,
      },
      // Only an unbound origin may be re-activated by `require-edges`.
      ...(relay.restore.purpose !== 'delete_relay' ? { bindingDeferred: true } : {}),
      updatedAt: now,
    });
    return { released };
  },
});

export const recordRestored = internalMutation({
  args: { relayId: v.id('relays'), remarks: v.array(v.string()) },
  handler: async (ctx, { relayId, remarks }) => {
    const relay = await ctx.db.get(relayId);
    await writeAuditLog(ctx, {
      actorType: 'system',
      action: 'edge.host.restored',
      targetType: 'relay',
      targetId: relayId,
      payload: { relaySlug: relay?.slug ?? '', count: remarks.length, remarks },
    });
    return null;
  },
});

/** Phase 7: the purpose's finish, then `restore` is cleared. */
export const finish = internalMutation({
  args: { relayId: v.id('relays'), hidesRestored: v.number() },
  handler: async (ctx, { relayId, hidesRestored }) => {
    const relay = await ctx.db.get(relayId);
    if (!relay?.restore || relay.restore.phase !== 'finish') return { ok: false as const };
    const { purpose, force, actorAdminId } = relay.restore;
    const now = Date.now();
    if (purpose === 'cancel_setup') {
      await ctx.db.patch(relayId, {
        restore: undefined,
        setupOwned: true,
        bindingDeferred: true,
        updatedAt: now,
      });
    } else if (purpose === 'release_requirement') {
      await ctx.db.patch(relayId, { restore: undefined, bindingDeferred: true, updatedAt: now });
    } else {
      await ctx.db.patch(relayId, { restore: undefined, updatedAt: now });
      const fresh = (await ctx.db.get(relayId))!;
      await applyDeleteBody(ctx, fresh, {
        force,
        disposition: 'restore-direct',
        ...(actorAdminId ? { actorAdminId } : {}),
        audited: true,
      });
    }
    await writeAuditLog(ctx, {
      actorType: actorAdminId ? 'admin' : 'system',
      actorId: actorAdminId,
      action: 'edge.relay.restore_finished',
      targetType: 'relay',
      targetId: relayId,
      payload: { relaySlug: relay.slug, purpose, hidesRestored },
    });
    return { ok: true as const, purpose };
  },
});

export const inProgress = internalQuery({
  args: {},
  handler: async (ctx): Promise<Id<'relays'>[]> => {
    const relays = await ctx.db.query('relays').collect(); // small operator table
    return relays.filter((r) => r.restore).map((r) => r._id);
  },
});

// --- Node half: the driver ---------------------------------------------------------------------

/** Fetch the RAW backend body of one cohort's representative (the sub route's fetch path, no render). */
async function rawBodyOf(ctx: ActionCtx, c: RestoreContext['cohorts'][number]): Promise<string> {
  const fetched = await ctx.runAction(internal.backends.fetchSubscriptionContent, {
    backend: c.backend,
    ...(c.backendServerId ? { backendServerId: c.backendServerId } : {}),
    backendShortId: c.backendShortId,
    subscriptionUrl: c.subscriptionUrl,
    ...(c.excludeNode ? { excludeNode: c.excludeNode } : {}),
  });
  return fetched.content;
}

/**
 * The raw check of a phase over every non-dark cohort. `fcp` = at least one FCP
 * entry and no origin entry; `direct` = at least one origin entry. Returns the
 * first failing cohort's reason, or null.
 */
async function checkCohorts(
  ctx: ActionCtx,
  c: RestoreContext,
  want: 'fcp' | 'direct',
): Promise<string | null> {
  const dark = new Set(c.restore.darkCohortKeys);
  for (const cohort of c.cohorts) {
    if (dark.has(cohort.key)) continue;
    let body: string;
    try {
      body = await rawBodyOf(ctx, cohort);
    } catch {
      return `fetch_failed:${cohort.key}`;
    }
    const verdict = judgeRawBody(body, c.raw);
    if (verdict.unreadable) return `unreadable_body:${cohort.key}`;
    if (want === 'fcp' && (verdict.fcp === 0 || verdict.direct > 0))
      return `${verdict.fcp === 0 ? 'no_fcp_entry' : 'direct_entry_present'}:${cohort.key}`;
    if (want === 'direct' && verdict.direct === 0) return `no_direct_entry:${cohort.key}`;
  }
  return null;
}

export interface StepResult {
  phase: RestorePhase | null;
  advanced: boolean;
  done: boolean;
  error: string | null;
}

/** Drive ONE phase of the origin's restore workflow. */
export const step = internalAction({
  args: { relayId: v.id('relays') },
  handler: async (ctx, { relayId }): Promise<StepResult> => {
    const c = await ctx.runQuery(internal.edgeRestore.context, { relayId });
    if (!c) return { phase: null, advanced: false, done: true, error: null };
    const phase = c.restore.phase;
    const go = async (to: RestorePhase): Promise<StepResult> => {
      await ctx.runMutation(internal.edgeRestore.advance, { relayId, from: phase, to });
      return { phase: to, advanced: true, done: false, error: null };
    };
    const stay = async (error: string): Promise<StepResult> => {
      await ctx.runMutation(internal.edgeRestore.advance, { relayId, from: phase, error });
      return { phase, advanced: false, done: false, error };
    };
    switch (phase) {
      case 'freeze':
        if (c.rotationRunning) return stay('rotation_running');
        return go('settle');
      case 'settle': {
        if (c.unsettled > 0) {
          await ctx.runAction(internal.edgeHostHides.settle, { relayId });
          const again = await ctx.runQuery(internal.edgeHostHides.status, { relayId });
          if (again.outstanding > 0) return stay(`hides_outstanding:${again.outstanding}`);
        }
        return go(c.bound ? 'verify_fcp_raw' : 'release_binding');
      }
      case 'verify_fcp_raw': {
        const err = await checkCohorts(ctx, c, 'fcp');
        if (err) return stay(err);
        return go('release_binding');
      }
      case 'release_binding': {
        await ctx.runMutation(internal.edgeRestore.releaseBinding, { relayId });
        return { phase: 'restore', advanced: true, done: false, error: null };
      }
      case 'restore': {
        // Unsettled restore rows from a previous pass first (observation only).
        if (c.unsettled > 0) await ctx.runAction(internal.edgeHostHides.settle, { relayId });
        if (c.confirmedDisables.length > 0) {
          let hosts: BackendHost[];
          try {
            hosts = await listPanelHosts(ctx, c.relay.backendServerId!);
          } catch {
            return stay('panel_unreachable');
          }
          const restored: string[] = [];
          for (const row of c.confirmedDisables) {
            const out = await restoreOne(ctx, { row, hosts });
            if (out === 'released') restored.push(row.observed.remark);
          }
          if (restored.length > 0)
            await ctx.runMutation(internal.edgeRestore.recordRestored, {
              relayId,
              remarks: restored,
            });
        }
        const st = await ctx.runQuery(internal.edgeHostHides.status, { relayId });
        if (st.outstanding > 0 || st.confirmed > 0)
          return stay(`hosts_pending:${st.outstanding + st.confirmed}`);
        return go('verify_direct');
      }
      case 'verify_direct': {
        // Nothing was hidden and nothing is to be checked against: an origin that
        // never had a direct Host has no direct entry to wait for.
        const hadHides = await ctx.runQuery(internal.edgeHostHides.status, { relayId });
        if (hadHides.rows.some((r) => r.intent === 'disable')) {
          const err = await checkCohorts(ctx, c, 'direct');
          if (err) return stay(err);
        }
        return go('finish');
      }
      case 'finish': {
        const st = await ctx.runQuery(internal.edgeHostHides.status, { relayId });
        const r = await ctx.runMutation(internal.edgeRestore.finish, {
          relayId,
          hidesRestored: st.rows.filter((x) => x.releasedReason === 'restored').length,
        });
        return { phase: null, advanced: r.ok, done: true, error: null };
      }
    }
  },
});

/** The reconcile pass: one phase per origin in a restore workflow. */
export const reconcilePass = internalAction({
  args: {},
  handler: async (ctx): Promise<{ stepped: number; finished: number; errors: number }> => {
    const ids = await ctx.runQuery(internal.edgeRestore.inProgress, {});
    const report = { stepped: 0, finished: 0, errors: 0 };
    for (const relayId of ids) {
      try {
        const r = await ctx.runAction(internal.edgeRestore.step, { relayId });
        report.stepped++;
        if (r.done) report.finished++;
      } catch (err) {
        report.errors++;
        console.warn(
          `[edge-reconcile] restore ${relayId}: ${err instanceof Error ? err.name : 'error'}`,
        );
      }
    }
    return report;
  },
});

export type { RestorePhase, RestorePurpose };
