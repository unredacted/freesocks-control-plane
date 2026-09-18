/**
 * Endpoint verification of L4 edges (docs/edges.md § "Publication"): the
 * binding a client displays and must echo back, and the operator's
 * confirmation against it.
 *
 * `binding` derives `{endpoint, listenerKey, listenerRevision, configHash}`
 * from the live rows (lib/edges/verification.ts). `confirm` RECOMPUTES that
 * binding and refuses a mismatch (`edge.verification_stale`): a listener write
 * or a re-addressing between the display and the tick means the operator
 * tested something that is no longer what would be published, so nothing is
 * stamped and the client fetches a fresh binding instead.
 *
 * Account trust is a SEPARATE consequence of the same tick: the first confirmed
 * endpoint of an untrusted L4 account also trusts the account (the existing
 * `setQualified` semantics, with endpoint evidence) when the endpoint is
 * evidence for the account as it is NOW (credentials tested after their last
 * change, edge provisioned with the account's effective template), unless a
 * manual untrust holds automatic trust off. A trusted account never exempts a
 * NEW endpoint from its own confirmation: the publication gate reads
 * `edges.verification`, never the account.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { DatabaseReader, MutationCtx } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { resolveTemplateFor } from './edgeTemplates';
import { providerHealthSatisfies } from './lib/edges/providers/capabilities';
import {
  bindingMatches,
  needsEndpointVerification,
  recordMatchesBinding,
  verificationBinding,
  verificationCurrent,
  verificationStale,
} from './lib/edges/verification';
import { partialRungFor } from './lib/edges/verifyRung';
import { checkPublishable } from './relays';
import { applyQualification } from './edgeProviderAccounts';

const methodValidator = v.union(v.literal('test_link'), v.literal('named_connection'));

/** The verification view the admin edge detail and the test-link builder share. */
export function verificationView(edge: Doc<'edges'>, listener: Doc<'relayListeners'> | null) {
  const rec = edge.verification;
  const required = needsEndpointVerification(edge);
  const current = !!listener && verificationCurrent(edge, listener);
  return {
    required,
    current,
    stale: !!listener && verificationStale(edge, listener),
    record: rec
      ? {
          rung: rec.rung,
          by: rec.by,
          at: new Date(rec.at).toISOString(),
          method: rec.method,
          listenerKey: rec.listenerKey,
          listenerRevision: rec.listenerRevision,
        }
      : null,
  };
}

/**
 * `GET edges/{id}/verification-binding`: what the operator is about to test,
 * exactly as the confirmation must echo it. Null when the edge has no address
 * yet or its listener is gone.
 */
export const binding = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const edge = await ctx.db.get(edgeId);
    if (!edge) return null;
    const listener = await ctx.db.get(edge.listenerId);
    if (!listener) return null;
    const b = verificationBinding(edge, listener);
    if (!b) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    // What the tick would unlock: the gate's verdict with ONLY the verification
    // rule taken out, so an edge that is also unhealthy (or otherwise blocked)
    // reports that blocker instead of "publishable once tested".
    const check = await checkPublishable(ctx, edge, cfg.requireProviderHealth, {
      skipVerification: true,
    });
    return {
      edgeId: edge._id as string,
      layer: (edge.layer ?? 'l4') as 'l4' | 'l7',
      ...b,
      verification: verificationView(edge, listener),
      publishableAfter: check.ok || check.code === 'already_published',
      blocker: check.ok ? null : (check.code ?? null),
    };
  },
});

/**
 * `POST edges/{id}/verify`: the operator's confirmation. Body = the binding
 * they were shown. L4 only: an L7 edge is verified by its authenticated proof.
 */
export const confirm = internalMutation({
  args: {
    edgeId: v.id('edges'),
    endpoint: v.string(),
    listenerRevision: v.number(),
    configHash: v.string(),
    method: methodValidator,
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const edge = await ctx.db.get(a.edgeId);
    if (!edge) throw new ConvexError({ code: 'not_found', message: 'Edge not found' });
    if (!needsEndpointVerification(edge))
      throw new ConvexError({
        code: 'edge.l7_proof_required',
        message: 'An L7 front is verified by its authenticated proof, not by hand',
      });
    if (edge.status !== 'active')
      throw new ConvexError({ code: 'edge.edge_not_active', message: 'The edge is not active' });
    const listener = await ctx.db.get(edge.listenerId);
    if (!listener || listener.retired)
      throw new ConvexError({ code: 'edge.listener_retired', message: 'Listener not found' });
    const current = verificationBinding(edge, listener);
    const echoed = {
      endpoint: a.endpoint,
      listenerKey: listener.listenerKey,
      listenerRevision: a.listenerRevision,
      configHash: a.configHash,
    };
    if (!bindingMatches(current, echoed))
      throw new ConvexError({
        code: 'edge.verification_stale',
        message:
          'The configuration changed since this endpoint was shown; fetch the binding again and retest',
      });
    const relay = await ctx.db.get(edge.relayId);
    const now = Date.now();
    await ctx.db.patch(edge._id, {
      verification: {
        rung: 'verified',
        by: 'admin',
        at: now,
        method: a.method,
        ...current!,
      },
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: a.actorAdminId ? 'admin' : 'system',
      actorId: a.actorAdminId ?? undefined,
      action: 'edge.verified',
      targetType: 'edge',
      targetId: edge._id,
      payload: {
        relaySlug: relay?.slug ?? '',
        edgeId: edge._id,
        listenerKey: listener.listenerKey,
        method: a.method,
      },
    });
    // The separate consequence: the first confirmed endpoint of an untrusted
    // account trusts the account, when the endpoint is evidence FOR THE
    // ACCOUNT AS IT IS NOW: the credentials passed a test after they last
    // changed, and the edge was provisioned with the template the account
    // provisions with now (the qualification's `templateHash` keys the
    // template-edit invalidation). An adopted edge or one from an older
    // template proves its own endpoint only. A manual untrust holds it off.
    let accountTrusted = false;
    let accountTrustReason: string | null = null;
    if (edge.accountId) {
      const account = await ctx.db.get(edge.accountId);
      if (!account) accountTrustReason = 'account_not_found';
      else if (account.qualified) accountTrustReason = 'already_qualified';
      else if (account.autoQualifyHold) accountTrustReason = 'hold';
      else {
        const trust = await accountTrustEvidence(ctx, account, edge);
        if (!trust.ok) accountTrustReason = trust.code;
        else {
          await applyQualification(ctx, account, {
            by: 'admin',
            actorAdminId: a.actorAdminId,
            evidence: {
              edgeId: edge._id,
              endpoint: current!.endpoint,
              accountTestedAt: trust.testedAt,
              templateHash: trust.templateHash,
              listenerId: listener._id as Id<'relayListeners'>,
              listenerRevision: listener.revision,
            },
          });
          accountTrusted = true;
        }
      }
    }
    return {
      ok: true as const,
      edgeId: edge._id as string,
      verifiedAt: new Date(now).toISOString(),
      accountTrusted,
      accountTrustReason,
    };
  },
});

/**
 * Whether a confirmed endpoint of `edge` is trust evidence for `account` NOW
 * (docs/edges.md § "Publication" > account trust): a passing credential test
 * AFTER the last credential / settings change, and the edge's template hash
 * equal to the account's effective template hash. Codes mirror the L7
 * auto-trust rule's (lib/edges/autoQualify.ts).
 */
async function accountTrustEvidence(
  ctx: { db: DatabaseReader },
  account: Doc<'edgeProviderAccounts'>,
  edge: Doc<'edges'>,
): Promise<
  | { ok: true; testedAt: number; templateHash: string }
  | {
      ok: false;
      code: 'account_untested' | 'tested_before_credential_change' | 'template_mismatch';
    }
> {
  const testedAt = account.lastTestOkAt ?? 0;
  if (!testedAt || account.lastTestError) return { ok: false, code: 'account_untested' };
  if (testedAt <= (account.credentialsChangedAt ?? 0))
    return { ok: false, code: 'tested_before_credential_change' };
  const effective = await resolveTemplateFor(
    ctx,
    account.provider,
    null,
    account.defaultTemplateId ?? null,
    account._id,
  );
  if (!edge.templateHash || edge.templateHash !== effective.hash)
    return { ok: false, code: 'template_mismatch' };
  return { ok: true, testedAt, templateHash: effective.hash };
}

// --- the partial rung (probe evidence) -----------------------------------------------------------

/** Newest probe runs read for the shape check (every source, every port, both families). */
const RUNG_RUN_WINDOW = 40;

/**
 * Re-derive the `partial` rung of an active L4 edge from its probe evidence
 * (lib/edges/verifyRung.ts) and persist it as `edges.verification` with
 * `rung: 'partial', by: 'system', method: 'probe'`. Called after every probe
 * run on an `edge` target settles, and by the reconcile pass below.
 *
 *   - a `verified` record is NEVER touched (the operator's tick outranks the
 *     probes, and a stale one is what `retest_needed` reads);
 *   - `partial` writes the record against the CURRENT binding (a matching
 *     record is left alone);
 *   - `unreachable` clears a `partial` record;
 *   - `pending` leaves things as they are.
 *
 * The record never satisfies the publication gate: `verificationCurrent`
 * answers false for any rung but `verified`.
 */
export async function refreshPartialRung(
  ctx: MutationCtx,
  edgeId: Id<'edges'>,
  now = Date.now(),
): Promise<'partial' | 'unreachable' | 'pending' | null> {
  const edge = await ctx.db.get(edgeId);
  if (!edge || edge.status !== 'active' || !needsEndpointVerification(edge)) return null;
  if (edge.verification?.rung === 'verified') return null;
  const listener = await ctx.db.get(edge.listenerId);
  if (!listener || listener.retired) return null;
  const binding = verificationBinding(edge, listener);
  if (!binding) return null;
  const cfg = await resolveEdgeConfig(ctx.db);
  const reachability = await ctx.db
    .query('probeReachability')
    .withIndex('by_target_country', (q) => q.eq('targetKind', 'edge').eq('targetRef', edgeId))
    .collect();
  const runs = await ctx.db
    .query('probeRuns')
    .withIndex('by_target_requested', (q) => q.eq('targetKind', 'edge').eq('targetRef', edgeId))
    .order('desc')
    .take(RUNG_RUN_WINDOW);
  const rung = partialRungFor(listener, {
    // The gate's own health rule: an observe-only import has no provider to ask.
    providerHealthy:
      !edge.managed ||
      providerHealthSatisfies(edge.provider, edge.health, cfg.requireProviderHealth),
    reachability: reachability.map((r) => ({
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
  const rec = edge.verification;
  if (rung === 'partial') {
    if (rec && rec.rung === 'partial' && recordMatchesBinding(rec, binding)) return rung;
    await ctx.db.patch(edge._id, {
      verification: { rung: 'partial', by: 'system', at: now, method: 'probe', ...binding },
      updatedAt: now,
    });
    await auditRung(ctx, edge, listener.listenerKey, 'partial');
  } else if (rung === 'unreachable' && rec) {
    await ctx.db.patch(edge._id, { verification: undefined, updatedAt: now });
    await auditRung(ctx, edge, listener.listenerKey, 'unreachable');
  }
  return rung;
}

async function auditRung(
  ctx: MutationCtx,
  edge: Doc<'edges'>,
  listenerKey: string,
  rung: 'partial' | 'unreachable' | 'cleared',
) {
  const relay = await ctx.db.get(edge.relayId);
  await writeAuditLog(ctx, {
    actorType: 'system',
    action: 'edge.verification.rung',
    targetType: 'edge',
    targetId: edge._id,
    payload: { relaySlug: relay?.slug ?? '', edgeId: edge._id, listenerKey, rung },
  });
}

/**
 * The reconcile pass: a `partial` record whose binding no longer matches the
 * live rows (the edge was re-addressed or its listener changed and no probe
 * has settled since) is cleared, so a system rung never outlives the
 * configuration it was measured on. `verified` records are never touched.
 * Bounded: active edges are operator-scale.
 */
export const reconcilePartialRungs = internalMutation({
  args: {},
  handler: async (ctx) => {
    const now = Date.now();
    let cleared = 0;
    const active = await ctx.db
      .query('edges')
      .withIndex('by_status', (q) => q.eq('status', 'active'))
      .take(500);
    for (const edge of active) {
      const rec = edge.verification;
      if (!rec || rec.rung !== 'partial' || !needsEndpointVerification(edge)) continue;
      const listener = await ctx.db.get(edge.listenerId);
      const binding = listener && !listener.retired ? verificationBinding(edge, listener) : null;
      if (binding && recordMatchesBinding(rec, binding)) continue;
      await ctx.db.patch(edge._id, { verification: undefined, updatedAt: now });
      await auditRung(ctx, edge, listener?.listenerKey ?? rec.listenerKey, 'cleared');
      cleared++;
    }
    return { cleared };
  },
});
