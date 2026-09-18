/**
 * Front qualification, isolate half: what the test session needs to run, and
 * where its verdict is written.
 *
 * The session itself is a `"use node"` action (frontQualifyOps.ts) because it
 * speaks TLS, HTTP/2 and raw frames. Everything that reads or writes relay
 * state stays here, so the action remains one bounded outbound operation that
 * returns plain data — the same split probeOps.ts and edgeProviderOps.ts use.
 *
 * Two functions:
 *  - `context` gathers the edge, its frozen intent, the listener's transport
 *    parameters and what it speaks, and the relay's qualification credential,
 *    and derives the BINDING the result will be valid for;
 *  - `record` writes `edges.frontQualification` and `edges.readiness.front`,
 *    re-deriving the binding from the live rows first: a listener or intent
 *    write that landed while the session was in flight means the session
 *    proved something that is no longer what would be published, so the result
 *    is stored as a failure (`config_changed`) rather than as a qualification.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { resolveEdgeConfig, edgeMs } from './lib/edgeConfig';
import { listenerProtoFields } from './lib/edgeProtocolIds';
import { scheduleMirrorRefresh } from './lib/edges/relayGuards';
import { parseIntent } from './lib/edges/intent';
import {
  bindingsMatch,
  qualificationBinding,
  type TransportParams,
} from './lib/edges/frontCheck/binding';
import { isUuid } from './lib/edges/frontCheck/vless';
import { protocolIsHttpTransport, protocolL7Proof } from './lib/edges/protocols';

const bindingValidator = v.object({
  hostname: v.string(),
  listenerId: v.string(),
  listenerRevision: v.number(),
  ...listenerProtoFields,
  transportParamsHash: v.string(),
  intentHash: v.string(),
});

const resultValidator = v.object({
  ok: v.boolean(),
  code: v.optional(v.string()),
  detail: v.optional(v.string()),
  steps: v.array(v.object({ step: v.string(), ok: v.boolean(), ms: v.number() })),
  checkedAt: v.number(),
});

function paramsOf(listener: Doc<'relayListeners'>): TransportParams {
  const t = listener.transportParams ?? {};
  return {
    path: t.path ?? null,
    host: t.host ?? null,
    serviceName: t.serviceName ?? null,
    upgradeToken: t.upgradeToken ?? null,
  };
}

/**
 * Everything the session and the binding depend on, read in one transaction so
 * the action cannot observe a half-updated relay.
 */
async function gather(ctx: QueryCtx | MutationCtx, edgeId: Id<'edges'>) {
  const edge = await ctx.db.get(edgeId);
  if (!edge) return null;
  const listener = await ctx.db.get(edge.listenerId);
  if (!listener) return null;
  const relay = await ctx.db.get(edge.relayId);
  if (!relay) return null;
  const intent = parseIntent(edge.provisionIntent);
  if (!intent) return null;
  const params = paramsOf(listener);
  const binding = qualificationBinding({
    listener: {
      _id: listener._id,
      revision: listener.revision,
      originPort: listener.originPort,
      originTransport: listener.originTransport ?? null,
      protocol: listener.protocol,
      streamTransport: listener.streamTransport,
      security: listener.security,
    },
    intent,
    params,
  });
  return { edge, listener, relay, intent, params, binding };
}

export const context = internalQuery({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }) => {
    const g = await gather(ctx, edgeId);
    if (!g) return null;
    const cfg = await resolveEdgeConfig(ctx.db);
    // The qualification account is minted through the backend provider and its
    // panel id doubles as the VLESS UUID on the panels FCP drives. Anything
    // else (a composite id from a panel that separates them) is reported as a
    // missing credential rather than sent as a guess.
    const credentialId = g.relay.qualificationUserId ?? '';
    const proto = {
      protocol: g.listener.protocol,
      streamTransport: g.listener.streamTransport,
      security: g.listener.security,
    };
    return {
      hostname: g.intent.hostname,
      proto,
      // Only an HTTP-carried listener with an authenticated proof can be qualified.
      carried: protocolIsHttpTransport(proto) && protocolL7Proof(proto) === 'vless',
      params: g.params,
      credential: isUuid(credentialId) ? { uuid: credentialId } : null,
      credentialConfigured: credentialId.length > 0,
      stepTimeoutMs: cfg.l7.qualifyStepTimeoutMs,
      ttlMinutes: cfg.l7.qualificationTtlMinutes,
      binding: g.binding,
    };
  },
});

export const record = internalMutation({
  args: {
    edgeId: v.id('edges'),
    result: resultValidator,
    binding: bindingValidator,
  },
  handler: async (
    ctx,
    { edgeId, result, binding },
  ): Promise<{ ok: boolean; code: string | null }> => {
    const g = await gather(ctx, edgeId);
    // The edge, listener or intent disappeared while the session ran.
    if (!g) return { ok: false, code: 'not_qualifiable' };
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    // Re-derive rather than trust: the listener or the intent may have been
    // written while the session was in flight.
    const current = g.binding;
    const raced = !bindingsMatch(current, binding);
    const stored = raced
      ? { ok: false, code: 'config_changed', checkedAt: result.checkedAt }
      : { ok: result.ok, code: result.code, checkedAt: result.checkedAt };
    const previous = g.edge.readiness;
    // A PASSING proof is good for the configured TTL. A FAILED one is not a
    // proof at all, so it expires after a few poll intervals, which makes the
    // reconcile cron re-run the check soon.
    const failRetryMs = Math.min(
      Math.max(edgeMs.poll(cfg) * 10, 60_000),
      cfg.l7.qualificationTtlMinutes * 60_000,
    );
    await ctx.db.patch(edgeId, {
      frontQualification: {
        ok: stored.ok,
        ...(stored.code ? { code: stored.code } : {}),
        checkedAt: stored.checkedAt,
        expiresAt:
          stored.checkedAt + (stored.ok ? cfg.l7.qualificationTtlMinutes * 60_000 : failRetryMs),
        binding: {
          hostname: current.hostname,
          listenerId: current.listenerId as Id<'relayListeners'>,
          listenerRevision: current.listenerRevision,
          protocol: current.protocol,
          streamTransport: current.streamTransport,
          security: current.security,
          transportParamsHash: current.transportParamsHash,
          intentHash: current.intentHash,
        },
        ...(g.edge.frontQualification?.affectedCountries
          ? { affectedCountries: g.edge.frontQualification.affectedCountries }
          : {}),
      },
      readiness: {
        dns: previous?.dns ?? 'unknown',
        certificate: previous?.certificate ?? 'unknown',
        front: stored.ok ? 'ready' : 'failed',
        checkedAt: now,
      },
      updatedAt: now,
    });
    // A PUBLISHED front that just failed its proof stops being rendered the
    // moment this mutation commits, so what subscribers should receive has
    // changed: bump the epoch and refresh the stored mirrors.
    if (!stored.ok && g.edge.publication === 'published') {
      const relay = await ctx.db.get(g.edge.relayId);
      if (relay) {
        await ctx.db.patch(relay._id, {
          publicationEpoch: relay.publicationEpoch + 1,
          updatedAt: now,
        });
        await scheduleMirrorRefresh(ctx);
      }
    }
    return { ok: stored.ok, code: stored.code ?? null };
  },
});
