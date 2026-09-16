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
 *  - `context` gathers the edge, its frozen intent, the slot's transport
 *    parameters, the profile's protocol and the relay's qualification
 *    credential, and derives the BINDING the result will be valid for;
 *  - `record` writes `edges.frontQualification` and `edges.readiness.front`,
 *    re-deriving the binding from the live rows first: a slot, profile or
 *    intent write that landed while the session was in flight means the session
 *    proved something that is no longer what would be published, so the result
 *    is stored as a failure (`config_changed`) rather than as a qualification.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc, Id } from './_generated/dataModel';
import type { MutationCtx, QueryCtx } from './_generated/server';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { parseIntent } from './lib/edges/intent';
import {
  bindingsMatch,
  qualificationBinding,
  type TransportParams,
} from './lib/edges/frontCheck/binding';
import { isUuid } from './lib/edges/frontCheck/vless';
import { protocolIsHttpTransport } from './lib/edges/protocols';

const bindingValidator = v.object({
  hostname: v.string(),
  slotId: v.string(),
  slotRevision: v.number(),
  profileId: v.string(),
  profileRevision: v.number(),
  protocol: v.union(
    v.literal('reality'),
    v.literal('tls'),
    v.literal('plain'),
    v.literal('ws'),
    v.literal('httpupgrade'),
    v.literal('grpc'),
  ),
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

function paramsOf(slot: Doc<'relaySlots'>): TransportParams {
  const t = slot.transportParams ?? {};
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
  const slot = await ctx.db.get(edge.slotId);
  if (!slot) return null;
  const profile = await ctx.db.get(slot.profileId);
  if (!profile) return null;
  const relay = await ctx.db.get(edge.relayId);
  if (!relay) return null;
  const intent = parseIntent(edge.provisionIntent);
  if (!intent) return null;
  const params = paramsOf(slot);
  const binding = qualificationBinding({
    slot: {
      _id: slot._id,
      revision: slot.revision,
      originPort: slot.originPort,
      originTransport: slot.originTransport ?? null,
    },
    profile: { _id: profile._id, revision: profile.revision, protocol: profile.protocol },
    intent,
    params,
  });
  return { edge, slot, profile, relay, intent, params, binding };
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
    return {
      hostname: g.intent.hostname,
      protocol: g.profile.protocol,
      carried: protocolIsHttpTransport(g.profile.protocol),
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
    // The edge, slot, profile or intent disappeared while the session ran.
    if (!g) return { ok: false, code: 'not_qualifiable' };
    const cfg = await resolveEdgeConfig(ctx.db);
    const now = Date.now();
    // Re-derive rather than trust: the slot, the profile or the intent may have
    // been written while the session was in flight.
    const current = g.binding;
    const raced = !bindingsMatch(current, binding);
    const stored = raced
      ? { ok: false, code: 'config_changed', checkedAt: result.checkedAt }
      : { ok: result.ok, code: result.code, checkedAt: result.checkedAt };
    const previous = g.edge.readiness;
    await ctx.db.patch(edgeId, {
      frontQualification: {
        ok: stored.ok,
        ...(stored.code ? { code: stored.code } : {}),
        checkedAt: stored.checkedAt,
        expiresAt: stored.checkedAt + cfg.l7.qualificationTtlMinutes * 60_000,
        binding: {
          hostname: current.hostname,
          slotId: current.slotId as Id<'relaySlots'>,
          slotRevision: current.slotRevision,
          profileId: current.profileId as Id<'protocolProfiles'>,
          profileRevision: current.profileRevision,
          protocol: current.protocol,
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
    return { ok: stored.ok, code: stored.code ?? null };
  },
});
