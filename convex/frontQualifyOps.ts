'use node';
/**
 * Front qualification executor — the `"use node"` half.
 *
 * One bounded operation per invocation: read what the session needs through an
 * internal query, run the authenticated test session through the edge
 * (lib/edges/frontCheck), hand the verdict back to a mutation. No origin state
 * is read or written here, and nothing member-owned is touched: the credential
 * is FCP's own qualification account and the tunnel fetches a neutral 204.
 *
 * The Node runtime is required by the check itself (TLS with SNI and full chain
 * verification, HTTP/2 for gRPC, raw frames for ws/httpupgrade), not by a
 * dependency: the checker adds no npm package.
 */
import { v } from 'convex/values';
import { internalAction } from './_generated/server';
import type { ActionCtx } from './_generated/server';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import {
  qualifyFront,
  type FrontCheckResult,
  type QualifyFrontArgs,
  type FrontCheckDeps,
} from './lib/edges/frontCheck';

type Checker = (args: QualifyFrontArgs, deps?: FrontCheckDeps) => Promise<FrontCheckResult>;

let checker: Checker = qualifyFront;

/** Test seam: run the state machine without opening a socket. */
export function __setFrontChecker(f: Checker | null): void {
  checker = f ?? qualifyFront;
}

function refusal(code: string, checkedAt: number): FrontCheckResult {
  return { ok: false, code, steps: [], checkedAt };
}

/**
 * A provider's own refusal, named for what the operator must do: Cloudflare
 * answers a gRPC call with 403 while the zone's gRPC switch is off (a
 * dashboard-only setting FCP cannot read or flip).
 */
export function providerVerdict(
  provider: string | null,
  streamTransport: string,
  result: FrontCheckResult,
): FrontCheckResult {
  if (
    provider === 'cloudflare' &&
    streamTransport === 'grpc' &&
    result.code === 'front_error' &&
    result.detail === '403'
  )
    return { ...result, code: 'grpc_disabled' };
  return result;
}

/**
 * The session authenticates as the origin's test account: a used-up one (a
 * test profile left connected in a client) is reset first
 * (relayQualification.keepUsable), and one that cannot be reset is named
 * `test_account_used_up`, not reported as a front that does not answer.
 */
async function accountUsable(ctx: ActionCtx, relayId: Id<'relays'>): Promise<boolean> {
  return (await ctx.runAction(internal.relayQualification.keepUsable, { relayId })).ok;
}

export const run = internalAction({
  args: { edgeId: v.id('edges') },
  handler: async (ctx, { edgeId }): Promise<{ ok: boolean; code: string | null }> => {
    const c = await ctx.runQuery(internal.frontQualify.context, { edgeId });
    // No row, no frozen intent, or an L4 edge: there is nothing to qualify and
    // nothing to record against.
    if (!c) return { ok: false, code: 'not_qualifiable' };
    const checkedAt = Date.now();

    let result: FrontCheckResult;
    if (!c.carried) result = refusal('unsupported_protocol', checkedAt);
    else if (!c.credential)
      result = {
        ...refusal('no_qualification_credential', checkedAt),
        // Distinguishes "never minted" from "minted but not a usable UUID", with
        // no identifier in the string.
        detail: c.credentialConfigured ? 'id_shape' : 'absent',
      };
    else if (!(await accountUsable(ctx, c.relayId)))
      result = refusal('test_account_used_up', checkedAt);
    else
      result = providerVerdict(
        c.provider,
        c.proto.streamTransport,
        await checker({
          hostname: c.hostname,
          proto: c.proto,
          params: c.params,
          credential: c.credential,
          stepTimeoutMs: c.stepTimeoutMs,
        }),
      );

    return await ctx.runMutation(internal.frontQualify.record, {
      edgeId,
      result,
      binding: c.binding,
    });
  },
});
