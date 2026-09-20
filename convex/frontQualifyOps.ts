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
import { internal } from './_generated/api';
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
    else
      result = await checker({
        hostname: c.hostname,
        proto: c.proto,
        params: c.params,
        uuid: c.credential.uuid,
        stepTimeoutMs: c.stepTimeoutMs,
      });

    return await ctx.runMutation(internal.frontQualify.record, {
      edgeId,
      result,
      binding: c.binding,
    });
  },
});
