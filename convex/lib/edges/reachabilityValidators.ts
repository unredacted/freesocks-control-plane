/**
 * The reachability shapes stored on probed targets (schema.ts) and written by
 * `edges.patchEdge`. They live here so a function module can validate its args
 * with the schema's own shape without importing schema.ts.
 */
import { v } from 'convex/values';

export const relayReachVerdict = v.union(
  v.literal('reachable'),
  v.literal('unreachable'),
  v.literal('mixed'),
  v.literal('unknown'),
);

/** Cross-source reachability summary kept on a probed target (edge, origin node, custom). */
export const probeReachabilitySummary = v.object({
  byCountry: v.array(
    v.object({
      country: v.string(),
      // The IPv4 path (what every member receives); IPv6 rows only when no v4 row exists.
      verdict: relayReachVerdict,
      // The IPv6 path, when the target has one and it was probed.
      v6Verdict: v.optional(relayReachVerdict),
      // The BY-NAME path, when the target was also probed by hostname (an L7
      // front has no family of its own; for such a target the name path IS
      // `verdict` and this stays absent).
      nameVerdict: v.optional(relayReachVerdict),
      okVantages: v.number(),
      failVantages: v.number(),
      lastAt: v.number(),
      // Transition marker, evaluated PER PORT before the ports roll up: some
      // listener port that is now unreachable from this country was reachable
      // from it before. A port that has never been reached is not evidence,
      // however long another port's reachable history is.
      wasReachable: v.optional(v.boolean()),
      // The target was NEVER reached from this country over its member-facing
      // path (IPv4, or the name; never IPv6), any source, any port: the failing
      // checks on record since the first one (lib/edges/probes/verdict.ts
      // `sustainedBlock` reads it). Absent once anything reached it.
      neverReached: v.optional(
        v.object({
          checks: v.number(),
          networks: v.number(),
          since: v.number(),
          lastAt: v.number(),
        }),
      ),
    }),
  ),
  updatedAt: v.number(),
});
