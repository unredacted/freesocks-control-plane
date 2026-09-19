/**
 * Member reports, attributed to server names (aggregate only).
 *
 * When a member reports a problem with ONE address (their snapshot names the
 * edge, see `edgeAttribution.ts`) and that address's listener hands out ranked
 * names (`hrw1`), the names that member holds on it are recomputed from the
 * same inputs the renderer uses, and each gets an equal share of the report's
 * deduplicated weight. What is stored is `sniReportCounts`: name, country, day,
 * summed weight. Nothing about the member reaches it.
 *
 * The country is the member's saved choice, else the country they consented to
 * share with this report, and only when it is a curated one; otherwise `ZZ`.
 * An inferred country is never used here (it is never stored anywhere).
 *
 * This is a hint for the operator (`suspectIn` on the family page). It never
 * retires a name and never changes what members are given.
 */
import { v } from 'convex/values';
import type { Doc, Id } from './_generated/dataModel';
import { internalMutation, type MutationCtx } from './_generated/server';
import { assignEndpoints } from './lib/edges/assignment';
import { resolveWhere } from './lib/edges/sni/country';
import { NO_COUNTRY, dayOf, shareOf } from './lib/edges/sni/health';
import { effectiveRule } from './lib/edges/render';
import { resolveEdgeConfig } from './lib/edgeConfig';
import { resolveSniConfig } from './lib/sniConfig';
import { recordHeartbeat } from './cronHeartbeat';
import { publishedEdgesOf } from './edgeRender';

/**
 * Add one deduplicated report to the names the reporter holds on `edgeId`.
 * Returns how many names shared it (0 = nothing attributable).
 */
export async function attributeReport(
  ctx: MutationCtx,
  args: {
    sub: Doc<'subscriptions'>;
    edgeId: string;
    consentedCountry: string | null;
    now: number;
  },
): Promise<number> {
  const { sub, edgeId, now } = args;
  const snap = sub.lastRender;
  const edge = await ctx.db.get(edgeId as Id<'edges'>);
  if (!snap || !edge || !sub.renderKey) return 0;
  const origin = await ctx.db.get(edge.relayId);
  if (!origin || snap.epoch !== origin.publicationEpoch) return 0;

  // Exactly the snapshot's edges, as the account page rebuilds its labels: a
  // recomputation over the whole pool could name an edge the member never got.
  const { published } = await publishedEdgesOf(ctx, origin, { includeIneligible: true });
  const byId = new Map(published.map((p) => [p.edgeId, p]));
  const primary = snap.primaryEdgeId ? byId.get(snap.primaryEdgeId) : undefined;
  const backup = snap.backupEdgeId ? byId.get(snap.backupEdgeId) : undefined;
  if (!primary) return 0;

  const [cfg, sniCfg] = await Promise.all([resolveEdgeConfig(ctx.db), resolveSniConfig(ctx.db)]);
  const { where } = resolveWhere({
    override: sub.sniRegion ?? null,
    inferred: args.consentedCountry,
    curated: sniCfg.curatedCountries,
  });
  const rule = effectiveRule(cfg.render, cfg.render.clients.other);
  const assigned = assignEndpoints(sub.renderKey, [primary, ...(backup ? [backup] : [])], {
    now,
    preferDistinctProviders: cfg.render.preferDistinctProviders,
    includeBackup: rule.includeBackup && !!backup,
    canEmitV6: rule.ipv6Mode === 'both',
    namesPerEndpoint: rule.namesPerEndpoint,
    backupNames: rule.backupNames,
    where,
  });
  const endpoint = [assigned.primary, assigned.backup].find((e) => e?.edge.edgeId === edgeId);
  // Only ranked, name-presenting L4 listeners: elsewhere the name is not a
  // per-member choice, so a report says nothing about it.
  if (!endpoint || endpoint.edge.sniPick !== 'hrw1' || endpoint.edge.addresses.hostname) return 0;
  const names = [endpoint.sni, ...(endpoint.alternates ?? []).map((a) => a.sni)].filter(
    (n): n is string => !!n,
  );
  const share = shareOf(names);
  if (share === 0) return 0;

  const country = where.country ?? NO_COUNTRY;
  const day = dayOf(now);
  for (const name of names) {
    const row = await ctx.db
      .query('sniReportCounts')
      .withIndex('by_name_country_day', (q) =>
        q.eq('name', name).eq('country', country).eq('day', day),
      )
      .unique();
    if (row) await ctx.db.patch(row._id, { weight: row.weight + share, updatedAt: now });
    else
      await ctx.db.insert('sniReportCounts', { name, country, day, weight: share, updatedAt: now });
  }
  return names.length;
}

/** Delete counts older than the window. Bounded per call; the cron calls it every tick. */
export const sweep = internalMutation({
  args: { now: v.optional(v.number()) },
  handler: async (ctx, a) => {
    await recordHeartbeat(ctx, 'sni-report-sweep');
    const now = a.now ?? Date.now();
    const { reportWindowDays } = await resolveSniConfig(ctx.db);
    const cutoff = dayOf(now - reportWindowDays * 86_400_000);
    const old = await ctx.db
      .query('sniReportCounts')
      .withIndex('by_day', (q) => q.lt('day', cutoff))
      .take(500);
    for (const row of old) await ctx.db.delete(row._id);
    return { deleted: old.length };
  },
});
