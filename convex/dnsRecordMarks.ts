/**
 * FCP's private ownership marks for DNS records whose provider cannot store a
 * comment on the record (Gandi LiveDNS; `lib/edges/providers/dns/gandiDns.ts`).
 * One row per record FCP wrote: the zone, the record's name, type and content
 * (normalized) and the marker its writer proves ownership with. Never served
 * anywhere: keeping the marker out of public DNS is the point.
 *
 * Bounded by construction: a row exists only while FCP's record does (the
 * client removes it on delete, and on a create the provider refused for good),
 * and a name holds a handful of records, so `forName` reads a small range.
 */
import { v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';

const recordType = v.union(v.literal('A'), v.literal('AAAA'), v.literal('CNAME'));

/** Most records one name can hold that a reader looks at (FCP writes one per type). */
const MAX_PER_NAME = 50;

export const forName = internalQuery({
  args: { zone: v.string(), name: v.string() },
  handler: async (ctx, a) => {
    const rows = await ctx.db
      .query('dnsRecordMarks')
      .withIndex('by_zone_name', (q) => q.eq('zone', a.zone).eq('name', a.name))
      .take(MAX_PER_NAME);
    return rows.map((r) => ({ type: r.type, name: r.name, content: r.content, marker: r.marker }));
  },
});

export const set = internalMutation({
  args: {
    zone: v.string(),
    name: v.string(),
    type: recordType,
    content: v.string(),
    marker: v.string(),
  },
  handler: async (ctx, a) => {
    const rows = await ctx.db
      .query('dnsRecordMarks')
      .withIndex('by_zone_name', (q) => q.eq('zone', a.zone).eq('name', a.name))
      .take(MAX_PER_NAME);
    const same = rows.filter((r) => r.type === a.type && r.content === a.content);
    const [keep, ...extra] = same;
    for (const r of extra) await ctx.db.delete(r._id);
    if (keep) {
      if (keep.marker !== a.marker) await ctx.db.patch(keep._id, { marker: a.marker });
      return;
    }
    await ctx.db.insert('dnsRecordMarks', a);
  },
});

export const remove = internalMutation({
  args: { zone: v.string(), name: v.string(), type: recordType, content: v.string() },
  handler: async (ctx, a) => {
    const rows = await ctx.db
      .query('dnsRecordMarks')
      .withIndex('by_zone_name', (q) => q.eq('zone', a.zone).eq('name', a.name))
      .take(MAX_PER_NAME);
    for (const r of rows)
      if (r.type === a.type && r.content === a.content) await ctx.db.delete(r._id);
  },
});
