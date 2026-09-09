/**
 * Custom probe targets: operator-entered host:port pairs probed alongside the
 * derived targets (edge addresses, relay nodes) from Telemetry → Probes. They
 * are operator evidence only and never reach the block detector. Audits carry
 * the label, never the address.
 */
import { ConvexError, v } from 'convex/values';
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { writeAuditLog } from './lib/audit';
import { addressFamily, bracketIfV6, isPublicIpLiteral } from './lib/edges/ip';
import { mapSummaryAdmin } from './probes';

const LABEL_RE = /^[\p{L}\p{N}][\p{L}\p{N} ._:/()-]{0,63}$/u;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$/i;
/** Names that resolve to the local machine / a private zone by convention (RFC 6761 / mDNS). */
const LOCAL_NAME_RE = /^(localhost|.+\.(localhost|local|internal|localdomain|home\.arpa))\.?$/i;

export function mapTargetAdmin(t: Doc<'probeTargets'>) {
  return {
    id: t._id as string,
    key: `custom:${t._id}`,
    label: t.label,
    address: t.address,
    port: t.port,
    display: `${bracketIfV6(t.address)}:${t.port}`,
    enabled: t.enabled,
    notes: t.notes ?? null,
    reachability: mapSummaryAdmin(t.reachability),
    updatedAt: new Date(t.updatedAt).toISOString(),
  };
}

function checkFields(a: { label?: string; address?: string; port?: number }) {
  if (a.label !== undefined && !LABEL_RE.test(a.label.trim()))
    throw new ConvexError({ code: 'validation', message: 'label must be 1-64 printable chars' });
  if (a.address !== undefined) {
    const s = a.address.trim();
    const fam = addressFamily(s);
    if (!fam && !HOSTNAME_RE.test(s))
      throw new ConvexError({ code: 'validation', message: 'address must be an IP or hostname' });
    // The internal probe connects from FCP's own host: a loopback, private,
    // link-local or unspecified target would turn it into a port scanner of
    // the control plane's network. Public literals (and public names) only.
    if ((fam && !isPublicIpLiteral(s)) || LOCAL_NAME_RE.test(s))
      throw new ConvexError({
        code: 'validation',
        message: 'address must be a public IP or hostname',
      });
  }
  if (a.port !== undefined && (!Number.isInteger(a.port) || a.port < 1 || a.port > 65535))
    throw new ConvexError({ code: 'validation', message: 'port out of range' });
}

export const list = internalQuery({
  args: {},
  handler: async (ctx) =>
    (await ctx.db.query('probeTargets').collect())
      .sort((a, b) => a.label.localeCompare(b.label))
      .map(mapTargetAdmin),
});

export const create = internalMutation({
  args: {
    label: v.string(),
    address: v.string(),
    port: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
    notes: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const port = a.port ?? 443;
    checkFields({ label: a.label, address: a.address, port });
    const now = Date.now();
    const id = await ctx.db.insert('probeTargets', {
      label: a.label.trim(),
      address: a.address.trim(),
      port,
      enabled: a.enabled ?? true,
      notes: a.notes?.slice(0, 500),
      updatedAt: now,
    });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'probe.target.create',
      targetType: 'probe_target',
      targetId: `custom:${id}`,
      payload: { label: a.label.trim() },
    });
    return { id, key: `custom:${id}` };
  },
});

export const update = internalMutation({
  args: {
    id: v.id('probeTargets'),
    label: v.optional(v.string()),
    address: v.optional(v.string()),
    port: v.optional(v.number()),
    enabled: v.optional(v.boolean()),
    notes: v.optional(v.string()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a) => {
    const row = await ctx.db.get(a.id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'Probe target not found' });
    checkFields(a);
    const patch: Partial<Doc<'probeTargets'>> = { updatedAt: Date.now() };
    if (a.label !== undefined) patch.label = a.label.trim();
    if (a.address !== undefined) patch.address = a.address.trim();
    if (a.port !== undefined) patch.port = a.port;
    if (a.enabled !== undefined) patch.enabled = a.enabled;
    if (a.notes !== undefined) patch.notes = a.notes.slice(0, 500);
    // A different address or port is a different target: its history no longer
    // applies — the summary, the per-(country, source, family) rollup rows the
    // next finish would otherwise fold back in, and any run still in flight
    // against the old endpoint (settled as failed so it can never finish).
    if (
      (patch.address !== undefined && patch.address !== row.address) ||
      (patch.port !== undefined && patch.port !== row.port)
    ) {
      patch.reachability = undefined;
      const rollups = await ctx.db
        .query('probeReachability')
        .withIndex('by_target_country', (q) => q.eq('targetKind', 'custom').eq('targetRef', a.id))
        .collect();
      for (const r of rollups) await ctx.db.delete(r._id);
      for (const status of ['requested', 'running'] as const) {
        const inflight = await ctx.db
          .query('probeRuns')
          .withIndex('by_status', (q) => q.eq('status', status))
          .filter((q) =>
            q.and(q.eq(q.field('targetKind'), 'custom'), q.eq(q.field('targetRef'), a.id)),
          )
          .take(200);
        for (const r of inflight)
          await ctx.db.patch(r._id, { status: 'failed', finishedAt: Date.now() });
      }
    }
    await ctx.db.patch(a.id, patch);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'probe.target.update',
      targetType: 'probe_target',
      targetId: `custom:${a.id}`,
      payload: { label: patch.label ?? row.label },
    });
    return { ok: true as const };
  },
});

export const remove = internalMutation({
  args: { id: v.id('probeTargets'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) return { ok: true as const };
    await ctx.db.delete(id);
    // Its rollup rows go with it (bounded: countries × sources × families).
    const rows = await ctx.db
      .query('probeReachability')
      .withIndex('by_target_country', (q) => q.eq('targetKind', 'custom').eq('targetRef', id))
      .collect();
    for (const r of rows) await ctx.db.delete(r._id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'probe.target.delete',
      targetType: 'probe_target',
      targetId: `custom:${id}`,
      payload: { label: row.label },
    });
    return { ok: true as const };
  },
});
