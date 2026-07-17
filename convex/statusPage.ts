/**
 * Network-status page — registered wrappers over the pure projection in
 * lib/statusPage.ts. `getPublic` feeds the unauthenticated GET /api/v1/status
 * route; the admin functions back the CMS Status page (incidents + the
 * censorship matrix + load thresholds, all in the `status.*` namespace).
 */
import { internalMutation, internalQuery } from './_generated/server';
import { ConvexError, v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import {
  resolvePublicStatusPage,
  resolveLocationLoad,
  resolveStatusConfig,
  sanitizeCensorshipRows,
  validateIncidentInput,
  STATUS_KEYS,
} from './lib/statusPage';

/** The assembled public status page (locations + matrix + incidents). */
export const getPublic = internalQuery({
  args: {},
  handler: (ctx) => resolvePublicStatusPage(ctx.db),
});

/** One location's coarse load band (the member node-status badge). */
export const locationLoad = internalQuery({
  args: { code: v.string() },
  handler: (ctx, { code }) => resolveLocationLoad(ctx.db, code),
});

// --- admin: page config -----------------------------------------------------

/** Current page config for the admin editor (sanitized, fail-safe). */
export const getPageConfig = internalQuery({
  args: {},
  handler: async (ctx) => {
    const cfg = await resolveStatusConfig(ctx.db);
    return {
      busyAt: cfg.busyAt,
      crowdedAt: cfg.crowdedAt,
      rows: cfg.censorshipRows,
    };
  },
});

/**
 * Admin sets the censorship matrix + load thresholds. `rows` replaces the full
 * matrix (the editor always submits the whole grid); thresholds validate to
 * positive ints with crowdedAt >= busyAt enforced downstream.
 */
export const setPageConfig = internalMutation({
  args: {
    rows: v.optional(v.any()),
    busyAt: v.optional(v.number()),
    crowdedAt: v.optional(v.number()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { rows, busyAt, crowdedAt, actorAdminId }) => {
    if (rows === undefined && busyAt === undefined && crowdedAt === undefined) {
      throw new ConvexError({ code: 'validation', message: 'no recognized status-page fields' });
    }
    if (rows !== undefined) {
      const clean = sanitizeCensorshipRows({ rows });
      await upsertSettingRow(
        ctx,
        STATUS_KEYS.censorship,
        JSON.stringify({ rows: clean }),
        actorAdminId,
      );
    }
    for (const [key, val] of [
      [STATUS_KEYS.loadBusyAt, busyAt],
      [STATUS_KEYS.loadCrowdedAt, crowdedAt],
    ] as const) {
      if (val === undefined) continue;
      if (!Number.isInteger(val) || val < 1 || val > 100_000) {
        throw new ConvexError({ code: 'validation', message: 'thresholds must be 1..100000' });
      }
      await upsertSettingRow(ctx, key, JSON.stringify(val), actorAdminId);
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'status.page.update',
      targetType: 'status_page',
      payload: {
        ...(rows !== undefined ? { censorshipRows: sanitizeCensorshipRows({ rows }).length } : {}),
        ...(busyAt !== undefined ? { busyAt } : {}),
        ...(crowdedAt !== undefined ? { crowdedAt } : {}),
      },
    });
    const cfg = await resolveStatusConfig(ctx.db);
    return { busyAt: cfg.busyAt, crowdedAt: cfg.crowdedAt, rows: cfg.censorshipRows };
  },
});

// --- admin: incidents -------------------------------------------------------

const ADMIN_INCIDENT_CAP = 100;

/** Newest-first incident list for the admin editor (bounded). */
export const listIncidents = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db
      .query('statusIncidents')
      .withIndex('by_startedAt')
      .order('desc')
      .take(ADMIN_INCIDENT_CAP);
    return rows.map((r) => ({
      id: r._id as string,
      title: r.title,
      body: r.body ?? null,
      severity: r.severity,
      locationCodes: r.locationCodes,
      startedAt: r.startedAt,
      resolvedAt: r.resolvedAt ?? null,
    }));
  },
});

export const createIncident = internalMutation({
  args: { input: v.any(), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { input, actorAdminId }) => {
    let clean;
    try {
      clean = validateIncidentInput(input);
    } catch (e) {
      throw new ConvexError({
        code: 'validation',
        message: e instanceof Error ? e.message : 'invalid incident',
      });
    }
    const now = Date.now();
    const id = await ctx.db.insert('statusIncidents', { ...clean, updatedAt: now });
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'status.incident.create',
      targetType: 'status_incident',
      targetId: id,
      payload: { severity: clean.severity, locationCodes: clean.locationCodes },
    });
    return { id: id as string };
  },
});

/**
 * Edit / resolve an incident. `resolve:true` stamps resolvedAt=now;
 * `resolve:false` re-opens (clears resolvedAt). Field patches are validated
 * through the same input validator (merged over the stored row).
 */
export const updateIncident = internalMutation({
  args: {
    id: v.id('statusIncidents'),
    input: v.optional(v.any()),
    resolve: v.optional(v.boolean()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { id, input, resolve, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'incident not found' });
    const patch: Record<string, unknown> = { updatedAt: Date.now() };
    if (input !== undefined) {
      let clean;
      try {
        clean = validateIncidentInput({
          title: row.title,
          body: row.body,
          severity: row.severity,
          locationCodes: row.locationCodes,
          startedAt: row.startedAt,
          ...input,
        });
      } catch (e) {
        throw new ConvexError({
          code: 'validation',
          message: e instanceof Error ? e.message : 'invalid incident',
        });
      }
      patch.title = clean.title;
      patch.body = clean.body;
      patch.severity = clean.severity;
      patch.locationCodes = clean.locationCodes;
      patch.startedAt = clean.startedAt;
    }
    if (resolve === true && row.resolvedAt == null) patch.resolvedAt = Date.now();
    if (resolve === false) patch.resolvedAt = undefined;
    await ctx.db.patch(id, patch);
    if (resolve === true && row.resolvedAt == null) {
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'status.incident.resolve',
        targetType: 'status_incident',
        targetId: id,
      });
    } else if (input !== undefined) {
      await writeAuditLog(ctx, {
        actorType: 'admin',
        actorId: actorAdminId ?? undefined,
        action: 'status.incident.update',
        targetType: 'status_incident',
        targetId: id,
      });
    }
    return null;
  },
});

export const deleteIncident = internalMutation({
  args: { id: v.id('statusIncidents'), actorAdminId: v.optional(v.id('adminUsers')) },
  handler: async (ctx, { id, actorAdminId }) => {
    const row = await ctx.db.get(id);
    if (!row) throw new ConvexError({ code: 'not_found', message: 'incident not found' });
    await ctx.db.delete(id);
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'status.incident.delete',
      targetType: 'status_incident',
      targetId: id,
      payload: { title: row.title },
    });
    return null;
  },
});
