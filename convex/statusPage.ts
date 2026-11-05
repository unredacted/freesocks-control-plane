/**
 * Network-status page — registered wrappers over the pure projection in
 * lib/statusPage.ts. `getPublic` feeds the unauthenticated GET /api/v1/status
 * route; the admin functions back the CMS Status page (incidents + the
 * censorship matrix in the `status.*` namespace). Load bands need no config:
 * they come from the nodes' CPU load (lib/loadBands).
 */
import { internalMutation, internalQuery } from './_generated/server';
import { ConvexError, v } from 'convex/values';
import { upsertSettingRow } from './appSettings';
import { writeAuditLog } from './lib/audit';
import { resolveCensoredCountries } from './lib/censoredCountries';
import {
  mergeCensorshipRows,
  resolvePublicStatusPage,
  resolveLocationLoad,
  resolveStatusConfig,
  resolveValidModeIds,
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

/**
 * Current page config for the admin editor (sanitized, fail-safe). `countries`
 * is the censored-country list: the editor shows one row per listed country,
 * in that order; `rows` holds every stored row, listed or not.
 */
export const getPageConfig = internalQuery({
  args: {},
  handler: async (ctx) => {
    const [cfg, censored] = await Promise.all([
      resolveStatusConfig(ctx.db),
      resolveCensoredCountries(ctx.db),
    ]);
    return {
      rows: cfg.censorshipRows,
      countries: censored.codes,
    };
  },
});

/**
 * Admin sets the censorship matrix. `rows` replaces the full matrix (the
 * editor always submits the whole grid).
 */
export const setPageConfig = internalMutation({
  args: {
    rows: v.optional(v.any()),
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, { rows, actorAdminId }) => {
    if (rows === undefined) {
      throw new ConvexError({ code: 'validation', message: 'no recognized status-page fields' });
    }
    const valid = await resolveValidModeIds(ctx.db);
    const [current, censored] = await Promise.all([
      resolveStatusConfig(ctx.db),
      resolveCensoredCountries(ctx.db),
    ]);
    // The editor shows only listed countries; rows of countries that left the
    // list are kept (re-adding the country brings its row back).
    const clean = sanitizeCensorshipRows(
      {
        rows: mergeCensorshipRows(
          sanitizeCensorshipRows({ rows }, valid),
          current.censorshipRows,
          censored.codes,
        ),
      },
      valid,
    );
    await upsertSettingRow(
      ctx,
      STATUS_KEYS.censorship,
      JSON.stringify({ rows: clean }),
      actorAdminId,
    );
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: actorAdminId ?? undefined,
      action: 'status.page.update',
      targetType: 'status_page',
      payload: { censorshipRows: clean.length },
    });
    const cfg = await resolveStatusConfig(ctx.db);
    return {
      rows: cfg.censorshipRows,
      countries: censored.codes,
    };
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
