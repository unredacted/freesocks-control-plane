/**
 * Member issue telemetry: recording (switch-server rides along, report-issue is
 * its own flow), the admin `diagnostics.*` config surface, the Admin → Telemetry
 * aggregations, and the retention sweep. Rows are UNLINKED by design — see the
 * schema note on `issueReports` and docs/privacy.md.
 */
import { internalMutation, internalQuery } from './_generated/server';
import type { Doc } from './_generated/dataModel';
import { v } from 'convex/values';
import { writeAuditLog } from './lib/audit';
import { currentOrActiveSub } from './subscriptions';
import {
  DIAGNOSTICS_KEYS,
  resolveDiagnosticsConfig,
  sanitizeAsnHeader,
  sanitizeRetentionDays,
  type DiagnosticsConfig,
} from './lib/issueTelemetry';

const DAY_MS = 86_400_000;

// The most rows one summary computation will read (current + previous window
// combined). Far above realistic volume; if a deployment ever hits it the
// response says so (`truncated`) instead of silently under-counting.
const SUMMARY_SCAN_CAP = 20_000;

const telemetryFields = {
  country: v.optional(v.union(v.string(), v.null())),
  city: v.optional(v.union(v.string(), v.null())),
  asn: v.optional(v.union(v.number(), v.null())),
};

/** Insert one telemetry row. Values arrive PRE-SANITIZED (lib/issueTelemetry in
 *  the HTTP layer); this re-checks only the master switch so a disabled
 *  deployment records nothing even if a caller forgets to gate. */
export const record = internalMutation({
  args: {
    kind: v.union(v.literal('switch'), v.literal('report')),
    reason: v.string(),
    backend: v.string(),
    locationCode: v.optional(v.union(v.string(), v.null())),
    nodeLabel: v.optional(v.union(v.string(), v.null())),
    connectionModeId: v.optional(v.union(v.string(), v.null())),
    ...telemetryFields,
    detectedCountry: v.optional(v.union(v.string(), v.null())),
    detectedCity: v.optional(v.union(v.string(), v.null())),
    detectedAsn: v.optional(v.union(v.number(), v.null())),
  },
  handler: async (ctx, a): Promise<void> => {
    const cfg = await resolveDiagnosticsConfig(ctx.db);
    if (!cfg.enabled) return;
    const opt = <T>(x: T | null | undefined): T | undefined => (x === null ? undefined : x);
    await ctx.db.insert('issueReports', {
      kind: a.kind,
      reason: a.reason,
      backend: a.backend,
      locationCode: opt(a.locationCode),
      nodeLabel: opt(a.nodeLabel),
      connectionModeId: opt(a.connectionModeId),
      country: opt(a.country),
      city: opt(a.city),
      asn: opt(a.asn),
      detectedCountry: opt(a.detectedCountry),
      detectedCity: opt(a.detectedCity),
      detectedAsn: opt(a.detectedAsn),
    });
  },
});

/**
 * The report-issue flow: resolve the member's live key server-side (backend +
 * location + mode are NEVER client-claimed), insert the telemetry row, and
 * audit the reason against the user — the per-user record stays reason-only,
 * exactly like switch-server. Reporting changes nothing about the key.
 */
export const reportIssue = internalMutation({
  args: {
    userId: v.id('users'),
    reason: v.string(),
    ...telemetryFields,
    detectedCountry: v.optional(v.union(v.string(), v.null())),
    detectedCity: v.optional(v.union(v.string(), v.null())),
    detectedAsn: v.optional(v.union(v.number(), v.null())),
    requestId: v.optional(v.string()),
  },
  handler: async (ctx, a): Promise<{ ok: boolean }> => {
    const user = await ctx.db.get(a.userId);
    if (!user) return { ok: false };
    const sub = await currentOrActiveSub(ctx.db, user);
    // No key: still a valid report (e.g. "can't connect" before first issue
    // would be odd, but a tombstone-grace member is real) — recorded without
    // node context.
    const server = sub?.backendServerId ? await ctx.db.get(sub.backendServerId) : null;
    const cfg = await resolveDiagnosticsConfig(ctx.db);
    if (cfg.enabled) {
      const opt = <T>(x: T | null | undefined): T | undefined => (x === null ? undefined : x);
      await ctx.db.insert('issueReports', {
        kind: 'report',
        reason: a.reason,
        backend: sub?.backend ?? 'none',
        locationCode: server?.location ?? undefined,
        nodeLabel: undefined,
        connectionModeId: user.connectionModeId ?? undefined,
        country: opt(a.country),
        city: opt(a.city),
        asn: opt(a.asn),
        detectedCountry: opt(a.detectedCountry),
        detectedCity: opt(a.detectedCity),
        detectedAsn: opt(a.detectedAsn),
      });
    }
    await writeAuditLog(ctx, {
      actorType: 'member',
      actorId: a.userId,
      action: 'subscription.issue_reported',
      targetType: sub ? 'subscription' : 'user',
      targetId: sub ? sub._id : a.userId,
      payload: { reason: a.reason, backend: sub?.backend ?? 'none' },
      requestId: a.requestId,
    });
    return { ok: true };
  },
});

// --- admin config -------------------------------------------------------------

export const getConfig = internalQuery({
  args: {},
  handler: (ctx): Promise<DiagnosticsConfig> => resolveDiagnosticsConfig(ctx.db),
});

export const setConfig = internalMutation({
  args: {
    enabled: v.boolean(),
    cloudflareEnabled: v.boolean(),
    collectCountry: v.boolean(),
    collectCity: v.boolean(),
    collectAsn: v.boolean(),
    asnHeader: v.string(),
    retentionDays: v.number(),
    // Optional: a token-authed admin has no adminUsers row to attribute.
    actorAdminId: v.optional(v.id('adminUsers')),
  },
  handler: async (ctx, a): Promise<DiagnosticsConfig> => {
    const clean: DiagnosticsConfig = {
      enabled: a.enabled,
      cloudflareEnabled: a.cloudflareEnabled,
      collectCountry: a.collectCountry,
      collectCity: a.collectCity,
      collectAsn: a.collectAsn,
      asnHeader: sanitizeAsnHeader(a.asnHeader),
      retentionDays: sanitizeRetentionDays(a.retentionDays),
    };
    const now = Date.now();
    for (const [field, key] of Object.entries(DIAGNOSTICS_KEYS)) {
      const value = JSON.stringify(clean[field as keyof DiagnosticsConfig]);
      const row = await ctx.db
        .query('appSettings')
        .withIndex('by_key', (q) => q.eq('key', key))
        .unique();
      if (row) await ctx.db.patch(row._id, { value, updatedAt: now });
      else await ctx.db.insert('appSettings', { key, value, updatedAt: now });
    }
    await writeAuditLog(ctx, {
      actorType: 'admin',
      actorId: a.actorAdminId ?? undefined,
      action: 'admin.diagnostics.change',
      targetType: 'app_settings',
      payload: { ...clean },
    });
    return clean;
  },
});

// --- admin aggregation ----------------------------------------------------------

interface ReasonCount {
  reason: string;
  count: number;
}
interface DimensionRow {
  key: string;
  count: number;
  topReason: string | null;
}

function countBy<T>(rows: T[], keyOf: (r: T) => string | null): Map<string, number> {
  const m = new Map<string, number>();
  for (const r of rows) {
    const k = keyOf(r);
    if (k === null) continue;
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return m;
}

/** Top-N of a dimension, each with its dominant reason (the "why" behind the
 *  "where"). Null keys (field not shared) are skipped, not bucketed — an
 *  'unknown' bar would just chart consent rates. */
function dimension(
  rows: Doc<'issueReports'>[],
  keyOf: (r: Doc<'issueReports'>) => string | null,
  topN = 10,
): DimensionRow[] {
  const totals = countBy(rows, keyOf);
  return [...totals.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([key, count]) => {
      const reasons = countBy(
        rows.filter((r) => keyOf(r) === key),
        (r) => r.reason,
      );
      const top = [...reasons.entries()].sort((a, b) => b[1] - a[1])[0];
      return { key, count, topReason: top ? top[0] : null };
    });
}

/**
 * The Admin → Telemetry aggregation: totals by reason for the CURRENT range,
 * the same for the PREVIOUS equal-length range (trending = the client renders
 * the delta), and top-N breakdowns by node location, country, ASN, connection
 * mode, and backend. One bounded index scan over 2×range, all math in JS — at
 * this table's realistic volume that is far cheaper than maintaining counters.
 *
 * Range selection: an explicit [sinceMs, untilMs) pair when given (the admin's
 * custom date range), else the trailing `windowMs` ending now. Span clamped to
 * [1h, 366d] — the retention sweep bounds how far back data exists anyway.
 */
export const summary = internalQuery({
  args: {
    windowMs: v.optional(v.number()),
    sinceMs: v.optional(v.number()),
    untilMs: v.optional(v.number()),
  },
  handler: async (ctx, a) => {
    const now = Date.now();
    const MIN_SPAN = 3_600_000;
    const MAX_SPAN = 366 * DAY_MS;
    let since: number;
    let until: number;
    if (a.sinceMs !== undefined && Number.isFinite(a.sinceMs)) {
      since = a.sinceMs;
      until = a.untilMs !== undefined && Number.isFinite(a.untilMs) ? a.untilMs : now;
      if (until <= since) until = since + MIN_SPAN;
      if (until - since > MAX_SPAN) until = since + MAX_SPAN;
    } else {
      const w = Math.min(Math.max(a.windowMs ?? 7 * DAY_MS, MIN_SPAN), MAX_SPAN);
      until = now;
      since = now - w;
    }
    const w = until - since;
    const prevSince = since - w;
    const rows = await ctx.db
      .query('issueReports')
      .withIndex('by_creation_time', (q) => q.gte('_creationTime', prevSince))
      .order('desc')
      .take(SUMMARY_SCAN_CAP);
    const current = rows.filter((r) => r._creationTime >= since && r._creationTime < until);
    const previous = rows.filter((r) => r._creationTime < since);

    const reasonRows = (set: Doc<'issueReports'>[]): ReasonCount[] =>
      [...countBy(set, (r) => r.reason).entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([reason, count]) => ({ reason, count }));

    const withTelemetry = current.filter(
      (r) => r.country !== undefined || r.city !== undefined || r.asn !== undefined,
    ).length;
    // "Edited" = the member changed at least one prefilled value before sending
    // (or the CDN saw nothing and they typed it in) — the dirty-data tell.
    const edited = current.filter(
      (r) =>
        (r.country !== undefined && r.country !== r.detectedCountry) ||
        (r.city !== undefined && r.city !== r.detectedCity) ||
        (r.asn !== undefined && r.asn !== r.detectedAsn),
    ).length;

    return {
      windowMs: w,
      sinceMs: since,
      untilMs: until,
      totals: {
        current: current.length,
        previous: previous.length,
        switch: current.filter((r) => r.kind === 'switch').length,
        report: current.filter((r) => r.kind === 'report').length,
        withTelemetry,
        edited,
      },
      reasons: {
        current: reasonRows(current),
        previous: reasonRows(previous),
        switch: reasonRows(current.filter((r) => r.kind === 'switch')),
        report: reasonRows(current.filter((r) => r.kind === 'report')),
      },
      byLocation: dimension(current, (r) => r.locationCode ?? r.nodeLabel ?? null),
      byCountry: dimension(current, (r) => r.country ?? null),
      byAsn: dimension(current, (r) => (r.asn !== undefined ? `AS${r.asn}` : null)),
      byMode: dimension(current, (r) => r.connectionModeId ?? null),
      byBackend: dimension(current, (r) => r.backend),
      truncated: rows.length >= SUMMARY_SCAN_CAP,
    };
  },
});

/** Recent raw rows (they are unlinked, so listing them is safe), newest first. */
export const recent = internalQuery({
  args: { cursor: v.optional(v.string()), limit: v.optional(v.number()) },
  handler: async (ctx, { cursor, limit }) => {
    const pageSize = Math.min(Math.max(limit ?? 50, 1), 200);
    const res = await ctx.db
      .query('issueReports')
      .order('desc')
      .paginate({ cursor: cursor ?? null, numItems: pageSize });
    return {
      events: res.page.map((r) => ({
        id: r._id as string,
        at: new Date(r._creationTime).toISOString(),
        kind: r.kind,
        reason: r.reason,
        backend: r.backend,
        locationCode: r.locationCode ?? null,
        connectionModeId: r.connectionModeId ?? null,
        country: r.country ?? null,
        city: r.city ?? null,
        asn: r.asn ?? null,
        detectedCountry: r.detectedCountry ?? null,
        detectedCity: r.detectedCity ?? null,
        detectedAsn: r.detectedAsn ?? null,
      })),
      nextCursor: res.isDone ? null : res.continueCursor,
    };
  },
});

/** Daily retention sweep: bounded delete of rows past `retentionDays`. */
export const sweep = internalMutation({
  args: {},
  handler: async (ctx): Promise<{ deleted: number }> => {
    const cfg = await resolveDiagnosticsConfig(ctx.db);
    const cutoff = Date.now() - cfg.retentionDays * DAY_MS;
    const stale = await ctx.db
      .query('issueReports')
      .withIndex('by_creation_time', (q) => q.lt('_creationTime', cutoff))
      .take(500);
    for (const row of stale) await ctx.db.delete(row._id);
    return { deleted: stale.length };
  },
});
