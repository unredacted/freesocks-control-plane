import { z } from 'zod';

/**
 * Member issue telemetry: the member-facing consent context + the Admin →
 * Telemetry config and aggregation shapes. Telemetry rows are UNLINKED by
 * design (no user/subscription/IP) — see convex/lib/issueTelemetry.ts and
 * docs/privacy.md.
 */

/** GET /api/v1/account/telemetry-context: what the consent block should offer
 *  (which fields this deployment collects) and the CDN edge's current view of
 *  the member's network, as the editable prefill. */
export const TelemetryContextResponse = z.object({
  enabled: z.boolean(),
  fields: z.object({
    country: z.boolean(),
    city: z.boolean(),
    asn: z.boolean(),
  }),
  detected: z.object({
    country: z.string().nullable(),
    city: z.string().nullable(),
    asn: z.number().nullable(),
  }),
});
export type TelemetryContextResponse = z.infer<typeof TelemetryContextResponse>;

/** The member-edited values a consenting report/switch sends. Strings on the
 *  wire (the server sanitizes; ASN accepts "AS44244" style too). */
export interface TelemetryPayload {
  country: string | null;
  city: string | null;
  asn: string | null;
}

/** POST /api/v1/account/report-issue. */
export const ReportIssueResponse = z.object({ ok: z.boolean() });
export type ReportIssueResponse = z.infer<typeof ReportIssueResponse>;

// --- admin surface -------------------------------------------------------------

export const AdminDiagnosticsConfig = z.object({
  enabled: z.boolean(),
  cloudflareEnabled: z.boolean(),
  collectCountry: z.boolean(),
  collectCity: z.boolean(),
  collectAsn: z.boolean(),
  asnHeader: z.string(),
  retentionDays: z.number().int(),
});
export type AdminDiagnosticsConfig = z.infer<typeof AdminDiagnosticsConfig>;

const ReasonCount = z.object({ reason: z.string(), count: z.number().int() });
const DimensionRow = z.object({
  key: z.string(),
  count: z.number().int(),
  topReason: z.string().nullable(),
  /** Per-reason split for the stacked breakdown chart. Defaulted for skew. */
  byReason: z.record(z.string(), z.number().int()).optional().default({}),
});

/** GET /api/v1/admin/telemetry/summary?window=<ms> (or ?from=<ms>&to=<ms>). */
export const AdminTelemetrySummary = z.object({
  windowMs: z.number(),
  /** The resolved range the summary actually covers (server-clamped). */
  sinceMs: z.number().optional(),
  untilMs: z.number().optional(),
  /** Time-bucketed series for the charts (hourly for short ranges, else daily),
   *  aligned to the range start. Defaulted for skew. */
  bucketMs: z.number().optional(),
  buckets: z
    .array(
      z.object({
        start: z.number(),
        switch: z.number().int(),
        report: z.number().int(),
        byReason: z.record(z.string(), z.number().int()),
      }),
    )
    .optional()
    .default([]),
  totals: z.object({
    current: z.number().int(),
    previous: z.number().int(),
    switch: z.number().int(),
    report: z.number().int(),
    withTelemetry: z.number().int(),
    edited: z.number().int(),
  }),
  reasons: z.object({
    current: z.array(ReasonCount),
    previous: z.array(ReasonCount),
    switch: z.array(ReasonCount),
    report: z.array(ReasonCount),
  }),
  byLocation: z.array(DimensionRow),
  byCountry: z.array(DimensionRow),
  byAsn: z.array(DimensionRow),
  byMode: z.array(DimensionRow),
  byBackend: z.array(DimensionRow),
  truncated: z.boolean(),
});
export type AdminTelemetrySummary = z.infer<typeof AdminTelemetrySummary>;

/** GET /api/v1/admin/telemetry/events. */
export const AdminTelemetryEvents = z.object({
  events: z.array(
    z.object({
      id: z.string(),
      at: z.string(),
      kind: z.enum(['switch', 'report']),
      reason: z.string(),
      backend: z.string(),
      locationCode: z.string().nullable(),
      connectionModeId: z.string().nullable(),
      country: z.string().nullable(),
      city: z.string().nullable(),
      asn: z.number().nullable(),
      detectedCountry: z.string().nullable(),
      detectedCity: z.string().nullable(),
      detectedAsn: z.number().nullable(),
    }),
  ),
  nextCursor: z.string().nullable(),
});
export type AdminTelemetryEvents = z.infer<typeof AdminTelemetryEvents>;
