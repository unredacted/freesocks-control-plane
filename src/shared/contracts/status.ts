import { z } from 'zod';

/**
 * Public network-status contracts (`GET /api/v1/status` + the admin
 * `/api/v1/admin/status/*` editor surface). Everything public-safe: location
 * codes/labels and coarse load BANDS only — never raw user counts.
 */

export const LoadBand = z.enum(['quiet', 'busy', 'crowded', 'unknown']);
export type LoadBand = z.infer<typeof LoadBand>;

export const StatusLocation = z.object({
  code: z.string(),
  label: z.string(),
  online: z.boolean(),
  // Coarse load band only — exact per-location node counts are internal
  // (the bands-only posture; never raw fleet-size figures).
  load: LoadBand,
});
export type StatusLocation = z.infer<typeof StatusLocation>;

export const CensorshipCell = z.enum(['available', 'partial', 'blocked']);
export type CensorshipCell = z.infer<typeof CensorshipCell>;

export const CensorshipRow = z.object({
  countryCode: z.string().length(2),
  label: z.string().nullable(),
  cells: z.record(z.string(), CensorshipCell),
});
export type CensorshipRow = z.infer<typeof CensorshipRow>;

export const StatusIncident = z.object({
  id: z.string(),
  title: z.string(),
  body: z.string().nullable(),
  severity: z.enum(['maintenance', 'degraded', 'outage']),
  /** Empty = global (all locations). */
  locationCodes: z.array(z.string()),
  startedAt: z.number(),
  resolvedAt: z.number().nullable(),
});
export type StatusIncident = z.infer<typeof StatusIncident>;

export const PublicStatusResponse = z.object({
  generatedAt: z.string(),
  locations: z.array(StatusLocation),
  censorship: z.object({
    modes: z.array(z.object({ id: z.string(), label: z.string().nullable() })),
    rows: z.array(CensorshipRow),
  }),
  incidents: z.array(StatusIncident),
});
export type PublicStatusResponse = z.infer<typeof PublicStatusResponse>;

// --- admin editor surface ---------------------------------------------------

export const AdminStatusPageConfig = z.object({
  busyAt: z.number().int().positive(),
  crowdedAt: z.number().int().positive(),
  rows: z.array(CensorshipRow),
});
export type AdminStatusPageConfig = z.infer<typeof AdminStatusPageConfig>;

export const AdminStatusIncidentsResponse = z.object({
  incidents: z.array(StatusIncident),
});
export type AdminStatusIncidentsResponse = z.infer<typeof AdminStatusIncidentsResponse>;

export const AdminStatusIncidentCreateResponse = z.object({
  id: z.string(),
});
export type AdminStatusIncidentCreateResponse = z.infer<typeof AdminStatusIncidentCreateResponse>;
