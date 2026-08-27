/**
 * Why a member is reporting a problem with their connection. A CLOSED set,
 * shared by the zod request contract, the HTTP validator, and the SPA's picker,
 * so the three can't drift — the same rule as ./switchServerReasons.ts.
 *
 * Deliberately not free text: the choice lands in the audit log (curated
 * scalars only) AND becomes a permanent aggregation key on the admin Telemetry
 * page, so every value here is a bucket operators will chart for years.
 * Adding one = add it here + a label in messages/en.json (`report.reason.*`).
 *
 * Zod-free on purpose — the Convex backend imports this and validates with its
 * own `v.*` validators (same pattern as ./backendIds.ts).
 */
export const REPORT_ISSUE_REASONS = [
  /** Can't establish a connection at all. */
  'cant-connect',
  /** Connects, but the speed is unusable. */
  'slow',
  /** Connects, then keeps dropping. */
  'disconnects',
  /** Connected, but a site or app won't load through the VPN. */
  'blocked-site',
  /** Trouble with the VPN app itself (import, UI, crashes). */
  'app-problem',
  'other',
] as const;

export type ReportIssueReason = (typeof REPORT_ISSUE_REASONS)[number];

export function isReportIssueReason(value: unknown): value is ReportIssueReason {
  return typeof value === 'string' && (REPORT_ISSUE_REASONS as readonly string[]).includes(value);
}
