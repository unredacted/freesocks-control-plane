/**
 * Why a member is moving their key to a different server. A CLOSED set, shared by
 * the zod request contract, the HTTP validator, and the SPA's picker, so the
 * three can't drift.
 *
 * A fixed set lets operators count which nodes members leave and why. Only
 * in-place switches contribute diagnostics.
 *
 * Zod-free on purpose — the Convex backend imports this and validates with its
 * own `v.*` validators (same pattern as ./backendIds.ts).
 */
export const SWITCH_SERVER_REASONS = ['slow', 'blocked', 'disconnects', 'other'] as const;

export type SwitchServerReason = (typeof SWITCH_SERVER_REASONS)[number];

export function isSwitchServerReason(value: unknown): value is SwitchServerReason {
  return typeof value === 'string' && (SWITCH_SERVER_REASONS as readonly string[]).includes(value);
}
