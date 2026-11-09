/**
 * Countries -> Delivery: "Where members connect from" (pure; unit-tested).
 * The card edits its own settings and saves only those, in one
 * `PATCH /api/v1/admin/settings` (the route takes a partial bag), so it never
 * writes back a stale copy of anything else. Admin -> Settings leaves these
 * keys out of its own save for the same reason.
 *
 * Exports:
 *   DELIVERY_KEYS                      the settings the card owns
 *   DeliveryDraft                      the card's working copy
 *   deliveryDraft(settings)            the working copy from the settings bag (defaults filled)
 *   deliveryPatch(draft)               the PATCH body (only DELIVERY_KEYS)
 *   deliveryChanged(draft, settings)   whether the copy differs from what is stored
 *   parseExitRanges(text)              the textarea's ranges as a list (at most 64)
 *   withExitRow(rows, country, slots)  the exit rows with one country's row set (its page's Exit)
 *   withoutDeliveryKeys(bag)           a settings bag without DELIVERY_KEYS
 */
import { exitRows, type CountryExitRow } from '../../../../lib/countryExits';

export const DELIVERY_KEYS = [
  'delivery.country.detect',
  'delivery.country.ask',
  'delivery.country.steer',
  'delivery.country.latency',
  'delivery.country.stickyDays',
  'delivery.country.refreshHours',
  'delivery.country.ownExitRanges',
  'delivery.country.exits',
] as const;
export type DeliveryKey = (typeof DELIVERY_KEYS)[number];

/** The server's bounds (convex/appSettings.ts). */
export const STICKY_DAYS = { min: 1, max: 90, fallback: 30 } as const;
export const REFRESH_HOURS = { min: 1, max: 48, fallback: 6 } as const;
export const MAX_EXIT_RANGES = 64;

export interface DeliveryDraft {
  detect: boolean;
  ask: boolean;
  steer: boolean;
  latency: boolean;
  stickyDays: number;
  refreshHours: number;
  ownExitRanges: string[];
  exits: CountryExitRow[];
}

/** A whole number inside [min, max]; anything unreadable is the fallback. */
export function clampWhole(
  raw: unknown,
  b: { min: number; max: number; fallback: number },
): number {
  const n = Math.round(Number(raw));
  if (!Number.isFinite(n) || n === 0) return b.fallback;
  return Math.min(b.max, Math.max(b.min, n));
}

export function parseExitRanges(text: string): string[] {
  return text
    .split(/\s+/)
    .map((r) => r.trim())
    .filter((r) => r.length > 0)
    .slice(0, MAX_EXIT_RANGES);
}

export function deliveryDraft(s: Record<string, unknown> | undefined): DeliveryDraft {
  const bag = s ?? {};
  const ranges = bag['delivery.country.ownExitRanges'];
  return {
    detect: bag['delivery.country.detect'] === true,
    ask: bag['delivery.country.ask'] === true,
    steer: bag['delivery.country.steer'] === true,
    latency: bag['delivery.country.latency'] === true,
    stickyDays: clampWhole(bag['delivery.country.stickyDays'] ?? STICKY_DAYS.fallback, STICKY_DAYS),
    refreshHours: clampWhole(
      bag['delivery.country.refreshHours'] ?? REFRESH_HOURS.fallback,
      REFRESH_HOURS,
    ),
    ownExitRanges: Array.isArray(ranges)
      ? ranges.filter((r): r is string => typeof r === 'string')
      : [],
    exits: exitRows(bag['delivery.country.exits']),
  };
}

export function deliveryPatch(d: DeliveryDraft): Record<DeliveryKey, unknown> {
  return {
    'delivery.country.detect': d.detect,
    'delivery.country.ask': d.ask,
    'delivery.country.steer': d.steer,
    'delivery.country.latency': d.latency,
    'delivery.country.stickyDays': clampWhole(d.stickyDays, STICKY_DAYS),
    'delivery.country.refreshHours': clampWhole(d.refreshHours, REFRESH_HOURS),
    'delivery.country.ownExitRanges': d.ownExitRanges.slice(0, MAX_EXIT_RANGES),
    'delivery.country.exits': d.exits,
  };
}

export function deliveryChanged(d: DeliveryDraft, s: Record<string, unknown> | undefined): boolean {
  return JSON.stringify(deliveryPatch(d)) !== JSON.stringify(deliveryPatch(deliveryDraft(s)));
}

/**
 * The exit rows with one country's row replaced by `slots` (a country page's
 * Exit): its codes in order, without blanks or repeats, at its old place (or
 * at the end when new); a country left with none is dropped. Others untouched.
 */
export function withExitRow(
  rows: readonly CountryExitRow[],
  country: string,
  slots: readonly string[],
): CountryExitRow[] {
  const locations: string[] = [];
  for (const c of slots) if (c && !locations.includes(c)) locations.push(c);
  const at = rows.findIndex((r) => r.country === country);
  const others = rows.filter((r) => r.country !== country);
  if (locations.length === 0) return others;
  const row = { country, locations };
  if (at < 0) return [...others, row];
  return [...rows.slice(0, at), row, ...rows.slice(at + 1)];
}

export function withoutDeliveryKeys(bag: Record<string, unknown>): Record<string, unknown> {
  const out = { ...bag };
  for (const k of DELIVERY_KEYS) delete out[k];
  return out;
}
