/**
 * Series/palette helpers for the Admin → Telemetry charts (LayerChart).
 *
 * Colors are CATEGORICAL identity: every reason owns a fixed palette slot, so
 * "blocked" is the same hue on every chart, every range, every filter (color
 * follows the entity, never its rank). The palette is a pre-validated 8-slot
 * categorical set (colorblind-safe on adjacent pairs in light AND dark mode -
 * the dark column is the same hues re-stepped for the dark surface, exposed as
 * the `--viz-s1..8` CSS variables the admin page defines for both themes).
 * Never append slots past 8: fold into 'other' instead.
 */
import type { AdminTelemetrySummary } from '../../shared/contracts/telemetry';

/** Fixed slot assignment (1-based → --viz-sN). Order = legend/stack order. */
export const REASON_SLOTS: readonly { reason: string; slot: number }[] = [
  { reason: 'blocked', slot: 1 },
  { reason: 'cant-connect', slot: 2 },
  { reason: 'slow', slot: 3 },
  { reason: 'disconnects', slot: 4 },
  { reason: 'blocked-site', slot: 5 },
  { reason: 'app-problem', slot: 6 },
  { reason: 'other', slot: 7 },
] as const;

/** The validated categorical palette (light / dark steps of the same hues). */
export const VIZ_PALETTE: readonly { light: string; dark: string }[] = [
  { light: '#2a78d6', dark: '#3987e5' }, // 1 blue
  { light: '#eb6834', dark: '#d95926' }, // 2 orange
  { light: '#1baf7a', dark: '#199e70' }, // 3 aqua
  { light: '#eda100', dark: '#c98500' }, // 4 yellow
  { light: '#e87ba4', dark: '#d55181' }, // 5 magenta
  { light: '#008300', dark: '#008300' }, // 6 green
  { light: '#4a3aa7', dark: '#9085e9' }, // 7 violet
  { light: '#e34948', dark: '#e66767' }, // 8 red
] as const;

export function reasonColor(reason: string): string {
  const slot = REASON_SLOTS.find((r) => r.reason === reason)?.slot ?? 8;
  return `var(--viz-s${slot})`;
}

/** The reasons present anywhere in the buckets, in FIXED slot order (an unknown
 *  future reason sorts last). Absent reasons stay out of the legend. */
export function presentReasons(buckets: AdminTelemetrySummary['buckets']): string[] {
  const seen = new Set<string>();
  for (const b of buckets) for (const r of Object.keys(b.byReason)) seen.add(r);
  const order = new Map(REASON_SLOTS.map((r) => [r.reason, r.slot]));
  return [...seen].sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99));
}

/** Chart rows for the over-time chart: one row per bucket with a preformatted
 *  band label and each reason/kind count flattened to a property. */
export function bucketRows(
  buckets: AdminTelemetrySummary['buckets'],
  bucketMs: number,
): Record<string, string | number>[] {
  const hourly = bucketMs < 86_400_000;
  return buckets.map((b) => ({
    label: new Date(b.start).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      ...(hourly ? { hour: 'numeric' } : {}),
    }),
    switch: b.switch,
    report: b.report,
    ...b.byReason,
  }));
}

/** Chart rows for the dimension breakdown: one row per key, reasons flattened. */
export function dimensionRows(
  rows: { key: string; count: number; byReason: Record<string, number> }[],
): Record<string, string | number>[] {
  return rows.map((r) => ({ key: r.key, ...r.byReason }));
}

/** Reasons present in a dimension's rows, fixed slot order. */
export function dimensionReasons(rows: { byReason: Record<string, number> }[]): string[] {
  const seen = new Set<string>();
  for (const r of rows) for (const k of Object.keys(r.byReason)) seen.add(k);
  const order = new Map(REASON_SLOTS.map((r) => [r.reason, r.slot]));
  return [...seen].sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99));
}
