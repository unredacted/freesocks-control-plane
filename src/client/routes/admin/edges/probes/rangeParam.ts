/**
 * The Probes page keeps its chart range in `?range`. Pure encode/decode so a
 * reload (or a shared link) restores the same view:
 *   ''            the default, the trailing 7 days (clean address)
 *   '24h' | '7d' | '30d' | '90d'   a trailing-window preset
 *   'w<ms>'       any other trailing window
 *   '<fromMs>-<toMs>'   a custom from/to range (epoch milliseconds)
 * Anything unreadable decodes to the default.
 */
import type { ProbeRange } from '../../../../lib/edgesApi';

const DAY = 86_400_000;
const PRESETS: Record<string, number> = {
  '24h': DAY,
  '7d': 7 * DAY,
  '30d': 30 * DAY,
  '90d': 90 * DAY,
};

const DEFAULT_WINDOW_MS = 7 * DAY;
export const DEFAULT_PROBE_RANGE: ProbeRange = { kind: 'window', windowMs: DEFAULT_WINDOW_MS };

export function encodeProbeRange(range: ProbeRange): string {
  if (range.kind === 'range') return `${range.fromMs}-${range.toMs}`;
  if (range.windowMs === DEFAULT_WINDOW_MS) return '';
  const preset = Object.entries(PRESETS).find(([, ms]) => ms === range.windowMs);
  return preset ? preset[0] : `w${range.windowMs}`;
}

export function decodeProbeRange(raw: string | null | undefined): ProbeRange {
  const s = (raw ?? '').trim();
  if (!s) return DEFAULT_PROBE_RANGE;
  const preset = PRESETS[s];
  if (preset !== undefined) return { kind: 'window', windowMs: preset };
  const w = /^w(\d{1,15})$/.exec(s);
  if (w) {
    const windowMs = Number(w[1]);
    return windowMs > 0 ? { kind: 'window', windowMs } : DEFAULT_PROBE_RANGE;
  }
  const r = /^(\d{1,15})-(\d{1,15})$/.exec(s);
  if (r) {
    const fromMs = Number(r[1]);
    const toMs = Number(r[2]);
    if (toMs > fromMs) return { kind: 'range', fromMs, toMs };
  }
  return DEFAULT_PROBE_RANGE;
}
