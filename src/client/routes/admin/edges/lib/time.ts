/**
 * Small time helpers for the Edges section (pure, no Svelte).
 *
 * Exports:
 *   relativeTime(iso, now?)   '3 min ago' / 'in 2 h' / 'just now'; '' for null.
 *   durationLabel(ms)         '45 s', '3 min', '2 h 10 min', '3 d'.
 *   shortId(id, n?)           the last `n` (default 6) characters of an id for labels.
 */
const UNITS: Array<[ms: number, label: string]> = [
  [86_400_000, 'd'],
  [3_600_000, 'h'],
  [60_000, 'min'],
  [1_000, 's'],
];

export function durationLabel(ms: number): string {
  const abs = Math.abs(ms);
  if (abs < 1_000) return '0 s';
  for (let i = 0; i < UNITS.length; i++) {
    const [unit, label] = UNITS[i]!;
    if (abs >= unit) {
      const whole = Math.floor(abs / unit);
      const rest = abs - whole * unit;
      const next = UNITS[i + 1];
      // Two units for hours/minutes so "2 h 10 min" reads better than "2 h".
      if (next && (label === 'h' || label === 'd')) {
        const sub = Math.floor(rest / next[0]);
        if (sub > 0) return `${whole} ${label} ${sub} ${next[1]}`;
      }
      return `${whole} ${label}`;
    }
  }
  return `${Math.round(abs / 1000)} s`;
}

export function relativeTime(
  iso: string | number | Date | null | undefined,
  now: number = Date.now(),
): string {
  if (iso === null || iso === undefined) return '';
  const t = iso instanceof Date ? iso.getTime() : new Date(iso).getTime();
  if (Number.isNaN(t)) return String(iso);
  const diff = now - t;
  if (Math.abs(diff) < 10_000) return 'just now';
  return diff > 0 ? `${durationLabel(diff)} ago` : `in ${durationLabel(-diff)}`;
}

export function shortId(id: string | null | undefined, n = 6): string {
  if (!id) return '';
  return id.length <= n ? id : id.slice(-n);
}
