/**
 * Resolve the oklch() theme tokens to sRGB for canvas painting. Canvas
 * `fillStyle` silently ignores oklch() on the older engines this audience
 * realistically runs (Chrome <111 / Safari <16.4 - the documented QrCode
 * gotcha), so anything drawn on a <canvas> that should track the brand hue
 * must convert in JS instead. Pure functions (unit-testable); the browser
 * read lives in `resolvePrimaryRgb`.
 */

export type Rgb = [number, number, number];

/** Parse an `oklch(L C H)` string (the token's declared form). */
export function parseOklch(css: string): { l: number; c: number; h: number } | null {
  const m = /oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)(?:\s*\/\s*[\d.]+%?)?\s*\)/i.exec(css.trim());
  if (!m) return null;
  return { l: parseFloat(m[1]!), c: parseFloat(m[2]!), h: parseFloat(m[3]!) };
}

/** OKLCH → sRGB (Björn Ottosson's matrices), channels clamped to 0–255. */
export function oklchToRgb(l: number, c: number, h: number): Rgb {
  const hr = (h * Math.PI) / 180;
  const a = c * Math.cos(hr);
  const b = c * Math.sin(hr);
  const l_ = l + 0.3963377774 * a + 0.2158037573 * b;
  const m_ = l - 0.1055613458 * a - 0.0638541728 * b;
  const s_ = l - 0.0894841775 * a - 1.291485548 * b;
  const l3 = l_ ** 3;
  const m3 = m_ ** 3;
  const s3 = s_ ** 3;
  const toSrgb = (x: number) => {
    const v = x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055;
    return Math.round(Math.min(1, Math.max(0, v)) * 255);
  };
  return [
    toSrgb(+4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3),
    toSrgb(-1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3),
    toSrgb(-0.0041960863 * l3 - 0.7034186147 * m3 + 1.707614701 * s3),
  ];
}

/** The current `--primary` token as sRGB (honors .dark + the admin hue
 *  override, since both redeclare the token). Null when unavailable/invalid -
 *  callers fall back to a fixed hex. */
export function resolvePrimaryRgb(): Rgb | null {
  if (typeof getComputedStyle === 'undefined' || typeof document === 'undefined') return null;
  const raw = getComputedStyle(document.documentElement).getPropertyValue('--primary');
  const parsed = parseOklch(raw);
  return parsed ? oklchToRgb(parsed.l, parsed.c, parsed.h) : null;
}
