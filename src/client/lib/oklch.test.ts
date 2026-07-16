import { describe, expect, test } from 'vitest';
import { parseOklch, oklchToRgb } from './oklch';

describe('parseOklch', () => {
  test('parses the declared token form', () => {
    expect(parseOklch('oklch(0.72 0.13 158)')).toEqual({ l: 0.72, c: 0.13, h: 158 });
    expect(parseOklch('  oklch(0.52 0.13 158) ')).toEqual({ l: 0.52, c: 0.13, h: 158 });
  });
  test('rejects non-oklch and malformed strings', () => {
    expect(parseOklch('#52b788')).toBeNull();
    expect(parseOklch('rgb(1,2,3)')).toBeNull();
    expect(parseOklch('')).toBeNull();
  });
});

describe('oklchToRgb', () => {
  test('anchors: white and black', () => {
    expect(oklchToRgb(1, 0, 0)).toEqual([255, 255, 255]);
    expect(oklchToRgb(0, 0, 0)).toEqual([0, 0, 0]);
  });
  test('the emerald brand hue lands in the green range (both theme steps)', () => {
    for (const l of [0.52, 0.72]) {
      const [r, g, b] = oklchToRgb(l, 0.13, 158);
      expect(g).toBeGreaterThan(r);
      expect(g).toBeGreaterThan(b);
      expect(b).toBeGreaterThan(r); // emerald leans teal, not lime
    }
  });
  test('achromatic stays neutral', () => {
    const [r, g, b] = oklchToRgb(0.5, 0, 0);
    expect(Math.abs(r - g)).toBeLessThanOrEqual(1);
    expect(Math.abs(g - b)).toBeLessThanOrEqual(1);
  });
  test('out-of-gamut clamps into 0–255', () => {
    for (const channel of oklchToRgb(0.7, 0.4, 30)) {
      expect(channel).toBeGreaterThanOrEqual(0);
      expect(channel).toBeLessThanOrEqual(255);
    }
  });
});
