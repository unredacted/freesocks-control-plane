/// <reference types="vite/client" />
/**
 * i18n catalog integrity (replaces the old hand-written catalogs.test.ts).
 * Paraglide guarantees locale key-parity at compile + auto-falls-back missing
 * translations to the base locale, so this just guards the contract between the
 * base catalog (messages/en.json) and the compiled output: every key resolves to
 * a callable message returning a non-empty string, and the dynamic `t()`-style
 * lookup by the original dotted id works (the shim relies on it).
 *
 * Requires the Paraglide output (gitignored) — `bun run test` compiles it first.
 */
import { describe, expect, test } from 'vitest';
import { m } from '../../../lib/paraglide/messages.js';
import en from '../../../../messages/en.json';

type MsgFn = (i?: Record<string, unknown>, o?: { locale?: string }) => string;
const messages = m as unknown as Record<string, MsgFn>;

// The inlang store is nested; flatten to the dotted message ids Paraglide exports.
function flattenKeys(obj: Record<string, unknown>, prefix = ''): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (!prefix && k === '$schema') continue;
    const full = prefix ? `${prefix}.${k}` : k;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      out.push(...flattenKeys(v as Record<string, unknown>, full));
    } else {
      out.push(full);
    }
  }
  return out;
}

// Covers every placeholder used across the catalog so interpolated messages
// render a non-empty string regardless of which params they read.
const SAMPLE = {
  count: 2,
  days: 1,
  devices: '1 device',
  months: 1,
  pct: 1,
  tier: 'Member',
  label: 'Outline',
  to: 'Outline',
  from: 'Xray',
  backend: 'Xray',
  suffix: 'abc123',
  filename: 'f.txt',
  amount: '1.2 GB',
  gb: 50,
  date: '2026-06-10',
  price: '$5',
};

describe('paraglide messages', () => {
  test('every base-catalog key compiles to a callable, non-empty message', () => {
    const keys = flattenKeys(en as Record<string, unknown>);
    expect(keys.length).toBeGreaterThan(200);
    for (const key of keys) {
      const fn = messages[key];
      expect(typeof fn, `missing compiled message for "${key}"`).toBe('function');
      const out = fn!(SAMPLE, { locale: 'en' });
      expect(typeof out, `"${key}" did not return a string`).toBe('string');
      expect(out.length, `"${key}" returned empty`).toBeGreaterThan(0);
    }
  });

  test('plural messages render distinct one/other forms', () => {
    expect(messages['common.deviceCount']!({ count: 1 }, { locale: 'en' })).toBe('1 device');
    expect(messages['common.deviceCount']!({ count: 5 }, { locale: 'en' })).toContain('5');
  });

  test('a non-base locale resolves (translated or base fallback)', () => {
    const out = messages['nav.signIn']!({}, { locale: 'fa' });
    expect(typeof out).toBe('string');
    expect(out.length).toBeGreaterThan(0);
  });
});
