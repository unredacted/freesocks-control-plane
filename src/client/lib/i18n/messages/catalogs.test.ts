import { describe, expect, test } from 'vitest';
import { en, type MessageKey } from './en';
import { fa } from './fa';
import { ar } from './ar';
import { ru } from './ru';
import { zh } from './zh';

/**
 * Catalog parity. TypeScript already rejects unknown keys (Partial<Messages>),
 * but the Msg union does NOT reject a plain string where en has a function —
 * params would be silently ignored and the variable lost. These tests close
 * that hole and smoke-call every function entry so a template-literal typo
 * can't throw at render time.
 */
const CATALOGS = { fa, ar, ru, zh } as const;

/** Representative params covering every placeholder used across the catalogs. */
const SAMPLE_PARAMS: Record<string, string | number> = {
  count: 2,
  days: 3,
  tier: 'Member',
  label: 'Outline',
  to: 'Outline',
  from: 'Xray',
  backend: 'Xray',
  suffix: 'abc123',
  filename: 'freesocks-subscription.txt',
  amount: '1.2 GB',
  gb: 50,
  date: '2026-06-10',
};

describe('i18n catalogs', () => {
  for (const [name, catalog] of Object.entries(CATALOGS)) {
    test(`${name}: every key matches en's kind (string vs function)`, () => {
      for (const key of Object.keys(catalog) as MessageKey[]) {
        expect(en[key], `${name} has unknown key ${key}`).toBeDefined();
        expect(typeof catalog[key], `${name}:${key} kind differs from en`).toBe(typeof en[key]);
      }
    });

    test(`${name}: every function entry returns a non-empty string`, () => {
      for (const [key, entry] of Object.entries(catalog)) {
        if (typeof entry !== 'function') continue;
        const out = entry(SAMPLE_PARAMS);
        expect(typeof out, `${name}:${key} did not return a string`).toBe('string');
        expect(out.length, `${name}:${key} returned an empty string`).toBeGreaterThan(0);
      }
    });
  }

  test('en: every function entry returns a non-empty string (incl. count=1 branch)', () => {
    for (const [key, entry] of Object.entries(en)) {
      if (typeof entry !== 'function') continue;
      for (const count of [1, 2, 5, 21]) {
        const out = entry({ ...SAMPLE_PARAMS, count });
        expect(typeof out, `en:${key} (count=${count})`).toBe('string');
        expect(out.length, `en:${key} (count=${count})`).toBeGreaterThan(0);
      }
    }
  });
});
