import { describe, expect, test } from 'vitest';
import en from '../../../messages/en.json';
import { DEFAULT_CONNECTION_MODES } from '../../../convex/lib/connectionModes';
import {
  MODE_COPY,
  adminFamilyName,
  adminModeFullName,
  adminModeName,
  modeBody,
  modeTitle,
} from './connectionModeCopy';

/** A dotted message key's English text, or undefined. */
function english(key: string): unknown {
  return key.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown>)?.[k], en);
}

describe('built-in connection mode copy', () => {
  test('every built-in mode has a title and a body in English (no humanized slug in the picker)', () => {
    for (const m of DEFAULT_CONNECTION_MODES) {
      const copy = MODE_COPY[m.slug];
      expect(copy, m.slug).toBeDefined();
      for (const key of [copy!.titleKey, copy!.bodyKey, copy!.rawConfigBodyKey].filter(Boolean))
        expect(typeof english(key!), `${m.slug}: ${key}`).toBe('string');
    }
  });

  test('the XHTTP mode says which apps cannot use it, in plain words without em-dashes', () => {
    const m = { id: 'freedom-xhttp', deliveryStyle: 'url' as const };
    expect(modeTitle(m)).toBe('XHTTP');
    const body = modeBody(m);
    expect(body).toMatch(/sing-box/);
    expect(body).toMatch(/Karing/);
    expect(body).not.toMatch(/—/);
  });
});

describe('adminModeFullName', () => {
  const families = [
    { id: 'freedom', label: null },
    { id: 'privacy', label: null },
  ];

  test('two REALITY modes read apart by their family', () => {
    const freedom = adminModeFullName({ id: 'freedom-reality', family: 'freedom' }, families);
    const privacy = adminModeFullName({ id: 'privacy-reality', family: 'privacy' }, families);
    expect(freedom).not.toBe(privacy);
    expect(freedom).toBe(
      `${adminFamilyName(families[0]!)} · ${adminModeName({ id: 'freedom-reality' })}`,
    );
  });

  test('an admin label wins on both sides, and one naming its family is kept as it is', () => {
    const fams = [{ id: 'freedom', label: 'Beat censorship' }];
    expect(adminModeFullName({ id: 'x', family: 'freedom', label: 'REALITY' }, fams)).toBe(
      'Beat censorship · REALITY',
    );
    expect(
      adminModeFullName({ id: 'x', family: 'freedom', label: 'Beat censorship fast' }, fams),
    ).toBe('Beat censorship fast');
  });

  test('a mode with no family, or a family not in the list, still gets a name', () => {
    expect(adminModeFullName({ id: 'solo-mode' }, [])).toBe(adminModeName({ id: 'solo-mode' }));
    expect(adminModeFullName({ id: 'x', family: 'new-family', label: 'Fast' }, [])).toBe(
      'New Family · Fast',
    );
  });
});
