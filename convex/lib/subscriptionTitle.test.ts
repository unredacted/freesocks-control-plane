/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from '../schema';
import { readFileSync } from 'node:fs';
import {
  BUILT_IN_FAMILY_NAMES_EN,
  BUILT_IN_MODE_NAMES_EN,
  DEFAULT_CONNECTION_MODES,
  DEFAULT_CONNECTION_MODE_FAMILIES,
} from './connectionModes';
import { memberSiteName } from './memberEntryNames';
import { modeTitleName, profileTitleValue, resolveSubscriptionSiteName } from './subscriptionTitle';

const modules = import.meta.glob('../**/*.*s');

describe('the subscription title', () => {
  test('the service name is one plain line, the one the connection labels carry', () => {
    expect(memberSiteName('  My  VPN\n')).toBe('My VPN');
    expect(memberSiteName('a,b|c\u0007d')).toBe('a b c d');
    expect(memberSiteName('x'.repeat(80))).toHaveLength(32);
    expect(memberSiteName('   ')).toBe('FreeSocks');
    // A lone surrogate half is dropped; a cut never splits a character.
    expect(memberSiteName('VPN \uD83D')).toBe('VPN');
    expect(memberSiteName('\uDE00ok')).toBe('ok');
    const emoji = '😀'.repeat(40);
    expect(Array.from(memberSiteName(emoji))).toHaveLength(32);
    expect(() => encodeURIComponent(memberSiteName(`${'a'.repeat(31)}😀`))).not.toThrow();
    expect(memberSiteName(7)).toBe('FreeSocks');
  });

  test('profile-title is the base64 form of the name, the default while unset', async () => {
    expect(profileTitleValue('')).toBe('base64:RnJlZVNvY2tz');
    expect(atob(profileTitleValue('VPN ✓').slice('base64:'.length))).toBe(
      String.fromCharCode(...new TextEncoder().encode('VPN ✓')),
    );
    const t = convexTest(schema, modules);
    expect(await t.run((ctx) => resolveSubscriptionSiteName(ctx.db))).toBe('FreeSocks');
    await t.run((ctx) =>
      ctx.db.insert('appSettings', {
        key: 'subscription.siteName',
        value: JSON.stringify(' Ours '),
        updatedAt: Date.now(),
      }),
    );
    expect(await t.run((ctx) => resolveSubscriptionSiteName(ctx.db))).toBe('Ours');
  });
});

describe("the connection mode's name in the title", () => {
  const fam = (id: string, label: string | null = null) => ({ id, label });
  const mode = (id: string, label: string | null = null) => ({ id, label });

  test('the built-in English names: the family, then the mode, as the picker names them', () => {
    expect(modeTitleName(mode('freedom-xhttp'), fam('freedom'))).toBe('Freedom XHTTP');
    expect(modeTitleName(mode('freedom-ws'), fam('freedom'))).toBe('Freedom WebSocket');
    expect(modeTitleName(mode('freedom-reality'), fam('freedom'))).toBe('Freedom REALITY');
    expect(modeTitleName(mode('privacy-reality'), fam('privacy'))).toBe('Privacy REALITY');
  });

  test('an admin\'s label wins (it is what members read in every locale); a family\'s "Mode" is left out', () => {
    expect(modeTitleName(mode('freedom-xhttp', 'Split HTTP'), fam('freedom'))).toBe(
      'Freedom Split HTTP',
    );
    expect(modeTitleName(mode('freedom-xhttp'), fam('freedom', 'Open Mode'))).toBe('Open XHTTP');
    // A mode label that already carries the family is not doubled.
    expect(modeTitleName(mode('freedom-xhttp', 'Freedom over HTTP'), fam('freedom'))).toBe(
      'Freedom over HTTP',
    );
    // An admin-created mode with no label (deploy skew): its slug, readable.
    expect(modeTitleName(mode('extra-fast'), fam('custom'))).toBe('Extra Fast');
    expect(modeTitleName(mode('a,b'), null)).toBe('A b');
  });

  test("the English names follow the SPA's English copy", () => {
    const en = JSON.parse(readFileSync('messages/en.json', 'utf8')) as {
      delivery: Record<string, string>;
    };
    const delivery = en.delivery;
    const titleKey = (slug: string) =>
      `${slug.replace(/-([a-z])/g, (_, c: string) => c.toUpperCase())}Title`;
    for (const f of DEFAULT_CONNECTION_MODE_FAMILIES)
      expect(`${BUILT_IN_FAMILY_NAMES_EN[f.slug]} Mode`, f.slug).toBe(delivery[titleKey(f.slug)]);
    for (const m of DEFAULT_CONNECTION_MODES)
      expect(BUILT_IN_MODE_NAMES_EN[m.slug], m.slug).toBe(delivery[titleKey(m.slug)]);
  });
});
