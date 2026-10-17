/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from '../schema';
import { memberSiteName } from './memberEntryNames';
import { profileTitleValue, resolveSubscriptionSiteName } from './subscriptionTitle';

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
