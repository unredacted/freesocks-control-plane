/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from '../schema';
import {
  profileTitleValue,
  resolveSubscriptionSiteName,
  subscriptionSiteName,
} from './subscriptionTitle';

const modules = import.meta.glob('../**/*.*s');

describe('the subscription title', () => {
  test('the service name is one plain line, cleaned like the connection labels', () => {
    expect(subscriptionSiteName('  My  VPN\n')).toBe('My VPN');
    expect(subscriptionSiteName('a,b|c\u0007d')).toBe('a b c d');
    expect(subscriptionSiteName('x'.repeat(80))).toHaveLength(32);
    expect(subscriptionSiteName('   ')).toBe('FreeSocks');
    // A lone surrogate half is dropped; a cut never splits a character.
    expect(subscriptionSiteName('VPN \uD83D')).toBe('VPN');
    expect(subscriptionSiteName('\uDE00ok')).toBe('ok');
    const emoji = '😀'.repeat(40);
    expect(Array.from(subscriptionSiteName(emoji))).toHaveLength(32);
    expect(() => encodeURIComponent(subscriptionSiteName(`${'a'.repeat(31)}😀`))).not.toThrow();
    expect(subscriptionSiteName(7)).toBe('FreeSocks');
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
