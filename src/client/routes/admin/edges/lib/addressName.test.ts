import { describe, expect, test } from 'vitest';
import type { EdgeAddressName } from '../../../../../shared/contracts/edges';
import { FIRST_NAME_WORDS, firstNameOffer } from './addressName';

const EDGE = {
  layer: 'l4' as const,
  managed: true,
  status: 'active',
  addresses: { v4: '192.0.2.10', v6: null, hostname: null },
};
type Settings = NonNullable<Parameters<typeof firstNameOffer>[2]>;
// Only the fields the offer reads (the full config view is much larger).
const settings = (names: { enabled?: boolean; zones?: string[] } = {}): Settings =>
  ({
    config: { names: { enabled: true, zones: ['zone-a'], moveQuietDays: 30, ...names } },
    nameZones: [{ id: 'zone-a', zone: 'example.org', account: 'DNS' }],
  }) as unknown as Settings;
const ON = settings();
const NAME: EdgeAddressName = {
  fqdn: 'quiet-river.example.org',
  state: 'live',
  zoneLocationId: 'zone-a',
  moves: 0,
  movedAt: null,
  movedHere: false,
  failure: null,
  stuck: false,
};

describe('firstNameOffer', () => {
  test('an active address FCP owns with an IPv4 and no name is offered one', () => {
    expect(firstNameOffer(EDGE, null, ON)).toBe('offer');
  });

  test('an address with a name gets the New name section instead', () => {
    expect(firstNameOffer(EDGE, NAME, ON)).toBeNull();
  });

  test('an address that takes no name shows no section', () => {
    expect(firstNameOffer({ ...EDGE, layer: 'l7' }, null, ON)).toBeNull();
    expect(firstNameOffer({ ...EDGE, managed: false }, null, ON)).toBeNull();
    const noV4 = { ...EDGE, addresses: { ...EDGE.addresses, v4: null } };
    expect(firstNameOffer(noV4, null, ON)).toBeNull();
    for (const status of ['planning', 'provisioning', 'verifying', 'draining', 'destroying'])
      expect(firstNameOffer({ ...EDGE, status }, null, ON)).toBeNull();
  });

  test('names off, or no chosen zone, says why instead of the button', () => {
    expect(firstNameOffer(EDGE, null, settings({ enabled: false }))).toBe('names_off');
    expect(firstNameOffer(EDGE, null, settings({ zones: [] }))).toBe('no_zone');
    // A chosen zone that is no DNS account's zone any more takes nothing.
    expect(firstNameOffer(EDGE, null, settings({ zones: ['zone-gone'] }))).toBe('no_zone');
  });

  test('settings that could not be read leave the choice to the server', () => {
    expect(firstNameOffer(EDGE, null, null)).toBe('offer');
  });

  test('the words are plain: no em-dash, no API path', () => {
    for (const text of Object.values(FIRST_NAME_WORDS)) {
      expect(text).not.toContain('—');
      expect(text).not.toContain('/api/');
    }
  });
});
