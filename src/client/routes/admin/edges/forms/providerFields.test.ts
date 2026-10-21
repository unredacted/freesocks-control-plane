import { describe, expect, test } from 'vitest';
import { EDGE_PROVIDER_IDS } from '@shared/contracts/edges';
import {
  PROVIDER_FIELDS,
  applyDiscovery,
  firstLocationOptional,
  hasLocations,
  locationFields,
  missingRequired,
  optionsFor,
  placementBody,
} from './providerFields';

describe('provider fields: a place is a location, a CDN zone included', () => {
  test.each([...EDGE_PROVIDER_IDS])('%s has location fields and a field table', (id) => {
    expect(PROVIDER_FIELDS[id]).toBeDefined();
    expect(hasLocations(id)).toBe(true);
  });

  test("a CDN's zone (and a front's DNS account and TLS configuration) are location fields", () => {
    expect(locationFields('cloudflare').map((f) => f.key)).toEqual(['zoneId', 'zoneName']);
    expect(locationFields('fastly').map((f) => f.key)).toEqual([
      'dnsAccountId',
      'zoneId',
      'zoneName',
      'tlsConfigurationId',
    ]);
    // The certificate authority stays the account's.
    expect(locationFields('fastly').some((f) => f.key === 'certificateAuthority')).toBe(false);
  });

  test("a CDN account's first zone is optional, all of it or none of it; a region is not", () => {
    expect(firstLocationOptional('cloudflare')).toBe(true);
    expect(firstLocationOptional('upcloud')).toBe(false);
    const opts = { firstLocation: true };
    // The form starts from the provider's defaults (a Fastly account's domain kind).
    const fastlyDefaults = { domainModel: 'versionless' };
    expect(missingRequired('cloudflare', {}, 'placement', opts)).toEqual([]);
    expect(missingRequired('fastly', fastlyDefaults, 'placement', opts)).toEqual([]);
    // A DNS account picked means the zone is needed too.
    expect(
      missingRequired('fastly', { ...fastlyDefaults, dnsAccountId: 'acct-dns' }, 'placement', opts),
    ).toEqual(['DNS zone', 'Zone name']);
    expect(missingRequired('upcloud', {}, 'placement', opts)).toEqual(['Zone']);
    // The location form itself always needs the zone.
    expect(missingRequired('cloudflare', {})).toContain('DNS zone');
  });

  test("a front's zone list is its DNS account's; a pick fills the zone name", () => {
    const zoneField = PROVIDER_FIELDS.fastly.find((f) => f.key === 'zoneId')!;
    const dnsZones = [{ id: 'a'.repeat(32), label: 'example.org' }];
    expect(optionsFor(zoneField, { discovered: null, accounts: [], values: {}, dnsZones })).toEqual(
      dnsZones,
    );
    const next = applyDiscovery(
      'fastly',
      { dnsAccountId: 'acct-dns', certificateAuthority: 'certainly' },
      {
        discovered: null,
        accounts: [{ id: 'acct-dns', name: 'dns', provider: 'cloudflare' }],
        dnsZones,
      },
    );
    expect(next).toMatchObject({ zoneId: 'a'.repeat(32), zoneName: 'example.org' });
    // The location body carries the place, and nothing of the account's own.
    expect(placementBody('fastly', next)).toEqual({
      dnsAccountId: 'acct-dns',
      zoneId: 'a'.repeat(32),
      zoneName: 'example.org',
    });
  });

  test("the optional first zone is the operator's to start: no single choice is picked for them", () => {
    const ctx = {
      discovered: { tlsConfigurations: [{ id: 'tls-1', label: 'default' }] },
      accounts: [{ id: 'acct-dns', name: 'dns', provider: 'cloudflare' as const }],
    };
    const first = applyDiscovery('fastly', {}, ctx, { firstLocation: true });
    expect(first.dnsAccountId).toBeUndefined();
    expect(first.tlsConfigurationId).toBeUndefined();
    // An optional field alone (a TLS configuration) starts no first location.
    expect(
      missingRequired(
        'fastly',
        { domainModel: 'versionless', tlsConfigurationId: 'tls-1' },
        'placement',
        {
          firstLocation: true,
        },
      ),
    ).toEqual([]);
    // A zone no longer offered takes its name with it.
    const stale = applyDiscovery(
      'cloudflare',
      { zoneId: 'z-gone', zoneName: 'gone.example.org' },
      { discovered: { zones: [{ id: 'z-1', label: 'example.org' }] }, accounts: [] },
      { firstLocation: true },
    );
    expect(stale).toMatchObject({ zoneId: '', zoneName: '' });
  });
});
