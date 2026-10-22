import { describe, expect, test } from 'vitest';
import { EDGE_PROVIDER_IDS } from '@shared/contracts/edges';
import {
  PROVIDER_FIELDS,
  applyDiscovery,
  hasLocations,
  locationFields,
  missingRequired,
  optionsFor,
  placementBody,
  regionPlacement,
  settingsBody,
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

  test("every account's first location is optional, all of it or none of it", () => {
    const opts = { firstLocation: true };
    // The form starts from the provider's defaults (a Fastly account's domain kind).
    const fastlyDefaults = { domainModel: 'versionless' };
    expect(missingRequired('cloudflare', {}, 'placement', opts)).toEqual([]);
    expect(missingRequired('fastly', fastlyDefaults, 'placement', opts)).toEqual([]);
    // A DNS account picked means the zone is needed too.
    expect(
      missingRequired('fastly', { ...fastlyDefaults, dnsAccountId: 'acct-dns' }, 'placement', opts),
    ).toEqual(['DNS zone', 'Zone name']);
    // A load balancer account too: its credentials alone are an account.
    expect(missingRequired('upcloud', {}, 'placement', opts)).toEqual([]);
    expect(missingRequired('gcore', {}, 'placement', opts)).toEqual([]);
    expect(missingRequired('scaleway', { accessKey: 'SCW' }, 'placement', opts)).toEqual([]);
    expect(missingRequired('ovh', { endpoint: 'ovh-eu' }, 'placement', opts)).toEqual([]);
    // Started by a region, the rest of that location is needed.
    expect(missingRequired('gcore', { regionId: '7' }, 'placement', opts)).toEqual(['Project']);
    expect(missingRequired('ovh', { regionName: 'GRA9' }, 'placement', opts)).toEqual([
      'Public Cloud project',
      'Private network',
      'Subnet',
    ]);
    // The credential step still needs its identifiers.
    expect(missingRequired('ovh', {}, 'credentials', opts)).toEqual([
      'Application key (public id)',
      'API endpoint',
    ]);
    // The location form itself always needs the place.
    expect(missingRequired('cloudflare', {})).toContain('DNS zone');
    expect(missingRequired('upcloud', {})).toEqual(['Zone']);
  });

  test('a region the key reaches names a location by its region alone (a number where the adapter wants one)', () => {
    expect(regionPlacement('gcore', '7')).toEqual({ regionId: 7 });
    expect(regionPlacement('ovh', 'GRA9')).toEqual({ regionName: 'GRA9' });
    expect(regionPlacement('upcloud', 'de-fra1')).toEqual({ zone: 'de-fra1' });
    expect(regionPlacement('scaleway', 'fr-par-1')).toEqual({ zone: 'fr-par-1' });
    // With the project it was listed in, where the provider has projects.
    expect(regionPlacement('gcore', '7', '12')).toEqual({ regionId: 7, projectId: 12 });
    expect(regionPlacement('ovh', 'GRA9', 'svc-b')).toEqual({
      regionName: 'GRA9',
      serviceName: 'svc-b',
    });
    expect(regionPlacement('upcloud', 'de-fra1', 'ignored')).toEqual({ zone: 'de-fra1' });
    // A CDN's place is a zone: picked in the location form.
    expect(regionPlacement('cloudflare', 'x')).toBeNull();
  });

  test('an optional location value alone is not sent as a first location', () => {
    const opts = { firstLocation: true };
    // A Project id with no zone, a network with no region, a gateway alone: no place.
    expect(settingsBody('scaleway', { accessKey: 'SCW', projectId: 'p-1' }, opts)).toEqual({
      accessKey: 'SCW',
    });
    expect(settingsBody('gcore', { networkId: 'net-1', subnetId: 'sub-1' }, opts)).toEqual({});
    expect(
      settingsBody('ovh', { applicationKey: 'ak', endpoint: 'ovh-eu', gatewayId: 'gw' }, opts),
    ).toEqual({ applicationKey: 'ak', endpoint: 'ovh-eu' });
    // Started by its region, the whole location goes.
    expect(
      settingsBody('scaleway', { accessKey: 'SCW', zone: 'fr-par-1', projectId: 'p-1' }, opts),
    ).toEqual({ accessKey: 'SCW', zone: 'fr-par-1', projectId: 'p-1' });
    // Anything else (a discovery) sends what the form holds.
    expect(settingsBody('gcore', { networkId: 'net-1' })).toEqual({ networkId: 'net-1' });
  });

  test("a load balancer's optional first location: no single project or region is picked for the operator", () => {
    const one = applyDiscovery(
      'gcore',
      {},
      {
        discovered: { projects: [{ id: '1', label: 'p' }], regions: [{ id: '7', label: 'r' }] },
        accounts: [],
      },
      { firstLocation: true },
    );
    expect(one.projectId).toBeUndefined();
    expect(one.regionId).toBeUndefined();
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
