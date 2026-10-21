import { describe, expect, test } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../edgeProviderIds';
import {
  EDGE_CREDENTIAL_FIELDS,
  EDGE_CREDENTIAL_IDENTIFIER_FIELDS,
  EDGE_INTENT_DEFAULT_SETTINGS,
  EDGE_LOCATING_SETTINGS,
  EDGE_PLACEMENT_SCHEMAS,
  EDGE_PLACEMENT_SETTINGS,
  EDGE_SETTINGS_SCHEMAS,
  legacySettingsOf,
  locatingSettingsChanged,
  pickCredentialIdentifiers,
  placementKeysOf,
  settingsEqual,
  validatePlacement,
  withoutPlacementKeys,
} from './accountSettings';

describe('account settings: locating vs credential-identifier split', () => {
  test.each([...EDGE_PROVIDER_IDS])(
    '%s: every account settings key is exactly one of locating / credential identifier / intent default, and never a secret',
    (id) => {
      const keys = Object.keys(EDGE_SETTINGS_SCHEMAS[id].shape).filter((k) => k !== 'type');
      const locating = new Set(EDGE_LOCATING_SETTINGS[id]);
      const idents = new Set(EDGE_CREDENTIAL_IDENTIFIER_FIELDS[id]);
      const defaults = new Set(EDGE_INTENT_DEFAULT_SETTINGS[id]);
      for (const k of keys) {
        const classes = [locating.has(k), idents.has(k), defaults.has(k)].filter(Boolean).length;
        expect(classes).toBe(1);
        expect(EDGE_CREDENTIAL_FIELDS[id]).not.toContain(k);
      }
      for (const k of [...locating, ...idents, ...defaults]) expect(keys).toContain(k);
    },
  );

  test.each([...EDGE_PROVIDER_IDS])(
    '%s: the placement is exactly the placement list, never on the account, never a secret',
    (id) => {
      const keys = Object.keys(EDGE_PLACEMENT_SCHEMAS[id].shape).filter((k) => k !== 'type');
      expect([...keys].sort()).toEqual([...EDGE_PLACEMENT_SETTINGS[id]].sort());
      const account = Object.keys(EDGE_SETTINGS_SCHEMAS[id].shape);
      for (const k of keys) {
        expect(account).not.toContain(k);
        expect(EDGE_CREDENTIAL_FIELDS[id]).not.toContain(k);
      }
    },
  );

  test('a place splits off an old single-location payload; the account keeps its own keys', () => {
    const old = {
      applicationKey: 'AK',
      endpoint: 'ovh-eu',
      serviceName: 'svc',
      regionName: 'R1',
      networkId: 'n',
      subnetId: 's',
    };
    expect(placementKeysOf('ovh', old)).toEqual({
      serviceName: 'svc',
      regionName: 'R1',
      networkId: 'n',
      subnetId: 's',
    });
    expect(withoutPlacementKeys('ovh', old)).toEqual({ applicationKey: 'AK', endpoint: 'ovh-eu' });
    expect(placementKeysOf('ovh', { applicationKey: 'AK', endpoint: 'ovh-eu' })).toBeNull();
    expect(validatePlacement('upcloud', { zone: 'de-fra1' })).toMatchObject({ ok: true });
    expect(validatePlacement('upcloud', { zone: 'nowhere' })).toMatchObject({ ok: false });
  });

  test("a CDN's place is its DNS zone (and a Fastly front's DNS account): never the account's", () => {
    const zone = { zoneId: 'a'.repeat(32), zoneName: 'example.org' };
    // The old single-zone account shape splits into a first location.
    expect(placementKeysOf('cloudflare', { ...zone, accountId: 'b'.repeat(32) })).toEqual(zone);
    expect(withoutPlacementKeys('cloudflare', { ...zone, accountId: 'b'.repeat(32) })).toEqual({
      accountId: 'b'.repeat(32),
    });
    expect(validatePlacement('cloudflare', zone)).toEqual({
      ok: true,
      placement: { type: 'cloudflare', ...zone },
    });
    // A CDN location without a zone is no place at all.
    expect(validatePlacement('cloudflare', {})).toMatchObject({ ok: false });
    expect(validatePlacement('cloudflare', { ...zone, zoneName: 'Not A Zone' })).toMatchObject({
      ok: false,
    });
    const front = { dnsAccountId: 'acct-dns', ...zone, tlsConfigurationId: 'tls-1' };
    expect(validatePlacement('fastly', front)).toMatchObject({ ok: true });
    expect(validatePlacement('fastly', { dnsAccountId: 'acct-dns' })).toMatchObject({ ok: false });
    // What is left of an old Fastly settings payload: nothing (its certificate
    // authority is a provider option now).
    expect(
      withoutPlacementKeys('fastly', { ...front, certificateAuthority: 'lets-encrypt' }),
    ).toEqual({});
  });

  test('legacy single-zone keys are found on a stored row (kept by edits until migrated)', () => {
    expect(
      legacySettingsOf('cloudflare', {
        type: 'cloudflare',
        zoneId: 'z',
        zoneName: 'example.org',
        accountId: 'a',
      }),
    ).toEqual({ zoneId: 'z', zoneName: 'example.org' });
    expect(
      legacySettingsOf('fastly', {
        type: 'fastly',
        dnsAccountId: 'd',
        certificateAuthority: 'certainly',
      }),
    ).toEqual({ dnsAccountId: 'd' });
    expect(legacySettingsOf('ovh', { type: 'ovh', endpoint: 'ovh-eu' })).toEqual({});
  });

  test('settingsEqual ignores key order recursively', () => {
    expect(
      settingsEqual(
        {
          type: 'ovh',
          serviceName: 'svc',
          regionName: 'R',
          nested: { a: 1, b: [1, { y: 2, z: 3 }] },
        },
        {
          nested: { b: [1, { z: 3, y: 2 }], a: 1 },
          regionName: 'R',
          serviceName: 'svc',
          type: 'ovh',
        },
      ),
    ).toBe(true);
    expect(settingsEqual({ a: 1 }, { a: 2 })).toBe(false);
  });

  test('locatingSettingsChanged ignores identifier, order and zone changes but sees another API endpoint', () => {
    const prev = { type: 'ovh', applicationKey: 'AK1', endpoint: 'ovh-eu' };
    expect(locatingSettingsChanged('ovh', { ...prev, applicationKey: 'AK2' }, prev)).toBe(false);
    const reordered = Object.fromEntries(Object.entries(prev).reverse());
    expect(locatingSettingsChanged('ovh', reordered, prev)).toBe(false);
    // The endpoint the key was issued for locates every edge of the account.
    expect(locatingSettingsChanged('ovh', { ...prev, endpoint: 'ovh-ca' }, prev)).toBe(true);
    // A region is a location's: never an account's locating setting.
    expect(locatingSettingsChanged('ovh', { ...prev, regionName: 'R2' }, prev)).toBe(false);
    // A zone is a location's: another zone never moves a CDN account.
    const cf = { type: 'cloudflare', zoneId: 'a'.repeat(32), zoneName: 'example.org' };
    expect(locatingSettingsChanged('cloudflare', { ...cf, zoneId: 'b'.repeat(32) }, cf)).toBe(
      false,
    );
    expect(
      locatingSettingsChanged(
        'scaleway',
        { type: 'scaleway', accessKey: 'SCWB', zone: 'fr-par-1' },
        { type: 'scaleway', accessKey: 'SCWA', zone: 'fr-par-1' },
      ),
    ).toBe(false);
  });

  test('pickCredentialIdentifiers keeps only the provider identifier fields, trimmed, non-blank', () => {
    expect(
      pickCredentialIdentifiers('scaleway', {
        accessKey: ' SCWNEW ',
        zone: 'nl-ams-1',
        secretKey: 'x',
      }),
    ).toEqual({ accessKey: 'SCWNEW' });
    expect(pickCredentialIdentifiers('ovh', { applicationKey: '', regionName: 'R' })).toEqual({});
    expect(pickCredentialIdentifiers('gcore', { apiKey: 'k' })).toEqual({});
  });
});
