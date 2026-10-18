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
    // A CDN has no place at all.
    expect(placementKeysOf('cloudflare', { zoneId: 'z', zoneName: 'example.org' })).toBeNull();
    expect(validatePlacement('upcloud', { zone: 'de-fra1' })).toMatchObject({ ok: true });
    expect(validatePlacement('upcloud', { zone: 'nowhere' })).toMatchObject({ ok: false });
    expect(validatePlacement('cloudflare', {})).toEqual({
      ok: true,
      placement: { type: 'cloudflare' },
    });
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

  test('locatingSettingsChanged ignores identifier and order changes but sees another API endpoint or zone', () => {
    const prev = { type: 'ovh', applicationKey: 'AK1', endpoint: 'ovh-eu' };
    expect(locatingSettingsChanged('ovh', { ...prev, applicationKey: 'AK2' }, prev)).toBe(false);
    const reordered = Object.fromEntries(Object.entries(prev).reverse());
    expect(locatingSettingsChanged('ovh', reordered, prev)).toBe(false);
    // The endpoint the key was issued for locates every edge of the account.
    expect(locatingSettingsChanged('ovh', { ...prev, endpoint: 'ovh-ca' }, prev)).toBe(true);
    // A region is a location's: never an account's locating setting.
    expect(locatingSettingsChanged('ovh', { ...prev, regionName: 'R2' }, prev)).toBe(false);
    const cf = { type: 'cloudflare', zoneId: 'a'.repeat(32), zoneName: 'example.org' };
    expect(locatingSettingsChanged('cloudflare', { ...cf, zoneId: 'b'.repeat(32) }, cf)).toBe(true);
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
