import { describe, expect, test } from 'vitest';
import { EDGE_PROVIDER_IDS } from '../edgeProviderIds';
import {
  EDGE_CREDENTIAL_FIELDS,
  EDGE_CREDENTIAL_IDENTIFIER_FIELDS,
  EDGE_LOCATING_SETTINGS,
  EDGE_SETTINGS_SCHEMAS,
  locatingSettingsChanged,
  pickCredentialIdentifiers,
  settingsEqual,
} from './accountSettings';

describe('account settings: locating vs credential-identifier split', () => {
  test.each([...EDGE_PROVIDER_IDS])(
    '%s: every settings key is either locating or a credential identifier (never both), and never a secret',
    (id) => {
      const keys = Object.keys(EDGE_SETTINGS_SCHEMAS[id].shape).filter((k) => k !== 'type');
      const locating = new Set(EDGE_LOCATING_SETTINGS[id]);
      const idents = new Set(EDGE_CREDENTIAL_IDENTIFIER_FIELDS[id]);
      for (const k of keys) {
        expect(locating.has(k) || idents.has(k)).toBe(true);
        expect(locating.has(k) && idents.has(k)).toBe(false);
        expect(EDGE_CREDENTIAL_FIELDS[id]).not.toContain(k);
      }
      for (const k of [...locating, ...idents]) expect(keys).toContain(k);
    },
  );

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

  test('locatingSettingsChanged ignores identifier and order changes but sees a moved region/zone', () => {
    const prev = {
      type: 'ovh',
      applicationKey: 'AK1',
      endpoint: 'ovh-eu',
      serviceName: 'svc',
      regionName: 'R1',
      networkId: 'n',
      subnetId: 's',
    };
    expect(locatingSettingsChanged('ovh', { ...prev, applicationKey: 'AK2' }, prev)).toBe(false);
    const reordered = Object.fromEntries(Object.entries(prev).reverse());
    expect(locatingSettingsChanged('ovh', reordered, prev)).toBe(false);
    expect(locatingSettingsChanged('ovh', { ...prev, regionName: 'R2' }, prev)).toBe(true);
    expect(locatingSettingsChanged('ovh', { ...prev, gatewayId: 'g' }, prev)).toBe(true);
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
