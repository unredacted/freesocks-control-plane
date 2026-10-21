import { describe, expect, it } from 'vitest';
import {
  inventoryOwner,
  isTested,
  locationTrustWords,
  observedRows,
  settingLabel,
  settingRows,
  sharedCertificateWords,
  testWords,
} from './accountWords';

const NOW = Date.parse('2026-01-01T01:00:00.000Z');
const okAt = '2026-01-01T00:00:00.000Z';

describe('testWords', () => {
  it('covers never, passed and failed', () => {
    expect(testWords({ lastTestOkAt: null, lastTestError: null }, NOW).label).toBe('Never tested');
    expect(testWords({ lastTestOkAt: okAt, lastTestError: null }, NOW)).toMatchObject({
      label: 'Tested',
      detail: 'Passed 1 h ago',
    });
    const failed = testWords({ lastTestOkAt: okAt, lastTestError: 'auth_failed' }, NOW);
    expect(failed.tone).toBe('danger');
    expect(failed.detail).not.toContain('_');
    expect(isTested({ lastTestOkAt: okAt, lastTestError: 'x' })).toBe(false);
  });
});

describe('settings', () => {
  it('puts keys in words', () => {
    expect(settingLabel('projectId')).toBe('Project ID');
    expect(settingLabel('dnsAccountId')).toBe('DNS account ID');
    expect(settingLabel('zone_name')).toBe('Zone name');
  });
  it('names id-valued settings and drops empty ones', () => {
    const rows = settingRows(
      { region: 'r1', dnsAccountId: 'acc1', empty: '' },
      { acc1: 'Main DNS' },
    );
    expect(rows).toHaveLength(2);
    expect(rows[1]).toMatchObject({ label: 'DNS account ID', value: 'Main DNS', hint: 'acc1' });
  });
  it('marks unowned resources as foreign', () => {
    expect(inventoryOwner({ unowned: true })).toBe('foreign');
    expect(inventoryOwner({})).toBe('fcp');
  });
});

describe('locationTrustWords', () => {
  const base = { qualified: false, autoQualifyHold: false, qualification: null };
  it('says how a location was trusted, or how it will be', () => {
    expect(locationTrustWords(base, NOW)).toMatchObject({
      label: 'Not trusted yet',
      detail: 'Its first tested address trusts it.',
    });
    expect(
      locationTrustWords(
        {
          qualified: true,
          autoQualifyHold: false,
          qualification: { by: 'auto', at: okAt, edgeId: 'e' },
        },
        NOW,
      ).detail,
    ).toBe('Trusted automatically, checked with a real session 1 h ago.');
    expect(
      locationTrustWords(
        {
          qualified: true,
          autoQualifyHold: false,
          qualification: { by: 'admin', at: okAt, edgeId: 'e' },
        },
        NOW,
      ).detail,
    ).toBe('Tried with a real session by you 1 h ago.');
    expect(
      locationTrustWords(
        {
          qualified: true,
          autoQualifyHold: false,
          qualification: { by: 'admin', at: okAt, edgeId: null },
        },
        NOW,
      ).detail,
    ).toBe('Trusted by your override 1 h ago.');
    expect(locationTrustWords({ ...base, autoQualifyHold: true }, NOW).tone).toBe('warning');
  });
});

describe('certificates in words', () => {
  it('names the certificate scope and the CAA verdict instead of their codes', () => {
    expect(settingRows({ certificateScope: 'wildcard' })).toEqual([
      { label: 'Certificates', value: 'One wildcard for every front' },
    ]);
    const rows = observedRows({ caa: 'forbids', caaIssuer: 'certainly.com', caaAt: 'example.org' });
    expect(rows[0]).toEqual({
      label: 'CAA records',
      value: 'Forbid the certificate authority',
      tone: 'danger',
    });
    expect(rows[1]).toMatchObject({
      label: 'CA as CAA names it',
      value: 'certainly.com',
      mono: true,
    });
  });
  it('says what the shared certificate waits on, when it expires and who uses it', () => {
    const base = {
      name: '*.example.org',
      code: null,
      notAfter: null,
      checkedAt: okAt,
      edges: 2,
    };
    expect(
      sharedCertificateWords({ ...base, state: 'processing', code: 'tls_caa_conflict' }, NOW),
    ).toMatchObject({
      label: 'Waiting to issue',
      tone: 'warning',
    });
    expect(
      sharedCertificateWords({ ...base, state: 'processing', code: 'tls_caa_conflict' }, NOW)
        .detail,
    ).toContain('Certificate blocked by CAA');
    const issued = sharedCertificateWords(
      { ...base, state: 'issued', notAfter: '2026-11-19T10:12:00.000Z' },
      NOW,
    );
    expect(issued).toMatchObject({ label: 'Issued', tone: 'success' });
    expect(issued.detail).toContain('Valid until 2026-11-19');
    expect(issued.detail).toContain('2 live fronts use it.');
    expect(sharedCertificateWords({ ...base, state: 'failed', code: 'tls_failed' }, NOW).tone).toBe(
      'danger',
    );
    expect(sharedCertificateWords({ ...base, state: 'absent', edges: 0 }, NOW).label).toBe(
      'Not ordered yet',
    );
    for (const state of ['issued', 'renewing', 'failed', 'absent', 'ambiguous', 'pending'])
      expect(sharedCertificateWords({ ...base, state }, NOW).detail).not.toContain('\u2014');
  });
});
