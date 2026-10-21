import { describe, expect, test } from 'vitest';
import {
  CA_CAA_DOMAINS,
  caaIssuerOf,
  caaParamsAllow,
  caaProbeName,
  caaSetAllows,
  caaWalkNames,
  checkCaa,
  wildcardBase,
  wildcardNameFor,
  type CaaLookup,
  type CaaRecord,
} from './caa';

/** A zone's CAA records by name; every other name has none. */
function zone(table: Record<string, CaaRecord[]>): CaaLookup & { asked: string[] } {
  const asked: string[] = [];
  const lookup = (async (name: string) => {
    asked.push(name);
    return table[name] ?? [];
  }) as CaaLookup & { asked: string[] };
  lookup.asked = asked;
  return lookup;
}
const issue = (value: string, flags = 0): CaaRecord => ({ flags, tag: 'issue', value });
const issuewild = (value: string, flags = 0): CaaRecord => ({ flags, tag: 'issuewild', value });

const HOST = 'k3m7q9zb.example.org';

describe('caa: the walk a CA does', () => {
  test('the names climb from the one ordered to the top label, never the root', () => {
    expect(caaWalkNames('A.B.Example.org.')).toEqual([
      'a.b.example.org',
      'b.example.org',
      'example.org',
      'org',
    ]);
  });

  test('no record anywhere up the tree restricts nothing', async () => {
    const lookup = zone({});
    const v = await checkCaa({ name: HOST, certificateAuthority: 'certainly', lookup });
    expect(v).toEqual({ verdict: 'no_records', issuer: 'certainly.com', wildcard: false });
    expect(lookup.asked).toEqual([HOST, 'example.org', 'org']);
  });

  test('a record allowing the CA allows it', async () => {
    const v = await checkCaa({
      name: HOST,
      certificateAuthority: 'certainly',
      lookup: zone({ 'example.org': [issue('letsencrypt.org'), issue('certainly.com')] }),
    });
    expect(v).toMatchObject({ verdict: 'allows', decidedAt: 'example.org' });
  });

  test('records that name only other CAs forbid it, inherited from the apex', async () => {
    const lookup = zone({ 'example.org': [issue('letsencrypt.org')] });
    const v = await checkCaa({ name: HOST, certificateAuthority: 'certainly', lookup });
    expect(v).toEqual({
      verdict: 'forbids',
      issuer: 'certainly.com',
      wildcard: false,
      decidedAt: 'example.org',
    });
    // The first name with records decides: nothing above it is read.
    expect(lookup.asked).toEqual([HOST, 'example.org']);
  });

  test('the closest records win over the apex', async () => {
    const v = await checkCaa({
      name: HOST,
      certificateAuthority: 'certainly',
      lookup: zone({ [HOST]: [issue('certainly.com')], 'example.org': [issue(';')] }),
    });
    expect(v).toMatchObject({ verdict: 'allows', decidedAt: HOST });
  });

  test('a wildcard starts at its base and is governed by issuewild', async () => {
    const lookup = zone({
      'example.org': [issue('certainly.com'), issuewild('letsencrypt.org')],
    });
    const wild = await checkCaa({
      name: '*.example.org',
      certificateAuthority: 'certainly',
      lookup,
    });
    expect(wild).toEqual({
      verdict: 'forbids',
      issuer: 'certainly.com',
      wildcard: true,
      decidedAt: 'example.org',
    });
    expect(lookup.asked).toEqual(['example.org']);
    // The same records let the CA issue one certificate per name.
    const host = await checkCaa({ name: HOST, certificateAuthority: 'certainly', lookup });
    expect(host.verdict).toBe('allows');
  });

  test('a wildcard falls back to issue when there is no issuewild', async () => {
    const v = await checkCaa({
      name: '*.example.org',
      certificateAuthority: 'lets-encrypt',
      lookup: zone({ 'example.org': [issue('letsencrypt.org; validationmethods=dns-01')] }),
    });
    expect(v).toMatchObject({ verdict: 'allows', issuer: 'letsencrypt.org', wildcard: true });
  });

  test('a failed lookup is unchecked, never a guess', async () => {
    const v = await checkCaa({
      name: HOST,
      certificateAuthority: 'globalsign',
      lookup: async () => {
        throw new Error('SERVFAIL');
      },
    });
    expect(v).toEqual({ verdict: 'unchecked', issuer: 'globalsign.com', wildcard: false });
  });
});

describe('caa: one record set', () => {
  test('an empty issuer allows no CA at all', () => {
    expect(caaSetAllows([issue(';')], 'certainly.com', false)).toBe(false);
    expect(caaIssuerOf(' Certainly.com. ; account=1')).toBe('certainly.com');
  });

  test('parameters FCP cannot meet do not allow it: an account binding, a method without dns-01', () => {
    expect(caaParamsAllow('certainly.com')).toBe(true);
    expect(caaParamsAllow('certainly.com; accounturi=https://acme.example.net/acct/1')).toBe(false);
    expect(caaParamsAllow('certainly.com; validationmethods=http-01')).toBe(false);
    expect(caaParamsAllow('certainly.com; validationmethods = http-01, DNS-01')).toBe(true);
    expect(caaParamsAllow('certainly.com; somethingelse=1')).toBe(true);
    expect(
      caaSetAllows([issue('certainly.com; validationmethods=tls-alpn-01')], 'certainly.com', false),
    ).toBe(false);
  });

  test('a front is checked from a label nothing serves, so a zone wildcard answers for it', () => {
    expect(caaProbeName('Example.org.')).toBe('_fcp-caa-check.example.org');
  });

  test('a set with only iodef restricts nothing', () => {
    expect(
      caaSetAllows(
        [{ flags: 0, tag: 'iodef', value: 'mailto:pki@example.org' }],
        'certainly.com',
        false,
      ),
    ).toBe(true);
  });

  test('a critical property with an unknown tag forbids issuance outright', () => {
    const records = [issue('certainly.com'), { flags: 128, tag: 'tbs', value: 'x' }];
    expect(caaSetAllows(records, 'certainly.com', false)).toBe(false);
    // Not critical: ignored.
    expect(
      caaSetAllows(
        [issue('certainly.com'), { flags: 0, tag: 'tbs', value: 'x' }],
        'certainly.com',
        false,
      ),
    ).toBe(true);
  });

  test('issuewild never restricts a name that is not a wildcard', () => {
    expect(caaSetAllows([issuewild(';')], 'certainly.com', false)).toBe(true);
    expect(caaSetAllows([issuewild(';')], 'certainly.com', true)).toBe(false);
  });

  test('every CA FCP orders from has its CAA issuer domain', () => {
    expect(CA_CAA_DOMAINS).toEqual({
      certainly: 'certainly.com',
      'lets-encrypt': 'letsencrypt.org',
      globalsign: 'globalsign.com',
    });
  });
});

describe('caa: the wildcard that covers a front', () => {
  test('a first-level front name is covered by the wildcard of its zone', () => {
    expect(wildcardNameFor('K3M7Q9ZB.example.org.')).toBe('*.example.org');
    expect(wildcardNameFor('x.fronts.example.org')).toBe('*.fronts.example.org');
    expect(wildcardBase('*.example.org')).toBe('example.org');
    expect(wildcardBase('example.org')).toBe('example.org');
  });
});
