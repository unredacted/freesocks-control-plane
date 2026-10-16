/**
 * Name checks from inside a country: what is sent to each source and how its
 * answer becomes an outcome (pure).
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { describe, expect, test } from 'vitest';
import {
  atlasNameBody,
  atlasProbeQuery,
  classifyConnectError,
  globalpingNameRequest,
  isNoProbesError,
  parseAtlasNameResults,
  parseAtlasProbes,
  parseGlobalpingNameResults,
  pickAtlasProbes,
} from './nameCheck';

const T = { address: '198.51.100.9', port: 443, name: 'site.example' };

describe('what is sent', () => {
  test('Globalping: HEAD / over HTTPS to the address, the name as SNI and Host, nothing else', () => {
    const first = globalpingNameRequest(T, { country: 'IR', limit: 3, preferEyeball: true });
    expect(first).toEqual({
      type: 'http',
      target: '198.51.100.9',
      inProgressUpdates: false,
      locations: [{ country: 'IR', limit: 3, tags: ['eyeball-network'] }],
      measurementOptions: {
        protocol: 'HTTPS',
        port: 443,
        request: { method: 'HEAD', path: '/', host: 'site.example' },
      },
    });
    // The rest of a batch reuses the first measurement's probes.
    expect(globalpingNameRequest(T, { reuse: 'm-1' }).locations).toBe('m-1');
    // A hostname origin is resolved by the probe, on v4.
    expect(
      globalpingNameRequest({ ...T, address: 'origin.example' }, { reuse: 'm-1' })
        .measurementOptions,
    ).toMatchObject({ ipVersion: 4 });
    expect(JSON.stringify(first)).not.toMatch(/freesocks/i);
  });

  test('RIPE Atlas: one private one-off request, one definition per name, the same probes', () => {
    const body = atlasNameBody([T, { ...T, name: 'other.example' }], [11, 12], 4);
    expect(body.definitions.map((d) => d.hostname)).toEqual(['site.example', 'other.example']);
    expect(body.definitions[0]).toMatchObject({
      type: 'sslcert',
      af: 4,
      target: '198.51.100.9',
      port: 443,
      is_oneoff: true,
      is_public: false,
    });
    expect(body.probes).toEqual([{ type: 'probes', value: '11,12', requested: 2 }]);
    expect(JSON.stringify(body)).not.toMatch(/freesocks/i);
    expect(atlasProbeQuery('IR')).toContain('country_code=IR');
    expect(atlasProbeQuery('IR')).toContain('status=1');
  });

  test('Atlas probes: one per network first, stable by id', () => {
    const rows = parseAtlasProbes(
      {
        results: [
          { id: 30, asn_v4: 64500 },
          { id: 10, asn_v4: 64500 },
          { id: 20, asn_v4: 64501 },
          { id: 40, asn_v4: null },
          { id: 'x' },
        ],
      },
      4,
    );
    expect(rows).toHaveLength(4);
    expect(pickAtlasProbes(rows, 3).map((r) => r.id)).toEqual([10, 20, 40]);
    expect(pickAtlasProbes(rows, 4).map((r) => r.id)).toEqual([10, 20, 40, 30]);
  });
});

describe('what comes back', () => {
  test('connection errors are classed; a refusal says nothing about the name', () => {
    expect(classifyConnectError('read ECONNRESET')).toBe('reset');
    expect(
      classifyConnectError('Client network socket disconnected before secure TLS connection'),
    ).toBe('reset');
    expect(classifyConnectError('connect: Connection reset by peer')).toBe('reset');
    expect(classifyConnectError('Connect Timeout Error')).toBe('timeout');
    expect(classifyConnectError('connect ECONNREFUSED 198.51.100.9:443')).toBe('refused');
    expect(classifyConnectError('something else')).toBe('error');
  });

  test('Globalping: authorized = ok, not authorized = cert_mismatch, failed = the error', () => {
    const probe = (asn: number, country = 'IR') => ({
      country,
      asn,
      network: `Net ${asn}`,
      tags: ['eyeball-network'],
    });
    const out = parseGlobalpingNameResults(
      [
        {
          probe: probe(1),
          result: {
            status: 'finished',
            statusCode: 200,
            timings: { total: 120 },
            tls: { authorized: true },
          },
        },
        {
          probe: probe(2),
          result: {
            status: 'finished',
            statusCode: 403,
            tls: { authorized: false, error: 'ERR_TLS_CERT_ALTNAME_INVALID site.example' },
          },
        },
        {
          probe: probe(3),
          result: { status: 'failed', rawOutput: 'read ECONNRESET site.example' },
        },
        { probe: probe(4), result: { status: 'finished', statusCode: 200, tls: null } },
        { probe: probe(5), result: { status: 'in-progress' } },
        { probe: probe(6, 'DE'), result: { status: 'finished', tls: { authorized: true } } },
      ],
      'IR',
      ['site.example', '198.51.100.9'],
    );
    expect(out.map((r) => [r.asn, r.outcome])).toEqual([
      ['AS1', 'ok'],
      ['AS2', 'cert_mismatch'],
      ['AS3', 'reset'],
      ['AS4', 'answered'],
    ]);
    expect(out[0]).toMatchObject({ vantageClass: 'eyeball', rttMs: 120 });
    // Stored error text never carries the name.
    for (const r of out) expect(r.error ?? '').not.toContain('site.example');
  });

  test('Atlas: the leaf is checked against the name; an alert or a bare answer is answered', () => {
    const covers = (pem: string, name: string) => (pem === 'BAD' ? null : pem === `CERT:${name}`);
    const out = parseAtlasNameResults(
      [
        { prb_id: 11, cert: ['CERT:site.example'], rt: 80 },
        { prb_id: 12, cert: ['CERT:wrong.example'] },
        { prb_id: 13, err: 'connect: timeout' },
        { prb_id: 14, alert: { level: 2, decription: 70 } },
        { prb_id: 15, cert: ['BAD'] },
        { prb_id: 16, err: 'connect: Connection refused' },
      ],
      'site.example',
      { asnByProbe: { 11: 'AS1', 12: 'AS2' }, certCovers: covers },
    );
    expect(out.map((r) => r.outcome)).toEqual([
      'ok',
      'cert_mismatch',
      'timeout',
      'answered',
      'answered',
      'refused',
    ]);
    expect(out[0]).toMatchObject({ asn: 'AS1', rttMs: 80 });
    expect(out[3]?.error).toBe('tls_alert');
  });

  test('a Globalping 422 for no matching probe is worth one retry without the tag', () => {
    expect(
      isNoProbesError(422, { error: { type: 'no_probes_found', message: 'No suitable probes' } }),
    ).toBe(true);
    expect(isNoProbesError(422, { error: { type: 'validation_error' } })).toBe(false);
    expect(isNoProbesError(429, {})).toBe(false);
  });
});
