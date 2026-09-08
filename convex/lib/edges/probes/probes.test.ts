import { describe, expect, test } from 'vitest';
import {
  GLOBALPING_USER_AGENT,
  globalpingRequest,
  globalpingStart,
  globalpingPoll,
  parseGlobalpingResults,
  type GlobalpingLike,
} from './globalping';
import {
  parseCheckhostNodes,
  selectCheckhostNodes,
  parseCheckhostResult,
  checkhostStart,
  type FetchLike,
} from './checkhost';
import { parseRipeAtlasResults, ripeAtlasBody } from './ripeatlas';
import { classifyInternalError, internalProbe } from './internal';
import { countryVerdict, probeScore, sourceVerdict, unreachableCountries } from './verdict';
import { shortError } from './types';
import type { ProbeResult } from './types';

const target = { address: '198.51.100.7', port: 443, ipVersion: 4 as const };
const opts = { countries: ['IR', 'RU'], perCountryLimit: 3, preferEyeball: true };

describe('globalping', () => {
  test('request: TCP ping on the edge port, per-country limits, eyeball tag when preferred', () => {
    const req = globalpingRequest(target, opts);
    expect(req).toMatchObject({
      type: 'ping',
      target: '198.51.100.7',
      measurementOptions: { protocol: 'TCP', port: 443, ipVersion: 4 },
    });
    expect(req.locations).toEqual([
      { country: 'IR', limit: 3, tags: ['eyeball-network'] },
      { country: 'RU', limit: 3, tags: ['eyeball-network'] },
    ]);
    expect(globalpingRequest(target, { ...opts, preferEyeball: false }).locations[0]).toEqual({
      country: 'IR',
      limit: 3,
    });
  });

  test('user agent is generic: names neither the project nor what is probed', () => {
    expect(GLOBALPING_USER_AGENT).not.toMatch(/fcp|freesocks|relay|edge|github|unredacted/i);
    expect(GLOBALPING_USER_AGENT.length).toBeGreaterThan(0);
  });

  test('results: finished with any reply → ok; 100% loss → fail; failed (probe-side error) and offline are DROPPED, not fails; tags → vantage', () => {
    const out = parseGlobalpingResults([
      {
        probe: { country: 'IR', asn: 12345, network: 'ISP A', tags: ['eyeball-network'] },
        result: { status: 'finished', stats: { loss: 0, avg: 41.7 } },
      },
      {
        probe: { country: 'ir', asn: 777, network: 'DC B', tags: ['datacenter-network'] },
        result: { status: 'finished', stats: { loss: 100, avg: null } },
      },
      { probe: { country: 'RU', asn: 1, tags: [] }, result: { status: 'failed', rawOutput: 'x' } },
      { probe: { country: 'RU', asn: 2, tags: [] }, result: { status: 'offline' } },
      {
        probe: { country: '??', asn: 3, tags: [] },
        result: { status: 'finished', stats: { loss: 0 } },
      },
    ]);
    expect(out).toEqual([
      {
        country: 'IR',
        asn: 'AS12345',
        network: 'ISP A',
        vantageClass: 'eyeball',
        ok: true,
        rttMs: 42,
        error: undefined,
      },
      {
        country: 'IR',
        asn: 'AS777',
        network: 'DC B',
        vantageClass: 'datacenter',
        ok: false,
        rttMs: undefined,
        error: 'no_reply',
      },
    ]);
    // A probe that could not run the command says nothing about the target.
    expect(out.some((r) => r.country === 'RU')).toBe(false);
  });

  test('start + poll through an injected client', async () => {
    const calls: unknown[] = [];
    const client: GlobalpingLike = {
      async createMeasurement(req) {
        calls.push(req);
        return { ok: true, data: { id: 'm-1', probesCount: 4 } };
      },
      async getMeasurement(id) {
        return {
          ok: true,
          data: {
            id,
            status: id === 'm-1' ? 'finished' : 'in-progress',
            results: [
              {
                probe: { country: 'IR', asn: 5, tags: ['eyeball-network'] },
                result: { status: 'finished', stats: { loss: 0, avg: 10 } },
              },
            ],
          },
        };
      },
    };
    const started = await globalpingStart(client, target, opts);
    expect(started.externalId).toBe('m-1');
    expect(calls).toHaveLength(1);
    const poll = await globalpingPoll(client, 'm-1');
    expect(poll.status).toBe('finished');
    expect(poll.results[0]).toMatchObject({ country: 'IR', ok: true });
    const running = await globalpingPoll(client, 'm-2');
    expect(running).toEqual({ status: 'running', results: [] });
    await expect(
      globalpingStart(
        {
          ...client,
          createMeasurement: async () => ({
            ok: false,
            response: new Response(null, { status: 429 }),
          }),
        },
        target,
        opts,
      ),
    ).rejects.toThrow(/429/);
  });
});

describe('check-host.net', () => {
  const nodesBody = {
    nodes: {
      'ir1.node.check-host.net': {
        asn: 'AS1',
        ip: '192.0.2.1',
        location: ['ir', 'Iran', 'Tehran'],
      },
      'ir2.node.check-host.net': {
        asn: 'AS2',
        ip: '192.0.2.2',
        location: ['ir', 'Iran', 'Isfahan'],
      },
      'ru1.node.check-host.net': {
        asn: 'AS3',
        ip: '192.0.2.3',
        location: ['ru', 'Russia', 'Moscow'],
      },
      'de1.node.check-host.net': {
        asn: 'AS4',
        ip: '192.0.2.4',
        location: ['de', 'Germany', 'Berlin'],
      },
      'bad.node': { location: 'nope' },
    },
  };

  test('nodes parse + per-country selection', () => {
    const nodes = parseCheckhostNodes(nodesBody);
    expect(nodes.map((n) => [n.host, n.country])).toEqual([
      ['ir1.node.check-host.net', 'IR'],
      ['ir2.node.check-host.net', 'IR'],
      ['ru1.node.check-host.net', 'RU'],
      ['de1.node.check-host.net', 'DE'],
    ]);
    expect(selectCheckhostNodes(nodes, ['IR', 'RU', 'CN'], 1).map((n) => n.host)).toEqual([
      'ir1.node.check-host.net',
      'ru1.node.check-host.net',
    ]);
  });

  test('start sends Accept: application/json, host:port and node params; v6 is bracketed', async () => {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    const fetchFn: FetchLike = async (url, init) => {
      seen.push({ url, init });
      return new Response(
        JSON.stringify({
          ok: 1,
          request_id: 'req-1',
          nodes: { 'ir1.node.check-host.net': ['ir', 'Iran', 'Tehran'] },
        }),
        { status: 200 },
      );
    };
    const nodes = parseCheckhostNodes(nodesBody);
    const started = await checkhostStart(fetchFn, target, { ...opts, perCountryLimit: 2 }, nodes);
    expect(started.externalId).toBe('req-1');
    const u = new URL(seen[0].url);
    expect(u.pathname).toBe('/check-tcp');
    expect(u.searchParams.get('host')).toBe('198.51.100.7:443');
    expect(u.searchParams.getAll('node')).toEqual([
      'ir1.node.check-host.net',
      'ir2.node.check-host.net',
      'ru1.node.check-host.net',
    ]);
    expect((seen[0].init?.headers as Record<string, string>).accept).toBe('application/json');
    expect(started.nodeCountries['ru1.node.check-host.net']).toBe('RU');
    await checkhostStart(fetchFn, { address: '2001:db8::7', port: 443, ipVersion: 6 }, opts, nodes);
    expect(new URL(seen[1].url).searchParams.get('host')).toBe('[2001:db8::7]:443');
  });

  test('result parse: null = pending, [{time}] = ok (seconds → ms), [{error}] = fail', () => {
    const nodeCountries = {
      'ir1.node.check-host.net': 'IR',
      'ir2.node.check-host.net': 'IR',
      'ru1.node.check-host.net': 'RU',
    };
    const pending = parseCheckhostResult(
      {
        'ir1.node.check-host.net': [{ time: 0.0512, address: '198.51.100.7' }],
        'ir2.node.check-host.net': null,
        'ru1.node.check-host.net': [{ error: 'Connection timed out' }],
      },
      nodeCountries,
      { 'ir1.node.check-host.net': 'AS1' },
    );
    expect(pending.status).toBe('running');
    expect(pending.results).toEqual([
      {
        country: 'IR',
        asn: 'AS1',
        network: 'ir1',
        vantageClass: 'datacenter',
        ok: true,
        rttMs: 51,
      },
      {
        country: 'RU',
        asn: undefined,
        network: 'ru1',
        vantageClass: 'datacenter',
        ok: false,
        error: 'Connection timed out',
      },
    ]);
    const done = parseCheckhostResult(
      {
        'ir1.node.check-host.net': [{ time: 0.1 }],
        'ir2.node.check-host.net': [{ error: 'x' }],
        'ru1.node.check-host.net': [{ time: 0.2 }],
      },
      nodeCountries,
    );
    expect(done.status).toBe('finished');
    expect(done.results).toHaveLength(3);
  });

  test('a node that answered without a result ([null], [], junk) is dropped: not a failed target, not pending', () => {
    const nodeCountries = {
      'ir1.node.check-host.net': 'IR',
      'ir2.node.check-host.net': 'IR',
      'ru1.node.check-host.net': 'RU',
    };
    const p = parseCheckhostResult(
      {
        'ir1.node.check-host.net': [null],
        'ir2.node.check-host.net': [],
        'ru1.node.check-host.net': [{ time: 0.2 }],
      },
      nodeCountries,
    );
    expect(p.status).toBe('finished');
    expect(p.results).toEqual([expect.objectContaining({ country: 'RU', ok: true })]);
    expect(p.results.some((r) => !r.ok)).toBe(false);
  });
});

describe('ripe atlas', () => {
  test('body: one PRIVATE sslcert definition per country with a non-identifying description, capped requested probes', () => {
    const b = ripeAtlasBody(target, 'IR', 50);
    expect(b.definitions[0]).toMatchObject({
      type: 'sslcert',
      af: 4,
      target: '198.51.100.7',
      port: 443,
      is_public: false,
    });
    expect(b.definitions[0].description).not.toMatch(/relay|edge|fcp|freesocks/i);
    expect(b.probes).toEqual([{ type: 'country', value: 'IR', requested: 10 }]);
  });
  test('results: rt/cert = ok, a TLS alert = the peer answered (ok), err = fail, junk skipped', () => {
    const out = parseRipeAtlasResults(
      [
        { prb_id: 1, rt: 120.4, cert: ['-----'] },
        { prb_id: 2, err: 'connect: timeout' },
        { prb_id: 3, rt: 80.2, alert: { level: 2, description: 40 } },
        { prb_id: 4 },
      ],
      'IR',
    );
    expect(out).toEqual([
      { country: 'IR', network: 'prb-1', vantageClass: 'unknown', ok: true, rttMs: 120 },
      {
        country: 'IR',
        network: 'prb-2',
        vantageClass: 'unknown',
        ok: false,
        error: 'connect: timeout',
      },
      {
        country: 'IR',
        network: 'prb-3',
        vantageClass: 'unknown',
        ok: true,
        rttMs: 80,
        error: 'tls_alert',
      },
    ]);
  });
});

describe('internal probe', () => {
  test('classification: connection failures are unreachable, TLS failures mean a peer answered', () => {
    expect(
      classifyInternalError(
        Object.assign(new Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }),
      ),
    ).toEqual({ ok: false, error: 'ECONNREFUSED' });
    expect(
      classifyInternalError(
        Object.assign(new Error('fetch failed'), { cause: { code: 'UND_ERR_CONNECT_TIMEOUT' } }),
      ).ok,
    ).toBe(false);
    expect(classifyInternalError(Object.assign(new Error('x'), { name: 'TimeoutError' }))).toEqual({
      ok: false,
      error: 'timeout',
    });
    expect(
      classifyInternalError(
        Object.assign(new Error('fetch failed'), {
          cause: { code: 'ERR_TLS_CERT_ALTNAME_INVALID' },
        }),
      ).ok,
    ).toBe(true);
    expect(
      classifyInternalError(
        Object.assign(new Error('fetch failed'), {
          cause: { code: 'DEPTH_ZERO_SELF_SIGNED_CERT' },
        }),
      ).ok,
    ).toBe(true);
    expect(
      classifyInternalError(
        Object.assign(new Error('fetch failed'), {
          cause: { message: 'unable to verify the first certificate' },
        }),
      ).ok,
    ).toBe(true);
  });
  test('any HTTP response is reachable; results never carry a country signal', async () => {
    const ok = await internalProbe(async () => new Response(null, { status: 400 }), target);
    expect(ok).toMatchObject({ country: 'XX', ok: true, vantageClass: 'datacenter' });
    const down = await internalProbe(async () => {
      throw Object.assign(new Error('fetch failed'), { cause: { code: 'EHOSTUNREACH' } });
    }, target);
    expect(down).toMatchObject({ country: 'XX', ok: false, error: 'EHOSTUNREACH' });
  });
});

describe('verdicts', () => {
  const r = (
    country: string,
    ok: boolean,
    asn: string,
    vantageClass: ProbeResult['vantageClass'] = 'datacenter',
  ): ProbeResult => ({ country, ok, asn, vantageClass });

  test('source verdict: agreement needed for unreachable; one eyeball success or two datacenter successes = reachable', () => {
    expect(
      sourceVerdict('globalping', [r('IR', false, 'AS1'), r('IR', false, 'AS2')], 2).verdict,
    ).toBe('unreachable');
    // Same network twice is ONE vantage.
    expect(
      sourceVerdict('globalping', [r('IR', false, 'AS1'), r('IR', false, 'AS1')], 2).verdict,
    ).toBe('unknown');
    expect(sourceVerdict('globalping', [r('IR', true, 'AS1', 'eyeball')], 2).verdict).toBe(
      'reachable',
    );
    expect(sourceVerdict('globalping', [r('IR', true, 'AS1')], 2).verdict).toBe('unknown');
    expect(
      sourceVerdict('globalping', [r('IR', true, 'AS1'), r('IR', true, 'AS2')], 2).verdict,
    ).toBe('reachable');
    expect(
      sourceVerdict(
        'globalping',
        [r('IR', true, 'AS1', 'eyeball'), r('IR', false, 'AS2'), r('IR', false, 'AS3')],
        2,
      ).verdict,
    ).toBe('mixed');
    expect(
      sourceVerdict('globalping', [r('IR', true, 'AS1'), r('IR', false, 'AS2')], 2).verdict,
    ).toBe('mixed');
    expect(sourceVerdict('globalping', [], 2).verdict).toBe('unknown');
  });

  test('country verdict: unreachable needs two sources or two networks and no success anywhere', () => {
    const gpDown = sourceVerdict('globalping', [r('IR', false, 'AS1'), r('IR', false, 'AS2')], 2);
    const chDown = sourceVerdict('checkhost', [r('IR', false, 'AS9'), r('IR', false, 'AS8')], 2);
    const chUp = sourceVerdict('checkhost', [r('IR', true, 'AS9'), r('IR', true, 'AS8')], 2);
    const chOneDown = sourceVerdict('checkhost', [r('IR', false, 'AS9')], 2); // unknown alone
    expect(countryVerdict([gpDown, chDown])).toBe('unreachable');
    expect(countryVerdict([gpDown])).toBe('unreachable'); // two networks within one source
    expect(countryVerdict([sourceVerdict('globalping', [r('IR', false, 'AS1')], 1)])).toBe(
      'unknown',
    ); // one network only
    expect(countryVerdict([gpDown, chUp])).toBe('mixed');
    expect(countryVerdict([chUp])).toBe('reachable');
    expect(countryVerdict([gpDown, chOneDown])).toBe('unreachable');
    expect(countryVerdict([])).toBe('unknown');
    // A single success anywhere blocks "unreachable".
    const gpMixed = sourceVerdict(
      'globalping',
      [r('IR', false, 'AS1'), r('IR', false, 'AS2'), r('IR', true, 'AS3')],
      2,
    );
    expect(countryVerdict([gpMixed, chDown])).toBe('mixed');
  });

  test('probe score is the WORST once-reachable country; a never-reachable country is not evidence', () => {
    const byCountry = [
      { country: 'IR', verdict: 'unreachable' as const, wasReachable: true },
      { country: 'RU', verdict: 'mixed' as const, wasReachable: true },
      { country: 'CN', verdict: 'reachable' as const, wasReachable: true },
    ];
    // One agreed unreachable country IS the signal (no dilution across countries).
    expect(probeScore(byCountry, ['IR', 'RU', 'CN', 'TR'])).toBe(1);
    expect(probeScore(byCountry, ['RU', 'CN'])).toBe(0.5);
    expect(probeScore(byCountry, ['CN'])).toBe(0);
    expect(probeScore(byCountry, [])).toBe(0);
    expect(unreachableCountries(byCountry)).toEqual(['IR']);
    // A country that has never reached the target: neither score nor evidence.
    const never = [{ country: 'IR', verdict: 'unreachable' as const, wasReachable: false }];
    expect(probeScore(never, ['IR'])).toBe(0);
    expect(unreachableCountries(never)).toEqual([]);
  });

  test('shortError scrubs addresses and urls', () => {
    expect(shortError('connect to 203.0.113.9 failed via https://x.example/y')).toBe(
      'connect to <ip> failed via <url>',
    );
    expect(shortError('peer [2001:db8::1] reset')).toBe('peer <ip6> reset');
  });
});
