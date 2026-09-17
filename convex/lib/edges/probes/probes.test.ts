import { describe, expect, test } from 'vitest';
import {
  GLOBALPING_USER_AGENT,
  globalpingKind,
  globalpingRequest,
  globalpingStart,
  globalpingPoll,
  parseGlobalpingHttpResults,
  parseGlobalpingResults,
  type GlobalpingLike,
} from './globalping';
import {
  checkhostEndpoint,
  checkhostHostParam,
  parseCheckhostNodes,
  selectCheckhostNodes,
  parseCheckhostResult,
  checkhostStart,
  type FetchLike,
} from './checkhost';
import { fetchAtlasProbeAsns, parseRipeAtlasResults, ripeAtlasBody } from './ripeatlas';
import { classifyInternalError, internalProbe, pickDialAddress, resolvePublic } from './internal';
import {
  countryVerdict,
  portRollup,
  probeScore,
  sourceVerdict,
  unreachableCountries,
} from './verdict';
import { shortError } from './types';
import type { ProbeResult, ProbeTarget } from './types';

const target: ProbeTarget = {
  address: '198.51.100.7',
  port: 443,
  addressKind: 'ip',
  protocol: 'tcp',
  requestedFamily: 4,
  ipVersion: 4,
};
/** An L7 (hostname) target: probed by name, no family requested, TLS handshake. */
const nameTarget: ProbeTarget = {
  address: 'front.example',
  port: 443,
  addressKind: 'name',
  protocol: 'tls',
  requestedFamily: 'any',
};
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

  test('a tls/https target becomes an http measurement: GET / over HTTPS with the name as Host', () => {
    expect(globalpingKind(target)).toBe('ping');
    expect(globalpingKind(nameTarget)).toBe('http');
    const req = globalpingRequest(nameTarget, opts);
    expect(req).toMatchObject({
      type: 'http',
      target: 'front.example',
      measurementOptions: {
        protocol: 'HTTPS',
        port: 443,
        request: { method: 'GET', path: '/', host: 'front.example' },
      },
    });
    // A name pins no family: the vantage's own resolver decides.
    expect(req.measurementOptions).not.toHaveProperty('ipVersion');
    expect(globalpingRequest(target, opts).measurementOptions).toMatchObject({ ipVersion: 4 });
  });

  test('http results: any status = the handshake completed (reachable); a failed item is a real connect/TLS failure, scrubbed of the name', () => {
    const out = parseGlobalpingHttpResults(
      [
        {
          probe: { country: 'IR', asn: 1, tags: ['eyeball-network'] },
          result: { status: 'finished', statusCode: 403, timings: { total: 91.6 } },
        },
        {
          probe: { country: 'RU', asn: 2, tags: [] },
          result: {
            status: 'failed',
            rawOutput: 'unable to verify the first certificate for front.example',
          },
        },
        { probe: { country: 'RU', asn: 3, tags: [] }, result: { status: 'in-progress' } },
        {
          probe: { country: 'RU', asn: 4, tags: [] },
          result: { status: 'finished' }, // answered, no status code: no evidence
        },
      ],
      ['front.example'],
    );
    expect(out).toHaveLength(2);
    // A 403 from the front still proves the connection and handshake worked.
    expect(out[0]).toMatchObject({ country: 'IR', ok: true, rttMs: 92 });
    expect(out[1]).toMatchObject({ country: 'RU', ok: false });
    expect(out[1].error).not.toContain('front.example');
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
    await checkhostStart(
      fetchFn,
      {
        address: '2001:db8::7',
        port: 443,
        addressKind: 'ip',
        protocol: 'tcp',
        requestedFamily: 6,
        ipVersion: 6,
      },
      opts,
      nodes,
    );
    expect(new URL(seen[1].url).searchParams.get('host')).toBe('[2001:db8::7]:443');
  });

  test('a tls/https target uses check-http against the https URL; tcp keeps check-tcp with host:port', async () => {
    expect(checkhostEndpoint(target)).toBe('check-tcp');
    expect(checkhostHostParam(target)).toBe('198.51.100.7:443');
    expect(checkhostEndpoint(nameTarget)).toBe('check-http');
    expect(checkhostHostParam(nameTarget)).toBe('https://front.example:443/');
    const seen: string[] = [];
    const fetchFn: FetchLike = async (url) => {
      seen.push(url);
      return new Response(JSON.stringify({ ok: 1, request_id: 'req-2' }), { status: 200 });
    };
    await checkhostStart(fetchFn, nameTarget, opts, parseCheckhostNodes(nodesBody));
    expect(new URL(seen[0]).pathname).toBe('/check-http');
    expect(new URL(seen[0]).searchParams.get('host')).toBe('https://front.example:443/');
  });

  test('check-http results: [1, s, msg, status, ip] = reachable, [0, ...] = fail with the name scrubbed', () => {
    const p = parseCheckhostResult(
      {
        'ir1.node.check-host.net': [[1, 0.212, 'OK', '403', '198.51.100.7']],
        'ru1.node.check-host.net': [[0, 0.0, 'SSL error for front.example']],
      },
      { 'ir1.node.check-host.net': 'IR', 'ru1.node.check-host.net': 'RU' },
      {},
      ['front.example'],
    );
    expect(p.status).toBe('finished');
    expect(p.results[0]).toMatchObject({ country: 'IR', ok: true, rttMs: 212 });
    expect(p.results[1]).toMatchObject({ country: 'RU', ok: false });
    expect(p.results[1].error).not.toContain('front.example');
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
      { asnByProbe: { 1: 'AS1', 2: 'AS2', 3: 'AS3' } },
    );
    expect(out).toEqual([
      { country: 'IR', asn: 'AS1', vantageClass: 'unknown', ok: true, rttMs: 120 },
      {
        country: 'IR',
        asn: 'AS2',
        vantageClass: 'unknown',
        ok: false,
        error: 'connect: timeout',
      },
      {
        country: 'IR',
        asn: 'AS3',
        vantageClass: 'unknown',
        ok: true,
        rttMs: 80,
        error: 'tls_alert',
      },
    ]);
    // For a `tls` probe (an L7 front by name) the handshake IS the measurement:
    // an alerting probe is a failure, never positive country evidence.
    const tls = parseRipeAtlasResults(
      [{ prb_id: 3, rt: 80.2, alert: { level: 2, description: 40 } }],
      'IR',
      { asnByProbe: { 3: 'AS3' }, protocol: 'tls' },
    );
    expect(tls).toEqual([
      { country: 'IR', asn: 'AS3', vantageClass: 'unknown', ok: false, error: 'tls_alert' },
    ]);
    expect(
      parseRipeAtlasResults([{ prb_id: 3, alert: {} }], 'IR', { protocol: 'https' })[0]?.ok,
    ).toBe(false);
  });

  test('a probe id is NOT a network: without an ASN the results carry neither asn nor network, so they cannot fake agreement', () => {
    const out = parseRipeAtlasResults(
      [
        { prb_id: 11, err: 'timeout' },
        { prb_id: 12, err: 'timeout' },
      ],
      'IR',
    );
    expect(out.every((r) => r.asn === undefined && r.network === undefined)).toBe(true);
    // Two network-less failures are ONE bucket, so the source stays undecided.
    expect(sourceVerdict('ripeatlas', out, 2)).toMatchObject({
      verdict: 'unknown',
      failNetworks: ['ripeatlas:unknown'],
    });
    // With the registry's ASNs they are two real networks and agreement holds.
    const withAsn = parseRipeAtlasResults(
      [
        { prb_id: 11, err: 'timeout' },
        { prb_id: 12, err: 'timeout' },
      ],
      'IR',
      { asnByProbe: { 11: 'AS11', 12: 'AS12' } },
    );
    expect(sourceVerdict('ripeatlas', withAsn, 2).verdict).toBe('unreachable');
  });

  test('inline asn fields win over the registry; the registry lookup asks for ids only and tolerates failure', async () => {
    const inline = parseRipeAtlasResults([{ prb_id: 5, asn_v4: 64500, rt: 10 }], 'IR', {
      af: 4,
      asnByProbe: { 5: 'AS999' },
    });
    expect(inline[0].asn).toBe('AS64500');
    const seen: string[] = [];
    const asns = await fetchAtlasProbeAsns(
      async (url) => {
        seen.push(url);
        return new Response(
          JSON.stringify({ results: [{ id: 7, asn_v4: 64501, asn_v6: 64601 }] }),
          { status: 200 },
        );
      },
      'key',
      [7],
      6,
    );
    expect(asns).toEqual({ 7: 'AS64601' });
    const u = new URL(seen[0]);
    expect(u.pathname).toBe('/api/v2/probes/');
    expect(u.searchParams.get('id__in')).toBe('7');
    // A registry outage leaves the probes network-less rather than guessing.
    expect(
      await fetchAtlasProbeAsns(async () => new Response(null, { status: 503 }), 'key', [7], 4),
    ).toEqual({});
  });

  test('a name target is dialled by name with the hostname as SNI', () => {
    const b = ripeAtlasBody(nameTarget, 'IR', 2);
    expect(b.definitions[0]).toMatchObject({
      type: 'sslcert',
      af: 4,
      target: 'front.example',
      hostname: 'front.example',
    });
    // An IP target carries no SNI override.
    expect(ripeAtlasBody(target, 'IR', 2).definitions[0]).not.toHaveProperty('hostname');
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
    const ok = await internalProbe(
      { fetchFn: async () => new Response(null, { status: 400 }) },
      target,
    );
    expect(ok).toMatchObject({ country: 'XX', ok: true, vantageClass: 'datacenter' });
    const down = await internalProbe(
      {
        fetchFn: async () => {
          throw Object.assign(new Error('fetch failed'), { cause: { code: 'EHOSTUNREACH' } });
        },
      },
      target,
    );
    expect(down).toMatchObject({ country: 'XX', ok: false, error: 'EHOSTUNREACH' });
  });

  test('a tls target handshakes with SNI = the name, and a certificate failure IS unreachable', async () => {
    const seen: Array<Record<string, unknown>> = [];
    const probe = (handshake: { ok: boolean; error?: string }) =>
      internalProbe(
        {
          fetchFn: async () => {
            throw new Error('the tls probe must not use fetch');
          },
          lookup: async () => ['198.51.100.7'],
          tlsConnect: async (o) => {
            seen.push(o);
            return handshake;
          },
        },
        nameTarget,
      );
    expect(await probe({ ok: true })).toMatchObject({ country: 'XX', ok: true });
    // The connection goes to the literal the resolution check verified, never
    // to the name again (a second lookup could rebind to a private address).
    expect(seen[0]).toMatchObject({
      host: '198.51.100.7',
      port: 443,
      servername: 'front.example',
    });
    // Unlike the `tcp` rule, a certificate error is a failure here.
    expect(await probe({ ok: false, error: 'cert_invalid' })).toMatchObject({
      ok: false,
      error: 'cert_invalid',
    });
  });

  test('a name that resolves into private space is refused before anything is dialled', async () => {
    const calls: string[] = [];
    const run = (addresses: string[]) =>
      internalProbe(
        {
          fetchFn: async () => {
            calls.push('fetch');
            return new Response(null, { status: 200 });
          },
          lookup: async () => addresses,
          tlsConnect: async () => {
            calls.push('tls');
            return { ok: true };
          },
        },
        nameTarget,
      );
    expect(await run(['10.0.0.5'])).toMatchObject({ ok: false, error: 'private_address' });
    // One private answer among public ones is enough to refuse the whole name.
    expect(await run(['198.51.100.7', '127.0.0.1'])).toMatchObject({
      ok: false,
      error: 'private_address',
    });
    expect(calls).toEqual([]);
    expect(await run(['198.51.100.7'])).toMatchObject({ ok: true });
    expect(calls).toEqual(['tls']);
    // A resolver failure never leaks the name into the stored error.
    const failed = await internalProbe(
      {
        fetchFn: async () => new Response(null, { status: 200 }),
        lookup: async () => {
          throw Object.assign(new Error('getaddrinfo ENOTFOUND front.example'), {
            code: 'ENOTFOUND',
          });
        },
      },
      nameTarget,
    );
    expect(failed.ok).toBe(false);
    expect(failed.error).not.toContain('front.example');
    expect(await resolvePublic('front.example', async () => [])).toEqual({
      ok: false,
      error: 'no_address',
    });
  });

  test('name targets never re-resolve: tcp and https probes dial the verified literal with the name as SNI/Host', async () => {
    const dialed: Array<Record<string, unknown>> = [];
    const deps = {
      fetchFn: async () => {
        throw new Error('a name target must not use fetch (it would resolve the name again)');
      },
      lookup: async () => ['2001:db8::7', '198.51.100.7'],
      tcpConnect: async (o: Record<string, unknown>) => {
        dialed.push({ kind: 'tcp', ...o });
        return { ok: true };
      },
      httpsRequest: async (o: Record<string, unknown>) => {
        dialed.push({ kind: 'https', ...o });
        return { ok: true };
      },
    };
    expect(
      await internalProbe(deps, { ...nameTarget, protocol: 'tcp', requestedFamily: 4 }),
    ).toMatchObject({ ok: true });
    expect(dialed[0]).toMatchObject({ kind: 'tcp', host: '198.51.100.7', port: 443 });
    expect(
      await internalProbe(deps, { ...nameTarget, protocol: 'https', requestedFamily: 6 }),
    ).toMatchObject({ ok: true });
    expect(dialed[1]).toMatchObject({
      kind: 'https',
      host: '2001:db8::7',
      servername: 'front.example',
    });
    // No requested family: the first verified answer is dialled.
    await internalProbe(deps, { ...nameTarget, protocol: 'tcp' });
    expect(dialed[2]).toMatchObject({ host: '2001:db8::7' });
    expect(pickDialAddress(['198.51.100.7'], 6)).toBe('198.51.100.7');
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

  test('portRollup: any blocked listener blocks the country; reachable needs every decided port', () => {
    expect(portRollup([])).toBe('unknown');
    expect(portRollup(['unknown', 'unknown'])).toBe('unknown');
    // A single-port target keeps its own verdict, whatever it is.
    for (const v of ['reachable', 'unreachable', 'mixed', 'unknown'] as const)
      expect(portRollup([v])).toBe(v);
    expect(portRollup(['reachable', 'unreachable'])).toBe('unreachable');
    expect(portRollup(['mixed', 'unreachable', 'reachable'])).toBe('unreachable');
    expect(portRollup(['reachable', 'mixed'])).toBe('mixed');
    expect(portRollup(['reachable', 'reachable'])).toBe('reachable');
    // An undecided port never vetoes the others.
    expect(portRollup(['reachable', 'unknown'])).toBe('reachable');
    expect(portRollup(['unknown', 'unreachable'])).toBe('unreachable');
  });

  test('results with no asn and no network are ONE bucket, not one per result', () => {
    const anon = (ok: boolean): ProbeResult => ({ country: 'IR', ok, vantageClass: 'datacenter' });
    const s = sourceVerdict('checkhost', [anon(false), anon(false), anon(false)], 2);
    expect(s.failNetworks).toEqual(['checkhost:unknown']);
    expect(s.verdict).toBe('unknown');
    // The bucket is per source, so two sources still disagree independently.
    expect(sourceVerdict('globalping', [anon(false)], 1).failNetworks).toEqual([
      'globalping:unknown',
    ]);
    // A named network still counts for itself alongside the unknown bucket.
    const mixedIds = sourceVerdict(
      'checkhost',
      [anon(false), { ...anon(false), network: 'ir1' }],
      2,
    );
    expect(mixedIds.failNetworks.sort()).toEqual(['checkhost:unknown', 'ir1']);
    expect(mixedIds.verdict).toBe('unreachable');
  });

  test('shortError scrubs addresses, urls and hostnames', () => {
    expect(shortError('connect to 203.0.113.9 failed via https://x.example/y')).toBe(
      'connect to <ip> failed via <url>',
    );
    expect(shortError('peer [2001:db8::1] reset')).toBe('peer <ip6> reset');
    // A stored error must never carry the fronted hostname it was measuring.
    expect(shortError('no cert for abc123.front.example')).toBe('no cert for <host>');
    // Short codes and plain prose survive untouched.
    expect(shortError('ECONNREFUSED')).toBe('ECONNREFUSED');
    expect(shortError('Connection timed out')).toBe('Connection timed out');
    // An explicit redaction list catches names the generic shape misses.
    expect(shortError('handshake with intranet failed', 60, ['intranet'])).toBe(
      'handshake with <host> failed',
    );
  });
});
