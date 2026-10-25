/**
 * FCP's own client check, the pure halves (docs/edges.md § "FCP's own client
 * check"): request signing, what the service accepts, how an engine's output
 * reads, the test link -> engine outbound converter, the verdict against a
 * control, and FCP's service client. Documentation addresses only.
 */
import { describe, expect, test } from 'vitest';
import {
  clientCheckService,
  DEFAULT_CLIENT_CHECK_URL,
  fetchHealth,
  runEngineCheck,
} from './client';
import { engineConfig, parseEngineVersion, sessionCodeOf } from './engine';
import { outboundsForLink } from './outbound';
import {
  CLIENT_CHECK_SIGNATURE_HEADER,
  CLIENT_CHECK_TIME_HEADER,
  type ClientCheckResponse,
} from './protocol';
import { sanitizeOutbound } from './sanitize';
import { ReplayGuard, signRequest, verifyRequest } from './signing';
import { judge, needsControl, type EngineRun } from './verdict';

const UUID = '00000000-0000-4000-8000-000000000001';
const PBK = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0';

describe('signing', () => {
  test('a signed request verifies once; a replay, a stale time or another body does not', async () => {
    const guard = new ReplayGuard();
    const now = 1_800_000_000_000;
    const time = String(now);
    const body = '{"engine":"sing-box"}';
    const signature = await signRequest('s3cret', 'POST', '/v1/check', time, body);
    const req = { method: 'POST', path: '/v1/check', time, signature, body };
    expect(await verifyRequest('s3cret', req, now + 1000, guard)).toBe('ok');
    expect(await verifyRequest('s3cret', req, now + 2000, guard)).toBe('replayed');
    expect(await verifyRequest('s3cret', { ...req, body: '{}' }, now, new ReplayGuard())).toBe(
      'bad_signature',
    );
    expect(await verifyRequest('other', req, now, new ReplayGuard())).toBe('bad_signature');
    expect(await verifyRequest('s3cret', req, now + 61_000, new ReplayGuard())).toBe('bad_time');
    expect(await verifyRequest('s3cret', { ...req, time: null }, now, new ReplayGuard())).toBe(
      'bad_time',
    );
    expect(
      await verifyRequest('s3cret', { ...req, path: '/v1/health' }, now, new ReplayGuard()),
    ).toBe('bad_signature');
  });

  test('the replay window forgets old signatures', () => {
    const g = new ReplayGuard(1000);
    expect(g.admit('a', 0)).toBe(true);
    expect(g.admit('a', 500)).toBe(false);
    expect(g.admit('a', 2000)).toBe(true);
  });
});

describe('sanitizeOutbound', () => {
  const reality = {
    type: 'vless',
    server: '203.0.113.10',
    server_port: 443,
    uuid: UUID,
    flow: 'xtls-rprx-vision',
    tls: {
      enabled: true,
      server_name: 'www.example.com',
      utls: { enabled: true, fingerprint: 'chrome' },
      reality: { enabled: true, public_key: PBK, short_id: 'ab' },
    },
  };

  test('rebuilds a sing-box outbound from the allowlist and drops everything else', () => {
    const r = sanitizeOutbound('sing-box', {
      ...reality,
      detour: 'direct',
      bind_interface: 'eth0',
      routing_mark: 1,
      tls: { ...reality.tls, certificate_path: '/etc/passwd' },
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.outbound).toEqual(reality);
    expect(r.destination).toEqual({ address: '203.0.113.10', port: 443 });
  });

  test('refuses a private, loopback or named destination unless the harness allows private', () => {
    for (const server of ['10.0.0.1', '127.0.0.1', '192.168.1.1', 'fd00::1', 'node.example'])
      expect(sanitizeOutbound('sing-box', { ...reality, server })).toEqual({
        ok: false,
        code: 'destination_not_public',
      });
    expect(
      sanitizeOutbound('sing-box', { ...reality, server: '10.0.0.1' }, { allowPrivate: true }).ok,
    ).toBe(true);
    expect(
      sanitizeOutbound('sing-box', { ...reality, server: 'node.example' }, { allowPrivate: true })
        .ok,
    ).toBe(false);
  });

  test('refuses unknown types, transports and wrongly typed fields', () => {
    expect(sanitizeOutbound('sing-box', { ...reality, type: 'direct' })).toEqual({
      ok: false,
      code: 'unsupported_type',
    });
    expect(sanitizeOutbound('sing-box', { ...reality, transport: { type: 'quic' } })).toEqual({
      ok: false,
      code: 'unsupported_type',
    });
    expect(sanitizeOutbound('sing-box', { ...reality, server_port: '443' })).toEqual({
      ok: false,
      code: 'invalid_outbound',
    });
    expect(sanitizeOutbound('sing-box', null)).toEqual({ ok: false, code: 'invalid_outbound' });
  });

  test('an Xray outbound keeps one server and no second destination or dialer', () => {
    const xr = {
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: '203.0.113.10',
            port: 443,
            users: [{ id: UUID, encryption: 'none', flow: 'xtls-rprx-vision' }],
          },
        ],
      },
      streamSettings: {
        network: 'xhttp',
        security: 'reality',
        realitySettings: { serverName: 'www.example.com', publicKey: PBK, shortId: 'ab' },
        xhttpSettings: {
          path: '/x',
          mode: 'auto',
          extra: {
            xPaddingBytes: '100-1000',
            downloadSettings: { address: '10.0.0.1', port: 443 },
          },
        },
        sockopt: { dialerProxy: 'other' },
      },
      proxySettings: { tag: 'other' },
    };
    const r = sanitizeOutbound('xray', xr);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const stream = r.outbound.streamSettings as Record<string, unknown>;
    expect(stream.sockopt).toBeUndefined();
    expect(r.outbound.proxySettings).toBeUndefined();
    expect(
      (stream.xhttpSettings as { extra: Record<string, unknown> }).extra.downloadSettings,
    ).toBeUndefined();
    const two = {
      ...xr,
      settings: { vnext: [xr.settings.vnext[0], { ...xr.settings.vnext[0], address: '10.0.0.2' }] },
    };
    expect(sanitizeOutbound('xray', two)).toEqual({ ok: false, code: 'invalid_outbound' });
    expect(sanitizeOutbound('xray', { ...xr, protocol: 'freedom' })).toEqual({
      ok: false,
      code: 'unsupported_type',
    });
  });
});

describe('engine', () => {
  test('the configuration has one loopback inbound and the outbound as the only route', () => {
    const sb = engineConfig('sing-box', { type: 'vless' }, 41000) as {
      inbounds: Array<{ listen: string; listen_port: number }>;
      outbounds: Array<{ tag: string }>;
      route: { final: string };
    };
    expect(sb.inbounds).toEqual([
      { type: 'mixed', tag: 'in', listen: '127.0.0.1', listen_port: 41000 },
    ]);
    expect(sb.outbounds.map((o) => o.tag)).toEqual(['check']);
    expect(sb.route.final).toBe('check');
    const xr = engineConfig('xray', { protocol: 'vless' }, 41001) as {
      inbounds: Array<{ listen: string; protocol: string }>;
      outbounds: unknown[];
    };
    expect(xr.inbounds[0]).toMatchObject({ listen: '127.0.0.1', protocol: 'http' });
    expect(xr.outbounds).toHaveLength(1);
  });

  test('versions', () => {
    expect(parseEngineVersion('sing-box', 'sing-box version 1.14.3\n\nEnvironment: go')).toBe(
      '1.14.3',
    );
    expect(parseEngineVersion('xray', 'Xray 26.10.21 (Xray, Penetrates Everything.)')).toBe(
      '26.10.21',
    );
    expect(parseEngineVersion('xray', 'nothing')).toBeNull();
  });

  test('a failed session reads as the reason the engine logged', () => {
    const started = { reality: true, started: true };
    expect(sessionCodeOf('ERROR ... reality verification failed', started)).toBe('reality_refused');
    expect(sessionCodeOf('REALITY: received real certificate', started)).toBe('reality_refused');
    // A REALITY server hands a refused client to its target: a CA error is a refusal.
    expect(sessionCodeOf('x509: certificate signed by unknown authority', started)).toBe(
      'reality_refused',
    );
    expect(
      sessionCodeOf('x509: certificate signed by unknown authority', {
        reality: false,
        started: true,
      }),
    ).toBe('tls_failed');
    expect(sessionCodeOf('dial tcp 203.0.113.10:443: i/o timeout', started)).toBe('timeout');
    expect(sessionCodeOf('connect: connection refused', started)).toBe('refused');
    expect(sessionCodeOf('read: connection reset by peer', started)).toBe('reset');
    expect(sessionCodeOf('connect: no route to host', started)).toBe('unreachable');
    expect(sessionCodeOf('something else', started)).toBe('session_failed');
    expect(
      sessionCodeOf('FATAL decode config at outbounds[0]: unknown field', {
        reality: false,
        started: false,
      }),
    ).toBe('config_refused');
  });
});

describe('outboundsForLink', () => {
  test('VLESS REALITY over raw TCP: both engines, the link fields only', () => {
    const r = outboundsForLink(
      `vless://${UUID}@203.0.113.10:443?security=reality&type=tcp&headerType=none&fp=firefox&sni=www.example.com&pbk=${PBK}&sid=ab&flow=xtls-rprx-vision&spx=%2F#FCP%20test`,
    );
    expect(r?.proto).toEqual({ protocol: 'vless', streamTransport: 'raw', security: 'reality' });
    expect(r?.reality).toBe(true);
    expect(r?.outbounds['sing-box']).toEqual({
      type: 'vless',
      server: '203.0.113.10',
      server_port: 443,
      uuid: UUID,
      flow: 'xtls-rprx-vision',
      tls: {
        enabled: true,
        server_name: 'www.example.com',
        utls: { enabled: true, fingerprint: 'firefox' },
        reality: { enabled: true, public_key: PBK, short_id: 'ab' },
      },
    });
    expect(r?.outbounds.xray).toEqual({
      protocol: 'vless',
      settings: {
        vnext: [
          {
            address: '203.0.113.10',
            port: 443,
            users: [{ id: UUID, encryption: 'none', flow: 'xtls-rprx-vision' }],
          },
        ],
      },
      streamSettings: {
        network: 'raw',
        security: 'reality',
        realitySettings: {
          serverName: 'www.example.com',
          fingerprint: 'firefox',
          publicKey: PBK,
          shortId: 'ab',
          spiderX: '/',
        },
      },
    });
    // Every converted outbound passes the service's allowlist unchanged.
    for (const e of ['sing-box', 'xray'] as const) {
      const s = sanitizeOutbound(e, r!.outbounds[e]);
      expect(s.ok && s.outbound).toEqual(r!.outbounds[e]);
    }
  });

  test('XHTTP is Xray only; sing-box is skipped and says why', () => {
    const r = outboundsForLink(
      `vless://${UUID}@203.0.113.10:8443?security=reality&type=xhttp&path=%2Fx&mode=auto&sni=www.example.com&pbk=${PBK}&sid=ab#t`,
    );
    expect(r?.skipped['sing-box']).toBe('no_xhttp');
    expect(r?.outbounds['sing-box']).toBeUndefined();
    expect(r?.outbounds.xray?.streamSettings).toMatchObject({
      network: 'xhttp',
      xhttpSettings: { path: '/x', mode: 'auto' },
    });
    expect(sanitizeOutbound('xray', r!.outbounds.xray).ok).toBe(true);
  });

  test('VLESS with its own encryption is Xray only', () => {
    const r = outboundsForLink(
      `vless://${UUID}@203.0.113.10:443?security=reality&type=tcp&encryption=mlkem768x25519plus.native.0rtt.abc&sni=a.example&pbk=${PBK}#t`,
    );
    expect(r?.skipped['sing-box']).toBe('vless_encryption');
    expect(r?.outbounds.xray).toBeDefined();
  });

  test('WebSocket under TLS, early data split for sing-box', () => {
    const r = outboundsForLink(
      `vless://${UUID}@203.0.113.10:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example&sni=cdn.example&alpn=h2%2Chttp%2F1.1#t`,
    );
    expect(r?.outbounds['sing-box']).toMatchObject({
      tls: { enabled: true, server_name: 'cdn.example', alpn: ['h2', 'http/1.1'] },
      transport: {
        type: 'ws',
        path: '/ws',
        headers: { Host: 'cdn.example' },
        max_early_data: 2048,
        early_data_header_name: 'Sec-WebSocket-Protocol',
      },
    });
    expect(r?.outbounds.xray?.streamSettings).toMatchObject({
      network: 'ws',
      security: 'tls',
      wsSettings: { path: '/ws?ed=2048', host: 'cdn.example' },
    });
  });

  test('Trojan over gRPC', () => {
    const r = outboundsForLink(
      'trojan://p%40ss@203.0.113.10:443?security=tls&type=grpc&serviceName=svc&sni=node.example#t',
    );
    expect(r?.outbounds['sing-box']).toMatchObject({
      type: 'trojan',
      password: 'p@ss',
      transport: { type: 'grpc', service_name: 'svc' },
    });
    expect(r?.outbounds.xray).toMatchObject({
      protocol: 'trojan',
      settings: { servers: [{ address: '203.0.113.10', port: 443, password: 'p@ss' }] },
      streamSettings: { network: 'grpc', grpcSettings: { serviceName: 'svc' } },
    });
  });

  test('Shadowsocks (an Outline key, base64 and plain userinfo)', () => {
    const b64 = outboundsForLink(
      'ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpleGFtcGxlLXBhc3N3b3Jk@203.0.113.10:8388/?outline=1#Key',
    );
    expect(b64?.outbounds['sing-box']).toEqual({
      type: 'shadowsocks',
      server: '203.0.113.10',
      server_port: 8388,
      method: 'chacha20-ietf-poly1305',
      password: 'example-password',
    });
    expect(b64?.outbounds.xray).toEqual({
      protocol: 'shadowsocks',
      settings: {
        servers: [
          {
            address: '203.0.113.10',
            port: 8388,
            method: 'chacha20-ietf-poly1305',
            password: 'example-password',
          },
        ],
      },
    });
    const plain = outboundsForLink('ss://2022-blake3-aes-128-gcm:a2V5@203.0.113.10:8388#k');
    expect(plain?.outbounds['sing-box']).toMatchObject({
      method: '2022-blake3-aes-128-gcm',
      password: 'a2V5',
    });
    expect(outboundsForLink('ss://YTpi@203.0.113.10:8388?plugin=obfs-local')).toBeNull();
  });

  test('Hysteria2 is sing-box only', () => {
    const r = outboundsForLink(
      'hy2://pw@203.0.113.10:443?sni=node.example&obfs=salamander&obfs-password=o#t',
    );
    expect(r?.outbounds['sing-box']).toMatchObject({
      type: 'hysteria2',
      password: 'pw',
      tls: { enabled: true, server_name: 'node.example' },
      obfs: { type: 'salamander', password: 'o' },
    });
    expect(r?.skipped.xray).toBe('no_codec');
  });

  test('not a link FCP renders', () => {
    expect(outboundsForLink('vmess://eyJhZGQiOiJ4In0=')).toBeNull();
    expect(outboundsForLink('nonsense')).toBeNull();
    expect(outboundsForLink(`vless://${UUID}@203.0.113.10:443?type=kcp`)).toBeNull();
  });
});

describe('judge', () => {
  const run = (
    engine: EngineRun['engine'],
    ok: boolean,
    egressIp: string | null = ok ? '198.51.100.7' : null,
  ): EngineRun => ({
    engine,
    ok,
    code: ok ? 'ok' : 'reality_refused',
    egressIp,
    engineVersion: null,
  });
  const expectedEgress = ['198.51.100.7'];

  test('every engine connects out of the node: passed, no control needed', () => {
    const candidate = [run('sing-box', true), run('xray', true)];
    expect(needsControl(candidate, expectedEgress)).toBe(false);
    expect(judge({ candidate, control: null, expectedEgress, expectedRefusals: [] })).toMatchObject(
      { verdict: 'passed', ok: true },
    );
  });

  test('sing-box refused here and through the control: as good as what members have', () => {
    const j = judge({
      candidate: [run('sing-box', false), run('xray', true)],
      control: [run('sing-box', false), run('xray', true)],
      expectedEgress,
      expectedRefusals: [],
    });
    expect(j).toMatchObject({ verdict: 'passed_with_refusals', ok: true });
    expect(j.engines[0]).toMatchObject({ engine: 'sing-box', excused: true, egress: null });
  });

  test('refused here while the control admits it: the address failed', () => {
    expect(
      judge({
        candidate: [run('sing-box', false), run('xray', true)],
        control: [run('sing-box', true), run('xray', true)],
        expectedEgress,
        expectedRefusals: [],
      }),
    ).toMatchObject({ verdict: 'address_failed', ok: false });
  });

  test('no control: only a refusal the REALITY verdict predicts is excused', () => {
    const candidate = [run('sing-box', false), run('xray', true)];
    expect(
      judge({ candidate, control: null, expectedEgress, expectedRefusals: ['sing-box'] }).verdict,
    ).toBe('passed_with_refusals');
    expect(judge({ candidate, control: null, expectedEgress, expectedRefusals: [] }).verdict).toBe(
      'address_failed',
    );
  });

  test('a control that connects nowhere is no control', () => {
    expect(
      judge({
        candidate: [run('sing-box', false), run('xray', true)],
        control: [run('sing-box', false), run('xray', false)],
        expectedEgress,
        expectedRefusals: ['sing-box'],
      }).verdict,
    ).toBe('passed_with_refusals');
  });

  test('nothing connects here or through the control: node_unreachable', () => {
    expect(
      judge({
        candidate: [run('sing-box', false), run('xray', false)],
        control: [run('sing-box', false), run('xray', false)],
        expectedEgress,
        expectedRefusals: [],
      }),
    ).toMatchObject({ verdict: 'node_unreachable', ok: false });
    expect(
      judge({
        candidate: [run('sing-box', false), run('xray', false)],
        control: null,
        expectedEgress,
        expectedRefusals: [],
      }).verdict,
    ).toBe('address_failed');
  });

  test('egress: another address fails; the control egress of a node with a second address passes', () => {
    const elsewhere = [run('sing-box', true, '198.51.100.99'), run('xray', true, '198.51.100.99')];
    expect(needsControl(elsewhere, expectedEgress)).toBe(true);
    expect(
      judge({ candidate: elsewhere, control: null, expectedEgress, expectedRefusals: [] }).verdict,
    ).toBe('egress_mismatch');
    expect(
      judge({
        candidate: elsewhere,
        control: [run('sing-box', true, '198.51.100.99'), run('xray', true, '198.51.100.99')],
        expectedEgress,
        expectedRefusals: [],
      }).verdict,
    ).toBe('passed');
    // An IPv6 egress written two ways is the same address.
    expect(
      judge({
        candidate: [run('sing-box', true, '2001:db8:0:0::1')],
        control: null,
        expectedEgress: ['2001:db8::1'],
        expectedRefusals: [],
      }).verdict,
    ).toBe('passed');
  });
});

describe('service client', () => {
  test('configured only with a secret; the compose name by default', () => {
    expect(clientCheckService({})).toBeNull();
    expect(clientCheckService({ EDGE_CLIENT_CHECK_SECRET: ' ' })).toBeNull();
    expect(clientCheckService({ EDGE_CLIENT_CHECK_SECRET: 'x' })).toEqual({
      url: DEFAULT_CLIENT_CHECK_URL,
      secret: 'x',
    });
    expect(
      clientCheckService({ EDGE_CLIENT_CHECK_SECRET: 'x', EDGE_CLIENT_CHECK_URL: 'http://h:1/' })
        ?.url,
    ).toBe('http://h:1');
  });

  test('every call is signed; refusals map to "could not check"', async () => {
    const svc = { url: 'http://svc', secret: 's3cret' };
    const seen: Array<{ url: string; init: RequestInit }> = [];
    const answer: ClientCheckResponse = {
      ok: true,
      engine: 'sing-box',
      engineVersion: '1.14.3',
      egressIp: '198.51.100.7',
      ms: 10,
      code: 'ok',
    };
    const ok = async (url: string, init: RequestInit) => {
      seen.push({ url, init });
      return new Response(JSON.stringify(answer));
    };
    const req = { engine: 'sing-box' as const, outbound: { type: 'vless' }, reality: true };
    expect(await runEngineCheck(svc, req, ok)).toEqual({ ok: true, value: answer });
    const h = seen[0]!.init.headers as Record<string, string>;
    expect(seen[0]!.url).toBe('http://svc/v1/check');
    expect(
      await verifyRequest(
        's3cret',
        {
          method: 'POST',
          path: '/v1/check',
          time: h[CLIENT_CHECK_TIME_HEADER]!,
          signature: h[CLIENT_CHECK_SIGNATURE_HEADER]!,
          body: String(seen[0]!.init.body),
        },
        Number(h[CLIENT_CHECK_TIME_HEADER]),
        new ReplayGuard(),
      ),
    ).toBe('ok');
    const status = (n: number) => async () => new Response('{}', { status: n });
    expect(await runEngineCheck(svc, req, status(401))).toEqual({
      ok: false,
      code: 'unauthorized',
    });
    expect(await runEngineCheck(svc, req, status(429))).toEqual({ ok: false, code: 'busy' });
    expect(await runEngineCheck(svc, req, status(503))).toEqual({
      ok: false,
      code: 'not_configured',
    });
    expect(await runEngineCheck(svc, req, status(500))).toEqual({ ok: false, code: 'unavailable' });
    expect(
      await runEngineCheck(svc, req, async () => {
        throw new TypeError('fetch failed');
      }),
    ).toEqual({ ok: false, code: 'unavailable' });
    expect(
      await fetchHealth(svc, async () =>
        Response.json({
          ok: true,
          engines: [{ engine: 'xray', version: '26.10.21' }],
          egressHost: 'h',
        }),
      ),
    ).toMatchObject({ ok: true });
  });
});
