/**
 * The origin probe (acceptance 15, `originTransport` probe results): pure,
 * every socket injected. Fixtures are RFC 5737 literals and `*.example`.
 */
import { describe, expect, test, vi } from 'vitest';
import {
  dnsNamesOfSan,
  FOREIGN_HOST_HEADER,
  probeOriginTransport,
  type OriginProbeDeps,
  type OriginProbeRequest,
} from './originProbe';

function deps(over: Partial<OriginProbeDeps> = {}): OriginProbeDeps {
  return {
    lookup: vi.fn(async () => ['203.0.113.40']),
    tcpConnect: vi.fn(async () => ({ ok: true })),
    tlsInspect: vi.fn(async () => ({
      ok: true,
      authorized: true,
      names: ['ws.example', '*.alt.example'],
    })),
    httpsStatus: vi.fn(async () => ({ status: 404 })),
    ...over,
  };
}

const ws = (over: Partial<OriginProbeRequest> = {}): OriginProbeRequest => ({
  listenerKey: 'w',
  originAddress: '203.0.113.10',
  originPort: 443,
  streamTransport: 'ws',
  security: 'tls',
  tlsNames: ['ws.example'],
  ...over,
});

describe('probeOriginTransport', () => {
  test('security none: a TCP answer on the port -> a plaintext HTTP origin (L7-only)', async () => {
    const d = deps();
    const out = await probeOriginTransport(d, ws({ security: 'none', tlsNames: [] }));
    expect(out).toEqual({
      listenerKey: 'w',
      originTransport: {
        scheme: 'http',
        certPublic: false,
        certNames: [],
        acceptsHostHeader: 'any',
      },
    });
    expect(d.tcpConnect).toHaveBeenCalledWith({ host: '203.0.113.10', port: 443, timeoutMs: 6000 });
    expect(d.tlsInspect).not.toHaveBeenCalled();
    const down = deps({ tcpConnect: async () => ({ ok: false, error: 'ECONNREFUSED' }) });
    expect(await probeOriginTransport(down, ws({ security: 'none', tlsNames: [] }))).toEqual({
      listenerKey: 'w',
      originTransport: null,
      reason: 'ECONNREFUSED',
    });
  });

  test('security tls: SNI = the first name, certPublic = the chain verifies, certNames = the leaf names, Host acceptance conservative', async () => {
    const d = deps();
    const out = await probeOriginTransport(d, ws());
    expect(out.originTransport).toEqual({
      scheme: 'https',
      certPublic: true,
      certNames: ['ws.example', '*.alt.example'],
      acceptsHostHeader: 'names',
    });
    expect(d.tlsInspect).toHaveBeenCalledWith({
      host: '203.0.113.10',
      port: 443,
      servername: 'ws.example',
      timeoutMs: 6000,
    });
    // The Host-acceptance request carries a name no origin serves on purpose.
    expect(d.httpsStatus).toHaveBeenCalledWith(
      expect.objectContaining({ hostHeader: FOREIGN_HOST_HEADER, servername: 'ws.example' }),
    );
  });

  test("a foreign Host answered 2xx -> 'any'; a private certificate is recorded as not public", async () => {
    const any = deps({ httpsStatus: async () => ({ status: 200 }) });
    expect((await probeOriginTransport(any, ws())).originTransport?.acceptsHostHeader).toBe('any');
    const priv = deps({
      tlsInspect: async () => ({ ok: true, authorized: false, names: ['ws.example'] }),
    });
    expect((await probeOriginTransport(priv, ws())).originTransport).toEqual({
      scheme: 'https',
      certPublic: false,
      certNames: ['ws.example'],
      acceptsHostHeader: 'names',
    });
    // A Host-acceptance request that throws leaves the conservative answer.
    const boom = deps({
      httpsStatus: async () => {
        throw new Error('reset');
      },
    });
    expect((await probeOriginTransport(boom, ws())).originTransport?.acceptsHostHeader).toBe(
      'names',
    );
  });

  test('a failed handshake, a nameless TLS listener, a non-HTTP transport and REALITY are not probed into a transport', async () => {
    const failed = deps({
      tlsInspect: async () => ({ ok: false, authorized: false, names: [], error: 'timeout' }),
    });
    expect(await probeOriginTransport(failed, ws())).toEqual({
      listenerKey: 'w',
      originTransport: null,
      reason: 'timeout',
    });
    expect((await probeOriginTransport(deps(), ws({ tlsNames: [] }))).reason).toBe(
      'no_server_name',
    );
    expect((await probeOriginTransport(deps(), ws({ streamTransport: 'raw' }))).reason).toBe(
      'not_http_transport',
    );
    expect((await probeOriginTransport(deps(), ws({ security: 'reality' }))).reason).toBe(
      'not_http_origin',
    );
  });

  test('public literals only: a private origin is refused; a NAME resolves first and the literal is dialled (never the name)', async () => {
    for (const address of ['10.0.0.5', '192.168.1.2', '127.0.0.1', 'fd00::1']) {
      const d = deps();
      expect(await probeOriginTransport(d, ws({ originAddress: address }))).toEqual({
        listenerKey: 'w',
        originTransport: null,
        reason: 'private_address',
      });
      expect(d.tlsInspect).not.toHaveBeenCalled();
      expect(d.tcpConnect).not.toHaveBeenCalled();
    }
    const named = deps();
    const out = await probeOriginTransport(named, ws({ originAddress: 'origin.example' }));
    expect(out.originTransport?.scheme).toBe('https');
    expect(named.lookup).toHaveBeenCalledWith('origin.example');
    expect(named.tlsInspect).toHaveBeenCalledWith(
      expect.objectContaining({ host: '203.0.113.40', servername: 'ws.example' }),
    );
    // One private answer among the resolutions refuses the whole probe.
    const mixed = deps({ lookup: async () => ['203.0.113.40', '10.1.1.1'] });
    expect(
      (await probeOriginTransport(mixed, ws({ originAddress: 'origin.example' }))).reason,
    ).toBe('private_address');
    const unresolved = deps({
      lookup: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    expect(
      (await probeOriginTransport(unresolved, ws({ originAddress: 'origin.example' }))).reason,
    ).toBe('resolve_failed');
  });

  test('dnsNamesOfSan keeps DNS entries only', () => {
    expect(dnsNamesOfSan('DNS:a.example, DNS:*.b.example, IP Address:203.0.113.1')).toEqual([
      'a.example',
      '*.b.example',
    ]);
    expect(dnsNamesOfSan(undefined)).toEqual([]);
  });
});
