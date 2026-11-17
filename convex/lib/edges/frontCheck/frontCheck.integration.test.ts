/**
 * The front qualification against a PINNED Xray-core, the software the origin
 * nodes actually run.
 *
 * The fake servers in session.test.ts prove the checker handles every answer a
 * chain can give, but a fake written beside the checker can agree with it on
 * the same wrong bytes without anyone noticing. This test removes that risk:
 * real Xray transports over `ws`, `httpupgrade`, `grpc` and `xhttp`, a real VLESS client
 * id, a real proxied request, and the same `qualifyFront` production calls.
 *
 * It runs only under the compat harness, which starts the container and mints
 * the certificate (docker/compat/frontcheck-up.sh, the `front-qualification`
 * job in .github/workflows/client-compatibility.yml). Without
 * FCP_FRONTCHECK_XRAY_URL there is nothing to talk to and the suite skips.
 */
import { readFileSync } from 'node:fs';
import { beforeAll, describe, expect, test } from 'vitest';
import { clientEncryption, generateVlessEncryption } from '../../backend/vlessEncryption';
import { qualifyFront, type FrontCheckResult } from './index';

const BASE = process.env.FCP_FRONTCHECK_XRAY_URL;
/** Fixed in docker/compat/frontcheck-xray.json; authenticates nothing else. */
const UUID = '01234567-89ab-cdef-0123-456789abcdef';
/** The name on the throwaway certificate the harness mints. */
const HOSTNAME = 'front.test';
const CA_PATH = process.env.FCP_FRONTCHECK_XRAY_CA ?? '.cache/compat/frontcheck/cert.pem';

function basePort(): number {
  return Number(new URL(BASE!).port || 443);
}

type Transport = 'ws' | 'httpupgrade' | 'grpc' | 'xhttp';
const OFFSET: Record<Transport, number> = { ws: 0, httpupgrade: 1, grpc: 2, xhttp: 3 };
/** Fixed in docker/compat/frontcheck-xray.json (Trojan over ws, the port after the four). */
const TROJAN_PASSWORD = 'fcp-frontcheck-trojan-test';
const TROJAN_OFFSET = 4;

/** The harness publishes ws, httpupgrade, grpc and xhttp on four consecutive ports. */
function portFor(protocol: Transport): number {
  const explicit =
    protocol === 'httpupgrade'
      ? process.env.FCP_FRONTCHECK_XRAY_HTTPUPGRADE_URL
      : protocol === 'grpc'
        ? process.env.FCP_FRONTCHECK_XRAY_GRPC_URL
        : protocol === 'xhttp'
          ? process.env.FCP_FRONTCHECK_XRAY_XHTTP_URL
          : BASE;
  if (explicit) return Number(new URL(explicit).port || 443);
  return basePort() + OFFSET[protocol];
}

describe.skipIf(!BASE)('front qualification against pinned Xray-core', () => {
  let ca = '';
  beforeAll(() => {
    ca = readFileSync(CA_PATH, 'utf8');
  });

  const run = (
    protocol: Transport,
    params: Record<string, string>,
    uuid = UUID,
  ): Promise<FrontCheckResult> =>
    qualifyFront(
      {
        hostname: HOSTNAME,
        proto: { protocol: 'vless', streamTransport: protocol, security: 'tls' },
        params,
        credential: { kind: 'vless', uuid },
        stepTimeoutMs: 10_000,
        // The container's outbound is pinned to the test origin, so the name
        // here is only what a member's client would really ask for.
        target: { host: 'www.gstatic.com', port: 80, path: '/generate_204' },
      },
      { dial: { host: '127.0.0.1', port: portFor(protocol), ca } },
    );

  test('websocket transport accepts our handshake, VLESS request and framing', async () => {
    const result = await run('ws', { path: '/relay-ws' });
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
    expect(result.steps.map((s) => s.step)).toEqual(['tls', 'transport', 'vless', 'close']);
  });

  test('httpupgrade inbound accepts the bare Upgrade with the default token', async () => {
    const result = await run('httpupgrade', { path: '/relay-hu', upgradeToken: 'websocket' });
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
  });

  test('grpc transport accepts our Hunk framing on /<service>/Tun', async () => {
    const result = await run('grpc', { serviceName: 'relay-svc' });
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
  });

  test('xhttp transport (packet-up) accepts our GET stream and sequenced POSTs', async () => {
    const result = await run('xhttp', { path: '/relay-xh', mode: 'packet-up' });
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
    expect(result.steps.map((s) => s.step)).toEqual(['tls', 'transport', 'vless', 'close']);
  });

  test('xhttp: a transport declared stream-only is reported as unsupported, never tried', async () => {
    const result = await run('xhttp', { path: '/relay-xh', mode: 'stream-one' });
    expect(result.ok).toBe(false);
    expect(result.code).toBe('transport_failed');
    expect(result.detail).toBe('mode');
  });

  test('real Xray refuses an unknown client id: auth_failed, not a false pass', async () => {
    const result = await run('ws', { path: '/relay-ws' }, 'ffffffff-ffff-ffff-ffff-ffffffffffff');
    expect(result.ok).toBe(false);
    expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
  });

  const trojan = (password: string): Promise<FrontCheckResult> =>
    qualifyFront(
      {
        hostname: HOSTNAME,
        proto: { protocol: 'trojan', streamTransport: 'ws', security: 'tls' },
        params: { path: '/relay-tw' },
        credential: { kind: 'trojan', password },
        stepTimeoutMs: 10_000,
        target: { host: 'www.gstatic.com', port: 80, path: '/generate_204' },
      },
      { dial: { host: '127.0.0.1', port: basePort() + TROJAN_OFFSET, ca } },
    );

  test('trojan over websocket accepts our Trojan request and returns the target', async () => {
    const result = await trojan(TROJAN_PASSWORD);
    expect(result.code).toBeUndefined();
    expect(result.ok).toBe(true);
    expect(result.steps.map((s) => s.step)).toEqual(['tls', 'transport', 'vless', 'close']);
  });

  test('real Xray refuses an unknown Trojan password: auth_failed, not a false pass', async () => {
    const result = await trojan('not-the-password');
    expect(result.ok).toBe(false);
    expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
  });

  test('a path the transport does not serve never becomes a tunnel', async () => {
    const result = await run('ws', { path: '/not-deployed' });
    expect(result.ok).toBe(false);
    expect(result.code).not.toBeUndefined();
  });

  // VLESS Encryption (docs/backends.md "VLESS Encryption"). The handshake
  // client in vlessEncryption.ts was written from Xray's source; this is where
  // it meets the real thing. Server strings fixed in frontcheck-xray.json.
  describe('VLESS Encryption', () => {
    const MLKEM768_SERVER =
      'mlkem768x25519plus.native.600s.Fvh2r1IFz2xQPXUqrNnCHhdPaqQY_ZSylKqHCfP0LCTlXBjPM7rBgU8y_qzQwFgXLVerLACnrIkcidp6SwRxKw';
    const X25519_XORPUB_SERVER =
      'mlkem768x25519plus.xorpub.600s.gKcizb1S38QLEf6BU2hhJ71xnyP-RPUaQFcnV4KPClE';
    /** The four encrypted inbounds follow the five plain ones. */
    const ENCRYPTED_OFFSET = { ws: 5, grpc: 6, xhttp: 7, 'ws-x25519': 8 } as const;
    const pq = clientEncryption(MLKEM768_SERVER)!;

    const encrypted = (
      inbound: keyof typeof ENCRYPTED_OFFSET,
      params: Record<string, string>,
      credential: { uuid?: string; encryption?: string },
      stepTimeoutMs = 10_000,
    ): Promise<FrontCheckResult> =>
      qualifyFront(
        {
          hostname: HOSTNAME,
          proto: {
            protocol: 'vless',
            streamTransport: inbound === 'ws-x25519' ? 'ws' : inbound,
            security: 'tls',
          },
          params,
          credential: { kind: 'vless', uuid: credential.uuid ?? UUID, ...credential },
          stepTimeoutMs,
          target: { host: 'www.gstatic.com', port: 80, path: '/generate_204' },
        },
        { dial: { host: '127.0.0.1', port: basePort() + ENCRYPTED_OFFSET[inbound], ca } },
      );

    test('websocket under an ML-KEM-768 key: real Xray completes our handshake and proxies', async () => {
      const result = await encrypted('ws', { path: '/relay-ws-e' }, { encryption: pq });
      expect(result.code).toBeUndefined();
      expect(result.ok).toBe(true);
      expect(result.steps.map((s) => s.step)).toEqual(['tls', 'transport', 'vless', 'close']);
    });

    test('gRPC and XHTTP carry the same encrypted session', async () => {
      const grpc = await encrypted('grpc', { serviceName: 'relay-svc-e' }, { encryption: pq });
      expect(grpc.code).toBeUndefined();
      expect(grpc.ok).toBe(true);
      const xhttp = await encrypted(
        'xhttp',
        { path: '/relay-xh-e', mode: 'packet-up' },
        { encryption: pq },
      );
      expect(xhttp.code).toBeUndefined();
      expect(xhttp.ok).toBe(true);
    });

    test('an X25519 key with the share masked (xorpub)', async () => {
      const result = await encrypted(
        'ws-x25519',
        { path: '/relay-ws-x' },
        { encryption: clientEncryption(X25519_XORPUB_SERVER)! },
      );
      expect(result.code).toBeUndefined();
      expect(result.ok).toBe(true);
    });

    test("another node's key is refused by real Xray: auth_failed, not a false pass", async () => {
      const other = clientEncryption(generateVlessEncryption().decryption)!;
      const result = await encrypted('ws', { path: '/relay-ws-e' }, { encryption: other });
      expect(result.ok).toBe(false);
      expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
    });

    test('the right key with an unknown client id is refused', async () => {
      const result = await encrypted(
        'ws',
        { path: '/relay-ws-e' },
        { encryption: pq, uuid: 'ffffffff-ffff-ffff-ffff-ffffffffffff' },
      );
      expect(result.ok).toBe(false);
      expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
    });

    test('an encrypted transport gives a plain client nothing: it is one or the other', async () => {
      const result = await encrypted('ws', { path: '/relay-ws-e' }, {}, 3_000);
      expect(result.ok).toBe(false);
      expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
    });

    test('a plain transport gives an encrypted client nothing', async () => {
      const result = await qualifyFront(
        {
          hostname: HOSTNAME,
          proto: { protocol: 'vless', streamTransport: 'ws', security: 'tls' },
          params: { path: '/relay-ws' },
          credential: { kind: 'vless', uuid: UUID, encryption: pq },
          stepTimeoutMs: 3_000,
          target: { host: 'www.gstatic.com', port: 80, path: '/generate_204' },
        },
        { dial: { host: '127.0.0.1', port: portFor('ws'), ca } },
      );
      expect(result.ok).toBe(false);
      expect(result.code).toMatch(/^(auth_failed|timeout_vless)$/);
    });
  });
});
