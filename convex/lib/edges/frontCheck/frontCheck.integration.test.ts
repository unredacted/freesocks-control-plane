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
        uuid,
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

  test('a path the transport does not serve never becomes a tunnel', async () => {
    const result = await run('ws', { path: '/not-deployed' });
    expect(result.ok).toBe(false);
    expect(result.code).not.toBeUndefined();
  });
});
