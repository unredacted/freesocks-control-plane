// @vitest-environment node
/**
 * The pinned fetch against a local TLS server. The server stands for a list's
 * source at `list.test`; the resolver is a fake whose answers the tests
 * control, so they can prove that the connection only ever reaches what was
 * checked, and that the name (Host, SNI, certificate) is kept.
 */
import { afterEach, describe, expect, test } from 'vitest';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { isPublicIpLiteral } from '../ip';
import { pinnedFetch, pinnedLookup, type Answer, type PinnedFetchDeps } from './pinnedFetch';

/**
 * A throwaway self-signed certificate for `list.test` only. It is not a secret
 * and never leaves this file: the tests pass it as an explicit trust anchor
 * (`deps.ca`), where production passes nothing and uses the system store.
 */
const KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHfl5MQtfjeVf4DBk
0UHy5CLuWXpQMkqHwseuZ3XrmvqhRANCAARaejfGoHoyDJlZiQjEkWxN3Htk3qhu
CfGZ1yA+Dk6TBtZztcJkqQzBXPVqMCPManiAJ1BRek9dDkVQgsohHPPh
-----END PRIVATE KEY-----`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIBdTCCARqgAwIBAgIUYbsCDmFo/DV8gb4CiRMwfCBRENswCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbGlzdC50ZXN0MCAXDTI2MTEwMzA0MTUyMFoYDzIxMjYxMDEw
MDQxNTIwWjAUMRIwEAYDVQQDDAlsaXN0LnRlc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAARaejfGoHoyDJlZiQjEkWxN3Htk3qhuCfGZ1yA+Dk6TBtZztcJkqQzB
XPVqMCPManiAJ1BRek9dDkVQgsohHPPho0gwRjAdBgNVHQ4EFgQUPN1lXmBLXfiY
hj+xu4gPV15/kcYwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTALgglsaXN0LnRl
c3QwCgYIKoZIzj0EAwIDSQAwRgIhAMfiTFJnNVVpUzEtuwnigFtwBGnUKR8JufOg
8BA1nmktAiEAuIA4vAa0vuKGSSz0FrdyUOQE/7G/M7fxna/IwMrUhYs=
-----END CERTIFICATE-----`;

const URL_ = 'https://list.test/lists/one.txt';
const LIMITS = { maxBytes: 1024, timeoutMs: 5_000 };

interface Seen {
  host?: string;
  servername?: string;
  ifNoneMatch?: string;
  path?: string;
}

let server: Server | null = null;
afterEach(async () => {
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
});

/** A source that answers with `reply`, recording what it was asked. */
async function source(
  reply: (seen: Seen) => { status: number; body?: string; headers?: Record<string, string> },
): Promise<{ port: number; seen: Seen[] }> {
  const seen: Seen[] = [];
  server = createServer({ key: KEY, cert: CERT }, (req, res) => {
    const s: Seen = {
      host: req.headers.host,
      servername: (req.socket as TLSSocket).servername || undefined,
      ifNoneMatch: req.headers['if-none-match'] as string | undefined,
      path: req.url,
    };
    seen.push(s);
    const r = reply(s);
    res.writeHead(r.status, r.headers ?? {});
    res.end(r.body ?? '');
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return { port: (server!.address() as AddressInfo).port, seen };
}

/** Loopback stands for a public address here; everything else follows the real rule. */
const allow = (ip: string) => ip === '127.0.0.1' || isPublicIpLiteral(ip);

function deps(port: number, answers: () => Answer[], over: Partial<PinnedFetchDeps> = {}) {
  let calls = 0;
  const d: PinnedFetchDeps = {
    resolve: async () => {
      calls++;
      return answers();
    },
    allowAddress: allow,
    port,
    ca: CERT,
    ...over,
  };
  return { d, calls: () => calls };
}

describe('pinnedFetch', () => {
  test('fetches through the checked address, keeping the name', async () => {
    const s = await source(() => ({
      status: 200,
      body: 'example.com\n',
      headers: { etag: '"v1"' },
    }));
    const { d, calls } = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }]);
    const r = await pinnedFetch(URL_, LIMITS, d);
    expect(r).toEqual({ ok: true, status: 200, text: 'example.com\n', etag: '"v1"' });
    expect(calls()).toBe(1);
    expect(s.seen).toEqual([
      {
        host: 'list.test',
        servername: 'list.test',
        ifNoneMatch: undefined,
        path: '/lists/one.txt',
      },
    ]);
  });

  test('resolves once: a second answer pointing inside never reaches a socket', async () => {
    const s = await source(() => ({ status: 200, body: 'ok' }));
    let n = 0;
    // A rebinding resolver: public first, private every time after.
    const { d, calls } = deps(s.port, () =>
      n++ === 0 ? [{ address: '127.0.0.1', family: 4 }] : [{ address: '10.0.0.1', family: 4 }],
    );
    const r = await pinnedFetch(URL_, LIMITS, d);
    expect(r.ok).toBe(true);
    expect(calls()).toBe(1);
    expect(s.seen).toHaveLength(1);
  });

  test('refuses when any answer is not public', async () => {
    const s = await source(() => ({ status: 200, body: 'ok' }));
    const { d } = deps(s.port, () => [
      { address: '127.0.0.1', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ]);
    expect(await pinnedFetch(URL_, LIMITS, d)).toEqual({ ok: false, error: 'private_address' });
    expect(s.seen).toHaveLength(0);
  });

  test('refuses a private address written into the address', async () => {
    const { d } = deps(1, () => []);
    expect(await pinnedFetch('https://10.0.0.1/list.txt', LIMITS, d)).toEqual({
      ok: false,
      error: 'private_address',
    });
  });

  test('refuses anything but https on 443, and addresses with a user', async () => {
    const { d } = deps(1, () => [{ address: '127.0.0.1', family: 4 }]);
    for (const url of [
      'http://list.test/a',
      'https://list.test:8443/a',
      'https://user:pw@list.test/a',
      'not a url',
    ])
      expect(await pinnedFetch(url, LIMITS, d)).toEqual({ ok: false, error: 'bad_url' });
  });

  test('refuses redirects', async () => {
    const s = await source(() => ({ status: 302, headers: { location: 'https://10.0.0.1/' } }));
    const { d } = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }]);
    expect(await pinnedFetch(URL_, LIMITS, d)).toEqual({ ok: false, error: 'redirect_refused' });
  });

  test('cuts off a body past the cap, declared or not', async () => {
    const big = 'x'.repeat(LIMITS.maxBytes + 1);
    const s = await source(() => ({ status: 200, body: big }));
    const { d } = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }]);
    expect(await pinnedFetch(URL_, LIMITS, d)).toEqual({ ok: false, error: 'too_large' });
    const chunked = await source(() => ({
      status: 200,
      body: big,
      headers: { 'transfer-encoding': 'chunked' },
    }));
    const c = deps(chunked.port, () => [{ address: '127.0.0.1', family: 4 }]);
    expect(await pinnedFetch(URL_, LIMITS, c.d)).toEqual({ ok: false, error: 'too_large' });
  });

  test('sends its validators, and a 304 says nothing changed', async () => {
    const s = await source((seen) =>
      seen.ifNoneMatch === '"v1"' ? { status: 304 } : { status: 200, body: 'x' },
    );
    const { d } = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }]);
    expect(await pinnedFetch(URL_, { ...LIMITS, etag: '"v1"' }, d)).toEqual({
      ok: true,
      status: 304,
    });
  });

  test('a certificate it cannot trust fails, and so does a missing page', async () => {
    const s = await source(() => ({ status: 404 }));
    const untrusted = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }], { ca: undefined });
    expect(await pinnedFetch(URL_, LIMITS, untrusted.d)).toEqual({
      ok: false,
      error: 'tls_failed',
    });
    const trusted = deps(s.port, () => [{ address: '127.0.0.1', family: 4 }]);
    expect(await pinnedFetch(URL_, LIMITS, trusted.d)).toEqual({ ok: false, error: 'not_found' });
  });

  test('the deadline covers a lookup that never answers', async () => {
    const { d } = deps(1, () => []);
    const stuck: PinnedFetchDeps = { ...d, resolve: () => new Promise<Answer[]>(() => {}) };
    const t0 = Date.now();
    expect(await pinnedFetch(URL_, { maxBytes: 1024, timeoutMs: 50 }, stuck)).toEqual({
      ok: false,
      error: 'timeout',
    });
    expect(Date.now() - t0).toBeLessThan(2_000);
  });

  test('no answer is a failed lookup', async () => {
    const { d } = deps(1, () => []);
    expect(await pinnedFetch(URL_, LIMITS, d)).toEqual({ ok: false, error: 'dns_failed' });
  });
});

describe('pinnedLookup', () => {
  const answers: Answer[] = [
    { address: '192.0.2.1', family: 4 },
    { address: '2001:db8::1', family: 6 },
  ];

  test('a dual-stack connect gets only the checked answers', () => {
    let got: unknown;
    pinnedLookup(answers)('list.test', { all: true }, (_e, a) => (got = a));
    expect(got).toEqual(answers);
  });

  test('a single lookup gets the first checked answer of the family asked for', () => {
    const got: unknown[] = [];
    pinnedLookup(answers)('list.test', { family: 6 }, (_e, a, f) => got.push([a, f]));
    pinnedLookup(answers)('list.test', { family: 'IPv4' }, (_e, a, f) => got.push([a, f]));
    expect(got).toEqual([
      ['2001:db8::1', 6],
      ['192.0.2.1', 4],
    ]);
  });

  test('a family with no checked answer fails instead of resolving', () => {
    let err: NodeJS.ErrnoException | null = null;
    pinnedLookup([answers[0]!])('list.test', { family: 6 }, (e) => (err = e));
    expect(err).not.toBeNull();
    expect(err!.code).toBe('ENOTFOUND');
  });
});
