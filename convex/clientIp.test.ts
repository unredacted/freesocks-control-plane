/// <reference types="vite/client" />
import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import { resolveClientIp, resolveClientIpDetailed } from './lib/http';

/**
 * Client-IP trust rules (A1 launch audit + the third-pass multi-hop fix).
 *
 * Two invariants:
 *  - A1: a client-supplied `cf-connecting-ip` is honoured ONLY when CF_FRONTED=true
 *    (a real Cloudflare edge), else any client picks its own rate-limit bucket.
 *  - Multi-hop: X-Forwarded-For is RIGHT-anchored — we take `chain[len - hops]`, so
 *    the trusted-infra-appended tail is authoritative and a client-prepended head
 *    can't be chosen. `TRUSTED_PROXY_HOPS` is the generic knob; `TRUSTED_PROXY=true`
 *    is the legacy alias for hops=1 (single-Caddy edge). Behind a fronting proxy
 *    (Pangolin / CF Tunnel / ngrok / LB) hops=2. A chain shorter than hops → null.
 */
function req(headers: Record<string, string>): Request {
  return new Request('https://beta.freesocks.org/api/v1/account', { headers });
}

describe('resolveClientIp trust rules', () => {
  const saved = {
    CF_FRONTED: process.env.CF_FRONTED,
    TRUSTED_PROXY: process.env.TRUSTED_PROXY,
    TRUSTED_PROXY_HOPS: process.env.TRUSTED_PROXY_HOPS,
  };
  beforeEach(() => {
    delete process.env.CF_FRONTED;
    delete process.env.TRUSTED_PROXY;
    delete process.env.TRUSTED_PROXY_HOPS;
  });
  afterEach(() => {
    for (const k of ['CF_FRONTED', 'TRUSTED_PROXY', 'TRUSTED_PROXY_HOPS'] as const) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  // --- legacy TRUSTED_PROXY=true (≡ hops=1, single-Caddy edge) ---------------
  // A single Caddy with no trusted_proxies OVERWRITES XFF with the immediate peer,
  // so the chain is one entry and right-anchoring returns it — unchanged behavior.

  test('legacy TRUSTED_PROXY=true: single-entry XFF (Caddy overwrite) resolves; forged cf ignored', () => {
    process.env.TRUSTED_PROXY = 'true';
    const ip = resolveClientIp(
      req({ 'cf-connecting-ip': '6.6.6.6', 'x-forwarded-for': '203.0.113.7' }),
    );
    expect(ip).toBe('203.0.113.7');
  });

  test('legacy TRUSTED_PROXY=true: a lone forged cf-connecting-ip resolves to null (no spoof bucket)', () => {
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'cf-connecting-ip': '6.6.6.6' }))).toBeNull();
  });

  test('legacy TRUSTED_PROXY=true: values are trimmed', () => {
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'x-forwarded-for': '  203.0.113.7  ' }))).toBe('203.0.113.7');
  });

  // --- neither flag: nothing trusted -----------------------------------------

  test('neither flag set: nothing is trusted, even a real-looking XFF', () => {
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBeNull();
    expect(resolveClientIp(req({ 'cf-connecting-ip': '203.0.113.7' }))).toBeNull();
  });

  // --- CF_FRONTED (still wins first) -----------------------------------------

  test('CF_FRONTED=true: cf-connecting-ip is honoured (and preferred over XFF)', () => {
    process.env.CF_FRONTED = 'true';
    process.env.TRUSTED_PROXY = 'true';
    const ip = resolveClientIp(
      req({ 'cf-connecting-ip': '198.51.100.9', 'x-forwarded-for': '203.0.113.7' }),
    );
    expect(ip).toBe('198.51.100.9');
  });

  test('CF_FRONTED=true but no cf header: falls through to XFF when TRUSTED_PROXY=true', () => {
    process.env.CF_FRONTED = 'true';
    process.env.TRUSTED_PROXY = 'true';
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBe('203.0.113.7');
  });

  // --- TRUSTED_PROXY_HOPS (generic multi-hop) --------------------------------

  test('hops=1: single-entry XFF resolves (explicit form of the legacy alias)', () => {
    process.env.TRUSTED_PROXY_HOPS = '1';
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBe('203.0.113.7');
  });

  test('hops=2: takes the second-from-right (real client behind one fronting proxy)', () => {
    // Caddy appended the fronting peer; the fronting proxy set the client → 2 entries.
    process.env.TRUSTED_PROXY_HOPS = '2';
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7, 100.64.0.1' }))).toBe(
      '203.0.113.7',
    );
  });

  test('hops=2: spoofed-prepend immunity — a client-prepended head is NOT chosen', () => {
    // Client forged the leftmost; the trusted tail (real client, tunnel peer) is appended.
    process.env.TRUSTED_PROXY_HOPS = '2';
    expect(resolveClientIp(req({ 'x-forwarded-for': '6.6.6.6, 203.0.113.7, 100.64.0.1' }))).toBe(
      '203.0.113.7',
    );
  });

  test('hops=2: a chain shorter than hops → null (fail closed; direct-to-origin can’t self-bucket)', () => {
    process.env.TRUSTED_PROXY_HOPS = '2';
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBeNull();
    expect(resolveClientIp(req({}))).toBeNull();
  });

  test('hops: whitespace/empty entries are dropped before anchoring', () => {
    process.env.TRUSTED_PROXY_HOPS = '2';
    // After trim+filter → ['203.0.113.7', '100.64.0.1']; second-from-right = the client.
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7, , 100.64.0.1' }))).toBe(
      '203.0.113.7',
    );
  });

  test('TRUSTED_PROXY_HOPS wins over the legacy TRUSTED_PROXY alias when both are set', () => {
    process.env.TRUSTED_PROXY = 'true'; // would be hops=1
    process.env.TRUSTED_PROXY_HOPS = '2'; // wins
    expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7, 100.64.0.1' }))).toBe(
      '203.0.113.7',
    );
  });

  test('present-but-invalid TRUSTED_PROXY_HOPS → fail closed (does NOT fall back to legacy)', () => {
    process.env.TRUSTED_PROXY = 'true';
    for (const bad of ['0', '-1', 'abc', '1.5']) {
      process.env.TRUSTED_PROXY_HOPS = bad;
      expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBeNull();
    }
  });

  test('empty/whitespace TRUSTED_PROXY_HOPS is treated as unset → the legacy alias applies', () => {
    // An unfilled `TRUSTED_PROXY_HOPS=` from a template must NOT fail-close the
    // site; it reads as "not set", so TRUSTED_PROXY=true still gives hops=1.
    process.env.TRUSTED_PROXY = 'true';
    for (const empty of ['', '   ']) {
      process.env.TRUSTED_PROXY_HOPS = empty;
      expect(resolveClientIp(req({ 'x-forwarded-for': '203.0.113.7' }))).toBe('203.0.113.7');
    }
  });
});

describe('resolveClientIpDetailed (admin self-diagnostic shape)', () => {
  const saved = {
    CF_FRONTED: process.env.CF_FRONTED,
    TRUSTED_PROXY: process.env.TRUSTED_PROXY,
    TRUSTED_PROXY_HOPS: process.env.TRUSTED_PROXY_HOPS,
  };
  beforeEach(() => {
    delete process.env.CF_FRONTED;
    delete process.env.TRUSTED_PROXY;
    delete process.env.TRUSTED_PROXY_HOPS;
  });
  afterEach(() => {
    for (const k of ['CF_FRONTED', 'TRUSTED_PROXY', 'TRUSTED_PROXY_HOPS'] as const) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  test('rule=cf when CF_FRONTED resolves it', () => {
    process.env.CF_FRONTED = 'true';
    process.env.TRUSTED_PROXY_HOPS = '2';
    const d = resolveClientIpDetailed(
      req({ 'cf-connecting-ip': '198.51.100.9', 'x-forwarded-for': '203.0.113.7, 100.64.0.1' }),
    );
    expect(d).toMatchObject({ ip: '198.51.100.9', rule: 'cf', hops: 2 });
    // chain is still parsed for diagnosis even when cf wins.
    expect(d.chain).toEqual(['203.0.113.7', '100.64.0.1']);
  });

  test('rule=xff-hops for the explicit hops knob', () => {
    process.env.TRUSTED_PROXY_HOPS = '2';
    const d = resolveClientIpDetailed(req({ 'x-forwarded-for': '203.0.113.7, 100.64.0.1' }));
    expect(d).toEqual({
      ip: '203.0.113.7',
      rule: 'xff-hops',
      hops: 2,
      chain: ['203.0.113.7', '100.64.0.1'],
    });
  });

  test('rule=xff-legacy for the TRUSTED_PROXY alias', () => {
    process.env.TRUSTED_PROXY = 'true';
    const d = resolveClientIpDetailed(req({ 'x-forwarded-for': '203.0.113.7' }));
    expect(d).toMatchObject({ ip: '203.0.113.7', rule: 'xff-legacy', hops: 1 });
  });

  test('rule=none with no trust configured (hops=0, ip null, chain still surfaced)', () => {
    const d = resolveClientIpDetailed(req({ 'x-forwarded-for': '203.0.113.7' }));
    expect(d).toEqual({ ip: null, rule: 'none', hops: 0, chain: ['203.0.113.7'] });
  });
});
