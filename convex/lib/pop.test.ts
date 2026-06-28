// @vitest-environment node
import { afterEach, describe, expect, test, vi } from 'vitest';
import { bytesToB64Url } from '../../src/shared/crypto/envelope';
import {
  buildPopMessage,
  digestB64Url,
  POP_NONCE_HEADER,
  POP_SIG_HEADER,
  POP_TS_HEADER,
  POP_VERSION,
  POP_VERSION_HEADER,
  POP_WINDOW_MS,
  signP1363,
} from '../../src/shared/crypto/pop';
import { allowedPopHosts, evaluatePop, extractPopFields, type PopFields } from './pop';

/** Produce a session keypair + a valid signed request the way the client does. */
async function signedRequest(opts: {
  method: string;
  path: string;
  query?: string;
  host?: string;
  respEph?: string;
  version?: string;
  wireBody: string;
  ts: number;
  nonceByte?: number;
}) {
  const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const popPublicKey = bytesToB64Url(
    new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)),
  );
  const nonceB64 = bytesToB64Url(new Uint8Array(16).fill(opts.nonceByte ?? 1));
  const bodyHashB64 = await digestB64Url(new TextEncoder().encode(opts.wireBody));
  const msg = buildPopMessage({
    version: opts.version,
    method: opts.method,
    path: opts.path,
    query: opts.query,
    host: opts.host,
    respEph: opts.respEph,
    bodyHashB64,
    ts: opts.ts,
    nonceB64,
  });
  const sigB64 = bytesToB64Url(await signP1363(kp.privateKey, msg));
  const fields: PopFields = { sigB64, ts: opts.ts, nonceB64, version: opts.version ?? POP_VERSION };
  return { popPublicKey, fields };
}

describe('evaluatePop', () => {
  const now = 1_700_000_000_000;
  const base = { method: 'POST', path: '/api/v1/account/regenerate', wireBody: '{"a":1}', ts: now };

  test('a valid, fresh, correctly-signed request verifies and yields a nonceHash', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({ popPublicKey, ...base, fields, nowMs: now });
    expect(r.verdict).toBe('ok');
    expect(r.nonceHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test('a tampered wire body fails (bodyHash mismatch)', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({ popPublicKey, ...base, wireBody: '{"a":2}', fields, nowMs: now });
    expect(r.verdict).toBe('invalid');
  });

  test('a different path fails (canonical mismatch)', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({
      popPublicKey,
      ...base,
      path: '/api/v1/account/account-id/rotate',
      fields,
      nowMs: now,
    });
    expect(r.verdict).toBe('invalid');
  });

  test('a stale ts (older than the window) fails', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({
      popPublicKey,
      ...base,
      fields,
      nowMs: now + POP_WINDOW_MS + 5_000,
    });
    expect(r.verdict).toBe('invalid');
  });

  test('a far-future ts (ahead of the window) fails', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({
      popPublicKey,
      ...base,
      fields,
      nowMs: now - POP_WINDOW_MS - 5_000,
    });
    expect(r.verdict).toBe('invalid');
  });

  test('an unknown PoP version fails', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const r = await evaluatePop({
      popPublicKey,
      ...base,
      fields: { ...fields, version: 'v999' },
      nowMs: now,
    });
    expect(r.verdict).toBe('invalid');
  });

  test('a signature from a different key fails', async () => {
    const { fields } = await signedRequest(base);
    const stranger = await signedRequest(base);
    const r = await evaluatePop({
      popPublicKey: stranger.popPublicKey,
      ...base,
      fields,
      nowMs: now,
    });
    expect(r.verdict).toBe('invalid');
  });

  test('within-window clock skew (either direction) still verifies', async () => {
    const { popPublicKey, fields } = await signedRequest(base);
    const ahead = await evaluatePop({ popPublicKey, ...base, fields, nowMs: now - 30_000 });
    const behind = await evaluatePop({ popPublicKey, ...base, fields, nowMs: now + 30_000 });
    expect(ahead.verdict).toBe('ok');
    expect(behind.verdict).toBe('ok');
  });
});

describe('allowedPopHosts', () => {
  afterEach(() => vi.unstubAllEnvs());

  test('parses POP_EXPECTED_HOST (comma-separated, lowercased)', () => {
    vi.stubEnv('POP_EXPECTED_HOST', 'App.Freesocks.org, alt.example');
    expect(allowedPopHosts()).toEqual(['app.freesocks.org', 'alt.example']);
  });

  test('falls back to the host(s) of WEBAUTHN_ORIGIN', () => {
    vi.stubEnv('POP_EXPECTED_HOST', '');
    vi.stubEnv('WEBAUTHN_ORIGIN', 'https://app.freesocks.org,https://admin.freesocks.org:8443');
    expect(allowedPopHosts()).toEqual(['app.freesocks.org', 'admin.freesocks.org:8443']);
  });

  test('empty when neither is set (no lockout: host bound but not enforced)', () => {
    vi.stubEnv('POP_EXPECTED_HOST', '');
    vi.stubEnv('WEBAUTHN_ORIGIN', '');
    expect(allowedPopHosts()).toEqual([]);
  });
});

describe('evaluatePop v2 host + reveal-ephemeral binding', () => {
  const now = 1_700_000_000_000;
  const base = { method: 'GET', path: '/api/v1/account', wireBody: '', ts: now };

  test('host must match what was signed (cross-vhost replay fails)', async () => {
    const { popPublicKey, fields } = await signedRequest({ ...base, host: 'app.freesocks.org' });
    const ok = await evaluatePop({
      popPublicKey,
      ...base,
      host: 'app.freesocks.org',
      fields,
      nowMs: now,
    });
    const bad = await evaluatePop({
      popPublicKey,
      ...base,
      host: 'evil.example',
      fields,
      nowMs: now,
    });
    expect(ok.verdict).toBe('ok');
    expect(bad.verdict).toBe('invalid');
  });

  test('the reveal-leg ephemeral must match what was signed (active swap fails)', async () => {
    const { popPublicKey, fields } = await signedRequest({
      ...base,
      host: 'app.x',
      respEph: 'CLIENT_EPH',
    });
    const ok = await evaluatePop({
      popPublicKey,
      ...base,
      host: 'app.x',
      respEph: 'CLIENT_EPH',
      fields,
      nowMs: now,
    });
    const swapped = await evaluatePop({
      popPublicKey,
      ...base,
      host: 'app.x',
      respEph: 'ATTACKER_EPH',
      fields,
      nowMs: now,
    });
    expect(ok.verdict).toBe('ok');
    expect(swapped.verdict).toBe('invalid');
  });

  test('a v1 signature still verifies (back-compat during rollout)', async () => {
    const { popPublicKey, fields } = await signedRequest({ ...base, version: 'v1' });
    // host/respEph are ignored for v1 on both sides.
    const r = await evaluatePop({
      popPublicKey,
      ...base,
      host: 'whatever',
      respEph: 'whatever',
      fields,
      nowMs: now,
    });
    expect(r.verdict).toBe('ok');
  });
});

describe('extractPopFields', () => {
  function reqWith(headers: Record<string, string>): Request {
    return { headers: new Headers(headers) } as unknown as Request;
  }

  test('reads all four headers', () => {
    const f = extractPopFields(
      reqWith({
        [POP_SIG_HEADER]: 'sig',
        [POP_TS_HEADER]: '1700000000000',
        [POP_NONCE_HEADER]: 'nonce',
        [POP_VERSION_HEADER]: POP_VERSION,
      }),
    );
    expect(f).toEqual({
      sigB64: 'sig',
      ts: 1_700_000_000_000,
      nonceB64: 'nonce',
      version: POP_VERSION,
    });
  });

  test('returns null when a header is missing', () => {
    expect(extractPopFields(reqWith({ [POP_SIG_HEADER]: 'sig', [POP_TS_HEADER]: '1' }))).toBeNull();
  });

  test('returns null when ts is not a number', () => {
    expect(
      extractPopFields(
        reqWith({
          [POP_SIG_HEADER]: 'sig',
          [POP_TS_HEADER]: 'not-a-number',
          [POP_NONCE_HEADER]: 'nonce',
          [POP_VERSION_HEADER]: POP_VERSION,
        }),
      ),
    ).toBeNull();
  });
});
