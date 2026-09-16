// @vitest-environment node
/**
 * The SPA seam for the member routes added to the sealing table in 2026-09:
 * `prepareOutbound` must put the reveal ephemeral in the `x-fs-resp-eph` header
 * for a GET reveal route (the server reads that header, and PoP v2 binds it),
 * seal the whole request body for a SEAL_REQ POST (the membership code), and
 * fold `fsRespEph` into the plain body for a POST reveal route. Routes without a
 * policy entry must stay untouched (plaintext, dual-mode).
 */
import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';
import {
  bytesToB64Url,
  isSealedWire,
  kidFromPublicKey,
  RESP_EPH_FIELD,
} from '../../shared/crypto/envelope';
import { serverOpenRequest, serverSealResponse } from '../../shared/crypto/channel';
import { serializePublicKey, serverKeyPairFromSeed } from '../../shared/crypto/hpke';

// The status store is a Svelte-runes module; the seam only pokes it after opening
// a sealed response, so a stub is all this test needs.
vi.mock('./hpke-status.svelte', () => ({ markSealedResponse: () => {} }));

const SEED = new Uint8Array(32).fill(9);
let kp: CryptoKeyPair;
let kid: string;
let hpke: typeof import('./hpke');

beforeAll(async () => {
  kp = await serverKeyPairFromSeed(SEED);
  const pkBytes = await serializePublicKey(kp.publicKey);
  kid = await kidFromPublicKey(pkBytes);
  // The pins are read at module load, so bake them before the first import.
  vi.stubEnv('VITE_FS_SERVER_HPKE_PK', bytesToB64Url(pkBytes));
  vi.stubEnv('VITE_FS_SERVER_HPKE_KID', kid);
  hpke = await import('./hpke');
  expect(hpke.sealingEnabled()).toBe(true);
});
afterAll(() => {
  vi.unstubAllEnvs();
});

describe('prepareOutbound on the member routes sealed in 2026-09', () => {
  test('GET /api/v1/subscription/content: reveal ephemeral rides the x-fs-resp-eph header, and the sealed response opens', async () => {
    const path = '/api/v1/subscription/content';
    const out = await hpke.prepareOutbound(path, 'GET', undefined);
    expect(out).toBeDefined();
    expect(out!.policy).toEqual({ request: 'plain', response: 'reveal' });
    expect(out!.body).toBeUndefined();
    expect(out!.header?.name).toBe('x-fs-resp-eph');
    expect(out!.header?.value).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(out!.respEphPriv).toBeDefined();
    // Server side: seal the config to that ephemeral; the client opens it.
    const wire = await serverSealResponse({
      serverKid: kid,
      method: 'GET',
      path,
      respEphPubB64: out!.header!.value,
      responseObj: { content: 'vless://uuid@1.2.3.4:443', contentType: 'text/plain' },
    });
    expect(isSealedWire(wire)).toBe(true);
    const opened = await hpke.openInbound(out!, path, 'GET', wire);
    expect(opened).toEqual({ content: 'vless://uuid@1.2.3.4:443', contentType: 'text/plain' });
  });

  test('POST /api/v1/account/redeem-code: the request body is a sealed envelope the server opens to the code', async () => {
    const path = '/api/v1/account/redeem-code';
    const out = await hpke.prepareOutbound(path, 'POST', JSON.stringify({ code: 'ABCD-EFGH' }));
    expect(out).toBeDefined();
    expect(out!.policy).toEqual({ request: 'seal', response: 'plain' });
    expect(out!.header).toBeUndefined();
    expect(out!.body).toBeDefined();
    expect(out!.body).not.toContain('ABCD-EFGH');
    const wire = JSON.parse(out!.body!);
    expect(isSealedWire(wire)).toBe(true);
    expect(wire.fsSealed.kid).toBe(kid); // no manifest key baked -> sealed to the static pin
    const plaintext = await serverOpenRequest({
      serverPriv: kp.privateKey,
      serverKid: kid,
      method: 'POST',
      path,
      wireBody: wire,
    });
    // Response leg is plain, so no ephemeral is folded in.
    expect(plaintext).toEqual({ code: 'ABCD-EFGH' });
  });

  test('POST /api/v1/mirror/request: plain body carrying fsRespEph, response sealed to it', async () => {
    const path = '/api/v1/mirror/request';
    const out = await hpke.prepareOutbound(path, 'POST', JSON.stringify({ countryCode: null }));
    expect(out).toBeDefined();
    expect(out!.policy).toEqual({ request: 'plain', response: 'reveal' });
    expect(out!.header).toBeUndefined();
    const body = JSON.parse(out!.body!) as Record<string, unknown>;
    expect(isSealedWire(body)).toBe(false);
    expect(body.countryCode).toBeNull();
    expect(typeof body[RESP_EPH_FIELD]).toBe('string');
    const wire = await serverSealResponse({
      serverKid: kid,
      method: 'POST',
      path,
      respEphPubB64: body[RESP_EPH_FIELD] as string,
      responseObj: { status: 'ok', publicUrl: 'https://bucket.example/abc', remaining: 0 },
    });
    const opened = (await hpke.openInbound(out!, path, 'POST', wire)) as { publicUrl: string };
    expect(opened.publicUrl).toBe('https://bucket.example/abc');
  });

  test('routes without a policy entry are left plaintext (intentionally unsealed)', async () => {
    expect(
      await hpke.prepareOutbound('/api/v1/account/devices/revoke', 'POST', '{"hwid":"x"}'),
    ).toBeUndefined();
    expect(
      await hpke.prepareOutbound('/api/v1/account/passkeys', 'GET', undefined),
    ).toBeUndefined();
    expect(
      await hpke.prepareOutbound('/api/v1/account/passkey/revoke', 'POST', '{"id":"x"}'),
    ).toBeUndefined();
  });
});
