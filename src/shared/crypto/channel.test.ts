// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { isSealedWire, kidFromPublicKey, RESP_EPH_FIELD, type SealedWire } from './envelope';
import { deserializePublicKey, serializePublicKey, serverKeyPairFromSeed } from './hpke';
import {
  clientOpenResponse,
  clientPrepareRequest,
  serverOpenRequest,
  serverSealResponse,
} from './channel';

// A stable "server identity" for the tests: a seed -> X-Wing keypair -> kid,
// with the public key round-tripped through serialize/deserialize the way the
// client receives it (baked bytes).
async function serverIdentity(seedByte = 5) {
  const seed = new Uint8Array(32).fill(seedByte);
  const kp = await serverKeyPairFromSeed(seed);
  const pkBytes = await serializePublicKey(kp.publicKey);
  return {
    priv: kp.privateKey,
    pubForClient: await deserializePublicKey(pkBytes),
    kid: await kidFromPublicKey(pkBytes),
  };
}

describe('channel: request seal (login construction)', () => {
  const method = 'POST';
  const path = '/api/v1/auth/account-login';
  const policy = { request: 'seal', response: 'plain' } as const;

  test('account number is sealed on the wire and the server recovers it', async () => {
    const srv = await serverIdentity();
    const accountId = '12345678901234567890123456789012';
    const prepared = await clientPrepareRequest({
      serverPub: srv.pubForClient,
      serverKid: srv.kid,
      method,
      path,
      policy,
      bodyObj: { accountId, turnstileToken: 'tok' },
    });
    expect(isSealedWire(prepared.body)).toBe(true);
    expect(JSON.stringify(prepared.body)).not.toContain(accountId);
    expect(prepared.respEphPriv).toBeUndefined();

    const opened = (await serverOpenRequest({
      serverPriv: srv.priv,
      serverKid: srv.kid,
      method,
      path,
      wireBody: prepared.body as SealedWire,
    })) as { accountId: string; turnstileToken: string };
    expect(opened.accountId).toBe(accountId);
    expect(opened.turnstileToken).toBe('tok');
  });

  test('a different server key cannot open the request', async () => {
    const srv = await serverIdentity(5);
    const other = await serverIdentity(9);
    const prepared = await clientPrepareRequest({
      serverPub: srv.pubForClient,
      serverKid: srv.kid,
      method,
      path,
      policy,
      bodyObj: { accountId: '1', turnstileToken: 't' },
    });
    await expect(
      serverOpenRequest({
        serverPriv: other.priv,
        serverKid: srv.kid,
        method,
        path,
        wireBody: prepared.body as SealedWire,
      }),
    ).rejects.toThrow();
  });
});

describe('channel: response reveal (issuance construction)', () => {
  const method = 'POST';
  const path = '/api/v1/subscription';
  const policy = { request: 'plain', response: 'reveal' } as const;

  async function fullRoundTrip(seed = 5) {
    const srv = await serverIdentity(seed);
    const prepared = await clientPrepareRequest({
      serverPub: srv.pubForClient,
      serverKid: srv.kid,
      method,
      path,
      policy,
      bodyObj: { turnstileToken: 'tok' },
    });
    const reqBody = prepared.body as Record<string, string>;
    const responseObj = {
      accountId: '99998888777766665555444433332222',
      subscriptionUrl: 'ss://deadbeef@example:443',
    };
    const sealed = await serverSealResponse({
      serverKid: srv.kid,
      method,
      path,
      respEphPubB64: reqBody[RESP_EPH_FIELD]!,
      responseObj,
    });
    return { srv, prepared, reqBody, responseObj, sealed };
  }

  test('request is plaintext with an ephemeral; response is sealed and recovered', async () => {
    const { prepared, reqBody, responseObj, sealed, srv } = await fullRoundTrip();
    // request carries a plaintext ephemeral, not a sealed envelope
    expect(isSealedWire(prepared.body)).toBe(false);
    expect(typeof reqBody[RESP_EPH_FIELD]).toBe('string');
    expect(prepared.respEphPriv).toBeDefined();
    // response hides the secrets
    expect(isSealedWire(sealed)).toBe(true);
    expect(JSON.stringify(sealed)).not.toContain(responseObj.accountId);
    expect(JSON.stringify(sealed)).not.toContain('ss://');
    // client opens it
    const opened = (await clientOpenResponse({
      serverKid: srv.kid,
      method,
      path,
      respEphPriv: prepared.respEphPriv!,
      wire: sealed,
    })) as typeof responseObj;
    expect(opened).toEqual(responseObj);
  });

  test('tampered response ct fails to open', async () => {
    const { prepared, sealed, srv } = await fullRoundTrip();
    const bad: SealedWire = { fsSealed: { ...sealed.fsSealed } };
    const ctChars = bad.fsSealed.ct.split('');
    ctChars[0] = ctChars[0] === 'A' ? 'B' : 'A';
    bad.fsSealed.ct = ctChars.join('');
    await expect(
      clientOpenResponse({
        serverKid: srv.kid,
        method,
        path,
        respEphPriv: prepared.respEphPriv!,
        wire: bad,
      }),
    ).rejects.toThrow();
  });

  test('opening the response under a different path fails (info binding)', async () => {
    const { prepared, sealed, srv } = await fullRoundTrip();
    await expect(
      clientOpenResponse({
        serverKid: srv.kid,
        method,
        path: '/api/v1/account', // wrong route
        respEphPriv: prepared.respEphPriv!,
        wire: sealed,
      }),
    ).rejects.toThrow();
  });

  test('a different ephemeral private key cannot open the response', async () => {
    const { sealed, srv } = await fullRoundTrip();
    // a fresh client ephemeral that was not the one bound into the response
    const stranger = await clientPrepareRequest({
      serverPub: srv.pubForClient,
      serverKid: srv.kid,
      method,
      path,
      policy,
      bodyObj: {},
    });
    await expect(
      clientOpenResponse({
        serverKid: srv.kid,
        method,
        path,
        respEphPriv: stranger.respEphPriv!,
        wire: sealed,
      }),
    ).rejects.toThrow();
  });
});
