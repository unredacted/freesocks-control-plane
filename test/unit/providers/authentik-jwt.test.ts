import { describe, expect, it, beforeAll, afterEach, vi } from 'vitest';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { AuthentikJwtVerifier } from '../../../src/server/providers/authentik/jwt';
import { UnauthenticatedError } from '../../../src/server/lib/errors';
import { Logger } from '../../../src/server/lib/logger';

const ISSUER = 'https://auth.example.com/application/o/freesocks/';
const AUDIENCE = 'freesocks-client-id';
const KID = 'test-key-1';
const JWKS_URI = 'https://auth.example.com/jwks';

let keyPair: Awaited<ReturnType<typeof generateKeyPair>>;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
  keyPair = await generateKeyPair('RS256');
  const jwk = await exportJWK(keyPair.publicKey);
  publicJwk = { ...jwk, kid: KID, alg: 'RS256', use: 'sig' };
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Stub global fetch so jose resolves discovery + JWKS to our test key. */
function stubIdpReachable() {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('.well-known/openid-configuration')) {
        return Promise.resolve(
          new Response(JSON.stringify({ jwks_uri: JWKS_URI }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      }
      if (url.startsWith(JWKS_URI)) {
        return Promise.resolve(
          new Response(JSON.stringify({ keys: [publicJwk] }), {
            status: 200,
            headers: { 'content-type': 'application/json' },
          }),
        );
      }
      return Promise.resolve(new Response('not found', { status: 404 }));
    }),
  );
}

async function signToken(opts: {
  iss?: string;
  aud?: string;
  sub?: string | null;
  exp?: string | number;
  email?: string;
  name?: string;
}): Promise<string> {
  let builder = new SignJWT({
    ...(opts.email ? { email: opts.email } : {}),
    ...(opts.name ? { name: opts.name } : {}),
  })
    .setProtectedHeader({ alg: 'RS256', kid: KID })
    .setIssuedAt()
    .setIssuer(opts.iss ?? ISSUER)
    .setAudience(opts.aud ?? AUDIENCE)
    .setExpirationTime(opts.exp ?? '2h');
  if (opts.sub !== null) builder = builder.setSubject(opts.sub ?? 'user-123');
  return builder.sign(keyPair.privateKey);
}

function makeVerifier() {
  return new AuthentikJwtVerifier({
    issuer: ISSUER,
    audience: AUDIENCE,
    logger: new Logger('error'),
  });
}

describe('AuthentikJwtVerifier', () => {
  it('throws at construction if audience is empty (defensive against misconfig)', () => {
    expect(
      () => new AuthentikJwtVerifier({ issuer: ISSUER, audience: '', logger: new Logger('error') }),
    ).toThrow(/audience is required/i);
    expect(
      () => new AuthentikJwtVerifier({ issuer: ISSUER, audience: [], logger: new Logger('error') }),
    ).toThrow(/audience is required/i);
  });

  it('verifies a well-formed token and extracts sub/email/name', async () => {
    stubIdpReachable();
    const token = await signToken({ sub: 'user-abc', email: 'a@example.com', name: 'Alice' });
    const result = await makeVerifier().verify(token);
    expect(result.sub).toBe('user-abc');
    expect(result.email).toBe('a@example.com');
    expect(result.name).toBe('Alice');
  });

  it('rejects a token with the wrong audience', async () => {
    stubIdpReachable();
    const token = await signToken({ aud: 'some-other-app' });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(UnauthenticatedError);
  });

  it('rejects a token with the wrong issuer', async () => {
    stubIdpReachable();
    const token = await signToken({ iss: 'https://evil.example.com/' });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(UnauthenticatedError);
  });

  it('rejects an expired token', async () => {
    stubIdpReachable();
    const token = await signToken({ exp: Math.floor(Date.now() / 1000) - 3600 });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(UnauthenticatedError);
  });

  it('rejects a token missing the sub claim', async () => {
    stubIdpReachable();
    const token = await signToken({ sub: null });
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(UnauthenticatedError);
  });

  it('maps an unreachable IdP to UnauthenticatedError (not a 500)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('down', { status: 503 }))),
    );
    const token = await signToken({});
    await expect(makeVerifier().verify(token)).rejects.toBeInstanceOf(UnauthenticatedError);
  });
});
