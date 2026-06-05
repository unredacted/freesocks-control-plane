import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import type { Logger } from '../../lib/logger';
import { UnauthenticatedError } from '../../lib/errors';

export interface AuthentikJwtVerifierOptions {
  issuer: string;
  /**
   * REQUIRED. The expected `aud` claim — typically the FreeSocks Authentik
   * client id. Authentik may issue tokens with the same issuer for other
   * applications registered on the same instance; without this check those
   * tokens would authenticate against our API. Pass the same value used
   * for `AUTHENTIK_CLIENT_ID`.
   */
  audience: string | string[];
  logger: Logger;
}

export interface VerifiedAuthentikToken {
  sub: string;
  email?: string;
  name?: string;
  payload: JWTPayload;
}

/**
 * Verifies bearer JWTs issued by Authentik against its JWKS.
 * JWKS is fetched via `jose`'s built-in caching (60s by default; we extend to 1h).
 */
export class AuthentikJwtVerifier {
  private jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

  constructor(private readonly opts: AuthentikJwtVerifierOptions) {
    // Fail loud if a caller didn't set the audience. Defensive against an
    // operator who copied an old config that omitted it.
    const aud = opts.audience;
    if (
      (Array.isArray(aud) && aud.length === 0) ||
      (typeof aud === 'string' && aud.length === 0) ||
      aud === undefined ||
      aud === null
    ) {
      throw new Error(
        'AuthentikJwtVerifier: audience is required. Pass the FreeSocks ' +
          'Authentik client id (same as AUTHENTIK_CLIENT_ID).',
      );
    }
  }

  private async getJwks(): Promise<ReturnType<typeof createRemoteJWKSet>> {
    if (this.jwks) return this.jwks;
    const discoveryUrl = new URL('.well-known/openid-configuration', this.opts.issuer).toString();
    const res = await fetch(discoveryUrl);
    if (!res.ok) {
      throw new Error(`Authentik discovery failed: ${res.status}`);
    }
    const doc = (await res.json()) as { jwks_uri?: string };
    if (!doc.jwks_uri) throw new Error('Authentik discovery doc has no jwks_uri');
    this.jwks = createRemoteJWKSet(new URL(doc.jwks_uri), {
      cacheMaxAge: 60 * 60 * 1000, // 1h
      cooldownDuration: 30 * 1000,
    });
    return this.jwks;
  }

  async verify(token: string): Promise<VerifiedAuthentikToken> {
    let jwks: ReturnType<typeof createRemoteJWKSet>;
    try {
      jwks = await this.getJwks();
    } catch (err) {
      this.opts.logger.warn('authentik_jwks_unavailable', { error: String(err) });
      throw new UnauthenticatedError('Identity provider unreachable');
    }
    try {
      const { payload } = await jwtVerify(token, jwks, {
        issuer: this.opts.issuer,
        audience: this.opts.audience,
      });
      const sub = payload.sub;
      if (!sub) throw new UnauthenticatedError('Token missing sub claim');
      return {
        sub,
        email: typeof payload.email === 'string' ? payload.email : undefined,
        name: typeof payload.name === 'string' ? payload.name : undefined,
        payload,
      };
    } catch (err) {
      this.opts.logger.debug('authentik_jwt_verify_failed', { error: String(err) });
      throw new UnauthenticatedError('Invalid bearer token');
    }
  }
}
