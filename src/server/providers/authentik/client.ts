import { z } from 'zod';
import { UpstreamError } from '../../lib/errors';
import { base64UrlEncode, randomHex } from '../../lib/crypto';
import type { Logger } from '../../lib/logger';

export interface AuthentikConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string;
}

const TokenResponse = z.object({
  access_token: z.string(),
  id_token: z.string(),
  refresh_token: z.string().optional(),
  token_type: z.string(),
  expires_in: z.number().optional(),
  scope: z.string().optional(),
});
export type TokenResponse = z.infer<typeof TokenResponse>;

const UserInfoResponse = z.object({
  sub: z.string(),
  email: z.string().email().optional(),
  email_verified: z.boolean().optional(),
  name: z.string().optional(),
  preferred_username: z.string().optional(),
});
export type UserInfo = z.infer<typeof UserInfoResponse>;

interface AuthentikDiscoveryDoc {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  end_session_endpoint?: string;
}

export class AuthentikClient {
  private discovery?: AuthentikDiscoveryDoc;

  constructor(
    private readonly config: AuthentikConfig,
    private readonly logger: Logger,
    private readonly fetcher: typeof fetch = fetch,
  ) {}

  private async getDiscovery(): Promise<AuthentikDiscoveryDoc> {
    if (this.discovery) return this.discovery;
    const url = new URL('.well-known/openid-configuration', this.config.issuer).toString();
    const res = await this.fetcher(url);
    if (!res.ok) throw new UpstreamError('authentik', `Discovery failed: ${res.status}`);
    this.discovery = (await res.json()) as AuthentikDiscoveryDoc;
    return this.discovery;
  }

  async generatePkce(): Promise<{ verifier: string; challenge: string }> {
    const verifier = randomHex(48);
    const data = new TextEncoder().encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const challenge = base64UrlEncode(hash);
    return { verifier, challenge };
  }

  async buildAuthorizeUrl(opts: {
    state: string;
    codeChallenge: string;
    nonce: string;
  }): Promise<string> {
    const d = await this.getDiscovery();
    const url = new URL(d.authorization_endpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.config.clientId);
    url.searchParams.set('redirect_uri', this.config.redirectUri);
    url.searchParams.set('scope', this.config.scopes);
    url.searchParams.set('state', opts.state);
    url.searchParams.set('nonce', opts.nonce);
    url.searchParams.set('code_challenge', opts.codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    return url.toString();
  }

  async exchangeCode(code: string, codeVerifier: string): Promise<TokenResponse> {
    const d = await this.getDiscovery();
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code_verifier: codeVerifier,
    });
    const res = await this.fetcher(d.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      this.logger.warn('authentik_token_exchange_failed', {
        status: res.status,
        body: text.slice(0, 500),
      });
      throw new UpstreamError('authentik', `Token exchange failed: ${res.status}`);
    }
    return TokenResponse.parse(await res.json());
  }

  async getUserInfo(accessToken: string): Promise<UserInfo> {
    const d = await this.getDiscovery();
    const res = await this.fetcher(d.userinfo_endpoint, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) throw new UpstreamError('authentik', `userinfo failed: ${res.status}`);
    return UserInfoResponse.parse(await res.json());
  }
}
