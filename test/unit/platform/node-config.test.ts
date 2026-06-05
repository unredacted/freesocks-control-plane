import { describe, expect, it } from 'vitest';
import { buildNodeConfig } from '../../../src/server/platform/node';

// Minimal set of required env vars so buildNodeConfig's must() checks pass.
const baseEnv: NodeJS.ProcessEnv = {
  REMNAWAVE_BASE_URL: 'https://rw.example',
  REMNAWAVE_API_TOKEN: 'tok',
  AUTHENTIK_ISSUER: 'https://auth.example/application/o/x/',
  AUTHENTIK_CLIENT_ID: 'cid',
  AUTHENTIK_CLIENT_SECRET: 'sec',
  AUTHENTIK_REDIRECT_URI: 'https://app.example/api/auth/callback',
  SESSION_SIGNING_KEY: 'a'.repeat(32),
  ADMIN_SESSION_SIGNING_KEY: 'b'.repeat(32),
  IP_HASH_SALT: 'salt',
  TURNSTILE_SECRET_KEY: 'ts-secret',
  FREE_TIER_TURNSTILE_SITE_KEY: 'ts-site',
  WEBAUTHN_RP_ID: 'example.com',
  WEBAUTHN_RP_NAME: 'Example',
  WEBAUTHN_ORIGIN: 'https://app.example',
};

const JOIN_DEFAULT = 'https://members.unredacted.org/join';
const ACCOUNT_DEFAULT = 'https://members.unredacted.org/account';

describe('buildNodeConfig MEMBERS_*_URL fallback', () => {
  it('falls back to defaults when unset', () => {
    const cfg = buildNodeConfig({ ...baseEnv });
    expect(cfg.MEMBERS_JOIN_URL).toBe(JOIN_DEFAULT);
    expect(cfg.MEMBERS_ACCOUNT_URL).toBe(ACCOUNT_DEFAULT);
  });

  it('falls back to defaults when set to an empty string (the 500 footgun)', () => {
    const cfg = buildNodeConfig({ ...baseEnv, MEMBERS_JOIN_URL: '', MEMBERS_ACCOUNT_URL: '' });
    expect(cfg.MEMBERS_JOIN_URL).toBe(JOIN_DEFAULT);
    expect(cfg.MEMBERS_ACCOUNT_URL).toBe(ACCOUNT_DEFAULT);
  });

  it('preserves a valid override', () => {
    const cfg = buildNodeConfig({ ...baseEnv, MEMBERS_JOIN_URL: 'https://join.example' });
    expect(cfg.MEMBERS_JOIN_URL).toBe('https://join.example');
  });
});
