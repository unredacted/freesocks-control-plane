import { describe, expect, it } from 'vitest';
import { PublicConfig } from '../../../src/shared/contracts/auth';

const base = {
  freeTierTurnstileSiteKey: 'site-key',
  environment: 'production' as const,
  tiers: [{ slug: 'free', name: 'Free', monthlyTrafficGb: 50, deviceLimit: 1 }],
  backends: {
    remnawaveEnabled: true,
    outlineEnabled: false,
    defaultBackend: 'remnawave' as const,
    userChoiceEnabled: false,
    labels: { remnawave: 'Xray', outline: 'Outline' },
  },
};

describe('PublicConfig member URLs', () => {
  it('parses with valid member URLs present', () => {
    const r = PublicConfig.safeParse({
      ...base,
      membersJoinUrl: 'https://members.example/join',
      membersAccountUrl: 'https://members.example/account',
    });
    expect(r.success).toBe(true);
  });

  it('parses when member URLs are omitted (server dropped an invalid override)', () => {
    // This is the load-bearing case: the server now emits `undefined` for a
    // blank/invalid MEMBERS_*_URL, and the client re-validates this SAME schema.
    // It must accept the omission, or the SPA would throw client.parse_error.
    const r = PublicConfig.safeParse(base);
    expect(r.success).toBe(true);
  });

  it('still rejects a present-but-invalid member URL', () => {
    const r = PublicConfig.safeParse({ ...base, membersJoinUrl: 'not-a-url' });
    expect(r.success).toBe(false);
  });
});
