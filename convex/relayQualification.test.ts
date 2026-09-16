import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { qualificationUsername } from './relayQualification';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  const { id: relayId } = await t.mutation(internal.relays.upsertBySlug, {
    slug: 'node-one',
    backendServerSlug: 'panel-a',
    nodeHostname: 'node-one',
    originAddress: '203.0.113.10',
  });
  return { t, relayId };
}

afterEach(() => vi.unstubAllEnvs());

describe('relay qualification credential', () => {
  test('username is slug-derived, bounded and tagged', () => {
    const u = qualificationUsername('Node.One/Very-Long-Relay-Slug-Name', 'abcd1234');
    expect(u.startsWith('fcp-qualify-node-one-very-long-r')).toBe(true);
    expect(u.endsWith('-abcd1234')).toBe(true);
    expect(u).toMatch(/^[a-z0-9-]+$/);
  });

  test('mint stores only the protocol uuid + panel user id; revoke clears and deactivates', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    const r = await t.action(internal.relayQualification.mint, { relayId });
    expect(r).toEqual({ ok: true });
    const row = await t.run((ctx) => ctx.db.get(relayId));
    expect(row?.qualificationUserId).toMatch(/^[0-9a-f-]{36}$/);
    expect(row?.qualificationBackendUserId).toMatch(/^mock-/);
    const admin = await t.query(internal.relays.get, { id: relayId });
    expect(admin?.qualificationUserId).toBeDefined();
    // Re-minting replaces the credential (the previous account is removed).
    const before = row?.qualificationUserId;
    await t.action(internal.relayQualification.mint, { relayId });
    const row2 = await t.run((ctx) => ctx.db.get(relayId));
    expect(row2?.qualificationUserId).not.toBe(before);
    await t.action(internal.relayQualification.revoke, { relayId });
    const row3 = await t.run((ctx) => ctx.db.get(relayId));
    expect(row3?.qualificationUserId).toBeUndefined();
    expect(row3?.qualificationBackendUserId).toBeUndefined();
    // Audit rows carry booleans only, never the credential.
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .collect()
        .then((rows) => rows.filter((a) => a.action === 'relay.qualification_credential')),
    );
    expect(audits.length).toBe(3);
    for (const a of audits) {
      const blob = JSON.stringify(a.payload);
      expect(blob).not.toContain(before ?? 'never');
      expect(blob).not.toContain('mock-');
    }
  });

  test('a backend that mints no protocol credential keeps no account and reports a code', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    const cryptoSpy = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => '' as never);
    try {
      const r = await t.action(internal.relayQualification.mint, { relayId });
      expect(r).toEqual({ ok: false, code: 'qualification_credential_unsupported' });
      const row = await t.run((ctx) => ctx.db.get(relayId));
      expect(row?.qualificationUserId).toBeUndefined();
    } finally {
      cryptoSpy.mockRestore();
    }
  });
});
