import { SELF, env } from 'cloudflare:test';
import { describe, expect, it, beforeEach } from 'vitest';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import * as schema from '../../src/server/db/schema';
import { sha256Hex, base64UrlEncode } from '../../src/server/lib/crypto';

const TOKEN_PREFIX = 'fsv1_';

/**
 * Mints a token directly in D1 (bypassing the admin-cookie-session-gated mint
 * endpoint). This simulates an admin minting a token via the CMS, then a
 * machine using that token to call protected endpoints.
 */
async function seedToken(opts: {
  scopes: string[];
  subjectType?: 'service' | 'user';
  subjectUserId?: number | null;
  expiresAt?: number | null;
  revokedAt?: number | null;
  name?: string;
}): Promise<{ plaintext: string; id: number; prefix: string }> {
  const db = drizzle(env.DB, { schema });
  // Ensure an admin user exists to satisfy the FK on api_tokens.created_by_admin_id.
  const existingAdmins = await db.select().from(schema.adminUsers).limit(1).all();
  let adminId: number;
  if (existingAdmins.length === 0) {
    const inserted = await db
      .insert(schema.adminUsers)
      .values({ username: 'integration-tester', displayName: 'Integration Tester' })
      .returning();
    adminId = inserted[0]!.id;
  } else {
    adminId = existingAdmins[0]!.id;
  }

  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const plaintext = `${TOKEN_PREFIX}${base64UrlEncode(random)}`;
  const tokenHash = await sha256Hex(plaintext);
  const tokenPrefix = plaintext.slice(0, 12);

  const inserted = await db
    .insert(schema.apiTokens)
    .values({
      name: opts.name ?? 'integration-test',
      tokenHash,
      tokenPrefix,
      createdByAdminId: adminId,
      scopes: JSON.stringify(opts.scopes),
      subjectType: opts.subjectType ?? 'service',
      subjectUserId: opts.subjectUserId ?? null,
      expiresAt: opts.expiresAt ?? null,
      revokedAt: opts.revokedAt ?? null,
    })
    .returning();
  return { plaintext, id: inserted[0]!.id, prefix: tokenPrefix };
}

async function clearTokens(): Promise<void> {
  const db = drizzle(env.DB, { schema });
  await db.delete(schema.apiTokens).run();
}

describe('Bearer token authentication', () => {
  beforeEach(async () => {
    await clearTokens();
  });

  it('mint → call → revoke → 401: full lifecycle on /api/v1/admin/audit', async () => {
    // 1. Seed a token with admin:audit:read scope (simulates an admin minting it).
    const { plaintext, id } = await seedToken({ scopes: ['admin:audit:read'] });
    expect(plaintext).toMatch(/^fsv1_/);

    // 2. Call a scope-gated endpoint with the token — expect 200.
    const callRes = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(callRes.status).toBe(200);
    const body = (await callRes.json()) as { entries: unknown[] };
    expect(Array.isArray(body.entries)).toBe(true);

    // 3. Revoke the token in the DB (simulates admin clicking revoke).
    const db = drizzle(env.DB, { schema });
    await db
      .update(schema.apiTokens)
      .set({ revokedAt: Date.now() })
      .where(eq(schema.apiTokens.id, id))
      .run();

    // 4. Re-call with the (now-revoked) token — expect 401.
    const afterRevokeRes = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(afterRevokeRes.status).toBe(401);
  });

  it('rejects tokens with insufficient scope (403)', async () => {
    // Token that is valid but lacks the right scope.
    const { plaintext } = await seedToken({ scopes: ['subscription:read'] });
    const res = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(res.status).toBe(403);
  });

  it('rejects expired tokens (401)', async () => {
    const { plaintext } = await seedToken({
      scopes: ['admin:audit:read'],
      expiresAt: Date.now() - 1000,
    });
    const res = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(res.status).toBe(401);
  });

  it('rejects revoked tokens (401)', async () => {
    const { plaintext } = await seedToken({
      scopes: ['admin:audit:read'],
      revokedAt: Date.now(),
    });
    const res = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${plaintext}` },
    });
    expect(res.status).toBe(401);
  });

  it('rejects tokens with bad fsv1_ prefix but otherwise random bytes', async () => {
    // A real-looking but never-issued token must not authenticate.
    const fake = 'fsv1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const res = await SELF.fetch('https://example.com/api/v1/admin/audit', {
      headers: { Authorization: `Bearer ${fake}` },
    });
    expect(res.status).toBe(401);
  });

  it('admin:tokens:write token can mint another token via /api/v1/admin/tokens', async () => {
    const { plaintext } = await seedToken({ scopes: ['admin:tokens:write', 'admin:tokens:read'] });
    const res = await SELF.fetch('https://example.com/api/v1/admin/tokens', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${plaintext}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        name: 'minted-by-service-token',
        scopes: ['subscription:read'],
        subjectType: 'service',
      }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { plaintext: string; token: { name: string } };
    expect(body.plaintext).toMatch(/^fsv1_/);
    expect(body.token.name).toBe('minted-by-service-token');
  });
});
