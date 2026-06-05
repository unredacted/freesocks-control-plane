import { SELF, env } from 'cloudflare:test';
import { describe, expect, it, beforeEach } from 'vitest';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import * as schema from '../../src/server/db/schema';
import { sha256Hex, base64UrlEncode } from '../../src/server/lib/crypto';

const TOKEN_PREFIX = 'fsv1_';
const SUB_URL = 'https://example.com/api/v1/subscription';

async function freeTierId(): Promise<number> {
  const db = drizzle(env.DB, { schema });
  const rows = await db
    .select()
    .from(schema.tiers)
    .where(eq(schema.tiers.slug, 'free'))
    .limit(1)
    .all();
  const t = rows[0];
  if (!t) throw new Error('free tier not seeded — check 0001_seed_tiers migration');
  return t.id;
}

/**
 * Insert a member user with a unique authentik_subject. The subject is REQUIRED:
 * bearer-auth.ts only populates c.var.member for a user-subject token when the
 * user row has a non-null authentikSubject. Mirrors the auto-provision insert
 * shape (so createdAt/updatedAt defaults apply). Returns the new user id.
 */
async function seedUser(): Promise<number> {
  const db = drizzle(env.DB, { schema });
  const tierId = await freeTierId();
  const inserted = await db
    .insert(schema.users)
    .values({
      authentikSubject: `test-${crypto.randomUUID()}`,
      email: 'member@example.com',
      tierId,
      status: 'active',
    })
    .returning();
  return inserted[0]!.id;
}

async function seedToken(opts: {
  scopes: string[];
  subjectType?: 'service' | 'user';
  subjectUserId?: number | null;
}): Promise<string> {
  const db = drizzle(env.DB, { schema });
  const existingAdmins = await db.select().from(schema.adminUsers).limit(1).all();
  let adminId: number;
  if (existingAdmins.length === 0) {
    const inserted = await db
      .insert(schema.adminUsers)
      .values({ username: `it-${crypto.randomUUID()}`, displayName: 'Integration Tester' })
      .returning();
    adminId = inserted[0]!.id;
  } else {
    adminId = existingAdmins[0]!.id;
  }
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const plaintext = `${TOKEN_PREFIX}${base64UrlEncode(random)}`;
  await db
    .insert(schema.apiTokens)
    .values({
      name: 'sub-scope-test',
      tokenHash: await sha256Hex(plaintext),
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: adminId,
      scopes: JSON.stringify(opts.scopes),
      subjectType: opts.subjectType ?? 'service',
      subjectUserId: opts.subjectUserId ?? null,
    })
    .run();
  return plaintext;
}

describe('Subscription scope enforcement (requireScopeIfToken)', () => {
  beforeEach(async () => {
    const db = drizzle(env.DB, { schema });
    await db.delete(schema.apiTokens).run();
  });

  it('user-subject token WITHOUT subscription:read → GET 403 (closes the privilege gap)', async () => {
    const userId = await seedUser();
    const token = await seedToken({
      scopes: ['account:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });
    const res = await SELF.fetch(SUB_URL, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(403);
  });

  it('user-subject token WITH subscription:read → GET 200, {subscription:null} when no active sub', async () => {
    const userId = await seedUser();
    const token = await seedToken({
      scopes: ['subscription:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });
    const res = await SELF.fetch(SUB_URL, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { subscription: unknown };
    expect(body.subscription).toBeNull();
  });

  it('anonymous (no auth) → GET 200, {subscription:null} (Turnstile path untouched)', async () => {
    const res = await SELF.fetch(SUB_URL);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { subscription: unknown };
    expect(body.subscription).toBeNull();
  });

  it('user-subject token WITHOUT subscription:write → POST 403 (in middleware, before Turnstile)', async () => {
    const userId = await seedUser();
    const token = await seedToken({
      scopes: ['subscription:read'],
      subjectType: 'user',
      subjectUserId: userId,
    });
    const res = await SELF.fetch(SUB_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ turnstileToken: 'x' }),
    });
    expect(res.status).toBe(403);
  });

  it('service token WITHOUT subscription:read → GET 403', async () => {
    const token = await seedToken({ scopes: ['admin:audit:read'], subjectType: 'service' });
    const res = await SELF.fetch(SUB_URL, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(403);
  });

  it('service token WITH subscription:read → GET 200, {subscription:null} (token is not a member)', async () => {
    const token = await seedToken({ scopes: ['subscription:read'], subjectType: 'service' });
    const res = await SELF.fetch(SUB_URL, { headers: { Authorization: `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { subscription: unknown };
    expect(body.subscription).toBeNull();
  });
});
