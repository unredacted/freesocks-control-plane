/// <reference types="vite/client" />
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { sha256Hex } from './lib/crypto';
import { MAX_SITE_IMAGE_BYTES } from './lib/siteImage';

const modules = import.meta.glob('./**/*.*s');

const poster = readFileSync(resolve(__dirname, '../src/client/assets/home-poster.png'));

async function settingsToken(t: ReturnType<typeof convexTest>, scopes: string[]) {
  const plaintext = `fsv1_site-${Math.random().toString(36).slice(2)}`;
  const tokenHash = await sha256Hex(plaintext);
  await t.run(async (ctx) => {
    const admin = await ctx.db.insert('adminUsers', {
      username: `tok-${plaintext.slice(-8)}`,
      displayName: 'T',
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('apiTokens', {
      name: 'test',
      tokenHash,
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: admin,
      scopes,
      subjectType: 'service',
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

const upload = (t: ReturnType<typeof convexTest>, token: string, data: unknown) =>
  t.fetch('/api/v1/admin/site/home-image', {
    method: 'PUT',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify({ data }),
  });

const errorCode = async (res: Response) =>
  ((await res.json()) as { error?: { code?: string } }).error?.code;

describe('home image routes', () => {
  test('upload, serve through /config, replace the cache policy, reset', async () => {
    const t = convexTest(schema, modules);
    const token = await settingsToken(t, ['admin:settings:write']);
    const readOnly = await settingsToken(t, ['admin:settings:read']);

    // Nothing set: the public route 404s and /config carries null.
    expect((await t.fetch('/api/v1/site/home-image')).status).toBe(404);
    const before = (await (await t.fetch('/api/v1/config')).json()) as {
      site?: { homeImage?: unknown };
    };
    expect(before.site?.homeImage).toBeNull();

    // Needs settings:write.
    expect((await upload(t, readOnly, poster.toString('base64'))).status).toBe(401);

    const ok = await upload(t, token, poster.toString('base64'));
    expect(ok.status).toBe(200);
    const { homeImage } = (await ok.json()) as {
      homeImage: { version: string; width: number; height: number };
    };
    expect(homeImage).toEqual({
      version: expect.stringMatching(/^[0-9a-f]{16}$/),
      width: 1000,
      height: 1440,
    });

    const cfg = (await (await t.fetch('/api/v1/config')).json()) as {
      site?: { homeImage?: unknown };
    };
    expect(cfg.site?.homeImage).toEqual(homeImage);

    // The asked-for version caches for good; anything else briefly.
    const img = await t.fetch(`/api/v1/site/home-image?v=${homeImage.version}`);
    expect(img.status).toBe(200);
    expect(img.headers.get('content-type')).toBe('image/png');
    expect(img.headers.get('cache-control')).toContain('immutable');
    expect(img.headers.get('x-content-type-options')).toBe('nosniff');
    expect(Buffer.from(await img.arrayBuffer()).equals(poster)).toBe(true);
    const stale = await t.fetch('/api/v1/site/home-image?v=0000000000000000');
    expect(stale.headers.get('cache-control')).toBe('public, max-age=300');

    const audit = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .filter((q) => q.eq(q.field('action'), 'admin.site.home_image.set'))
        .first(),
    );
    expect(audit?.payload).toEqual({
      ...homeImage,
      bytes: poster.length,
      contentType: 'image/png',
    });

    const reset = await t.fetch('/api/v1/admin/site/home-image', {
      method: 'DELETE',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(reset.status).toBe(200);
    expect(await reset.json()).toEqual({ homeImage: null });
    expect((await t.fetch('/api/v1/site/home-image')).status).toBe(404);
    const after = (await (await t.fetch('/api/v1/config')).json()) as {
      site?: { homeImage?: unknown };
    };
    expect(after.site?.homeImage).toBeNull();
    const rows = await t.run((ctx) => ctx.db.query('siteImages').collect());
    expect(rows).toEqual([]);
  });

  test('refuses what is not a usable image', async () => {
    const t = convexTest(schema, modules);
    const token = await settingsToken(t, ['admin:settings:write']);

    const notBase64 = await upload(t, token, 'data:image/png;base64,AAAA');
    expect(notBase64.status).toBe(400);
    expect(await errorCode(notBase64)).toBe('site_image.bad_request');

    const svg = await upload(t, token, btoa('<svg xmlns="http://www.w3.org/2000/svg"/>'));
    expect(await errorCode(svg)).toBe('site_image.unsupported_type');

    const big = Buffer.alloc(MAX_SITE_IMAGE_BYTES + 1);
    poster.copy(big, 0, 0, 64);
    const tooLarge = await upload(t, token, big.toString('base64'));
    expect(tooLarge.status).toBe(400);
    expect(await errorCode(tooLarge)).toBe('site_image.too_large');

    expect(await t.run((ctx) => ctx.db.query('siteImages').collect())).toEqual([]);
  });
});
