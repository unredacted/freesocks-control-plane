/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from '../schema';
import { resolveSiteConfig, sanitizeBannerText, SITE_DEFAULTS } from './siteConfig';

const modules = import.meta.glob('../**/*.*s');

describe('sanitizeBannerText', () => {
  test('trims and coerces non-strings to empty', () => {
    expect(sanitizeBannerText('  maintenance tonight  ')).toBe('maintenance tonight');
    expect(sanitizeBannerText('')).toBe('');
    expect(sanitizeBannerText(undefined)).toBe('');
    expect(sanitizeBannerText(42)).toBe('');
    expect(sanitizeBannerText(null)).toBe('');
  });

  test('caps length (banners are one-liners)', () => {
    expect(sanitizeBannerText('a'.repeat(400)).length).toBe(280);
    expect(sanitizeBannerText('a'.repeat(400), 10)).toBe('aaaaaaaaaa');
  });
});

describe('resolveSiteConfig', () => {
  test('defaults (no rows): banner + repo off, empty strings', async () => {
    const t = convexTest(schema, modules);
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg).toEqual(SITE_DEFAULTS);
    expect(cfg.bannerEnabled).toBe(false);
    expect(cfg.repoEnabled).toBe(false);
  });

  test('reads set values from appSettings', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: 'site.bannerEnabled',
        value: JSON.stringify(true),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'site.bannerText',
        value: JSON.stringify('  Service maintenance 03:00 UTC  '),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'site.repoEnabled',
        value: JSON.stringify(true),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'site.repoUrl',
        value: JSON.stringify('https://github.com/org/repo'),
        updatedAt: now,
      });
    });
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg.bannerEnabled).toBe(true);
    expect(cfg.bannerText).toBe('Service maintenance 03:00 UTC'); // trimmed on read
    expect(cfg.repoEnabled).toBe(true);
    expect(cfg.repoUrl).toBe('https://github.com/org/repo');
  });

  test('fail-safe: non-https repo URL → empty; non-boolean toggle → default', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      await ctx.db.insert('appSettings', {
        key: 'site.repoUrl',
        value: JSON.stringify('javascript:alert(1)'),
        updatedAt: now,
      });
      await ctx.db.insert('appSettings', {
        key: 'site.repoEnabled',
        value: JSON.stringify(true),
        updatedAt: now,
      });
      // A corrupt (non-boolean) toggle must fall back to the default, not throw.
      await ctx.db.insert('appSettings', {
        key: 'site.bannerEnabled',
        value: JSON.stringify('yes'),
        updatedAt: now,
      });
    });
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg.repoUrl).toBe(''); // unsafe scheme rejected — the footer link then hides
    expect(cfg.repoEnabled).toBe(true); // toggle itself is valid
    expect(cfg.bannerEnabled).toBe(false); // corrupt value → default
  });
});
