/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from '../schema';
import { internal } from '../_generated/api';
import { resolveSiteConfig, sanitizeBannerText, sanitizeEmail, SITE_DEFAULTS } from './siteConfig';

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

describe('sanitizeEmail', () => {
  test('accepts a plain single address (trimmed)', () => {
    expect(sanitizeEmail('help@freesocks.org')).toBe('help@freesocks.org');
    expect(sanitizeEmail('  help@freesocks.org  ')).toBe('help@freesocks.org');
    expect(sanitizeEmail('support+tag@sub.example.co')).toBe('support+tag@sub.example.co');
  });

  test('rejects non-strings and empty', () => {
    expect(sanitizeEmail(undefined)).toBe('');
    expect(sanitizeEmail(null)).toBe('');
    expect(sanitizeEmail(42)).toBe('');
    expect(sanitizeEmail('')).toBe('');
    expect(sanitizeEmail('   ')).toBe('');
  });

  test('rejects anything unsafe inside a mailto: href', () => {
    expect(sanitizeEmail('not-an-email')).toBe('');
    expect(sanitizeEmail('two words@example.org')).toBe('');
    expect(sanitizeEmail('a@b@example.org')).toBe('');
    expect(sanitizeEmail('a,b@example.org')).toBe('');
    expect(sanitizeEmail('<script>@example.org')).toBe('');
    expect(sanitizeEmail('help@localhost')).toBe(''); // no dotted domain
    expect(sanitizeEmail(`${'a'.repeat(250)}@example.org`)).toBe(''); // overlong
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

  test('reads the transparency + social URLs; non-https values sanitize to empty', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      const rows: Array<[string, string]> = [
        ['site.transparencyUrl', 'https://example.org/transparency'],
        ['site.socialXUrl', 'https://x.com/freesocks'],
        ['site.socialMastodonUrl', 'http://mastodon.example/@freesocks'], // http → rejected
        ['site.socialBlueskyUrl', 'javascript:alert(1)'], // unsafe scheme → rejected
        ['site.supportEmail', 'help@freesocks.org'],
      ];
      for (const [key, value] of rows) {
        await ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: now });
      }
    });
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg.transparencyUrl).toBe('https://example.org/transparency');
    expect(cfg.socialXUrl).toBe('https://x.com/freesocks');
    expect(cfg.socialMastodonUrl).toBe(''); // the footer icon then hides
    expect(cfg.socialBlueskyUrl).toBe('');
    expect(cfg.supportEmail).toBe('help@freesocks.org');
  });

  test('setSiteConfig round-trips supportEmail through sanitize + storage', async () => {
    const t = convexTest(schema, modules);
    const blank = {
      bannerEnabled: false,
      bannerText: '',
      repoEnabled: false,
      repoUrl: '',
      tosUrl: '',
      privacyUrl: '',
      transparencyUrl: '',
      socialXUrl: '',
      socialMastodonUrl: '',
      socialBlueskyUrl: '',
    };
    const clean = await t.mutation(internal.adminApi.setSiteConfig, {
      ...blank,
      supportEmail: '  help@freesocks.org ',
    });
    expect(clean.supportEmail).toBe('help@freesocks.org');
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg.supportEmail).toBe('help@freesocks.org');

    // A junk value stores as '' (links hide) rather than a broken mailto.
    const cleared = await t.mutation(internal.adminApi.setSiteConfig, {
      ...blank,
      supportEmail: 'help@freesocks.org?bcc=evil@example.org',
    });
    expect(cleared.supportEmail).toBe('');
  });

  test('invalid stored support email resolves to empty (links hide)', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.db.insert('appSettings', {
        key: 'site.supportEmail',
        value: JSON.stringify('mailto:evil@example.org?bcc=x'),
        updatedAt: Date.now(),
      });
    });
    const cfg = await t.run((ctx) => resolveSiteConfig(ctx.db));
    expect(cfg.supportEmail).toBe('');
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
