/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from '../schema';
import { internal } from '../_generated/api';
import {
  ANALYTICS_DEFAULTS,
  publicAnalytics,
  resolveAnalyticsConfig,
  sanitizeUmamiUrl,
  sanitizeWebsiteId,
} from './analyticsConfig';

const modules = import.meta.glob('../**/*.*s');

const UUID = 'b1f0a2c4-1234-4abc-9def-0123456789ab';

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('sanitizeUmamiUrl', () => {
  test('accepts a trimmed https URL and strips trailing slashes', () => {
    expect(sanitizeUmamiUrl('  https://analytics.example.org  ')).toBe(
      'https://analytics.example.org',
    );
    expect(sanitizeUmamiUrl('https://analytics.example.org/')).toBe(
      'https://analytics.example.org',
    );
    expect(sanitizeUmamiUrl('https://analytics.example.org//')).toBe(
      'https://analytics.example.org',
    );
  });

  test('rejects non-https, junk, and non-strings', () => {
    expect(sanitizeUmamiUrl('http://analytics.example.org')).toBe('');
    expect(sanitizeUmamiUrl('javascript:alert(1)')).toBe('');
    expect(sanitizeUmamiUrl('')).toBe('');
    expect(sanitizeUmamiUrl('   ')).toBe('');
    expect(sanitizeUmamiUrl(42)).toBe('');
    expect(sanitizeUmamiUrl(null)).toBe('');
    expect(sanitizeUmamiUrl(`https://a.example/${'x'.repeat(600)}`)).toBe('');
  });

  test('rejects loopback/link-local/metadata literals (SSRF denylist)', () => {
    expect(sanitizeUmamiUrl('https://127.0.0.1:3000')).toBe('');
    expect(sanitizeUmamiUrl('https://localhost:3000')).toBe('');
    expect(sanitizeUmamiUrl('https://169.254.169.254')).toBe('');
    expect(sanitizeUmamiUrl('https://[::1]:3000')).toBe('');
  });

  test('ALLOW_INTERNAL_BACKENDS=true permits loopback AND plain http (dev)', () => {
    vi.stubEnv('ALLOW_INTERNAL_BACKENDS', 'true');
    expect(sanitizeUmamiUrl('https://127.0.0.1:3000')).toBe('https://127.0.0.1:3000');
    expect(sanitizeUmamiUrl('http://umami:3000/')).toBe('http://umami:3000');
    expect(sanitizeUmamiUrl('http://host.docker.internal:3999')).toBe(
      'http://host.docker.internal:3999',
    );
    // Still not a scheme free-for-all.
    expect(sanitizeUmamiUrl('javascript:alert(1)')).toBe('');
  });
});

describe('sanitizeWebsiteId', () => {
  test('accepts a UUID (uppercase lowercased, trimmed)', () => {
    expect(sanitizeWebsiteId(UUID)).toBe(UUID);
    expect(sanitizeWebsiteId(`  ${UUID.toUpperCase()}  `)).toBe(UUID);
  });

  test('rejects junk and non-strings', () => {
    expect(sanitizeWebsiteId('abc')).toBe('');
    expect(sanitizeWebsiteId('')).toBe('');
    expect(sanitizeWebsiteId(`${UUID}; DROP`)).toBe('');
    expect(sanitizeWebsiteId(42)).toBe('');
    expect(sanitizeWebsiteId(null)).toBe('');
  });
});

describe('resolveAnalyticsConfig', () => {
  test('defaults (no rows): disabled, empty targets, forwardIp off', async () => {
    const t = convexTest(schema, modules);
    const cfg = await t.run((ctx) => resolveAnalyticsConfig(ctx.db));
    expect(cfg).toEqual(ANALYTICS_DEFAULTS);
  });

  test('reads set rows; corrupt values fall back safely', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      const now = Date.now();
      const rows: Array<[string, unknown]> = [
        ['analytics.enabled', 'yes'], // corrupt non-boolean → default false
        ['analytics.umamiUrl', 'javascript:alert(1)'], // unsafe → ''
        ['analytics.websiteId', UUID],
        ['analytics.forwardIp', true],
      ];
      for (const [key, value] of rows) {
        await ctx.db.insert('appSettings', { key, value: JSON.stringify(value), updatedAt: now });
      }
    });
    const cfg = await t.run((ctx) => resolveAnalyticsConfig(ctx.db));
    expect(cfg.enabled).toBe(false);
    expect(cfg.umamiUrl).toBe('');
    expect(cfg.websiteId).toBe(UUID);
    expect(cfg.forwardIp).toBe(true);
  });
});

describe('publicAnalytics', () => {
  const base = { enabled: true, umamiUrl: 'https://a.example', websiteId: UUID, forwardIp: false };

  test('effectively enabled only when the toggle AND both targets are set', () => {
    expect(publicAnalytics(base)).toEqual({ enabled: true });
    expect(publicAnalytics({ ...base, enabled: false })).toEqual({ enabled: false });
    expect(publicAnalytics({ ...base, umamiUrl: '' })).toEqual({ enabled: false });
    expect(publicAnalytics({ ...base, websiteId: '' })).toEqual({ enabled: false });
  });

  test('projects EXACTLY one key (regression guard against a future leak)', () => {
    expect(Object.keys(publicAnalytics(base))).toEqual(['enabled']);
  });
});

describe('setAnalyticsConfig', () => {
  test('round-trips through sanitize + storage and echoes cleaned values', async () => {
    const t = convexTest(schema, modules);
    const clean = await t.mutation(internal.adminApi.setAnalyticsConfig, {
      enabled: true,
      umamiUrl: '  https://analytics.example.org/  ',
      websiteId: UUID.toUpperCase(),
      forwardIp: false,
      umamiUrlHash: 'deadbeef',
    });
    expect(clean).toEqual({
      enabled: true,
      umamiUrl: 'https://analytics.example.org',
      websiteId: UUID,
      forwardIp: false,
    });
    const cfg = await t.run((ctx) => resolveAnalyticsConfig(ctx.db));
    expect(cfg).toEqual(clean);
  });

  test('junk values store harmlessly as empty', async () => {
    const t = convexTest(schema, modules);
    const clean = await t.mutation(internal.adminApi.setAnalyticsConfig, {
      enabled: true,
      umamiUrl: 'http://insecure.example',
      websiteId: 'not-a-uuid',
      forwardIp: true,
      umamiUrlHash: '',
    });
    expect(clean.umamiUrl).toBe('');
    expect(clean.websiteId).toBe('');
    // Effectively disabled despite the toggle.
    const cfg = await t.run((ctx) => resolveAnalyticsConfig(ctx.db));
    expect(publicAnalytics(cfg)).toEqual({ enabled: false });
  });

  test('audits booleans + hash only — never the URL or website id', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.adminApi.setAnalyticsConfig, {
      enabled: true,
      umamiUrl: 'https://analytics.example.org',
      websiteId: UUID,
      forwardIp: true,
      umamiUrlHash: 'deadbeef',
    });
    const entries = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const entry = entries.find((e) => e.action === 'admin.analytics.change');
    expect(entry).toBeTruthy();
    const payload = JSON.stringify(entry?.payload ?? {});
    expect(payload).toContain('deadbeef');
    expect(payload).not.toContain('analytics.example.org');
    expect(payload).not.toContain(UUID);
  });
});
