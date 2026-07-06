/// <reference types="vite/client" />
/**
 * The DB-driven recommended-client catalog: CRUD + name uniqueness, the
 * resolveClients empty→defaults fallback, the public projection (enabled-only,
 * sorted, no CMS internals), and that publicConfig.get ships it.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { api, internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { DEFAULT_CLIENTS, resolveClients, publicClients } from './lib/clientCatalog';

const modules = import.meta.glob('./**/*.*s');

describe('clients CRUD', () => {
  test('create normalizes platforms + rejects a duplicate name', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.clients.create, {
      name: 'TestApp',
      platforms: ['android', 'ios', 'bogus'],
      backends: ['remnawave'],
      homepageUrl: 'https://example.com',
      schemeId: 'hiddify',
      hwid: true,
    });
    expect(created.name).toBe('TestApp');
    expect(created.platforms).toEqual(['android', 'ios']); // 'bogus' dropped
    expect(created.schemeId).toBe('hiddify');
    expect(created.enabled).toBe(true); // default

    const { clients } = await t.query(internal.clients.listForAdmin, {});
    expect(clients.map((c) => c.name)).toContain('TestApp');

    await expect(
      t.mutation(internal.clients.create, {
        name: 'TestApp',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'https://x.com',
      }),
    ).rejects.toThrow(/already exists/i);
  });

  test('update patches, clears the scheme with null; remove deletes', async () => {
    const t = convexTest(schema, modules);
    const c = await t.mutation(internal.clients.create, {
      name: 'App2',
      platforms: ['ios'],
      backends: ['remnawave'],
      homepageUrl: 'https://a.com',
      schemeId: 'clash',
    });
    const upd = await t.mutation(internal.clients.update, {
      id: c.id as Id<'clients'>,
      schemeId: null,
      enabled: false,
    });
    expect(upd.schemeId).toBeNull();
    expect(upd.enabled).toBe(false);

    await t.mutation(internal.clients.remove, { id: c.id as Id<'clients'> });
    const { clients } = await t.query(internal.clients.listForAdmin, {});
    expect(clients.find((x) => x.name === 'App2')).toBeUndefined();
  });

  test('upsertByName creates then patches, preserving unspecified fields', async () => {
    const t = convexTest(schema, modules);
    const a = await t.mutation(internal.clients.upsertByName, {
      name: 'UpApp',
      homepageUrl: 'https://u.com',
      backends: ['remnawave'],
      platforms: ['android'],
    });
    expect(a.created).toBe(true);
    const b = await t.mutation(internal.clients.upsertByName, { name: 'UpApp', priority: 5 });
    expect(b.created).toBe(false);
    expect(b.priority).toBe(5);
    expect(b.homepageUrl).toBe('https://u.com'); // preserved
  });
});

describe('clientCatalog resolve + project', () => {
  test('resolveClients falls back to DEFAULT_CLIENTS when the table is empty', async () => {
    const t = convexTest(schema, modules);
    const list = await t.run((ctx) => resolveClients(ctx.db));
    expect(list.length).toBe(DEFAULT_CLIENTS.length);
    expect(list.map((c) => c.name)).toContain('Hiddify');
  });

  test('resolveClients returns the table rows once populated', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.clients.create, {
      name: 'Only',
      platforms: ['android'],
      backends: ['remnawave'],
      homepageUrl: 'https://o.com',
    });
    const list = await t.run((ctx) => resolveClients(ctx.db));
    expect(list.map((c) => c.name)).toEqual(['Only']);
  });

  test('publicClients: enabled-only, priority-sorted, no CMS internals', () => {
    const projected = publicClients([
      {
        name: 'B',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'x',
        schemeId: null,
        hwid: false,
        enabled: true,
        priority: 20,
      },
      {
        name: 'A',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'x',
        schemeId: 'hiddify',
        hwid: false,
        enabled: true,
        priority: 10,
      },
      {
        name: 'Off',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'x',
        schemeId: null,
        hwid: false,
        enabled: false,
        priority: 5,
      },
    ]);
    expect(projected.map((c) => c.name)).toEqual(['A', 'B']); // sorted; 'Off' filtered
    expect(projected[0]).not.toHaveProperty('enabled');
    expect(projected[0]).not.toHaveProperty('priority');
  });

  test('publicConfig.get ships the clients catalog (defaults when unseeded)', async () => {
    const t = convexTest(schema, modules);
    const cfg = await t.query(api.publicConfig.get, {});
    expect(Array.isArray(cfg.clients)).toBe(true);
    expect(cfg.clients.map((c) => c.name)).toContain('Hiddify');
    expect(cfg.clients[0]).not.toHaveProperty('enabled');
  });
});
