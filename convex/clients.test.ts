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
import {
  DEFAULT_CLIENTS,
  resolveClients,
  publicClients,
  type ClientBackend,
} from './lib/clientCatalog';

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
      easeOfUse: 'easy',
    });
    expect(a.created).toBe(true);
    expect(a.easeOfUse).toBe('easy');
    const b = await t.mutation(internal.clients.upsertByName, { name: 'UpApp', priority: 5 });
    expect(b.created).toBe(false);
    expect(b.priority).toBe(5);
    expect(b.homepageUrl).toBe('https://u.com'); // preserved
    expect(b.easeOfUse).toBe('easy'); // preserved
    const c = await t.mutation(internal.clients.upsertByName, { name: 'UpApp', easeOfUse: null });
    expect(c.easeOfUse).toBeNull(); // null clears the rating
  });

  test('description round-trips (trimmed + capped), null clears it', async () => {
    const t = convexTest(schema, modules);
    const created = await t.mutation(internal.clients.create, {
      name: 'DescApp',
      platforms: ['android'],
      backends: ['remnawave'],
      homepageUrl: 'https://d.example',
      description: '  A fine app.  ',
    });
    expect(created.description).toBe('A fine app.'); // trimmed

    const capped = await t.mutation(internal.clients.update, {
      id: created.id as Id<'clients'>,
      description: 'x'.repeat(400),
    });
    expect(capped.description?.length).toBe(280); // length-capped

    const cleared = await t.mutation(internal.clients.update, {
      id: created.id as Id<'clients'>,
      description: null,
    });
    expect(cleared.description).toBeNull(); // null clears → SPA i18n fallback
  });

  test('refreshDefaultClients overwrites default-managed fields, keeps enabled + admin rows', async () => {
    const t = convexTest(schema, modules);
    // Seed the defaults, then simulate the pre-repoint state: a stale install
    // URL + no rating, and an admin's enabled=false choice.
    await t.mutation(internal.seed.seedClients, {});
    const { clients } = await t.query(internal.clients.listForAdmin, {});
    const hiddify = clients.find((c) => c.name === 'Hiddify')!;
    await t.mutation(internal.clients.update, {
      id: hiddify.id as Id<'clients'>,
      homepageUrl: 'https://stale.example',
      easeOfUse: null,
      enabled: false,
      description: 'Admin blurb the refresh must keep.',
    });
    // An admin-added client the refresh must not touch.
    await t.mutation(internal.clients.create, {
      name: 'AdminOnly',
      platforms: ['android'],
      backends: ['remnawave'],
      homepageUrl: 'https://admin.example',
    });

    const res = await t.mutation(internal.seed.refreshDefaultClients, {});
    expect(res.updated).toBe(DEFAULT_CLIENTS.length);
    expect(res.inserted).toBe(0);

    const after = (await t.query(internal.clients.listForAdmin, {})).clients;
    const h = after.find((c) => c.name === 'Hiddify')!;
    expect(h.homepageUrl).toBe('https://hiddify.com'); // default re-applied
    expect(h.easeOfUse).toBe('easy'); // rating re-applied
    expect(h.enabled).toBe(false); // admin's enabled choice preserved
    expect(h.description).toBe('Admin blurb the refresh must keep.'); // admin blurb preserved
    const admin = after.find((c) => c.name === 'AdminOnly')!;
    expect(admin.homepageUrl).toBe('https://admin.example'); // untouched
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
        description: 'An admin blurb that must reach members.',
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
    // The admin-set blurb travels to members (i18n-fallback happens client-side).
    expect(projected.find((c) => c.name === 'B')?.description).toBe(
      'An admin blurb that must reach members.',
    );
  });

  test('Anywhere is Apple-only: no Android tab, App Store install link', () => {
    const anywhere = DEFAULT_CLIENTS.find((c) => c.name === 'Anywhere')!;
    // Verified upstream (iOS/iPadOS/tvOS, runs on Apple-silicon Macs): the app
    // has NO Android build, and installs come from the App Store.
    expect(anywhere.platforms).not.toContain('android');
    expect(anywhere.platforms).toContain('ios');
    expect(anywhere.homepageUrl).toMatch(/^https:\/\/apps\.apple\.com\//);
  });

  test('DEFAULT_CLIENTS carry open-source metadata (labels + source repos)', () => {
    const find = (name: string) => DEFAULT_CLIENTS.find((c) => c.name === name);
    // 7 of the 8 originals are open source; Shadowrocket is the lone proprietary one.
    expect(find('Hiddify')?.openSource).toBe(true);
    expect(find('Hiddify')?.license).toBe('GPL-3.0');
    expect(find('Shadowrocket')?.openSource).toBe(false);
    expect(find('Shadowrocket')?.license).toBe('Proprietary');
    // the verified open-source additions are present + labeled OSS
    for (const name of ['Anywhere', 'v2rayN', 'FlClash', 'Mihomo Party']) {
      expect(find(name)?.openSource, name).toBe(true);
    }
    // every open-source app advertises a public source repo
    for (const c of DEFAULT_CLIENTS) {
      if (c.openSource) expect(c.sourceUrl, c.name).toBeTruthy();
    }
  });

  test('DEFAULT_CLIENTS all carry an ease-of-use rating + install-page (non-repo-root) URLs', () => {
    for (const c of DEFAULT_CLIENTS) {
      expect(c.easeOfUse, c.name).toMatch(/^(easy|moderate|advanced)$/);
      // The Install link must land on a page with downloads, not a bare source
      // repo root (github.com/<org>/<repo> with no further path).
      expect(c.homepageUrl, c.name).not.toMatch(/^https:\/\/github\.com\/[^/]+\/[^/]+$/);
    }
  });

  test('publicClients ranks open-source ahead of proprietary, then by priority', () => {
    const projected = publicClients([
      {
        name: 'Proprietary-best-priority',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'x',
        schemeId: null,
        hwid: false,
        openSource: false,
        enabled: true,
        priority: 1,
      },
      {
        name: 'OSS-worst-priority',
        platforms: [],
        backends: ['remnawave'],
        homepageUrl: 'x',
        schemeId: null,
        hwid: false,
        openSource: true,
        sourceUrl: 'https://example.com/src',
        enabled: true,
        priority: 99,
      },
    ]);
    // The open-source app wins despite the worse (higher) priority number.
    expect(projected.map((c) => c.name)).toEqual([
      'OSS-worst-priority',
      'Proprietary-best-priority',
    ]);
    expect(projected[0].openSource).toBe(true);
    expect(projected[0].sourceUrl).toBe('https://example.com/src');
  });

  test('publicClients ranks by ease within an OSS group; OSS still beats proprietary-easy', () => {
    const base = {
      platforms: [],
      backends: ['remnawave'] satisfies ClientBackend[],
      homepageUrl: 'x',
      schemeId: null,
      hwid: false,
      enabled: true,
    };
    const projected = publicClients([
      { ...base, name: 'oss-advanced', openSource: true, easeOfUse: 'advanced', priority: 1 },
      { ...base, name: 'oss-easy', openSource: true, easeOfUse: 'easy', priority: 99 },
      // unrated = moderate → between easy and advanced despite a better priority
      { ...base, name: 'oss-unrated', openSource: true, priority: 1 },
      { ...base, name: 'prop-easy', openSource: false, easeOfUse: 'easy', priority: 1 },
    ]);
    expect(projected.map((c) => c.name)).toEqual([
      'oss-easy',
      'oss-unrated',
      'oss-advanced',
      'prop-easy',
    ]);
    expect(projected[0].easeOfUse).toBe('easy'); // shipped in the projection
  });

  test('publicConfig.get ships the clients catalog (defaults when unseeded)', async () => {
    const t = convexTest(schema, modules);
    const cfg = await t.query(api.publicConfig.get, {});
    expect(Array.isArray(cfg.clients)).toBe(true);
    expect(cfg.clients.map((c) => c.name)).toContain('Hiddify');
    expect(cfg.clients[0]).not.toHaveProperty('enabled');
  });
});
