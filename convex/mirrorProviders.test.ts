/// <reference types="vite/client" />
/**
 * S3 mirror-provider CRUD + resolvers (the DB-driven replacement for the
 * S3_PROVIDER_* env scheme). Covers: the masked admin view never leaks the
 * secret, name uniqueness, the write-only secret (a blank edit keeps it), the
 * active-only vs all resolvers, and the `anyActive` issuance gate.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

const BASE = {
  name: 'p1',
  endpoint: 'https://s3.example.com',
  bucket: 'subs',
  publicUrl: 'https://cdn.example.com',
  accessKeyId: 'AKIATEST',
  secretAccessKey: 'sk-secret-1',
};

describe('mirrorProviders CRUD', () => {
  test('create returns a masked row (secret → boolean, never the value)', async () => {
    const t = convexTest(schema, modules);
    const row = await t.mutation(internal.mirrorProviders.create, BASE);
    expect(row.name).toBe('p1');
    expect(row.region).toBe('us-east-1'); // defaulted
    expect(row.accessKeyId).toBe('AKIATEST'); // public half is shown
    expect(row.secretAccessKeySet).toBe(true);
    expect(row.isActive).toBe(true);
    // The secret must NOT appear on the admin-facing object.
    expect(JSON.stringify(row)).not.toContain('sk-secret-1');
  });

  test('create rejects a duplicate name', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.mirrorProviders.create, BASE);
    await expect(t.mutation(internal.mirrorProviders.create, BASE)).rejects.toThrow(
      /already exists/,
    );
  });

  test('create rejects a missing required field', async () => {
    const t = convexTest(schema, modules);
    const { secretAccessKey: _drop, ...partial } = BASE;
    await expect(
      t.mutation(internal.mirrorProviders.create, { ...partial, secretAccessKey: '' }),
    ).rejects.toThrow(/required/);
  });

  test('update is write-only for the secret: a blank edit keeps the stored one', async () => {
    const t = convexTest(schema, modules);
    const row = await t.mutation(internal.mirrorProviders.create, BASE);
    // Edit priority only — no secret retyped.
    await t.mutation(internal.mirrorProviders.update, {
      id: row.id as never,
      priority: 7,
    });
    const active = await t.query(internal.mirrorProviders.listActiveWithSecret, {});
    expect(active).toHaveLength(1);
    expect(active[0]!.secretAccessKey).toBe('sk-secret-1'); // unchanged
    // Now rotate the secret.
    await t.mutation(internal.mirrorProviders.update, {
      id: row.id as never,
      secretAccessKey: 'sk-secret-2',
    });
    const after = await t.query(internal.mirrorProviders.listActiveWithSecret, {});
    expect(after[0]!.secretAccessKey).toBe('sk-secret-2');
  });

  test('listActiveWithSecret returns only active, ascending by priority', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'a', priority: 5 });
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'b', priority: 1 });
    await t.mutation(internal.mirrorProviders.create, {
      ...BASE,
      name: 'c',
      priority: 0,
      isActive: false,
    });
    const active = await t.query(internal.mirrorProviders.listActiveWithSecret, {});
    expect(active.map((p) => p.name)).toEqual(['b', 'a']); // c is inactive, dropped
  });

  test('listAllWithSecret includes inactive providers (for teardown cleanup)', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'a' });
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'b', isActive: false });
    const all = await t.query(internal.mirrorProviders.listAllWithSecret, {});
    expect(all.map((p) => p.name).sort()).toEqual(['a', 'b']);
  });

  test('anyActive is the issuance gate: false until an active provider exists', async () => {
    const t = convexTest(schema, modules);
    expect(await t.query(internal.mirrorProviders.anyActive, {})).toBe(false);
    await t.mutation(internal.mirrorProviders.create, { ...BASE, isActive: false });
    expect(await t.query(internal.mirrorProviders.anyActive, {})).toBe(false);
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'p2', isActive: true });
    expect(await t.query(internal.mirrorProviders.anyActive, {})).toBe(true);
  });

  test('listForAdmin masks every row + remove deletes', async () => {
    const t = convexTest(schema, modules);
    const row = await t.mutation(internal.mirrorProviders.create, BASE);
    const list = await t.query(internal.mirrorProviders.listForAdmin, {});
    expect(list.providers).toHaveLength(1);
    expect(JSON.stringify(list.providers)).not.toContain('sk-secret-1');
    await t.mutation(internal.mirrorProviders.remove, { id: row.id as never });
    const after = await t.query(internal.mirrorProviders.listForAdmin, {});
    expect(after.providers).toHaveLength(0);
  });
});

describe('mirrorProviders country tiering', () => {
  test('create normalizes country codes (uppercase, 2-letter, dedupe)', async () => {
    const t = convexTest(schema, modules);
    const row = await t.mutation(internal.mirrorProviders.create, {
      ...BASE,
      countryCodes: ['ir', 'RU', ' cn ', 'bad', '12', 'IR'],
    });
    expect([...row.countryCodes].sort()).toEqual(['CN', 'IR', 'RU']);
  });

  test('selectNextProvider: country match first, then global by priority, excluding tried', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.mirrorProviders.create, {
      ...BASE,
      name: 'ir-host',
      countryCodes: ['IR'],
      priority: 5,
    });
    await t.mutation(internal.mirrorProviders.create, {
      ...BASE,
      name: 'global-host',
      countryCodes: [],
      priority: 1,
    });
    await t.mutation(internal.mirrorProviders.create, {
      ...BASE,
      name: 'cn-host',
      countryCodes: ['CN'],
      priority: 0,
    });

    // IR match beats the lower-priority global host AND the CN-only host.
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, { countryCode: 'IR', tried: [] }),
    ).toEqual({ name: 'ir-host' });
    // IR tried → only the global host is eligible (cn-host is scoped to CN).
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, {
        countryCode: 'IR',
        tried: ['ir-host'],
      }),
    ).toEqual({ name: 'global-host' });
    // No country, or a country with no match → the global host.
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, { countryCode: null, tried: [] }),
    ).toEqual({ name: 'global-host' });
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, { countryCode: 'US', tried: [] }),
    ).toEqual({ name: 'global-host' });
    // Everything eligible tried → null (cn-host stays excluded for IR).
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, {
        countryCode: 'IR',
        tried: ['ir-host', 'global-host'],
      }),
    ).toBeNull();
  });

  test('an inactive provider is never selected', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.mirrorProviders.create, { ...BASE, name: 'off', isActive: false });
    expect(
      await t.query(internal.mirrorProviders.selectNextProvider, { countryCode: null, tried: [] }),
    ).toBeNull();
  });
});
