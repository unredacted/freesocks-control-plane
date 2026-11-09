/// <reference types="vite/client" />
/**
 * `migrateProbeNetworks`: the retired "Prefer residential networks" switch
 * (`edge.probe.preferEyeball`) becomes `edge.probe.networks` at deploy, and
 * `restoreProbeNetworksForRollback` writes it back before an older build.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { resolveEdgeConfig } from './lib/edgeConfig';

const modules = import.meta.glob('./**/*.*s');
const OLD = 'edge.probe.preferEyeball';
const NEW = 'edge.probe.networks';

type T = ReturnType<typeof convexTest>;
async function put(t: T, key: string, raw: string) {
  await t.run((ctx) => ctx.db.insert('appSettings', { key, value: raw, updatedAt: Date.now() }));
}
async function stored(t: T) {
  const rows = await t.run((ctx) => ctx.db.query('appSettings').collect());
  return new Map(rows.map((r) => [r.key, r.value]));
}
const networks = (t: T) => t.run(async (ctx) => (await resolveEdgeConfig(ctx.db)).probe.networks);

describe('seed.migrateProbeNetworks', () => {
  test('nothing stored: home networks only (the default), nothing written', async () => {
    const t = convexTest(schema, modules);
    expect(await t.mutation(internal.seed.migrateProbeNetworks, {})).toEqual({
      migrated: null,
      kept: false,
    });
    expect((await stored(t)).has(NEW)).toBe(false);
    expect(await networks(t)).toBe('home');
  });

  test('on becomes home networks only, off becomes any network; the old row goes; a second run is a no-op', async () => {
    for (const [raw, want] of [
      ['true', 'home'],
      ['false', 'any'],
      ['"garbage"', 'home'],
    ] as const) {
      const t = convexTest(schema, modules);
      await put(t, OLD, raw);
      expect(await t.mutation(internal.seed.migrateProbeNetworks, {})).toEqual({
        migrated: want,
        kept: false,
      });
      const after = await stored(t);
      expect(after.has(OLD)).toBe(false);
      expect(after.get(NEW)).toBe(JSON.stringify(want));
      expect(await networks(t)).toBe(want);
      expect(await t.mutation(internal.seed.migrateProbeNetworks, {})).toEqual({
        migrated: null,
        kept: false,
      });
    }
  });

  test('a stored network setting wins over the old switch', async () => {
    const t = convexTest(schema, modules);
    await put(t, OLD, 'false');
    await put(t, NEW, '"home_first"');
    expect(await t.mutation(internal.seed.migrateProbeNetworks, {})).toEqual({
      migrated: null,
      kept: true,
    });
    expect((await stored(t)).has(OLD)).toBe(false);
    expect(await networks(t)).toBe('home_first');
  });

  test('rollback: any network writes the old switch off, a home setting writes it on', async () => {
    for (const [raw, on] of [
      ['"any"', false],
      ['"home"', true],
      ['"home_first"', true],
    ] as const) {
      const t = convexTest(schema, modules);
      await put(t, NEW, raw);
      expect(await t.mutation(internal.seed.restoreProbeNetworksForRollback, {})).toEqual({
        preferEyeball: on,
      });
      expect((await stored(t)).get(OLD)).toBe(JSON.stringify(on));
    }
  });
});
