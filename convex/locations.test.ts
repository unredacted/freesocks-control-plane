/// <reference types="vite/client" />
/**
 * Member-facing node-location catalog (lib/locations.resolveLocations): the
 * dedupe-by-code projection of active Remnawave instances that publicConfig
 * ships and the regenerate route validates a member's pick against.
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import type { Id } from './_generated/dataModel';
import { resolveLocations } from './lib/locations';

const modules = import.meta.glob('./**/*.*s');

async function seedServer(
  t: ReturnType<typeof convexTest>,
  o: {
    slug: string;
    backend?: 'remnawave' | 'outline';
    location?: string;
    locationLabel?: string;
    isActive?: boolean;
    healthAgeMs?: number | null;
    priority?: number;
  },
): Promise<Id<'backendServers'>> {
  return t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: o.backend ?? 'remnawave',
      name: o.slug,
      slug: o.slug,
      location: o.location,
      locationLabel: o.locationLabel,
      config:
        (o.backend ?? 'remnawave') === 'remnawave'
          ? { type: 'remnawave', baseUrl: `https://${o.slug}.example`, apiToken: 'tok' }
          : {
              type: 'outline',
              apiUrl: `https://${o.slug}.example/secret`,
              websocketEnabled: false,
            },
      isActive: o.isActive ?? true,
      priority: o.priority ?? 0,
      keyCount: 0,
      lastHealthOkAt: o.healthAgeMs === null ? undefined : Date.now() - (o.healthAgeMs ?? 0),
      updatedAt: Date.now(),
    }),
  );
}

describe('resolveLocations', () => {
  test('projects only located, active Remnawave instances (code + label + online)', async () => {
    const t = convexTest(schema, modules);
    await seedServer(t, { slug: 'mci', location: 'MCI', locationLabel: 'Kansas City, MO' });
    await seedServer(t, { slug: 'no-loc' }); // no location → not offered
    await seedServer(t, { slug: 'off', location: 'OFF', isActive: false }); // inactive → skipped
    await seedServer(t, { slug: 'ol', backend: 'outline', location: 'OL' }); // wrong backend
    const locations = await t.run((ctx) => resolveLocations(ctx.db));
    expect(locations).toEqual([{ code: 'MCI', label: 'Kansas City, MO', online: true }]);
  });

  test("dedupes by code; online is the OR across the code's instances", async () => {
    const t = convexTest(schema, modules);
    await seedServer(t, { slug: 'mci-1', location: 'MCI', healthAgeMs: 45 * 60_000 }); // stale
    await seedServer(t, { slug: 'mci-2', location: 'MCI', locationLabel: 'Kansas City, MO' });
    const locations = await t.run((ctx) => resolveLocations(ctx.db));
    expect(locations).toHaveLength(1);
    expect(locations[0]).toMatchObject({ code: 'MCI', online: true });
  });

  test('label falls back to the code; never-probed or stale instances read offline', async () => {
    const t = convexTest(schema, modules);
    await seedServer(t, { slug: 'ams', location: 'AMS', healthAgeMs: null }); // never probed
    const locations = await t.run((ctx) => resolveLocations(ctx.db));
    expect(locations).toEqual([{ code: 'AMS', label: 'AMS', online: false }]);
  });
});
