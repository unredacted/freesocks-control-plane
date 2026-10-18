/**
 * A node's provider set as the admin reads and edits it, and what the
 * requirement counts as published. Fixtures only (RFC 5737, `*.example`).
 */
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { adoptL4Edge, seedEdgeFixture } from './lib/edges/testing/fixtures';
import { setStateOf } from './lib/edges/setState';

const modules = import.meta.glob('./**/*.*s');

describe('provider set view and state', () => {
  test('without a recorded set the picks are the ones its published edges imply, and are not offered again', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
    await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.21',
      publish: true,
      accountId: fx.accountId,
    });
    const view = await t.query(internal.edgeProviderSets.view, { relayId: fx.relayId });
    expect(view!.hasSet).toBe(false);
    expect(view!.picks).toHaveLength(1);
    expect(view!.available.some((a) => a.locationId === view!.picks[0]!.locationId)).toBe(false);
  });

  test('an edge of a disabled transport neither covers it nor holds a pick', async () => {
    const t = convexTest(schema, modules);
    const fx = await seedEdgeFixture(t, { qualified: true, provider: 'upcloud' });
    const e = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
      ipv4: '198.51.100.22',
      publish: true,
      accountId: fx.accountId,
    });
    const publishedIds = () =>
      t.run(async (c) =>
        (await setStateOf(c.db, (await c.db.get(fx.relayId))!)).published.map((p) => p.edgeId),
      );
    expect(await publishedIds()).toEqual([e.edgeId as Id<'edges'>]);
    await t.run((c) => c.db.patch(fx.listenerId, { enabled: false }));
    expect(await publishedIds()).toEqual([]);
  });
});
