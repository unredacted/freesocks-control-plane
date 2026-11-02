import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { DETAIL_KEYS_MAX, detailKey, readRefusals, REFUSALS_CRITICAL_AT } from './deliveryRefusals';
import { writeStateJson } from './lib/appStateJson';

const modules = import.meta.glob('./**/*.*s');

describe('the refusal counter', () => {
  test('keys name a fleet node and a known app family, nothing else', () => {
    expect(detailKey('empty_pool', 'node-a', 'mihomo')).toBe('empty_pool|node-a|mihomo');
    expect(detailKey('empty_pool', null, 'curl')).toBe('empty_pool|-|other');
    expect(detailKey('node_gated', 'a|b', undefined)).toBe('node_gated|ab|other');
  });

  test('the breakdown is bounded per bucket; the reasons still count every refusal', async () => {
    const t = convexTest(schema, modules);
    for (let i = 0; i < DETAIL_KEYS_MAX + 20; i++)
      await t.mutation(internal.deliveryRefusals.record, {
        reason: 'empty_pool',
        node: `node-${i}`,
        family: 'v2rayng',
      });
    await t.mutation(internal.deliveryRefusals.record, {
      reason: 'empty_pool',
      node: 'node-0',
      family: 'v2rayng',
    });
    const r = await t.run((ctx) => readRefusals(ctx.db, Date.now()));
    expect(r.total).toBe(DETAIL_KEYS_MAX + 21);
    expect(r.byReason).toEqual({ empty_pool: DETAIL_KEYS_MAX + 21 });
    expect(r.top[0]).toEqual({ reason: 'empty_pool', node: 'node-0', family: 'v2rayng', count: 2 });
    expect(r.top).toHaveLength(3);
  });

  test('an app the backend serves nothing to is shown, never what grades the item', async () => {
    const t = convexTest(schema, modules);
    const record = (reason: string) =>
      t.mutation(internal.deliveryRefusals.record, { reason, node: 'node-a', family: 'mihomo' });
    for (let i = 0; i < REFUSALS_CRITICAL_AT + 5; i++) await record('no_entries');
    const item = async () =>
      (await t.query(internal.edgeOperator.attention, {})).items.find(
        (i) => i.kind === 'delivery_refusals',
      )!;
    expect(await item()).toMatchObject({
      severity: 'info',
      code: 'no_entries',
      facts: {
        total: REFUSALS_CRITICAL_AT + 5,
        byReason: { no_entries: REFUSALS_CRITICAL_AT + 5 },
      },
    });
    // One refusal the fleet could fix names the item and grades it on its own count.
    await record('empty_pool');
    expect(await item()).toMatchObject({ severity: 'warning', code: 'empty_pool' });
    for (let i = 1; i < REFUSALS_CRITICAL_AT; i++) await record('empty_pool');
    expect(await item()).toMatchObject({ severity: 'critical', code: 'empty_pool' });
  });

  test('a bucket written before the breakdown is read as reasons only', async () => {
    const t = convexTest(schema, modules);
    const now = Date.now();
    await t.run((ctx) =>
      writeStateJson(ctx.db, 'edge:refusals:0', {
        buckets: [{ t: now - (now % 600_000), counts: { node_gated: 3 } }],
      }),
    );
    const r = await t.run((ctx) => readRefusals(ctx.db, now));
    expect(r).toMatchObject({ total: 3, byReason: { node_gated: 3 }, top: [] });
  });
});
