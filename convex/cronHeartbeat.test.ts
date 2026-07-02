/// <reference types="vite/client" />
import { readFileSync } from 'node:fs';
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { CRON_META } from './cronHeartbeat';
import { AdminStatusSummary } from '../src/shared/contracts/admin';

const modules = import.meta.glob('./**/*.*s');

const DAY = 86_400_000;

describe('cronHeartbeat', () => {
  test('stamp upserts one row per cron name and increments runCount', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.cronHeartbeat.stamp, { name: 'grace-sweep' });
    await t.mutation(internal.cronHeartbeat.stamp, { name: 'grace-sweep' });
    await t.mutation(internal.cronHeartbeat.stamp, { name: 'session-sweep' });

    await t.run(async (ctx) => {
      const rows = await ctx.db.query('cronHeartbeats').collect();
      expect(rows).toHaveLength(2); // one row per distinct name, not per stamp
      const grace = rows.find((r) => r.name === 'grace-sweep')!;
      expect(grace.runCount).toBe(2);
      expect(typeof grace.lastRunAt).toBe('number');
    });
  });

  test('statusSummary joins heartbeats to cadences: ok / stale / pending', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      // Fresh 10-min cron → ok. Well within its ~25-min stale window.
      await ctx.db.insert('cronHeartbeats', {
        name: 'backend-healthcheck',
        lastRunAt: Date.now(),
        runCount: 7,
      });
      // A daily cron last seen 3 days ago → past its ~1.5-day window → stale.
      await ctx.db.insert('cronHeartbeats', {
        name: 'session-sweep',
        lastRunAt: Date.now() - 3 * DAY,
        runCount: 4,
      });
      // Every other cron has no row → pending.
    });

    const s = await t.query(internal.adminApi.statusSummary, {});
    AdminStatusSummary.parse(s); // shape stays in contract agreement

    expect(s.crons).toHaveLength(CRON_META.length);
    const byName = new Map(s.crons.map((c) => [c.name, c]));

    const ok = byName.get('backend-healthcheck')!;
    expect(ok.state).toBe('ok');
    expect(ok.runCount).toBe(7);
    expect(ok.lastRunAt).not.toBeNull();

    expect(byName.get('session-sweep')!.state).toBe('stale');

    const pending = byName.get('grace-sweep')!;
    expect(pending.state).toBe('pending');
    expect(pending.lastRunAt).toBeNull();
    expect(pending.ageSeconds).toBeNull();
    expect(pending.runCount).toBe(0);

    expect(s.cronsStale).toBe(1); // only session-sweep is overdue
  });

  // The registry powers the dashboard freshness surface; if a cron is added to
  // crons.ts without a CRON_META entry it would silently escape observability.
  // This locks the two lists together (the reason the class of bug can't recur).
  test('CRON_META matches every job registered in crons.ts', () => {
    const src = readFileSync(new URL('./crons.ts', import.meta.url), 'utf8');
    const registered = [...src.matchAll(/crons\.(?:interval|daily)\(\s*'([a-z-]+)'/g)].map(
      (m) => m[1],
    );
    expect(new Set(registered).size).toBe(registered.length); // no dup names in crons.ts
    expect(registered.slice().sort()).toEqual(CRON_META.map((c) => c.name).sort());
  });
});
