/**
 * Test helper: end the scheduled work a test leaves behind before the next
 * test starts. convex-test runs scheduled functions on timers, outside the test
 * that scheduled them, while `fetch` is one global: a reconcile one test left
 * pending otherwise runs during the next test, against THAT test's fake backend
 * (a node it creates there makes the next enroll refused as unowned), or
 * against the real network once the stub is gone. Not a test file itself.
 *
 *   const scheduled = scheduledWork();
 *   afterEach(async () => {
 *     await scheduled.end();
 *     vi.unstubAllGlobals();
 *   });
 *   const t = scheduled.track(convexTest(schema, modules));
 */
import type { TestConvex } from 'convex-test';
import type schema from '../../../schema';

type T = TestConvex<typeof schema>;

/** Rounds of cancel-then-wait before work that keeps scheduling more is reported. */
const MAX_ROUNDS = 100;

/** The test is over: what it left running reaches neither a fake backend nor the network. */
const refused: typeof fetch = async () => {
  throw new Error('the test that scheduled this has ended');
};

/** The convex-test instances a test made, ended together in `afterEach`. */
export function scheduledWork() {
  const live = new Set<T>();
  return {
    track<X extends T>(t: X): X {
      live.add(t);
      return t;
    },
    async end() {
      const ending = [...live];
      live.clear();
      const before = globalThis.fetch;
      globalThis.fetch = refused;
      try {
        for (const t of ending) await endScheduled(t);
      } finally {
        globalThis.fetch = before;
      }
    },
  };
}

/**
 * Cancel what has not started and wait for what is running; a running function
 * may schedule more, which the next round cancels. Done when nothing is pending
 * or in progress.
 */
export async function endScheduled(t: T): Promise<void> {
  for (let round = 0; round < MAX_ROUNDS; round++) {
    const open = await t.run(async (ctx) => {
      let n = 0;
      for (const f of await ctx.db.system.query('_scheduled_functions').collect()) {
        if (f.state.kind === 'pending') await ctx.scheduler.cancel(f._id);
        if (f.state.kind === 'pending' || f.state.kind === 'inProgress') n++;
      }
      return n;
    });
    if (open === 0) return;
    await t.finishInProgressScheduledFunctions();
  }
  throw new Error(`scheduled functions still open after ${MAX_ROUNDS} rounds`);
}
