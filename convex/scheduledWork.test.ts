/// <reference types="vite/client" />
/**
 * The fast suite's runner (convex/lib/edges/testing/scheduledWork.runner.ts):
 * a test's scheduled work ends with that test. Each case leaves work behind and
 * the next one looks at it, so the cases keep their order.
 */
import { convexTest } from 'convex-test';
import {
  internalActionGeneric,
  internalMutationGeneric,
  makeFunctionReference,
} from 'convex/server';
import { v } from 'convex/values';
import { afterEach, describe, expect, onTestFailed, test, vi } from 'vitest';
import schema from './schema';

const DAY = 86_400_000;

// Two functions only these tests schedule, beside the real modules.
const modules = {
  ...import.meta.glob('./**/*.*s'),
  './scheduledWorkProbe.ts': async () => ({
    sleep: internalActionGeneric({
      args: { ms: v.number() },
      handler: async (_ctx, { ms }) => {
        await new Promise((resolve) => setTimeout(resolve, ms));
      },
    }),
    noop: internalMutationGeneric({ args: {}, handler: async () => {} }),
  }),
};
const sleep = makeFunctionReference<'action'>('scheduledWorkProbe:sleep');
const noop = makeFunctionReference<'mutation'>('scheduledWorkProbe:noop');

type T = ReturnType<typeof convexTest>;
const leftBehind: Record<'pending' | 'sleeping' | 'sleepingA' | 'dueSoonerB' | 'besideStuck', T> =
  {} as never;
let stuckFailure = '';

async function jobStates(t: T) {
  return await t.run(async (ctx) =>
    (await ctx.db.system.query('_scheduled_functions').collect()).map((f) => f.state.kind),
  );
}

/** Starts a job that sleeps `ms` on the (faked) clock and returns once it is running. */
async function leaveSleeping(t: T, ms: number) {
  await t.run(async (ctx) => {
    await ctx.scheduler.runAfter(0, sleep, { ms });
  });
  for (let i = 0; i < 50 && !(await jobStates(t)).includes('inProgress'); i++) {
    await vi.advanceTimersByTimeAsync(1);
  }
  expect(await jobStates(t)).toEqual(['inProgress']);
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('scheduled work ends with its test', { shuffle: false }, () => {
  test('a test leaves a job pending', async () => {
    const t = convexTest(schema, modules);
    leftBehind.pending = t;
    await t.run(async (ctx) => {
      await ctx.scheduler.runAfter(100, noop, {});
    });
    expect(await jobStates(t)).toEqual(['pending']);
  });

  test('the next test never sees it run: it was cancelled when its test ended', async () => {
    await new Promise((resolve) => setTimeout(resolve, 250));
    expect(await jobStates(leftBehind.pending)).toEqual(['canceled']);
  });

  test('a test leaves a job sleeping on a fake timer', async () => {
    vi.useFakeTimers();
    leftBehind.sleeping = convexTest(schema, modules);
    await leaveSleeping(leftBehind.sleeping, 60_000);
  });

  test('that job finished inside its own test, before afterEach restored real timers', async () => {
    expect(await jobStates(leftBehind.sleeping)).toEqual(['success']);
  });

  test('one instance leaves a job sleeping on the fake clock, another a job due before it wakes', async () => {
    vi.useFakeTimers();
    leftBehind.sleepingA = convexTest(schema, modules);
    leftBehind.dueSoonerB = convexTest(schema, modules);
    await leaveSleeping(leftBehind.sleepingA, 1_000);
    await leftBehind.dueSoonerB.run(async (ctx) => {
      await ctx.scheduler.runAfter(100, noop, {});
    });
  });

  test('moving the clock for the sleeper never started the other job: every instance was cancelled first', async () => {
    expect(await jobStates(leftBehind.sleepingA)).toEqual(['success']);
    expect(await jobStates(leftBehind.dueSoonerB)).toEqual(['canceled']);
  });

  test.fails(
    'a job stuck on a fake timer the test dropped fails its test at the limit',
    async () => {
      vi.stubGlobal(Symbol.for('fcp.test.scheduledWorkSettleLimitMs'), 200);
      onTestFailed(({ task }) => {
        stuckFailure = (task.result?.errors ?? []).map((e) => e.message).join('\n');
      });
      vi.useFakeTimers();
      await leaveSleeping(convexTest(schema, modules), 60_000);
      vi.useRealTimers();
      leftBehind.besideStuck = convexTest(schema, modules);
      await leftBehind.besideStuck.run(async (ctx) => {
        await ctx.scheduler.runAfter(120_000, noop, {});
      });
    },
  );

  test('the other instance was still ended, and the failure names the dropped timer', async () => {
    expect(await jobStates(leftBehind.besideStuck)).toEqual(['canceled']);
    expect(stuckFailure).toMatch(/still running 200 ms after their test ended/);
  });

  test('under real timers a job 30 days out stays pending: Node would run it after 1 ms', async () => {
    const t = convexTest(schema, modules);
    await t.run(async (ctx) => {
      await ctx.scheduler.runAfter(30 * DAY, noop, {});
    });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(await jobStates(t)).toEqual(['pending']);
  });
});
