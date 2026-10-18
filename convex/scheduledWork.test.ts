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
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';

const DAY = 86_400_000;

// Two functions only these tests schedule, beside the real modules.
const modules = {
  ...import.meta.glob('./**/*.*s'),
  './scheduledWorkProbe.ts': async () => ({
    sleep: internalActionGeneric({
      args: {},
      handler: async () => {
        await new Promise((resolve) => setTimeout(resolve, 60_000));
      },
    }),
    noop: internalMutationGeneric({ args: {}, handler: async () => {} }),
  }),
};
const sleep = makeFunctionReference<'action'>('scheduledWorkProbe:sleep');
const noop = makeFunctionReference<'mutation'>('scheduledWorkProbe:noop');

type T = ReturnType<typeof convexTest>;
const leftBehind: { pending?: T; sleeping?: T } = {};

async function jobStates(t: T) {
  return await t.run(async (ctx) =>
    (await ctx.db.system.query('_scheduled_functions').collect()).map((f) => f.state.kind),
  );
}

afterEach(() => {
  vi.useRealTimers();
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
    expect(await jobStates(leftBehind.pending!)).toEqual(['canceled']);
  });

  test('a test leaves a job sleeping on a fake timer', async () => {
    vi.useFakeTimers();
    const t = convexTest(schema, modules);
    leftBehind.sleeping = t;
    await t.run(async (ctx) => {
      await ctx.scheduler.runAfter(0, sleep, {});
    });
    for (let i = 0; i < 50 && !(await jobStates(t)).includes('inProgress'); i++) {
      await vi.advanceTimersByTimeAsync(1);
    }
    expect(await jobStates(t)).toEqual(['inProgress']);
  });

  test('that job finished inside its own test, before afterEach restored real timers', async () => {
    expect(await jobStates(leftBehind.sleeping!)).toEqual(['success']);
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
