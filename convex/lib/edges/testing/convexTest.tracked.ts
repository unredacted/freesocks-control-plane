/**
 * convex-test as the fast suite sees it: vitest.config.ts resolves every
 * `import { convexTest } from 'convex-test'` here. Each instance is tracked so
 * the test runner (scheduledWork.runner.ts) can end the scheduled work a test
 * leaves behind before the next test starts.
 *
 * An instance is live from its creation and again whenever a test calls one of
 * its methods (also through `withIdentity`), so an instance shared across tests
 * is ended after each test that used it. The registry lives on `globalThis`,
 * so it stays one registry however many times the runner and the test files
 * load this module.
 *
 * Test-only: the two-dot name keeps it out of the Convex bundle.
 */
import { convexTest as untracked } from 'convex-test/dist/index.js';

type Instance = ReturnType<typeof untracked>;

/** What ending an instance's scheduled work needs, unwrapped so ending it does not make it live again. */
export type ScheduledWorkOf = Pick<Instance, 'run' | 'finishInProgressScheduledFunctions'>;

const LIVE = Symbol.for('fcp.test.liveConvexTests');
const registry = globalThis as typeof globalThis & { [LIVE]?: Map<Instance, ScheduledWorkOf> };
const live = (registry[LIVE] ??= new Map());

export const convexTest = ((...args: Parameters<typeof untracked>) => {
  const t = untracked(...args);
  const work: ScheduledWorkOf = {
    run: t.run,
    finishInProgressScheduledFunctions: t.finishInProgressScheduledFunctions,
  };
  const touch = () => live.set(t, work);
  touch();
  return touching(t, touch);
}) as typeof untracked;

/** The instances used since the last call, which forgets them. */
export function takeLiveConvexTests(): ScheduledWorkOf[] {
  const taken = [...live.values()];
  live.clear();
  return taken;
}

function touching<X extends object>(accessor: X, touch: () => void): X {
  const methods = accessor as Record<string, unknown>;
  for (const [key, method] of Object.entries(methods)) {
    if (typeof method !== 'function') continue;
    methods[key] = (...args: unknown[]) => {
      touch();
      const out = method(...args);
      return key === 'withIdentity' ? touching(out, touch) : out;
    };
  }
  return accessor;
}
