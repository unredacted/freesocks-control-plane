/**
 * The fast suite's test runner (vitest.config.ts `test.runner`): the scheduled
 * work a test leaves behind ends with that test.
 *
 * convex-test runs scheduled functions on timers, outside the test that
 * scheduled them, while `fetch` and fake timers are one global per test. A job
 * one test leaves pending otherwise runs during a later test: against THAT
 * test's fake backend (a node it creates there makes the next enroll refused as
 * unowned), against the real network once the stub is gone, or as a write into
 * a store nobody reads any more. So when a test body is over, before its
 * afterEach hooks restore timers and globals, every convex-test instance it
 * used (convexTest.tracked.ts) is ended: pending jobs are cancelled, running
 * ones finish, and whatever they schedule meanwhile is cancelled too. While
 * that runs, `fetch` is refused, so a finished test's work reaches neither a
 * fake backend nor the network. It runs again after the afterEach hooks and
 * after each suite, for work those hooks scheduled.
 *
 * The instances a test used end as one group. Every instance's pending jobs are
 * cancelled before any running job is waited for, and one instance that cannot
 * end does not keep the others from ending: the drain finishes them all, then
 * fails the test with what went wrong.
 *
 * Fake timers: a running job may await a faked timer (a sleep between probe
 * attempts). If the test still has fake timers installed, the drain moves the
 * faked clock one timer at a time, cancelling every instance's new jobs before
 * each step (the clock is the whole test's), so that job finishes inside its
 * own test instead of whenever a later test moves the clock. If the test
 * restored real timers itself while such a job was waiting, the timer is gone
 * and the job can never resume: the drain fails the test after SETTLE_LIMIT_MS
 * (a test may stub a shorter one under SETTLE_LIMIT_KEY) rather than hang.
 * Finish the scheduled work (`t.finishAllScheduledFunctions(vi.runAllTimers)`)
 * before `vi.useRealTimers()` in such a test.
 *
 * Tests run one at a time within a file (no `test.concurrent`): the drain ends
 * every instance used since the last drain.
 *
 * A job further out than Node can arm a timer (2^31-1 ms, about 24.8 days) is
 * not armed under real timers: Node would run it after 1 ms instead (with a
 * TimeoutOverflowWarning), so a `runAfter(30 * DAY)` like the referral reward
 * vesting ran at once, inside whichever test was running. It stays pending
 * until its test ends and is cancelled. A test that wants such a job to run
 * moves a faked clock; vi.useFakeTimers() replaces setTimeout and
 * vi.useRealTimers() restores this one. Production Convex is unaffected.
 *
 * Test-only: the two-dot name keeps it out of the Convex bundle.
 */
import { TestRunner, vi, type RunnerTestSuite } from 'vitest';
import { takeLiveConvexTests, type ScheduledWorkOf } from './convexTest.tracked';

/** Rounds of cancel-then-wait before work that keeps scheduling more is reported. */
const MAX_ROUNDS = 100;
/** How long running jobs may take to finish once their test is over. */
const SETTLE_LIMIT_MS = 30_000;
/** `vi.stubGlobal(Symbol.for(...), ms)` sets a shorter limit for one test. */
const SETTLE_LIMIT_KEY = Symbol.for('fcp.test.scheduledWorkSettleLimitMs');
/** The longest delay Node arms as asked. */
const MAX_TIMER_DELAY_MS = 2 ** 31 - 1;
const WITHIN_RANGE = Symbol.for('fcp.test.setTimeoutWithinRange');

// Real clock and timer, taken before any test fakes them.
const realNow = Date.now;
const realSetTimeout = globalThis.setTimeout;

/** The test is over: what it left running reaches neither a fake backend nor the network. */
const refused: typeof fetch = async () => {
  throw new Error('the test that scheduled this has ended');
};

export default class ScheduledWorkRunner extends TestRunner {
  /** The test environment has installed its globals; no hook or test has run yet. */
  override async onBeforeRunSuite(suite: RunnerTestSuite): Promise<void> {
    leaveOverlongTimersUnarmed();
    await super.onBeforeRunSuite(suite);
  }

  /** The test body is over; its fake timers and fetch stub are still in place. */
  async onTaskFinished(): Promise<void> {
    await endScheduledWork();
  }

  /** The afterEach hooks are over: whatever they scheduled. */
  async onAfterRetryTask(): Promise<void> {
    await endScheduledWork();
  }

  /** A suite's afterAll hooks are over: whatever beforeAll or afterAll scheduled. */
  override async onAfterRunSuite(suite: RunnerTestSuite): Promise<void> {
    await endScheduledWork();
    await super.onAfterRunSuite(suite);
  }
}

/** The environment's setTimeout, except that a delay Node cannot arm never fires. */
function leaveOverlongTimersUnarmed(): void {
  const armed = globalThis.setTimeout as typeof setTimeout & { [WITHIN_RANGE]?: true };
  if (armed[WITHIN_RANGE]) return;
  const withinRange = (handler: TimerHandler, delay?: number, ...args: unknown[]) =>
    Number(delay) > MAX_TIMER_DELAY_MS
      ? // A handle clearTimeout accepts; the handler is never called.
        armed(() => {}, 0)
      : armed(handler, delay, ...args);
  globalThis.setTimeout = Object.assign(withinRange as typeof setTimeout, {
    [WITHIN_RANGE]: true as const,
  });
}

/** End the scheduled work of every convex-test instance used since the last call. */
export async function endScheduledWork(): Promise<void> {
  const ending = takeLiveConvexTests();
  if (ending.length === 0) return;
  const before = globalThis.fetch;
  globalThis.fetch = refused;
  try {
    const errors = await endTogether(ending);
    if (errors.length === 1) throw errors[0];
    if (errors.length > 1) {
      throw new AggregateError(errors, `${errors.length} failures ending scheduled work`);
    }
  } finally {
    globalThis.fetch = before;
  }
}

/**
 * Each round cancels what has not started on every instance, then waits for
 * what is running; a running job may schedule more, which the next round
 * cancels. Done when nothing is running anywhere. Returns what went wrong.
 */
async function endTogether(ending: ScheduledWorkOf[]): Promise<unknown[]> {
  const errors: unknown[] = [];
  let open = ending;
  for (let round = 0; open.length > 0; round++) {
    if (round === MAX_ROUNDS) {
      errors.push(new Error(`scheduled functions still running after ${MAX_ROUNDS} rounds`));
      break;
    }
    const running: ScheduledWorkOf[] = [];
    for (const work of open) {
      try {
        if ((await cancelPending(work)) > 0) running.push(work);
      } catch (error) {
        errors.push(error);
      }
    }
    open = await settle(running, errors);
  }
  return errors;
}

/** Cancels every pending job; returns how many are running. */
async function cancelPending(work: ScheduledWorkOf): Promise<number> {
  return await work.run(async (ctx) => {
    let running = 0;
    for (const f of await ctx.db.system.query('_scheduled_functions').collect()) {
      if (f.state.kind === 'pending') await ctx.scheduler.cancel(f._id);
      if (f.state.kind === 'inProgress') running++;
    }
    return running;
  });
}

/**
 * Wait for the running jobs, moving a faked clock for them if the test left one
 * installed; returns the instances that settled. One still running at the
 * limit is reported and left behind: it is waiting for a timer that is gone.
 */
async function settle(running: ScheduledWorkOf[], errors: unknown[]): Promise<ScheduledWorkOf[]> {
  const settled: ScheduledWorkOf[] = [];
  let waiting = running.length;
  for (const work of running) {
    work
      .finishInProgressScheduledFunctions()
      .then(
        () => settled.push(work),
        (error: unknown) => errors.push(error),
      )
      .finally(() => waiting--);
  }
  const limitMs =
    (globalThis as { [SETTLE_LIMIT_KEY]?: number })[SETTLE_LIMIT_KEY] ?? SETTLE_LIMIT_MS;
  const deadline = realNow() + limitMs;
  while (waiting > 0) {
    if (vi.isFakeTimers()) {
      // The faked clock is the whole test's: no instance's pending job may start when it moves.
      await Promise.allSettled(running.map(cancelPending));
      vi.advanceTimersToNextTimer();
    }
    await new Promise((resolve) => realSetTimeout(resolve, 1));
    if (waiting > 0 && realNow() > deadline) {
      errors.push(
        new Error(
          `scheduled functions still running ${limitMs} ms after their test ended; ` +
            'one awaiting a fake timer that vi.useRealTimers() dropped never resumes, so ' +
            "finish the test's scheduled work before restoring real timers",
        ),
      );
      break;
    }
  }
  return [...settled];
}
