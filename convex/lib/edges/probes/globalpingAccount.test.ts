import { describe, expect, test } from 'vitest';
import {
  globalpingFits,
  readingFits,
  readingFromHeaders,
  readingFromLimits,
  recordingClient,
  type GlobalpingLike,
  type TimedReading,
} from './globalping';
import {
  accountView,
  mergeReading,
  namesShare,
  probeShare,
  utcDay,
  type GlobalpingAccount,
} from './globalpingAccount';

const T0 = Date.UTC(2026, 10, 5, 10, 0, 0);
const MIN = 60_000;
const DAY = 86_400_000;

describe("Globalping's own answers", () => {
  test('a limits answer, with and without a token', () => {
    expect(
      readingFromLimits({
        rateLimit: {
          measurements: { create: { type: 'user', limit: 500, remaining: 146, reset: 1380 } },
        },
        credits: { remaining: 59812 },
      }),
    ).toEqual({ type: 'user', limit: 500, remaining: 146, resetSec: 1380, credits: 59812 });
    // No window open yet (nothing spent): reset 0; no credits without a token.
    expect(
      readingFromLimits({
        rateLimit: {
          measurements: { create: { type: 'ip', limit: 250, remaining: 250, reset: 0 } },
        },
      }),
    ).toEqual({ type: 'ip', limit: 250, remaining: 250, resetSec: 0 });
    for (const bad of [null, 'x', {}, { rateLimit: { measurements: { create: { limit: 'a' } } } }])
      expect(readingFromLimits(bad)).toBeNull();
  });

  test("a create's headers", () => {
    const h = new Headers({
      'x-ratelimit-limit': '500',
      'x-ratelimit-remaining': '0',
      'x-ratelimit-reset': '600',
      'x-credits-consumed': '24',
      'x-credits-remaining': '59788',
    });
    expect(readingFromHeaders(h)).toEqual({
      limit: 500,
      remaining: 0,
      resetSec: 600,
      credits: 59788,
      creditsConsumed: 24,
    });
    // Within the free tests: no credit headers, and a zero spend is no spend.
    expect(
      readingFromHeaders(
        new Headers({
          'x-ratelimit-limit': '250',
          'x-ratelimit-remaining': '249',
          'x-ratelimit-reset': '3600',
          'x-credits-consumed': '0',
        }),
      ),
    ).toEqual({ limit: 250, remaining: 249, resetSec: 3600 });
    expect(readingFromHeaders(new Headers())).toBeNull();
    expect(readingFromHeaders(undefined)).toBeNull();
  });

  test('what fits: the free tests left plus the credits', () => {
    expect(readingFits({ limit: 500, remaining: 10, resetSec: 1, credits: 5 }, 15)).toBe(true);
    expect(readingFits({ limit: 500, remaining: 10, resetSec: 1, credits: 4 }, 15)).toBe(false);
    expect(readingFits({ limit: 250, remaining: 30, resetSec: 1 }, 31)).toBe(false);
  });

  test('the recording client hands over every answer, refused creates included', async () => {
    const sink: TimedReading[] = [];
    let n = 0;
    const inner: GlobalpingLike = {
      async createMeasurement() {
        n++;
        return n === 1
          ? {
              ok: true,
              data: { id: 'm1' },
              response: new Response(null, {
                status: 202,
                headers: { 'x-ratelimit-limit': '500', 'x-ratelimit-remaining': '476' },
              }),
            }
          : {
              ok: false,
              data: { error: { type: 'insufficient_credits' } },
              response: new Response(null, {
                status: 429,
                headers: { 'x-ratelimit-limit': '500', 'x-ratelimit-remaining': '0' },
              }),
            };
      },
      async getMeasurement(id) {
        return { ok: true, data: { id, status: 'finished' } };
      },
      async getLimits() {
        return {
          ok: true,
          data: {
            rateLimit: {
              measurements: { create: { type: 'user', limit: 500, remaining: 500, reset: 0 } },
            },
            credits: { remaining: 100 },
          },
        };
      },
    };
    let clock = T0;
    const client = recordingClient(inner, sink, () => clock++);
    expect(await globalpingFits(client, 24)).toBe(true);
    expect((await client.createMeasurement({})).ok).toBe(true);
    expect((await client.createMeasurement({})).ok).toBe(false);
    expect((await client.getMeasurement('m1')).ok).toBe(true);
    expect(sink.map((s) => [s.at - T0, s.reading.remaining])).toEqual([
      [0, 500],
      [1, 476],
      [2, 0],
    ]);
    // A client without a limits call stays without one (no preflight).
    const bare = recordingClient({ ...inner, getLimits: undefined }, []);
    expect(bare.getLimits).toBeUndefined();
  });
});

describe('the account row', () => {
  test('the newest reading sets the window; an older one landing late does not', () => {
    let a = mergeReading(null, { type: 'user', limit: 500, remaining: 300, resetSec: 1200 }, T0);
    expect(a).toMatchObject({ at: T0, type: 'user', limit: 500, remaining: 300 });
    expect(a.resetAt).toBe(T0 + 1_200_000);
    // A create's headers carry no type: the stored one stays.
    a = mergeReading(a, { limit: 500, remaining: 276, resetSec: 1100 }, T0 + 100_000);
    expect(a).toMatchObject({ type: 'user', remaining: 276 });
    const late = mergeReading(a, { limit: 500, remaining: 290, resetSec: 1150 }, T0 + 50_000);
    expect(late).toMatchObject({ at: T0 + 100_000, remaining: 276 });
  });

  test('credits follow the newest reading that has them; spending adds up per UTC day', () => {
    let a = mergeReading(
      null,
      { limit: 500, remaining: 0, resetSec: 600, credits: 1000, creditsConsumed: 24 },
      T0,
    );
    a = mergeReading(a, { limit: 500, remaining: 0, resetSec: 500, creditsConsumed: 8 }, T0 + MIN);
    // An out-of-order reading still counts its spend, but not its older balance.
    a = mergeReading(
      a,
      { limit: 500, remaining: 0, resetSec: 590, credits: 1500, creditsConsumed: 3 },
      T0 - MIN,
    );
    expect(a.credits).toBe(1000);
    expect(a.spent).toEqual([{ day: utcDay(T0), credits: 35 }]);
    // The days roll; at most eight are kept, newest first.
    for (let d = 1; d <= 9; d++)
      a = mergeReading(
        a,
        { limit: 500, remaining: 0, resetSec: 1, creditsConsumed: d },
        T0 + d * DAY,
      );
    expect(a.spent).toHaveLength(8);
    expect(a.spent[0]).toEqual({ day: utcDay(T0 + 9 * DAY), credits: 9 });
  });

  test('the view: a window that has reset shows the whole allowance; the runway uses the last full day', () => {
    const base: GlobalpingAccount = {
      at: T0,
      type: 'user',
      limit: 500,
      remaining: 12,
      resetAt: T0 + 10 * MIN,
      credits: 9000,
      creditsAt: T0,
      spent: [
        { day: utcDay(T0), credits: 200 },
        { day: utcDay(T0 - DAY), credits: 3000 },
      ],
    };
    expect(accountView(base, T0 + MIN)).toMatchObject({
      remaining: 12,
      resetAt: T0 + 10 * MIN,
      credits: 9000,
      spentToday: 200,
      spentYesterday: 3000,
      runwayDays: 3,
    });
    expect(accountView(base, T0 + 11 * MIN)).toMatchObject({ remaining: 500, resetAt: null });
    // Nothing spent in the window it was read in: no reset to show.
    expect(accountView({ ...base, resetAt: T0 }, T0 + MIN)).toMatchObject({
      remaining: 12,
      resetAt: null,
    });
    // No spend on the last full day: no runway, whatever today holds.
    expect(accountView({ ...base, spent: [{ day: utcDay(T0), credits: 5 }] }, T0).runwayDays).toBe(
      null,
    );
    expect(accountView({ ...base, credits: undefined }, T0)).toMatchObject({
      credits: null,
      runwayDays: null,
    });
  });
});

describe("the name checks' share", () => {
  test('their budgets times the vantages each, only while they are on', () => {
    const on = {
      vantage: { on: true, hourlyBudget: 12, perCountryLimit: 3 },
      huntTiming: { on: true, perHour: 6 },
    };
    expect(namesShare(on)).toBe(36 + 12);
    expect(namesShare({ ...on, huntTiming: { on: false, perHour: 6 } })).toBe(36);
    expect(namesShare({ ...on, vantage: { ...on.vantage, on: false } })).toBe(12);
    expect(probeShare(500, 48)).toBe(452);
    expect(probeShare(40, 48)).toBe(0);
    expect(probeShare(400, 0)).toBe(400);
  });
});
