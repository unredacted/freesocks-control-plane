import { describe, expect, test } from 'vitest';
import {
  ADMIN_ONLINE_WINDOW_MS,
  CUT_CLAIM_STALE_MS,
  MAX_CUTS,
  REVOCATION_DEFAULTS,
  cutDue,
  decide,
  onlineRecently,
  revocationConfig,
  type Probe,
} from './revocationWatch';

const MIN = 60_000;
const cfg = revocationConfig({ ...REVOCATION_DEFAULTS, 'revocation.watch': true });
const t0 = 1_800_000_000_000;
const watch = (over: Partial<Parameters<typeof decide>[0]> = {}) => ({
  revokedAt: t0,
  settleUntil: t0 + 3 * MIN,
  cuts: 0,
  ...over,
});
const disabled = (usedBytes: number): Probe => ({
  gone: false,
  status: 'disabled',
  usedBytes,
  onlineAt: null,
});

describe('revocationConfig', () => {
  test('defaults: off, 30 min between restarts, admin cut on, 60 min drain, 14 days', () => {
    const c = revocationConfig({});
    expect(c.enabled).toBe(false);
    expect(c.cutMinIntervalMs).toBe(30 * MIN);
    expect(c.adminDisableCutsNow).toBe(true);
    expect(c.drainMs).toBe(60 * MIN);
    expect(c.watchMs).toBe(14 * 86_400_000);
    expect(c.leakBytes).toBe(262_144);
  });

  test('a stored value of the wrong type keeps the default; numbers are clamped', () => {
    const c = revocationConfig({
      'revocation.watch': 'yes',
      'revocation.cutMinIntervalMinutes': 1,
      'revocation.drainMinutes': 'soon',
      'revocation.watchDays': 1000,
      'revocation.adminDisableCutsNow': 0,
    });
    expect(c.enabled).toBe(false);
    expect(c.cutMinIntervalMs).toBe(5 * MIN);
    expect(c.drainMs).toBe(60 * MIN);
    expect(c.watchMs).toBe(90 * 86_400_000);
    expect(c.adminDisableCutsNow).toBe(true);
  });
});

describe('decide', () => {
  test('a key the backend no longer knows ends the watch', () => {
    expect(decide(watch(), { gone: true }, t0 + 10 * MIN, cfg)).toEqual({
      kind: 'close',
      reason: 'gone',
    });
  });

  test('a key enabled again ends the watch', () => {
    const p: Probe = { gone: false, status: 'active', usedBytes: 0, onlineAt: null };
    expect(decide(watch(), p, t0 + 10 * MIN, cfg)).toEqual({ kind: 'close', reason: 'enabled' });
  });

  test('the window ending ends the watch', () => {
    expect(decide(watch(), disabled(0), t0 + cfg.watchMs + 1, cfg)).toEqual({
      kind: 'close',
      reason: 'expired',
    });
  });

  test('nothing is judged while the stats settle', () => {
    expect(decide(watch(), disabled(10 ** 9), t0 + MIN, cfg)).toEqual({ kind: 'wait' });
  });

  test('the first read after the settle time is the baseline', () => {
    expect(decide(watch(), disabled(5000), t0 + 4 * MIN, cfg)).toEqual({
      kind: 'baseline',
      bytes: 5000,
    });
  });

  test('growth below leakBytes is kept; at or past it the key leaked', () => {
    const w = watch({ baselineBytes: 1000 });
    expect(decide(w, disabled(1000 + cfg.leakBytes - 1), t0 + 9 * MIN, cfg).kind).toBe('keep');
    expect(decide(w, disabled(1000 + cfg.leakBytes), t0 + 9 * MIN, cfg)).toEqual({
      kind: 'leaked',
      bytes: 1000 + cfg.leakBytes,
      moved: cfg.leakBytes,
    });
  });

  test('a counter that went backwards (a periodic reset) re-baselines', () => {
    expect(decide(watch({ baselineBytes: 9000 }), disabled(10), t0 + 9 * MIN, cfg)).toEqual({
      kind: 'baseline',
      bytes: 10,
    });
  });

  test(`still moving after ${MAX_CUTS} cuts is stuck, not cut again`, () => {
    const w = watch({ baselineBytes: 0, cuts: MAX_CUTS });
    expect(decide(w, disabled(10 ** 9), t0 + 9 * MIN, cfg).kind).toBe('stuck');
  });
});

describe('cutDue', () => {
  const now = t0 + 100 * MIN;
  test('nothing pending is never due', () => {
    expect(cutDue({}, now, cfg)).toBe(false);
  });
  test('a node restarted within the interval waits; past it, it is due', () => {
    expect(cutDue({ pendingSince: now, lastCutAt: now - 10 * MIN }, now, cfg)).toBe(false);
    expect(cutDue({ pendingSince: now, lastCutAt: now - 30 * MIN }, now, cfg)).toBe(true);
  });
  test('an admin cut skips the interval', () => {
    expect(
      cutDue({ pendingSince: now, lastCutAt: now - MIN, bypassInterval: true }, now, cfg),
    ).toBe(true);
  });
  test('a failed cut waits for its retry time', () => {
    expect(cutDue({ pendingSince: now, retryAfter: now + MIN }, now, cfg)).toBe(false);
    expect(cutDue({ pendingSince: now, retryAfter: now }, now, cfg)).toBe(true);
  });
  test('a fresh claim holds the cut; a stale one frees it', () => {
    expect(cutDue({ pendingSince: now, claimAt: now - MIN }, now, cfg)).toBe(false);
    expect(cutDue({ pendingSince: now, claimAt: now - CUT_CLAIM_STALE_MS }, now, cfg)).toBe(true);
  });
});

describe('onlineRecently', () => {
  test('within the admin window only', () => {
    expect(onlineRecently(null, t0)).toBe(false);
    expect(onlineRecently('not a date', t0)).toBe(false);
    expect(onlineRecently(new Date(t0 - MIN).toISOString(), t0)).toBe(true);
    expect(onlineRecently(new Date(t0 - ADMIN_ONLINE_WINDOW_MS - 1).toISOString(), t0)).toBe(false);
  });
});
