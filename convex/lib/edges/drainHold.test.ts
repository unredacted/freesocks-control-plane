import { describe, expect, test } from 'vitest';
import {
  DRAIN_HOLD_EVERY_MS,
  drainHoldDecision,
  heldCandidate,
  keyMayHoldEdge,
  type DrainHoldEdge,
} from './drainHold';

const H = 3_600_000;
const DAY = 24 * H;
const T0 = 1_800_000_000_000; // drain start
const cfg = { enabled: true, maxDays: 30, releaseAtKeys: 10 };

const edge = (o: Partial<DrainHoldEdge> = {}): DrainHoldEdge => ({
  layer: 'l7',
  managed: true,
  publishedAt: T0 - 5 * DAY,
  statusChangedAt: T0,
  drainUntil: T0 + 2 * H,
  ...o,
});

const decide = (
  e: DrainHoldEdge,
  now: number,
  o: Partial<Parameters<typeof drainHoldDecision>[0]> = {},
) =>
  drainHoldDecision({
    edge: e,
    cfg,
    now,
    nodeOrigin: true,
    originDeleting: false,
    listenerLive: true,
    accountFullOldest: false,
    ...o,
  });

describe('drainHoldDecision', () => {
  test('a drained L7 front is held and counted, the hard maximum from the drain start', () => {
    const d = decide(edge(), T0 + 3 * H);
    expect(d).toEqual({ hold: true, recount: true, record: { since: T0, until: T0 + 30 * DAY } });
  });

  test('only managed L7 fronts that were handed out, with a real drain, are held', () => {
    const now = T0 + 3 * H;
    expect(decide(edge({ layer: 'l4' }), now)).toEqual({ hold: false, reason: 'not_l7' });
    expect(decide(edge({ layer: undefined }), now)).toEqual({ hold: false, reason: 'not_l7' });
    expect(decide(edge({ managed: false }), now)).toEqual({ hold: false, reason: 'not_managed' });
    expect(decide(edge({ publishedAt: undefined }), now)).toEqual({
      hold: false,
      reason: 'never_published',
    });
    // "Delete now" from an operator or an origin delete: a drain of no length.
    expect(decide(edge({ drainUntil: T0 }), now)).toEqual({ hold: false, reason: 'forced' });
  });

  test('the switch, a zero maximum, no node, a deleting origin, a gone listener let go', () => {
    const now = T0 + 3 * H;
    expect(
      drainHoldDecision({
        edge: edge(),
        cfg: { ...cfg, enabled: false },
        now,
        nodeOrigin: true,
        originDeleting: false,
        listenerLive: true,
        accountFullOldest: false,
      }),
    ).toEqual({ hold: false, reason: 'off' });
    expect(
      drainHoldDecision({
        edge: edge(),
        cfg: { ...cfg, maxDays: 0 },
        now,
        nodeOrigin: true,
        originDeleting: false,
        listenerLive: true,
        accountFullOldest: false,
      }),
    ).toEqual({ hold: false, reason: 'off' });
    expect(decide(edge(), now, { nodeOrigin: false })).toEqual({ hold: false, reason: 'no_node' });
    expect(decide(edge(), now, { originDeleting: true })).toEqual({
      hold: false,
      reason: 'origin_deleting',
    });
    expect(decide(edge(), now, { listenerLive: false })).toEqual({
      hold: false,
      reason: 'listener_gone',
    });
  });

  test('the hard maximum and a full account let go whatever the count says', () => {
    const held = edge({ drainHold: { since: T0, until: T0 + 30 * DAY, at: T0, holders: 9000 } });
    expect(decide(held, T0 + 30 * DAY)).toEqual({ hold: false, reason: 'max_age' });
    expect(decide(held, T0 + DAY, { accountFullOldest: true })).toEqual({
      hold: false,
      reason: 'account_full',
    });
  });

  test('a stored maximum stands when the setting changes later', () => {
    const held = edge({ drainHold: { since: T0, until: T0 + 2 * DAY } });
    expect(decide(held, T0 + 3 * DAY)).toEqual({ hold: false, reason: 'max_age' });
  });

  test('released once few enough keys may hold it', () => {
    const at = T0 + 4 * H;
    const few = edge({ drainHold: { since: T0, until: T0 + 30 * DAY, at, holders: 10 } });
    expect(decide(few, at + 1)).toEqual({ hold: false, reason: 'refreshed' });
    const many = edge({ drainHold: { since: T0, until: T0 + 30 * DAY, at, holders: 11 } });
    expect(decide(many, at + 1)).toMatchObject({ hold: true, recount: false });
  });

  test('counted again hourly, and never while a count is already asked for', () => {
    const at = T0 + 4 * H;
    const rec = { since: T0, until: T0 + 30 * DAY, at, holders: 500 };
    expect(decide(edge({ drainHold: rec }), at + DRAIN_HOLD_EVERY_MS)).toMatchObject({
      hold: true,
      recount: true,
    });
    const asked = { ...rec, requestedAt: at + DRAIN_HOLD_EVERY_MS };
    expect(decide(edge({ drainHold: asked }), at + DRAIN_HOLD_EVERY_MS + 1)).toMatchObject({
      hold: true,
      recount: false,
    });
    // Asked but never answered (the count failed): asked again an hour later.
    expect(decide(edge({ drainHold: asked }), at + 2 * DRAIN_HOLD_EVERY_MS)).toMatchObject({
      hold: true,
      recount: true,
    });
  });

  test('a record of an earlier drain is ignored', () => {
    const old = { since: T0 - 10 * DAY, until: T0 - 5 * DAY, at: T0 - 6 * DAY, holders: 0 };
    expect(decide(edge({ drainHold: old }), T0 + 3 * H)).toEqual({
      hold: true,
      recount: true,
      record: { since: T0, until: T0 + 30 * DAY },
    });
  });
});

describe('keyMayHoldEdge', () => {
  const w = { from: T0 - 5 * DAY, to: T0 };
  test('a key last rendered inside the published window may hold it', () => {
    expect(keyMayHoldEdge({ lastRenderedAt: T0 - DAY }, w)).toBe(true);
    expect(keyMayHoldEdge({ lastRender: { at: T0 - 5 * DAY } }, w)).toBe(true);
  });
  test('rendered before it was published, after the drain began, or never: it does not', () => {
    expect(keyMayHoldEdge({ lastRenderedAt: T0 - 6 * DAY }, w)).toBe(false);
    expect(keyMayHoldEdge({ lastRenderedAt: T0 }, w)).toBe(false);
    expect(keyMayHoldEdge({ lastRenderedAt: T0 - DAY, lastRender: { at: T0 + H } }, w)).toBe(false);
    expect(keyMayHoldEdge({}, w)).toBe(false);
  });
});

describe('heldCandidate', () => {
  test('a managed L7 edge draining past its drain', () => {
    const e = { layer: 'l7', managed: true, status: 'draining', drainUntil: T0 };
    expect(heldCandidate(e, T0)).toBe(true);
    expect(heldCandidate(e, T0 - 1)).toBe(false);
    expect(heldCandidate({ ...e, layer: 'l4' }, T0)).toBe(false);
    expect(heldCandidate({ ...e, status: 'destroying' }, T0)).toBe(false);
    expect(heldCandidate({ ...e, managed: false }, T0)).toBe(false);
  });
});
