import { describe, expect, test } from 'vitest';
import {
  clockWords,
  drainLength,
  endNowWords,
  replaceDrainMinutes,
  retiringWords,
} from './drainWords';

// Local-time fixtures: the words are about the admin's own clock.
const NOW = new Date(2026, 9, 17, 23, 18);
const iso = (d: Date) => d.toISOString();

describe('drain words', () => {
  test('a drain length reads in hours and minutes', () => {
    expect(drainLength(1440)).toBe('24 h');
    expect(drainLength(4320)).toBe('3 d');
    expect(drainLength(60)).toBe('1 h');
    expect(drainLength(90)).toBe('1 h 30 min');
    expect(drainLength(45)).toBe('45 min');
  });

  test('a clock time says the day when it is not today', () => {
    expect(clockWords(new Date(2026, 9, 17, 23, 45), NOW)).toBe('23:45');
    expect(clockWords(new Date(2026, 9, 18, 8, 30), NOW)).toBe('08:30 tomorrow');
    expect(clockWords(new Date(2026, 9, 19, 8, 30), NOW)).toBe('08:30 on 19 Oct');
  });

  test('a retiring address says what it means, when it is deleted and that billing stops', () => {
    const edge = {
      status: 'draining',
      publication: 'draining',
      drainUntil: iso(new Date(2026, 9, 18, 8, 30)),
      managed: true,
      burnedAt: null,
    };
    expect(retiringWords(edge, NOW.getTime())).toEqual({
      word: 'Retiring',
      line: 'Members are moved off it. Deleted in 9 h 12 min (around 08:30 tomorrow), then billing stops.',
      left: '9 h 12 min (around 08:30 tomorrow)',
      canDelete: true,
      canKeep: true,
    });
    // Past its drain: the next 5-minute check deletes it.
    expect(
      retiringWords({ ...edge, drainUntil: iso(new Date(2026, 9, 17, 23, 0)) }, NOW.getTime()).line,
    ).toBe(
      "Members are moved off it. Deleted at FCP's next check (every 5 minutes), then billing stops.",
    );
    // A burned address never comes back as a spare.
    const burned = retiringWords({ ...edge, burnedAt: iso(NOW) }, NOW.getTime());
    expect(burned.line).toMatch(/^Replaced as blocked: members are moved off it\./);
    expect(burned.canKeep).toBe(false);
    expect(burned.canDelete).toBe(true);
    // FCP did not create an observe-only address: nothing is billed through it.
    expect(retiringWords({ ...edge, managed: false }, NOW.getTime()).line).toMatch(
      /stops tracking it in 9 h 12 min .* delete it at your provider\.$/,
    );
  });

  test('Delete now deletes what FCP created; an observe-only address is only forgotten', () => {
    const edge = {
      status: 'draining',
      publication: 'draining',
      drainUntil: iso(new Date(2026, 9, 18, 8, 30)),
      managed: true,
      burnedAt: null,
    };
    const managed = endNowWords(edge, '198.51.100.44', NOW.getTime());
    expect(managed.label).toBe('Delete now');
    expect(managed.body).toMatch(/lose it now/);
    expect(managed.body).toMatch(/would be deleted in 9 h 12 min \(around 08:30 tomorrow\)/);
    expect(managed.body).toMatch(/at the provider .* billing stops\.$/);
    const observed = endNowWords({ ...edge, managed: false }, '198.51.100.44', NOW.getTime());
    expect(observed.label).toBe('Stop tracking');
    expect(observed.title).toBe('Stop tracking 198.51.100.44 now?');
    // Never claims a provider delete FCP does not make.
    expect(observed.body).not.toMatch(/FCP deletes|billing stops/);
    expect(observed.body).toMatch(/keeps billing for it, until you delete it there/);
    expect(observed.done).toMatch(/Delete it at your provider\.$/);
  });

  test('an address being deleted offers no action', () => {
    expect(
      retiringWords(
        {
          status: 'destroying',
          publication: 'unpublished',
          drainUntil: null,
          managed: true,
          burnedAt: null,
        },
        NOW.getTime(),
      ),
    ).toEqual({
      word: 'Being deleted',
      line: 'FCP removes it at the provider; billing stops once it is gone.',
      left: null,
      canDelete: false,
      canKeep: false,
    });
  });

  test('a replace drains for the origin drain, a burn for the burned drain', () => {
    expect(replaceDrainMinutes('rotate', 1440, 60)).toBe(1440);
    expect(replaceDrainMinutes('burn', 1440, 60)).toBe(60);
    expect(replaceDrainMinutes('burn', 1440, null)).toBeNull();
  });

  test('no em-dashes in any of it', () => {
    const lines = [
      retiringWords(
        {
          status: 'draining',
          publication: 'draining',
          drainUntil: null,
          managed: true,
          burnedAt: null,
        },
        NOW.getTime(),
      ).line,
    ];
    for (const l of lines) expect(l).not.toMatch(/—/);
  });
});
