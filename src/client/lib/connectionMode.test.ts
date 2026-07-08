import { describe, expect, test } from 'vitest';
import { resolveEffectiveModeId, shouldConfirmSwitch } from './connectionMode';

describe('resolveEffectiveModeId', () => {
  test('server-backed prefers the persisted connectionModeId', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: 'privacy',
        pref: 'evade',
        suggested: 'evade',
        fallback: 'evade',
      }),
    ).toBe('privacy');
  });

  test('server-backed falls through connectionModeId → pref → suggested → fallback', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: 'evade',
        suggested: 'privacy',
        fallback: 'evade',
      }),
    ).toBe('evade');
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: null,
        suggested: 'privacy',
        fallback: 'evade',
      }),
    ).toBe('privacy');
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: null,
        suggested: null,
        fallback: 'evade',
      }),
    ).toBe('evade');
  });

  test('non-server-backed IGNORES connectionModeId (local pref wins)', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        connectionModeId: 'privacy',
        pref: 'evade',
        suggested: 'privacy',
        fallback: 'evade',
      }),
    ).toBe('evade');
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        connectionModeId: 'privacy',
        pref: null,
        suggested: 'privacy',
        fallback: 'evade',
      }),
    ).toBe('privacy');
  });
});

describe('shouldConfirmSwitch', () => {
  const base = {
    serverBacked: true,
    disabled: false,
    busy: false,
    selected: 'evade',
    target: 'privacy',
  };

  test('true when server-backed, enabled, idle, and changing', () => {
    expect(shouldConfirmSwitch(base)).toBe(true);
  });

  test('false when not server-backed (a local-only preference)', () => {
    expect(shouldConfirmSwitch({ ...base, serverBacked: false })).toBe(false);
  });

  test('false when picking the current mode', () => {
    expect(shouldConfirmSwitch({ ...base, target: 'evade' })).toBe(false);
  });

  test('false while busy or disabled', () => {
    expect(shouldConfirmSwitch({ ...base, busy: true })).toBe(false);
    expect(shouldConfirmSwitch({ ...base, disabled: true })).toBe(false);
  });
});
