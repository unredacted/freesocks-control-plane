import { describe, expect, test } from 'vitest';
import { resolveEffectiveModeId, shouldConfirmSwitch } from './connectionMode';

describe('resolveEffectiveModeId', () => {
  test('server-backed prefers the persisted connectionModeId', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: 'privacy-reality',
        pref: 'freedom-ws',
        suggested: 'freedom-ws',
        fallback: 'freedom-ws',
      }),
    ).toBe('privacy-reality');
  });

  test('server-backed falls through connectionModeId → pref → suggested → fallback', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: 'freedom-ws',
        suggested: 'privacy-reality',
        fallback: 'freedom-ws',
      }),
    ).toBe('freedom-ws');
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: null,
        suggested: 'privacy-reality',
        fallback: 'freedom-ws',
      }),
    ).toBe('privacy-reality');
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: null,
        pref: null,
        suggested: null,
        fallback: 'freedom-ws',
      }),
    ).toBe('freedom-ws');
  });

  test('non-server-backed IGNORES connectionModeId (local pref wins)', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        connectionModeId: 'privacy-reality',
        pref: 'freedom-ws',
        suggested: 'privacy-reality',
        fallback: 'freedom-ws',
      }),
    ).toBe('freedom-ws');
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        connectionModeId: 'privacy-reality',
        pref: null,
        suggested: 'privacy-reality',
        fallback: 'freedom-ws',
      }),
    ).toBe('privacy-reality');
  });
});

describe('shouldConfirmSwitch', () => {
  const base = {
    serverBacked: true,
    disabled: false,
    busy: false,
    selected: 'freedom-ws',
    target: 'privacy-reality',
  };

  test('true when server-backed, enabled, idle, and changing', () => {
    expect(shouldConfirmSwitch(base)).toBe(true);
  });

  test('false when not server-backed (a local-only preference)', () => {
    expect(shouldConfirmSwitch({ ...base, serverBacked: false })).toBe(false);
  });

  test('false when picking the current mode', () => {
    expect(shouldConfirmSwitch({ ...base, target: 'freedom-ws' })).toBe(false);
  });

  test('false while busy or disabled', () => {
    expect(shouldConfirmSwitch({ ...base, busy: true })).toBe(false);
    expect(shouldConfirmSwitch({ ...base, disabled: true })).toBe(false);
  });
});

describe('resolveEffectiveModeId: catalog validation', () => {
  const KNOWN = ['freedom-ws', 'freedom-reality', 'privacy-reality'];

  test('a stale pre-rename pref fails the catalog check and falls through', () => {
    // The client legacy-id map is GONE: the server migrates stored rows at
    // deploy and serves canonical ids, so the only place a legacy id survives
    // is old localStorage — which simply fails knownIds and falls to the
    // suggestion/default instead of resolving to a dead id.
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        pref: 'privacy',
        suggested: null,
        fallback: 'freedom-ws',
        knownIds: KNOWN,
      }),
    ).toBe('freedom-ws');
  });

  test('the server value passes through VERBATIM (server serves canonical ids)', () => {
    // Deliberately unvalidated: an admin-disabled mode is omitted from the
    // catalog but is still where the member is; the picker synthesizes it.
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: 'some-disabled-mode',
        pref: null,
        suggested: null,
        fallback: 'freedom-ws',
        knownIds: KNOWN,
      }),
    ).toBe('some-disabled-mode');
  });

  test('drops a genuinely unknown pref / suggestion', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        pref: 'no-such-mode',
        suggested: 'also-bogus',
        fallback: 'freedom-ws',
        knownIds: KNOWN,
      }),
    ).toBe('freedom-ws');
  });

  test('keeps the SERVER-persisted mode even when absent from the catalog', () => {
    // An admin-disabled mode is omitted from publicConfig but is still where the
    // member actually is - dropping it would strand them on a mode they cannot
    // see or move off. The picker synthesizes an entry for it instead.
    expect(
      resolveEffectiveModeId({
        serverBacked: true,
        connectionModeId: 'freedom-reality',
        pref: null,
        suggested: null,
        fallback: 'freedom-ws',
        knownIds: ['freedom-ws'], // freedom-reality was just disabled
      }),
    ).toBe('freedom-reality');
  });

  test('without knownIds nothing is validated (back-compat)', () => {
    expect(
      resolveEffectiveModeId({
        serverBacked: false,
        pref: 'anything',
        suggested: null,
        fallback: 'freedom-ws',
      }),
    ).toBe('anything');
  });
});
