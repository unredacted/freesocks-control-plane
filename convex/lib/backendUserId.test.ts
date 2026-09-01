import { describe, expect, test } from 'vitest';
import {
  isNumericBackendUserId,
  scopedServerId,
  toProviderUserId,
  toStoredBackendUserId,
} from './backendUserId';

const SERVER = 'j57abc123def456ghi789jkl';
const UUID = '550e8400-e29b-41d4-a716-446655440000';

describe('backend user id scoping', () => {
  test('a per-panel numeric id is stored scoped to its instance', () => {
    expect(isNumericBackendUserId('2')).toBe(true);
    expect(toStoredBackendUserId(SERVER, '2')).toBe(`${SERVER}:2`);
    expect(toProviderUserId(`${SERVER}:2`)).toBe('2');
  });

  test('a UUID (Remnawave 2.x) is stored verbatim and round-trips untouched', () => {
    expect(isNumericBackendUserId(UUID)).toBe(false);
    expect(toStoredBackendUserId(SERVER, UUID)).toBe(UUID);
    expect(toProviderUserId(UUID)).toBe(UUID);
  });

  test('non-numeric, non-uuid ids (mock, outline key names) are left alone', () => {
    for (const id of ['mock-1a2b3c4d', 'k2', 'abc:def']) {
      expect(toStoredBackendUserId(SERVER, id)).toBe(id);
      expect(toProviderUserId(id)).toBe(id);
    }
  });

  test('a scoped id names its instance; an unscoped one names none', () => {
    expect(scopedServerId(`${SERVER}:2`)).toBe(SERVER);
    expect(scopedServerId(UUID)).toBeNull();
    expect(scopedServerId('mock-1a2b3c4d')).toBeNull();
  });

  test('two instances minting the same numeric id store DISTINCT keys', () => {
    expect(toStoredBackendUserId('serverA', '7')).not.toBe(toStoredBackendUserId('serverB', '7'));
  });
});
