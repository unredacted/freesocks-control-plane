import { describe, expect, test } from 'vitest';
import { findLegacyField, LEGACY } from './legacyFields';

describe('findLegacyField', () => {
  test('finds an obsolete key at the top level, alone or next to its new name', () => {
    expect(findLegacyField({ inboundUuid: 'x' }, LEGACY.addressCreate)).toBe('inboundUuid');
    expect(findLegacyField({ inboundUuid: 'x', transportUuid: 'x' }, LEGACY.addressCreate)).toBe(
      'inboundUuid',
    );
    expect(findLegacyField({ transportUuid: 'x' }, LEGACY.addressCreate)).toBeNull();
  });

  test('walks nested objects and every element of nested arrays', () => {
    expect(
      findLegacyField(
        { ops: [{ transportTag: 'a' }, { inboundTag: 'b', transportTag: 'b' }] },
        LEGACY.profileApply,
      ),
    ).toBe('ops[1].inboundTag');
    expect(findLegacyField({ binding: { inboundUuid: 'u' } }, LEGACY.directConfirm)).toBe(
      'binding.inboundUuid',
    );
    expect(findLegacyField({ binding: { transportUuid: 'u' } }, LEGACY.directConfirm)).toBeNull();
  });

  test('a key that is present with an undefined-like value still counts; non-objects never match', () => {
    expect(findLegacyField({ inboundTag: null }, LEGACY.sniBind)).toBe('inboundTag');
    expect(findLegacyField(null, LEGACY.sniBind)).toBeNull();
    expect(findLegacyField([{ inboundTag: 'x' }], LEGACY.sniBind)).toBeNull();
    expect(findLegacyField({ ops: 'not-a-list' }, LEGACY.profilePreview)).toBeNull();
  });
});
