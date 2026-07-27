import { describe, expect, test } from 'vitest';
import {
  familyTargetMode,
  groupModesByFamily,
  withCurrentMode,
  type PickerFamily,
  type PickerMode,
} from './connectionModeGroups';

function mode(over: Partial<PickerMode> & Pick<PickerMode, 'id'>): PickerMode {
  return {
    family: 'freedom',
    deliveryStyle: 'url',
    label: null,
    description: null,
    isDefault: false,
    isFamilyDefault: false,
    available: true,
    ...over,
  };
}

const FAMILIES: PickerFamily[] = [
  { id: 'freedom', label: null, description: null },
  { id: 'privacy', label: null, description: null },
];

const WS = mode({ id: 'freedom-ws', isDefault: true, isFamilyDefault: true });
const REALITY = mode({ id: 'freedom-reality', deliveryStyle: 'rawConfig' });
const PRIVACY = mode({
  id: 'privacy-reality',
  family: 'privacy',
  deliveryStyle: 'rawConfig',
  isFamilyDefault: true,
});

describe('groupModesByFamily', () => {
  test('groups leaves under their family, in catalog order', () => {
    const groups = groupModesByFamily([PRIVACY, WS, REALITY], FAMILIES);
    expect(groups.map((g) => g.family?.id)).toEqual(['freedom', 'privacy']);
    expect(groups[0]!.children.map((m) => m.id)).toEqual(['freedom-ws', 'freedom-reality']);
    expect(groups[1]!.children.map((m) => m.id)).toEqual(['privacy-reality']);
  });

  test('a family with ONE child still groups (the caller collapses the sub-choice)', () => {
    // Privacy Mode has a single transport today, so it must render as a plain
    // card - the component keys that off children.length, not a special case.
    const groups = groupModesByFamily([WS, PRIVACY], FAMILIES);
    expect(groups.find((g) => g.family?.id === 'privacy')!.children).toHaveLength(1);
  });

  test('drops a family whose children are all gone (e.g. admin-disabled)', () => {
    const groups = groupModesByFamily([PRIVACY], FAMILIES);
    expect(groups.map((g) => g.family?.id)).toEqual(['privacy']);
  });

  test('an orphan leaf gets its own standalone group so it is never unreachable', () => {
    const orphan = mode({ id: 'weird-mode', family: 'gone' });
    const groups = groupModesByFamily([WS, orphan], FAMILIES);
    expect(groups.map((g) => g.family?.id ?? null)).toEqual(['freedom', null]);
    expect(groups[1]!.children.map((m) => m.id)).toEqual(['weird-mode']);
  });

  test('no families at all: every leaf becomes its own group', () => {
    const groups = groupModesByFamily([WS, PRIVACY], []);
    expect(groups).toHaveLength(2);
    expect(groups.every((g) => g.family === null)).toBe(true);
  });
});

describe('withCurrentMode', () => {
  test('passes the list through when the selection is present', () => {
    const modes = [WS, PRIVACY];
    expect(withCurrentMode(modes, 'freedom-ws')).toBe(modes);
  });

  test('synthesizes an entry for a selection the catalog omits (admin-disabled)', () => {
    // The member is on freedom-reality when an admin turns it off: publicConfig
    // stops shipping it, but they must still see it and be able to move away.
    const out = withCurrentMode([WS, PRIVACY], 'freedom-reality');
    expect(out.map((m) => m.id)).toContain('freedom-reality');
    const synthetic = out.find((m) => m.id === 'freedom-reality')!;
    expect(synthetic.available).toBe(false); // not a switch TARGET…
    // …but it lands in a standalone group, so it is visible and selectable-off.
    const groups = groupModesByFamily(out, FAMILIES);
    expect(groups.some((g) => g.children.some((m) => m.id === 'freedom-reality'))).toBe(true);
  });

  test('an empty selection is a no-op', () => {
    const modes = [WS];
    expect(withCurrentMode(modes, '')).toBe(modes);
  });
});

describe('familyTargetMode', () => {
  test('prefers the family default when it is available', () => {
    expect(familyTargetMode([REALITY, WS])!.id).toBe('freedom-ws');
  });

  test('falls back to the first AVAILABLE child when the default is not', () => {
    const unavailableDefault = { ...WS, available: false };
    expect(familyTargetMode([unavailableDefault, REALITY])!.id).toBe('freedom-reality');
  });

  test('falls back to the first child when nothing is available (click is never a no-op)', () => {
    const a = { ...WS, available: false };
    const b = { ...REALITY, available: false };
    expect(familyTargetMode([a, b])!.id).toBe('freedom-ws');
  });

  test('empty family yields undefined', () => {
    expect(familyTargetMode([])).toBeUndefined();
  });
});
