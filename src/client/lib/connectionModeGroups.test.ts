import { describe, expect, test } from 'vitest';
import {
  availableOn,
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
    availableBackends: ['remnawave'],
    available: true,
    ...over,
  };
}

const FAMILIES: PickerFamily[] = [
  { id: 'freedom', label: null, description: null, audience: null, iconId: 'zap' },
  { id: 'privacy', label: null, description: null, audience: null, iconId: 'shield-check' },
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

  test('a family with ONE child still groups, so its transport stays visible', () => {
    // Privacy Mode has a single transport today. It must still come back as a
    // family with a child - the component renders that child as a static chip
    // rather than hiding it, and turns the row interactive once a second
    // transport is added, with no code change.
    const groups = groupModesByFamily([WS, PRIVACY], FAMILIES);
    expect(groups.find((g) => g.family?.id === 'privacy')!.children).toEqual([PRIVACY]);
  });

  test('a SECOND privacy transport slots in with no special-casing', () => {
    // The forward-looking case: adding a transport is a catalog entry plus copy.
    const privacyAlt = mode({ id: 'privacy-alt', family: 'privacy' });
    const groups = groupModesByFamily([WS, PRIVACY, privacyAlt], FAMILIES);
    const privacyGroup = groups.find((g) => g.family?.id === 'privacy')!;
    expect(privacyGroup.children.map((m) => m.id)).toEqual(['privacy-reality', 'privacy-alt']);
    // The declared family default still wins the parent-card click, so adding a
    // sibling cannot silently change what picking "Privacy Mode" selects.
    expect(familyTargetMode(privacyGroup.children)!.id).toBe('privacy-reality');
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

  test('synthesizes from the currentMode PROJECTION: real deliveryStyle/label/family', () => {
    // The member is on freedom-reality when an admin turns it off: publicConfig
    // stops shipping it, but the account view still projects it — the synth
    // entry must carry the REAL rawConfig delivery style (the old blind 'url'
    // guess flipped a privacy-posture member to URL-first delivery UI).
    const out = withCurrentMode([WS, PRIVACY], 'freedom-reality', {
      id: 'freedom-reality',
      deliveryStyle: 'rawConfig',
      label: null,
      description: null,
      family: { id: 'freedom', label: null },
      available: false,
    });
    const synthetic = out.find((m) => m.id === 'freedom-reality')!;
    expect(synthetic.deliveryStyle).toBe('rawConfig');
    expect(synthetic.family).toBe('freedom');
    expect(synthetic.available).toBe(false); // not a switch TARGET…
    // …and with its family known it renders INSIDE the family group.
    const groups = groupModesByFamily(out, FAMILIES);
    const freedom = groups.find((g) => g.family?.id === 'freedom')!;
    expect(freedom.children.map((m) => m.id)).toContain('freedom-reality');
  });

  test('deploy-skew fallback (no projection): the old blind synth, standalone group', () => {
    const out = withCurrentMode([WS, PRIVACY], 'freedom-reality');
    const synthetic = out.find((m) => m.id === 'freedom-reality')!;
    expect(synthetic.available).toBe(false);
    expect(synthetic.deliveryStyle).toBe('url');
    const groups = groupModesByFamily(out, FAMILIES);
    expect(groups.some((g) => g.family === null && g.children[0]!.id === 'freedom-reality')).toBe(
      true,
    );
  });

  test('a projection for a DIFFERENT id is ignored (stale account cache)', () => {
    const out = withCurrentMode([WS], 'gone-mode', {
      id: 'other-mode',
      deliveryStyle: 'rawConfig',
      label: 'Other',
      description: null,
      family: null,
      available: false,
    });
    const synthetic = out.find((m) => m.id === 'gone-mode')!;
    expect(synthetic.deliveryStyle).toBe('url');
    expect(synthetic.label).toBeNull();
  });

  test('an empty selection is a no-op', () => {
    const modes = [WS];
    expect(withCurrentMode(modes, '')).toBe(modes);
  });
});

describe('availableOn', () => {
  test('joins per-backend availability; falls back to `available` without a backend', () => {
    const m = mode({ id: 'x', availableBackends: ['remnawave'], available: true });
    expect(availableOn(m, 'remnawave')).toBe(true);
    expect(availableOn(m, 'outline')).toBe(false);
    expect(availableOn(m, null)).toBe(true);
  });

  test('deploy skew: empty availableBackends falls back to the any-backend bool', () => {
    const m = mode({ id: 'x', availableBackends: [], available: true });
    expect(availableOn(m, 'outline')).toBe(true);
    const n = mode({ id: 'y', availableBackends: [], available: false });
    expect(availableOn(n, 'remnawave')).toBe(false);
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
