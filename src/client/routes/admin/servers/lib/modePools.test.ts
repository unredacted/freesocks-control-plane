import { describe, expect, test } from 'vitest';
import {
  canonicalUuid,
  indexModeGroups,
  parseGroupList,
  poolSpread,
  readPoolLines,
  UUID_RE,
} from './modePools';

const U1 = '11111111-1111-4111-8111-111111111111';
const U2 = '22222222-2222-4222-8222-222222222222';
const U3 = '33333333-3333-4333-8333-333333333333';

const trees = [
  {
    instance: { slug: 'panel-a', name: 'Panel A' },
    modeGroups: [
      { groupUuid: U1, name: 'freedom-a', membersCount: 4 },
      { groupUuid: U2, name: 'privacy-a', membersCount: null },
    ],
  },
  {
    instance: { slug: 'panel-b', name: 'Panel B' },
    modeGroups: [{ groupUuid: U2.toUpperCase(), name: 'privacy-b', membersCount: 1 }],
  },
];

describe('parseGroupList', () => {
  test('one per line or comma, trimmed and deduped', () => {
    expect(parseGroupList(` ${U1}\n${U2}, ${U1}\n\n`)).toEqual([U1, U2]);
    expect(parseGroupList('')).toEqual([]);
    expect(UUID_RE.test(U1)).toBe(true);
    expect(UUID_RE.test('nope')).toBe(false);
  });
});

describe('indexModeGroups', () => {
  test('finds a group by uuid in any case, on every backend that has it', () => {
    const index = indexModeGroups(trees);
    expect(index.get(U1)?.map((g) => [g.name, g.backendSlug])).toEqual([['freedom-a', 'panel-a']]);
    expect(index.get(U2)?.map((g) => g.backendSlug)).toEqual(['panel-a', 'panel-b']);
    expect(index.get(U3)).toBeUndefined();
  });
});

describe('readPoolLines', () => {
  test('names each typed uuid, or says why it names nothing', () => {
    const lines = readPoolLines(`${U1.toUpperCase()}\n${U3}\nnot-a-uuid`, indexModeGroups(trees));
    expect(lines.map((l) => l.kind)).toEqual(['group', 'unknown', 'invalid']);
    const first = lines[0]!;
    expect(first.kind === 'group' && first.groups[0]?.name).toBe('freedom-a');
  });
});

describe('canonicalUuid', () => {
  const index = indexModeGroups(trees);
  test('saves a pasted uuid the way the backend spells it', () => {
    expect(canonicalUuid(U1.toUpperCase(), index)).toBe(U1);
    expect(canonicalUuid(U1, index)).toBe(U1);
    // Spelled two ways on two backends: an exact match is kept as typed.
    expect(canonicalUuid(U2.toUpperCase(), index)).toBe(U2.toUpperCase());
    expect(canonicalUuid(U2, index)).toBe(U2);
    // No backend reports it: kept as typed.
    expect(canonicalUuid(U3.toUpperCase(), index)).toBe(U3.toUpperCase());
  });
  test('the preview says what will be saved', () => {
    const [line] = readPoolLines(U1.toUpperCase(), index);
    expect(line?.kind === 'group' && line.saved).toBe(U1);
  });
});

describe('poolSpread', () => {
  const checks = [
    {
      slug: 'panel-a',
      name: 'Panel A',
      modes: [
        { modeSlug: 'freedom', modeGroups: 3, unknownHere: 1, withoutTransports: ['empty-a'] },
        { modeSlug: 'privacy', modeGroups: 0, unknownHere: 0, withoutTransports: [] },
      ],
    },
    {
      slug: 'panel-b',
      name: 'Panel B',
      modes: [{ modeSlug: 'freedom', modeGroups: 3, unknownHere: 2, withoutTransports: [] }],
    },
  ];

  test('says where the bound groups live and how many are found nowhere', () => {
    expect(poolSpread('freedom', checks)).toEqual({
      size: 3,
      found: [
        { slug: 'panel-a', name: 'Panel A', count: 2 },
        { slug: 'panel-b', name: 'Panel B', count: 1 },
      ],
      missing: 0,
      missingUpTo: 0,
      withoutTransports: [{ slug: 'panel-a', name: 'Panel A', group: 'empty-a' }],
    });
  });

  test('counts groups no backend has', () => {
    const one = [{ ...checks[0]!, modes: [{ ...checks[0]!.modes[0]!, unknownHere: 3 }] }];
    expect(poolSpread('freedom', one)).toMatchObject({ size: 3, found: [], missing: 3 });
  });

  test('an unbound mode, or one no backend checked, has nothing', () => {
    expect(poolSpread('privacy', checks)).toEqual({
      size: 0,
      found: [],
      missing: 0,
      missingUpTo: 0,
      withoutTransports: [],
    });
    expect(poolSpread('other', [])).toMatchObject({ size: 0, missing: 0 });
  });

  test('a uuid on two backends never hides a group that is on none', () => {
    // Pool of 2: U2 is on both backends, the other uuid on neither.
    const two = [
      {
        slug: 'panel-a',
        name: 'Panel A',
        modes: [{ modeSlug: 'm', modeGroups: 2, unknownHere: 1, withoutTransports: [] }],
      },
      {
        slug: 'panel-b',
        name: 'Panel B',
        modes: [{ modeSlug: 'm', modeGroups: 2, unknownHere: 1, withoutTransports: [] }],
      },
    ];
    const spread = poolSpread('m', two, indexModeGroups(trees));
    expect(spread.missing).toBe(0);
    expect(spread.missingUpTo).toBe(1);
    // Without a uuid held twice, the sum is exact.
    expect(poolSpread('m', two, new Map())).toMatchObject({ missing: 0, missingUpTo: 0 });
  });
});
