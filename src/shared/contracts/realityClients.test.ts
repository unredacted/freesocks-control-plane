import { describe, expect, test } from 'vitest';
import {
  realityClientBoundsOf,
  realityClientRefusal,
  sameRefusal,
  xrayVersionOf,
} from './realityClients';

const unset = { minClientVer: null, maxClientVer: null };
const bounds = (minClientVer: string | null, maxClientVer: string | null = null) => ({
  minClientVer,
  maxClientVer,
});
const reasonsOf = (b: ReturnType<typeof bounds>, core: string | null) =>
  realityClientRefusal(b, core)?.reasons ?? null;

describe('realityClientRefusal', () => {
  test('no minClientVer on Xray 26.7.11 to 26.7.28: every sing-box and Mihomo client is refused', () => {
    for (const core of [
      '26.7.11',
      '26.7.28',
      'v26.7.28',
      'Xray 26.7.28 (Xray, Penetrates Everything.)',
    ])
      expect(realityClientRefusal(unset, core)).toMatchObject({
        refuses: ['singbox', 'mihomo'],
        reasons: [{ cause: 'core_default', families: ['singbox', 'mihomo'] }],
        minClientVer: null,
      });
  });

  test('no minClientVer before the default, and from v26.9.8 on, has no default minimum', () => {
    for (const core of ['1.8.24', '25.10.15', '26.3.27', '26.6.27'])
      expect(realityClientRefusal(unset, core)).toBeNull();
    // v26.9.8 already dropped it (the default floor would wrongly refuse Mihomo there).
    expect(reasonsOf(unset, '26.9.8')).toEqual([
      { cause: 'core_key_share', families: ['singbox'] },
    ]);
  });

  test('from v26.9.8 on, sing-box is refused whatever the transport sets; Mihomo is not', () => {
    for (const core of ['26.9.8', '26.9.9', '26.10.21'])
      for (const b of [unset, bounds('1.8.1'), bounds('1.0.0')])
        expect(realityClientRefusal(b, core)).toMatchObject({
          refuses: ['singbox'],
          reasons: [{ cause: 'core_key_share', families: ['singbox'] }],
        });
  });

  test('no known Xray version is never "they get in"', () => {
    // No minClientVer: the default minimum may refuse both.
    expect(realityClientRefusal(unset, null)).toMatchObject({
      refuses: ['singbox', 'mihomo'],
      reasons: [{ cause: 'core_unknown', families: ['singbox', 'mihomo'] }],
      xrayVersion: null,
    });
    // With 1.8.1 the key share still may refuse sing-box.
    expect(reasonsOf(bounds('1.8.1'), 'unknown')).toEqual([
      { cause: 'core_unknown', families: ['singbox'] },
    ]);
    // A family a bound already refuses is not named again as unknown.
    expect(reasonsOf(bounds('1.8.2'), null)).toEqual([
      { cause: 'min_above', families: ['singbox'] },
    ]);
  });

  test('an empty minClientVer is no minClientVer (Xray reads it as unset)', () => {
    expect(reasonsOf(bounds(''), '26.7.28')?.[0]?.cause).toBe('core_default');
  });

  test('1.8.1 admits every family on the default releases', () => {
    for (const core of ['26.7.11', '26.7.28', '26.6.27'])
      expect(realityClientRefusal(bounds('1.8.1'), core)).toBeNull();
  });

  test('a minClientVer above what a family sends refuses that family', () => {
    expect(realityClientRefusal(bounds('1.8.2'), '26.7.28')).toMatchObject({
      refuses: ['singbox'],
      reasons: [{ cause: 'min_above', families: ['singbox'] }],
      minClientVer: '1.8.2',
    });
    expect(reasonsOf(bounds('25.1.1'), '26.6.27')).toEqual([
      { cause: 'min_above', families: ['singbox', 'mihomo'] },
    ]);
  });

  test('a maxClientVer below what a family sends refuses that family', () => {
    expect(realityClientRefusal(bounds('1.0.0', '1.8.1'), '26.6.27')).toMatchObject({
      refuses: ['mihomo'],
      reasons: [{ cause: 'max_below', families: ['mihomo'] }],
      maxClientVer: '1.8.1',
    });
  });

  test('opposite bounds keep a reason each, with the family each refuses', () => {
    expect(realityClientRefusal(bounds('1.8.2', '1.8.1'), '26.6.27')).toMatchObject({
      refuses: ['singbox', 'mihomo'],
      reasons: [
        { cause: 'min_above', families: ['singbox'] },
        { cause: 'max_below', families: ['mihomo'] },
      ],
    });
    // The default minimum and a low maximum: both named, so the fix covers both.
    expect(reasonsOf(bounds(null, '1.8.1'), '26.7.28')).toEqual([
      { cause: 'core_default', families: ['singbox', 'mihomo'] },
      { cause: 'max_below', families: ['mihomo'] },
    ]);
  });

  test('two-part bounds read as Xray reads them (1.8 = 1.8.0)', () => {
    expect(realityClientRefusal(bounds('1.8'), '26.7.28')).toBeNull();
  });

  test('a bound Xray cannot read is not judged', () => {
    expect(realityClientRefusal(bounds('1.8.x'), '26.7.28')).toBeNull();
    expect(realityClientRefusal(bounds('1.8.1.0'), null)).toBeNull();
    expect(realityClientRefusal(bounds('1.300.1'), null)).toBeNull();
  });
});

describe('realityClientBoundsOf', () => {
  test('reads the two bounds and nothing else', () => {
    expect(
      realityClientBoundsOf({ privateKey: 'k', minClientVer: '1.8.1', maxClientVer: ' 26.1.1 ' }),
    ).toEqual({ minClientVer: '1.8.1', maxClientVer: '26.1.1' });
    expect(realityClientBoundsOf({ minClientVer: 1 })).toEqual(unset);
    expect(realityClientBoundsOf(null)).toEqual(unset);
  });
});

describe('xrayVersionOf / sameRefusal', () => {
  test('the first x.y.z the panel reports', () => {
    expect(xrayVersionOf('26.7.28')).toEqual([26, 7, 28]);
    expect(xrayVersionOf('')).toBeNull();
    expect(xrayVersionOf(undefined)).toBeNull();
  });

  test('verdicts compare by value, reasons included', () => {
    const a = realityClientRefusal(unset, '26.7.28');
    expect(sameRefusal(a, realityClientRefusal(unset, '26.7.28'))).toBe(true);
    expect(sameRefusal(a, realityClientRefusal(unset, '26.7.11'))).toBe(false);
    expect(
      sameRefusal(
        realityClientRefusal(bounds('1.8.2'), '26.6.27'),
        realityClientRefusal(bounds('1.8.2'), '26.9.9'),
      ),
    ).toBe(false);
    expect(sameRefusal(null, undefined)).toBe(true);
    expect(sameRefusal(a, null)).toBe(false);
  });
});
