import { describe, expect, test } from 'vitest';
import {
  realityClientBoundsOf,
  realityClientRefusal,
  sameRefusal,
  xrayVersionOf,
} from './realityClients';

const unset = { minClientVer: null, maxClientVer: null };

describe('realityClientRefusal', () => {
  test('no minClientVer on Xray 26.7.11 to 26.7.28: every sing-box and Mihomo client is refused', () => {
    for (const core of [
      '26.7.11',
      '26.7.28',
      'v26.7.28',
      'Xray 26.7.28 (Xray, Penetrates Everything.)',
    ])
      expect(realityClientRefusal(unset, core)).toMatchObject({
        cause: 'core_default',
        refuses: ['singbox', 'mihomo'],
        minClientVer: null,
      });
  });

  test('no minClientVer outside those releases admits them', () => {
    for (const core of ['1.8.24', '25.10.15', '26.3.27', '26.6.27', '26.9.9', '26.10.21'])
      expect(realityClientRefusal(unset, core)).toBeNull();
  });

  test('no minClientVer and no known Xray version: it may refuse them', () => {
    expect(realityClientRefusal(unset, null)).toMatchObject({
      cause: 'core_unknown',
      refuses: ['singbox', 'mihomo'],
      xrayVersion: null,
    });
    expect(realityClientRefusal(unset, 'unknown')?.cause).toBe('core_unknown');
  });

  test('an empty minClientVer is no minClientVer (Xray reads it as unset)', () => {
    expect(realityClientRefusal({ minClientVer: '', maxClientVer: null }, '26.7.28')?.cause).toBe(
      'core_default',
    );
  });

  test('1.8.1 admits every family on any Xray, the default releases included', () => {
    for (const core of ['26.7.28', '26.10.21', null])
      expect(realityClientRefusal({ minClientVer: '1.8.1', maxClientVer: null }, core)).toBeNull();
  });

  test('a minClientVer above what a family sends refuses that family', () => {
    expect(
      realityClientRefusal({ minClientVer: '1.8.2', maxClientVer: null }, '26.7.28'),
    ).toMatchObject({ cause: 'min_above', refuses: ['singbox'], minClientVer: '1.8.2' });
    expect(
      realityClientRefusal({ minClientVer: '25.1.1', maxClientVer: null }, '26.10.21'),
    ).toMatchObject({ cause: 'min_above', refuses: ['singbox', 'mihomo'] });
  });

  test('a maxClientVer below what a family sends refuses that family', () => {
    expect(
      realityClientRefusal({ minClientVer: '1.0.0', maxClientVer: '1.8.1' }, '26.10.21'),
    ).toMatchObject({ cause: 'max_below', refuses: ['mihomo'], maxClientVer: '1.8.1' });
  });

  test('two-part bounds read as Xray reads them (1.8 = 1.8.0)', () => {
    expect(realityClientRefusal({ minClientVer: '1.8', maxClientVer: null }, '26.7.28')).toBeNull();
  });

  test('a bound Xray cannot read is not judged', () => {
    expect(
      realityClientRefusal({ minClientVer: '1.8.x', maxClientVer: null }, '26.7.28'),
    ).toBeNull();
    expect(realityClientRefusal({ minClientVer: '1.8.1.0', maxClientVer: null }, null)).toBeNull();
    expect(realityClientRefusal({ minClientVer: '1.300.1', maxClientVer: null }, null)).toBeNull();
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

  test('verdicts compare by value', () => {
    const a = realityClientRefusal(unset, '26.7.28');
    expect(sameRefusal(a, realityClientRefusal(unset, '26.7.28'))).toBe(true);
    expect(sameRefusal(a, realityClientRefusal(unset, '26.7.11'))).toBe(false);
    expect(sameRefusal(null, undefined)).toBe(true);
    expect(sameRefusal(a, null)).toBe(false);
  });
});
