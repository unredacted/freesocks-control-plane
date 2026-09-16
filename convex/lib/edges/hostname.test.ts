import { describe, expect, test } from 'vitest';
import {
  acmeChallengeName,
  edgeHostnameFor,
  isFirstLevelUnder,
  isValidHostname,
  labelFromSeed,
} from './hostname';

describe('hostname minting', () => {
  test('deterministic, random-looking, first-level label of the requested length', () => {
    const a = edgeHostnameFor('fcp-relay-o1-0badf00d', 'Example.ORG.', { labelLength: 12 });
    const b = edgeHostnameFor('fcp-relay-o1-0badf00d', 'example.org', { labelLength: 12 });
    expect(a).toBe(b);
    expect(a.endsWith('.example.org')).toBe(true);
    const label = a.slice(0, -'.example.org'.length);
    expect(label).toHaveLength(12);
    expect(label).toMatch(/^[0-9bcdfghjklmnpqrstvwxz]+$/);
    expect(label).not.toContain('fcp');
    expect(isFirstLevelUnder(a, 'example.org')).toBe(true);
  });

  test('different spec names or zones give different labels; prefix is applied', () => {
    const a = edgeHostnameFor('fcp-relay-o1-aaaaaaaa', 'example.org', { labelLength: 10 });
    const b = edgeHostnameFor('fcp-relay-o1-bbbbbbbb', 'example.org', { labelLength: 10 });
    const c = edgeHostnameFor('fcp-relay-o1-aaaaaaaa', 'example.net', { labelLength: 10 });
    expect(new Set([a, b, c]).size).toBe(3);
    const p = edgeHostnameFor('fcp-relay-o1-aaaaaaaa', 'example.org', {
      labelLength: 10,
      labelPrefix: 'cdn-',
    });
    expect(p.startsWith('cdn-')).toBe(true);
    expect(p.split('.')[0]).toHaveLength(14);
  });

  test('length is clamped to 8..16 and the seed expansion covers long labels', () => {
    expect(edgeHostnameFor('x', 'example.org', { labelLength: 2 }).split('.')[0]).toHaveLength(8);
    expect(edgeHostnameFor('x', 'example.org', { labelLength: 99 }).split('.')[0]).toHaveLength(16);
    expect(labelFromSeed('seed', 16)).toHaveLength(16);
    expect(labelFromSeed('seed', 16)).toBe(labelFromSeed('seed', 16));
    expect(labelFromSeed('seed', 16).slice(0, 8)).not.toBe(labelFromSeed('seed2', 16).slice(0, 8));
  });

  test('refuses invalid zones, prefixes and deeper labels', () => {
    expect(() => edgeHostnameFor('x', 'not a zone', { labelLength: 8 })).toThrow();
    expect(() => edgeHostnameFor('x', '203.0.113.1', { labelLength: 8 })).toThrow();
    expect(() => edgeHostnameFor('x', 'example.org', { labelLength: 8, labelPrefix: 'a.b' })).toThrow();
    expect(isFirstLevelUnder('a.b.example.org', 'example.org')).toBe(false);
    expect(isFirstLevelUnder('example.org', 'example.org')).toBe(false);
    expect(isFirstLevelUnder('a.example.org', 'ample.org')).toBe(false);
    expect(isValidHostname('a.example.org')).toBe(true);
    expect(isValidHostname('203.0.113.1')).toBe(false);
    expect(isValidHostname('-a.example.org')).toBe(false);
  });

  test('acme challenge name', () => {
    expect(acmeChallengeName('A.Example.org.')).toBe('_acme-challenge.a.example.org');
  });
});
