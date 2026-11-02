import { describe, expect, test } from 'vitest';
import {
  acmeChallengeName,
  edgeHostnameFor,
  isFirstLevelUnder,
  isValidHostname,
  labelFromSeed,
  labelOptionsOf,
  wordsFromSeed,
} from './hostname';
import { frontWords } from './frontWords';
import naughty from 'naughty-words/en.json';
import { validatePickOptions, validateTemplateParams } from './providers/templates';

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
    expect(() =>
      edgeHostnameFor('x', 'example.org', { labelLength: 8, labelPrefix: 'a.b' }),
    ).toThrow();
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

  test('a words-style label is two (or three) distinct dictionary words, deterministic, under the zone', () => {
    const opts = { labelLength: 12, labelStyle: 'words' as const };
    const a = edgeHostnameFor('fcp-relay-o1-0badf00d', 'Example.ORG.', opts);
    expect(edgeHostnameFor('fcp-relay-o1-0badf00d', 'example.org', opts)).toBe(a);
    const label = a.slice(0, -'.example.org'.length);
    expect(label).toMatch(/^[a-z]{4,9}-[a-z]{4,9}$/);
    const [w1, w2] = label.split('-');
    expect(w1).not.toBe(w2);
    expect(frontWords()).toContain(w1);
    expect(frontWords()).toContain(w2);
    expect(isFirstLevelUnder(a, 'example.org')).toBe(true);
    const three = edgeHostnameFor('fcp-relay-o1-0badf00d', 'example.org', {
      ...opts,
      labelWords: 3,
      labelPrefix: 'cdn-',
    });
    expect(three.split('.')[0]).toMatch(/^cdn-[a-z]{4,9}-[a-z]{4,9}-[a-z]{4,9}$/);
    // Clamped to 2..3; another spec name or zone gives another name.
    expect(
      edgeHostnameFor('x', 'example.org', { ...opts, labelWords: 9 })
        .split('.')[0]
        .split('-'),
    ).toHaveLength(3);
    const others = new Set(
      ['a', 'b', 'c', 'd'].map((n) => edgeHostnameFor(`fcp-relay-${n}`, 'example.org', opts)),
    );
    expect(others.size).toBe(4);
    expect(wordsFromSeed('seed', 3, ['one', 'two', 'three'])).toHaveLength(3);
  });

  test('the dictionary is large, sorted, plain, and free of offensive and telling words', () => {
    const words = frontWords();
    expect(words.length).toBeGreaterThan(30000);
    expect([...words].sort()).toEqual(words);
    expect(new Set(words).size).toBe(words.length);
    expect(words.every((w) => /^[a-z]{4,9}$/.test(w))).toBe(true);
    const offensive = (naughty as string[]).filter((w) => /^[a-z]{4,9}$/.test(w));
    expect(offensive.length).toBeGreaterThan(50);
    expect(offensive.filter((w) => words.includes(w))).toEqual([]);
    for (const w of ['proxy', 'tunnel', 'censor', 'bypass', 'freedom', 'secret', 'hidden'])
      expect(words.includes(w)).toBe(false);
  });

  test('a template without the name style parses as before; a pick may choose words', () => {
    for (const provider of ['fastly', 'cloudflare'] as const) {
      const parsed = validateTemplateParams(provider, {});
      expect(parsed.ok && 'labelStyle' in parsed.params).toBe(false);
      expect(parsed.ok && 'labelWords' in parsed.params).toBe(false);
      expect(validatePickOptions(provider, { labelStyle: 'words', labelWords: 3 })).toMatchObject({
        ok: true,
        values: { labelStyle: 'words', labelWords: 3 },
      });
      expect(validatePickOptions(provider, { labelWords: 5 }).ok).toBe(false);
    }
    expect(labelOptionsOf({})).toEqual({ labelLength: 12, labelPrefix: undefined });
    expect(labelOptionsOf({ labelStyle: 'words', labelWords: 3, labelPrefix: '' })).toEqual({
      labelLength: 12,
      labelPrefix: '',
      labelStyle: 'words',
      labelWords: 3,
    });
  });
});
