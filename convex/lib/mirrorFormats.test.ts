import { describe, expect, test } from 'vitest';
import { sha256Hex } from './crypto';
import { DEFAULT_CLIENTS } from './clientCatalog';
import { legacyClashCore } from './appNotice';
import { classifyClient } from './edges/clientFamilies';
import { normalizeSubscriptionUserAgent } from './backends/remnawave';
import {
  MIRROR_FETCH_UA,
  mirrorFamily,
  mirrorFormatOfApp,
  mirrorFormatsFor,
  mirrorSetHash,
} from './mirrorFormats';
import {
  mirrorFormatPath,
  mirrorFormatsOf,
  mirrorObjectPaths,
} from '../../src/shared/mirrorFormats';

describe('mirror formats', () => {
  test('each catalogued app reads the format its User-Agent would be served', () => {
    const formats = Object.fromEntries(
      DEFAULT_CLIENTS.map((c) => [c.name, mirrorFormatOfApp(c.name)]),
    );
    expect(formats).toMatchObject({
      Hiddify: 'links',
      Karing: 'singbox',
      'sing-box': 'singbox',
      v2rayNG: 'links',
      Clash: 'clash',
      FlClash: 'clash',
      'Mihomo Party': 'clash',
      Shadowrocket: 'links',
      Outline: 'links',
    });
  });

  test('each format is fetched as a current app of its kind, never a legacy Clash core', () => {
    expect(MIRROR_FETCH_UA.links).toBeUndefined();
    expect(mirrorFamily('links')).toBe('other');
    expect(mirrorFamily('clash')).toBe('mihomo');
    expect(mirrorFamily('singbox')).toBe('singbox');
    expect(legacyClashCore(MIRROR_FETCH_UA.clash!)).toBe(false);
    expect(classifyClient(MIRROR_FETCH_UA.clash).expectedFormat).toBe('clash-yaml');
    expect(classifyClient(MIRROR_FETCH_UA.singbox).expectedFormat).toBe('singbox-json');
    // Already the canonical form the main link rewrites sing-box shells to.
    expect(normalizeSubscriptionUserAgent(MIRROR_FETCH_UA.singbox)).toBe(MIRROR_FETCH_UA.singbox);
  });

  test('a bare access key keeps one object; a subscription document all three', () => {
    expect(mirrorFormatsFor('outline')).toEqual(['links']);
    expect(mirrorFormatsFor('remnawave')).toEqual(['links', 'clash', 'singbox']);
  });

  test('paths: the plain list at the bare path, the others beside it', () => {
    expect(mirrorFormatPath('mirrors/ab', 'links')).toBe('mirrors/ab');
    expect(mirrorFormatPath('https://cdn.example/mirrors/ab', 'clash')).toBe(
      'https://cdn.example/mirrors/ab.yaml',
    );
    expect(mirrorObjectPaths('mirrors/ab')).toEqual([
      'mirrors/ab',
      'mirrors/ab.yaml',
      'mirrors/ab.json',
    ]);
    expect(mirrorFormatsOf({})).toEqual(['links']);
    expect(mirrorFormatsOf({ formats: ['singbox', 'links', 'bogus'] })).toEqual([
      'links',
      'singbox',
    ]);
  });

  test('the set hash: a links-only copy hashes as its body (as before formats); order never matters', async () => {
    const h = await sha256Hex('body');
    expect(await mirrorSetHash([{ format: 'links', hash: h }])).toBe(h);
    const a = await mirrorSetHash([
      { format: 'singbox', hash: 's' },
      { format: 'links', hash: h },
      { format: 'clash', hash: 'c' },
    ]);
    const b = await mirrorSetHash([
      { format: 'links', hash: h },
      { format: 'clash', hash: 'c' },
      { format: 'singbox', hash: 's' },
    ]);
    expect(a).toBe(b);
    expect(a).not.toBe(h);
    expect(
      await mirrorSetHash([
        { format: 'links', hash: h },
        { format: 'clash', hash: 'x' },
      ]),
    ).not.toBe(
      await mirrorSetHash([
        { format: 'links', hash: h },
        { format: 'clash', hash: 'c' },
      ]),
    );
  });
});
