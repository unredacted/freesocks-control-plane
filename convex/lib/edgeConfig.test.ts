import { describe, expect, test } from 'vitest';
import {
  EDGE_DEFAULTS,
  EDGE_KEYS,
  RENDER_CLIENT_FAMILIES,
  clientRuleKey,
  defaultClientRule,
  edgeConfigWrites,
  edgeSecretWrites,
  sanitizeClientRule,
  sanitizeCountryList,
  sanitizeInt,
  sanitizeLabel,
  sanitizeRelayConfig,
} from './edgeConfig';

describe('edgeConfig sanitizers', () => {
  test('defaults when nothing is stored', () => {
    expect(sanitizeRelayConfig({})).toEqual(EDGE_DEFAULTS);
  });

  test('ints clamp to bounds and reject garbage', () => {
    expect(sanitizeInt('7', 1, 10, 3)).toBe(7);
    expect(sanitizeInt(99, 1, 10, 3)).toBe(10);
    expect(sanitizeInt(-4, 1, 10, 3)).toBe(1);
    expect(sanitizeInt('x', 1, 10, 3)).toBe(3);
    expect(sanitizeInt(2.6, 1, 10, 3)).toBe(3);
  });

  test('probe agreement needs at least two networks; source spacing is bounded', () => {
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 1 }).probe.agreementVantages).toBe(2);
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 0 }).probe.agreementVantages).toBe(2);
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 4 }).probe.agreementVantages).toBe(4);
    expect(EDGE_DEFAULTS.probe.sourceSpacingMs).toBe(1500);
    expect(sanitizeRelayConfig({ 'probe.sourceSpacingMs': -5 }).probe.sourceSpacingMs).toBe(0);
    expect(sanitizeRelayConfig({ 'probe.sourceSpacingMs': 1e9 }).probe.sourceSpacingMs).toBe(
      60_000,
    );
    expect(EDGE_KEYS['probe.sourceSpacingMs']).toBe('edge.probe.sourceSpacingMs');
  });

  test('clearBelow is forced under suspectAt (hysteresis)', () => {
    const cfg = sanitizeRelayConfig({ 'detect.suspectAt': 0.5, 'detect.clearBelow': 0.9 });
    expect(cfg.detect.suspectAt).toBe(0.5);
    expect(cfg.detect.clearBelow).toBeLessThan(0.5);
  });

  test('labels strip control chars, collapse whitespace, fall back when empty/too long', () => {
    expect(sanitizeLabel(' Hi  there ', 'd')).toBe('Hi there');
    expect(sanitizeLabel('', 'd')).toBe('d');
    expect(sanitizeLabel('x'.repeat(49), 'd')).toBe('d');
    expect(sanitizeLabel(42, 'd')).toBe('d');
  });

  test('country lists uppercase, dedupe and drop junk', () => {
    expect(sanitizeCountryList(['ir', 'IR', 'ru ', 'usa', 7], ['XX'])).toEqual(['IR', 'RU']);
    expect(sanitizeCountryList('IR', ['XX'])).toEqual(['XX']);
  });

  test('client rules: auto families get the auto group by default, others do not', () => {
    expect(defaultClientRule('singbox').autoGroup).toBe(true);
    expect(defaultClientRule('mihomo').autoGroup).toBe(true);
    expect(defaultClientRule('v2rayng').autoGroup).toBe(false);
    const rule = sanitizeClientRule({ ipv6Mode: 'nope', maxEntries: 500, enabled: false }, 'happ');
    expect(rule.ipv6Mode).toBe('inherit');
    expect(rule.maxEntries).toBe(20);
    expect(rule.enabled).toBe(false);
  });

  test('every EDGE_KEYS value is namespaced under edge.', () => {
    for (const key of Object.values(EDGE_KEYS)) expect(key.startsWith('edge.')).toBe(true);
    for (const f of RENDER_CLIENT_FAMILIES) {
      expect(clientRuleKey(f)).toBe(`edge.render.clients.${f}`);
    }
  });
});

describe('edgeConfigWrites', () => {
  test('accepts flat and nested paths, ignores unknown keys, writes only provided ones', () => {
    const { writes, changedKeys } = edgeConfigWrites({
      enabled: true,
      'detect.windowMinutes': 15,
      probe: { countries: ['ir', 'ru'], sources: { checkhost: false } },
      bogus: 1,
      detect: { nothing: 2 },
    });
    const keys = writes.map((w) => w.key).sort();
    expect(keys).toEqual(
      [
        'edge.enabled',
        'edge.detect.windowMinutes',
        'edge.probe.countries',
        'edge.probe.sources.checkhost',
      ].sort(),
    );
    expect(changedKeys.sort()).toEqual(
      ['enabled', 'detect.windowMinutes', 'probe.countries', 'probe.sources.checkhost'].sort(),
    );
    // Stored as given; the resolver sanitizes on read.
    expect(writes.find((w) => w.key === 'edge.probe.countries')?.value).toBe('["ir","ru"]');
  });

  test('client rules are sanitized on write, one row per family, unknown families dropped', () => {
    const { writes } = edgeConfigWrites({
      render: {
        clients: { singbox: { autoGroup: false, maxEntries: 99 }, martian: { enabled: true } },
      },
    });
    expect(writes).toHaveLength(1);
    expect(writes[0].key).toBe('edge.render.clients.singbox');
    const rule = JSON.parse(writes[0].value);
    expect(rule.autoGroup).toBe(false);
    expect(rule.maxEntries).toBe(20);
  });

  test('non-object patches write nothing', () => {
    expect(edgeConfigWrites(null).writes).toEqual([]);
    expect(edgeConfigWrites([1]).writes).toEqual([]);
  });
});

describe('edgeSecretWrites', () => {
  test('blank leaves a secret unchanged; set values are written', () => {
    expect(edgeSecretWrites({ globalpingToken: '  ', ripeAtlasKey: '' })).toEqual([]);
    const w = edgeSecretWrites({ globalpingToken: 'tok' });
    expect(w).toEqual([{ key: 'edge.secret.probe.globalping.token', value: '"tok"' }]);
  });
});
