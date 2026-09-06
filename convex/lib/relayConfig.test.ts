import { describe, expect, test } from 'vitest';
import {
  RELAY_DEFAULTS,
  RELAY_KEYS,
  RENDER_CLIENT_FAMILIES,
  clientRuleKey,
  defaultClientRule,
  relayConfigWrites,
  relaySecretWrites,
  sanitizeClientRule,
  sanitizeCountryList,
  sanitizeInt,
  sanitizeLabel,
  sanitizeRelayConfig,
} from './relayConfig';

describe('relayConfig sanitizers', () => {
  test('defaults when nothing is stored', () => {
    expect(sanitizeRelayConfig({})).toEqual(RELAY_DEFAULTS);
  });

  test('ints clamp to bounds and reject garbage', () => {
    expect(sanitizeInt('7', 1, 10, 3)).toBe(7);
    expect(sanitizeInt(99, 1, 10, 3)).toBe(10);
    expect(sanitizeInt(-4, 1, 10, 3)).toBe(1);
    expect(sanitizeInt('x', 1, 10, 3)).toBe(3);
    expect(sanitizeInt(2.6, 1, 10, 3)).toBe(3);
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

  test('every RELAY_KEYS value is namespaced under relay.', () => {
    for (const key of Object.values(RELAY_KEYS)) expect(key.startsWith('relay.')).toBe(true);
    for (const f of RENDER_CLIENT_FAMILIES) {
      expect(clientRuleKey(f)).toBe(`relay.render.clients.${f}`);
    }
  });
});

describe('relayConfigWrites', () => {
  test('accepts flat and nested paths, ignores unknown keys, writes only provided ones', () => {
    const { writes, changedKeys } = relayConfigWrites({
      enabled: true,
      'detect.windowMinutes': 15,
      probe: { countries: ['ir', 'ru'], sources: { checkhost: false } },
      bogus: 1,
      detect: { nothing: 2 },
    });
    const keys = writes.map((w) => w.key).sort();
    expect(keys).toEqual(
      [
        'relay.enabled',
        'relay.detect.windowMinutes',
        'relay.probe.countries',
        'relay.probe.sources.checkhost',
      ].sort(),
    );
    expect(changedKeys.sort()).toEqual(
      ['enabled', 'detect.windowMinutes', 'probe.countries', 'probe.sources.checkhost'].sort(),
    );
    // Stored as given; the resolver sanitizes on read.
    expect(writes.find((w) => w.key === 'relay.probe.countries')?.value).toBe('["ir","ru"]');
  });

  test('client rules are sanitized on write, one row per family, unknown families dropped', () => {
    const { writes } = relayConfigWrites({
      render: {
        clients: { singbox: { autoGroup: false, maxEntries: 99 }, martian: { enabled: true } },
      },
    });
    expect(writes).toHaveLength(1);
    expect(writes[0].key).toBe('relay.render.clients.singbox');
    const rule = JSON.parse(writes[0].value);
    expect(rule.autoGroup).toBe(false);
    expect(rule.maxEntries).toBe(20);
  });

  test('non-object patches write nothing', () => {
    expect(relayConfigWrites(null).writes).toEqual([]);
    expect(relayConfigWrites([1]).writes).toEqual([]);
  });
});

describe('relaySecretWrites', () => {
  test('blank leaves a secret unchanged; set values are written', () => {
    expect(relaySecretWrites({ globalpingToken: '  ', ripeAtlasKey: '' })).toEqual([]);
    const w = relaySecretWrites({ globalpingToken: 'tok' });
    expect(w).toEqual([{ key: 'relay.secret.probe.globalping.token', value: '"tok"' }]);
  });
});
