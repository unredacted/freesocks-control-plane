import { describe, expect, test } from 'vitest';
import {
  EDGE_DEFAULTS,
  EDGE_KEYS,
  EDGE_PLUMBING,
  __setEdgePlumbingForTests,
  originOverrideNames,
  originPolicy,
  qualificationRenewLeadMs,
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

  test('probe agreement needs at least two networks', () => {
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 1 }).probe.agreementVantages).toBe(2);
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 0 }).probe.agreementVantages).toBe(2);
    expect(sanitizeRelayConfig({ 'probe.agreementVantages': 4 }).probe.agreementVantages).toBe(4);
  });

  test('the machinery is constants, not settings: no key, no stored value read', () => {
    const keys = Object.keys(EDGE_KEYS);
    for (const gone of [
      'providerAffinity',
      'settleGraceSeconds',
      'pollSeconds',
      'opClaimSeconds',
      'verifyAttempts',
      'maxFlipAttempts',
      'maxRollbackAttempts',
      'maxDestroyAttempts',
      'maxRotationMinutes',
      'provisionTimeoutMinutes',
      'discoveryTimeoutMinutes',
      'maxReconcileStartsPerTick',
      'detect.maxReportRowsPerEval',
      'l7.qualifyTimeoutMinutes',
      'l7.qualifyStepTimeoutMs',
      'l7.qualificationTtlMinutes',
      'l7.maxRequalifyPerTick',
      'probe.sourceSpacingMs',
    ])
      expect(keys).not.toContain(gone);
    expect(EDGE_PLUMBING.pollMs).toBe(20_000);
    expect(EDGE_PLUMBING.probeSourceSpacingMs).toBe(1500);
    // The renewal lead: a quarter of the TTL, at least 15 minutes, under half of it.
    expect(qualificationRenewLeadMs()).toBe(15 * 60_000);
    __setEdgePlumbingForTests({ pollMs: 5_000, l7QualificationTtlMs: 8 * 60 * 60_000 });
    expect(EDGE_PLUMBING.pollMs).toBe(5_000);
    expect(qualificationRenewLeadMs()).toBe(2 * 60 * 60_000);
    __setEdgePlumbingForTests(null);
    expect(EDGE_PLUMBING.pollMs).toBe(20_000);
    expect(EDGE_PLUMBING.l7QualificationTtlMs).toBe(60 * 60_000);
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
    // `probe.countries` is not a setting any more: it comes from the
    // censored-country list (lib/censoredCountries.ts), so it is never written.
    expect(keys).toEqual(
      ['edge.enabled', 'edge.detect.windowMinutes', 'edge.probe.sources.checkhost'].sort(),
    );
    expect(changedKeys.sort()).toEqual(
      ['enabled', 'detect.windowMinutes', 'probe.sources.checkhost'].sort(),
    );
    // Stored as given; the resolver sanitizes on read.
    expect(writes.find((w) => w.key === 'edge.probe.sources.checkhost')?.value).toBe('false');
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

describe('originPolicy: one inheritance rule', () => {
  const cfg = sanitizeRelayConfig({
    standbyPerRelay: 1,
    standbyPerListener: 1,
    cooldownMinutes: 30,
    maxRotationsPerRelayPerDay: 5,
    drainMinutes: 90,
  });

  test('an origin without its own values follows the fleet', () => {
    expect(originPolicy({}, cfg)).toEqual({
      standbyPerRelay: 1,
      standbyPerListener: 1,
      cooldownMs: 30 * 60_000,
      maxRotationsPerDay: 5,
      drainMs: 90 * 60_000,
    });
    expect(originOverrideNames({})).toEqual([]);
  });

  test("an origin's own value wins, field by field, including a zero", () => {
    const own = { standbyPerRelay: 0, drainMs: 5 * 60_000 };
    expect(originPolicy(own, cfg)).toEqual({
      standbyPerRelay: 0,
      standbyPerListener: 1,
      cooldownMs: 30 * 60_000,
      maxRotationsPerDay: 5,
      drainMs: 5 * 60_000,
    });
    expect(originOverrideNames(own)).toEqual(['standbyPerRelay', 'drainMinutes']);
  });
});
