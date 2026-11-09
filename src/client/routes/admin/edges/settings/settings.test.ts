import { describe, expect, it } from 'vitest';
import {
  EDGE_CONFIG_BOUNDS,
  EDGE_DEFAULTS,
  EDGE_KEYS,
  flattenEdgeConfig,
} from '../../../../../../convex/lib/edgeConfig';
import {
  adjustedValues,
  buildPatch,
  canonical,
  diffConfig,
  flattenConfig,
  formatConfigValue,
  pathCovers,
} from './configDiff';
import { ALL_FIELDS, RULE_FIELDS, groupPaths } from './fields';
import { SETTINGS_GROUPS } from './groups';

describe('flattenConfig', () => {
  it('matches the server flattening (rules stay objects, arrays stay values)', () => {
    expect(flattenConfig(EDGE_DEFAULTS)).toEqual(flattenEdgeConfig(EDGE_DEFAULTS));
    const flat = flattenConfig(EDGE_DEFAULTS);
    expect(flat['detect.windowMinutes']).toBe(30);
    expect(flat['probe.countries']).toEqual(EDGE_DEFAULTS.probe.countries);
    expect(flat['render.clients.singbox']).toEqual(EDGE_DEFAULTS.render.clients.singbox);
    expect(flat['render.clients']).toBeUndefined();
  });
});

describe('diffConfig / buildPatch', () => {
  const base = flattenConfig(EDGE_DEFAULTS);

  it('reports only real changes, as a flat patch', () => {
    const edits = { 'detect.windowMinutes': 15, cooldownMinutes: 120, enabled: true };
    const changes = diffConfig(base, edits);
    expect(changes.map((c) => c.display)).toEqual(['detect.windowMinutes', 'enabled']);
    expect(buildPatch(changes)).toEqual({ 'detect.windowMinutes': 15, enabled: true });
  });

  it('limits the diff to the section paths', () => {
    const edits = { 'detect.windowMinutes': 15, enabled: true };
    expect(buildPatch(diffConfig(base, edits, groupPaths('detection')))).toEqual({
      'detect.windowMinutes': 15,
    });
  });

  it('shows a rule change per field but sends the whole rule', () => {
    const rule = { ...EDGE_DEFAULTS.render.clients.mihomo, maxEntries: 3, includeBackup: false };
    const changes = diffConfig(base, { 'render.clients.mihomo': rule });
    expect(changes.map((c) => c.display)).toEqual([
      'render.clients.mihomo.includeBackup',
      'render.clients.mihomo.maxEntries',
    ]);
    expect(buildPatch(changes)).toEqual({ 'render.clients.mihomo': rule });
  });

  it('treats arrays by value and key order as irrelevant', () => {
    expect(diffConfig(base, { 'probe.countries': [...EDGE_DEFAULTS.probe.countries] })).toEqual([]);
    expect(canonical({ a: 1, b: [1, 2] })).toBe(canonical({ b: [1, 2], a: 1 }));
  });
});

describe('adjustedValues', () => {
  it('lists what the server stored differently', () => {
    const fresh = {
      'detect.clearBelow': 0.55,
      'detect.suspectAt': 0.6,
      'render.ipv6Mode': 'both',
    };
    expect(
      adjustedValues(
        { 'detect.clearBelow': 0.9, 'detect.suspectAt': 0.6, 'render.ipv6Mode': 'both' },
        fresh,
      ),
    ).toEqual([{ display: 'detect.clearBelow', sent: 0.9, stored: 0.55 }]);
  });
});

describe('formatConfigValue / pathCovers', () => {
  it('speaks in words', () => {
    expect(formatConfigValue(true)).toBe('on');
    expect(formatConfigValue(false)).toBe('off');
    expect(formatConfigValue([])).toBe('none');
    expect(formatConfigValue(['IR', 'RU'])).toBe('IR, RU');
    expect(formatConfigValue('')).toBe('empty');
  });
  it('covers sub-keys only', () => {
    expect(pathCovers('render.clients.mihomo', 'render.clients.mihomo.maxEntries')).toBe(true);
    expect(pathCovers('drainMinutes', 'drainMinutesX')).toBe(false);
  });
});

describe('settings fields', () => {
  it('puts every server config path in exactly one group', () => {
    const owned = SETTINGS_GROUPS.flatMap((g) => groupPaths(g.id));
    expect(new Set(owned).size).toBe(owned.length);
    // Everything the server has: no stored key without a control, no control without a key.
    expect([...owned].sort()).toEqual(Object.keys(EDGE_KEYS).sort());
  });

  it('gives every bounded path a number field and every number field bounds', () => {
    const numbers = ALL_FIELDS.filter((f) => f.kind === 'number').map((f) => f.path);
    const bounded = Object.keys(EDGE_CONFIG_BOUNDS).filter(
      (k) => k !== 'render.clients.maxEntries',
    );
    expect([...numbers].sort()).toEqual(bounded.sort());
  });

  it('covers every key of a client rule', () => {
    expect(RULE_FIELDS.map((f) => f.key).sort()).toEqual(
      Object.keys(EDGE_DEFAULTS.render.clients.other).sort(),
    );
  });

  it('keeps the copy free of em-dashes and API paths', () => {
    const copy = [...ALL_FIELDS, ...RULE_FIELDS].flatMap((f) => [f.label, f.helper]);
    for (const line of copy) {
      expect(line).not.toContain(String.fromCharCode(0x2014));
      expect(line).not.toContain('/api/');
    }
  });

  it('gives the subscriptions group every client family rule', () => {
    expect(groupPaths('subscriptions', ['singbox', 'other'])).toEqual(
      expect.arrayContaining(['render.clients.singbox', 'render.clients.other']),
    );
    expect(groupPaths('maintenance')).toEqual([]);
  });
});
