import { describe, expect, it } from 'vitest';
import { EDGE_DEFAULTS } from '../../../../../../convex/lib/edgeConfig';
import { flattenConfig } from './configDiff';
import { ALL_FIELDS, ENTRY_IDS, settingEntries, type SettingEntry } from './fields';
import {
  ALL_GROUPS,
  LEGACY_SECTIONS,
  SETTINGS_GROUPS,
  groupLabel,
  groupOfSection,
  parseGroup,
} from './groups';
import {
  changedFromDefault,
  entryMatches,
  fieldDomId,
  normalizeQuery,
  settingsView,
  type ViewOptions,
} from './search';

const FAMILIES = Object.keys(EDGE_DEFAULTS.render.clients);
const entries = settingEntries(FAMILIES);
const byId = (id: string): SettingEntry => entries.find((e) => e.id === id)!;
const view = (opts: Partial<ViewOptions>) =>
  settingsView(entries, {
    group: ALL_GROUPS,
    query: '',
    changedOnly: false,
    isChanged: () => false,
    ...opts,
  });
const ids = (opts: Partial<ViewOptions>) => [...view(opts).shown];

describe('groups', () => {
  it('parses the group param, falling back to all', () => {
    expect(parseGroup('probes')).toBe('probes');
    expect(parseGroup('nope')).toBe('all');
    expect(parseGroup(null)).toBe('all');
    expect(groupLabel('address-hostnames')).toBe('Address hostnames');
  });

  it('maps every old card to a group', () => {
    expect(groupOfSection('basics')).toBe('automatic');
    expect(groupOfSection('names')).toBe('address-hostnames');
    expect(groupOfSection('freedom')).toBe('delivery');
    expect(groupOfSection('nope')).toBeNull();
    expect(groupOfSection('toString')).toBeNull();
    expect(groupOfSection(null)).toBeNull();
    const ids = SETTINGS_GROUPS.map((g) => g.id) as string[];
    for (const g of Object.values(LEGACY_SECTIONS)) expect(ids).toContain(g);
  });

  it('never calls an address hostname a name, nor an SNI a server name', () => {
    for (const g of SETTINGS_GROUPS) expect(g.label.toLowerCase()).not.toMatch(/\bnames?\b/);
  });
});

describe('the catalog', () => {
  it('lists every knob once, with a group and a unique id', () => {
    const seen = new Set(entries.map((e) => e.id));
    expect(seen.size).toBe(entries.length);
    for (const f of ALL_FIELDS) expect(byId(f.path).group).toBe(f.group);
  });

  it('puts the cards that came onto the page in their groups', () => {
    expect(byId(ENTRY_IDS.freedom).group).toBe('delivery');
    expect(byId(ENTRY_IDS.deliveryPlaces).group).toBe('delivery');
    expect(byId(ENTRY_IDS.clientCheck).group).toBe('client-check');
    expect(byId(ENTRY_IDS.pause).group).toBe('maintenance');
    expect(byId(ENTRY_IDS.panelRead).group).toBe('maintenance');
    expect(byId(ENTRY_IDS.panelChanges).group).toBe('maintenance');
  });

  it('splits trust and country checks out of their old cards', () => {
    expect(byId('trust.strikesToSuspect').group).toBe('trust');
    expect(byId('lanes.openReplacesPerDay').group).toBe('trust');
    expect(byId('drainHold.maxDays').group).toBe('replacement');
    expect(byId('country.minProbes').group).toBe('country-checks');
    expect(byId('probe.intervalMinutes').group).toBe('probes');
  });

  it('gives every group at least one row', () => {
    for (const g of SETTINGS_GROUPS) expect(entries.some((e) => e.group === g.id)).toBe(true);
  });

  it('keeps the copy short of dashes and plain', () => {
    const copy = entries.flatMap((e) => [e.label, e.helper, ...(e.keywords ?? [])]);
    for (const line of copy) {
      expect(line).not.toMatch(/[–—]/);
      expect(line.toLowerCase()).not.toContain('meant for');
      expect(line.toLowerCase()).not.toContain('relay');
    }
  });

  it('says changed for the client families when any rule is off its default', () => {
    expect(byId(ENTRY_IDS.clientRules).paths).toEqual(FAMILIES.map((f) => `render.clients.${f}`));
  });
});

describe('search', () => {
  it('normalizes case, accents and spaces', () => {
    expect(normalizeQuery('  Dráin   TIME ')).toBe('drain time');
  });

  it('finds a knob by its label, helper, key, path, keywords or group', () => {
    const drain = byId('drainMinutes');
    expect(entryMatches(drain, 'drain')).toBe(true);
    expect(entryMatches(drain, 'destroyed')).toBe(true); // helper
    expect(entryMatches(drain, 'edge.drainMinutes')).toBe(true); // key
    expect(entryMatches(drain, 'drainminutes')).toBe(true); // path, any case
    expect(entryMatches(drain, 'retiring')).toBe(true); // keyword
    expect(entryMatches(drain, 'automatic work')).toBe(true); // group name
    expect(entryMatches(drain, 'drain zebra')).toBe(false); // every word must match
    expect(entryMatches(drain, '')).toBe(true);
  });

  it('finds the panel switches and the pause by the words an operator types', () => {
    expect(entryMatches(byId(ENTRY_IDS.panelRead), 'manage.observe')).toBe(true);
    expect(entryMatches(byId(ENTRY_IDS.panelChanges), 'servers.manage.enabled')).toBe(true);
    expect(entryMatches(byId(ENTRY_IDS.pause), 'freeze')).toBe(true);
    expect(entryMatches(byId('autoRotate'), 'automatic replacement')).toBe(true);
  });

  it('searches every group, whatever group is picked', () => {
    const v = view({ group: 'maintenance', query: 'globalping' });
    expect(v.shown.has('probe.sources.globalping')).toBe(true);
    expect(v.shown.has(ENTRY_IDS.globalpingToken)).toBe(true);
    expect(v.shown.has('probe.globalpingTestsPerHour')).toBe(true);
    expect(v.groups).toEqual(expect.arrayContaining(['probes', 'country-checks']));
    expect(v.groups).not.toContain('maintenance');
    expect(v.total).toBe(v.shown.size);
  });

  it('shows one group without a search, and every group for all', () => {
    const one = view({ group: 'detection' });
    expect(one.groups).toEqual(['detection']);
    expect([...one.shown].every((id) => byId(id).group === 'detection')).toBe(true);
    // The counts stay per group, so the column says how many each holds.
    expect(one.counts.probes).toBeGreaterThan(0);
    expect(view({}).shown.size).toBe(entries.length);
    expect(view({}).groups).toEqual(SETTINGS_GROUPS.map((g) => g.id));
  });

  it('keeps only changed rows with "changed only"', () => {
    const changed = new Set(['drainMinutes', ENTRY_IDS.panelRead]);
    const v = view({ changedOnly: true, isChanged: (e) => changed.has(e.id) });
    expect([...v.shown].sort()).toEqual([...changed].sort());
    expect(v.groups).toEqual(['automatic', 'maintenance']);
    expect(v.counts.automatic).toBe(1);
    expect(v.total).toBe(2);
  });

  it('never hides a pinned row (an unsaved edit) under the search', () => {
    const pinned = new Set(['cooldownMinutes']);
    expect(ids({ query: 'globalping', pinned })).toContain('cooldownMinutes');
    expect(ids({ changedOnly: true, pinned })).toEqual(['cooldownMinutes']);
    // ...but the group picked still applies without a search.
    expect(ids({ group: 'detection', pinned })).not.toContain('cooldownMinutes');
  });

  it('shows nothing when nothing matches', () => {
    const v = view({ query: 'qqqqzzzz' });
    expect(v.shown.size).toBe(0);
    expect(v.groups).toEqual([]);
    expect(v.total).toBe(0);
  });
});

describe('changedFromDefault', () => {
  const defaults = flattenConfig(EDGE_DEFAULTS);

  it('compares by value, and only paths with a default', () => {
    expect(changedFromDefault(defaults, defaults, ['drainMinutes'])).toBe(false);
    expect(
      changedFromDefault(
        { ...defaults, drainMinutes: (defaults.drainMinutes as number) + 1 },
        defaults,
        ['drainMinutes'],
      ),
    ).toBe(true);
    expect(changedFromDefault({ nope: 1 }, defaults, ['nope'])).toBe(false);
    expect(changedFromDefault(defaults, defaults, [])).toBe(false);
  });

  it('treats arrays and rules by value', () => {
    const zones = { ...defaults, 'names.zones': [...(defaults['names.zones'] as string[])] };
    expect(changedFromDefault(zones, defaults, ['names.zones'])).toBe(false);
    const rule = {
      ...(defaults['render.clients.singbox'] as object),
      maxEntries: 99,
    };
    expect(
      changedFromDefault({ ...defaults, 'render.clients.singbox': rule }, defaults, [
        'render.clients.singbox',
      ]),
    ).toBe(true);
  });
});

describe('fieldDomId', () => {
  it('makes a safe element id', () => {
    expect(fieldDomId('detect.windowMinutes')).toBe('setting-detect-windowMinutes');
    expect(fieldDomId('a b/c')).toBe('setting-a-b-c');
  });
});
