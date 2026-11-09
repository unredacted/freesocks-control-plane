/**
 * SNIs -> More settings (SniSettings.svelte; pure, unit-tested): the numeric
 * `edge.sni.*` knobs, as data. Three groups, one per block of
 * `PATCH sni/config`: checking SNIs on lists (top level), finding SNIs
 * (`hunt`), and the checks from inside countries (`vantage`). The switches
 * stay on the views they belong to.
 *
 * Bounds and defaults mirror convex/lib/sniConfig.ts (`SNI_BOUNDS`,
 * `SNI_HUNT_BOUNDS`, `SNI_VANTAGE_BOUNDS` and their defaults); sniKnobs.test.ts
 * pins them to it, so a change there fails here until the page says it too.
 * The server clamps whatever it is sent to the same bounds.
 *
 *   KNOB_GROUPS, KNOBS            the catalog
 *   knobValue(view, knob)         a knob's value now
 *   knobError(knob, raw)          why a typed value cannot be saved, or null
 *   groupErrors(group, values)    every reason, by knob id (the cross-field rules too)
 *   groupPatch(group, edits, view) the `PATCH sni/config` body for what changed, or null
 */
import type { SniConfigPatch, SniConfigView } from '../../../../../../shared/contracts/sni';

export type KnobGroup = 'lists' | 'find' | 'checks';

export const KNOB_GROUPS: ReadonlyArray<{ id: KnobGroup; title: string; description: string }> = [
  {
    id: 'lists',
    title: 'Checking SNIs on lists',
    description: 'How often FCP checks the SNIs of every list against their cover site.',
  },
  {
    id: 'find',
    title: 'Finding SNIs',
    description:
      'How far the top-sites search goes, and how fast FCP checks and measures what it finds.',
  },
  {
    id: 'checks',
    title: 'Checks from inside countries',
    description: 'How many checks run, and how much evidence a suggestion needs.',
  },
];

export interface Knob {
  /** `<group>.<key>`: unique across groups. */
  id: string;
  group: KnobGroup;
  /** The key in its block of `SniConfigView` and `SniConfigPatch`. */
  key: string;
  label: string;
  help: string;
  unit: string;
  min: number;
  max: number;
  default: number;
}

const knob = (group: KnobGroup, k: Omit<Knob, 'id' | 'group'>): Knob => ({
  id: `${group}.${k.key}`,
  group,
  ...k,
});

export const KNOBS: readonly Knob[] = [
  // --- checking SNIs on lists (`edge.sni.*`) --------------------------------------------------
  knob('lists', {
    key: 'qualifyPerTick',
    label: 'SNIs checked each run',
    help: 'A run starts every 5 minutes. More finds a failing SNI sooner, with more handshakes to cover sites.',
    unit: 'SNIs',
    min: 1,
    max: 200,
    default: 40,
  }),
  knob('lists', {
    key: 'requalifyHours',
    label: 'Check an SNI again after',
    help: 'A checked SNI is checked against its cover site again after this long.',
    unit: 'hours',
    min: 1,
    max: 720,
    default: 24,
  }),
  knob('lists', {
    key: 'suspendAfterFails',
    label: 'Take an SNI out of use after',
    help: 'An SNI in use that fails this many checks in a row stops being handed out until it passes again.',
    unit: 'failed checks',
    min: 1,
    max: 10,
    default: 2,
  }),
  knob('lists', {
    key: 'reportWindowDays',
    label: 'Member reports count for',
    help: 'How many days of member reports count toward "this SNI looks blocked there". Older counts are deleted.',
    unit: 'days',
    min: 1,
    max: 60,
    default: 14,
  }),
  // --- finding SNIs (`edge.sni.hunt.*`) -------------------------------------------------------
  knob('find', {
    key: 'depth',
    label: 'Top sites searched',
    help: 'How far down the top-sites list a search goes.',
    unit: 'sites',
    min: 1000,
    max: 1_000_000,
    default: 300_000,
  }),
  knob('find', {
    key: 'wwwDepth',
    label: 'Of those, also tried with www.',
    help: 'The top ones whose www. hostname is looked up too. Never more than the sites searched.',
    unit: 'sites',
    min: 0,
    max: 1_000_000,
    default: 100_000,
  }),
  knob('find', {
    key: 'lookupsPerSecond',
    label: 'Lookups a second',
    help: 'DNS lookups during a search. A and AAAA count alike.',
    unit: 'lookups',
    min: 1,
    max: 50,
    default: 20,
  }),
  knob('find', {
    key: 'sweepEveryDays',
    label: 'Search again every',
    help: 'While a network is included, a new top-sites search starts this long after the last one ended.',
    unit: 'days',
    min: 1,
    max: 365,
    default: 30,
  }),
  knob('find', {
    key: 'checksPerTick',
    label: 'Found SNIs checked each run',
    help: 'Each check costs up to three handshakes.',
    unit: 'SNIs',
    min: 1,
    max: 40,
    default: 12,
  }),
  knob('find', {
    key: 'recheckHours',
    label: 'Check a found SNI again after',
    help: 'A checked find is checked again after this long.',
    unit: 'hours',
    min: 6,
    max: 720,
    default: 72,
  }),
  knob('find', {
    key: 'shortlist',
    label: 'Finds measured per network or list',
    help: 'The best finds get timing and country evidence. The last 3 places rotate.',
    unit: 'SNIs',
    min: 4,
    max: 30,
    default: 10,
  }),
  knob('find', {
    key: 'ctRequestsPerHour',
    label: 'Certificate log requests an hour',
    help: 'Whatever their answer. 0 stops reading certificate logs.',
    unit: 'requests',
    min: 0,
    max: 60,
    default: 6,
  }),
  knob('find', {
    key: 'ctPagesPerDomain',
    label: 'Certificate log pages per site',
    help: 'After this many pages, the answer for a site is marked as cut short.',
    unit: 'pages',
    min: 1,
    max: 200,
    default: 20,
  }),
  knob('find', {
    key: 'timingPerHour',
    label: 'Timing measurements an hour',
    help: 'How far each find is from the nodes of its network. 0 stops timing.',
    unit: 'measurements',
    min: 0,
    max: 60,
    default: 6,
  }),
  // --- checks from inside countries (`edge.sni.vantage.*`) ------------------------------------
  knob('checks', {
    key: 'intervalHours',
    label: 'Check an SNI from a country again after',
    help: 'Each SNI is checked from each country at most this often.',
    unit: 'hours',
    min: 6,
    max: 720,
    default: 72,
  }),
  knob('checks', {
    key: 'hourlyBudget',
    label: 'Checks an hour',
    help: 'One SNI, one service, one country each. Real-site checks count too. 0 stops new checks.',
    unit: 'checks',
    min: 0,
    max: 120,
    default: 12,
  }),
  knob('checks', {
    key: 'perCountryLimit',
    label: 'Vantages per check',
    help: 'How many machines in the country each check asks.',
    unit: 'vantages',
    min: 1,
    max: 5,
    default: 3,
  }),
  knob('checks', {
    key: 'batchNames',
    label: 'SNIs per batch',
    help: 'Tried together on one address from one country, a control SNI included.',
    unit: 'SNIs',
    min: 2,
    max: 6,
    default: 3,
  }),
  knob('checks', {
    key: 'windowDays',
    label: 'Results count for',
    help: 'Older results no longer count, and are deleted.',
    unit: 'days',
    min: 1,
    max: 60,
    default: 14,
  }),
  knob('checks', {
    key: 'minVantages',
    label: 'Vantages needed for a suggestion',
    help: 'A suggestion needs results from at least this many machines.',
    unit: 'vantages',
    min: 1,
    max: 20,
    default: 3,
  }),
  knob('checks', {
    key: 'minNetworks',
    label: 'Networks needed for a suggestion',
    help: 'Those machines must be on at least this many different networks.',
    unit: 'networks',
    min: 1,
    max: 10,
    default: 2,
  }),
];

export const knobsOf = (group: KnobGroup): Knob[] => KNOBS.filter((k) => k.group === group);

/** The block of the config view a group reads. */
function block(view: SniConfigView, group: KnobGroup): Record<string, unknown> | undefined {
  if (group === 'lists') return view.config as unknown as Record<string, unknown>;
  if (group === 'find') return view.hunt as unknown as Record<string, unknown> | undefined;
  return view.vantage as unknown as Record<string, unknown>;
}

/** A knob's value now (its default when the server sent no value). */
export function knobValue(view: SniConfigView, k: Knob): number {
  const v = block(view, k.group)?.[k.key];
  return typeof v === 'number' && Number.isFinite(v) ? v : k.default;
}

const fmt = (n: number) => n.toLocaleString('en-US');

/** "Default 40. From 1 to 200." */
export function knobRange(k: Knob): string {
  return `Default ${fmt(k.default)}. From ${fmt(k.min)} to ${fmt(k.max)}.`;
}

/** Why a typed value cannot be saved, or null. Thousands separators are fine. */
export function knobError(k: Knob, raw: string): string | null {
  const s = raw.trim().replace(/[,_\s]/g, '');
  if (!/^\d+$/.test(s)) return `A whole number from ${fmt(k.min)} to ${fmt(k.max)}.`;
  const n = Number(s);
  if (n < k.min || n > k.max) return `A whole number from ${fmt(k.min)} to ${fmt(k.max)}.`;
  return null;
}

const parse = (raw: string) => Number(raw.trim().replace(/[,_\s]/g, ''));

/**
 * Every reason a group cannot be saved, by knob id. `values` holds what each
 * field shows (typed or current).
 */
export function groupErrors(
  group: KnobGroup,
  values: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of knobsOf(group)) {
    const e = knobError(k, values[k.id] ?? '');
    if (e) out[k.id] = e;
  }
  if (group === 'find' && !out['find.depth'] && !out['find.wwwDepth']) {
    if (parse(values['find.wwwDepth'] ?? '') > parse(values['find.depth'] ?? ''))
      out['find.wwwDepth'] = 'No more than the top sites searched.';
  }
  return out;
}

/**
 * The `PATCH sni/config` body for the group's changed fields, or null when
 * nothing changed or a field cannot be saved. `edits` holds typed values by
 * knob id; a field not in it keeps its current value.
 */
export function groupPatch(
  group: KnobGroup,
  edits: Record<string, string>,
  view: SniConfigView,
): SniConfigPatch | null {
  const values: Record<string, string> = {};
  for (const k of knobsOf(group)) values[k.id] = edits[k.id] ?? String(knobValue(view, k));
  if (Object.keys(groupErrors(group, values)).length > 0) return null;
  const changed: Record<string, number> = {};
  for (const k of knobsOf(group)) {
    const n = parse(values[k.id]!);
    if (n !== knobValue(view, k)) changed[k.key] = n;
  }
  if (Object.keys(changed).length === 0) return null;
  if (group === 'lists') return changed as SniConfigPatch;
  if (group === 'find') return { hunt: changed };
  return { vantage: changed };
}

/** How many fields of a group differ from their defaults (the card's "N changed"). */
export function changedFromDefault(group: KnobGroup, view: SniConfigView): number {
  return knobsOf(group).filter((k) => knobValue(view, k) !== k.default).length;
}
