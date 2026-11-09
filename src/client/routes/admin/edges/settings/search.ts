/**
 * What Servers -> Settings shows for a group choice, a search and "Show changed
 * only" (pure; unit-tested in search.test.ts). The page renders a row only when
 * `settingsView` says so, and a group's card only when one of its rows shows.
 *
 * Exports:
 *   normalizeQuery(q)                  lower case, accents dropped, spaces collapsed
 *   entryMatches(entry, query)         every word of the query is in the label, helper,
 *                                      key, path, keywords or group name
 *   changedFromDefault(values, defaults, paths)
 *                                      true when any of `paths` differs from its default
 *   settingsView(entries, opts)        -> { shown, groups, counts, total }
 *   fieldDomId(id)                     the element id of a row (`?field=` scrolls to it)
 */
import { sameValue } from './configDiff';
import { SETTINGS_GROUPS, groupLabel, type GroupChoice, type SettingsGroupId } from './groups';
import type { SettingEntry } from './fields';

export function normalizeQuery(q: string): string {
  return q.normalize('NFKD').replace(/\p{M}/gu, '').toLowerCase().replace(/\s+/g, ' ').trim();
}

const haystack = (e: SettingEntry): string =>
  normalizeQuery(
    [e.label, e.helper, e.id, e.key ?? '', ...(e.keywords ?? []), groupLabel(e.group)].join(
      ' \u0000 ',
    ),
  );

/** Every word of `query` appears in the entry's words (an empty query matches all). */
export function entryMatches(entry: SettingEntry, query: string): boolean {
  const words = normalizeQuery(query).split(' ').filter(Boolean);
  if (words.length === 0) return true;
  const hay = haystack(entry);
  return words.every((w) => hay.includes(w));
}

/** A value differs from its default (a path with no known default never counts). */
export function changedFromDefault(
  values: Readonly<Record<string, unknown>>,
  defaults: Readonly<Record<string, unknown>>,
  paths: readonly string[],
): boolean {
  return paths.some((p) => p in defaults && !sameValue(values[p], defaults[p]));
}

export interface ViewOptions {
  group: GroupChoice;
  query: string;
  changedOnly: boolean;
  /** Whether a row's value differs from its default. */
  isChanged: (entry: SettingEntry) => boolean;
  /** Rows that show whatever the search says (an unsaved or invalid value), within the group choice. */
  pinned?: ReadonlySet<string>;
}

export interface SettingsView {
  /** The ids of the rows to render. */
  shown: Set<string>;
  /** The groups with a row to render, in page order. */
  groups: SettingsGroupId[];
  /** Per group, the rows the search and "changed only" leave (the group choice aside). */
  counts: Record<SettingsGroupId, number>;
  /** The sum of `counts`. */
  total: number;
}

/**
 * A search looks in every group (the group choice applies only without one);
 * "changed only" keeps the rows off their default. A pinned row always shows
 * in its group, so an edit never hides under the filter that is typed next.
 */
export function settingsView(entries: readonly SettingEntry[], opts: ViewOptions): SettingsView {
  const searching = normalizeQuery(opts.query) !== '';
  const counts = Object.fromEntries(SETTINGS_GROUPS.map((g) => [g.id, 0])) as Record<
    SettingsGroupId,
    number
  >;
  const shown = new Set<string>();
  for (const e of entries) {
    const passes = entryMatches(e, opts.query) && (!opts.changedOnly || opts.isChanged(e));
    if (passes) counts[e.group]++;
    const inChoice = searching || opts.group === 'all' || opts.group === e.group;
    if (inChoice && (passes || opts.pinned?.has(e.id))) shown.add(e.id);
  }
  const groups = SETTINGS_GROUPS.map((g) => g.id).filter((g) =>
    entries.some((e) => e.group === g && shown.has(e.id)),
  );
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return { shown, groups, counts, total };
}

/** The element id of a row: `setting-` and the id with every dot made a dash. */
export const fieldDomId = (id: string): string => `setting-${id.replace(/[^A-Za-z0-9_-]/g, '-')}`;
