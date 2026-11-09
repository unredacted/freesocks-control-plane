/**
 * Mode pools and the mode groups behind them (pure; unit-tested in
 * modePools.test.ts). A connection mode issues new keys into a pool of mode
 * group uuids. The uuids a mode holds are write-only, so the client never
 * reads them back: names come from what it does know, the mode groups each
 * backend reports (`ServerTree.modeGroups`), the uuids typed in the editor,
 * the node load rows (by uuid) and each backend's pool check (counts and the
 * names of groups without transports).
 *
 * Exports:
 *   UUID_RE, parseGroupList(text)        the editor's input: one uuid per line (commas too), deduped
 *   indexModeGroups(trees)               lower-case uuid -> the backends' groups with that uuid
 *   readPoolLines(text, index)           each typed line, with the group it names or why not
 *   poolSpread(modeId, checks)           where a mode's bound groups were found, per backend
 */
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** One uuid per line (commas also accepted); trims and dedupes. */
export function parseGroupList(text: string): string[] {
  const out: string[] = [];
  for (const raw of text.split(/[\n,]/)) {
    const s = raw.trim();
    if (s && !out.includes(s)) out.push(s);
  }
  return out;
}

/** A mode group as one backend reports it. */
export interface GroupRef {
  uuid: string;
  name: string;
  backendSlug: string;
  backendName: string;
  membersCount: number | null;
}

/** What indexing needs of a backend's tree (`ServerTree`). */
export interface TreeGroups {
  instance: { slug: string; name: string };
  modeGroups: ReadonlyArray<{ groupUuid: string; name: string; membersCount: number | null }>;
}

export type GroupIndex = ReadonlyMap<string, readonly GroupRef[]>;

export function indexModeGroups(trees: readonly TreeGroups[]): GroupIndex {
  const out = new Map<string, GroupRef[]>();
  for (const t of trees) {
    for (const g of t.modeGroups) {
      const key = g.groupUuid.toLowerCase();
      const refs = out.get(key) ?? [];
      refs.push({
        uuid: g.groupUuid,
        name: g.name,
        backendSlug: t.instance.slug,
        backendName: t.instance.name,
        membersCount: g.membersCount,
      });
      out.set(key, refs);
    }
  }
  return out;
}

export type PoolLine =
  | { text: string; kind: 'group'; groups: readonly GroupRef[] }
  | { text: string; kind: 'unknown' }
  | { text: string; kind: 'invalid' };

/** Each line typed in a pool editor, read against the backends' mode groups. */
export function readPoolLines(text: string, index: GroupIndex): PoolLine[] {
  return parseGroupList(text).map((t) => {
    if (!UUID_RE.test(t)) return { text: t, kind: 'invalid' };
    const groups = index.get(t.toLowerCase());
    return groups && groups.length > 0
      ? { text: t, kind: 'group', groups }
      : { text: t, kind: 'unknown' };
  });
}

/** One backend's pool check (`PlacementValidation`) with the backend it was made on. */
export interface PoolCheck {
  slug: string;
  name: string;
  modes: ReadonlyArray<{
    modeSlug: string;
    modeGroups: number;
    unknownHere: number;
    withoutTransports: readonly string[];
  }>;
}

export interface PoolSpread {
  /** How many groups the mode's pool holds (0 = none bound, or no backend checked it). */
  size: number;
  /** The backends holding some of them. */
  found: Array<{ slug: string; name: string; count: number }>;
  /** Groups found on no backend checked. */
  missing: number;
  /** Groups found but granting no transport, by name. */
  withoutTransports: Array<{ slug: string; name: string; group: string }>;
}

export function poolSpread(modeId: string, checks: readonly PoolCheck[]): PoolSpread {
  let size = 0;
  const found: PoolSpread['found'] = [];
  const withoutTransports: PoolSpread['withoutTransports'] = [];
  for (const c of checks) {
    const m = c.modes.find((x) => x.modeSlug === modeId);
    if (!m) continue;
    size = Math.max(size, m.modeGroups);
    const here = m.modeGroups - m.unknownHere;
    if (here > 0) found.push({ slug: c.slug, name: c.name, count: here });
    for (const group of m.withoutTransports)
      withoutTransports.push({ slug: c.slug, name: c.name, group });
  }
  const seen = found.reduce((n, f) => n + f.count, 0);
  return { size, found, missing: Math.max(0, size - seen), withoutTransports };
}
