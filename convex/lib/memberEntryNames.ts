/**
 * Member-facing entry names (pure; unit-tested).
 *
 * The backend names every entry of a subscription body after the Host it comes
 * from, and FCP's own Host remarks name the node and the server name
 * (`<node> | <server name>`, lib/backend/hostRemark.ts; older role-written
 * remarks `<node>-reality`, `<node>-ws-<hash>`, `<node>-relay-<slot>`). Those
 * names become the connection names in every member's app (a link's
 * `#remark`, a sing-box outbound tag, a Clash proxy name, an Xray config's
 * `remarks`), so a member, or a censor with a free account, would read the
 * fleet's internal names. This module renames every entry whose name names a
 * node (`splitPanelRemark`, the pinner's own parse) to a neutral label:
 *
 *   <site name> · <place>            one entry
 *   <site name> · <place> · <code>   several (one per server name)
 *
 * `<place>` is the backend instance's member-facing location label (its first
 * comma segment: "Example City, EX" reads "Example City"), left out when unset.
 * `<code>` is three characters derived from the part of the remark after the
 * node (the server name, `entryKey`), so an entry keeps its label across
 * refreshes, node renames and other entries coming and going; two entries whose codes
 * collide are told apart deterministically (`uniqueName`). Entries that name
 * no node (an edge's rendered label, a group, the backend's placeholder) are
 * left alone.
 *
 * It runs on the body the member receives, AFTER node pinning and edge
 * rendering: both read the original names. References follow the rename
 * (sing-box selector/urltest members, `default`, `route.final`, rule
 * `outbound`s, `detour`s; Clash proxy-group members and rule targets), via the
 * structural walk in edges/render/refs.ts. Fail-open like the pinner: a body
 * this module cannot read comes back verbatim (emitting a broken config is the
 * one unacceptable outcome; the names are a privacy weakening, not a break).
 */
import YAML from 'yaml';
import { remarkTag } from './backend/hostRemark';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { mentionsAny, renameRefs, uniqueName } from './edges/render/refs';
import { linkRemark, splitPanelRemark } from './nodePinning';

export const DEFAULT_SITE_NAME = 'FreeSocks';
/** Between the label's parts (a middle dot: no comma, no pipe, no dash). */
export const ENTRY_NAME_SEP = ' · ';
const MAX_SITE_NAME = 32;
const MAX_PLACE = 32;
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I
const CODE_LENGTH = 3;

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;
// Names a Clash config resolves without a proxy of that name.
const CLASH_BUILTINS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'];

/** What a member's entry names are built from. */
export interface EntryNaming {
  siteName: string;
  place: string | null;
}

/**
 * Operator text made safe inside a connection name: no control characters, no
 * comma (a Clash rule splits on it) and no pipe (FCP's own remark separator),
 * whitespace collapsed, length capped.
 */
function cleanPart(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  return (
    v
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u001f\u007f,|]/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, max)
      .trim()
  );
}

/** The site name members see (`subscription.siteName`), with the built-in default. */
export function memberSiteName(v: unknown): string {
  return cleanPart(v, MAX_SITE_NAME) || DEFAULT_SITE_NAME;
}

/** The place part of a label: a location label's first comma segment, or null. */
export function memberPlace(locationLabel: unknown): string | null {
  if (typeof locationLabel !== 'string') return null;
  return cleanPart(locationLabel.split(',')[0], MAX_PLACE) || null;
}

/**
 * The naming for one body from the resolved settings and the backend instance's
 * location label; null when the operator turned it off (`subscription.entryNames`
 * false). Any other stored value counts as on: the default is the private one.
 */
export function entryNamingFrom(
  settings: Record<string, unknown>,
  locationLabel: string | null | undefined,
): EntryNaming | null {
  if (settings['subscription.entryNames'] === false) return null;
  return {
    siteName: memberSiteName(settings['subscription.siteName']),
    place: memberPlace(locationLabel),
  };
}

/**
 * What an entry's code is derived from: the part of its remark after the node.
 * An FCP address remark carries the server name, or the server name's tag when
 * the whole would not fit (`addressRemark`); a server name is reduced to that
 * same tag, so the key does not depend on the node name's length (a rename).
 * Tags and role suffixes (`reality`, `ws-6a536a`) never contain a dot.
 */
export function entryKey(remarkRest: string): string {
  return remarkRest.includes('.') ? remarkTag(remarkRest) : remarkRest.toLowerCase();
}

/** The short code an entry is told apart by: FNV-1a 32 of its key, 3 chars of a 32-letter alphabet. */
export function entryCode(key: string): string {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(key)) {
    h ^= b;
    h = Math.imul(h, 0x01000193);
  }
  h >>>= 0;
  let out = '';
  for (let i = 0; i < CODE_LENGTH; i++) {
    out += CODE_ALPHABET[h & 31];
    h >>>= 5;
  }
  return out;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The new name of every node-named entry, by its old name. `names` are the
 * distinct names in the body that name a node; `taken` every other name the
 * body defines (groups, edge labels, built-ins), which no new name may equal.
 * The order of `names` does not matter: the assignment is sorted by code, then
 * by the entry's key, then by the old name.
 */
export function planEntryNames(
  names: readonly string[],
  taken: ReadonlySet<string>,
  naming: EntryNaming,
): Map<string, string> {
  const base = naming.place
    ? `${naming.siteName}${ENTRY_NAME_SEP}${naming.place}`
    : naming.siteName;
  const rows = [...new Set(names)]
    .map((name) => {
      const entry = entryKey(splitPanelRemark(name)?.entry ?? name);
      return { name, entry, code: entryCode(entry) };
    })
    .sort((a, b) => cmp(a.code, b.code) || cmp(a.entry, b.entry) || cmp(a.name, b.name));
  const used = new Set(taken);
  const plan = new Map<string, string>();
  for (const r of rows) {
    const label = uniqueName(rows.length === 1 ? base : `${base}${ENTRY_NAME_SEP}${r.code}`, used);
    used.add(label);
    plan.set(r.name, label);
  }
  return plan;
}

const namesNode = (name: unknown): name is string =>
  typeof name === 'string' && splitPanelRemark(name) !== null;

export interface RelabelResult {
  content: string;
  /** Distinct entry names replaced (0 = the body came back verbatim). */
  renamed: number;
}

/**
 * Rename every node-named entry of a member body (link list, base64-wrapped or
 * not; sing-box JSON; Clash / Mihomo YAML; an Xray JSON config list). A null
 * naming (off), an unknown shape, a body with no node-named entry, or any
 * parse failure returns the body verbatim.
 */
export function relabelMemberEntries(content: string, naming: EntryNaming | null): RelabelResult {
  const verbatim = { content, renamed: 0 };
  if (!naming) return verbatim;
  try {
    const trimmed = content.trim();
    if (!trimmed || trimmed.startsWith('<')) return verbatim;
    const out = trimmed.startsWith('{')
      ? relabelSingbox(trimmed, naming)
      : trimmed.startsWith('[')
        ? relabelXrayJson(trimmed, naming)
        : /^proxies:/m.test(trimmed) || /^proxy-groups:/m.test(trimmed)
          ? relabelClash(trimmed, naming)
          : relabelLinks(trimmed, naming);
    return out ?? verbatim;
  } catch {
    return verbatim;
  }
}

/** Share links, one per line (CRLF kept), optionally base64-wrapped. */
function relabelLinks(trimmed: string, naming: EntryNaming): RelabelResult | null {
  let encoded = false;
  let text = trimmed;
  if (!PROXY_LINE_RE.test(trimmed)) {
    const decoded = decodeBase64Loose(trimmed);
    if (decoded === null || !PROXY_LINE_RE.test(decoded.trim())) return null;
    encoded = true;
    text = decoded;
  }
  const lines = text.split('\n').map((raw) => {
    const cr = raw.endsWith('\r');
    const line = cr ? raw.slice(0, -1) : raw;
    const remark = PROXY_LINE_RE.test(line.trim()) ? linkRemark(line) : null;
    return { line, cr, remark };
  });
  const names = lines.map((l) => l.remark).filter(namesNode);
  if (names.length === 0) return null;
  const taken = new Set(
    lines.map((l) => l.remark).filter((r): r is string => r !== null && !namesNode(r)),
  );
  const plan = planEntryNames(names, taken, naming);
  const joined = lines
    .map(({ line, cr, remark }) => {
      const label = remark === null ? undefined : plan.get(remark);
      const next =
        label === undefined
          ? line
          : `${line.slice(0, line.indexOf('#'))}#${encodeURIComponent(label)}`;
      return cr ? `${next}\r` : next;
    })
    .join('\n');
  return { content: encoded ? encodeBase64(joined) : joined, renamed: plan.size };
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Rename across the whole tree, then prove no old name survives anywhere. */
function renameAll(tree: unknown, plan: Map<string, string>): unknown | null {
  const next = renameRefs(tree, plan);
  return mentionsAny(next, new Set(plan.keys())) ? null : next;
}

/** sing-box: outbound (and endpoint) tags, and every reference to them. */
function relabelSingbox(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const cfg = JSON.parse(trimmed) as unknown;
  if (!isObj(cfg) || !Array.isArray(cfg.outbounds)) return null;
  const tags = [
    ...cfg.outbounds,
    ...(Array.isArray(cfg.endpoints) ? (cfg.endpoints as unknown[]) : []),
  ].map((o) => (isObj(o) ? o.tag : undefined));
  const names = tags.filter(namesNode);
  if (names.length === 0) return null;
  const taken = new Set(tags.filter((t): t is string => typeof t === 'string' && !namesNode(t)));
  const plan = planEntryNames(names, taken, naming);
  const next = renameAll(cfg, plan);
  return next === null ? null : { content: JSON.stringify(next), renamed: plan.size };
}

/** Clash / Mihomo: proxy names, and every group member / rule target naming them. */
function relabelClash(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const doc = YAML.parse(trimmed) as unknown;
  if (!isObj(doc) || !Array.isArray(doc.proxies)) return null;
  const proxyNames = doc.proxies.map((p) => (isObj(p) ? p.name : undefined));
  const names = proxyNames.filter(namesNode);
  if (names.length === 0) return null;
  const groups = Array.isArray(doc['proxy-groups']) ? (doc['proxy-groups'] as unknown[]) : [];
  const taken = new Set([
    ...CLASH_BUILTINS,
    ...proxyNames.filter((n): n is string => typeof n === 'string' && !namesNode(n)),
    ...groups
      .map((g) => (isObj(g) ? g.name : undefined))
      .filter((n): n is string => typeof n === 'string'),
  ]);
  const plan = planEntryNames(names, taken, naming);
  const next = renameAll(doc, plan);
  return next === null
    ? null
    : { content: YAML.stringify(next, { lineWidth: 0 }), renamed: plan.size };
}

/** Xray JSON (a list of whole client configs): each config's `remarks`. */
function relabelXrayJson(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const list = JSON.parse(trimmed) as unknown;
  if (!Array.isArray(list) || !list.every(isObj)) return null;
  const remarks = list.map((c) => c.remarks);
  const names = remarks.filter(namesNode);
  if (names.length === 0) return null;
  const taken = new Set(remarks.filter((r): r is string => typeof r === 'string' && !namesNode(r)));
  const plan = planEntryNames(names, taken, naming);
  const next = list.map((c) => {
    const label = typeof c.remarks === 'string' ? plan.get(c.remarks) : undefined;
    return label === undefined ? c : { ...c, remarks: label };
  });
  return { content: JSON.stringify(next), renamed: plan.size };
}
