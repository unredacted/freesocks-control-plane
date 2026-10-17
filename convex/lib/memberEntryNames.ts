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
 * node (`splitPanelRemark`, the pinner's own parse, given the entry's own server
 * name as evidence) to a neutral label:
 *
 *   <site name> · <place>            one entry
 *   <site name> · <place> · <code>   several (one per server name)
 *
 * `<place>` is the backend instance's member-facing location label (its first
 * comma segment: "Example City, EX" reads "Example City"), left out when unset.
 * `<code>` is four characters derived from the part of the remark after the
 * node (the server name, `entryKey`) and nothing else, so an entry keeps its
 * label across refreshes, node renames and other entries coming and going.
 * Only when two server names in one body share a code do both carry their
 * longer six-character code instead, again derived from each key alone.
 * Entries that name no node (an edge's rendered label, a group, the backend's
 * placeholder, an operator's own Host remark) are left alone.
 *
 * Groups are named too: the backend's subscription templates
 * (lib/backend/subscriptionTemplates) hold one selector group, named after the
 * backend product ("→ Remnawave"), that apps show like an entry. That group,
 * and any group whose name carries the backend product's name, is renamed to
 *
 *   <site name> Select
 *
 * "Select" because it is the group the member picks a connection in, and it
 * pairs with the edge renderer's url-test group (`edge.render.autoGroupName`,
 * "FreeSocks Auto"); never the bare site name, which the default edge entry
 * label already is. An operator's own groups keep their names, and a new group
 * name never takes a name the body already uses. A relabelled body relabels to
 * itself, so a cached body can go through it again when it is served.
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
import { configServerName, linkRemark, linkServerName, splitPanelRemark } from './nodePinning';

export const DEFAULT_SITE_NAME = 'FreeSocks';
/** Between the label's parts (a middle dot: no comma, no pipe, no dash). */
export const ENTRY_NAME_SEP = ' · ';
const MAX_SITE_NAME = 32;
const MAX_PLACE = 32;
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O, 1/I
const CODE_LENGTH = 4;
// A 32-bit hash holds six characters of a 32-letter alphabet.
const LONG_CODE_LENGTH = 6;

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;
// Names a Clash config resolves without a proxy of that name.
const CLASH_BUILTINS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'];
// The group names of the backend's own subscription templates
// (lib/backend/subscriptionTemplates; a test keeps the two in step).
const TEMPLATE_GROUP_NAMES: ReadonlySet<string> = new Set(['→ Remnawave']);
// The backend product's name, anywhere in a group's name.
const BACKEND_PRODUCT_RE = /remnawave/i;
// sing-box outbound types that are groups.
const SINGBOX_GROUP_TYPES = new Set(['selector', 'urltest']);
// Keys whose values are never an entry or group name, however they read: the
// sing-box template's `cache_file.cache_id` is "remnawave" (a group of that
// name must not rename the cache), and a `path` is a file or URL path.
const NOT_REFERENCES: ReadonlySet<string> = new Set(['cache_id', 'path']);

/** What a member's entry names are built from. */
export interface EntryNaming {
  siteName: string;
  place: string | null;
}

// A UTF-16 surrogate half with no partner: invalid text that
// `encodeURIComponent` throws on.
const LONE_SURROGATE_RE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/**
 * Operator text made safe inside a connection name: no control characters, no
 * comma (a Clash rule splits on it), no pipe (FCP's own remark separator), no
 * lone surrogate, whitespace collapsed, length capped in code points (a cut
 * never splits a character, so the label always encodes).
 */
function cleanPart(v: unknown, max: number): string {
  if (typeof v !== 'string') return '';
  const text = v
    .replace(LONE_SURROGATE_RE, '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f,|]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return Array.from(text).slice(0, max).join('').trim();
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

/** An entry's code: FNV-1a 32 of its key, `length` characters of a 32-letter alphabet. */
export function entryCode(key: string, length = CODE_LENGTH): string {
  let h = 0x811c9dc5;
  for (const b of new TextEncoder().encode(key)) {
    h ^= b;
    h = Math.imul(h, 0x01000193);
  }
  h >>>= 0;
  let out = '';
  for (let i = 0; i < length; i++) {
    out += CODE_ALPHABET[h & 31];
    h >>>= 5;
  }
  return out;
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/** A node-named entry: its current name and the rest of its remark after the node. */
export interface NamedEntry {
  name: string;
  entry: string;
}

/**
 * The new name of every node-named entry, by its old name. `taken` holds every
 * other name the body defines (groups, edge labels, built-ins), which no new
 * name may equal. An entry's code depends on its own key only: the short code,
 * or (when another key in the body has the same short code) its long code. The
 * order of `entries` does not matter; a name that is still not unique (the
 * same server name under two nodes, a taken name) gets `uniqueName`'s ` (2)`,
 * assigned in sorted order.
 */
export function planEntryNames(
  entries: readonly NamedEntry[],
  taken: ReadonlySet<string>,
  naming: EntryNaming,
): Map<string, string> {
  const base = naming.place
    ? `${naming.siteName}${ENTRY_NAME_SEP}${naming.place}`
    : naming.siteName;
  const byName = new Map<string, string>();
  for (const e of entries) if (!byName.has(e.name)) byName.set(e.name, entryKey(e.entry));
  const keysByCode = new Map<string, Set<string>>();
  for (const key of byName.values()) {
    const code = entryCode(key);
    keysByCode.set(code, (keysByCode.get(code) ?? new Set()).add(key));
  }
  const rows = [...byName]
    .map(([name, key]) => {
      const short = entryCode(key);
      const code = keysByCode.get(short)!.size > 1 ? entryCode(key, LONG_CODE_LENGTH) : short;
      return { name, key, code };
    })
    .sort((a, b) => cmp(a.code, b.code) || cmp(a.key, b.key) || cmp(a.name, b.name));
  const used = new Set(taken);
  const plan = new Map<string, string>();
  for (const r of rows) {
    const label = uniqueName(rows.length === 1 ? base : `${base}${ENTRY_NAME_SEP}${r.code}`, used);
    used.add(label);
    plan.set(r.name, label);
  }
  return plan;
}

/** Whether a group is the backend's: a template group, or one named after the backend product. */
export function backendGroupName(name: string): boolean {
  return TEMPLATE_GROUP_NAMES.has(name) || BACKEND_PRODUCT_RE.test(name);
}

/** The name a backend group gets: `<site name> Select`. */
export function memberGroupName(naming: EntryNaming): string {
  return `${naming.siteName} Select`;
}

/** Whether a group already has a member group name (`<site name> Select`, ` (2)`…). */
function hasMemberGroupName(name: string, naming: EntryNaming): boolean {
  const base = memberGroupName(naming);
  return name === base || (name.startsWith(base) && /^ \(\d+\)$/.test(name.slice(base.length)));
}

/**
 * The new name of every backend group (`backendGroupName`) among `groups`, by
 * its old name: the member group name, then ` (2)`, ` (3)` for any further one,
 * the template's group first and the rest in body order. `taken` holds every
 * name the body uses or is given, which no new name may equal. Every other
 * group keeps its name.
 */
export function planGroupNames(
  groups: readonly string[],
  taken: ReadonlySet<string>,
  naming: EntryNaming,
): Map<string, string> {
  const used = new Set(taken);
  const plan = new Map<string, string>();
  const template = (name: string) => TEMPLATE_GROUP_NAMES.has(name);
  for (const name of [...groups.filter(template), ...groups.filter((g) => !template(g))]) {
    // Already renamed (a body relabelled before, a site name that carries
    // the backend product's name): renaming again would only add a suffix.
    if (plan.has(name) || !backendGroupName(name) || hasMemberGroupName(name, naming)) continue;
    const next = uniqueName(memberGroupName(naming), used);
    used.add(next);
    plan.set(name, next);
  }
  return plan;
}

/**
 * Every rename of a body with groups: its node-named entries (`planEntryNames`,
 * with `taken` as it is there), then its backend groups, which take none of the
 * body's names, old or new.
 */
function planWithGroups(
  entries: readonly NamedEntry[],
  groups: readonly string[],
  taken: ReadonlySet<string>,
  naming: EntryNaming,
): Map<string, string> {
  const plan = planEntryNames(entries, taken, naming);
  const used = new Set([...taken, ...entries.map((e) => e.name), ...plan.values()]);
  for (const [from, to] of planGroupNames(groups, used, naming)) plan.set(from, to);
  return plan;
}

/** The node-named entry a name and its server name make, or null. */
function named(name: unknown, serverName: string | null): NamedEntry | null {
  if (typeof name !== 'string') return null;
  const split = splitPanelRemark(name, serverName);
  return split ? { name, entry: split.entry } : null;
}

export interface RelabelResult {
  content: string;
  /** Distinct entry and group names replaced (0 = the body came back verbatim). */
  renamed: number;
}

/**
 * Rename every node-named entry of a member body (link list, base64-wrapped or
 * not; sing-box JSON; Clash / Mihomo YAML; an Xray JSON config list), and every
 * backend group of a sing-box or Clash body. A null naming (off), an unknown
 * shape, a body with nothing to rename, or any parse failure returns the body
 * verbatim.
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
    return { line, cr, remark, node: named(remark, linkServerName(line)) };
  });
  const entries = lines.map((l) => l.node).filter((e): e is NamedEntry => e !== null);
  if (entries.length === 0) return null;
  const taken = new Set(
    lines.filter((l) => l.remark !== null && l.node === null).map((l) => l.remark as string),
  );
  const plan = planEntryNames(entries, taken, naming);
  const joined = lines
    .map(({ line, cr, node }) => {
      const label = node ? plan.get(node.name) : undefined;
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

/** Rename across the whole tree (`NOT_REFERENCES` aside), then prove no old name survives as a reference. */
function renameAll(tree: unknown, plan: Map<string, string>): unknown | null {
  const next = renameRefs(tree, plan, NOT_REFERENCES);
  return mentionsAny(next, new Set(plan.keys()), NOT_REFERENCES) ? null : next;
}

/** sing-box: outbound (and endpoint) tags, group tags, and every reference to them. */
function relabelSingbox(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const cfg = JSON.parse(trimmed) as unknown;
  if (!isObj(cfg) || !Array.isArray(cfg.outbounds)) return null;
  const defs = [
    ...cfg.outbounds,
    ...(Array.isArray(cfg.endpoints) ? (cfg.endpoints as unknown[]) : []),
  ].filter(isObj);
  const nodes = defs.map((o) => named(o.tag, configServerName(o)));
  const entries = nodes.filter((e): e is NamedEntry => e !== null);
  const others = defs.filter((o, i) => nodes[i] === null && typeof o.tag === 'string');
  const taken = new Set(others.map((o) => o.tag as string));
  const groups = others
    .filter((o) => typeof o.type === 'string' && SINGBOX_GROUP_TYPES.has(o.type))
    .map((o) => o.tag as string);
  const plan = planWithGroups(entries, groups, taken, naming);
  if (plan.size === 0) return null;
  const next = renameAll(cfg, plan);
  return next === null ? null : { content: JSON.stringify(next), renamed: plan.size };
}

/** Clash / Mihomo: proxy and group names, and every group member / rule target naming them. */
function relabelClash(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const doc = YAML.parse(trimmed) as unknown;
  if (!isObj(doc) || (!Array.isArray(doc.proxies) && !Array.isArray(doc['proxy-groups'])))
    return null;
  // A key with no entry yet still shows the template's group.
  const proxies = Array.isArray(doc.proxies) ? doc.proxies.filter(isObj) : [];
  const nodes = proxies.map((p) => named(p.name, configServerName(p)));
  const entries = nodes.filter((e): e is NamedEntry => e !== null);
  const groups = (Array.isArray(doc['proxy-groups']) ? (doc['proxy-groups'] as unknown[]) : [])
    .map((g) => (isObj(g) ? g.name : undefined))
    .filter((n): n is string => typeof n === 'string');
  const taken = new Set([
    ...CLASH_BUILTINS,
    ...proxies
      .filter((p, i) => nodes[i] === null && typeof p.name === 'string')
      .map((p) => p.name as string),
    ...groups,
  ]);
  const plan = planWithGroups(entries, groups, taken, naming);
  if (plan.size === 0) return null;
  const next = renameAll(doc, plan);
  return next === null
    ? null
    : { content: YAML.stringify(next, { lineWidth: 0 }), renamed: plan.size };
}

/** Xray JSON (a list of whole client configs): each config's `remarks`. */
function relabelXrayJson(trimmed: string, naming: EntryNaming): RelabelResult | null {
  const list = JSON.parse(trimmed) as unknown;
  if (!Array.isArray(list) || !list.every(isObj)) return null;
  const nodes = list.map((c) => named(c.remarks, xrayServerName(c)));
  const entries = nodes.filter((e): e is NamedEntry => e !== null);
  if (entries.length === 0) return null;
  const taken = new Set(
    list
      .filter((c, i) => nodes[i] === null && typeof c.remarks === 'string')
      .map((c) => c.remarks as string),
  );
  const plan = planEntryNames(entries, taken, naming);
  const next = list.map((c, i) => {
    const label = nodes[i] ? plan.get(nodes[i].name) : undefined;
    return label === undefined ? c : { ...c, remarks: label };
  });
  return { content: JSON.stringify(next), renamed: plan.size };
}

/** The server name an Xray client config's first proxy outbound carries (REALITY or TLS), or null. */
function xrayServerName(config: Obj): string | null {
  const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
  for (const o of outbounds) {
    if (!isObj(o) || !isObj(o.streamSettings)) continue;
    for (const key of ['realitySettings', 'tlsSettings']) {
      const settings = o.streamSettings[key];
      if (isObj(settings) && typeof settings.serverName === 'string' && settings.serverName)
        return settings.serverName;
    }
  }
  return null;
}
