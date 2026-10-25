/**
 * Per-user node pinning for Remnawave subscriptions.
 *
 * The backend serves a mode group-wide subscription (every node's Hosts) as a list of
 * proxy links. Serving it verbatim exposes the whole fleet's endpoints to
 * every user. This module filters that content down to ONE node per
 * subscription, chosen by rendezvous hashing on (pinKey, nodeName):
 *
 *   - deterministic: the same key always lands on the same node while the
 *     node set is unchanged (no server-side state needed),
 *   - stable under rotation: only users pinned to a REMOVED node move — the
 *     rest keep their node (rendezvous property),
 *   - uniform: keys spread across nodes approximately evenly.
 *
 * Node identity comes from the link remark (the backend Host's remark):
 *   <node> | <server name or tag>     FCP's own addresses of a direct node
 *                                     (lib/backend/hostRemark.ts)
 *   <hostname>-<transport>            e.g. xray2-front-mci1-beta-fs-ce-ws (v1 role)
 *   <hostname>-<transport>-<hash6>    (multi-edge: xray2-…-ws-6a536a)
 *   <hostname>-reality                (v1 direct nodes)
 *   <node>-relay-<slot>               an origin's template Host
 *   <node>-relay                      an operator's own Host for a node it fronts
 *                                     by hand (a load balancer it built)
 * so the node name is the part before the separator, or the remark with the
 * transport suffix stripped. All of a node's entries (one per server name, or
 * multi-domain fronting) stay together — pinning is per NODE, not per endpoint.
 *
 * These remarks are infrastructure names. The member-facing body never keeps
 * them: lib/memberEntryNames.ts relabels every entry the parse below
 * recognises, AFTER pinning (and after edge rendering, which may match on them).
 *
 * Three content shapes are understood:
 *   - link lists (optionally base64-wrapped) — filtered line by line;
 *   - sing-box JSON configs (what the backend serves to sing-box User-Agents) —
 *     outbounds are tagged with the same Host remarks, so we drop the other
 *     nodes' outbounds and prune them from selector/urltest groups;
 *   - Clash / Mihomo YAML — `proxies[].name` carries the same remarks; the
 *     other nodes' proxies are dropped and pruned from `proxy-groups`.
 *
 * A body that carries exactly ONE node (the real topology: one mode group per node)
 * is returned verbatim WITH that node reported, so the caller can record the
 * pin and run origin rendering for it. Fail-open everywhere else: unknown
 * content shape, unparseable lines, or zero nodes come back verbatim with
 * `node: null`.
 */
import YAML from 'yaml';
import { remarkTag } from './backend/hostRemark';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { mentionsAny } from './edges/render/refs';
import { parseProxyUri } from './edges/render/uri';

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;
// Known transport suffixes the role appends to Host remarks (xhttp removed
// 2026-07-04 but kept here so legacy remarks still parse), plus the origin-edge
// template Host remark `<node>-relay-<slotKey>` (convex/lib/edges/hosts.ts) and
// the bare `<node>-relay` an operator gives the Host of a front it built by hand:
// a node's origin templates must pin WITH the node, never pass through to all.
const TRANSPORT_SUFFIX_RE = /-(ws|reality|xhttp)(-[0-9a-f]{6})?$|-relay(-[a-z0-9]{1,16})?$/i;

// An FCP address remark (`addressRemark`): a node name (nodeIntents'
// NODE_NAME charset), the ` | ` separator (ADDRESS_SEP), and the server name
// or its short tag.
const ADDRESS_REMARK_RE = /^([A-Za-z0-9 ._-]{3,30}) \| (\S.*)$/;
// What that rest looks like when the entry carries no server name to compare:
// a dotted host name, or the 7-character `remarkTag`.
const DOTTED_HOST_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i;
const REMARK_TAG_RE = /^[0-9a-z]{7}$/;

/**
 * A Host remark split into the node it names and the rest (`entry`: the server
 * name or tag of an FCP address, the transport suffix of a role-written one),
 * or null when the remark names no node (a group, an edge label, a placeholder,
 * an operator's own display remark).
 *
 * `serverName` is the server name the entry itself carries (a link's `sni`,
 * sing-box `tls.server_name`, Clash `servername`): the ` | ` form is FCP's only
 * when its rest IS that name or that name's tag, so an operator's Host remark
 * such as `Region | VLESS` is never read as a node. An entry with no server
 * name to compare must at least carry a rest shaped like one (a dotted host
 * name) or like a tag.
 */
export function splitPanelRemark(
  remark: string,
  serverName?: string | null,
): { node: string; entry: string } | null {
  const fcp = ADDRESS_REMARK_RE.exec(remark);
  if (fcp) {
    const [, node, entry] = fcp;
    const owned = serverName
      ? entry.toLowerCase() === serverName.toLowerCase() || entry === remarkTag(serverName)
      : DOTTED_HOST_RE.test(entry) || REMARK_TAG_RE.test(entry);
    if (owned) return { node, entry };
  }
  const suffix = TRANSPORT_SUFFIX_RE.exec(remark);
  if (!suffix || suffix.index === 0) return null;
  return { node: remark.slice(0, suffix.index), entry: suffix[0].slice(1) };
}

/** A proxy link's remark (its `#fragment`, decoded), or null. */
export function linkRemark(line: string): string | null {
  const hashIdx = line.indexOf('#');
  if (hashIdx < 0 || hashIdx === line.length - 1) return null;
  try {
    return decodeURIComponent(line.slice(hashIdx + 1));
  } catch {
    return null;
  }
}

/** The server name a share link carries (`sni`, else its HTTP `host`), or null. */
export function linkServerName(line: string): string | null {
  const params = parseProxyUri(line)?.params;
  return params?.get('sni') || params?.get('host') || null;
}

/** The server name a sing-box outbound (`tls.server_name`) or a Clash proxy (`servername` / `sni`) carries, or null. */
export function configServerName(entry: Record<string, unknown>): string | null {
  const text = (v: unknown): string | null => (typeof v === 'string' && v ? v : null);
  const tls = entry.tls;
  const fromTls =
    typeof tls === 'object' && tls !== null
      ? text((tls as Record<string, unknown>).server_name)
      : null;
  return fromTls ?? text(entry.servername) ?? text(entry.sni);
}

/** Extract the node name from a proxy link's remark, or null if unparseable. */
export function nodeNameFromLink(line: string): string | null {
  const remark = linkRemark(line);
  return remark === null ? null : nodeNameFromTag(remark, linkServerName(line));
}

/** Extract the node name from a sing-box outbound tag / Clash proxy name (the
 *  backend uses the Host remark verbatim), or null when the name names no node
 *  (selector/urltest groups, direct/block/dns outbounds, edge labels).
 *  `serverName`: the entry's own, when it has one (see `splitPanelRemark`). */
export function nodeNameFromTag(tag: string, serverName?: string | null): string | null {
  return splitPanelRemark(tag, serverName)?.node ?? null;
}

/** FNV-1a 32-bit — small, synchronous, and stable across runs. */
function fnv1a(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** One node, or several (the node a key was pinned to before, plus every node whose delivery gate is closed). */
export type ExcludeNodes = string | readonly string[] | undefined;

/**
 * The nodes that may serve this key at all (freedom modes only through edges:
 * the nodes an edge covers, lib/edges/freedomDelivery.ts). The pick is made
 * among them while one is in the body; otherwise among every node, and the
 * delivery policy refuses what cannot serve.
 */
export type ServableNode = ((node: string) => boolean) | undefined;

function excludedSet(ex: ExcludeNodes): Set<string> {
  return new Set(typeof ex === 'string' ? [ex] : (ex ?? []));
}

/** The node a pin key maps to (highest rendezvous score wins). */
export function pickNode(
  pinKey: string,
  nodes: string[],
  excludeNode?: ExcludeNodes,
  servable?: ServableNode,
): string | null {
  let pool = nodes;
  if (servable) {
    const usable = nodes.filter(servable);
    if (usable.length > 0) pool = usable;
  }
  const ex = excludedSet(excludeNode);
  if (ex.size > 0) {
    const filtered = pool.filter((n) => !ex.has(n));
    // Exclusion never empties the pool (a single-node fleet still serves; a
    // gated node that is the only one is refused by the delivery policy, not here).
    if (filtered.length > 0) pool = filtered;
  }
  let best: string | null = null;
  let bestScore = -1;
  for (const node of pool) {
    const score = fnv1a(`${pinKey}${node}`);
    if (score > bestScore) {
      bestScore = score;
      best = node;
    }
  }
  return best;
}

export interface PinResult {
  content: string;
  node: string | null;
}

/**
 * Filter mode group-wide subscription content down to the lines of the single node
 * `pinKey` maps to. `excludeNode` (the node the key was PREVIOUSLY pinned to,
 * e.g. before a regenerate) is avoided when others exist, so a regenerated
 * key lands on a different node. `servable`, when given, narrows the pick to
 * the nodes that may serve the key while one of them is in the body (before
 * `excludeNode` is applied). Returns the (possibly re-encoded) content
 * unchanged when there is nothing to filter (unknown format, zero nodes, or
 * a single node — which is still REPORTED as the pin) or on any parse error,
 * plus the node that was picked (null when no node could be identified).
 */
export function pinSubscriptionToNode(
  content: string,
  pinKey: string,
  excludeNode?: ExcludeNodes,
  servable?: ServableNode,
): PinResult {
  try {
    const trimmed = content.trim();
    if (!trimmed || !pinKey) return { content, node: null };

    // JSON bodies: pin sing-box configs by outbound tag; anything else JSON
    // (v2ray-json, an error envelope) passes through verbatim.
    if (trimmed.startsWith('{')) {
      return finish(content, pinSingboxConfig(trimmed, pinKey, excludeNode, servable));
    }
    // HTML landing pages pass through — no pinning is defined for them.
    if (trimmed.startsWith('<')) return { content, node: null };
    // Clash / Mihomo YAML: pin by proxy name.
    if (/^proxies:/m.test(trimmed) || /^proxy-groups:/m.test(trimmed)) {
      return finish(content, pinClashConfig(trimmed, pinKey, excludeNode, servable));
    }

    // Subscription bodies are commonly base64-encoded line lists; decode when
    // that is what we have, re-encode at the end.
    let encoded = false;
    let body = trimmed;
    if (!PROXY_LINE_RE.test(trimmed)) {
      const decoded = decodeBase64Loose(trimmed);
      if (decoded !== null && PROXY_LINE_RE.test(decoded.trim())) {
        encoded = true;
        body = decoded;
      }
    }

    const byNode = new Map<string, string[]>();
    const passthrough: string[] = [];
    for (const rawLine of body.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;
      if (PROXY_LINE_RE.test(line)) {
        const node = nodeNameFromLink(line);
        if (node) {
          const list = byNode.get(node) ?? [];
          list.push(line);
          byNode.set(node, list);
          continue;
        }
      }
      passthrough.push(line);
    }

    // No identifiable node — serve verbatim, nothing to pin.
    if (byNode.size === 0) return { content, node: null };
    // Exactly one node: the body IS that node's; report it, content verbatim.
    if (byNode.size === 1) return { content, node: [...byNode.keys()][0] };

    const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode, servable);
    if (!chosen) return { content, node: null };

    const out = [...passthrough, ...(byNode.get(chosen) ?? [])].join('\n');
    return { content: encoded ? encodeBase64(out) : out, node: chosen };
  } catch {
    return { content, node: null };
  }
}

/** A config pinner's outcome: null = unknown shape (verbatim, no node);
 *  `content` undefined = single node (verbatim WITH the node). */
type ConfigPin = { node: string; content?: string } | null;

/** An address no client can use: what a backend's placeholder entries point at. */
function placeholderHost(host: unknown): boolean {
  if (typeof host !== 'string') return false;
  const h = host
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return h === '0.0.0.0' || h === '::' || h === '::1' || /^127\./.test(h) || h === 'localhost';
}

/** Outbound / proxy types that are not a proxy entry (routing helpers). */
const NON_PROXY_TYPES = new Set([
  'direct',
  'block',
  'dns',
  'selector',
  'urltest',
  'select',
  'url-test',
  'fallback',
  'load-balance',
  'relay',
]);

/**
 * Whether a body is the backend's PLACEHOLDER for a key whose node serves
 * nothing yet: empty, or a shape the pinner understands whose every proxy
 * entry names no node AND points at an unusable address (0.0.0.0, a
 * loopback). A body with any real entry is not, whatever its remarks say, and
 * neither is a shape the pinner does not know (HTML, another JSON, free text).
 */
export function nodelessBody(content: string): boolean {
  return placeholderVerdict(content).nodeless;
}

/**
 * The backend's placeholder for a key that serves nothing (an expired or
 * disabled key): at least one proxy entry, every one naming no node AND at an
 * unusable address. Unlike `nodelessBody`, an empty body is not one: handing
 * an empty body out would wipe a client's configuration. A link list with any
 * other line is not one either: delivery hands the body out whole, so no line
 * may pass unread. (A config's other fields are the caller's leak scan.)
 */
export function placeholderBody(content: string): boolean {
  const v = placeholderVerdict(content, true);
  return v.nodeless && v.entries > 0;
}

/** `nodelessBody`'s verdict, with how many proxy entries it judged. */
function placeholderVerdict(
  content: string,
  /** Every non-empty line of a link list must be a proxy entry (no other line passes unread). */
  strict = false,
): { nodeless: boolean; entries: number } {
  const no = { nodeless: false, entries: 0 };
  try {
    const trimmed = content.trim();
    if (!trimmed) return { nodeless: true, entries: 0 };
    if (trimmed.startsWith('{')) {
      const cfg = JSON.parse(trimmed) as { outbounds?: unknown };
      if (!cfg || typeof cfg !== 'object' || !Array.isArray(cfg.outbounds)) return no;
      return placeholderEntries(cfg.outbounds, 'tag', 'server');
    }
    if (trimmed.startsWith('<')) return no;
    if (/^proxies:/m.test(trimmed) || /^proxy-groups:/m.test(trimmed)) {
      const doc = YAML.parse(trimmed) as { proxies?: unknown } | null;
      if (!doc || typeof doc !== 'object' || !Array.isArray(doc.proxies)) return no;
      return placeholderEntries(doc.proxies, 'name', 'server');
    }
    let body = trimmed;
    if (!PROXY_LINE_RE.test(trimmed)) {
      const decoded = decodeBase64Loose(trimmed);
      if (decoded === null) return no;
      if (!decoded.trim()) return { nodeless: true, entries: 0 };
      if (!PROXY_LINE_RE.test(decoded.trim())) return no;
      body = decoded;
    }
    const all = body
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    const lines = all.filter((l) => PROXY_LINE_RE.test(l));
    if (strict && lines.length !== all.length) return no;
    return {
      nodeless:
        lines.length > 0 &&
        lines.every((l) => nodeNameFromLink(l) === null && placeholderHost(parseProxyUri(l)?.host)),
      entries: lines.length,
    };
  } catch {
    return no;
  }
}

/** Every proxy entry of a config list is a placeholder (no node, unusable address); none at all counts too. */
function placeholderEntries(
  entries: unknown[],
  nameKey: 'tag' | 'name',
  hostKey: 'server',
): { nodeless: boolean; entries: number } {
  let proxies = 0;
  for (const e of entries) {
    if (typeof e !== 'object' || e === null) return { nodeless: false, entries: proxies };
    const o = e as Record<string, unknown>;
    if (typeof o.type === 'string' && NON_PROXY_TYPES.has(o.type)) continue;
    proxies++;
    const name = o[nameKey];
    if (typeof name === 'string' && nodeNameFromTag(name, configServerName(o)))
      return { nodeless: false, entries: proxies };
    if (!placeholderHost(o[hostKey])) return { nodeless: false, entries: proxies };
  }
  return { nodeless: true, entries: proxies };
}

function finish(original: string, pin: ConfigPin): PinResult {
  if (!pin) return { content: original, node: null };
  return { content: pin.content ?? original, node: pin.node };
}

/** Group named entries by node; null when any entry is not an object. */
function groupByNode(entries: unknown[], nameKey: 'tag' | 'name'): Map<string, string[]> | null {
  const byNode = new Map<string, string[]>();
  for (const e of entries) {
    if (typeof e !== 'object' || e === null) return null;
    const name = (e as Record<string, unknown>)[nameKey];
    if (typeof name !== 'string') continue;
    const node = nodeNameFromTag(name, configServerName(e as Record<string, unknown>));
    if (!node) continue;
    const list = byNode.get(node) ?? [];
    list.push(name);
    byNode.set(node, list);
  }
  return byNode;
}

/** Pick the node and collect the names of every OTHER node (to drop). */
function chooseAndDrop(
  byNode: Map<string, string[]>,
  pinKey: string,
  excludeNode?: ExcludeNodes,
  servable?: ServableNode,
): { chosen: string; dropped: Set<string> } | null {
  const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode, servable);
  if (!chosen) return null;
  const dropped = new Set<string>();
  for (const [node, names] of byNode) {
    if (node !== chosen) for (const n of names) dropped.add(n);
  }
  return { chosen, dropped };
}

/**
 * Pin a sing-box JSON config to one node. The backend's sing-box template emits
 * one outbound per Host, tagged with the Host remark (the same names the link
 * list carries), plus selector/urltest groups whose `outbounds` arrays list
 * those tags. We keep the chosen node's outbounds, drop the rest, and prune
 * the dropped tags from every group (fixing a group `default` that pointed at
 * a dropped tag). Returns null — meaning "serve verbatim, no node" — whenever
 * the shape isn't the one we understand: not a config, no node tags, a group
 * that would end up empty, or a dropped tag still referenced elsewhere (route
 * rules) after pruning. Emitting a broken config is the one unacceptable
 * outcome; the whole-fleet fallback merely weakens endpoint hygiene.
 */
function pinSingboxConfig(
  trimmed: string,
  pinKey: string,
  excludeNode?: ExcludeNodes,
  servable?: ServableNode,
): ConfigPin {
  let cfg: unknown;
  try {
    cfg = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof cfg !== 'object' || cfg === null) return null;
  const outbounds = (cfg as { outbounds?: unknown }).outbounds;
  if (!Array.isArray(outbounds)) return null;

  const byNode = groupByNode(outbounds, 'tag');
  if (!byNode || byNode.size === 0) return null;
  if (byNode.size === 1) return { node: [...byNode.keys()][0] };

  const pick = chooseAndDrop(byNode, pinKey, excludeNode, servable);
  if (!pick) return null;
  const { chosen, dropped } = pick;

  const kept: unknown[] = [];
  for (const ob of outbounds) {
    const o = ob as Record<string, unknown>;
    if (typeof o.tag === 'string' && dropped.has(o.tag)) continue;
    if (!Array.isArray(o.outbounds)) {
      kept.push(ob);
      continue;
    }
    // A selector/urltest group: prune dropped members.
    const members = o.outbounds.filter((m) => !(typeof m === 'string' && dropped.has(m)));
    if (members.length === 0) return null; // group would break — fail open
    const next: Record<string, unknown> = { ...o, outbounds: members };
    if (typeof o.default === 'string' && dropped.has(o.default)) next.default = members[0];
    kept.push(next);
  }

  // A dropped tag surviving ANYWHERE in the pinned config — route/dns rules,
  // a kept outbound's `detour`, anything — would be a dangling reference, so
  // scan the FINAL config structurally (kept groups were pruned above, so no
  // legitimate mention remains) and serve verbatim on any hit.
  const pinned = { ...(cfg as Record<string, unknown>), outbounds: kept };
  if (mentionsAny(pinned, dropped)) return null;
  return { node: chosen, content: JSON.stringify(pinned) };
}

/**
 * Pin a Clash / Mihomo YAML config to one node: `proxies[].name` carries the
 * Host remark; `proxy-groups[].proxies` lists those names; `rules` target
 * group (or proxy) names. Same contract as the sing-box pinner: keep the chosen
 * node's proxies, prune the others from every group, and fail open (null) on
 * an empty group or a surviving reference. Comments are lost in the YAML round
 * trip (the backend's template comments are operator notes, not client input).
 */
function pinClashConfig(
  trimmed: string,
  pinKey: string,
  excludeNode?: ExcludeNodes,
  servable?: ServableNode,
): ConfigPin {
  let doc: unknown;
  try {
    doc = YAML.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return null;
  const proxies = (doc as { proxies?: unknown }).proxies;
  if (!Array.isArray(proxies)) return null;

  const byNode = groupByNode(proxies, 'name');
  if (!byNode || byNode.size === 0) return null;
  if (byNode.size === 1) return { node: [...byNode.keys()][0] };

  const pick = chooseAndDrop(byNode, pinKey, excludeNode, servable);
  if (!pick) return null;
  const { chosen, dropped } = pick;

  const keptProxies = proxies.filter(
    (p) =>
      !(
        typeof (p as { name?: unknown }).name === 'string' &&
        dropped.has((p as { name: string }).name)
      ),
  );
  const rawGroups = (doc as Record<string, unknown>)['proxy-groups'];
  const groups = Array.isArray(rawGroups) ? rawGroups : [];
  const keptGroups: unknown[] = [];
  for (const g of groups) {
    if (
      typeof g !== 'object' ||
      g === null ||
      !Array.isArray((g as { proxies?: unknown }).proxies)
    ) {
      keptGroups.push(g);
      continue;
    }
    const members = (g as { proxies: unknown[] }).proxies.filter(
      (m) => !(typeof m === 'string' && dropped.has(m)),
    );
    if (members.length === 0) return null; // group would break — fail open
    keptGroups.push({ ...(g as Record<string, unknown>), proxies: members });
  }
  const pinned: Record<string, unknown> = {
    ...(doc as Record<string, unknown>),
    proxies: keptProxies,
  };
  if (Array.isArray(rawGroups)) pinned['proxy-groups'] = keptGroups;
  if (mentionsAny(pinned, dropped)) return null;
  return { node: chosen, content: YAML.stringify(pinned, { lineWidth: 0 }) };
}
