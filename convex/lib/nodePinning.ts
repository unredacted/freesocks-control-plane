/**
 * Per-user node pinning for Remnawave subscriptions.
 *
 * The panel serves a squad-wide subscription (every node's Hosts) as a list of
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
 * Node identity comes from the link remark, which the Ansible role writes as
 *   <hostname>-<transport>            e.g. xray2-front-mci1-beta-fs-ce-ws
 *   <hostname>-<transport>-<hash6>    (multi-edge: xray2-…-ws-6a536a)
 *   <hostname>-reality                (direct nodes)
 * so the node name is the remark with the transport suffix stripped. All of a
 * node's edges (multi-domain fronting) stay together — pinning is per NODE,
 * not per endpoint.
 *
 * Three content shapes are understood:
 *   - link lists (optionally base64-wrapped) — filtered line by line;
 *   - sing-box JSON configs (what the panel serves to sing-box User-Agents) —
 *     outbounds are tagged with the same Host remarks, so we drop the other
 *     nodes' outbounds and prune them from selector/urltest groups;
 *   - Clash / Mihomo YAML — `proxies[].name` carries the same remarks; the
 *     other nodes' proxies are dropped and pruned from `proxy-groups`.
 *
 * A body that carries exactly ONE node (the real topology: one squad per node)
 * is returned verbatim WITH that node reported, so the caller can record the
 * pin and run relay rendering for it. Fail-open everywhere else: unknown
 * content shape, unparseable lines, or zero nodes come back verbatim with
 * `node: null`.
 */
import YAML from 'yaml';
import { decodeBase64Loose } from './edges/render/base64';
import { mentionsAny } from './edges/render/refs';

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;
// Known transport suffixes the role appends to Host remarks (xhttp removed
// 2026-07-04 but kept here so legacy remarks still parse), plus the relay-edge
// template Host remark `<node>-relay-<slotKey>` (convex/lib/edges/hosts.ts):
// a node's relay templates must pin WITH the node, never pass through to all.
const TRANSPORT_SUFFIX_RE = /-(ws|reality|xhttp)(-[0-9a-f]{6})?$|-relay-[a-z0-9]{1,16}$/i;

/** Extract the node name from a proxy link's remark, or null if unparseable. */
export function nodeNameFromLink(line: string): string | null {
  const hashIdx = line.indexOf('#');
  if (hashIdx < 0 || hashIdx === line.length - 1) return null;
  let remark: string;
  try {
    remark = decodeURIComponent(line.slice(hashIdx + 1));
  } catch {
    return null;
  }
  const node = remark.replace(TRANSPORT_SUFFIX_RE, '');
  return node.length > 0 && node !== remark ? node : null;
}

/** Extract the node name from a sing-box outbound tag / Clash proxy name (the
 *  panel uses the Host remark verbatim), or null when the name carries no
 *  transport suffix (selector/urltest groups, direct/block/dns outbounds). */
export function nodeNameFromTag(tag: string): string | null {
  const node = tag.replace(TRANSPORT_SUFFIX_RE, '');
  return node.length > 0 && node !== tag ? node : null;
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

/** The node a pin key maps to (highest rendezvous score wins). */
export function pickNode(pinKey: string, nodes: string[], excludeNode?: string): string | null {
  let pool = nodes;
  if (excludeNode) {
    const filtered = nodes.filter((n) => n !== excludeNode);
    // Exclusion never empties the pool (a single-node fleet still serves).
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
 * Filter squad-wide subscription content down to the lines of the single node
 * `pinKey` maps to. `excludeNode` (the node the key was PREVIOUSLY pinned to,
 * e.g. before a regenerate) is avoided when others exist, so a regenerated
 * key lands on a different node. Returns the (possibly re-encoded) content
 * unchanged when there is nothing to filter (unknown format, zero nodes, or
 * a single node — which is still REPORTED as the pin) or on any parse error,
 * plus the node that was picked (null when no node could be identified).
 */
export function pinSubscriptionToNode(
  content: string,
  pinKey: string,
  excludeNode?: string,
): PinResult {
  try {
    const trimmed = content.trim();
    if (!trimmed || !pinKey) return { content, node: null };

    // JSON bodies: pin sing-box configs by outbound tag; anything else JSON
    // (v2ray-json, an error envelope) passes through verbatim.
    if (trimmed.startsWith('{')) {
      return finish(content, pinSingboxConfig(trimmed, pinKey, excludeNode));
    }
    // HTML landing pages pass through — no pinning is defined for them.
    if (trimmed.startsWith('<')) return { content, node: null };
    // Clash / Mihomo YAML: pin by proxy name.
    if (/^proxies:/m.test(trimmed) || /^proxy-groups:/m.test(trimmed)) {
      return finish(content, pinClashConfig(trimmed, pinKey, excludeNode));
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

    const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode);
    if (!chosen) return { content, node: null };

    const out = [...passthrough, ...(byNode.get(chosen) ?? [])].join('\n');
    return { content: encoded ? btoa(out) : out, node: chosen };
  } catch {
    return { content, node: null };
  }
}

/** A config pinner's outcome: null = unknown shape (verbatim, no node);
 *  `content` undefined = single node (verbatim WITH the node). */
type ConfigPin = { node: string; content?: string } | null;

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
    const node = nodeNameFromTag(name);
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
  excludeNode?: string,
): { chosen: string; dropped: Set<string> } | null {
  const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode);
  if (!chosen) return null;
  const dropped = new Set<string>();
  for (const [node, names] of byNode) {
    if (node !== chosen) for (const n of names) dropped.add(n);
  }
  return { chosen, dropped };
}

/**
 * Pin a sing-box JSON config to one node. The panel's sing-box template emits
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
function pinSingboxConfig(trimmed: string, pinKey: string, excludeNode?: string): ConfigPin {
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

  const pick = chooseAndDrop(byNode, pinKey, excludeNode);
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
 * trip (the panel's template comments are operator notes, not client input).
 */
function pinClashConfig(trimmed: string, pinKey: string, excludeNode?: string): ConfigPin {
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

  const pick = chooseAndDrop(byNode, pinKey, excludeNode);
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
