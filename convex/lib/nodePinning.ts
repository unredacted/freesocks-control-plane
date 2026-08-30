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
 * Two content shapes are understood:
 *   - link lists (optionally base64-wrapped) — filtered line by line;
 *   - sing-box JSON configs (what the panel serves to sing-box User-Agents) —
 *     outbounds are tagged with the same Host remarks, so we drop the other
 *     nodes' outbounds and prune them from selector/urltest groups.
 *
 * Fail-open everywhere: unknown content shape, unparseable lines, or a
 * single-node subscription are returned verbatim.
 */

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;
// Known transport suffixes the role appends to Host remarks (xhttp removed
// 2026-07-04 but kept here so legacy remarks still parse).
const TRANSPORT_SUFFIX_RE = /-(ws|reality|xhttp)(-[0-9a-f]{6})?$/i;

function looksLikeBase64(s: string): boolean {
  return /^[A-Za-z0-9+/=\r\n]+$/.test(s) && s.length % 4 === 0;
}

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

/** Extract the node name from a sing-box outbound tag (the panel uses the Host
 *  remark verbatim as the tag), or null when the tag carries no transport
 *  suffix (selector/urltest groups, direct/block/dns outbounds). */
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

/**
 * Filter squad-wide subscription content down to the lines of the single node
 * `pinKey` maps to. `excludeNode` (the node the key was PREVIOUSLY pinned to,
 * e.g. before a regenerate) is avoided when others exist, so a regenerated
 * key lands on a different node. Returns the (possibly re-encoded) content
 * unchanged when there is nothing to pin (0/1 nodes, unknown format) or on
 * any parse error, plus the node that was picked (null when not filtered).
 */
export function pinSubscriptionToNode(
  content: string,
  pinKey: string,
  excludeNode?: string,
): { content: string; node: string | null } {
  try {
    const trimmed = content.trim();
    if (!trimmed || !pinKey) return { content, node: null };

    // JSON bodies: pin sing-box configs by outbound tag; anything else JSON
    // (v2ray-json, an error envelope) passes through verbatim. Clash YAML and
    // HTML landing pages pass through too — no pinning is defined for them.
    if (trimmed.startsWith('{')) {
      return pinSingboxConfig(trimmed, pinKey, excludeNode) ?? { content, node: null };
    }
    if (trimmed.startsWith('<') || trimmed.startsWith('proxies:')) {
      return { content, node: null };
    }

    // Subscription bodies are commonly base64-encoded line lists; decode when
    // that is what we have, re-encode at the end.
    let encoded = false;
    let body = trimmed;
    if (looksLikeBase64(trimmed)) {
      try {
        const decoded = atob(trimmed);
        if (PROXY_LINE_RE.test(decoded.trim())) {
          encoded = true;
          body = decoded;
        }
      } catch {
        // Not actually base64 — treat as plain text.
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

    // Nothing to pin (empty fleet or a single node) — serve verbatim.
    if (byNode.size <= 1) return { content, node: null };

    const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode);
    if (!chosen) return { content, node: null };

    const out = [...passthrough, ...(byNode.get(chosen) ?? [])].join('\n');
    return { content: encoded ? btoa(out) : out, node: chosen };
  } catch {
    return { content, node: null };
  }
}

/**
 * Pin a sing-box JSON config to one node. The panel's sing-box template emits
 * one outbound per Host, tagged with the Host remark (the same names the link
 * list carries), plus selector/urltest groups whose `outbounds` arrays list
 * those tags. We keep the chosen node's outbounds, drop the rest, and prune
 * the dropped tags from every group (fixing a group `default` that pointed at
 * a dropped tag). Returns null — meaning "serve verbatim" — whenever the shape
 * isn't the one we understand: not a config, fewer than two nodes, a group
 * that would end up empty, or a dropped tag still referenced elsewhere (route
 * rules) after pruning. Emitting a broken config is the one unacceptable
 * outcome; the whole-fleet fallback merely weakens endpoint hygiene.
 */
function pinSingboxConfig(
  trimmed: string,
  pinKey: string,
  excludeNode?: string,
): { content: string; node: string } | null {
  let cfg: unknown;
  try {
    cfg = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof cfg !== 'object' || cfg === null) return null;
  const outbounds = (cfg as { outbounds?: unknown }).outbounds;
  if (!Array.isArray(outbounds)) return null;

  const byNode = new Map<string, string[]>(); // node -> its outbound tags
  for (const ob of outbounds) {
    if (typeof ob !== 'object' || ob === null) return null;
    const tag = (ob as { tag?: unknown }).tag;
    if (typeof tag !== 'string') continue;
    const node = nodeNameFromTag(tag);
    if (!node) continue;
    const list = byNode.get(node) ?? [];
    list.push(tag);
    byNode.set(node, list);
  }
  if (byNode.size <= 1) return null;

  const chosen = pickNode(pinKey, [...byNode.keys()], excludeNode);
  if (!chosen) return null;
  const dropped = new Set<string>();
  for (const [node, tags] of byNode) {
    if (node !== chosen) for (const t of tags) dropped.add(t);
  }

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

  // A dropped tag referenced anywhere OUTSIDE the outbounds (route/dns rules)
  // means this template wires nodes in a way we don't understand — verbatim.
  const rest = JSON.stringify({ ...(cfg as Record<string, unknown>), outbounds: [] });
  for (const t of dropped) {
    if (rest.includes(JSON.stringify(t))) return null;
  }

  return {
    content: JSON.stringify({ ...(cfg as Record<string, unknown>), outbounds: kept }),
    node: chosen,
  };
}
