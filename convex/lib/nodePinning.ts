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
export function pickNode(pinKey: string, nodes: string[]): string | null {
  let best: string | null = null;
  let bestScore = -1;
  for (const node of nodes) {
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
 * `pinKey` maps to. Returns the content unchanged when there is nothing to
 * pin (0/1 nodes, unknown format) or on any parse error.
 */
export function pinSubscriptionToNode(content: string, pinKey: string): string {
  try {
    const trimmed = content.trim();
    if (!trimmed || !pinKey) return content;

    // Pass through non-line-list formats (Clash YAML, sing-box JSON, HTML
    // landing pages) untouched — pinning is only defined for link lists.
    if (trimmed.startsWith('{') || trimmed.startsWith('<') || trimmed.startsWith('proxies:')) {
      return content;
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
    if (byNode.size <= 1) return content;

    const chosen = pickNode(pinKey, [...byNode.keys()]);
    if (!chosen) return content;

    const out = [...passthrough, ...(byNode.get(chosen) ?? [])].join('\n');
    return encoded ? btoa(out) : out;
  } catch {
    return content;
  }
}
