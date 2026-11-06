/**
 * The delivery guard for Hysteria 2 entries (pure; docs/privacy.md §5c).
 *
 * A Hysteria password is the member's VLESS id. An entry that would trust
 * anyone who answers, or any certificate a CA signed, hands that credential to
 * whoever sits in the path, so no member body ever carries one: every Hysteria
 * entry must verify the node by an expected pin (lib/hysteriaPins.ts). The
 * backend's Host rewrites (lib/backend/hostMapper.ts) make this the case; the
 * guard is the backstop for a backend that drifted or a hand edit.
 *
 * An entry that fails is DROPPED and everything that named it is repaired:
 * group members pruned, a group default moved, then the whole result scanned
 * for any reference left (rules, `detour`, dns). Unlike the node pinner it
 * never fails open: a group the drop would empty, a reference it cannot
 * remove, a body left with no connection, or a body that names Hysteria in a
 * way no reader understands is REFUSED, never handed out as it came.
 */
import YAML from 'yaml';
import { decodeLinkList } from './edges/render/links';
import { decodeBase64Loose, encodeBase64 } from './edges/render/base64';
import { MENTIONS_HYSTERIA, scanHysteria, type ExpectedPins } from './hysteriaPins';

export type GuardOutcome =
  | { kind: 'kept'; content: string; dropped: number }
  | { kind: 'refuse'; reason: 'hysteria_unverifiable'; dropped: number };

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === 'object' && !Array.isArray(v);

const PROXY_LINE_RE = /^(vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic):\/\//i;

/** Whether `v` names any of `names` anywhere (a string equal to one, at any depth). */
function mentions(v: unknown, names: ReadonlySet<string>): boolean {
  if (typeof v === 'string') return names.has(v);
  if (Array.isArray(v)) return v.some((x) => mentions(x, names));
  if (isObj(v)) return Object.values(v).some((x) => mentions(x, names));
  return false;
}

const refuse = (dropped: number): GuardOutcome => ({
  kind: 'refuse',
  reason: 'hysteria_unverifiable',
  dropped,
});

function guardLinks(body: string, drop: ReadonlySet<string>): GuardOutcome {
  const decoded = decodeLinkList(body)!;
  const kept = decoded.lines.filter((_, i) => !drop.has(String(i)));
  if (!kept.some((l) => PROXY_LINE_RE.test(l))) return refuse(drop.size);
  const text = kept.join('\n');
  return { kind: 'kept', content: decoded.encoded ? encodeBase64(text) : text, dropped: drop.size };
}

function guardClash(body: string, drop: ReadonlySet<string>): GuardOutcome {
  const doc = YAML.parse(body) as Obj;
  const proxies = (Array.isArray(doc.proxies) ? doc.proxies : []).filter(
    (p) => !(isObj(p) && typeof p.name === 'string' && drop.has(p.name)),
  );
  if (proxies.length === 0) return refuse(drop.size);
  doc.proxies = proxies;
  if (Array.isArray(doc['proxy-groups'])) {
    for (const g of doc['proxy-groups']) {
      if (!isObj(g) || !Array.isArray(g.proxies)) continue;
      const left = g.proxies.filter((m) => !(typeof m === 'string' && drop.has(m)));
      // A group left empty would make the whole config unloadable.
      if (left.length === 0 && g.proxies.length > 0) return refuse(drop.size);
      g.proxies = left;
    }
  }
  // A rule's target, a provider, anything else: refused, never left dangling.
  for (const [k, v] of Object.entries(doc))
    if (k !== 'proxies' && k !== 'proxy-groups' && mentions(v, drop)) return refuse(drop.size);
  if (Array.isArray(doc.rules))
    for (const r of doc.rules)
      if (typeof r === 'string' && r.split(',').some((part) => drop.has(part.trim())))
        return refuse(drop.size);
  return { kind: 'kept', content: YAML.stringify(doc, { lineWidth: 0 }), dropped: drop.size };
}

function guardSingbox(body: string, drop: ReadonlySet<string>): GuardOutcome {
  const doc = JSON.parse(body) as Obj;
  const outbounds = Array.isArray(doc.outbounds) ? doc.outbounds : [];
  // Untagged entries are found by index (`#i`); tags are what references use.
  const tags = new Set<string>();
  const kept: unknown[] = [];
  outbounds.forEach((o, i) => {
    const tag = isObj(o) && typeof o.tag === 'string' ? o.tag : null;
    if (drop.has(tag ?? `#${i}`)) {
      if (tag) tags.add(tag);
      return;
    }
    kept.push(o);
  });
  const next: unknown[] = [];
  for (const o of kept) {
    if (!isObj(o) || !Array.isArray(o.outbounds)) {
      next.push(o);
      continue;
    }
    const members = o.outbounds.filter((m) => !(typeof m === 'string' && tags.has(m)));
    if (members.length === 0 && o.outbounds.length > 0) return refuse(drop.size);
    const g: Obj = { ...o, outbounds: members };
    if (typeof o.default === 'string' && tags.has(o.default)) g.default = members[0];
    next.push(g);
  }
  if (!next.some((o) => isObj(o) && typeof o.server === 'string')) return refuse(drop.size);
  const out = { ...doc, outbounds: next };
  if (mentions(out, tags)) return refuse(drop.size);
  return { kind: 'kept', content: JSON.stringify(out), dropped: drop.size };
}

function guardXray(body: string, drop: ReadonlySet<string>): GuardOutcome {
  const json = JSON.parse(body) as unknown;
  const configs = (Array.isArray(json) ? json : [json]).filter(isObj);
  const proxyOf = (o: unknown) =>
    isObj(o) &&
    typeof o.protocol === 'string' &&
    !['freedom', 'blackhole', 'dns'].includes(o.protocol);
  const out: Obj[] = [];
  for (let c = 0; c < configs.length; c++) {
    const cfg = configs[c]!;
    const obs = Array.isArray(cfg.outbounds) ? cfg.outbounds : [];
    const gone = obs.map((_, i) => drop.has(`${c}/${i}`));
    if (!gone.some(Boolean)) {
      out.push(cfg);
      continue;
    }
    const left = obs.filter((_, i) => !gone[i]);
    // A config of an array that held one connection goes whole.
    if (Array.isArray(json) && !left.some(proxyOf)) continue;
    const tags = new Set(
      obs
        .filter((o, i) => gone[i] && isObj(o) && typeof o.tag === 'string')
        .map((o) => (o as Obj).tag as string),
    );
    const next = { ...cfg, outbounds: left };
    if (mentions(next, tags)) return refuse(drop.size);
    out.push(next);
  }
  if (!out.some((cfg) => (Array.isArray(cfg.outbounds) ? cfg.outbounds : []).some(proxyOf)))
    return refuse(drop.size);
  return {
    kind: 'kept',
    content: JSON.stringify(Array.isArray(json) ? out : out[0]),
    dropped: drop.size,
  };
}

/**
 * A body with only verified Hysteria entries, or a refusal. A body that names
 * no Hysteria at all comes back as it was, unread.
 */
export function guardHysteria(body: string, pins: ExpectedPins): GuardOutcome {
  // Read only a body that names Hysteria (a base64 link list, once decoded).
  if (!MENTIONS_HYSTERIA.test(body)) {
    const decoded = decodeBase64Loose(body.trim());
    if (decoded === null || !MENTIONS_HYSTERIA.test(decoded))
      return { kind: 'kept', content: body, dropped: 0 };
  }
  const scan = scanHysteria(body, pins);
  if (scan.unreadable) return refuse(0);
  const bad = new Set(scan.entries.filter((e) => e.trust !== 'pinned').map((e) => e.ref));
  if (bad.size === 0) return { kind: 'kept', content: body, dropped: 0 };
  try {
    switch (scan.format) {
      case 'links':
        return guardLinks(body.trim(), bad);
      case 'clash':
        return guardClash(body.trim(), bad);
      case 'singbox':
        return guardSingbox(body.trim(), bad);
      case 'xray':
        return guardXray(body.trim(), bad);
      default:
        return refuse(bad.size);
    }
  } catch {
    return refuse(bad.size);
  }
}
