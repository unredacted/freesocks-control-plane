/**
 * Where a subscription body sends the traffic no rule claims (pure). A member's
 * client must reach the proxy group by default: a body that lets unmatched
 * traffic go direct hands a censored member an unproxied connection that still
 * looks connected. What the tests hold every template FCP ships, and every
 * member body built from one, to:
 *
 *   Clash / Mihomo / Stash YAML
 *     - `mode: rule`. Global mode ignores `rules:` and sends everything through
 *       the engine's built-in GLOBAL group, whose default is DIRECT; direct
 *       mode bypasses every proxy.
 *     - one catch-all rule, the last: `MATCH,<group>`, `<group>` a proxy group
 *       (the named one, when given). Without it unmatched traffic goes DIRECT.
 *   sing-box JSON
 *     - the default outbound (`route.final`, else the first outbound) is a
 *       selector or urltest group (the named one, when given).
 *     - the clash API's `default_mode`, when set, is `rule`.
 *
 * In either format the group must not default to a direct or reject outbound:
 * a selector's default (sing-box `default`, else its first member) and every
 * member of an automatic group, followed through nested groups. A group with no
 * members yet (a template: the backend fills it in) passes.
 */
import YAML from 'yaml';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const names = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((m): m is string => typeof m === 'string') : [];

// Clash outbounds that are not a proxy.
const CLASH_BYPASS = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'GLOBAL']);
// Clash rule types that match everything.
const CLASH_CATCH_ALL = new Set(['MATCH', 'FINAL']);
const SINGBOX_GROUPS = new Set(['selector', 'urltest']);
const SINGBOX_BYPASS = new Set(['direct', 'block']);

/** What in this body sends unmatched traffic around the proxy group; empty when nothing does. */
export function defaultRouteFaults(body: string, group?: string): string[] {
  const trimmed = body.trim();
  if (trimmed.startsWith('{')) {
    let cfg: unknown;
    try {
      cfg = JSON.parse(trimmed);
    } catch {
      return ['not JSON'];
    }
    return isObj(cfg) ? singboxFaults(cfg, group) : ['not a sing-box config'];
  }
  let doc: unknown;
  try {
    doc = YAML.parse(trimmed);
  } catch {
    return ['not YAML'];
  }
  return isObj(doc) ? clashFaults(doc, group) : ['not a Clash config'];
}

/**
 * The members a group may send traffic to by default: a selector's default
 * (or first) member, every member of anything else.
 */
function defaultMembers(members: string[], selector: boolean, chosen?: unknown): string[] {
  if (!selector) return members;
  const pick = typeof chosen === 'string' && chosen ? chosen : members[0];
  return pick === undefined ? [] : [pick];
}

/** Every bypass reachable by default from `start` through nested groups. */
function bypassesFrom(
  start: string,
  next: (name: string) => string[] | null,
  bypass: (name: string) => boolean,
): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const walk = (name: string) => {
    if (seen.has(name)) return;
    seen.add(name);
    if (bypass(name)) {
      out.push(name);
      return;
    }
    for (const m of next(name) ?? []) walk(m);
  };
  walk(start);
  return out;
}

function clashFaults(doc: Obj, group?: string): string[] {
  const faults: string[] = [];
  if (typeof doc.mode !== 'string' || doc.mode.toLowerCase() !== 'rule')
    faults.push(`mode is ${JSON.stringify(doc.mode ?? null)}, not rule`);
  const rules = names(doc.rules);
  const catchAll = rules
    .map((r, i) => ({ i, parts: r.split(',').map((p) => p.trim()) }))
    .filter((r) => CLASH_CATCH_ALL.has(r.parts[0]!.toUpperCase()));
  if (catchAll.length === 0) return [...faults, 'no MATCH rule: unmatched traffic goes DIRECT'];
  if (catchAll.length > 1 || catchAll[0]!.i !== rules.length - 1)
    faults.push('MATCH is not the one last rule');
  const target = catchAll[catchAll.length - 1]!.parts[1] ?? '';
  const groups = new Map<string, Obj>();
  for (const g of Array.isArray(doc['proxy-groups']) ? doc['proxy-groups'] : [])
    if (isObj(g) && typeof g.name === 'string') groups.set(g.name, g);
  if (!groups.has(target)) return [...faults, `MATCH goes to ${target}, not a proxy group`];
  if (group !== undefined && target !== group) faults.push(`MATCH goes to ${target}, not ${group}`);
  const next = (name: string) => {
    const g = groups.get(name);
    return g ? defaultMembers(names(g.proxies), g.type === 'select') : null;
  };
  for (const b of bypassesFrom(target, next, (n) => CLASH_BYPASS.has(n.toUpperCase())))
    faults.push(`${target} reaches ${b} by default`);
  return faults;
}

function singboxFaults(cfg: Obj, group?: string): string[] {
  const faults: string[] = [];
  const experimental = isObj(cfg.experimental) ? cfg.experimental : {};
  const clashApi = isObj(experimental.clash_api) ? experimental.clash_api : {};
  if (clashApi.default_mode !== undefined && String(clashApi.default_mode).toLowerCase() !== 'rule')
    faults.push(`clash_api default_mode is ${JSON.stringify(clashApi.default_mode)}, not rule`);
  const outbounds = (Array.isArray(cfg.outbounds) ? cfg.outbounds : []).filter(isObj);
  const byTag = new Map(
    outbounds.filter((o) => typeof o.tag === 'string').map((o) => [o.tag as string, o]),
  );
  const route = isObj(cfg.route) ? cfg.route : {};
  const first = outbounds[0]?.tag;
  const final: string | undefined =
    typeof route.final === 'string' && route.final
      ? route.final
      : typeof first === 'string'
        ? first
        : undefined;
  const out = final === undefined ? undefined : byTag.get(final);
  if (final === undefined || !out || !SINGBOX_GROUPS.has(String(out.type)))
    return [...faults, `the default outbound is ${final ?? 'missing'}, not a proxy group`];
  if (group !== undefined && final !== group)
    faults.push(`the default outbound is ${final}, not ${group}`);
  const next = (tag: string) => {
    const o = byTag.get(tag);
    return o && SINGBOX_GROUPS.has(String(o.type))
      ? defaultMembers(names(o.outbounds), o.type === 'selector', o.default)
      : null;
  };
  const bypass = (tag: string) => SINGBOX_BYPASS.has(String(byTag.get(tag)?.type));
  for (const b of bypassesFrom(final, next, bypass))
    faults.push(`${final} reaches ${b} by default`);
  return faults;
}
