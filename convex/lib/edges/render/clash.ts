/**
 * Clash / Mihomo / Stash YAML renderer. The panel emits `proxies:` (one entry
 * per Host, `name` = Host remark, `server`, `port`, `servername`) and
 * `proxy-groups:` whose `proxies` lists those names. We clone the slot's
 * template proxy per assigned endpoint, drop the templates, replace their
 * membership in every group with the emitted names and (per rule) ensure a
 * `url-test` group named after the auto group, listed first in the selector.
 * Comments are dropped by the round trip (acceptable; the panel's template
 * comments are operator notes). Fail-open on any unknown shape.
 *
 * Removing a template never leaves a dangling reference: `rules` targets
 * (`MATCH,<name>`), other groups and any other mention are rewritten to the
 * rendered fallback or pruned structurally (`refs.ts`) — never a substring
 * scan, and never by returning the original body.
 */
import YAML from 'yaml';
import { cloneJson, pruneRefs, uniqueName } from './refs';
import { AUTO_GROUP_TEST_URL, orderEndpoints, type RenderInput, type RenderOutput } from './types';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Proxy types whose TLS name key is `sni` (the rest use `servername`). */
const SNI_KEY_TYPES = new Set(['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls']);

/** Set the server name a cloned proxy presents. Mihomo defaults the SNI to
 *  `server` when the key is absent, which would present the edge's IP — so the
 *  key is set even when the template never carried one. */
function setServerName(clone: Obj, sni: string) {
  let touched = false;
  if ('servername' in clone) {
    clone.servername = sni;
    touched = true;
  }
  if ('sni' in clone) {
    clone.sni = sni;
    touched = true;
  }
  if (!touched) clone[SNI_KEY_TYPES.has(String(clone.type)) ? 'sni' : 'servername'] = sni;
}

export function renderClash(input: RenderInput): RenderOutput {
  let doc: unknown;
  try {
    doc = YAML.parse(input.body);
  } catch {
    return { body: input.body, applied: false, reason: 'not_yaml', emitted: 0 };
  }
  if (!isObj(doc) || !Array.isArray(doc.proxies)) {
    return { body: input.body, applied: false, reason: 'no_proxies', emitted: 0 };
  }
  const proxies = doc.proxies as unknown[];
  const groups = Array.isArray(doc['proxy-groups']) ? (doc['proxy-groups'] as unknown[]) : [];
  const templateSet = new Set(input.templateRemarks);
  const templates = new Map<string, Obj>();
  const taken = new Set<string>();
  for (const p of proxies) {
    if (!isObj(p) || typeof p.name !== 'string') continue;
    if (templateSet.has(p.name)) {
      if (!templates.has(p.name)) templates.set(p.name, p);
      continue;
    }
    taken.add(p.name);
  }
  let autoGroupIsGroup = false;
  for (const g of groups) {
    if (!isObj(g) || typeof g.name !== 'string') continue;
    taken.add(g.name);
    if (g.name === input.rule.autoGroupName && Array.isArray(g.proxies)) autoGroupIsGroup = true;
  }
  if (templates.size === 0)
    return { body: input.body, applied: false, reason: 'no_template_proxies', emitted: 0 };

  // The auto group reuses an existing GROUP of that name; a plain proxy already
  // holding the name forces a suffixed one so names stay unique.
  const autoName = autoGroupIsGroup
    ? input.rule.autoGroupName
    : uniqueName(input.rule.autoGroupName, taken);
  if (input.rule.autoGroup) taken.add(autoName);

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.slotRemark);
    if (!tpl) continue;
    const clone = cloneJson(tpl);
    const name = uniqueName(ep.label, taken);
    taken.add(name);
    clone.name = name;
    clone.server = ep.address;
    clone.port = ep.port;
    if (ep.sni !== null) setServerName(clone, ep.sni);
    emitted.push(clone);
  }
  // Drop-only: no endpoint to emit (empty pool) — remove the templates, prune
  // their group memberships, and drop the groups that end up empty.
  const dropOnly = emitted.length === 0;
  if (dropOnly && !input.rule.dropTemplateEntries)
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  const names = emitted.map((e) => e.name as string);
  const useAuto = input.rule.autoGroup && !dropOnly;

  const nextProxies: unknown[] = [];
  let inserted = false;
  for (const p of proxies) {
    if (isObj(p) && typeof p.name === 'string' && templateSet.has(p.name)) {
      if (!inserted) {
        inserted = true;
        nextProxies.push(...emitted);
      }
      if (!input.rule.dropTemplateEntries) nextProxies.push(p);
      continue;
    }
    nextProxies.push(p);
  }

  let sawAuto = false;
  const nextGroups: unknown[] = groups.map((g) => {
    if (!isObj(g) || !Array.isArray(g.proxies)) return g;
    const members: unknown[] = [];
    let swapped = false;
    for (const m of g.proxies) {
      if (typeof m === 'string' && templateSet.has(m)) {
        if (!swapped) {
          swapped = true;
          if (useAuto && g.name !== autoName) members.push(autoName);
          members.push(...names);
        }
        if (!input.rule.dropTemplateEntries) members.push(m);
        continue;
      }
      members.push(m);
    }
    const out: Obj = { ...g, proxies: members };
    if (g.name === autoName && autoGroupIsGroup) {
      sawAuto = true;
      out.type = 'url-test';
      out.proxies = names;
    }
    return out;
  });
  if (useAuto && !sawAuto) {
    nextGroups.unshift({
      name: autoName,
      type: 'url-test',
      proxies: names,
      url: AUTO_GROUP_TEST_URL,
      interval: 300,
      tolerance: 50,
      lazy: true,
    });
  }
  const stringify = (d: unknown) => YAML.stringify(d, { lineWidth: 0 });
  if (!input.rule.dropTemplateEntries) {
    return {
      body: stringify({ ...doc, proxies: nextProxies, 'proxy-groups': nextGroups }),
      applied: true,
      emitted: emitted.length,
    };
  }

  // Templates were removed: groups left without members go too (cascading),
  // then every remaining mention — `rules` targets, other groups' lists — is
  // rewritten to the fallback (the auto group / first emitted entry when
  // rendering, the first remaining proxy or group when dropping) or pruned.
  const removed = new Set<string>(templateSet);
  let list = nextGroups;
  for (let changed = true; changed; ) {
    changed = false;
    const keep: unknown[] = [];
    for (const g of list) {
      if (!isObj(g) || !Array.isArray(g.proxies)) {
        keep.push(g);
        continue;
      }
      const members = g.proxies.filter((m) => !(typeof m === 'string' && removed.has(m)));
      if (members.length === 0) {
        if (typeof g.name === 'string') removed.add(g.name);
        changed = true;
        continue;
      }
      keep.push({ ...g, proxies: members });
    }
    list = keep;
  }
  const firstName = (arr: unknown[]) => {
    for (const x of arr) if (isObj(x) && typeof x.name === 'string') return x.name;
    return null;
  };
  const fallback =
    useAuto && !removed.has(autoName)
      ? autoName
      : (names[0] ?? firstName(list) ?? firstName(nextProxies));
  const pruned = pruneRefs(
    { ...doc, proxies: nextProxies, 'proxy-groups': list },
    removed,
    fallback,
  ) as Obj;
  if (!Array.isArray(doc['proxy-groups'])) delete pruned['proxy-groups'];
  return {
    body: stringify(pruned),
    applied: true,
    ...(dropOnly ? { reason: 'templates_dropped' } : {}),
    emitted: emitted.length,
  };
}
