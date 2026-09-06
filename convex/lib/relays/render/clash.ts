/**
 * Clash / Mihomo / Stash YAML renderer. The panel emits `proxies:` (one entry
 * per Host, `name` = Host remark, `server`, `port`, `servername`) and
 * `proxy-groups:` whose `proxies` lists those names. We clone the slot's
 * template proxy per assigned endpoint, drop the templates, replace their
 * membership in every group with the emitted names and (per rule) ensure a
 * `url-test` group named after the auto group, listed first in the selector.
 * Comments are dropped by the round trip (acceptable; the panel's template
 * comments are operator notes). Fail-open on any unknown shape.
 */
import YAML from 'yaml';
import { AUTO_GROUP_TEST_URL, orderEndpoints, type RenderInput, type RenderOutput } from './types';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

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
  const templateSet = new Set(input.templateRemarks);
  const templates = new Map<string, Obj>();
  for (const p of proxies) {
    if (isObj(p) && typeof p.name === 'string' && templateSet.has(p.name) && !templates.has(p.name))
      templates.set(p.name, p);
  }
  if (templates.size === 0)
    return { body: input.body, applied: false, reason: 'no_template_proxies', emitted: 0 };

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.slotRemark);
    if (!tpl) continue;
    const clone = structuredClone(tpl) as Obj;
    clone.name = ep.label;
    clone.server = ep.address;
    clone.port = ep.port;
    if ('servername' in clone) clone.servername = ep.sni;
    if ('sni' in clone) clone.sni = ep.sni;
    emitted.push(clone);
  }
  if (emitted.length === 0)
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  const names = emitted.map((e) => e.name as string);

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

  const groups = Array.isArray(doc['proxy-groups']) ? (doc['proxy-groups'] as unknown[]) : [];
  let sawAuto = false;
  const nextGroups: unknown[] = groups.map((g) => {
    if (!isObj(g) || !Array.isArray(g.proxies)) return g;
    const members: unknown[] = [];
    let swapped = false;
    for (const m of g.proxies) {
      if (typeof m === 'string' && templateSet.has(m)) {
        if (!swapped) {
          swapped = true;
          if (input.rule.autoGroup && g.name !== input.rule.autoGroupName)
            members.push(input.rule.autoGroupName);
          members.push(...names);
        }
        if (!input.rule.dropTemplateEntries) members.push(m);
        continue;
      }
      members.push(m);
    }
    const out: Obj = { ...g, proxies: members };
    if (g.name === input.rule.autoGroupName) {
      sawAuto = true;
      out.type = 'url-test';
      out.proxies = names;
    }
    return out;
  });
  if (input.rule.autoGroup && !sawAuto) {
    nextGroups.unshift({
      name: input.rule.autoGroupName,
      type: 'url-test',
      proxies: names,
      url: AUTO_GROUP_TEST_URL,
      interval: 300,
      tolerance: 50,
      lazy: true,
    });
  }
  const rendered = YAML.stringify(
    { ...doc, proxies: nextProxies, 'proxy-groups': nextGroups },
    { lineWidth: 0 },
  );
  if (input.rule.dropTemplateEntries) {
    for (const t of templateSet) {
      // A template name still referenced (rules, other groups) would dangle.
      if (rendered.includes(t))
        return {
          body: input.body,
          applied: false,
          reason: 'dangling_template_reference',
          emitted: 0,
        };
    }
  }
  return { body: rendered, applied: true, emitted: emitted.length };
}
