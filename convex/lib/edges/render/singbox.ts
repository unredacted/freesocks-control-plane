/**
 * sing-box JSON renderer. The panel emits one outbound per Host tagged with the
 * Host remark, plus selector/urltest groups listing those tags. We clone the
 * slot's template outbound per assigned endpoint (server, server_port,
 * tls.server_name, tag = label), drop the template outbounds, replace their
 * membership in every group with the emitted tags, and (per rule) ensure a
 * `urltest` group named after the auto group that contains exactly the
 * emitted tags and is the selector's default. Fail-open on any unknown shape.
 *
 * Removing a template never leaves a dangling reference: every other mention
 * of its tag (route rules, `route.final`, DNS/outbound `detour`s, group
 * `default`s) is rewritten to the rendered fallback or pruned structurally
 * (`refs.ts`), so the config stays valid instead of falling back to the
 * original body — which would hand the template's address back out.
 */
import { cloneJson, pruneRefs, uniqueName } from './refs';
import { AUTO_GROUP_TEST_URL, orderEndpoints, type RenderInput, type RenderOutput } from './types';

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const NON_PROXY_TYPES = new Set(['direct', 'block', 'dns']);

/** The outbound a dangling reference falls back to: a proxy or group first, any tag otherwise. */
function fallbackTag(list: unknown[]): string | null {
  let any: string | null = null;
  for (const ob of list) {
    if (!isObj(ob) || typeof ob.tag !== 'string') continue;
    any ??= ob.tag;
    if (!NON_PROXY_TYPES.has(String(ob.type))) return ob.tag;
  }
  return any;
}

export function renderSingbox(input: RenderInput): RenderOutput {
  let cfg: unknown;
  try {
    cfg = JSON.parse(input.body);
  } catch {
    return { body: input.body, applied: false, reason: 'not_json', emitted: 0 };
  }
  if (!isObj(cfg) || !Array.isArray(cfg.outbounds)) {
    return { body: input.body, applied: false, reason: 'no_outbounds', emitted: 0 };
  }
  const outbounds = cfg.outbounds as unknown[];
  const templateSet = new Set(input.templateRemarks);
  const templates = new Map<string, Obj>();
  const taken = new Set<string>();
  let autoGroupIsGroup = false;
  for (const ob of outbounds) {
    if (!isObj(ob) || typeof ob.tag !== 'string') continue;
    if (templateSet.has(ob.tag)) {
      if (!templates.has(ob.tag)) templates.set(ob.tag, ob);
      continue;
    }
    taken.add(ob.tag);
    if (ob.tag === input.rule.autoGroupName && Array.isArray(ob.outbounds)) autoGroupIsGroup = true;
  }
  if (templates.size === 0)
    return { body: input.body, applied: false, reason: 'no_template_outbounds', emitted: 0 };

  // The auto group reuses an existing GROUP of that name; a non-group outbound
  // already holding the name forces a suffixed one so tags stay unique.
  const autoName = autoGroupIsGroup
    ? input.rule.autoGroupName
    : uniqueName(input.rule.autoGroupName, taken);
  if (input.rule.autoGroup) taken.add(autoName);

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.slotRemark);
    if (!tpl) continue;
    const clone = cloneJson(tpl);
    const tag = uniqueName(ep.label, taken);
    taken.add(tag);
    clone.tag = tag;
    clone.server = ep.address;
    clone.server_port = ep.port;
    if (ep.sni !== null && isObj(clone.tls)) clone.tls = { ...clone.tls, server_name: ep.sni };
    emitted.push(clone);
  }
  // Drop-only: no endpoint to emit (empty pool) — remove the templates, prune
  // their group memberships, and drop the groups that end up empty (the auto
  // group included: an empty urltest is not a valid outbound).
  const dropOnly = emitted.length === 0;
  if (dropOnly && !input.rule.dropTemplateEntries)
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  const emittedTags = emitted.map((e) => e.tag as string);
  const useAuto = input.rule.autoGroup && !dropOnly;

  const next: unknown[] = [];
  let inserted = false;
  let sawAutoGroup = false;
  for (const ob of outbounds) {
    if (!isObj(ob)) {
      next.push(ob);
      continue;
    }
    const tag = typeof ob.tag === 'string' ? ob.tag : null;
    if (tag && templateSet.has(tag)) {
      if (!inserted) {
        inserted = true;
        next.push(...emitted);
      }
      if (!input.rule.dropTemplateEntries) next.push(ob);
      continue;
    }
    if (Array.isArray(ob.outbounds)) {
      // A group: swap template members for the emitted tags (once, in place).
      const members: unknown[] = [];
      let swapped = false;
      for (const m of ob.outbounds) {
        if (typeof m === 'string' && templateSet.has(m)) {
          if (!swapped) {
            swapped = true;
            if (useAuto && tag !== autoName) members.push(autoName);
            members.push(...emittedTags);
          }
          if (!input.rule.dropTemplateEntries) members.push(m);
          continue;
        }
        members.push(m);
      }
      const group: Obj = { ...ob, outbounds: members };
      if (tag === autoName && autoGroupIsGroup) {
        sawAutoGroup = true;
        group.outbounds = emittedTags;
        group.type = 'urltest';
      }
      if (typeof ob.default === 'string' && templateSet.has(ob.default)) {
        if (dropOnly) delete group.default;
        else group.default = useAuto ? autoName : emittedTags[0];
      } else if (useAuto && ob.type === 'selector' && swapped && ob.default === undefined) {
        group.default = autoName;
      }
      next.push(group);
      continue;
    }
    next.push(ob);
  }
  if (!inserted)
    return { body: input.body, applied: false, reason: 'template_not_in_outbounds', emitted: 0 };
  if (useAuto && !sawAutoGroup) {
    next.push({
      type: 'urltest',
      tag: autoName,
      outbounds: emittedTags,
      url: AUTO_GROUP_TEST_URL,
      interval: '3m',
      tolerance: 50,
      interrupt_exist_connections: false,
    });
  }
  if (!input.rule.dropTemplateEntries) {
    return {
      body: JSON.stringify({ ...cfg, outbounds: next }),
      applied: true,
      emitted: emitted.length,
    };
  }

  // Templates were removed: nothing may still reference them. Groups left
  // without members go too, and so does anything that pointed at them
  // (iterate until stable; a selector of only dropped tags cascades).
  const removed = new Set<string>(templateSet);
  let list = next;
  for (let changed = true; changed; ) {
    changed = false;
    const keep: unknown[] = [];
    for (const ob of list) {
      if (!isObj(ob) || !Array.isArray(ob.outbounds)) {
        keep.push(ob);
        continue;
      }
      const members = ob.outbounds.filter((m) => !(typeof m === 'string' && removed.has(m)));
      if (members.length === 0) {
        if (typeof ob.tag === 'string') removed.add(ob.tag);
        changed = true;
        continue;
      }
      const g: Obj = { ...ob, outbounds: members };
      if (typeof g.default === 'string' && removed.has(g.default)) delete g.default;
      keep.push(g);
    }
    list = keep;
  }
  // Every remaining mention (route rules, `route.final`, detours) is rewritten
  // to the fallback — the auto group / first emitted entry when rendering, the
  // first remaining proxy-ish outbound when dropping — or pruned outright.
  const fallback =
    useAuto && !removed.has(autoName) ? autoName : (emittedTags[0] ?? fallbackTag(list));
  const pruned = pruneRefs({ ...cfg, outbounds: list }, removed, fallback) as Obj;
  return {
    body: JSON.stringify(pruned),
    applied: true,
    ...(dropOnly ? { reason: 'templates_dropped' } : {}),
    emitted: emitted.length,
  };
}
