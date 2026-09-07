/**
 * sing-box JSON renderer. The panel emits one outbound per Host tagged with the
 * Host remark, plus selector/urltest groups listing those tags. We clone the
 * slot's template outbound per assigned endpoint (server, server_port,
 * tls.server_name, tag = label), drop the template outbounds, replace their
 * membership in every group with the emitted tags, and (per rule) ensure a
 * `urltest` group named after the auto group that contains exactly the
 * emitted tags and is the selector's default. Fail-open on any unknown shape.
 */
import { AUTO_GROUP_TEST_URL, orderEndpoints, type RenderInput, type RenderOutput } from './types';

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
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
  for (const ob of outbounds) {
    if (
      isObj(ob) &&
      typeof ob.tag === 'string' &&
      templateSet.has(ob.tag) &&
      !templates.has(ob.tag)
    ) {
      templates.set(ob.tag, ob);
    }
  }
  if (templates.size === 0)
    return { body: input.body, applied: false, reason: 'no_template_outbounds', emitted: 0 };

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.slotRemark);
    if (!tpl) continue;
    const clone = structuredClone(tpl) as Obj;
    clone.tag = ep.label;
    clone.server = ep.address;
    clone.server_port = ep.port;
    if (ep.sni !== null && isObj(clone.tls)) clone.tls = { ...clone.tls, server_name: ep.sni };
    emitted.push(clone);
  }
  if (emitted.length === 0)
    return { body: input.body, applied: false, reason: 'no_endpoints_rendered', emitted: 0 };
  const emittedTags = emitted.map((e) => e.tag as string);

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
            if (input.rule.autoGroup) members.push(input.rule.autoGroupName);
            members.push(...emittedTags);
          }
          if (!input.rule.dropTemplateEntries) members.push(m);
          continue;
        }
        members.push(m);
      }
      const group: Obj = { ...ob, outbounds: members };
      if (tag === input.rule.autoGroupName) {
        sawAutoGroup = true;
        group.outbounds = emittedTags;
        group.type = 'urltest';
      }
      if (typeof ob.default === 'string' && templateSet.has(ob.default)) {
        group.default = input.rule.autoGroup ? input.rule.autoGroupName : emittedTags[0];
      } else if (
        input.rule.autoGroup &&
        ob.type === 'selector' &&
        swapped &&
        ob.default === undefined
      ) {
        group.default = input.rule.autoGroupName;
      }
      next.push(group);
      continue;
    }
    next.push(ob);
  }
  if (!inserted)
    return { body: input.body, applied: false, reason: 'template_not_in_outbounds', emitted: 0 };
  if (input.rule.autoGroup && !sawAutoGroup) {
    next.push({
      type: 'urltest',
      tag: input.rule.autoGroupName,
      outbounds: emittedTags,
      url: AUTO_GROUP_TEST_URL,
      interval: '3m',
      tolerance: 50,
      interrupt_exist_connections: false,
    });
  }
  // Nothing may still reference a dropped template tag (route rules, detours).
  const rendered = JSON.stringify({ ...cfg, outbounds: next });
  if (input.rule.dropTemplateEntries) {
    for (const t of templateSet) {
      if (rendered.includes(JSON.stringify(t))) {
        return {
          body: input.body,
          applied: false,
          reason: 'dangling_template_reference',
          emitted: 0,
        };
      }
    }
  }
  return { body: rendered, applied: true, emitted: emitted.length };
}
