/**
 * sing-box JSON renderer. The panel emits one outbound per Host tagged with the
 * Host remark, plus selector/urltest groups listing those tags. Each listener's
 * template outbound is found by its matcher (tag, or server:server_port, or the
 * whole single-outbound body) and verified against what the listener speaks;
 * we clone it per assigned endpoint (server, server_port, tls.server_name, tag
 * = label), drop the template outbounds, replace their membership in every
 * group with the emitted tags, and (per rule) ensure a `urltest` group named
 * after the auto group that contains exactly the emitted tags and is the
 * selector's default. Fail-open on any unknown shape.
 *
 * Removing a template never leaves a dangling reference: every other mention
 * of its tag (route rules, `route.final`, DNS/outbound `detour`s, group
 * `default`s) is rewritten to the rendered fallback or pruned structurally
 * (`refs.ts`), so the config stays valid instead of falling back to the
 * original body, which would hand the template's address back out.
 */
import { sameAddress } from '../hosts';
import { codecFor, type ListenerProto } from '../protocols';
import { cloneJson, pruneRefs, uniqueName } from './refs';
import {
  AUTO_GROUP_TEST_URL,
  orderEndpoints,
  resolveMatchers,
  templateIdentities,
  type MatchableEntry,
  type RenderInput,
  type RenderMatcher,
  type RenderOutput,
} from './types';

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const NON_PROXY_TYPES = new Set(['direct', 'block', 'dns', 'selector', 'urltest']);

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

/** Whether an outbound's tls / transport blocks agree with the listener. */
function outboundAgrees(ob: Obj, proto: ListenerProto): boolean {
  const tls = isObj(ob.tls) ? ob.tls : null;
  const tlsOn = !!tls && tls.enabled !== false;
  const reality = tlsOn && isObj(tls!.reality) && (tls!.reality as Obj).enabled !== false;
  const transport = isObj(ob.transport) ? String(ob.transport.type ?? '') : '';
  const streamAgrees =
    proto.streamTransport === 'raw'
      ? transport === '' || transport === 'tcp'
      : proto.streamTransport === 'udp'
        ? true
        : transport === proto.streamTransport;
  switch (proto.security) {
    case 'reality':
      return streamAgrees && reality;
    case 'tls':
      return streamAgrees && tlsOn && !reality;
    case 'none':
      return streamAgrees && !tlsOn;
  }
}

function entriesOf(outbounds: readonly unknown[]): MatchableEntry<Obj>[] {
  const out: MatchableEntry<Obj>[] = [];
  for (const ob of outbounds) {
    if (!isObj(ob) || typeof ob.type !== 'string') continue;
    if (NON_PROXY_TYPES.has(ob.type) || Array.isArray(ob.outbounds)) continue;
    const address = typeof ob.server === 'string' ? ob.server : null;
    const port = typeof ob.server_port === 'number' ? ob.server_port : null;
    out.push({
      entry: ob,
      identity: typeof ob.tag === 'string' ? ob.tag : null,
      address,
      port,
      supported: (proto) => codecFor(proto, 'singbox').includes(String(ob.type)),
      agrees: (proto) => outboundAgrees(ob, proto),
    });
  }
  return out;
}

/** Which listeners resolve in this body (the pipeline's eligibility pass). */
export function matchSingbox(body: string, matchers: readonly RenderMatcher[]) {
  let cfg: unknown;
  try {
    cfg = JSON.parse(body);
  } catch {
    return null;
  }
  if (!isObj(cfg) || !Array.isArray(cfg.outbounds)) return null;
  return resolveMatchers(entriesOf(cfg.outbounds as unknown[]), matchers, sameAddress);
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
  const entries = entriesOf(outbounds);
  const { templates, matches } = resolveMatchers(entries, input.matchers, sameAddress);
  if (templates.size === 0)
    return {
      body: input.body,
      applied: false,
      reason: 'no_template_outbounds',
      emitted: 0,
      listeners: matches,
    };
  const templateSet = templateIdentities(entries, templates);
  const templateObjs = new Set(templates.values());
  const isTemplate = (ob: Obj) =>
    templateObjs.has(ob) || (typeof ob.tag === 'string' && templateSet.has(ob.tag));

  const taken = new Set<string>();
  let autoGroupIsGroup = false;
  for (const ob of outbounds) {
    if (!isObj(ob) || typeof ob.tag !== 'string') continue;
    if (isTemplate(ob)) continue;
    taken.add(ob.tag);
    if (ob.tag === input.rule.autoGroupName && Array.isArray(ob.outbounds)) autoGroupIsGroup = true;
  }

  // The auto group reuses an existing GROUP of that name; a non-group outbound
  // already holding the name forces a suffixed one so tags stay unique.
  const autoName = autoGroupIsGroup
    ? input.rule.autoGroupName
    : uniqueName(input.rule.autoGroupName, taken);
  if (input.rule.autoGroup) taken.add(autoName);

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.listenerKey);
    if (!tpl) continue;
    const clone = cloneJson(tpl);
    const tag = uniqueName(ep.label, taken);
    taken.add(tag);
    clone.tag = tag;
    clone.server = ep.address;
    clone.server_port = ep.port;
    if (ep.sni !== null && isObj(clone.tls)) clone.tls = { ...clone.tls, server_name: ep.sni };
    // The HTTP transports carry their own Host, which an L7 front must see as
    // its own hostname (and an L4 edge as the name it presents). `path` /
    // `service_name` stay exactly as the panel wrote them: they are the node's
    // routing, not the front's.
    if (ep.hostHeader !== null && isObj(clone.transport)) {
      const transport = clone.transport;
      if (transport.type === 'ws') {
        const headers = isObj(transport.headers) ? { ...transport.headers } : {};
        headers.Host = ep.hostHeader;
        clone.transport = { ...transport, headers };
      } else if (transport.type === 'httpupgrade') {
        clone.transport = { ...transport, host: ep.hostHeader };
      }
      // gRPC takes the authority from the server name; nothing to write.
    }
    emitted.push(clone);
  }
  // Drop-only: no endpoint to emit (empty pool): remove the templates, prune
  // their group memberships, and drop the groups that end up empty (the auto
  // group included: an empty urltest is not a valid outbound).
  const dropOnly = emitted.length === 0;
  if (dropOnly && !input.rule.dropTemplateEntries)
    return {
      body: input.body,
      applied: false,
      reason: 'no_endpoints_rendered',
      emitted: 0,
      listeners: matches,
    };
  const emittedTags = emitted.map((e) => e.tag as string);
  const useAuto = input.rule.autoGroup && !dropOnly;
  // A template found by address may carry a tag no group names; groups are
  // swapped by tag, so every template's tag (when it has one) is in the set.
  for (const t of templateObjs) if (typeof t.tag === 'string') templateSet.add(t.tag);

  const next: unknown[] = [];
  let inserted = false;
  let sawAutoGroup = false;
  for (const ob of outbounds) {
    if (!isObj(ob)) {
      next.push(ob);
      continue;
    }
    const tag = typeof ob.tag === 'string' ? ob.tag : null;
    if (isTemplate(ob)) {
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
      // Only ADOPT an operator group of that name when the auto group is on:
      // with `autoGroup` off the name is the operator's, not ours.
      if (useAuto && tag === autoName && autoGroupIsGroup) {
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
    return {
      body: input.body,
      applied: false,
      reason: 'template_not_in_outbounds',
      emitted: 0,
      listeners: matches,
    };
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
      listeners: matches,
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
  const fallback =
    useAuto && !removed.has(autoName) ? autoName : (emittedTags[0] ?? fallbackTag(list));
  const pruned = pruneRefs({ ...cfg, outbounds: list }, removed, fallback) as Obj;
  return {
    body: JSON.stringify(pruned),
    applied: true,
    ...(dropOnly ? { reason: 'templates_dropped' } : {}),
    emitted: emitted.length,
    listeners: matches,
  };
}

/** Every proxy outbound's server in a body: the leak check's input. */
export function singboxAddresses(body: string): Array<{ address: string; port: number }> {
  let cfg: unknown;
  try {
    cfg = JSON.parse(body);
  } catch {
    return [];
  }
  if (!isObj(cfg) || !Array.isArray(cfg.outbounds)) return [];
  const out: Array<{ address: string; port: number }> = [];
  for (const ob of cfg.outbounds as unknown[]) {
    if (!isObj(ob) || typeof ob.server !== 'string') continue;
    out.push({ address: ob.server, port: typeof ob.server_port === 'number' ? ob.server_port : 0 });
  }
  return out;
}
