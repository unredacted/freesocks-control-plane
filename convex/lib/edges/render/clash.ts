/**
 * Clash / Mihomo / Stash YAML renderer. The panel emits `proxies:` (one entry
 * per Host, `name` = Host remark, `server`, `port`, `servername`) and
 * `proxy-groups:` whose `proxies` lists those names. Each listener's template
 * proxy is found by its matcher (name, or server:port, or the whole
 * single-proxy body) and verified against what the listener speaks; we clone
 * it per assigned endpoint, drop the templates, replace their membership in
 * every group with the emitted names and (per rule) ensure a `url-test` group
 * named after the auto group, listed first in the selector. Comments are
 * dropped by the round trip (acceptable; the panel's template comments are
 * operator notes). Fail-open on any unknown shape.
 *
 * Removing a template never leaves a dangling reference: `rules` targets
 * (`MATCH,<name>`), other groups and any other mention are rewritten to the
 * rendered fallback or pruned structurally (`refs.ts`), never by returning the
 * original body.
 */
import YAML from 'yaml';
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
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Proxy types whose TLS name key is `sni` (the rest use `servername`). */
const SNI_KEY_TYPES = new Set(['trojan', 'hysteria', 'hysteria2', 'tuic', 'anytls']);

/** Set the server name a cloned proxy presents. Mihomo defaults the SNI to
 *  `server` when the key is absent, which would present the edge's IP: so the
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

/** Whether a proxy's tls / network keys agree with the listener. */
function proxyAgrees(p: Obj, proto: ListenerProto): boolean {
  const type = String(p.type ?? '');
  const reality = isObj(p['reality-opts']);
  // Trojan / hysteria2 / tuic are TLS by nature and carry no `tls:` key.
  const tlsOn = p.tls === true || SNI_KEY_TYPES.has(type) || reality;
  const network = String(p.network ?? 'tcp');
  const streamAgrees =
    proto.streamTransport === 'raw'
      ? network === 'tcp'
      : proto.streamTransport === 'udp'
        ? true
        : proto.streamTransport === 'httpupgrade'
          ? network === 'ws' // Clash has no httpupgrade network: mihomo serves it as ws.
          : network === proto.streamTransport;
  switch (proto.security) {
    case 'reality':
      return streamAgrees && reality;
    case 'tls':
      return streamAgrees && tlsOn && !reality;
    case 'none':
      return streamAgrees && !tlsOn;
  }
}

function entriesOf(proxies: readonly unknown[]): MatchableEntry<Obj>[] {
  const out: MatchableEntry<Obj>[] = [];
  for (const p of proxies) {
    if (!isObj(p) || typeof p.type !== 'string') continue;
    out.push({
      entry: p,
      identity: typeof p.name === 'string' ? p.name : null,
      address: typeof p.server === 'string' ? p.server : null,
      port: typeof p.port === 'number' ? p.port : null,
      supported: (proto) => codecFor(proto, 'clash').includes(String(p.type)),
      agrees: (proto) => proxyAgrees(p, proto),
    });
  }
  return out;
}

/** Which listeners resolve in this body (the pipeline's eligibility pass). */
export function matchClash(body: string, matchers: readonly RenderMatcher[]) {
  let doc: unknown;
  try {
    doc = YAML.parse(body);
  } catch {
    return null;
  }
  if (!isObj(doc) || !Array.isArray(doc.proxies)) return null;
  return resolveMatchers(entriesOf(doc.proxies as unknown[]), matchers, sameAddress);
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
  const entries = entriesOf(proxies);
  const { templates, matches } = resolveMatchers(entries, input.matchers, sameAddress);
  if (templates.size === 0)
    return {
      body: input.body,
      applied: false,
      reason: 'no_template_proxies',
      emitted: 0,
      listeners: matches,
    };
  const templateSet = templateIdentities(entries, templates);
  const templateObjs = new Set(templates.values());
  for (const t of templateObjs) if (typeof t.name === 'string') templateSet.add(t.name);
  const isTemplate = (p: Obj) =>
    templateObjs.has(p) || (typeof p.name === 'string' && templateSet.has(p.name));

  const taken = new Set<string>();
  for (const p of proxies) {
    if (!isObj(p) || typeof p.name !== 'string') continue;
    if (isTemplate(p)) continue;
    taken.add(p.name);
  }
  let autoGroupIsGroup = false;
  for (const g of groups) {
    if (!isObj(g) || typeof g.name !== 'string') continue;
    taken.add(g.name);
    if (g.name === input.rule.autoGroupName && Array.isArray(g.proxies)) autoGroupIsGroup = true;
  }

  const autoName = autoGroupIsGroup
    ? input.rule.autoGroupName
    : uniqueName(input.rule.autoGroupName, taken);
  if (input.rule.autoGroup) taken.add(autoName);

  const emitted: Obj[] = [];
  for (const ep of orderEndpoints(input.endpoints, input.rule)) {
    const tpl = templates.get(ep.listenerKey);
    if (!tpl) continue;
    const clone = cloneJson(tpl);
    const name = uniqueName(ep.label, taken);
    taken.add(name);
    clone.name = name;
    clone.server = ep.address;
    clone.port = ep.port;
    if (ep.sni !== null) setServerName(clone, ep.sni);
    // `network: ws` carries the Host in `ws-opts.headers` (Clash has no
    // httpupgrade network, so an httpupgrade listener is served as ws); gRPC
    // takes its authority from the server name. `ws-opts.path` /
    // `grpc-opts.grpc-service-name` are the node's routing and stay untouched.
    if (ep.hostHeader !== null && clone.network === 'ws') {
      const wsOpts = isObj(clone['ws-opts']) ? { ...clone['ws-opts'] } : {};
      const headers = isObj(wsOpts.headers) ? { ...wsOpts.headers } : {};
      headers.Host = ep.hostHeader;
      wsOpts.headers = headers;
      clone['ws-opts'] = wsOpts;
    }
    // Mihomo's XHTTP carries the Host in `xhttp-opts.host`; `path` and `mode`
    // are the node's and stay untouched.
    if (ep.hostHeader !== null && clone.network === 'xhttp') {
      const opts = isObj(clone['xhttp-opts']) ? { ...clone['xhttp-opts'] } : {};
      opts.host = ep.hostHeader;
      clone['xhttp-opts'] = opts;
    }
    emitted.push(clone);
  }
  const dropOnly = emitted.length === 0;
  if (dropOnly && !input.rule.dropTemplateEntries)
    return {
      body: input.body,
      applied: false,
      reason: 'no_endpoints_rendered',
      emitted: 0,
      listeners: matches,
    };
  const names = emitted.map((e) => e.name as string);
  const useAuto = input.rule.autoGroup && !dropOnly;

  const nextProxies: unknown[] = [];
  let inserted = false;
  for (const p of proxies) {
    if (isObj(p) && isTemplate(p)) {
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
    if (useAuto && g.name === autoName && autoGroupIsGroup) {
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
      listeners: matches,
    };
  }

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
    listeners: matches,
  };
}

/** Every proxy's server in a body: the leak check's input. */
export function clashAddresses(body: string): Array<{ address: string; port: number }> {
  let doc: unknown;
  try {
    doc = YAML.parse(body);
  } catch {
    return [];
  }
  if (!isObj(doc) || !Array.isArray(doc.proxies)) return [];
  const out: Array<{ address: string; port: number }> = [];
  for (const p of doc.proxies as unknown[]) {
    if (!isObj(p) || typeof p.server !== 'string') continue;
    out.push({ address: p.server, port: typeof p.port === 'number' ? p.port : 0 });
  }
  return out;
}
