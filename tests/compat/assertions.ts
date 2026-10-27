import { parse } from 'yaml';
import type { Format } from './manifest';

export interface SubscriptionEndpoint {
  server: string;
  port: number;
  serverName: string | null;
}
export interface SubscriptionEntry extends SubscriptionEndpoint {
  name: string;
}
type Obj = Record<string, any>;
const object = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0;

/** Error messages never include a response, proxy name or credential. */
export function subscriptionEntries(
  body: string,
  format: Exclude<Format, 'outline'>,
): SubscriptionEntry[] {
  let entries: SubscriptionEntry[];
  if (format === 'links') {
    try {
      const content = body.trim().startsWith('vless://')
        ? body.trim()
        : Buffer.from(body.trim(), 'base64').toString('utf8');
      const links = content.split(/\r?\n/).filter(Boolean);
      if (!links.length || links.some((line) => !line.startsWith('vless://'))) throw new Error();
      entries = links.map((line) => {
        const url = new URL(line);
        if (!/^[0-9a-f-]{36}$/i.test(url.username)) throw new Error();
        return {
          name: decodeURIComponent(url.hash.slice(1)),
          server: url.hostname,
          port: Number(url.port),
          serverName: url.searchParams.get('sni') || url.searchParams.get('host'),
        };
      });
    } catch {
      throw new Error('Expected complete VLESS subscription links');
    }
  } else {
    let config: unknown;
    try {
      config = format === 'singbox' ? JSON.parse(body) : parse(body);
    } catch {
      throw new Error(
        format === 'singbox'
          ? 'Expected sing-box JSON; received non-JSON subscription'
          : 'Expected Mihomo YAML',
      );
    }
    if (!object(config)) throw new Error('Expected a proxy configuration');
    const definitions: unknown = format === 'singbox' ? config.outbounds : config.proxies;
    if (!Array.isArray(definitions) || !definitions.every(object))
      throw new Error('Expected proxy definitions');
    const proxies = definitions.filter((p) => p.type === 'vless');
    entries = proxies.map((p) => ({
      name: format === 'singbox' ? p.tag : p.name,
      server: p.server,
      port: format === 'singbox' ? p.server_port : p.port,
      serverName:
        format === 'singbox' ? (p.tls?.server_name ?? null) : (p.servername ?? p.sni ?? null),
    }));
    if (entries.some((e) => !text(e.name))) throw new Error('Missing proxy name');
    assertSelectable(config, format, definitions, entries);
  }
  if (!entries.length) throw new Error('No VLESS proxy in subscription');
  if (
    entries.some(
      (e) => !text(e.server) || !Number.isInteger(e.port) || e.port < 1 || e.port > 65535,
    )
  )
    throw new Error('Incomplete VLESS endpoint');
  if (new Set(entries.map((e) => e.name)).size !== entries.length)
    throw new Error('Duplicate VLESS proxy names');
  return entries;
}

/** Every VLESS entry must be reachable from the default group, not merely defined. */
function assertSelectable(
  config: Obj,
  format: 'singbox' | 'mihomo',
  definitions: Obj[],
  entries: SubscriptionEntry[],
): void {
  const singbox = format === 'singbox';
  const groups: Obj[] = singbox
    ? definitions.filter((p) => p.type === 'selector' || p.type === 'urltest')
    : config['proxy-groups'];
  if (!Array.isArray(groups) || !groups.every(object)) throw new Error('Missing proxy groups');
  const name = (p: Obj): string => (singbox ? p.tag : p.name);
  const all = singbox ? definitions : [...definitions, ...groups];
  const names = all.map(name);
  if (names.some((n) => !text(n)) || new Set(names).size !== names.length)
    throw new Error('Missing or duplicate outbound names');
  const known = new Set(names);
  if (!singbox)
    for (const builtin of ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'])
      known.add(builtin);
  const members = new Map<string, string[]>();
  for (const group of groups) {
    const list: unknown = singbox ? group.outbounds : group.proxies;
    if (!Array.isArray(list) || !list.length || !list.every((n) => text(n) && known.has(n)))
      throw new Error('Empty group or dangling proxy reference');
    if (singbox && group.default !== undefined && !list.includes(group.default))
      throw new Error('Group default is not a member');
    members.set(name(group), list);
  }
  const catchAll =
    !singbox && Array.isArray(config.rules)
      ? config.rules
          .filter((r: unknown) => typeof r === 'string' && /^(MATCH|FINAL),/i.test(r))
          .at(-1)
      : undefined;
  const root = singbox
    ? (config.route?.final ?? definitions[0]?.tag)
    : catchAll?.split(',')[1]?.trim();
  if (!members.has(root)) throw new Error('Default route does not select a proxy group');
  const reachable = new Set<string>();
  const visit = (n: string, path: Set<string>) => {
    if (path.has(n)) throw new Error('Cyclic proxy group');
    if (reachable.has(n)) return;
    reachable.add(n);
    for (const next of members.get(n) ?? []) visit(next, new Set([...path, n]));
  };
  visit(root, new Set());
  if (entries.some((e) => !reachable.has(e.name)))
    throw new Error('VLESS proxy is missing from the default selector');
}

/** Optional fixture identities catch dropped, duplicated or substituted endpoints. */
export function assertSubscription(
  body: string,
  format: Format,
  expected?: readonly SubscriptionEndpoint[],
): void {
  if (format === 'outline') {
    if (!body.startsWith('ss://')) throw new Error('Expected Outline access key');
    return;
  }
  const entries = subscriptionEntries(body, format);
  if (!expected) return;
  const key = (e: SubscriptionEndpoint) => JSON.stringify([e.server, e.port, e.serverName]);
  const actualKeys = entries.map(key).sort();
  const expectedKeys = expected.map(key).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys))
    throw new Error('Subscription endpoint set differs from the fixture');
}
