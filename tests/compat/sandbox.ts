/**
 * A served body made runnable in the compat client container, and nothing
 * else: the container has no TUN device (the local SOCKS listener the probes
 * use carries the requests, on 127.0.0.1:1080), no public resolver (every
 * plain DNS server points at Docker's own), and nothing may be exposed or
 * downloaded (no controller, no dashboard, no extra ports). Everything that
 * decides where traffic goes stays as served: the proxies and groups, the
 * Mihomo `mode` and `rules`, the sing-box `route`. `routing` is that part,
 * which the caller asserts the sandbox left alone.
 */
import YAML from 'yaml';

/** Docker's embedded resolver, inside every container on a user network. */
const DOCKER_DNS = '127.0.0.11';
const PORT = 1080;

type Obj = Record<string, any>;

export function sandboxed(engine: 'singbox' | 'mihomo', body: string): string {
  if (engine === 'singbox') {
    const c = JSON.parse(body) as Obj;
    c.inbounds = (c.inbounds ?? []).filter((i: Obj) => i.type !== 'tun');
    const mixed = c.inbounds.find((i: Obj) => i.type === 'mixed');
    if (!mixed) throw new Error('the served sing-box body has no mixed listener');
    Object.assign(mixed, { listen: '127.0.0.1', listen_port: PORT });
    if (c.dns?.servers)
      c.dns.servers = c.dns.servers.map((s: Obj) =>
        ['udp', 'tcp', 'tls', 'https', 'quic', 'h3'].includes(s.type)
          ? { type: 'udp', tag: s.tag, server: DOCKER_DNS }
          : s,
      );
    if (c.experimental) delete c.experimental.clash_api;
    return JSON.stringify(c);
  }
  const c = YAML.parse(body) as Obj;
  for (const key of ['port', 'socks-port', 'redir-port', 'tproxy-port', 'external-controller'])
    delete c[key];
  delete c.tun;
  Object.assign(c, { 'mixed-port': PORT, 'allow-lan': false, 'bind-address': '127.0.0.1' });
  if (c.dns)
    for (const key of ['default-nameserver', 'nameserver', 'proxy-server-nameserver', 'fallback'])
      if (c.dns[key]) c.dns[key] = [DOCKER_DNS];
  return YAML.stringify(c);
}

/** What decides where a body sends traffic. */
export function routing(engine: 'singbox' | 'mihomo', body: string): unknown {
  if (engine === 'singbox') {
    const c = JSON.parse(body) as Obj;
    return { outbounds: c.outbounds, route: c.route };
  }
  const c = YAML.parse(body) as Obj;
  return { mode: c.mode, proxies: c.proxies, groups: c['proxy-groups'], rules: c.rules };
}

/** A separate per-endpoint probe: the default selector has exactly one choice. */
export function selectProxy(engine: 'singbox' | 'mihomo', body: string, name: string): string {
  if (engine === 'singbox') {
    const c = JSON.parse(body) as Obj;
    const group = c.outbounds.find((o: Obj) => o.tag === c.route.final);
    if (group?.type !== 'selector' || !group.outbounds.includes(name))
      throw new Error('Probe proxy is not in the default selector');
    group.outbounds = [name];
    group.default = name;
    return JSON.stringify(c);
  }
  const c = YAML.parse(body) as Obj;
  const target = c.rules.at(-1).split(',')[1].trim();
  const group = c['proxy-groups'].find((g: Obj) => g.name === target);
  if (group?.type !== 'select' || !group.proxies.includes(name))
    throw new Error('Probe proxy is not in the default selector');
  group.proxies = [name];
  return YAML.stringify(c);
}
