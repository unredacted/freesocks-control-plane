/**
 * The direct-node rehearsal check (pure): does a real panel body, in each
 * client family, carry an entry for the node's endpoint, and does that entry
 * say what the node serves (REALITY with the expected public key, presenting
 * the expected server name). Every one of a node's addresses is checked, since
 * one good entry says nothing about the others. Bodies are
 * what the panel actually generated for the test credential: a base64 or
 * plain link list, a sing-box JSON config, or a Clash / Mihomo YAML.
 */
import { decodeLinkList } from '../edges/render/links';
import { parseProxyUri } from '../edges/render/uri';

export interface EndpointExpectation {
  address: string;
  port: number;
  /** The REALITY public key the entry must carry (links and sing-box name it; Clash as `public-key`). */
  publicKey?: string | null;
  /**
   * The server name the entry must present (links `sni`, sing-box
   * `tls.server_name`, Clash `servername`). A direct node has one address per
   * family name, so the address alone does not say which name was served.
   */
  sni?: string | null;
}

export type RehearsalFamily = 'links' | 'singbox' | 'clash';

export interface RehearsalVerdict {
  found: boolean;
  /** The entry names the endpoint but not the expected key (a stale profile, another inbound). */
  keyMismatch: boolean;
  /** The entry names the endpoint and the key, but serves another name. */
  sniMismatch?: boolean;
}

function sameHost(a: string, b: string): boolean {
  return (
    a
      .trim()
      .toLowerCase()
      .replace(/^\[|\]$/g, '') === b.trim().toLowerCase()
  );
}

function checkLinks(body: string, e: EndpointExpectation): RehearsalVerdict {
  const decoded = decodeLinkList(body);
  if (!decoded) return { found: false, keyMismatch: false };
  let keyMismatch = false;
  let sniMismatch = false;
  for (const line of decoded.lines) {
    const uri = parseProxyUri(line);
    if (!uri || !sameHost(uri.host, e.address) || uri.port !== e.port) continue;
    const pbk = uri.params.get('pbk');
    if (e.publicKey && pbk !== e.publicKey) {
      keyMismatch = true;
      continue;
    }
    if (e.sni && !sameHost(uri.params.get('sni') ?? '', e.sni)) {
      sniMismatch = true;
      continue;
    }
    return { found: true, keyMismatch: false };
  }
  return { found: false, keyMismatch, sniMismatch };
}

function walk(v: unknown, visit: (o: Record<string, unknown>) => void): void {
  if (Array.isArray(v)) for (const x of v) walk(x, visit);
  else if (v && typeof v === 'object') {
    visit(v as Record<string, unknown>);
    for (const x of Object.values(v as Record<string, unknown>)) walk(x, visit);
  }
}

function checkSingbox(body: string, e: EndpointExpectation): RehearsalVerdict {
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return { found: false, keyMismatch: false };
  }
  let found = false;
  let keyMismatch = false;
  let sniMismatch = false;
  walk(json, (o) => {
    if (found) return;
    if (typeof o.server !== 'string' || !sameHost(o.server, e.address)) return;
    if (o.server_port !== e.port) return;
    const tls = o.tls as { server_name?: string; reality?: { public_key?: string } } | undefined;
    if (e.publicKey && tls?.reality?.public_key !== e.publicKey) {
      keyMismatch = true;
      return;
    }
    if (e.sni && !sameHost(tls?.server_name ?? '', e.sni)) {
      sniMismatch = true;
      return;
    }
    found = true;
  });
  return {
    found,
    keyMismatch: found ? false : keyMismatch,
    sniMismatch: found ? false : sniMismatch,
  };
}

function checkClash(body: string, e: EndpointExpectation): RehearsalVerdict {
  // One proxy per `- name:` block; the fields we read are flat scalars.
  const blocks = body.split(/\n(?=\s*-\s+name:)/);
  let keyMismatch = false;
  let sniMismatch = false;
  for (const b of blocks) {
    const server = /^\s*server:\s*['"]?([^'"\s]+)['"]?\s*$/m.exec(b)?.[1];
    const port = /^\s*port:\s*(\d+)\s*$/m.exec(b)?.[1];
    if (!server || !sameHost(server, e.address) || Number(port) !== e.port) continue;
    const pbk = /^\s*public-key:\s*['"]?([^'"\s]+)['"]?\s*$/m.exec(b)?.[1];
    if (e.publicKey && pbk !== e.publicKey) {
      keyMismatch = true;
      continue;
    }
    const sni = /^\s*servername:\s*['"]?([^'"\s]+)['"]?\s*$/m.exec(b)?.[1];
    if (e.sni && !sameHost(sni ?? '', e.sni)) {
      sniMismatch = true;
      continue;
    }
    return { found: true, keyMismatch: false };
  }
  return { found: false, keyMismatch, sniMismatch };
}

/** Whether the body of one client family carries the node's endpoint as expected. */
export function bodyHasEndpoint(
  family: RehearsalFamily,
  body: string,
  e: EndpointExpectation,
): RehearsalVerdict {
  if (family === 'singbox') return checkSingbox(body, e);
  if (family === 'clash') return checkClash(body, e);
  return checkLinks(body, e);
}

/** The panel picks its template by User-Agent; these select the three families. */
export const REHEARSAL_USER_AGENTS: Readonly<Record<RehearsalFamily, string>> = {
  links: 'v2rayNG/1.8.29',
  singbox: 'SFI/1.11.0 sing-box/1.11.0',
  clash: 'clash-verge/2.0.0 mihomo/1.19.0',
};
