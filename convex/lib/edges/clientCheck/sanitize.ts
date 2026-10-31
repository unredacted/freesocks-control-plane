/**
 * What the client-check service accepts as an outbound (docs/edges.md § "FCP's
 * own client check"). Every outbound is REBUILT from a per-engine allowlist of
 * fields: anything not listed is dropped, a listed field of the wrong type
 * refuses the whole outbound. So no request can reach an engine option that
 * chains another outbound (`detour`, `dialerProxy`), binds an interface, sets a
 * routing mark, reads a file or opens a second destination (XHTTP's
 * `downloadSettings`).
 *
 * The one destination must be an IP literal, and a public one (`allowPrivate`
 * is for the CI harness only, whose nodes sit on private addresses). A name is
 * refused: it would be resolved by the service, where FCP cannot see what it
 * becomes.
 */
import type { ClientCheckEngine } from '../../../../src/shared/contracts/edgeCodes';
import { addressFamily, isPublicIpLiteral } from '../ip';

type Obj = Record<string, unknown>;
type Field =
  | 'string'
  | 'longString'
  | 'number'
  | 'boolean'
  | 'scalar'
  | 'strings'
  | 'headers'
  | Spec
  | [Spec];
interface Spec {
  [key: string]: Field;
}

/** Longest string value kept (keys, ids, paths, names). */
const MAX_STRING = 512;
/** A REALITY ML-DSA-65 verification key: 1,952 bytes, base64 encoded (with room). */
const MAX_LONG_STRING = 4096;
const MAX_LIST = 8;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

const INVALID = Symbol('invalid');

function value(x: unknown, f: Field): unknown {
  if (f === 'string') return typeof x === 'string' && x.length <= MAX_STRING ? x : INVALID;
  if (f === 'longString') return typeof x === 'string' && x.length <= MAX_LONG_STRING ? x : INVALID;
  if (f === 'number') return typeof x === 'number' && Number.isFinite(x) ? x : INVALID;
  if (f === 'boolean') return typeof x === 'boolean' ? x : INVALID;
  if (f === 'scalar')
    return (typeof x === 'string' && x.length <= MAX_STRING) ||
      (typeof x === 'number' && Number.isFinite(x))
      ? x
      : INVALID;
  if (f === 'strings')
    return Array.isArray(x) &&
      x.length <= MAX_LIST &&
      x.every((s) => typeof s === 'string' && s.length <= MAX_STRING)
      ? [...x]
      : INVALID;
  if (f === 'headers') {
    if (!isObj(x)) return INVALID;
    const entries = Object.entries(x);
    if (
      entries.length > MAX_LIST ||
      !entries.every(([k, s]) => /^[A-Za-z0-9-]{1,64}$/.test(k) && typeof s === 'string')
    )
      return INVALID;
    return Object.fromEntries(entries.map(([k, s]) => [k, String(s).slice(0, MAX_STRING)]));
  }
  if (Array.isArray(f)) {
    // A one-element list (one server, one user): never a second destination.
    if (!Array.isArray(x) || x.length !== 1) return INVALID;
    const one = pick(x[0], f[0]!);
    return one === null ? INVALID : [one];
  }
  const nested = pick(x, f);
  return nested === null ? INVALID : nested;
}

/** The allowlisted fields of `v`, or null when one has the wrong type. */
function pick(v: unknown, spec: Spec): Obj | null {
  if (!isObj(v)) return null;
  const out: Obj = {};
  for (const [k, f] of Object.entries(spec)) {
    const x = v[k];
    if (x === undefined || x === null) continue;
    const kept = value(x, f);
    if (kept === INVALID) return null;
    out[k] = kept;
  }
  return out;
}

// --- sing-box --------------------------------------------------------------------------------

const SB_TLS: Spec = {
  enabled: 'boolean',
  server_name: 'string',
  insecure: 'boolean',
  alpn: 'strings',
  utls: { enabled: 'boolean', fingerprint: 'string' },
  reality: { enabled: 'boolean', public_key: 'string', short_id: 'string' },
};
const SB_TRANSPORT: Spec = {
  type: 'string',
  path: 'string',
  host: 'string',
  service_name: 'string',
  headers: 'headers',
  max_early_data: 'number',
  early_data_header_name: 'string',
};
const SB_TRANSPORT_TYPES = new Set(['ws', 'grpc', 'httpupgrade']);
const SB_BASE: Spec = { type: 'string', server: 'string', server_port: 'number' };
const SB_TYPES: Record<string, Spec> = {
  vless: { ...SB_BASE, uuid: 'string', flow: 'string', tls: SB_TLS, transport: SB_TRANSPORT },
  trojan: { ...SB_BASE, password: 'string', tls: SB_TLS, transport: SB_TRANSPORT },
  shadowsocks: { ...SB_BASE, method: 'string', password: 'string' },
  hysteria2: {
    ...SB_BASE,
    password: 'string',
    tls: SB_TLS,
    obfs: { type: 'string', password: 'string' },
  },
  tuic: {
    ...SB_BASE,
    uuid: 'string',
    password: 'string',
    congestion_control: 'string',
    tls: SB_TLS,
  },
};

// --- Xray ------------------------------------------------------------------------------------

const XR_STREAM: Spec = {
  network: 'string',
  security: 'string',
  tlsSettings: {
    serverName: 'string',
    fingerprint: 'string',
    alpn: 'strings',
    allowInsecure: 'boolean',
  },
  realitySettings: {
    serverName: 'string',
    fingerprint: 'string',
    publicKey: 'string',
    password: 'string',
    shortId: 'string',
    spiderX: 'string',
    mldsa65Verify: 'longString',
  },
  wsSettings: { path: 'string', host: 'string', headers: 'headers' },
  grpcSettings: { serviceName: 'string', authority: 'string', multiMode: 'boolean' },
  httpupgradeSettings: { path: 'string', host: 'string' },
  xhttpSettings: {
    path: 'string',
    host: 'string',
    mode: 'string',
    // Request shaping only. `downloadSettings` (a second destination) is not here.
    extra: {
      headers: 'headers',
      xPaddingBytes: 'scalar',
      noGRPCHeader: 'boolean',
      noSSEHeader: 'boolean',
      scMaxEachPostBytes: 'scalar',
      scMinPostsIntervalMs: 'scalar',
      scMaxBufferedPosts: 'number',
      scStreamUpServerSecs: 'scalar',
      xmux: {
        maxConcurrency: 'scalar',
        maxConnections: 'scalar',
        cMaxReuseTimes: 'scalar',
        hMaxRequestTimes: 'scalar',
        hMaxReusableSecs: 'scalar',
        hKeepAlivePeriod: 'number',
      },
    },
  },
};
const XR_NETWORKS = new Set(['raw', 'tcp', 'ws', 'grpc', 'httpupgrade', 'xhttp']);
const XR_SECURITY = new Set(['none', 'tls', 'reality']);
const XR_TYPES: Record<string, Spec> = {
  vless: {
    vnext: [
      {
        address: 'string',
        port: 'number',
        users: [{ id: 'string', encryption: 'string', flow: 'string' }],
      },
    ],
  },
  trojan: { servers: [{ address: 'string', port: 'number', password: 'string' }] },
  shadowsocks: {
    servers: [{ address: 'string', port: 'number', method: 'string', password: 'string' }],
  },
};

// --- Mihomo ----------------------------------------------------------------------------------

const MH_BASE: Spec = {
  type: 'string',
  server: 'string',
  port: 'number',
  udp: 'boolean',
  network: 'string',
  tls: 'boolean',
  alpn: 'strings',
  'skip-cert-verify': 'boolean',
  'client-fingerprint': 'string',
  'reality-opts': {
    'public-key': 'string',
    'short-id': 'string',
    'support-x25519mlkem768': 'boolean',
  },
  'ws-opts': {
    path: 'string',
    headers: 'headers',
    'max-early-data': 'number',
    'early-data-header-name': 'string',
    'v2ray-http-upgrade': 'boolean',
  },
  'grpc-opts': { 'grpc-service-name': 'string' },
};
// VLESS and Trojan only: the protocols whose names a send proves. Nothing that
// chains (`dialer-proxy`), binds (`interface-name`, `routing-mark`) or opens a
// second destination is listed, so none of it reaches the engine.
const MH_TYPES: Record<string, Spec> = {
  vless: { ...MH_BASE, uuid: 'string', flow: 'string', servername: 'string' },
  trojan: { ...MH_BASE, password: 'string', sni: 'string' },
};
const MH_NETWORKS = new Set(['tcp', 'ws', 'grpc']);

export type SanitizeResult =
  | { ok: true; outbound: Obj; destination: { address: string; port: number } }
  | { ok: false; code: 'unsupported_type' | 'invalid_outbound' | 'destination_not_public' };

function destinationOk(address: unknown, port: unknown, allowPrivate: boolean): boolean {
  if (typeof address !== 'string' || addressFamily(address) === null) return false;
  if (typeof port !== 'number' || !Number.isInteger(port) || port < 1 || port > 65535) return false;
  return allowPrivate || isPublicIpLiteral(address);
}

export function sanitizeOutbound(
  engine: ClientCheckEngine,
  raw: unknown,
  opts: { allowPrivate?: boolean } = {},
): SanitizeResult {
  const allowPrivate = opts.allowPrivate === true;
  if (!isObj(raw)) return { ok: false, code: 'invalid_outbound' };
  if (engine === 'mihomo') {
    const spec = typeof raw.type === 'string' ? MH_TYPES[raw.type] : undefined;
    if (!spec) return { ok: false, code: 'unsupported_type' };
    const out = pick(raw, spec);
    if (!out) return { ok: false, code: 'invalid_outbound' };
    if (out.network !== undefined && !MH_NETWORKS.has(String(out.network)))
      return { ok: false, code: 'unsupported_type' };
    if (!destinationOk(out.server, out.port, allowPrivate))
      return { ok: false, code: 'destination_not_public' };
    return {
      ok: true,
      outbound: out,
      destination: { address: out.server as string, port: out.port as number },
    };
  }
  if (engine === 'sing-box') {
    const spec = typeof raw.type === 'string' ? SB_TYPES[raw.type] : undefined;
    if (!spec) return { ok: false, code: 'unsupported_type' };
    const out = pick(raw, spec);
    if (!out) return { ok: false, code: 'invalid_outbound' };
    const transport = out.transport as Obj | undefined;
    if (transport && !SB_TRANSPORT_TYPES.has(String(transport.type)))
      return { ok: false, code: 'unsupported_type' };
    if (!destinationOk(out.server, out.server_port, allowPrivate))
      return { ok: false, code: 'destination_not_public' };
    return {
      ok: true,
      outbound: out,
      destination: { address: out.server as string, port: out.server_port as number },
    };
  }
  const protocol = typeof raw.protocol === 'string' ? raw.protocol : '';
  const spec = XR_TYPES[protocol];
  if (!spec) return { ok: false, code: 'unsupported_type' };
  const settings = pick(raw.settings, spec);
  const stream = raw.streamSettings === undefined ? {} : pick(raw.streamSettings, XR_STREAM);
  if (!settings || !stream) return { ok: false, code: 'invalid_outbound' };
  if (stream.network !== undefined && !XR_NETWORKS.has(String(stream.network)))
    return { ok: false, code: 'unsupported_type' };
  if (stream.security !== undefined && !XR_SECURITY.has(String(stream.security)))
    return { ok: false, code: 'unsupported_type' };
  const server = ((settings.vnext ?? settings.servers) as Obj[] | undefined)?.[0];
  if (!server) return { ok: false, code: 'invalid_outbound' };
  if (!destinationOk(server.address, server.port, allowPrivate))
    return { ok: false, code: 'destination_not_public' };
  return {
    ok: true,
    outbound: { protocol, settings, streamSettings: stream },
    destination: { address: server.address as string, port: server.port as number },
  };
}
