/**
 * Inbound discovery (pure half): turn the inbounds a panel node serves
 * (`PanelInbound`, the provider's allowlisted projection) into relay listener
 * candidates in the by-slug registration shape, or say why one cannot be a
 * listener. The guided setup builds its "protect every frontable inbound"
 * plan from this; nothing here touches the database or the panel.
 *
 * Mapping:
 *   protocol   vless / trojan / shadowsocks; anything else (vmess, ...) -> `protocol`
 *   network    tcp | raw -> raw; ws, httpupgrade, grpc -> themselves; xhttp, kcp,
 *              quic, ... -> `transport`
 *   security   reality -> `realityTarget` (dest/target "host:port") + `tlsNames`
 *              (serverNames); tls -> `tlsNames` (serverName; none = `needsName`);
 *              none -> no names; anything else -> `security`
 *   params     ws / httpupgrade path + host, grpc serviceName -> `transportParams`
 *   binding    `panelBinding` {inboundTag, configProfileUuid, configProfileInboundUuid};
 *              a tag outside `INBOUND_TAG_RE` -> `tag`
 *   rule       `matchRule` = the default `remark` rule for the node
 *
 * Every candidate is run through `validateListenerSpec` (a refusal -> `invalid`
 * with the code as detail). `originTransport` is NEVER set here: only an origin
 * probe can say how an L7 front may dial the node, so an HTTP-transport
 * listener discovered here starts L4-only (`layers` says so) until that probe
 * fills it in.
 *
 * Listener key: `slug10 + base36(sha256(tag))[0..6]`, deterministic across runs
 * and collision-resistant (two tags sharing their first ten alphanumerics get
 * different keys); at most 16 chars, matching the `[a-z0-9]{1,16}` slot-key
 * rule. Uniqueness is still enforced against the relay's existing keys and
 * within the batch: a collision after the digest is `invalid`.
 */
import type { PanelInbound } from '../backends/types';
import { sha256Hex } from '../crypto';
import type { InboundUnsupportedCode } from '../../../src/shared/contracts/edgeCodes';
import {
  isValidListenerCombo,
  type ListenerProto,
  type ListenerProtocolId,
  type ListenerSecurity,
  type ListenerStreamTransport,
} from '../../../src/shared/contracts/edgeProtocolIds';
import { templateHostRemark } from './hosts';
import { listenerLayers, type ListenerLayers } from './layers';
import type { RelayOrigin } from './origin';
import { formatSupported } from './protocols';
import {
  INBOUND_TAG_RE,
  validateListenerSpec,
  type ListenerSpecInput,
  type TransportParams,
} from './registration';

export type PanelNodeOrigin = Extract<RelayOrigin, { kind: 'panel-node' }>;

export interface InboundCandidate {
  /** The listener as a registration body carries it (no `originTransport`). */
  listenerSpec: ListenerSpecInput;
  /** Which edge layers can front it today (L4-only until an origin probe runs). */
  layers: ListenerLayers;
  /** Which subscription formats the renderer can rewrite for the combination. */
  formats: { links: boolean; singbox: boolean; clash: boolean };
  /** The listener presents a server name but the inbound declares none: the operator must supply one before registering. */
  needsName: boolean;
  /** The panel inbound tag this candidate came from. */
  sourceTag: string;
}

export interface UnsupportedInbound {
  tag: string;
  reason: InboundUnsupportedCode;
  /** A short machine-ish hint (a protocol id, a validator code); never an address. */
  detail?: string;
}

export interface InboundMappingOptions {
  /** Listener keys the relay already holds (uniqueness is enforced against them). */
  existingKeys: readonly string[];
  /** The relay's panel-node origin: names the default Host remark rule. */
  origin: PanelNodeOrigin;
}

export interface InboundMapping {
  candidates: InboundCandidate[];
  unsupported: UnsupportedInbound[];
}

const SLUG_LEN = 10;
const DIGEST_LEN = 6;
/** A valid placeholder so the validator's name rule passes for a `needsName` candidate; never emitted. */
const NAME_PLACEHOLDER = 'name-pending.example';

/**
 * The deterministic listener key for a panel inbound tag: the first ten
 * lowercase alphanumerics of the tag, then six base36 digits of sha256(tag).
 */
export async function listenerKeyForTag(tag: string): Promise<string> {
  const slug = tag
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '')
    .slice(0, SLUG_LEN);
  const hex = await sha256Hex(tag);
  // A 256-bit number has ~50 base36 digits: the leading six are always present.
  const digest = BigInt(`0x${hex}`).toString(36).slice(0, DIGEST_LEN).padEnd(DIGEST_LEN, '0');
  return `${slug}${digest}`;
}

const PROTOCOLS: Readonly<Record<string, ListenerProtocolId>> = {
  vless: 'vless',
  trojan: 'trojan',
  shadowsocks: 'shadowsocks',
};
const TRANSPORTS: Readonly<Record<string, ListenerStreamTransport>> = {
  tcp: 'raw',
  raw: 'raw',
  ws: 'ws',
  websocket: 'ws',
  httpupgrade: 'httpupgrade',
  grpc: 'grpc',
  gun: 'grpc',
  xhttp: 'xhttp',
  splithttp: 'xhttp',
};
const SECURITIES: Readonly<Record<string, ListenerSecurity>> = {
  none: 'none',
  '': 'none',
  tls: 'tls',
  reality: 'reality',
};

/** `host:port`, `[v6]:port` -> the REALITY target; null when it is not one plain address:port. */
export function parseRealityTarget(v: string | null): { address: string; port: number } | null {
  if (!v) return null;
  const m = /^\[([^\]]+)\]:(\d{1,5})$/.exec(v.trim()) ?? /^([^:\s]+):(\d{1,5})$/.exec(v.trim());
  if (!m) return null;
  const port = Number(m[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { address: m[1] ?? '', port };
}

function skip(tag: string, reason: InboundUnsupportedCode, detail?: string): UnsupportedInbound {
  return detail ? { tag, reason, detail } : { tag, reason };
}

function isLoopbackListen(listen: string | null | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

function refusalDetail(err: unknown): string {
  if (err && typeof err === 'object' && 'data' in err) {
    const data = (err as { data?: unknown }).data;
    if (data && typeof data === 'object') {
      const d = data as { code?: unknown; message?: unknown };
      if (typeof d.code === 'string' && d.code !== 'validation') return d.code;
      if (typeof d.message === 'string') return d.message;
    }
  }
  return err instanceof Error ? err.message : 'validation';
}

export async function mapInboundsToListeners(
  inbounds: readonly PanelInbound[],
  opts: InboundMappingOptions,
): Promise<InboundMapping> {
  const candidates: InboundCandidate[] = [];
  const unsupported: UnsupportedInbound[] = [];
  const taken = new Set(opts.existingKeys);
  const ctx = { origin: opts.origin };

  for (const ib of inbounds) {
    const tag = ib.tag;
    if (!ib.active) {
      unsupported.push(skip(tag, 'inactive'));
      continue;
    }
    // Bound to loopback: the node's public address never reaches it. Something
    // else on the node (a TLS terminator) does, and only the operator or the
    // node role can describe that hop (the listener's origin port + transport).
    if (isLoopbackListen(ib.listen)) {
      unsupported.push(skip(tag, 'loopback', ib.listen ?? undefined));
      continue;
    }
    if (!INBOUND_TAG_RE.test(tag)) {
      unsupported.push(skip(tag, 'tag'));
      continue;
    }
    const protocol = PROTOCOLS[ib.protocol];
    if (!protocol) {
      unsupported.push(skip(tag, 'protocol', ib.protocol || 'unknown'));
      continue;
    }
    const streamTransport = TRANSPORTS[ib.network];
    if (!streamTransport) {
      unsupported.push(skip(tag, 'transport', ib.network || 'unknown'));
      continue;
    }
    const security = SECURITIES[ib.security];
    if (!security) {
      unsupported.push(skip(tag, 'security', ib.security || 'unknown'));
      continue;
    }
    const proto: ListenerProto = { protocol, streamTransport, security };
    if (!isValidListenerCombo(proto)) {
      unsupported.push(skip(tag, 'invalid', 'invalid_combination'));
      continue;
    }
    if (ib.port === null) {
      unsupported.push(skip(tag, 'invalid', 'port'));
      continue;
    }

    const listenerKey = await listenerKeyForTag(tag);
    if (taken.has(listenerKey)) {
      unsupported.push(skip(tag, 'invalid', 'listener_key_collision'));
      continue;
    }

    // Names: REALITY serverNames / the TLS serverName. None declared where the
    // combination presents one = the operator supplies them (needsName).
    const tlsNames =
      security === 'reality'
        ? (ib.reality?.serverNames ?? [])
        : security === 'tls' && ib.tls?.serverName
          ? [ib.tls.serverName]
          : [];
    const needsName = security !== 'none' && tlsNames.length === 0;

    let realityTarget: { address: string; port: number } | undefined;
    if (security === 'reality') {
      const t = parseRealityTarget(ib.reality?.target ?? null);
      if (!t) {
        unsupported.push(skip(tag, 'invalid', 'reality_target'));
        continue;
      }
      realityTarget = t;
    }

    let transportParams: TransportParams | undefined;
    if (streamTransport === 'ws' || streamTransport === 'httpupgrade') {
      const p = streamTransport === 'ws' ? ib.ws : ib.httpupgrade;
      transportParams = {};
      if (p?.path) transportParams.path = p.path;
      if (p?.host) transportParams.host = p.host;
    } else if (streamTransport === 'grpc') {
      transportParams = {};
      if (ib.grpc?.serviceName) transportParams.serviceName = ib.grpc.serviceName;
    } else if (streamTransport === 'xhttp') {
      transportParams = {};
      if (ib.xhttp?.path) transportParams.path = ib.xhttp.path;
      if (ib.xhttp?.host) transportParams.host = ib.xhttp.host;
      // Xray's default when the inbound declares none.
      transportParams.mode = ib.xhttp?.mode ?? 'auto';
    }

    const spec: ListenerSpecInput = {
      ...proto,
      listenerKey,
      originPort: ib.port,
      tlsNames,
      realityTarget,
      transportParams,
      panelBinding: {
        inboundTag: tag,
        configProfileUuid: ib.configProfileUuid,
        configProfileInboundUuid: ib.configProfileInboundUuid,
      },
      matchRule: { kind: 'remark', remark: templateHostRemark(opts.origin.nodeName, listenerKey) },
    };

    // Validate everything the registration validator checks. A needsName
    // candidate is validated as if one name were present (the validator
    // rightly refuses a nameless TLS listener; the operator supplies the
    // names before registering); the emitted spec carries none.
    let canonical;
    try {
      canonical = validateListenerSpec(
        needsName ? { ...spec, tlsNames: [NAME_PLACEHOLDER] } : spec,
        ctx,
      );
    } catch (err) {
      unsupported.push(skip(tag, 'invalid', refusalDetail(err)));
      continue;
    }
    taken.add(listenerKey);

    const listenerSpec: ListenerSpecInput = {
      protocol: canonical.protocol,
      streamTransport: canonical.streamTransport,
      security: canonical.security,
      listenerKey: canonical.listenerKey,
      originPort: canonical.originPort,
      tlsNames: needsName ? [] : canonical.tlsNames,
      ...(canonical.realityTarget ? { realityTarget: canonical.realityTarget } : {}),
      ...(canonical.transportParams ? { transportParams: canonical.transportParams } : {}),
      panelBinding: canonical.panelBinding!,
      matchRule: canonical.matchRule,
    };
    candidates.push({
      listenerSpec,
      layers: listenerLayers({
        ...proto,
        tlsNames: listenerSpec.tlsNames!.map((name) => ({ name, status: 'active' as const })),
        originTransport: null,
      }),
      formats: {
        links: formatSupported(proto, 'links'),
        singbox: formatSupported(proto, 'singbox'),
        clash: formatSupported(proto, 'clash'),
      },
      needsName,
      sourceTag: tag,
    });
  }
  return { candidates, unsupported };
}
