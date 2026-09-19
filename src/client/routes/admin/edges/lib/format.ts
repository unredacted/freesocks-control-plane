/**
 * Small display formatters for the Edges section (pure).
 *
 * Exports:
 *   PROTOCOL_LABELS / TRANSPORT_LABELS / SECURITY_LABELS, protocolLine(p)
 *   LAYER_LABELS, LAYER_HINTS
 *   PROVIDER_LABELS, providerLabel(id)      adapter ids -> display names
 *   formatBytes(n), displayValue(v)         for KeyValue rows
 *   auditDetailLine(payload)                one short line out of an audit payload (known keys only)
 */
import type {
  ListenerProtocolId,
  ListenerSecurity,
  ListenerStreamTransport,
} from '../../../../../shared/contracts/edgeProtocolIds';
import { codeLabel } from '../../../../lib/edgeCodes';

export const PROTOCOL_LABELS: Record<ListenerProtocolId, string> = {
  vless: 'VLESS',
  trojan: 'Trojan',
  shadowsocks: 'Shadowsocks',
  hysteria2: 'Hysteria2',
  tuic: 'TUIC',
};
export const TRANSPORT_LABELS: Record<ListenerStreamTransport, string> = {
  raw: 'raw',
  ws: 'WebSocket',
  httpupgrade: 'HTTP Upgrade',
  grpc: 'gRPC',
  xhttp: 'XHTTP',
  udp: 'UDP',
};
export const SECURITY_LABELS: Record<ListenerSecurity, string> = {
  none: 'no TLS',
  tls: 'TLS',
  reality: 'REALITY',
};

export interface ProtoLike {
  protocol: ListenerProtocolId;
  streamTransport: ListenerStreamTransport;
  security: ListenerSecurity;
}
/** "VLESS · raw · REALITY" */
export function protocolLine(p: ProtoLike): string {
  return [
    PROTOCOL_LABELS[p.protocol] ?? p.protocol,
    TRANSPORT_LABELS[p.streamTransport] ?? p.streamTransport,
    SECURITY_LABELS[p.security] ?? p.security,
  ].join(' · ');
}

export const LAYER_LABELS: Record<'l4' | 'l7', string> = { l4: 'L4', l7: 'L7' };
export const LAYER_HINTS: Record<'l4' | 'l7', string> = {
  l4: 'Layer 4: a load balancer that forwards connections to the origin by address.',
  l7: 'Layer 7: a CDN front reached by hostname that carries HTTP transports only.',
};

export const PROVIDER_LABELS: Record<string, string> = {
  gcore: 'Gcore',
  upcloud: 'UpCloud',
  scaleway: 'Scaleway',
  ovh: 'OVH',
  cloudflare: 'Cloudflare',
  fastly: 'Fastly',
};
export const providerLabel = (id: string | null | undefined): string =>
  id ? (PROVIDER_LABELS[id] ?? id) : 'Imported';

const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || !Number.isFinite(n)) return '';
  let v = Math.abs(n);
  let i = 0;
  while (v >= 1024 && i < BYTE_UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const s = i === 0 || v >= 100 ? v.toFixed(0) : v.toFixed(1);
  return `${n < 0 ? '-' : ''}${s} ${BYTE_UNITS[i]}`;
}

/** A KeyValue cell as text: booleans in words, empty as '', objects as compact JSON. */
export function displayValue(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'string') return v;
  if (typeof v === 'number') return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x === 'string' || typeof x === 'number')) {
    return v.join(', ');
  }
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/**
 * One short line of context from an audit payload. Only keys known to be short,
 * non-secret codes or names are read; `code` / `reason` / `veto` go through the
 * code copy so the operator never sees a bare identifier.
 */
export function auditDetailLine(payload: unknown): string {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return '';
  const p = payload as Record<string, unknown>;
  const out: string[] = [];
  for (const k of ['code', 'reason', 'veto', 'outcome'] as const) {
    const v = p[k];
    if (typeof v === 'string' && v && v.length <= 64) out.push(codeLabel(v.replace(/^edge\./, '')));
  }
  const listener = p['listenerKey'];
  if (typeof listener === 'string' && listener) out.push(`listener ${listener}`);
  const keys = p['changedKeys'];
  if (Array.isArray(keys) && keys.length > 0) {
    const names = keys.filter((x): x is string => typeof x === 'string').slice(0, 4);
    if (names.length > 0) {
      out.push(`changed ${names.join(', ')}${keys.length > names.length ? ' and more' : ''}`);
    }
  }
  return [...new Set(out)].join(' · ');
}
