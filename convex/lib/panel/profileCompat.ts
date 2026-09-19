/**
 * Adopting an EXISTING profile as the bootstrap profile (pure). Finding a
 * profile by name and counting three tags is not compatibility: each inbound
 * must be the shape the node purposes rely on, or nodes built for it will not
 * work. What is checked per tag is what the observation projects (protocol,
 * transport, security, listen, port, path, names, target, a usable key); the
 * privacy block is checked by the setup action through the harden preview,
 * since the projection deliberately does not carry it.
 *
 * Existing REALITY keys and short ids are never touched: the effective values
 * come from the adopted profile, not from the requested defaults.
 */
import type { PanelObservedInbound } from '../backends/types';
import { parseRealityTarget } from '../edges/inboundMapping';
import { BOOTSTRAP_TAGS, type BootstrapInboundKind } from './profileTemplate';

export interface CompatIssue {
  tag: string;
  /** The field that does not fit, as a code word. */
  field:
    | 'missing'
    | 'protocol'
    | 'network'
    | 'security'
    | 'listen'
    | 'port'
    | 'path'
    | 'server_names'
    | 'target'
    | 'reality_key'
    | 'public_key_mismatch';
}

export interface EffectiveCdnInbound {
  kind: 'cdn';
  tag: string;
  inboundUuid: string;
  listen: string;
  port: number;
  path: string;
}
export interface EffectiveRealityInbound {
  kind: 'reality' | 'relay';
  tag: string;
  inboundUuid: string;
  port: number;
  serverNames: string[];
  target: { address: string; port: number };
  publicKey: string;
}
export type EffectiveInbound = EffectiveCdnInbound | EffectiveRealityInbound;

export type CompatResult =
  | { ok: true; effective: Record<BootstrapInboundKind, EffectiveInbound> }
  | { ok: false; issue: CompatIssue };

function isLoopback(listen: string | null | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

function checkCdn(ib: PanelObservedInbound): EffectiveCdnInbound | CompatIssue {
  const tag = ib.tag;
  if (ib.protocol !== 'vless') return { tag, field: 'protocol' };
  if (ib.network !== 'ws') return { tag, field: 'network' };
  if (ib.security !== 'none') return { tag, field: 'security' };
  if (!isLoopback(ib.listen)) return { tag, field: 'listen' };
  if (ib.port === null) return { tag, field: 'port' };
  const path = ib.ws?.path ?? null;
  if (!path || !path.startsWith('/')) return { tag, field: 'path' };
  return {
    kind: 'cdn',
    tag,
    inboundUuid: ib.configProfileInboundUuid,
    listen: ib.listen!,
    port: ib.port,
    path,
  };
}

function checkReality(
  ib: PanelObservedInbound,
  kind: 'reality' | 'relay',
): EffectiveRealityInbound | CompatIssue {
  const tag = ib.tag;
  if (ib.protocol !== 'vless') return { tag, field: 'protocol' };
  if (ib.network !== 'raw' && ib.network !== 'tcp') return { tag, field: 'network' };
  if (ib.security !== 'reality') return { tag, field: 'security' };
  if (isLoopback(ib.listen)) return { tag, field: 'listen' };
  if (ib.port === null) return { tag, field: 'port' };
  const names = ib.reality?.serverNames ?? [];
  if (names.length === 0) return { tag, field: 'server_names' };
  const target = parseRealityTarget(ib.reality?.target ?? null);
  if (!target) return { tag, field: 'target' };
  if (!ib.realityAuth?.publicKey) return { tag, field: 'reality_key' };
  if (ib.realityAuth.publicKeyMismatch) return { tag, field: 'public_key_mismatch' };
  return {
    kind,
    tag,
    inboundUuid: ib.configProfileInboundUuid,
    port: ib.port,
    serverNames: names,
    target,
    publicKey: ib.realityAuth.publicKey,
  };
}

/**
 * Whether an observed profile can serve as the bootstrap profile, and the
 * effective values of its three inbounds when it can.
 */
export function checkProfileCompatibility(profile: {
  inbounds: readonly PanelObservedInbound[];
}): CompatResult {
  const byTag = new Map(profile.inbounds.map((i) => [i.tag, i]));
  const out: Partial<Record<BootstrapInboundKind, EffectiveInbound>> = {};
  for (const kind of ['cdn', 'reality', 'relay'] as const) {
    const tag = BOOTSTRAP_TAGS[kind];
    const ib = byTag.get(tag);
    if (!ib) return { ok: false, issue: { tag, field: 'missing' } };
    if (!ib.configProfileInboundUuid) return { ok: false, issue: { tag, field: 'missing' } };
    const r = kind === 'cdn' ? checkCdn(ib) : checkReality(ib, kind);
    if ('field' in r) return { ok: false, issue: r };
    out[kind] = r;
  }
  return { ok: true, effective: out as Record<BootstrapInboundKind, EffectiveInbound> };
}
