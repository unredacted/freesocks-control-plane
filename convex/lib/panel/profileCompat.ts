/**
 * Adopting an EXISTING profile for a backend's modes (pure). Finding a
 * profile by name and counting tags is not compatibility: each mode's
 * transport must be the shape nodes built for it rely on, or they will not
 * work. What is checked per transport is what the observation projects
 * (protocol, network, security, listen, port, path, names, target, a usable
 * key); the privacy block is checked by the setup action through the harden
 * preview, since the projection deliberately does not carry it.
 *
 * A transport is found by the mode's own tag first, then by a tag an earlier
 * setup gave the same mode (a backend keys transports by tag, so an adopted
 * tag is kept, never renamed). Existing REALITY keys and short ids are never
 * touched: the effective values come from the adopted profile.
 */
import type { ObservedTransport } from '../backends/types';
import { parseRealityTarget } from '../edges/inboundMapping';
import { transportTagOf, type ModeShape } from './profileTemplate';

export interface CompatIssue {
  slug: string;
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

export interface EffectiveWsTransport {
  kind: 'ws';
  tag: string;
  uuid: string;
  listen: string;
  port: number;
  path: string;
}
export interface EffectiveRealityTransport {
  kind: 'reality' | 'xhttp-reality';
  tag: string;
  uuid: string;
  port: number;
  path: string | null;
  serverNames: string[];
  target: { address: string; port: number };
  publicKey: string;
}
export type EffectiveTransport = EffectiveWsTransport | EffectiveRealityTransport;

export type CompatResult =
  | { ok: true; effective: Record<string, EffectiveTransport> }
  | { ok: false; issue: CompatIssue };

/**
 * What identifies a mode's transport: its definition, plus what an earlier
 * setup of the same mode already found (never re-derived from a renamed group).
 */
export interface ModeLookup {
  slug: string;
  name: string;
  shape: ModeShape;
  /** The tag a previous setup recorded for this mode. */
  tag?: string;
  /** The transport a previous setup bound. */
  transport?: { uuid?: string };
}

/**
 * Tags an earlier setup gave the same modes: the profile shape the node
 * role once created (`VLESS_*`). Looked up after the mode's own tag.
 */
export const LEGACY_TRANSPORT_TAGS: Readonly<Record<string, readonly string[]>> = {
  'privacy-reality': ['VLESS_REALITY'],
  'freedom-reality': ['VLESS_RELAY_REALITY'],
  'freedom-ws': ['VLESS_WS_CDN'],
};

function isLoopback(listen: string | null | undefined): boolean {
  if (!listen) return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}

function checkWs(slug: string, ib: ObservedTransport): EffectiveWsTransport | CompatIssue {
  const tag = ib.tag;
  if (ib.protocol !== 'vless') return { slug, tag, field: 'protocol' };
  if (ib.network !== 'ws') return { slug, tag, field: 'network' };
  if (ib.security !== 'none') return { slug, tag, field: 'security' };
  if (!isLoopback(ib.listen)) return { slug, tag, field: 'listen' };
  if (ib.port === null) return { slug, tag, field: 'port' };
  const path = ib.ws?.path ?? null;
  if (!path || !path.startsWith('/')) return { slug, tag, field: 'path' };
  return {
    kind: 'ws',
    tag,
    uuid: ib.configProfileInboundUuid,
    listen: ib.listen!,
    port: ib.port,
    path,
  };
}

function checkReality(
  slug: string,
  ib: ObservedTransport,
  kind: 'reality' | 'xhttp-reality',
): EffectiveRealityTransport | CompatIssue {
  const tag = ib.tag;
  if (ib.protocol !== 'vless') return { slug, tag, field: 'protocol' };
  if (kind === 'xhttp-reality') {
    if (ib.network !== 'xhttp') return { slug, tag, field: 'network' };
  } else if (ib.network !== 'raw' && ib.network !== 'tcp') return { slug, tag, field: 'network' };
  if (ib.security !== 'reality') return { slug, tag, field: 'security' };
  if (isLoopback(ib.listen)) return { slug, tag, field: 'listen' };
  if (ib.port === null) return { slug, tag, field: 'port' };
  const names = ib.reality?.serverNames ?? [];
  if (names.length === 0) return { slug, tag, field: 'server_names' };
  const target = parseRealityTarget(ib.reality?.target ?? null);
  if (!target) return { slug, tag, field: 'target' };
  if (!ib.realityAuth?.publicKey) return { slug, tag, field: 'reality_key' };
  if (ib.realityAuth.publicKeyMismatch) return { slug, tag, field: 'public_key_mismatch' };
  return {
    kind,
    tag,
    uuid: ib.configProfileInboundUuid,
    port: ib.port,
    path: kind === 'xhttp-reality' ? (ib.xhttp?.path ?? null) : null,
    serverNames: names,
    target,
    publicKey: ib.realityAuth.publicKey,
  };
}

/**
 * The observed transport a mode adopts: the one a previous setup of this mode
 * already bound (by uuid, then by the tag it recorded, since a backend never
 * renames a transport), else the tag this mode's group name gives, else a tag
 * an older release gave the same mode.
 */
export function findTransport(
  inbounds: readonly ObservedTransport[],
  mode: ModeLookup,
): ObservedTransport | null {
  const byTag = new Map(inbounds.map((i) => [i.tag, i]));
  if (mode.transport?.uuid) {
    const byUuid = inbounds.find((i) => i.configProfileInboundUuid === mode.transport!.uuid);
    if (byUuid) return byUuid;
  }
  for (const tag of [
    mode.tag,
    transportTagOf(mode.name),
    ...(LEGACY_TRANSPORT_TAGS[mode.slug] ?? []),
  ]) {
    const hit = tag ? byTag.get(tag) : undefined;
    if (hit) return hit;
  }
  return null;
}

/**
 * Whether an observed profile can serve every mode, and the effective
 * values of each mode's transport when it can (keyed by mode slug).
 */
export function checkProfileCompatibility(
  profile: { inbounds: readonly ObservedTransport[] },
  modes: readonly ModeLookup[],
): CompatResult {
  const out: Record<string, EffectiveTransport> = {};
  for (const m of modes) {
    const tag = m.tag ?? transportTagOf(m.name);
    const ib = findTransport(profile.inbounds, m);
    if (!ib || !ib.configProfileInboundUuid)
      return { ok: false, issue: { slug: m.slug, tag, field: 'missing' } };
    const r =
      m.shape.transport === 'ws'
        ? checkWs(m.slug, ib)
        : checkReality(m.slug, ib, m.shape.transport);
    if ('field' in r) return { ok: false, issue: r };
    out[m.slug] = r;
  }
  return { ok: true, effective: out };
}
