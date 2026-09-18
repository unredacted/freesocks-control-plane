/**
 * Relay registration (pure half): validate the listeners a registration body
 * carries, canonicalise them for an idempotency hash, merge server names under
 * the ownership rules, and diff a body against the stored listeners.
 *
 * Idempotency: an identical body must change NOTHING material (no listener
 * revision bump, no epoch bump, no mirror refresh, no qualification
 * invalidation). The hash is computed over a canonical copy whose names are
 * SORTED; the persisted `tlsNames` order is the body's order and is never
 * re-sorted, because SNI selection is index-based (assignment.ts).
 *
 * Ownership: the node role may add names and retire names it added; it never
 * reactivates an admin-retired name or shortens a drain. Admin-created
 * listeners are never touched by a role registration.
 */
import { ConvexError } from 'convex/values';
import {
  isValidListenerCombo,
  listenerCombo,
  type ListenerProto,
} from '../../../src/shared/contracts/edgeProtocolIds';
import { isValidHostname } from './hostname';
import { isSlotKey, templateHostRemark } from './hosts';
import type { OriginTransport } from './layers';
import type { RelayOrigin } from './origin';

export type ListenerNameStatus = 'active' | 'retired';
export interface ListenerName {
  name: string;
  status: ListenerNameStatus;
  retiredAt?: number;
  drainUntil?: number;
  retiredBy?: 'admin' | 'role';
}

export type MatchRule =
  | { kind: 'remark'; remark: string }
  | { kind: 'address' }
  | { kind: 'whole-body' };

export interface PanelBinding {
  inboundTag: string;
  configProfileUuid: string;
  configProfileInboundUuid: string;
}

export interface TransportParams {
  path?: string;
  host?: string;
  serviceName?: string;
  upgradeToken?: string;
}

export interface ProviderScope {
  provider: string;
  accountId?: string;
}

/** What a registration body (role or admin form) says about one listener. */
export interface ListenerSpecInput extends ListenerProto {
  listenerKey: string;
  originPort: number;
  tlsNames?: string[] | null;
  realityTarget?: { address: string; port: number } | null;
  transportParams?: TransportParams | null;
  originTransport?: OriginTransport | null;
  panelBinding?: PanelBinding | null;
  matchRule?: MatchRule | null;
  providerScope?: ProviderScope | null;
  deployed?: boolean;
}

/** A validated, normalised listener spec (names in body order). */
export interface CanonicalListener extends ListenerProto {
  listenerKey: string;
  transport: 'tcp' | 'udp';
  originPort: number;
  tlsNames: string[];
  realityTarget?: { address: string; port: number };
  transportParams?: TransportParams;
  originTransport?: OriginTransport;
  panelBinding?: PanelBinding;
  matchRule: MatchRule;
  providerScope?: ProviderScope;
  deployed: boolean;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A panel inbound tag a listener may bind to (shared with inbound discovery). */
export const INBOUND_TAG_RE = /^[A-Z0-9_]{1,64}$/;
const MAX_NAMES = 32;

function fail(message: string, code = 'validation'): never {
  throw new ConvexError({ code, message });
}

export function normalizeName(s: unknown): string | null {
  if (typeof s !== 'string') return null;
  const t = s.trim().toLowerCase().replace(/\.$/, '');
  return isValidHostname(t) ? t : null;
}

export function checkOriginTransport(t: OriginTransport): OriginTransport {
  if (t.certNames.length > 16) fail('certNames takes at most 16 entries');
  const names: string[] = [];
  for (const raw of t.certNames) {
    const n = raw.trim().toLowerCase().replace(/\.$/, '');
    const body = n.startsWith('*.') ? n.slice(2) : n;
    if (n.includes('*') && !n.startsWith('*.')) fail(`invalid certificate name: ${n}`);
    if (!isValidHostname(body)) fail(`invalid certificate name: ${n}`);
    if (!names.includes(n)) names.push(n);
  }
  if (t.scheme === 'https' && t.certPublic && names.length === 0)
    fail('a publicly trusted origin must name its certificate');
  return { ...t, certNames: names };
}

function checkPort(port: number, what: string): number {
  if (!Number.isInteger(port) || port < 1 || port > 65535) fail(`${what} out of range`);
  return port;
}

export interface ValidationContext {
  origin: RelayOrigin;
}

/**
 * Validate one listener spec against the catalogue and the origin kind.
 * Throws `validation` / `invalid_combination`; returns the canonical spec.
 */
export function validateListenerSpec(
  spec: ListenerSpecInput,
  ctx: ValidationContext,
): CanonicalListener {
  if (!isSlotKey(spec.listenerKey)) fail('listenerKey must be 1-16 lowercase alphanumerics');
  const proto: ListenerProto = {
    protocol: spec.protocol,
    streamTransport: spec.streamTransport,
    security: spec.security,
  };
  if (!isValidListenerCombo(proto))
    fail(
      `${proto.protocol}/${proto.streamTransport}/${proto.security} is not a supported listener combination`,
      'invalid_combination',
    );
  const combo = listenerCombo(proto)!;
  const originPort = checkPort(spec.originPort, 'originPort');
  const originTransport = spec.originTransport
    ? checkOriginTransport(spec.originTransport)
    : undefined;
  const l7Only = originTransport?.scheme === 'http';

  const tlsNames: string[] = [];
  for (const raw of spec.tlsNames ?? []) {
    const n = normalizeName(raw);
    if (!n) fail(`invalid server name: ${String(raw)}`);
    if (!tlsNames.includes(n)) tlsNames.push(n);
  }
  if (tlsNames.length > MAX_NAMES) fail(`at most ${MAX_NAMES} server names`);
  if (!combo.usesSni && tlsNames.length > 0)
    fail(`${combo.label} presents no server name; drop tlsNames`);
  if (combo.usesSni && tlsNames.length === 0 && !l7Only)
    fail(
      `${combo.label} needs at least one server name (or an http origin transport for an L7-only listener)`,
    );

  let realityTarget: CanonicalListener['realityTarget'];
  if (combo.needsTarget) {
    if (!spec.realityTarget) fail('a REALITY listener needs realityTarget {address, port}');
    const addr = spec.realityTarget.address.trim().toLowerCase().replace(/\.$/, '');
    if (!isValidHostname(addr) && !/^[0-9a-f:.]+$/i.test(addr))
      fail('invalid realityTarget address');
    realityTarget = {
      address: addr,
      port: checkPort(spec.realityTarget.port, 'realityTarget.port'),
    };
  } else if (spec.realityTarget) {
    fail(`${combo.label} impersonates no target; drop realityTarget`);
  }

  let transportParams: TransportParams | undefined;
  if (spec.transportParams) {
    if (!combo.isHttpTransport) fail(`${combo.label} has no HTTP transport parameters`);
    const p = spec.transportParams;
    transportParams = {};
    if (p.path !== undefined) transportParams.path = p.path;
    if (p.host !== undefined) transportParams.host = p.host;
    if (p.serviceName !== undefined) transportParams.serviceName = p.serviceName;
    if (p.upgradeToken !== undefined) transportParams.upgradeToken = p.upgradeToken;
  }

  let panelBinding: PanelBinding | undefined;
  if (spec.panelBinding) {
    if (ctx.origin.kind !== 'panel-node')
      fail('panelBinding is only valid for a panel-node origin');
    const b = spec.panelBinding;
    if (!UUID_RE.test(b.configProfileUuid) || !UUID_RE.test(b.configProfileInboundUuid))
      fail('config profile / inbound uuids must be UUIDs');
    if (!INBOUND_TAG_RE.test(b.inboundTag)) fail('inboundTag must be [A-Z0-9_]');
    panelBinding = {
      inboundTag: b.inboundTag,
      configProfileUuid: b.configProfileUuid.toLowerCase(),
      configProfileInboundUuid: b.configProfileInboundUuid.toLowerCase(),
    };
  }

  let matchRule: MatchRule;
  if (spec.matchRule) {
    if (spec.matchRule.kind === 'remark') {
      if (!panelBinding) fail('a remark match rule needs a panelBinding');
      const r = spec.matchRule.remark.trim();
      if (!r || r.length > 128) fail('invalid remark');
      matchRule = { kind: 'remark', remark: r };
    } else matchRule = { kind: spec.matchRule.kind };
  } else if (panelBinding && ctx.origin.kind === 'panel-node') {
    matchRule = {
      kind: 'remark',
      remark: templateHostRemark(ctx.origin.nodeName, spec.listenerKey),
    };
  } else {
    matchRule = { kind: 'address' };
  }

  let providerScope: ProviderScope | undefined;
  if (spec.providerScope) {
    providerScope = { provider: spec.providerScope.provider };
    if (spec.providerScope.accountId) providerScope.accountId = spec.providerScope.accountId;
  }

  return {
    ...proto,
    listenerKey: spec.listenerKey,
    transport: combo.transport,
    originPort,
    tlsNames,
    realityTarget,
    transportParams,
    originTransport,
    panelBinding,
    matchRule,
    providerScope,
    deployed: spec.deployed ?? true,
  };
}

/**
 * Overlapping match rules make an entry ambiguous: two `address` rules on the
 * same origin port, or `whole-body` next to any other rule, or two identical
 * remarks.
 */
export function assertNoMatchOverlap(
  listeners: ReadonlyArray<{ listenerKey: string; originPort: number; matchRule: MatchRule }>,
): void {
  const live = listeners;
  const wholeBody = live.filter((l) => l.matchRule.kind === 'whole-body');
  if (wholeBody.length > 0 && live.length > 1)
    fail(
      `listener ${wholeBody[0].listenerKey} matches the whole body; it cannot share a relay with other listeners`,
      'edge.match_rule_overlap',
    );
  const seenPorts = new Map<number, string>();
  const seenRemarks = new Map<string, string>();
  for (const l of live) {
    if (l.matchRule.kind === 'address') {
      const other = seenPorts.get(l.originPort);
      if (other)
        fail(
          `listeners ${other} and ${l.listenerKey} both match by address on port ${l.originPort}`,
          'edge.match_rule_overlap',
        );
      seenPorts.set(l.originPort, l.listenerKey);
    } else if (l.matchRule.kind === 'remark') {
      const other = seenRemarks.get(l.matchRule.remark);
      if (other)
        fail(
          `listeners ${other} and ${l.listenerKey} both match remark ${l.matchRule.remark}`,
          'edge.match_rule_overlap',
        );
      seenRemarks.set(l.matchRule.remark, l.listenerKey);
    }
  }
}

/** FNV-1a 64-bit as 16 hex chars (deterministic, no dependency). */
export function fnv1a64Hex(s: string): string {
  let h = 0xcbf29ce484222325n;
  const prime = 0x100000001b3n;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * prime) & 0xffffffffffffffffn;
  }
  return h.toString(16).padStart(16, '0');
}

function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(v);
}

/**
 * The idempotency hash of a canonical listener. Names are hashed as a SORTED
 * copy (set semantics); everything else field by field. `deployed` and the
 * match rule are part of it (they change what renders / what the Host is).
 */
export function listenerConfigHash(c: CanonicalListener): string {
  return fnv1a64Hex(
    canonicalJson({
      protocol: c.protocol,
      streamTransport: c.streamTransport,
      security: c.security,
      originPort: c.originPort,
      tlsNames: [...c.tlsNames].sort(),
      realityTarget: c.realityTarget ?? null,
      transportParams: c.transportParams ?? null,
      originTransport: c.originTransport ?? null,
      panelBinding: c.panelBinding ?? null,
      matchRule: c.matchRule,
      providerScope: c.providerScope ?? null,
      deployed: c.deployed,
    }),
  );
}

export interface MergeNamesResult {
  next: ListenerName[];
  added: string[];
  retired: string[];
  reactivated: string[];
  /** Names the caller wanted active but may not reactivate (admin-retired). */
  blocked: string[];
  changed: boolean;
}

/**
 * Merge the names a body carries into the stored list. Body order wins for
 * the persisted order of the names it names; names the body omits are retired
 * (with a drain) when the caller may retire them, and kept otherwise. A `role`
 * caller can only reactivate names it retired itself.
 */
export function mergeNames(
  existing: readonly ListenerName[],
  incoming: readonly string[],
  source: 'role' | 'admin',
  now: number,
  drainMs: number,
): MergeNamesResult {
  const added: string[] = [];
  const retired: string[] = [];
  const reactivated: string[] = [];
  const blocked: string[] = [];
  const byName = new Map(existing.map((n) => [n.name, n]));
  const next: ListenerName[] = [];
  const wanted = new Set(incoming);
  // Keep the stored order for names that remain; append new ones in body order.
  for (const e of existing) {
    if (wanted.has(e.name)) {
      if (e.status === 'retired') {
        if (source === 'role' && e.retiredBy === 'admin') {
          blocked.push(e.name);
          next.push(e);
        } else {
          reactivated.push(e.name);
          next.push({ name: e.name, status: 'active' });
        }
      } else next.push(e);
    } else if (e.status === 'active') {
      retired.push(e.name);
      next.push({
        name: e.name,
        status: 'retired',
        retiredAt: now,
        drainUntil: now + drainMs,
        retiredBy: source,
      });
    } else next.push(e);
  }
  for (const n of incoming) {
    if (!byName.has(n)) {
      added.push(n);
      next.push({ name: n, status: 'active' });
    }
  }
  return {
    next,
    added,
    retired,
    reactivated,
    blocked,
    changed: added.length + retired.length + reactivated.length > 0,
  };
}

export interface StoredListenerLike {
  listenerKey: string;
  source: 'role' | 'admin';
  configHash: string;
  retired: boolean;
}

export interface ListenerDiff<T extends StoredListenerLike> {
  create: CanonicalListener[];
  /** Existing rows whose canonical hash differs (material change). */
  update: Array<{ existing: T; spec: CanonicalListener }>;
  /** Existing rows an identical body re-stated. */
  unchanged: Array<{ existing: T; spec: CanonicalListener }>;
  /** Rows owned by this source that the body no longer names. */
  prune: T[];
  /** Body keys that collide with a listener another source owns. */
  owned: string[];
}

export function diffListeners<T extends StoredListenerLike>(
  existing: readonly T[],
  specs: readonly CanonicalListener[],
  source: 'role' | 'admin',
  prune: boolean,
): ListenerDiff<T> {
  const byKey = new Map(existing.map((l) => [l.listenerKey, l]));
  const out: ListenerDiff<T> = { create: [], update: [], unchanged: [], prune: [], owned: [] };
  const seen = new Set<string>();
  for (const spec of specs) {
    if (seen.has(spec.listenerKey)) fail(`duplicate listenerKey ${spec.listenerKey}`);
    seen.add(spec.listenerKey);
    const ex = byKey.get(spec.listenerKey);
    if (!ex) {
      out.create.push(spec);
      continue;
    }
    if (ex.source !== source) {
      out.owned.push(spec.listenerKey);
      continue;
    }
    if (!ex.retired && ex.configHash === listenerConfigHash(spec))
      out.unchanged.push({ existing: ex, spec });
    else out.update.push({ existing: ex, spec });
  }
  if (prune) {
    for (const ex of existing) {
      if (ex.source === source && !ex.retired && !seen.has(ex.listenerKey)) out.prune.push(ex);
    }
  }
  return out;
}
