/**
 * Typed edits of a backend config profile (pure; unit-tested). The backend takes a
 * profile's config WHOLESALE (`PATCH /api/config-profiles` replaces it and
 * re-derives the transports), so an edit is a read-modify-write, and the modify
 * step is the dangerous one. This module is that step, and nothing else:
 *
 *  - a CLOSED set of operations. There is no raw JSON edit;
 *  - it refuses rather than guesses: a config that is not an object, an empty
 *    `transports` (writing that would strip the node), a tag that is missing or
 *    appears twice, an operation aimed at a transport of the wrong kind;
 *  - everything it does not name is carried over UNTOUCHED, by reference, key
 *    material included. It never reads a secret and never returns one;
 *  - it never changes a transport's protocol, tag, or position: the backend keeps
 *    a transport's uuid only while tag and protocol hold (measured), and
 *    listener bindings, Hosts and mode groups hang off that uuid. A new
 *    transport is appended, so no existing one moves.
 *
 * `dest` and `target` are the same setting under its old and new name; the
 * edit writes whichever the transport already carries.
 *
 * Two edits open a port: `setInboundPort` moves a transport, and every node
 * serving it listens there next; `addInboundFromTemplate` adds a transport no
 * node serves yet (a node serves only the transports it is assigned, measured).
 * Whether a node's firewall lets the port in is not this module's question:
 * the port change is staged until the nodes confirm it (docs/servers.md
 * "Firewall acknowledgement"). The backend checks neither range nor collisions
 * of ports (measured: it stores 70000, and two transports on one port), so the
 * range is checked here and collisions per node by the caller.
 *
 * A REALITY transport made from a template carries its own key pair. The key is
 * generated inside the claimed attempt and INJECTED (`PatchMaterial`); without
 * it a placeholder stands in and `needsMaterial` says the result cannot be sent
 * and its token cannot be predicted.
 */
import { parseRealityTarget } from '../edges/inboundMapping';
import { normalizeName } from '../edges/registration';
import {
  PROFILE_DEFAULTS,
  buildTransport,
  checkModes,
  type ModeTemplateInput,
} from './profileTemplate';

/**
 * The catalogue a new transport is made from: the shapes nodes are built for
 * (lib/backend/profileTemplate.ts). Non-secret; a REALITY template's target and
 * names are the family's, resolved before the edit is previewed.
 */
export type TransportTemplate =
  | {
      kind: 'reality' | 'xhttp-reality';
      port: number;
      /** `host:port`, a real TLS 1.3 site serving every name below. */
      target: string;
      serverNames: string[];
      acceptProxyProtocol: boolean;
    }
  | { kind: 'ws'; port: number; path: string };

export type PatchOp =
  | { op: 'setRealityServerNames'; inboundTag: string; names: string[] }
  | { op: 'setRealityTarget'; inboundTag: string; target: string }
  | { op: 'setInboundPort'; inboundTag: string; port: number }
  | { op: 'addInboundFromTemplate'; inboundTag: string; template: TransportTemplate };

/**
 * Key material for the REALITY transports an edit creates, by tag: generated in
 * the attempt immediately before the write, held in memory only, never stored,
 * logged or returned.
 */
export type PatchMaterial = Readonly<
  Record<string, { privateKey: string; shortIds: readonly string[] }>
>;

/** Whether an op list makes a node listen on a port it may not listen on yet. */
export const opensPort = (ops: readonly PatchOp[]): boolean =>
  ops.some((o) => o.op === 'setInboundPort');

/** Whether an op list creates a REALITY transport, whose key is made in the attempt. */
export const needsFreshKeys = (ops: readonly PatchOp[]): boolean =>
  ops.some((o) => o.op === 'addInboundFromTemplate' && o.template.kind !== 'ws');

/** A transport tag as FCP writes one (a backend keys transports by tag, backend-wide). */
export const TRANSPORT_TAG_RE = /^[A-Za-z0-9_-]{2,40}$/;

/** Production Xray takes 1024 names on one transport (measured); the working cap is lower. */
export const MAX_SERVER_NAMES = 512;

export class PatchRefused extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'PatchRefused';
    this.code = code;
  }
}
const refuse = (code: string, message: string): never => {
  throw new PatchRefused(code, message);
};

const isObj = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === 'object' && !Array.isArray(v);

export interface PatchChange {
  inboundTag: string;
  field: 'serverNames' | 'target' | 'port' | 'transport';
  before: string[] | string | number | null;
  /** `transport`: the template kind of the transport that is added. */
  after: string[] | string | number;
}

export interface PatchResult {
  /** The config to send. Identical in every respect the ops did not name. */
  config: Record<string, unknown>;
  changed: boolean;
  /** Non-secret before/after of what moved, for the preview. */
  changes: PatchChange[];
  touchedTags: string[];
  /**
   * A REALITY transport is added and no material was given: the config holds a
   * placeholder key, so it must not be sent and its token predicts nothing.
   */
  needsMaterial: boolean;
}

const isPort = (p: unknown): p is number =>
  typeof p === 'number' && Number.isInteger(p) && p >= 1 && p <= 65535;

const PATH_RE = /^\/[A-Za-z0-9._~\-/]{0,127}$/;

/** A template, checked on its own: the same rules the setup's template is built under. */
function checkTemplate(tag: string, raw: unknown): TransportTemplate {
  const t = (raw ?? {}) as Record<string, unknown>;
  if (!isPort(t.port)) return refuse('validation', 'A port is 1 to 65535');
  if (t.kind === 'ws') {
    const path = typeof t.path === 'string' ? t.path.trim() : '';
    if (!PATH_RE.test(path)) return refuse('servers.template_invalid', 'A path starts with /');
    if (t.port < 1024)
      return refuse('servers.template_invalid', 'A loopback WebSocket port is 1024 or higher');
    return { kind: 'ws', port: t.port, path };
  }
  if (t.kind !== 'reality' && t.kind !== 'xhttp-reality')
    return refuse('servers.template_invalid', 'Unknown transport template');
  const target = typeof t.target === 'string' ? t.target.trim().toLowerCase() : '';
  const parsed = parseRealityTarget(target);
  if (!parsed) return refuse('servers.template_invalid', 'A target is host:port');
  const names: string[] = [];
  for (const n of Array.isArray(t.serverNames) ? t.serverNames : []) {
    const norm = normalizeName(n);
    if (!norm)
      return refuse(
        'servers.template_invalid',
        `Not a valid server name: ${String(n).slice(0, 80)}`,
      );
    if (!names.includes(norm)) names.push(norm);
  }
  if (names.length > MAX_SERVER_NAMES)
    refuse('servers.too_many_names', `At most ${MAX_SERVER_NAMES} server names per inbound`);
  const out: TransportTemplate = {
    kind: t.kind,
    port: t.port,
    target,
    serverNames: names,
    acceptProxyProtocol: t.acceptProxyProtocol === true,
  };
  // The setup's own validation, so an added transport is one setup can adopt.
  const bad = checkModes([templateMode(tag, out)]);
  if (bad) refuse('servers.template_invalid', `The template does not fit: ${bad.split(':')[1]}`);
  return out;
}

/** A template as the setup's builder takes it (the fronting only has to be a valid shape). */
function templateMode(tag: string, t: TransportTemplate): ModeTemplateInput {
  if (t.kind === 'ws')
    return {
      slug: 'added',
      name: tag.slice(0, 20),
      shape: { transport: 'ws', fronting: 'edge-l7' },
      ws: { path: t.path, port: t.port },
    };
  const target = parseRealityTarget(t.target)!;
  return {
    slug: 'added',
    name: tag.slice(0, 20),
    shape: { transport: t.kind, fronting: t.kind === 'reality' ? 'direct' : 'edge-l4' },
    acceptProxyProtocol: t.acceptProxyProtocol,
    reality: { target, serverNames: t.serverNames },
  };
}

/** The transport JSON of a template, its tag and port as asked; key material injected. */
export function templateTransport(
  tag: string,
  t: TransportTemplate,
  keys: { privateKey: string; shortIds: readonly string[] } | undefined,
): Record<string, unknown> {
  const built = buildTransport(templateMode(tag, t), t.kind === 'ws' ? undefined : keys);
  return { ...built, tag, port: t.port };
}

/** Validate an op list on its own (shape, names, targets), before any config is read. */
export function checkPatchOps(ops: readonly PatchOp[]): PatchOp[] {
  if (!Array.isArray(ops) || ops.length === 0) refuse('validation', 'Nothing to change');
  if (ops.length > 16) refuse('validation', 'Too many changes at once');
  // A port change and a new transport each have a blast radius of their own
  // (the nodes that must open the port; a tag that must be free backend-wide):
  // each is made on its own.
  if (
    ops.length > 1 &&
    ops.some((o) => o?.op === 'setInboundPort' || o?.op === 'addInboundFromTemplate')
  )
    refuse('validation', 'A port change or a new transport is made on its own');
  const seen = new Set<string>();
  return ops.map((raw) => {
    const tag = typeof raw?.inboundTag === 'string' ? raw.inboundTag : '';
    if (!tag) refuse('validation', 'A transport tag is required');
    const key = `${raw.op}:${tag}`;
    if (seen.has(key)) refuse('validation', `${raw.op} is listed twice for ${tag}`);
    seen.add(key);
    if (raw.op === 'setRealityServerNames') {
      if (!Array.isArray(raw.names)) refuse('validation', 'names must be a list');
      const names: string[] = [];
      for (const n of raw.names) {
        const norm = normalizeName(n);
        if (!norm)
          return refuse('validation', `Not a valid server name: ${String(n).slice(0, 80)}`);
        if (!names.includes(norm)) names.push(norm);
      }
      if (names.length === 0)
        refuse('validation', 'A REALITY transport needs at least one server name');
      if (names.length > MAX_SERVER_NAMES)
        refuse('servers.too_many_names', `At most ${MAX_SERVER_NAMES} server names per inbound`);
      return { op: raw.op, inboundTag: tag, names };
    }
    if (raw.op === 'setRealityTarget') {
      const target = typeof raw.target === 'string' ? raw.target.trim() : '';
      if (!parseRealityTarget(target)) refuse('validation', 'A target is host:port');
      return { op: raw.op, inboundTag: tag, target };
    }
    if (raw.op === 'setInboundPort') {
      if (!isPort(raw.port)) refuse('validation', 'A port is 1 to 65535');
      return { op: raw.op, inboundTag: tag, port: raw.port };
    }
    if (raw.op === 'addInboundFromTemplate') {
      if (!TRANSPORT_TAG_RE.test(tag))
        refuse('validation', 'A transport tag is 2 to 40 letters, digits, dashes or underscores');
      return { op: raw.op, inboundTag: tag, template: checkTemplate(tag, raw.template) };
    }
    return refuse('validation', 'Unknown change');
  });
}

const sameList = (a: readonly unknown[], b: readonly unknown[]) =>
  a.length === b.length && a.every((x, i) => x === b[i]);

/**
 * Apply `ops` to a config read a moment ago. Returns a NEW top-level object and
 * new objects only along the touched paths; every other value is the same
 * reference the caller passed in.
 */
export function applyPatchOps(
  config: unknown,
  rawOps: readonly PatchOp[],
  material?: PatchMaterial,
): PatchResult {
  const ops = checkPatchOps(rawOps);
  if (!isObj(config))
    return refuse('servers.profile_malformed', 'The profile has no config object');
  const inbounds = config.inbounds;
  if (!Array.isArray(inbounds) || inbounds.length === 0)
    return refuse(
      'servers.profile_malformed',
      'The profile lists no transports. Writing it back would strip its nodes',
    );
  const next = [...inbounds];
  const changes: PatchChange[] = [];
  let needsMaterial = false;

  for (const op of ops) {
    if (op.op === 'addInboundFromTemplate') {
      if (next.some((ib) => isObj(ib) && ib.tag === op.inboundTag))
        refuse('servers.tag_taken', `A transport is already tagged ${op.inboundTag}`);
      let keys: { privateKey: string; shortIds: readonly string[] } | undefined;
      if (op.template.kind !== 'ws') {
        keys = material?.[op.inboundTag];
        if (!keys) {
          needsMaterial = true;
          keys = {
            privateKey: 'material-made-in-the-attempt',
            shortIds: PROFILE_DEFAULTS.shortIds,
          };
        }
      }
      next.push(templateTransport(op.inboundTag, op.template, keys));
      changes.push({
        inboundTag: op.inboundTag,
        field: 'transport',
        before: null,
        after: op.template.kind,
      });
      continue;
    }
    const at = next
      .map((ib, i) => (isObj(ib) && ib.tag === op.inboundTag ? i : -1))
      .filter((i) => i >= 0);
    if (at.length === 0) refuse('servers.unknown_inbound', `No inbound is tagged ${op.inboundTag}`);
    if (at.length > 1)
      refuse('servers.profile_malformed', `Two inbounds are tagged ${op.inboundTag}`);
    const index = at[0] ?? -1;
    const ib = next[index] as Record<string, unknown>;
    if (op.op === 'setInboundPort') {
      // A loopback transport sits behind the node's Caddy, whose route to it is
      // a node setting: moving it here would leave the route pointing at nothing.
      if (isLoopback(ib.listen))
        refuse(
          'servers.port_loopback',
          `${op.inboundTag} listens on loopback behind the node's own proxy`,
        );
      if (!isPort(ib.port))
        refuse('servers.port_not_single', `${op.inboundTag} does not listen on one plain port`);
      if (ib.port !== op.port) {
        changes.push({
          inboundTag: op.inboundTag,
          field: 'port',
          before: ib.port as number,
          after: op.port,
        });
        next[index] = { ...ib, port: op.port };
      }
      continue;
    }
    const stream = isObj(ib.streamSettings) ? ib.streamSettings : null;
    const rs = stream && isObj(stream.realitySettings) ? stream.realitySettings : null;
    if (!stream || !rs || String(stream.security ?? '').toLowerCase() !== 'reality')
      return refuse('servers.not_reality', `${op.inboundTag} is not a REALITY inbound`);

    let nextRs: Record<string, unknown> = rs;
    if (op.op === 'setRealityServerNames') {
      const before = Array.isArray(rs.serverNames)
        ? rs.serverNames.filter((n): n is string => typeof n === 'string')
        : [];
      if (!sameList(before, op.names)) {
        nextRs = { ...rs, serverNames: op.names };
        changes.push({ inboundTag: op.inboundTag, field: 'serverNames', before, after: op.names });
      }
    } else {
      // Write the key the transport already uses; a config carrying both keeps both in step.
      const keys = (['target', 'dest'] as const).filter((k) => typeof rs[k] === 'string');
      const use = keys.length > 0 ? keys : (['target'] as const);
      const before = typeof rs[use[0]] === 'string' ? (rs[use[0]] as string) : null;
      if (use.some((k) => rs[k] !== op.target)) {
        nextRs = { ...rs };
        for (const k of use) nextRs[k] = op.target;
        changes.push({ inboundTag: op.inboundTag, field: 'target', before, after: op.target });
      }
    }
    if (nextRs !== rs)
      next[index] = { ...ib, streamSettings: { ...stream, realitySettings: nextRs } };
  }

  const changed = changes.length > 0;
  return {
    config: changed ? { ...config, inbounds: next } : config,
    changed,
    changes,
    touchedTags: [...new Set(changes.map((c) => c.inboundTag))],
    needsMaterial,
  };
}

function isLoopback(listen: unknown): boolean {
  if (typeof listen !== 'string') return false;
  const l = listen
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '');
  return l === 'localhost' || l === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(l);
}
