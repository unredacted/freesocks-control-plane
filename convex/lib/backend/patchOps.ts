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
 *    listener bindings, Hosts and mode groups hang off that uuid.
 *
 * `dest` and `target` are the same setting under its old and new name; the
 * edit writes whichever the transport already carries.
 */
import { parseRealityTarget } from '../edges/inboundMapping';
import { normalizeName } from '../edges/registration';

export type PatchOp =
  | { op: 'setRealityServerNames'; inboundTag: string; names: string[] }
  | { op: 'setRealityTarget'; inboundTag: string; target: string };

export const PATCH_OP_IDS = ['setRealityServerNames', 'setRealityTarget'] as const;

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
  field: 'serverNames' | 'target';
  before: string[] | string | null;
  after: string[] | string;
}

export interface PatchResult {
  /** The config to send. Identical in every respect the ops did not name. */
  config: Record<string, unknown>;
  changed: boolean;
  /** Non-secret before/after of what moved, for the preview. */
  changes: PatchChange[];
  touchedTags: string[];
}

/** Validate an op list on its own (shape, names, targets), before any config is read. */
export function checkPatchOps(ops: readonly PatchOp[]): PatchOp[] {
  if (!Array.isArray(ops) || ops.length === 0) refuse('validation', 'Nothing to change');
  if (ops.length > 16) refuse('validation', 'Too many changes at once');
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
export function applyPatchOps(config: unknown, rawOps: readonly PatchOp[]): PatchResult {
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

  for (const op of ops) {
    const at = next
      .map((ib, i) => (isObj(ib) && ib.tag === op.inboundTag ? i : -1))
      .filter((i) => i >= 0);
    if (at.length === 0) refuse('servers.unknown_inbound', `No inbound is tagged ${op.inboundTag}`);
    if (at.length > 1)
      refuse('servers.profile_malformed', `Two inbounds are tagged ${op.inboundTag}`);
    const index = at[0] ?? -1;
    const ib = next[index] as Record<string, unknown>;
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
  };
}
