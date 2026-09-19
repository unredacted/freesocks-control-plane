/**
 * The rules of a panel write (pure; unit-tested). See `panelOps` in schema.ts.
 *
 * A write to a panel has three independent facts, and conflating them is how a
 * control plane ends up overwriting its own later work:
 *
 *   request      what happened to the HTTP exchange;
 *   panelState   whether the intended result was SEEN on a read made afterwards;
 *   asyncEffect  whether work the panel QUEUED behind the write has finished.
 *
 * `request`: only an outcome on the pre-mutation ALLOWLIST proves nothing
 * changed. Measured on the panel (docs/backends.md "Management contract"): an
 * auth rejection stores nothing, while an invalid config also stores nothing
 * but answers 500, and a 5xx can never be on the list (a gateway can answer one
 * while upstream commits). So: no bytes sent, 401 and 403 are rejected; a 2xx is
 * acknowledged; EVERYTHING else, a timeout included, is uncertain.
 *
 * An uncertain attempt stays fenced. It resolves when its postcondition is
 * observed (with a single outstanding attempt, and a postcondition that differs
 * from the state before, seeing it means the attempt landed and is finished) or
 * through a recorded recovery. It is never retried, never re-asserted and never
 * released by the clock.
 */

export type RequestOutcome = 'pending' | 'rejected_pre_mutation' | 'acknowledged' | 'uncertain';
export type PanelStateSeen = 'observed' | 'unobserved';
export type AsyncEffect = 'none' | 'pending' | 'complete' | 'unresolved';

export interface OpFacts {
  request: RequestOutcome;
  panelState: PanelStateSeen;
  asyncEffect: AsyncEffect;
  recovery?: unknown;
}

/** What a provider call ended as, reduced to what the classification may read. */
export type CallResult =
  | { kind: 'ok' }
  | { kind: 'http'; status: number }
  /** The request provably never left (DNS failure, connection refused before any byte). */
  | { kind: 'not_sent' }
  /** Timeout, reset mid-exchange, unparseable answer: anything else. */
  | { kind: 'unknown' };

const PRE_MUTATION_STATUSES = new Set([401, 403]);

export function classifyRequest(result: CallResult): RequestOutcome {
  if (result.kind === 'ok') return 'acknowledged';
  if (result.kind === 'not_sent') return 'rejected_pre_mutation';
  if (result.kind === 'http' && PRE_MUTATION_STATUSES.has(result.status))
    return 'rejected_pre_mutation';
  return 'uncertain';
}

/** Reduce a thrown provider error to a CallResult without reading its message. */
export function callResultOf(err: unknown): CallResult {
  const meta = (err as { meta?: { status?: unknown } } | null)?.meta;
  if (meta && typeof meta.status === 'number') return { kind: 'http', status: meta.status };
  const code = (err as { cause?: { code?: unknown }; code?: unknown } | null) ?? {};
  const c = String((code.cause as { code?: unknown } | undefined)?.code ?? code.code ?? '');
  if (c === 'ENOTFOUND' || c === 'ECONNREFUSED' || c === 'EAI_AGAIN') return { kind: 'not_sent' };
  return { kind: 'unknown' };
}

/** The only conditions under which an op lets go of its claims. */
export function claimsReleasable(op: OpFacts): boolean {
  if (op.request === 'rejected_pre_mutation') return true;
  if (op.recovery) return true;
  return (
    op.panelState === 'observed' && (op.asyncEffect === 'none' || op.asyncEffect === 'complete')
  );
}

export type OpDisplayState =
  | 'working'
  | 'done'
  | 'refused'
  | 'waiting_for_nodes'
  | 'outcome_unknown'
  | 'recovered';

/** One word for the operator, derived; control flow reads the three facts. */
export function displayState(op: OpFacts): OpDisplayState {
  if (op.recovery) return 'recovered';
  if (op.request === 'rejected_pre_mutation') return 'refused';
  if (op.request === 'pending') return 'working';
  if (op.panelState === 'unobserved')
    return op.request === 'uncertain' ? 'outcome_unknown' : 'working';
  if (op.asyncEffect === 'pending' || op.asyncEffect === 'unresolved') return 'waiting_for_nodes';
  return 'done';
}

// --- identities and claim keys ------------------------------------------------------------------

/**
 * A Host being CREATED has no uuid and its attributes enforce no uniqueness (an
 * identical create is a second Host, measured). Its reserved identity is what
 * discovery looks for after a lost response: remark + inbound + address:port,
 * the same composite the edges Host machine matches on.
 */
export function hostIdentity(h: {
  remark: string;
  inboundUuid: string;
  address: string;
  port: number;
}): string {
  return JSON.stringify([h.remark, h.inboundUuid, h.address.toLowerCase(), h.port]);
}

export const claimKey = {
  host: (uuid: string) => `host:${uuid}`,
  hostIdentity: (identity: string) => `hostid:${identity}`,
  hostOrder: () => 'hosts:order',
  squad: (uuid: string) => `squad:${uuid}`,
  squadName: (name: string) => `squadname:${name.toLowerCase()}`,
  profile: (uuid: string) => `profile:${uuid}`,
  node: (uuid: string) => `node:${uuid}`,
};

// --- postconditions ---------------------------------------------------------------------------

export interface ObservedHostLike {
  hostUuid: string;
  remark: string;
  address: string;
  port: number;
  configProfileInboundUuid: string | null;
}

/** Hosts matching a create's reserved identity. 0 = not there, 1 = adopt, 2+ = an operator's call. */
export function hostsMatchingIdentity<H extends ObservedHostLike>(
  hosts: readonly H[],
  identity: string,
): H[] {
  return hosts.filter(
    (h) =>
      hostIdentity({
        remark: h.remark,
        inboundUuid: h.configProfileInboundUuid ?? '',
        address: h.address,
        port: h.port,
      }) === identity,
  );
}

/** Every field the postcondition names equals the observed row's (null and '' are the same "unset"). */
export function fieldsMatch(
  observed: Record<string, unknown> | null | undefined,
  expected: Record<string, unknown>,
): boolean {
  if (!observed) return false;
  const norm = (v: unknown) => (v === '' || v === undefined ? null : v);
  return Object.entries(expected).every(([k, v]) =>
    Array.isArray(v)
      ? Array.isArray(observed[k]) &&
        JSON.stringify([...(observed[k] as unknown[])].sort()) === JSON.stringify([...v].sort())
      : norm(observed[k]) === norm(v),
  );
}

/** A delete is confirmed only by absence on this many consecutive reads. */
export const GONE_LOOKS_REQUIRED = 2;

/**
 * Whether the panel's queued node work behind a write is finished: for every
 * node recorded before the call, the panel's `lastStatusChange` has moved. A
 * node that is unreachable stays PENDING (the panel delivers on reconnect,
 * measured), which is the honest answer. `isConnected` and `xrayUptime` are
 * deliberately not read: neither says anything about application (measured).
 */
export function asyncWorkFinished(
  before: readonly { nodeUuid: string; before: string | null }[],
  now: readonly { nodeUuid: string; lastStatusChange: string | null; isDisabled: boolean }[],
): boolean {
  const by = new Map(now.map((n) => [n.nodeUuid, n]));
  return before.every((b) => {
    const n = by.get(b.nodeUuid);
    // A node that is gone or was disabled has no application work left to wait for.
    if (!n || n.isDisabled) return true;
    return n.lastStatusChange !== null && n.lastStatusChange !== b.before;
  });
}

// --- Host locks -----------------------------------------------------------------------------------

export type HostLock = 'edge' | 'legacy' | 'hide-ledger';

/** Why a Host is not the operator's to edit here: it belongs to the edges machinery. */
export function hostLock(
  hostUuid: string,
  refs: {
    listenerHostUuids: ReadonlySet<string>;
    legacyHostUuids: ReadonlySet<string>;
    hideLedgerUuids: ReadonlySet<string>;
  },
): HostLock | null {
  if (refs.listenerHostUuids.has(hostUuid)) return 'edge';
  if (refs.legacyHostUuids.has(hostUuid)) return 'legacy';
  if (refs.hideLedgerUuids.has(hostUuid)) return 'hide-ledger';
  return null;
}

/** `<node>-relay[-<key>]`: a remark the edges machinery owns; an operator may not create one. */
export function looksLikeRelayRemark(remark: string, nodeNames: readonly string[]): boolean {
  return nodeNames.some((n) => {
    const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`^${esc}-relay(?:-[a-z0-9]{1,16})?$`).test(remark);
  });
}

/** The role contract version a write requires of an instance's handoff. */
export const REQUIRED_ROLE_CONTRACT_VERSION = 1;
