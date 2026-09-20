/**
 * Pure helpers for the origin layer's view of a backend's Hosts (client-facing
 * connection entries). Two jobs:
 *
 *  1. Find the TEMPLATE Host that belongs to an origin slot. The Ansible role
 *     creates exactly one per slot with the stable remark
 *     `<nodeHostname>-origin-<slotKey>`; the remark is the identity, so a
 *     friendly display label elsewhere never affects discovery.
 *  2. Diff a set of planned Hosts against what the backend actually holds
 *     (observe-then-write): which are already at the target, which still need
 *     a write, which vanished or changed transport. A planned uuid that is missing
 *     is `hosts_changed`, NEVER convergence — an empty remaining set is not a
 *     success.
 *
 * Anti-leak invariant: a Host whose address equals the origin's own address
 * would publish the node to every subscriber; such a Host is excluded from any
 * plan and surfaced as drift.
 */
import type { BackendHost } from '../backends/types';

const SLOT_KEY_RE = /^[a-z0-9]{1,16}$/;

export function isSlotKey(v: unknown): v is string {
  return typeof v === 'string' && SLOT_KEY_RE.test(v);
}

/** The template Host remark for one origin slot. */
export function templateHostRemark(nodeHostname: string, slotKey: string): string {
  return `${nodeHostname}-relay-${slotKey}`;
}

/** Matches every origin Host of a node: `<node>-origin`, `<node>-origin-<slotKey>`,
 *  and the legacy `<node>-origin-<hash6>` multi-SNI convention. */
export function relayRemarkRegex(nodeHostname: string): RegExp {
  const esc = nodeHostname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${esc}-relay(?:-[a-z0-9]{1,16})?$`);
}

export interface SlotRef {
  slotId: string;
  slotKey: string;
  templateHostRemark: string;
}

export interface SlotHostMatch {
  slotId: string;
  slotKey: string;
  host: BackendHost | null;
  /** More than one Host carries the slot's remark (operator error). */
  duplicates: number;
  /** The matched Host points at the origin itself. */
  leaks: boolean;
}

/** Match each slot's template Host by exact remark. */
export function matchSlotHosts(
  hosts: readonly BackendHost[],
  slots: readonly SlotRef[],
  originAddress: string,
): SlotHostMatch[] {
  return slots.map((slot) => {
    const found = hosts.filter((h) => h.remark === slot.templateHostRemark);
    const host = found[0] ?? null;
    return {
      slotId: slot.slotId,
      slotKey: slot.slotKey,
      host,
      duplicates: Math.max(0, found.length - 1),
      leaks: host !== null && sameAddress(host.address, originAddress),
    };
  });
}

/** Plan snapshot version 2 also captured the Host's SNI and Host header. */
export const HOST_PLAN_SNAPSHOT_VERSION = 2;

export interface HostPlanEntry {
  uuid: string;
  oldAddress: string;
  oldPort: number;
  inboundUuid?: string;
  /**
   * 2 = the SNI/Host below were read from the live Host. ABSENT = a legacy plan
   * whose historical SNI/Host are UNKNOWN, which is not the same as a known
   * `null` (= the Host carried none): a legacy rollback restores address and
   * port only and never clears operator configuration.
   */
  snapshotVersion?: number;
  oldSni?: string | null;
  oldHost?: string | null;
}

/**
 * The Host tuple a flip writes. `null` = the field must be CLEARED on the
 * backend; `undefined` = the field is not part of this target (not compared, not
 * written), which keeps legacy callers that only move address/port working.
 */
export interface HostTarget {
  address: string;
  port: number;
  sni?: string | null;
  host?: string | null;
}

/** `''` and `null` mean the same thing on the backend: the field carries nothing. */
function sameOptional(live: string | null | undefined, want: string | null): boolean {
  const l = live === undefined || live === null || live === '' ? null : live.trim().toLowerCase();
  const w = want === null || want === '' ? null : want.trim().toLowerCase();
  return l === w;
}

export interface HostDiff {
  /** Planned Hosts already at the target. */
  atTarget: HostPlanEntry[];
  /** Planned Hosts that still need a write. */
  needsWrite: HostPlanEntry[];
  /** Planned uuids the backend no longer has. */
  missing: HostPlanEntry[];
  /** Planned Hosts whose transport binding changed (the role re-created them). */
  changedInbound: HostPlanEntry[];
  /** True iff every planned Host is present, unchanged, and at the target. */
  converged: boolean;
  /** Any missing/changed entry: the run must not proceed as if converged. */
  hostsChanged: boolean;
}

/**
 * Compare the planned Hosts against the live list for one target tuple.
 * Convergence requires a NON-EMPTY plan with every entry present and at target.
 * SNI / Host are compared only when the target defines them, so an L4 → L7
 * transition (which must also rewrite them) is not reported converged while the
 * backend still carries the previous layer's names.
 */
export function diffHosts(
  live: readonly BackendHost[],
  plan: readonly HostPlanEntry[],
  target: HostTarget,
): HostDiff {
  const byUuid = new Map(live.map((h) => [h.uuid, h]));
  const atTarget: HostPlanEntry[] = [];
  const needsWrite: HostPlanEntry[] = [];
  const missing: HostPlanEntry[] = [];
  const changedInbound: HostPlanEntry[] = [];
  for (const p of plan) {
    const h = byUuid.get(p.uuid);
    if (!h) {
      missing.push(p);
      continue;
    }
    // A planned binding that changed OR disappeared is drift (the role re-created
    // or detached the Host); only a plan without a binding skips the check.
    if (p.inboundUuid && (h.inbound?.configProfileInboundUuid ?? null) !== p.inboundUuid) {
      changedInbound.push(p);
      continue;
    }
    const at =
      sameAddress(h.address, target.address) &&
      h.port === target.port &&
      (target.sni === undefined || sameOptional(h.sni, target.sni)) &&
      (target.host === undefined || sameOptional(h.host, target.host));
    if (at) atTarget.push(p);
    else needsWrite.push(p);
  }
  const hostsChanged = missing.length > 0 || changedInbound.length > 0;
  return {
    atTarget,
    needsWrite,
    missing,
    changedInbound,
    converged: plan.length > 0 && !hostsChanged && needsWrite.length === 0,
    hostsChanged,
  };
}

/**
 * Build the plan entries from matched template Hosts (skipping leaking ones).
 * Captures the FULL previous tuple at version 2: `''` on the backend is recorded
 * as `null` (the Host carried nothing), which a rollback then clears again.
 */
export function planFromMatches(matches: readonly SlotHostMatch[]): HostPlanEntry[] {
  const out: HostPlanEntry[] = [];
  for (const m of matches) {
    if (!m.host || m.leaks) continue;
    out.push({
      uuid: m.host.uuid,
      oldAddress: m.host.address,
      oldPort: m.host.port,
      inboundUuid: m.host.inbound?.configProfileInboundUuid ?? undefined,
      snapshotVersion: HOST_PLAN_SNAPSHOT_VERSION,
      oldSni: m.host.sni ? m.host.sni : null,
      oldHost: m.host.host ? m.host.host : null,
    });
  }
  return out;
}

/**
 * The tuple a rollback must restore for one plan entry. A version-2 entry
 * restores address, port, SNI and Host (clears included); a LEGACY entry
 * restores address and port only: its historical SNI/Host are unknown, and
 * "unknown" must never be written as "clear it".
 */
export function rollbackTargetFor(entry: HostPlanEntry): HostTarget {
  if ((entry.snapshotVersion ?? 0) < HOST_PLAN_SNAPSHOT_VERSION)
    return { address: entry.oldAddress, port: entry.oldPort };
  return {
    address: entry.oldAddress,
    port: entry.oldPort,
    sni: entry.oldSni ?? null,
    host: entry.oldHost ?? null,
  };
}

/** Case-insensitive, bracket-tolerant address equality (IPv6 literals). */
export function sameAddress(a: string, b: string): boolean {
  return normalizeAddress(a) === normalizeAddress(b);
}

export function normalizeAddress(a: string): string {
  return a
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '');
}
