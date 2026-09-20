/**
 * Fencing for the bootstrap workflows (pure). Every scheduled action carries
 * the row id, the generation it was scheduled for and its attempt id, and a
 * workflow row changes only when both still match: a callback of an older
 * generation, or of a lease another attempt now holds, is a no-op. A changed
 * `desired` bumps the generation; an identical one reuses the row.
 */
import { sha256Hex } from '../crypto';
import { canonicalJson } from './digest';

/** How long an attempt may hold a workflow row before the sweep may resume it. */
export const CLAIM_LEASE_MS = 10 * 60_000;

export interface Fence {
  generation: number;
  attemptId: string;
}

export interface FencedRow {
  generation: number;
  claim?: { attemptId: string; expiresAt: number } | null;
}

/** Whether a callback made for `fence` may act on `row` now. */
export function fenceHolds(row: FencedRow, fence: Fence): boolean {
  if (row.generation !== fence.generation) return false;
  return !!row.claim && row.claim.attemptId === fence.attemptId;
}

/** Whether a new attempt may take the row: no claim, or an expired one. */
export function claimAvailable(row: FencedRow, now: number): boolean {
  return !row.claim || row.claim.expiresAt <= now;
}

/** A stable hash of a workflow's desired input (what an identical PUT reuses). */
export async function desiredHashOf(desired: unknown): Promise<string> {
  return sha256Hex(canonicalJson(desired));
}
