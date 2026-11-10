/**
 * The revocation watch (pure): when a revoked key's open connection is still
 * being served, and what to do about it. docs/backends.md "Revoking a key with
 * an open Hysteria connection".
 *
 * A Hysteria connection authenticates once, and the node core never closes it
 * when the key is disabled or deleted; only a restart of the node's core does.
 * A disabled key is still metered, though: any growth in the bytes the backend
 * counts to it after the revocation proves an open connection is carrying
 * traffic. So FCP watches a revoked Hysteria key while it is disabled, and asks
 * for a restart of its node only when it keeps moving bytes.
 *
 * Settings live in the generic `revocation.*` keys (appSettings
 * SETTINGS_DEFAULTS); `revocationConfig` reads them fail-safe (a stored value
 * of the wrong type or out of range falls back to the default or is clamped).
 */

const MIN = 60_000;
const DAY = 86_400_000;

export interface RevocationConfig {
  /** Master switch: watch revoked Hysteria keys and cut leaked sessions. Off by default. */
  enabled: boolean;
  /** At most one restart per node in this window (admin cuts bypass it). */
  cutMinIntervalMs: number;
  /** An admin disable cuts the key's node at once when the key was online recently. */
  adminDisableCutsNow: boolean;
  /** A Hysteria key being deleted is disabled first and deleted this much later. */
  drainMs: number;
  /** A disabled key is watched this long after its revocation. */
  watchMs: number;
  /** Bytes counted after the baseline that prove a leaked session. */
  leakBytes: number;
}

export const REVOCATION_DEFAULTS = {
  'revocation.watch': false,
  'revocation.cutMinIntervalMinutes': 30,
  'revocation.adminDisableCutsNow': true,
  'revocation.drainMinutes': 60,
  'revocation.watchDays': 14,
  'revocation.leakBytes': 262_144,
} as const;

/** The backend collects node stats late: bytes from before the revocation can land after it. */
export const SETTLE_MS = 3 * MIN;
/** How often one watch is read. */
export const CHECK_EVERY_MS = 5 * MIN;
/** A key that keeps moving bytes after this many cuts is reported, not cut again. */
export const MAX_CUTS = 2;
/** An admin disable cuts at once only when the key was online this recently. */
export const ADMIN_ONLINE_WINDOW_MS = 15 * MIN;
/** A cut the ledger refused or the backend failed is tried again after this. */
export const CUT_RETRY_MS = 15 * MIN;
/** A claimed cut that never finished is claimable again after this. */
export const CUT_CLAIM_STALE_MS = 5 * MIN;

function num(v: unknown, def: number, lo: number, hi: number): number {
  const n = typeof v === 'number' && Number.isFinite(v) ? v : def;
  return Math.min(hi, Math.max(lo, n));
}

export function revocationConfig(settings: Record<string, unknown>): RevocationConfig {
  const d = REVOCATION_DEFAULTS;
  return {
    enabled: settings['revocation.watch'] === true,
    cutMinIntervalMs:
      num(
        settings['revocation.cutMinIntervalMinutes'],
        d['revocation.cutMinIntervalMinutes'],
        5,
        1440,
      ) * MIN,
    adminDisableCutsNow:
      typeof settings['revocation.adminDisableCutsNow'] === 'boolean'
        ? settings['revocation.adminDisableCutsNow']
        : d['revocation.adminDisableCutsNow'],
    drainMs: num(settings['revocation.drainMinutes'], d['revocation.drainMinutes'], 10, 1440) * MIN,
    watchMs: num(settings['revocation.watchDays'], d['revocation.watchDays'], 1, 90) * DAY,
    leakBytes: num(settings['revocation.leakBytes'], d['revocation.leakBytes'], 1024, 1024 ** 3),
  };
}

export interface WatchView {
  revokedAt: number;
  /** No baseline is taken before this (the revocation or the last cut, plus SETTLE_MS). */
  settleUntil: number;
  baselineBytes?: number;
  cuts: number;
}

export type Probe =
  { gone: true } | { gone: false; status: string; usedBytes: number; onlineAt: string | null };

export type Decision =
  /** Stop watching: the key is gone, enabled again, or the window ended. */
  | { kind: 'close'; reason: 'gone' | 'enabled' | 'expired' }
  /** Too early to judge (stats still settling). */
  | { kind: 'wait' }
  /** Record the bytes counted so far as the baseline. */
  | { kind: 'baseline'; bytes: number }
  /** Nothing moved beyond the baseline. */
  | { kind: 'keep'; bytes: number }
  /** An open connection is carrying traffic: ask for a cut of the key's node(s). */
  | { kind: 'leaked'; bytes: number; moved: number }
  /** Still moving after MAX_CUTS cuts: something else serves the key; report it. */
  | { kind: 'stuck'; bytes: number; moved: number };

export function decide(w: WatchView, probe: Probe, now: number, cfg: RevocationConfig): Decision {
  if (probe.gone) return { kind: 'close', reason: 'gone' };
  // Enabled again (a renewal, an admin re-enable): nothing to cut.
  if (probe.status === 'ACTIVE' || probe.status === 'active')
    return { kind: 'close', reason: 'enabled' };
  if (now > w.revokedAt + cfg.watchMs) return { kind: 'close', reason: 'expired' };
  if (now < w.settleUntil) return { kind: 'wait' };
  const bytes = Math.max(0, probe.usedBytes);
  // No baseline yet, or the counter went backwards (a periodic traffic reset).
  if (w.baselineBytes === undefined || bytes < w.baselineBytes) return { kind: 'baseline', bytes };
  const moved = bytes - w.baselineBytes;
  if (moved < cfg.leakBytes) return { kind: 'keep', bytes };
  return w.cuts >= MAX_CUTS ? { kind: 'stuck', bytes, moved } : { kind: 'leaked', bytes, moved };
}

/** Whether a node's pending cut may run now. */
export function cutDue(
  row: {
    pendingSince?: number;
    bypassInterval?: boolean;
    lastCutAt?: number;
    claimAt?: number;
    retryAfter?: number;
  },
  now: number,
  cfg: Pick<RevocationConfig, 'cutMinIntervalMs'>,
): boolean {
  if (row.pendingSince === undefined) return false;
  if (row.claimAt !== undefined && now - row.claimAt < CUT_CLAIM_STALE_MS) return false;
  if (row.retryAfter !== undefined && now < row.retryAfter) return false;
  if (row.bypassInterval) return true;
  return row.lastCutAt === undefined || now - row.lastCutAt >= cfg.cutMinIntervalMs;
}

/** Whether an admin disable should cut at once: the key was online recently. */
export function onlineRecently(onlineAt: string | null | undefined, now: number): boolean {
  if (!onlineAt) return false;
  const t = Date.parse(onlineAt);
  return Number.isFinite(t) && now - t <= ADMIN_ONLINE_WINDOW_MS;
}
