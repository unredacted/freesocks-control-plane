/**
 * The mirror sync ledger's rules (convex/mirrorCopies.ts holds the rows): how
 * one copy of a member's mirror (subscription x provider) moves between
 * states. Pure, so every transition is unit-testable without a database.
 *
 *  - `in_sync`: the object holds the body FCP would serve, as of the last check.
 *  - `stale`: it is known to differ (or to have been overtaken) and an upload is
 *    due: the key moved, the policy moved under the write, the object was
 *    overwritten or the member-facing URL serves something else.
 *  - `failing`: the last attempt to bring it in sync failed (the backend body
 *    could not be fetched, the write failed, the provider is gone).
 *  - `never`: FCP holds no record of what the object holds: a copy tracked from
 *    before the ledger and not checked yet, or one the member-facing URL no
 *    longer serves at all.
 */
import type { MirrorCopyState } from './statusCounters';

export type { MirrorCopyState };

export type MirrorReason =
  /** What FCP serves changed since the object was written (another copy took the new body). */
  | 'content_changed'
  /** The key moved in place (a mode or server switch, a pin rotation). */
  | 'invalidated'
  /** The member's stored country changed (the render depends on it). */
  | 'country_changed'
  /** The mirror moved to a re-issued key: the object still holds the old one. */
  | 'reissued'
  /** The delivery policy moved while the object was written. */
  | 'policy_moved'
  /** An upload of an older row of the same key overwrote the object. */
  | 'overwritten'
  /** The member-facing URL serves a different body. */
  | 'object_mismatch'
  /** The member-facing URL serves nothing (not found / forbidden). */
  | 'missing'
  /** Tracked from before the ledger; not checked yet. */
  | 'unchecked'
  /** The backend body could not be fetched. */
  | 'fetch_failed'
  /** The write to the provider failed. */
  | 'upload_failed'
  /** The provider row is gone (removed before FCP withdrew its mirrors). */
  | 'provider_missing'
  /** The object was rewritten, and the member-facing URL still serves nothing. */
  | 'url_unreadable'
  /** The object was rewritten, and the member-facing URL still serves another body. */
  | 'url_stale';

/** What a copy row carries about its sync (the `mirrorCopies` fields this module decides). */
export interface CopySync {
  state: MirrorCopyState;
  reason?: string;
  since: number;
  checkedAt?: number;
  syncedAt?: number;
  uploadedAt?: number;
  objectHash?: string;
  servedHash?: string;
  servedEpoch?: number | null;
  stub?: boolean;
  failures: number;
  lastError?: string;
  lastErrorAt?: number;
}

/** What one check found for one copy. */
export type CopyOutcome =
  /** The object already holds the served body. */
  | { kind: 'confirmed' }
  /** The served body was written now; `moved` = the policy moved during the write. */
  | { kind: 'uploaded'; moved: boolean }
  | { kind: 'upload_failed' }
  | { kind: 'fetch_failed' }
  | { kind: 'provider_missing' };

/** The served body of one check (absent when it could not be rendered). */
export interface ServedBody {
  hash: string;
  epoch: number | null;
  stub: boolean;
}

/** `since` moves only when the state does. */
function enter(prev: CopySync, state: MirrorCopyState, at: number): number {
  return prev.state === state ? prev.since : at;
}

/** The copy after one check. Fields absent from the result are cleared. */
export function afterCheck(
  prev: CopySync,
  outcome: CopyOutcome,
  at: number,
  served: ServedBody | null,
): CopySync {
  const seen = served
    ? { servedHash: served.hash, servedEpoch: served.epoch, stub: served.stub || undefined }
    : { servedHash: prev.servedHash, servedEpoch: prev.servedEpoch, stub: prev.stub };
  // The last failure stays as history; `failures` counts the consecutive ones.
  const kept = {
    objectHash: prev.objectHash,
    uploadedAt: prev.uploadedAt,
    syncedAt: prev.syncedAt,
    lastError: prev.lastError,
    lastErrorAt: prev.lastErrorAt,
  };
  // A copy whose public URL fails stays failing whatever a check says: the
  // object holding the body (per the S3 API) does not prove the URL serves
  // it. Only a read that matches clears it (`afterVerify`).
  const urlFailing =
    prev.state === 'failing' && (prev.reason === 'url_unreadable' || prev.reason === 'url_stale');
  if (
    urlFailing &&
    (outcome.kind === 'confirmed' || (outcome.kind === 'uploaded' && !outcome.moved))
  )
    return {
      ...prev,
      ...seen,
      checkedAt: at,
      ...(outcome.kind === 'uploaded' ? { uploadedAt: at } : {}),
      objectHash: served?.hash ?? prev.objectHash,
    };
  switch (outcome.kind) {
    case 'confirmed':
      return {
        ...kept,
        ...seen,
        state: 'in_sync',
        since: enter(prev, 'in_sync', at),
        checkedAt: at,
        syncedAt: at,
        objectHash: served?.hash ?? prev.objectHash,
        failures: 0,
      };
    case 'uploaded':
      return outcome.moved
        ? {
            ...kept,
            ...seen,
            state: 'stale',
            reason: 'policy_moved',
            since: enter(prev, 'stale', at),
            checkedAt: at,
            uploadedAt: at,
            objectHash: served?.hash ?? prev.objectHash,
            failures: 0,
          }
        : {
            ...kept,
            ...seen,
            state: 'in_sync',
            since: enter(prev, 'in_sync', at),
            checkedAt: at,
            uploadedAt: at,
            syncedAt: at,
            objectHash: served?.hash ?? prev.objectHash,
            failures: 0,
          };
    case 'upload_failed':
    case 'fetch_failed':
    case 'provider_missing':
      return {
        ...kept,
        ...seen,
        state: 'failing',
        reason: outcome.kind,
        since: enter(prev, 'failing', at),
        checkedAt: at,
        failures: prev.failures + 1,
        lastError: outcome.kind,
        lastErrorAt: at,
      };
  }
}

/**
 * Something the served body depends on moved for this key: the copy is stale
 * until the next check (a failing copy stays failing, and keeps its count).
 * The served hash is unknown again.
 */
export function afterInvalidation(prev: CopySync, reason: MirrorReason, at: number): CopySync {
  if (prev.state === 'failing') return { ...prev, servedHash: undefined };
  return {
    ...prev,
    state: 'stale',
    reason,
    since: enter(prev, 'stale', at),
    servedHash: undefined,
  };
}

/** What a read of the member-facing URL found. */
export type VerifyOutcome =
  | { kind: 'match' }
  | { kind: 'mismatch'; observedHash: string }
  | { kind: 'missing' }
  | { kind: 'unreachable' };

export type VerifyResult = VerifyOutcome['kind'];

/**
 * The copy after a read of its member-facing URL, and whether an upload is due.
 * `last`: what the previous read found, and when.
 *
 * The first time the URL serves another body, or nothing, the object is
 * rewritten (something overwrote or deleted it). If a read after that rewrite
 * finds the same, rewriting again will not help: the URL itself is the
 * problem (the bucket is not publicly readable, the public URL is wrong, a
 * cache in front keeps an old body), so the copy is failing and waits for the
 * operator, not for another upload. A read that matches clears that. A copy
 * already failing for another reason (its upload fails) is left to the
 * retries that already handle it. An unreachable URL changes nothing: the read
 * is retried and the state stays what the last check found.
 */
export function afterVerify(
  prev: CopySync,
  last: { verify?: VerifyResult; verifiedAt?: number },
  outcome: VerifyOutcome,
  at: number,
): { next: CopySync; reupload: boolean } {
  const rewroteSinceProblem =
    (last.verify === 'mismatch' || last.verify === 'missing') &&
    prev.uploadedAt !== undefined &&
    last.verifiedAt !== undefined &&
    prev.uploadedAt > last.verifiedAt;
  const urlFailing =
    prev.state === 'failing' && (prev.reason === 'url_unreadable' || prev.reason === 'url_stale');
  const otherFailure = prev.state === 'failing' && !urlFailing;
  const fail = (reason: MirrorReason): { next: CopySync; reupload: boolean } => ({
    next: {
      ...prev,
      state: 'failing',
      reason,
      since: enter(prev, 'failing', at),
      failures: prev.failures + 1,
      lastError: reason,
      lastErrorAt: at,
    },
    reupload: false,
  });
  switch (outcome.kind) {
    case 'unreachable':
      return { next: prev, reupload: false };
    case 'match': {
      if (!urlFailing) return { next: prev, reupload: false };
      if (prev.servedHash && prev.objectHash === prev.servedHash)
        return {
          next: {
            ...prev,
            state: 'in_sync',
            reason: undefined,
            since: at,
            failures: 0,
            syncedAt: at,
          },
          reupload: false,
        };
      return {
        next: { ...prev, state: 'stale', reason: 'content_changed', since: at, failures: 0 },
        reupload: true,
      };
    }
    case 'mismatch': {
      if (urlFailing || rewroteSinceProblem) return fail('url_stale');
      const next = { ...prev, objectHash: outcome.observedHash };
      if (prev.servedHash && outcome.observedHash === prev.servedHash)
        return {
          next: { ...next, state: 'in_sync', reason: undefined, since: enter(prev, 'in_sync', at) },
          reupload: false,
        };
      if (otherFailure) return { next, reupload: false };
      return {
        next: {
          ...next,
          state: 'stale',
          reason: 'object_mismatch',
          since: enter(prev, 'stale', at),
        },
        reupload: true,
      };
    }
    case 'missing':
      if (urlFailing || rewroteSinceProblem) return fail('url_unreadable');
      if (otherFailure) return { next: { ...prev, objectHash: undefined }, reupload: false };
      return {
        next: {
          ...prev,
          objectHash: undefined,
          state: 'never',
          reason: 'missing',
          since: enter(prev, 'never', at),
        },
        reupload: true,
      };
  }
}

/** A copy that needs an upload on this check: unknown or different content, or a forced rewrite. */
export function needsUpload(
  objectHash: string | null | undefined,
  servedHash: string,
  forced: boolean,
): boolean {
  return forced || objectHash !== servedHash;
}

// --- attention bounds -----------------------------------------------------------------------------

/**
 * A copy that stays stale, failing or not uploaded this long needs the operator:
 * every change that moves a body schedules its own refresh at once, and the
 * repair pass retries within minutes, so an hour means something is broken.
 */
export const MIRROR_ATTENTION_AFTER_MS = 60 * 60_000;
/** An in-sync copy not checked for this long: the six-hourly sweep is not reaching it. */
export const MIRROR_CHECK_OVERDUE_MS = 13 * 3_600_000;
/** How often each copy's member-facing URL is read back (the `mirror-verify` cron). */
export const MIRROR_VERIFY_EVERY_MS = 6 * 3_600_000;
/** A read that found a problem is repeated this soon (after the rewrite it caused). */
export const MIRROR_REVERIFY_AFTER_MS = 10 * 60_000;
