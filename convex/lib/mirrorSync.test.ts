import { describe, expect, test } from 'vitest';
import {
  afterCheck,
  afterInvalidation,
  afterVerify,
  needsUpload,
  type CopySync,
} from './mirrorSync';

const T0 = 1_000_000;
const base = (over: Partial<CopySync> = {}): CopySync => ({
  state: 'in_sync',
  since: T0,
  checkedAt: T0,
  syncedAt: T0,
  objectHash: 'h1',
  servedHash: 'h1',
  failures: 0,
  ...over,
});
const served = (hash: string) => ({ hash, epoch: 3, stub: false });

describe('afterCheck', () => {
  test('a confirmed copy stays in sync and keeps its since', () => {
    const next = afterCheck(base(), { kind: 'confirmed' }, T0 + 5, served('h1'));
    expect(next).toMatchObject({
      state: 'in_sync',
      since: T0,
      checkedAt: T0 + 5,
      syncedAt: T0 + 5,
    });
  });

  test('an upload brings a stale copy in sync with the served hash', () => {
    const prev = base({
      state: 'stale',
      reason: 'invalidated',
      since: T0 + 1,
      servedHash: undefined,
    });
    const next = afterCheck(prev, { kind: 'uploaded', moved: false }, T0 + 9, served('h2'));
    expect(next).toMatchObject({
      state: 'in_sync',
      since: T0 + 9,
      objectHash: 'h2',
      servedHash: 'h2',
      uploadedAt: T0 + 9,
      failures: 0,
    });
    expect(next.reason).toBeUndefined();
  });

  test('an upload a policy move overtook records the bytes but stays stale', () => {
    const next = afterCheck(base(), { kind: 'uploaded', moved: true }, T0 + 9, served('h2'));
    expect(next).toMatchObject({ state: 'stale', reason: 'policy_moved', objectHash: 'h2' });
  });

  test('failures count up, keep the object hash and leave the last error as history', () => {
    const once = afterCheck(base(), { kind: 'upload_failed' }, T0 + 1, served('h2'));
    const twice = afterCheck(once, { kind: 'upload_failed' }, T0 + 2, served('h2'));
    expect(twice).toMatchObject({
      state: 'failing',
      reason: 'upload_failed',
      since: T0 + 1,
      failures: 2,
      objectHash: 'h1',
      servedHash: 'h2',
      lastErrorAt: T0 + 2,
    });
    const healed = afterCheck(twice, { kind: 'uploaded', moved: false }, T0 + 3, served('h2'));
    expect(healed).toMatchObject({ state: 'in_sync', failures: 0, lastError: 'upload_failed' });
  });

  test('a check never clears a public-URL failure (only a matching read does)', () => {
    const failing = base({ state: 'failing', reason: 'url_stale', failures: 1, since: T0 });
    const confirmed = afterCheck(failing, { kind: 'confirmed' }, T0 + 5, served('h1'));
    expect(confirmed).toMatchObject({ state: 'failing', reason: 'url_stale', checkedAt: T0 + 5 });
    const uploaded = afterCheck(failing, { kind: 'uploaded', moved: false }, T0 + 6, served('h2'));
    expect(uploaded).toMatchObject({ state: 'failing', objectHash: 'h2', uploadedAt: T0 + 6 });
  });

  test('a fetch failure says nothing new about the served body', () => {
    const next = afterCheck(base(), { kind: 'fetch_failed' }, T0 + 1, null);
    expect(next).toMatchObject({ state: 'failing', servedHash: 'h1', objectHash: 'h1' });
  });
});

describe('afterInvalidation', () => {
  test('an in-sync copy goes stale and forgets the served hash', () => {
    const next = afterInvalidation(base(), 'country_changed', T0 + 1);
    expect(next).toMatchObject({ state: 'stale', reason: 'country_changed', since: T0 + 1 });
    expect(next.servedHash).toBeUndefined();
  });

  test('a failing copy stays failing (its count is kept)', () => {
    const next = afterInvalidation(
      base({ state: 'failing', reason: 'upload_failed', failures: 3 }),
      'invalidated',
      T0 + 1,
    );
    expect(next).toMatchObject({ state: 'failing', reason: 'upload_failed', failures: 3 });
  });

  test('an already stale copy keeps its since', () => {
    const next = afterInvalidation(base({ state: 'stale', since: T0 - 50 }), 'reissued', T0 + 1);
    expect(next.since).toBe(T0 - 50);
  });
});

describe('afterVerify', () => {
  test('a match changes nothing', () => {
    expect(afterVerify(base(), {}, { kind: 'match' }, T0 + 1)).toEqual({
      next: base(),
      reupload: false,
    });
  });

  test('an unreachable URL changes nothing', () => {
    expect(afterVerify(base(), { verify: 'match' }, { kind: 'unreachable' }, T0 + 1).reupload).toBe(
      false,
    );
  });

  test('the first missing read means the object went: rewrite it once', () => {
    const { next, reupload } = afterVerify(
      base(),
      { verify: 'match' },
      { kind: 'missing' },
      T0 + 1,
    );
    expect(reupload).toBe(true);
    expect(next).toMatchObject({ state: 'never', reason: 'missing' });
    expect(next.objectHash).toBeUndefined();
  });

  test('missing again after that rewrite: the URL is the problem, no upload loop', () => {
    const rewritten = base({ uploadedAt: T0 + 5 });
    const { next, reupload } = afterVerify(
      rewritten,
      { verify: 'missing', verifiedAt: T0 + 1 },
      { kind: 'missing' },
      T0 + 9,
    );
    expect(reupload).toBe(false);
    expect(next).toMatchObject({ state: 'failing', reason: 'url_unreadable', failures: 1 });
  });

  test('another body: stale and rewritten, then failing if it persists after the rewrite', () => {
    const first = afterVerify(
      base(),
      { verify: 'match' },
      { kind: 'mismatch', observedHash: 'hx' },
      T0 + 1,
    );
    expect(first.reupload).toBe(true);
    expect(first.next).toMatchObject({
      state: 'stale',
      reason: 'object_mismatch',
      objectHash: 'hx',
    });
    const again = afterVerify(
      base({ uploadedAt: T0 + 3 }),
      { verify: 'mismatch', verifiedAt: T0 + 1 },
      { kind: 'mismatch', observedHash: 'hx' },
      T0 + 4,
    );
    expect(again.reupload).toBe(false);
    expect(again.next).toMatchObject({ state: 'failing', reason: 'url_stale' });
  });

  test('a body that turns out to be the served one is in sync', () => {
    const prev = base({ objectHash: 'h0', servedHash: 'h1', state: 'stale' });
    const { next, reupload } = afterVerify(
      prev,
      {},
      { kind: 'mismatch', observedHash: 'h1' },
      T0 + 1,
    );
    expect(reupload).toBe(false);
    expect(next).toMatchObject({ state: 'in_sync', objectHash: 'h1' });
  });

  test('a URL that serves the object again clears the failure', () => {
    const failing = base({ state: 'failing', reason: 'url_unreadable', failures: 2 });
    const { next } = afterVerify(failing, { verify: 'missing' }, { kind: 'match' }, T0 + 9);
    expect(next).toMatchObject({ state: 'in_sync', failures: 0, since: T0 + 9 });
  });

  test('a problem found again with no rewrite in between asks for the rewrite again', () => {
    const { reupload, next } = afterVerify(
      base({ state: 'never', reason: 'missing', objectHash: undefined, uploadedAt: T0 }),
      { verify: 'missing', verifiedAt: T0 + 1 },
      { kind: 'missing' },
      T0 + 2,
    );
    expect(reupload).toBe(true);
    expect(next.state).toBe('never');
  });

  test('a copy whose upload keeps failing is left to its retries (no extra rewrite)', () => {
    const { reupload, next } = afterVerify(
      base({ state: 'failing', reason: 'upload_failed', failures: 2 }),
      { verify: 'match' },
      { kind: 'missing' },
      T0 + 2,
    );
    expect(reupload).toBe(false);
    expect(next).toMatchObject({ state: 'failing', reason: 'upload_failed' });
  });
});

describe('needsUpload', () => {
  test('per copy: unknown or different content, or forced', () => {
    expect(needsUpload('h1', 'h1', false)).toBe(false);
    expect(needsUpload('h1', 'h2', false)).toBe(true);
    expect(needsUpload(null, 'h1', false)).toBe(true);
    expect(needsUpload('h1', 'h1', true)).toBe(true);
  });
});
