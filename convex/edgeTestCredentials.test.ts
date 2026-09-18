/// <reference types="vite/client" />
/**
 * Temporary test credentials (docs/edges.md § "Publication"; acceptance 22 +
 * 27): the row exists BEFORE `issueUser`; closing the sheet (release),
 * cancelling the run (releaseForRelay) and a failed panel delete each leave a
 * `pending` row the reconcile sweep removes (bounded retries, then attention
 * `test_key_cleanup`); an empty Outline server has no rehearsal credential
 * (`use_manual_setup`); Remnawave reuses the relay's qualification user and
 * writes no row.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { fakeOutline, fakePanel } from './lib/edges/testing/fakePanel';
import {
  adoptL4Edge,
  insertPanelServer,
  registerRelay,
  shadowsocksListener,
} from './lib/edges/testing/fixtures';
import { TEST_CREDENTIAL_MAX_ATTEMPTS } from './edgeTestCredentials';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

const OUTLINE_ORIGIN = '203.0.113.77';

async function seedOutline() {
  const outline = fakeOutline({ origin: OUTLINE_ORIGIN });
  const t = convexTest(schema, modules);
  await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
  const { relayId } = await registerRelay(t, {
    slug: 'outline-one',
    kind: 'backend-server',
    backendSlug: 'outline-a',
    originAddress: OUTLINE_ORIGIN,
    listeners: [shadowsocksListener()],
  });
  const rows = () => t.run((ctx) => ctx.db.query('edgeTestCredentials').collect());
  return { t, relayId, outline, rows };
}

describe('edgeTestCredentials (Outline temporary keys)', () => {
  test('the obligation row is written BEFORE the create: a lost create leaves a row without an id; a typed refusal leaves none', async () => {
    const { t, relayId, outline, rows } = await seedOutline();
    outline.failCreateWith = 500;
    await expect(
      t.action(internal.edgeTestCredentials.ensure, { relayId, purpose: 'test_link' }),
    ).rejects.toThrow();
    let all = await rows();
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ purpose: 'test_link', removal: 'pending', attempts: 0 });
    expect(all[0].backendUserId).toBeUndefined();
    expect(all[0].username).toMatch(/^fcp-test-link-outline-one-/);
    // A working create fills the id in; the earlier row stays for the sweep.
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    expect(r).toMatchObject({ ok: true, source: 'temporary', reused: false });
    all = await rows();
    expect(all).toHaveLength(2);
    const issued = all.find((x) => x.backendUserId)!;
    expect(issued.backendShortId).toBe(issued.backendUserId!.split(':').pop());
    expect(outline.created).toEqual([issued.username]);
    // The same purpose is reused while the key lives.
    const r2 = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    expect(r2).toMatchObject({ ok: true, reused: true, credentialId: issued._id });
    expect(outline.created).toHaveLength(1);
  });

  test('release (the sheet closed) + the sweep: the key is deleted once, the row is done, nothing is left for attention', async () => {
    const { t, relayId, outline, rows } = await seedOutline();
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    if (!r.ok) throw new Error(r.code);
    const id = r.credentialId!;
    // Not expired yet: the sweep leaves it alone.
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 0 });
    await t.mutation(internal.edgeTestCredentials.release, { id });
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 1 });
    expect(outline.deleted).toHaveLength(1);
    expect((await rows())[0]).toMatchObject({ removal: 'done' });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    expect(items.filter((i) => i.kind === 'test_key_cleanup')).toEqual([]);
    // Audited as booleans only.
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .collect()
        .then((a) => a.filter((x) => x.action === 'edge.test_credential').map((x) => x.payload)),
    );
    expect(audits).toEqual([
      { relaySlug: 'outline-one', purpose: 'test_link', issued: true },
      { relaySlug: 'outline-one', purpose: 'test_link', removed: true, attempts: 1 },
    ]);
    for (const a of audits) expect(JSON.stringify(a)).not.toContain('ss://');
  });

  test('the card closed: releaseForEdge expires the credential behind a link, scoped to the edge relay', async () => {
    const { t, relayId, rows } = await seedOutline();
    const listener = await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', relayId))
        .unique(),
    );
    const { edgeId } = await adoptL4Edge(t, relayId, listener!._id, { ipv4: '198.51.100.7' });
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    expect(r.ok).toBe(true);
    const row = (await rows())[0]!;
    expect(row.expiresAt).toBeGreaterThan(Date.now());
    const out = await t.mutation(internal.edgeTestCredentials.releaseForEdge, {
      edgeId: edgeId as Id<'edges'>,
      credentialId: row._id,
    });
    expect(out).toEqual({ ok: true, released: true });
    expect((await rows())[0]!.expiresAt).toBeLessThanOrEqual(Date.now());
    // A second call is a no-op; a credential of another relay is not found.
    expect(
      await t.mutation(internal.edgeTestCredentials.releaseForEdge, {
        edgeId: edgeId as Id<'edges'>,
        credentialId: row._id,
      }),
    ).toEqual({ ok: true, released: false });
  });

  test('cancelling the run releases every pending row of the relay; the expiry (24 h) releases on its own', async () => {
    const { t, relayId, outline, rows } = await seedOutline();
    await t.action(internal.edgeTestCredentials.ensure, { relayId, purpose: 'test_link' });
    expect(await t.mutation(internal.edgeTestCredentials.releaseForRelay, { relayId })).toEqual({
      released: 1,
    });
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 1 });
    // A second key, never released: it expires.
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    if (!r.ok) throw new Error(r.code);
    await t.run((ctx) =>
      ctx.db.patch(r.credentialId as Id<'edgeTestCredentials'>, { expiresAt: Date.now() - 1 }),
    );
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 1 });
    expect(outline.deleted).toHaveLength(2);
    expect((await rows()).every((x) => x.removal === 'done')).toBe(true);
  });

  test('a failed panel delete stays pending with backoff, then `failed` after the retry cap with attention `test_key_cleanup`; retry re-arms it', async () => {
    const { t, relayId, outline, rows } = await seedOutline();
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    if (!r.ok) throw new Error(r.code);
    const id = r.credentialId!;
    await t.mutation(internal.edgeTestCredentials.release, { id });
    outline.failDeleteWith = 500;
    for (let i = 1; i < TEST_CREDENTIAL_MAX_ATTEMPTS; i++) {
      expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ retried: 1 });
      const row = (await rows())[0];
      expect(row).toMatchObject({ removal: 'pending', attempts: i });
      expect(row.retryAfter).toBeGreaterThan(Date.now());
      // Still backing off: the next sweep skips it until the retry time.
      expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ retried: 0 });
      await t.run((ctx) => ctx.db.patch(id, { retryAfter: Date.now() - 1 }));
    }
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ failed: 1 });
    expect((await rows())[0]).toMatchObject({
      removal: 'failed',
      attempts: TEST_CREDENTIAL_MAX_ATTEMPTS,
    });
    const { items } = await t.query(internal.edgeOperator.attention, {});
    const item = items.find((i) => i.kind === 'test_key_cleanup')!;
    expect(item).toMatchObject({
      severity: 'warning',
      relaySlug: 'outline-one',
      code: 'backend_delete_failed',
      action: 'open_relay',
      facts: { purpose: 'test_link', attempts: TEST_CREDENTIAL_MAX_ATTEMPTS },
    });
    // The panel is back: the operator's retry re-arms the row and the sweep finishes it.
    outline.failDeleteWith = null;
    await t.mutation(internal.edgeTestCredentials.retryCleanup, { id });
    expect(await t.action(internal.edgeTestCredentials.sweep, {})).toMatchObject({ removed: 1 });
    expect(outline.deleted).toEqual(['1']);
  });

  test('a rehearsal on an empty Outline server has no credential path: use_manual_setup, nothing created', async () => {
    const { t, relayId, outline, rows } = await seedOutline();
    expect(
      await t.action(internal.edgeTestCredentials.ensure, { relayId, purpose: 'rehearsal' }),
    ).toEqual({ ok: false, code: 'use_manual_setup', credentialId: null });
    expect(outline.created).toEqual([]);
    expect(await rows()).toEqual([]);
  });
});

describe('edgeTestCredentials (Remnawave: the qualification user)', () => {
  test('both purposes reuse the relay credential through the persisted mint; no row is written; the second call reuses', async () => {
    const panel = fakePanel();
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const { relayId } = await registerRelay(t);
    // A bound pool: the rehearsal body must come from a real placement.
    await t.run((ctx) =>
      ctx.db.insert('modePlacements', {
        modeSlug: 'freedom-ws',
        backend: 'remnawave',
        config: JSON.stringify({ squadUuids: ['sq-node-one'] }),
        updatedAt: Date.now(),
      }),
    );
    const r = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'rehearsal',
    });
    expect(r).toMatchObject({
      ok: true,
      credentialId: null,
      source: 'qualification',
      reused: false,
    });
    if (!r.ok) throw new Error('unreachable');
    expect(r.fetchRef.backendShortId).toBe(r.subscriptionToken);
    expect(panel.created).toHaveLength(1);
    const relay = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(relay.qualificationMint).toMatchObject({ state: 'stored', placement: 'sq-node-one' });
    const r2 = await t.action(internal.edgeTestCredentials.ensure, {
      relayId,
      purpose: 'test_link',
    });
    expect(r2).toMatchObject({ ok: true, reused: true, source: 'qualification' });
    expect(panel.created).toHaveLength(1);
    expect(await t.run((ctx) => ctx.db.query('edgeTestCredentials').collect())).toEqual([]);
  });

  test('a relay with no bound placement: the rehearsal credential is refused with choose_mode', async () => {
    fakePanel();
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const { relayId } = await registerRelay(t);
    expect(
      await t.action(internal.edgeTestCredentials.ensure, { relayId, purpose: 'rehearsal' }),
    ).toEqual({ ok: false, code: 'choose_mode', credentialId: null });
  });
});
