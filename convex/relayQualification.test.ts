import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { fakePanel } from './lib/edges/testing/fakePanel';
import {
  __setEnsureFailpointForTests,
  __setQualificationRemoverForTests,
  MINT_SETTLE_LOOKS,
  MINT_SETTLE_MS,
  qualificationUsername,
} from './relayQualification';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const { relayId } = await registerRelay(t);
  return { t, relayId };
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  __setQualificationRemoverForTests(null);
  __setEnsureFailpointForTests(null);
});

describe('relay qualification credential', () => {
  test('username is slug-derived, bounded and tagged', () => {
    const u = qualificationUsername('Node.One/Very-Long-Relay-Slug-Name', 'abcd1234');
    expect(u.startsWith('fcp-qualify-node-one-very-long-r')).toBe(true);
    expect(u.endsWith('-abcd1234')).toBe(true);
    expect(u).toMatch(/^[a-z0-9-]+$/);
  });

  test('mintContext: the relay’s panel + the placement of its qualificationModeSlug; a manual origin has nothing to mint on', async () => {
    const { t, relayId } = await seed();
    const c = (await t.query(internal.relayQualification.mintContext, { relayId }))!;
    expect(c).toMatchObject({
      slug: 'node-one',
      backend: 'remnawave',
      previousBackendUserId: null,
      pendingRemovals: [],
    });
    expect(c.backendServerId).toBeDefined();
    // An unknown mode slug falls back to the panel's default placement (fail-soft), never a throw.
    await t.run((ctx) => ctx.db.patch(relayId, { qualificationModeSlug: 'no-such-mode' }));
    expect(await t.query(internal.relayQualification.mintContext, { relayId })).toMatchObject({
      slug: 'node-one',
    });
    // The admin projection exposes the slug (nullable), never the credential.
    expect((await t.query(internal.relays.listForAdmin, {}))[0]).toMatchObject({
      qualificationModeSlug: 'no-such-mode',
      qualificationCredential: false,
    });
    // A manual origin: no panel, so no context and mint refuses.
    const { relayId: manual } = await registerRelay(t, {
      slug: 'hand-made',
      kind: 'manual',
      originAddress: '203.0.113.77',
      listeners: [{ ...realityListener(), panelBinding: undefined }],
    });
    expect(await t.query(internal.relayQualification.mintContext, { relayId: manual })).toBeNull();
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    await expect(t.action(internal.relayQualification.mint, { relayId: manual })).rejects.toThrow(
      /not_found/,
    );
  });

  test('mint stores only the protocol uuid + panel user id; revoke clears and deactivates', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    const r = await t.action(internal.relayQualification.mint, { relayId });
    expect(r).toMatchObject({ ok: true, pendingRemovals: 0 });
    const row = await t.run((ctx) => ctx.db.get(relayId));
    expect(row?.qualificationUserId).toMatch(/^[0-9a-f-]{36}$/);
    expect(row?.qualificationBackendUserId).toMatch(/^mock-/);
    const admin = await t.query(internal.relays.get, { id: relayId });
    expect(admin?.qualificationUserId).toBeDefined();
    // Re-minting replaces the credential (the previous account is removed).
    const before = row?.qualificationUserId;
    await t.action(internal.relayQualification.mint, { relayId });
    const row2 = await t.run((ctx) => ctx.db.get(relayId));
    expect(row2?.qualificationUserId).not.toBe(before);
    await t.action(internal.relayQualification.revoke, { relayId });
    const row3 = await t.run((ctx) => ctx.db.get(relayId));
    expect(row3?.qualificationUserId).toBeUndefined();
    expect(row3?.qualificationBackendUserId).toBeUndefined();
    expect(row3?.qualificationMint).toBeUndefined();
    // Audit rows carry booleans only, never the credential.
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .collect()
        .then((rows) => rows.filter((a) => a.action === 'relay.qualification_credential')),
    );
    expect(audits.length).toBe(3);
    for (const a of audits) {
      const blob = JSON.stringify(a.payload);
      expect(blob).not.toContain(before ?? 'never');
      expect(blob).not.toContain('mock-');
    }
  });

  test('a failed panel deactivation is OWED and retried, never orphaned', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    await t.action(internal.relayQualification.mint, { relayId });
    const first = (await t.run((ctx) => ctx.db.get(relayId)))!.qualificationBackendUserId!;
    // The panel is unreachable while the credential is replaced: the old account
    // must stay recorded as owed rather than vanish with its only identifier.
    __setQualificationRemoverForTests(async () => false);
    const r = await t.action(internal.relayQualification.mint, { relayId });
    expect(r).toMatchObject({ ok: true, pendingRemovals: 1 });
    let row = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(row.qualificationRemovalPending).toEqual([first]);
    expect(row.qualificationBackendUserId).not.toBe(first);
    // Revoke while the panel is still down: the credential is kept (the
    // operator sees it is still minted) and the failure is reported.
    expect(await t.action(internal.relayQualification.revoke, { relayId })).toMatchObject({
      ok: false,
      code: 'backend_delete_failed',
    });
    row = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(row.qualificationUserId).toBeDefined();
    // The panel is back: the owed removal and the current account both go.
    const removed: string[] = [];
    __setQualificationRemoverForTests(async (_b, id) => {
      removed.push(id);
      return true;
    });
    expect(await t.action(internal.relayQualification.revoke, { relayId })).toMatchObject({
      ok: true,
      pendingRemovals: 0,
    });
    row = (await t.run((ctx) => ctx.db.get(relayId)))!;
    expect(row.qualificationUserId).toBeUndefined();
    expect(row.qualificationRemovalPending).toBeUndefined();
    expect(removed).toContain(first);
  });

  test('deleting the relay schedules every owed deactivation, not only the current one', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    await t.action(internal.relayQualification.mint, { relayId });
    await t.mutation(internal.relayQualification.setPendingRemovals, {
      relayId,
      pending: ['mock-owed-1', 'mock-owed-2'],
    });
    await t.mutation(internal.relays.requestDelete, {
      id: relayId,
      force: true,
      disposition: 'restore-direct',
    });
    const r = await t.mutation(internal.relays.finalizeDelete, { id: relayId });
    expect(r.removed).toBe(true);
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const removals = scheduled.filter((s) => /removeBackendUser/.test(s.name));
    expect(
      removals.map((s) => (s.args[0] as { backendUserId: string }).backendUserId).sort(),
      JSON.stringify(scheduled.map((s) => s.name)),
    ).toHaveLength(3);
  });

  test('a backend that mints no protocol credential keeps no account and reports a code', async () => {
    vi.stubEnv('DEV_MOCK_BACKEND', 'true');
    vi.stubEnv('ENVIRONMENT', 'development');
    const { t, relayId } = await seed();
    const cryptoSpy = vi.spyOn(crypto, 'randomUUID').mockImplementation(() => '' as never);
    try {
      const r = await t.action(internal.relayQualification.mint, { relayId });
      expect(r).toMatchObject({ ok: false, code: 'qualification_credential_unsupported' });
      const row = await t.run((ctx) => ctx.db.get(relayId));
      expect(row?.qualificationUserId).toBeUndefined();
      expect(row?.qualificationMint).toBeUndefined();
    } finally {
      cryptoSpy.mockRestore();
    }
  });
});

// --- the persisted mint operation (docs/edges.md § "Publication"; acceptance 8) ------------------

async function seedWithPanel() {
  const panel = fakePanel();
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const { relayId } = await registerRelay(t);
  const relay = () => t.run((ctx) => ctx.db.get(relayId)).then((r) => r!);
  const createCalls = () =>
    panel.calls.filter((c) => c.method === 'POST' && c.path === '/api/users');
  return { t, relayId, panel, relay, createCalls };
}

describe('relayQualification.ensure: the persisted mint operation', () => {
  test('a crash after issueUser and before store: the retry re-finds the user by name and ADOPTS it (no second user)', async () => {
    const { t, relayId, panel, relay, createCalls } = await seedWithPanel();
    __setEnsureFailpointForTests((point) => {
      if (point === 'after_issue') throw new Error('killed between issue and store');
    });
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).rejects.toThrow(/killed/);
    let row = await relay();
    // The intent (with the username) landed BEFORE the panel call; the user exists on the panel.
    expect(row.qualificationMint).toMatchObject({ state: 'intended', placement: 'sq-a' });
    expect(row.qualificationUserId).toBeUndefined();
    expect(panel.users.size).toBe(1);
    expect(panel.users.has(row.qualificationMint!.username)).toBe(true);

    __setEnsureFailpointForTests(null);
    const r = await t.action(internal.relayQualification.ensure, {
      relayId,
      placement: 'sq-a',
      purpose: 'qualification',
    });
    expect(r).toMatchObject({ ok: true, reused: false, adopted: true });
    row = await relay();
    const user = panel.users.get(row.qualificationMint!.username)!;
    expect(row.qualificationMint?.state).toBe('stored');
    expect(row.qualificationUserId).toBe(user.vlessUuid);
    expect(row.qualificationSubscription?.backendShortId).toBe(user.shortUuid);
    expect(createCalls()).toHaveLength(1); // no second create
    expect(panel.users.size).toBe(1);
    expect(panel.deleted).toEqual([]);

    // The same binding again: reused without a panel call.
    const before = panel.calls.length;
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).toMatchObject({ ok: true, reused: true });
    expect(panel.calls.length).toBe(before);
    // Audit: booleans only; the adoption is recorded.
    const audits = await t.run((ctx) =>
      ctx.db
        .query('auditLog')
        .collect()
        .then((rows) => rows.filter((a) => a.action === 'relay.qualification_credential')),
    );
    expect(audits.map((a) => (a.payload as { adopted?: boolean }).adopted)).toEqual([true]);
  });

  test('a crash after the issued mark takes the same adoption path', async () => {
    const { t, relayId, panel, relay, createCalls } = await seedWithPanel();
    __setEnsureFailpointForTests((point) => {
      if (point === 'after_issued') throw new Error('killed after issued');
    });
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'rehearsal',
      }),
    ).rejects.toThrow(/killed/);
    expect((await relay()).qualificationMint?.state).toBe('issued');
    __setEnsureFailpointForTests(null);
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'rehearsal',
      }),
    ).toMatchObject({ ok: true, adopted: true });
    expect(createCalls()).toHaveLength(1);
    expect(panel.users.size).toBe(1);
  });

  test('a stored credential with a DIFFERENT placement (after choose_mode) is replaced and the old user removed', async () => {
    const { t, relayId, panel, relay } = await seedWithPanel();
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'rehearsal',
      }),
    ).toMatchObject({ ok: true, reused: false });
    const first = (await relay()).qualificationBackendUserId!;
    const r = await t.action(internal.relayQualification.ensure, {
      relayId,
      placement: 'sq-b',
      purpose: 'rehearsal',
    });
    expect(r).toMatchObject({ ok: true, reused: false, pendingRemovals: 0 });
    const row = await relay();
    expect(row.qualificationMint).toMatchObject({ state: 'stored', placement: 'sq-b' });
    expect(row.qualificationBackendUserId).not.toBe(first);
    expect(panel.deleted).toEqual([first]);
    expect(panel.users.size).toBe(1);
    // A different mode slug with the same placement is a different binding too.
    const r2 = await t.action(internal.relayQualification.ensure, {
      relayId,
      placement: 'sq-b',
      modeSlug: 'freedom-ws',
      purpose: 'rehearsal',
    });
    expect(r2).toMatchObject({ ok: true, reused: false });
    expect(panel.users.size).toBe(1);
    expect(panel.deleted).toHaveLength(2);
  });

  test('a pending operation whose user is NOT on the panel waits for the settle rule, then issues under a new name', async () => {
    const { t, relayId, panel, relay, createCalls } = await seedWithPanel();
    __setEnsureFailpointForTests((point) => {
      if (point === 'after_claim') throw new Error('killed before the create');
    });
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).rejects.toThrow(/killed/);
    __setEnsureFailpointForTests(null);
    const op = (await relay()).qualificationMint!;
    expect(op.state).toBe('intended');
    expect(panel.users.size).toBe(0);
    // Quiet looks alone are not enough while the settle floor has not passed.
    for (let i = 1; i <= MINT_SETTLE_LOOKS; i++) {
      expect(
        await t.action(internal.relayQualification.ensure, {
          relayId,
          placement: 'sq-a',
          purpose: 'qualification',
        }),
      ).toMatchObject({ ok: false, code: 'credential_unresolved' });
      expect((await relay()).qualificationMint).toMatchObject({ state: 'unresolved', looks: i });
    }
    expect(createCalls()).toHaveLength(0);
    // The floor passed: a fresh operation under a NEW username; the old name is never reused.
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        qualificationMint: {
          ...op,
          state: 'unresolved',
          looks: MINT_SETTLE_LOOKS,
          claimedAt: op.claimedAt - MINT_SETTLE_MS - 1,
        },
      }),
    );
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).toMatchObject({ ok: true, reused: false });
    const row = await relay();
    expect(row.qualificationMint?.state).toBe('stored');
    expect(row.qualificationMint?.username).not.toBe(op.username);
    expect(createCalls()).toHaveLength(1);
  });

  test('a definitive create failure drops the claim; an ambiguous one leaves it unresolved', async () => {
    const { t, relayId, panel, relay } = await seedWithPanel();
    panel.failCreateWith = 400;
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).rejects.toThrow();
    expect((await relay()).qualificationMint).toBeUndefined();
    panel.failCreateWith = 500;
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).rejects.toThrow();
    expect((await relay()).qualificationMint?.state).toBe('unresolved');
  });

  test('refusals: a rehearsal with no usable placement -> choose_mode; Outline -> use_manual_setup / unsupported, nothing minted', async () => {
    const { t, relayId } = await seedWithPanel();
    expect(
      await t.action(internal.relayQualification.ensure, { relayId, purpose: 'rehearsal' }),
    ).toMatchObject({ ok: false, code: 'choose_mode' });
    // Outline: no name lookup, so the operation could never be settled: refused before any call.
    await insertPanelServer(t, { slug: 'outline-a', backend: 'outline' });
    const { relayId: outlineRelay } = await registerRelay(t, {
      slug: 'outline-one',
      kind: 'backend-server',
      backendSlug: 'outline-a',
      originAddress: '203.0.113.77',
      listeners: [{ ...realityListener(), panelBinding: undefined }],
    });
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId: outlineRelay,
        purpose: 'rehearsal',
      }),
    ).toMatchObject({ ok: false, code: 'use_manual_setup' });
    expect(
      await t.action(internal.relayQualification.ensure, {
        relayId: outlineRelay,
        purpose: 'qualification',
      }),
    ).toMatchObject({ ok: false, code: 'qualification_credential_unsupported' });
    expect((await t.run((ctx) => ctx.db.get(outlineRelay)))?.qualificationMint).toBeUndefined();
  });

  test('deleting a relay with an unsettled operation schedules the by-username removal', async () => {
    const { t, relayId, panel } = await seedWithPanel();
    __setEnsureFailpointForTests((point) => {
      if (point === 'after_issue') throw new Error('killed');
    });
    await expect(
      t.action(internal.relayQualification.ensure, {
        relayId,
        placement: 'sq-a',
        purpose: 'qualification',
      }),
    ).rejects.toThrow();
    __setEnsureFailpointForTests(null);
    await t.mutation(internal.relays.requestDelete, {
      id: relayId,
      force: true,
      disposition: 'restore-direct',
    });
    expect((await t.mutation(internal.relays.finalizeDelete, { id: relayId })).removed).toBe(true);
    const scheduled = await t.run((ctx) => ctx.db.system.query('_scheduled_functions').collect());
    const byName = scheduled.filter((s) => /removeByUsername/.test(s.name));
    expect(byName).toHaveLength(1);
    expect((byName[0].args[0] as { username: string }).username).toBe(panel.created[0]);
    // The removal itself re-finds the user by name and deletes it.
    await t.action(internal.relayQualification.removeByUsername, byName[0].args[0] as never);
    expect(panel.users.size).toBe(0);
  });
});
