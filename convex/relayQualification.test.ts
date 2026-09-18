import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { insertPanelServer, realityListener, registerRelay } from './lib/edges/testing/fixtures';
import { __setQualificationRemoverForTests, qualificationUsername } from './relayQualification';

const modules = import.meta.glob('./**/*.*s');

async function seed() {
  const t = convexTest(schema, modules);
  await insertPanelServer(t);
  const { relayId } = await registerRelay(t);
  return { t, relayId };
}

afterEach(() => {
  vi.unstubAllEnvs();
  __setQualificationRemoverForTests(null);
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
    } finally {
      cryptoSpy.mockRestore();
    }
  });
});
