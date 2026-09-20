/// <reference types="vite/client" />
/**
 * Endpoint verification and the shared publication gate (docs/edges.md
 * § "Publication"): an L4 edge goes live only with the operator's CURRENT
 * per-endpoint confirmation, wherever the publish comes from; a replace never
 * provisions a doomed L4 candidate; the attention list raises the three
 * verification cards; account trust follows the first confirmed endpoint of
 * an untrusted L4 account, and the L7 auto-trust rule binds to the proof.
 */
import { convexTest } from 'convex-test';
import { afterEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { upsertSettingRow } from './appSettings';
import { resolveTemplateFor } from './edgeTemplates';
import { qualificationBinding } from './lib/edges/frontCheck/binding';
import {
  adoptL4Edge,
  createAccount,
  insertPanelServer,
  realityListener,
  registerRelay,
  seedEdgeFixture,
  verifyL4Edge,
  wsListener,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');

afterEach(() => vi.unstubAllGlobals());

const PUBLISHED = '198.51.100.1';
const SPARE = '198.51.100.2';

/** backend + gcore account (tested, trusted) + origin with one REALITY listener + a published, confirmed edge. */
async function seed(opts: { qualified?: boolean } = {}) {
  const t = convexTest(schema, modules);
  const fx = await seedEdgeFixture(t, { qualified: opts.qualified ?? true });
  await t.mutation(internal.edgeProviderAccounts.recordTest, { id: fx.accountId, ok: true });
  const published = await adoptL4Edge(t, fx.relayId, fx.listenerId, {
    ipv4: PUBLISHED,
    publish: true,
    accountId: fx.accountId,
  });
  return { ...fx, publishedEdgeId: published.edgeId as Id<'edges'> };
}

async function attentionKinds(t: ReturnType<typeof convexTest>) {
  const { items } = await t.query(internal.edgeOperator.attention, {});
  return items;
}

describe('the publication gate', () => {
  test('an untested L4 spare is refused by every publish path; a confirmed one passes', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    // Direct publish.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 }),
    ).rejects.toThrow(/unverified_endpoint/);
    // Publish rotation start.
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'publish',
        trigger: 'manual',
        toEdgeId: spare,
      }),
    ).rejects.toThrow(/unverified_endpoint/);
    // Reconcile upkeep: skipped, and reported so the cron does not provision another.
    expect(
      await t.mutation(internal.edgeReconcileMutations.publishStandby, {
        relayId,
        candidates: [spare],
      }),
    ).toEqual({ published: false, rotationId: null, awaitingVerification: true });
    // Adopt-and-publish without the operator's statement.
    await expect(
      adoptL4Edge(t, relayId, listenerId, { ipv4: '198.51.100.3', publish: true, verified: false }),
    ).rejects.toThrow(/unverified_endpoint/);
    // Preflight names the same code.
    const pre = await t.query(internal.edgeOperator.preflight, {
      relayId,
      kind: 'publish',
      edgeId: spare,
    });
    expect(pre.blockers.map((b) => b.code)).toContain('unverified_endpoint');
    // The tick: what was shown is what is confirmed.
    const binding = (await t.query(internal.edgeVerification.binding, { edgeId: spare }))!;
    expect(binding).toMatchObject({
      endpoint: `${SPARE}:443`,
      listenerKey: 'a',
      publishableAfter: true,
      blocker: null,
      verification: { required: true, current: false, stale: false, record: null },
    });
    const res = await t.mutation(internal.edgeVerification.confirm, {
      edgeId: spare,
      endpoint: binding.endpoint,
      listenerRevision: binding.listenerRevision,
      configHash: binding.configHash,
      method: 'test_link',
    });
    expect(res.ok).toBe(true);
    const row = (await t.query(internal.edges.get, { id: spare }))!;
    expect(row.verification).toMatchObject({
      rung: 'verified',
      by: 'admin',
      method: 'test_link',
      listenerKey: 'a',
      listenerRevision: binding.listenerRevision,
      configHash: binding.configHash,
    });
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const verified = audit.find((a) => a.action === 'edge.verified');
    expect(verified?.payload).toEqual({
      relaySlug: 'node-one',
      edgeId: spare,
      listenerKey: 'a',
      method: 'test_link',
    });
    expect(JSON.stringify(audit)).not.toContain(SPARE);
    // Now the direct publish passes (index 1 behind the template: no Host flip).
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 });
    expect((await t.query(internal.relays.get, { id: relayId }))!.publishedEdgeIds[1]).toBe(spare);
  });

  test('an L7 edge is verified by its proof: the confirm route refuses it (l7_proof_required)', async () => {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const accountId = await createAccount(t, { provider: 'cloudflare', name: 'acct-cf' });
    const { relayId, listenerId } = await registerRelay(t, { listeners: [wsListener()] });
    const { edgeId } = await t.mutation(internal.relays.adoptEdge, {
      relayId,
      listenerId,
      hostname: 'front.example',
      accountId,
    });
    await expect(
      t.mutation(internal.edgeVerification.confirm, {
        edgeId: edgeId as Id<'edges'>,
        endpoint: 'front.example:443',
        listenerRevision: 1,
        configHash: 'x',
        method: 'test_link',
      }),
    ).rejects.toThrow(/l7_proof_required/);
    const admin = await t.query(internal.edgeAdmin.edgeDetail, { edgeId: edgeId as Id<'edges'> });
    expect(admin?.edge.verification).toMatchObject({ required: false, current: true });
  });
});

describe('case 23: blocked primary, trusted account, untested spare', () => {
  test('the detector replace is refused (no_verified_spare), attention says needs_test, nothing is published; after the tick the same replace starts', async () => {
    const { t, relayId, listenerId, accountId, publishedEdgeId } = await seed();
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.autoRotate', 'true');
      await ctx.db.patch(relayId, { autoRotate: true });
    });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    // A spare the selection would take: provider health satisfied (the same
    // rule `pickStandby` applies), so ONLY the missing tick stands in the way.
    await t.run((ctx) => ctx.db.patch(spare, { health: 'online' }));
    const replace = () =>
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'detector',
        burn: true,
        targetEdgeId: publishedEdgeId,
      });
    await expect(replace()).rejects.toThrow(/no_verified_spare/);
    // The same refusal, as the preflight reports it, and NOT waived by force.
    const pre = await t.query(internal.edgeOperator.preflight, {
      relayId,
      kind: 'replace',
      edgeId: publishedEdgeId,
      trigger: 'detector',
    });
    expect(pre.blockers.map((b) => b.code)).toContain('no_verified_spare');
    await expect(
      t.mutation(internal.edgeRotations.start, {
        relayId,
        kind: 'replace',
        trigger: 'manual',
        targetEdgeId: publishedEdgeId,
        force: true,
      }),
    ).rejects.toThrow(/no_verified_spare/);
    // The detector records the refusal on the origin's suspicion (its own test
    // pins that `lastRotateError` takes the thrown code); attention then raises
    // needs_test pointing at the untested spare.
    await t.run((ctx) =>
      ctx.db.patch(relayId, {
        suspicion: {
          state: 'suspected',
          hintLevel: 'probes',
          score: 0.9,
          reportScore: 0,
          loadScore: 0,
          probeScore: 0.9,
          scope: 'global',
          countries: [{ code: 'IR', count: 3 }],
          edgeEvidence: [{ edgeId: publishedEdgeId, source: 'probes', countries: ['IR'] }],
          firstSeenAt: Date.now() - 60_000,
          lastEvalAt: Date.now(),
          quietEvals: 0,
          baselineWarm: true,
          veto: null,
          lastRotateError: 'edge.no_verified_spare',
        },
      }),
    );
    const items = await attentionKinds(t);
    expect(items.find((i) => i.kind === 'needs_test')).toMatchObject({
      severity: 'critical',
      relaySlug: 'node-one',
      edgeId: spare,
      listenerKey: 'a',
      code: 'no_verified_spare',
      action: 'verify_endpoint',
    });
    expect(items.find((i) => i.kind === 'spare_untested')).toMatchObject({
      edgeId: spare,
      action: 'verify_endpoint',
    });
    // Nothing moved.
    const before = (await t.query(internal.relays.get, { id: relayId }))!;
    expect(before.publishedEdgeIds).toEqual([publishedEdgeId]);
    expect(before.activeRotationId).toBeUndefined();
    // The tick, then the very same replace starts (and switches to the spare).
    await verifyL4Edge(t, spare);
    const after = await attentionKinds(t);
    expect(after.some((i) => i.kind === 'spare_untested')).toBe(false);
    expect(after.some((i) => i.kind === 'needs_test')).toBe(true); // the stale refusal is still recorded
    const { rotationId } = await replace();
    const rot = (await t.query(internal.edgeRotations.get, { id: rotationId }))!;
    expect(rot).toMatchObject({ kind: 'replace', trigger: 'detector', phase: 'select' });
    await t.mutation(internal.edgeRotations.requestCancel, { rotationId });
  });
});

describe('case 24: configuration-bound evidence', () => {
  test('a listener revision bump after the tick makes the verification stale: retest_needed, publish refused, a stale echo refused', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    const shown = (await t.query(internal.edgeVerification.binding, { edgeId: spare }))!;
    await verifyL4Edge(t, spare);
    expect(
      (await t.query(internal.edgeAdmin.edgeDetail, { edgeId: spare }))!.edge.verification,
    ).toMatchObject({ current: true, stale: false });
    // A material listener change while the operator was away.
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: false });
    await t.mutation(internal.relayListeners.setEnabled, { id: listenerId, enabled: true });
    const listener = (await t.run((ctx) => ctx.db.get(listenerId)))!;
    expect(listener.revision).toBe(shown.listenerRevision + 2);
    // The endpoint is back to "needs a test".
    expect(
      (await t.query(internal.edgeAdmin.edgeDetail, { edgeId: spare }))!.edge.verification,
    ).toMatchObject({ current: false, stale: true, record: { rung: 'verified' } });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 }),
    ).rejects.toThrow(/unverified_endpoint/);
    const items = await attentionKinds(t);
    expect(items.find((i) => i.kind === 'retest_needed' && i.edgeId === spare)).toMatchObject({
      listenerKey: 'a',
      code: 'verification_stale',
      action: 'verify_endpoint',
      facts: { verifiedRevision: shown.listenerRevision, listenerRevision: listener.revision },
    });
    // The PUBLISHED endpoint of the same listener went stale too: one card each.
    expect(items.filter((i) => i.kind === 'retest_needed')).toHaveLength(2);
    expect(items.some((i) => i.kind === 'spare_untested' && i.edgeId === spare)).toBe(false);
    // Echoing the binding the operator saw BEFORE the change is refused, never stamped.
    await expect(
      t.mutation(internal.edgeVerification.confirm, {
        edgeId: spare,
        endpoint: shown.endpoint,
        listenerRevision: shown.listenerRevision,
        configHash: shown.configHash,
        method: 'test_link',
      }),
    ).rejects.toThrow(/verification_stale/);
    expect((await t.query(internal.edges.get, { id: spare }))!.verification?.listenerRevision).toBe(
      shown.listenerRevision,
    );
    // A fresh binding + tick restores it.
    await verifyL4Edge(t, spare);
    expect(
      (await t.query(internal.edgeAdmin.edgeDetail, { edgeId: spare }))!.edge.verification,
    ).toMatchObject({ current: true, stale: false });
    await t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 });
  });

  test('a re-addressed edge is stale too (the hash covers addresses and ports)', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    await verifyL4Edge(t, spare);
    await t.run((ctx) => ctx.db.patch(spare, { addresses: { v4: '198.51.100.9' } }));
    expect(
      (await t.query(internal.edgeAdmin.edgeDetail, { edgeId: spare }))!.edge.verification,
    ).toMatchObject({ current: false, stale: true });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 }),
    ).rejects.toThrow(/unverified_endpoint/);
  });
});

describe('the verification binding', () => {
  test('publishableAfter reports the remaining blocker of an unverified AND unhealthy edge', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    // A managed edge the provider reports offline (the health gate is on by default).
    await t.run((ctx) => ctx.db.patch(spare, { managed: true, health: 'offline' }));
    const binding = (await t.query(internal.edgeVerification.binding, { edgeId: spare }))!;
    expect(binding).toMatchObject({
      publishableAfter: false,
      blocker: 'edge_unhealthy',
      verification: { current: false },
    });
    // The tick is still recorded; the publish is then refused for the OTHER reason.
    await verifyL4Edge(t, spare);
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 }),
    ).rejects.toThrow(/edge_unhealthy/);
    await t.run((ctx) => ctx.db.patch(spare, { health: 'online' }));
    expect(await t.query(internal.edgeVerification.binding, { edgeId: spare })).toMatchObject({
      publishableAfter: true,
      blocker: null,
      verification: { current: true },
    });
  });
});

describe('account trust', () => {
  /** The hash of the template the fixture's account provisions with NOW. */
  const effectiveHash = (t: ReturnType<typeof convexTest>, accountId: Id<'edgeProviderAccounts'>) =>
    t.run(async (ctx) => (await resolveTemplateFor(ctx, 'gcore', null, null, accountId)).hash);

  test('the first confirmed endpoint of an untrusted L4 account trusts it with endpoint evidence; a trusted account never exempts a new endpoint', async () => {
    const { t, relayId, listenerId, accountId } = await seed({ qualified: false });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    // Provisioned with the account's effective template (what a rotation stamps).
    const hash = await effectiveHash(t, accountId);
    await t.run((ctx) => ctx.db.patch(spare, { templateHash: hash }));
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualified).toBe(false);
    const res = await verifyL4Edge(t, spare);
    expect(res).toMatchObject({ accountTrusted: true, accountTrustReason: null });
    const account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account.qualified).toBe(true);
    expect(account.qualification).toMatchObject({
      by: 'admin',
      evidence: { edgeId: spare, endpoint: `${SPARE}:443`, listenerId },
    });
    expect(account.qualifiedTemplateHash).toBe(hash);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.provider_account.qualified')?.payload).toEqual({
      name: 'acct-a',
      provider: 'gcore',
      qualified: true,
      edgeId: spare,
      endpointEvidence: true,
    });
    // A NEW endpoint of the now-trusted account still needs its own tick.
    const next = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.3',
      accountId,
      verified: false,
    });
    await expect(
      t.mutation(internal.relays.publishEdge, {
        relayId,
        edgeId: next.edgeId as Id<'edges'>,
        poolIndex: 1,
      }),
    ).rejects.toThrow(/unverified_endpoint/);
    expect(await verifyL4Edge(t, next.edgeId as Id<'edges'>)).toMatchObject({
      accountTrusted: false,
      accountTrustReason: 'already_qualified',
    });
  });

  test('an endpoint is account evidence only for the account as it is NOW: an adopted (template-less) edge, a stale credential test or a moved template verify the endpoint but leave the account untrusted', async () => {
    const { t, relayId, listenerId, accountId } = await seed({ qualified: false });
    // An import with no template hash proves its own endpoint only.
    const adopted = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    expect(await verifyL4Edge(t, adopted.edgeId as Id<'edges'>)).toMatchObject({
      accountTrusted: false,
      accountTrustReason: 'template_mismatch',
    });
    expect(
      (await t.query(internal.edges.get, { id: adopted.edgeId as Id<'edges'> }))!.verification
        ?.rung,
    ).toBe('verified');
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualified).toBe(false);
    // A template-matching edge, but the credentials changed AFTER the last test.
    const next = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: '198.51.100.3',
      accountId,
      verified: false,
    });
    const edge = next.edgeId as Id<'edges'>;
    const hash = await effectiveHash(t, accountId);
    await t.run((ctx) => ctx.db.patch(edge, { templateHash: hash }));
    await t.run(async (ctx) => {
      const acct = (await ctx.db.get(accountId))!;
      await ctx.db.patch(accountId, { credentialsChangedAt: acct.lastTestOkAt! + 1 });
    });
    expect(await verifyL4Edge(t, edge)).toMatchObject({
      accountTrusted: false,
      accountTrustReason: 'tested_before_credential_change',
    });
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualified).toBe(false);
    // A passing test after the change, then a retest of the endpoint (the record
    // is re-stamped; the binding is unchanged) trusts the account.
    await t.run(async (ctx) => {
      const acct = (await ctx.db.get(accountId))!;
      await ctx.db.patch(accountId, { lastTestOkAt: acct.credentialsChangedAt! + 1 });
    });
    expect(await verifyL4Edge(t, edge)).toMatchObject({ accountTrusted: true });
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualification).toMatchObject({
      by: 'admin',
      evidence: { edgeId: edge },
    });
  });

  test('a manual untrust holds automatic trust off; a manual trust records by:admin without evidence and clears the hold', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: accountId,
      qualified: false,
    });
    let account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account).toMatchObject({ qualified: false, autoQualifyHold: true });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, {
      ipv4: SPARE,
      accountId,
      verified: false,
    });
    expect((await verifyL4Edge(t, edgeId as Id<'edges'>)).accountTrusted).toBe(false);
    account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account.qualified).toBe(false);
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: accountId,
      qualified: true,
    });
    account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account.qualified).toBe(true);
    expect(account.autoQualifyHold).toBeUndefined();
    expect(account.qualification).toMatchObject({ by: 'admin' });
    expect(account.qualification?.evidence).toBeUndefined();
    const view = await t.query(internal.edgeProviderAccounts.getForAdmin, { id: accountId });
    expect(view).toMatchObject({ qualified: true, autoQualifyHold: false });
    expect(view?.qualification).toMatchObject({ by: 'admin', edgeId: null });
  });
});

describe('L7 auto-trust (cases 7 and 13)', () => {
  async function l7World() {
    const t = convexTest(schema, modules);
    await insertPanelServer(t);
    const accountId = await createAccount(t, { provider: 'cloudflare', name: 'acct-cf' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
    const { relayId, listenerId } = await registerRelay(t, { listeners: [wsListener()] });
    const template = await t.run((ctx) =>
      resolveTemplateFor(ctx, 'cloudflare', null, null, accountId),
    );
    /** An active L7 edge of the account carrying a proof for `templateHash` against the listener's current revision. */
    const provenEdge = async (
      templateHash: string,
      opts: { ok?: boolean; expired?: boolean } = {},
    ) =>
      t.run(async (ctx) => {
        const listener = (await ctx.db.get(listenerId))!;
        const intent = {
          hostname: 'front.example',
          zoneId: 'z'.repeat(32),
          zoneName: 'example.org',
          originTransport: listener.originTransport!,
          originPort: listener.originPort,
          zoneSslMode: 'full',
          templateHash,
          templateParams: {},
        };
        const now = Date.now();
        return ctx.db.insert('edges', {
          relayId,
          listenerId,
          accountId,
          provider: 'cloudflare',
          templateHash,
          managed: true,
          name: `fcp-relay-${now.toString(36)}`,
          steps: [],
          resources: [],
          listeners: [{ edgePort: 443, originAddress: '203.0.113.10', originPort: 443 }],
          addresses: { hostname: 'front.example' },
          layer: 'l7',
          provisionIntent: JSON.stringify(intent),
          frontQualification: {
            ok: opts.ok ?? true,
            checkedAt: now - 1000,
            expiresAt: opts.expired ? now - 1 : now + 3_600_000,
            binding: {
              ...qualificationBinding({
                listener,
                intent,
                params: listener.transportParams ?? {},
              }),
              listenerId,
            },
          },
          publication: 'unpublished',
          status: 'active',
          statusChangedAt: now,
          health: 'unknown',
          destroyAttempts: 0,
          updatedAt: now,
        });
      });
    return { t, accountId, relayId, listenerId, template, provenEdge };
  }

  test('a current proof on a template-matching edge trusts the account (by:auto, evidence bound to the proof + template hash)', async () => {
    const { t, accountId, template, provenEdge } = await l7World();
    const edgeId = await provenEdge(template.hash);
    const r = await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, {
      accountId,
    });
    expect(r).toEqual({ qualified: true, code: null });
    const account = (await t.run((ctx) => ctx.db.get(accountId)))!;
    expect(account.qualified).toBe(true);
    expect(account.qualifiedTemplateHash).toBe(template.hash);
    expect(account.qualification).toMatchObject({
      by: 'auto',
      evidence: { edgeId, endpoint: 'front.example:443', templateHash: template.hash },
    });
    expect(account.qualification?.evidence?.proofCheckedAt).toBeDefined();
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(
      audit.find((a) => a.action === 'edge.provider_account.auto_qualified')?.payload,
    ).toMatchObject({ name: 'acct-cf', provider: 'cloudflare', qualified: true, edgeId });
    expect(JSON.stringify(audit)).not.toContain('front.example');
    // Idempotent: a second evaluation changes nothing.
    expect(
      await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, { accountId }),
    ).toEqual({ qualified: true, code: 'already_qualified' });
  });

  test('case 7: a template change after the proof is an evidence mismatch; an expired or failed proof is no proof', async () => {
    const { t, accountId, provenEdge } = await l7World();
    await provenEdge('some-other-template');
    expect(
      await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, { accountId }),
    ).toEqual({ qualified: false, code: 'template_mismatch' });
    const { template } = await l7World();
    const w = await l7World();
    await w.provenEdge(w.template.hash, { expired: true });
    expect(
      await w.t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, {
        accountId: w.accountId,
      }),
    ).toEqual({ qualified: false, code: 'no_current_proof' });
    void template;
  });

  test('the hold and a stale test refuse; the reconcile sweep evaluates only unheld, unqualified L7 accounts', async () => {
    const { t, accountId, template, provenEdge } = await l7World();
    await provenEdge(template.hash);
    // A manual untrust holds it off...
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: accountId,
      qualified: false,
    });
    expect(
      await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, { accountId }),
    ).toEqual({ qualified: false, code: 'hold' });
    expect(await t.mutation(internal.edgeProviderAccounts.reconcileAutoQualification, {})).toEqual({
      evaluated: 0,
      qualified: 0,
    });
    // ...until the credentials change (which also demands a NEW test).
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: accountId,
      credentials: { apiToken: 'cf-2' },
    });
    expect(
      await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, { accountId }),
    ).toEqual({ qualified: false, code: 'tested_before_credential_change' });
    await t.mutation(internal.edgeProviderAccounts.recordTest, { id: accountId, ok: true });
    expect(await t.mutation(internal.edgeProviderAccounts.reconcileAutoQualification, {})).toEqual({
      evaluated: 1,
      qualified: 1,
    });
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualification?.by).toBe('auto');
  });

  test('L4 accounts are never auto-trusted, whatever their edges carry', async () => {
    const { t, relayId, listenerId, accountId } = await seed({ qualified: false });
    const { edgeId } = await adoptL4Edge(t, relayId, listenerId, { ipv4: SPARE, accountId });
    // A confirmed L4 endpoint on the account (the operator's tick), still no auto rule applies.
    expect(
      (await t.query(internal.edges.get, { id: edgeId as Id<'edges'> }))!.verification?.rung,
    ).toBe('verified');
    expect(
      await t.mutation(internal.edgeProviderAccounts.evaluateAutoQualification, { accountId }),
    ).toEqual({ qualified: false, code: 'not_l7' });
    expect(await t.mutation(internal.edgeProviderAccounts.reconcileAutoQualification, {})).toEqual({
      evaluated: 0,
      qualified: 0,
    });
    expect((await t.run((ctx) => ctx.db.get(accountId)))!.qualified).toBe(false);
  });
});

describe('the partial rung (probe evidence)', () => {
  const ok = (country: string, k: number) => ({
    country,
    asn: `AS${k}`,
    network: `net-${k}`,
    vantageClass: 'eyeball' as const,
    ok: true,
  });
  const fail = (country: string, k: number) => ({ ...ok(country, k), ok: false });

  async function world() {
    const w = await seed();
    await w.t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.probe.countries', JSON.stringify(['IR', 'TR']));
    });
    const { edgeId } = await adoptL4Edge(w.t, w.relayId, w.listenerId, {
      ipv4: SPARE,
      accountId: w.accountId,
      verified: false,
    });
    const spare = edgeId as Id<'edges'>;
    /** One probe round on the spare; returns the internal (shape) and globalping runs. */
    const round = async () => {
      const before = new Set(
        (await w.t.run((ctx) => ctx.db.query('probeRuns').collect())).map((r) => r._id),
      );
      await w.t.mutation(internal.probes.requestMany, {
        targets: [{ kind: 'edge', ref: spare }],
        sources: ['internal', 'globalping'],
      });
      const runs = (await w.t.run((ctx) => ctx.db.query('probeRuns').collect())).filter(
        (r) => !before.has(r._id) && r.targetRef === spare,
      );
      return {
        shape: runs.find((r) => r.source === 'internal')!,
        outside: runs.find((r) => r.source === 'globalping')!,
      };
    };
    const record = async () => (await w.t.query(internal.edges.get, { id: spare }))!.verification;
    return { ...w, spare, round, record };
  }

  test('probe evidence writes partial (by system, method probe); it never satisfies the gate; unreachable clears it; a verified record is never touched', async () => {
    const { t, relayId, spare, round, record } = await world();
    const r1 = await round();
    expect(r1.shape.probeProtocol).toBe('tls-sni');
    // The shape check passes but one outside vantage is below the agreement bar: pending.
    await t.mutation(internal.probes.finishRun, {
      runId: r1.shape._id,
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: true }],
    });
    expect(await record()).toBeUndefined();
    await t.mutation(internal.probes.finishRun, {
      runId: r1.outside._id,
      results: [ok('IR', 1)],
    });
    expect(await record()).toBeUndefined();
    // Two reachable vantages + a passing shape run: partial, against the current binding.
    const r2 = await round();
    await t.mutation(internal.probes.finishRun, {
      runId: r2.shape._id,
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: true }],
    });
    await t.mutation(internal.probes.finishRun, {
      runId: r2.outside._id,
      results: [ok('IR', 1), ok('TR', 2)],
    });
    const shown = (await t.query(internal.edgeVerification.binding, { edgeId: spare }))!;
    expect(await record()).toMatchObject({
      rung: 'partial',
      by: 'system',
      method: 'probe',
      listenerKey: 'a',
      listenerRevision: shown.listenerRevision,
      configHash: shown.configHash,
      endpoint: shown.endpoint,
    });
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.find((a) => a.action === 'edge.verification.rung')?.payload).toEqual({
      relaySlug: 'node-one',
      edgeId: spare,
      listenerKey: 'a',
      rung: 'partial',
    });
    expect(JSON.stringify(audit)).not.toContain(SPARE);
    // The ceiling: partial is not verified, for the gate, the binding view or attention.
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId, edgeId: spare, poolIndex: 1 }),
    ).rejects.toThrow(/unverified_endpoint/);
    expect(shown.verification).toMatchObject({ current: false, stale: false });
    expect(
      (await t.query(internal.edgeVerification.binding, { edgeId: spare }))!.verification,
    ).toMatchObject({ current: false, stale: false, record: { rung: 'partial', by: 'system' } });
    const items = await attentionKinds(t);
    expect(items.find((i) => i.kind === 'spare_untested' && i.edgeId === spare)).toBeTruthy();
    expect(items.some((i) => i.kind === 'retest_needed' && i.edgeId === spare)).toBe(false);
    // An agreed outside `unreachable` clears the partial record.
    const r3 = await round();
    await t.mutation(internal.probes.finishRun, {
      runId: r3.outside._id,
      results: [fail('IR', 1), fail('IR', 3)],
    });
    expect(await record()).toBeUndefined();
    expect(
      (await t.run((ctx) => ctx.db.query('auditLog').collect()))
        .filter((a) => a.action === 'edge.verification.rung')
        .map((a) => (a.payload as { rung: string }).rung),
    ).toEqual(['partial', 'unreachable']);
    // The operator's tick outranks the probes: a verified record is never touched.
    await verifyL4Edge(t, spare);
    const r4 = await round();
    await t.mutation(internal.probes.finishRun, {
      runId: r4.outside._id,
      results: [fail('IR', 1), fail('IR', 3)],
    });
    expect(await record()).toMatchObject({ rung: 'verified', by: 'admin' });
  });

  test('the reconcile pass clears a partial record the live configuration no longer matches (re-addressed, never probed since)', async () => {
    const { t, spare, round, record } = await world();
    const r = await round();
    await t.mutation(internal.probes.finishRun, {
      runId: r.shape._id,
      results: [{ country: 'XX', vantageClass: 'datacenter', ok: true }],
    });
    await t.mutation(internal.probes.finishRun, {
      runId: r.outside._id,
      results: [ok('IR', 1), ok('TR', 2)],
    });
    expect(await record()).toMatchObject({ rung: 'partial' });
    // Nothing to do while the binding matches.
    expect(await t.mutation(internal.edgeVerification.reconcilePartialRungs, {})).toEqual({
      cleared: 0,
    });
    await t.run((ctx) => ctx.db.patch(spare, { addresses: { v4: '198.51.100.9' } }));
    expect(await t.mutation(internal.edgeVerification.reconcilePartialRungs, {})).toEqual({
      cleared: 1,
    });
    expect(await record()).toBeUndefined();
    expect(
      (await t.run((ctx) => ctx.db.query('auditLog').collect()))
        .filter((a) => a.action === 'edge.verification.rung')
        .map((a) => (a.payload as { rung: string }).rung),
    ).toEqual(['partial', 'cleared']);
  });
});

describe('probe protocol branching', () => {
  test('an L4 edge behind a REALITY listener runs tls-sni internally and tcp outside; a plaintext listener runs tcp everywhere', async () => {
    const { t, relayId, listenerId, accountId } = await seed();
    await t.run(async (ctx) => {
      await upsertSettingRow(ctx, 'edge.probe.enabled', 'true');
      await upsertSettingRow(ctx, 'edge.probe.countries', JSON.stringify(['IR']));
    });
    const reality = await adoptL4Edge(t, relayId, listenerId, { ipv4: SPARE, accountId });
    const runsFor = async (edgeId: string) => {
      const r = await t.mutation(internal.probes.requestMany, {
        targets: [{ kind: 'edge', ref: edgeId }],
        sources: ['internal', 'globalping'],
      });
      expect(r.runIds.length).toBeGreaterThan(0);
      const rows = await t.run((ctx) => ctx.db.query('probeRuns').collect());
      return rows
        .filter((row) => row.targetRef === edgeId)
        .map((row) => [row.source, row.probeProtocol] as const);
    };
    const realityRuns = await runsFor(reality.edgeId as string);
    expect(realityRuns).toEqual(
      expect.arrayContaining([
        ['internal', 'tls-sni'],
        ['globalping', 'tcp'],
      ]),
    );
    // The executor context resolves the listener's ACTIVE name for the SNI at run time.
    const internalRun = (await t.run((ctx) => ctx.db.query('probeRuns').collect())).find(
      (row) => row.source === 'internal' && row.targetRef === (reality.edgeId as string),
    )!;
    const ctxRow = await t.query(internal.probes.runContext, { runId: internalRun._id });
    expect(ctxRow?.servername).toBe('a.example');
    const ss = await registerRelay(t, {
      slug: 'node-ss',
      nodeName: 'node-ss',
      originAddress: '203.0.113.11',
      listeners: [
        realityListener({
          listenerKey: 's',
          protocol: 'shadowsocks',
          security: 'none',
          originPort: 8388,
          tlsNames: undefined,
          realityTarget: undefined,
          panelBinding: {
            inboundTag: 'SS_IN',
            configProfileUuid: '11111111-1111-4111-8111-111111111111',
            configProfileInboundUuid: '44444444-4444-4444-8444-444444444444',
          },
        }),
      ],
    });
    const ssEdge = await adoptL4Edge(t, ss.relayId, ss.listenerId, {
      ipv4: '198.51.100.20',
      port: 8388,
    });
    const ssRuns = await runsFor(ssEdge.edgeId as string);
    expect(ssRuns).toEqual(
      expect.arrayContaining([
        ['internal', 'tcp'],
        ['globalping', 'tcp'],
      ]),
    );
    expect(ssRuns.some(([, p]) => p === 'tls-sni')).toBe(false);
  });
});
