/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';

const modules = import.meta.glob('./**/*.*s');

const gcoreSettings = { projectId: 11, regionId: 22 };

type T = ReturnType<typeof convexTest>;

/** A minimal live edge referencing `accountId` (relay/slot/profile fixtures included). */
async function insertLiveEdge(
  t: T,
  accountId: Id<'edgeProviderAccounts'>,
  provider: 'gcore' | 'upcloud' | 'scaleway' | 'ovh',
) {
  await t.run(async (ctx) => {
    const now = Date.now();
    const serverId = await ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: `p-${accountId}`,
      slug: `p-${accountId}`,
      config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: now,
    });
    const relayId = await ctx.db.insert('relays', {
      slug: `o-${accountId}`,
      backendServerId: serverId,
      nodeHostname: 'node-a',
      originAddress: '198.51.100.7',
      modeSlugs: [],
      enabled: true,
      autoRotate: false,
      hostManaged: true,
      providerAffinity: 'rotate',
      desiredPublished: 1,
      standbyPerRelay: 0,
      cooldownMs: 1,
      maxRotationsPerDay: 3,
      drainMs: 1,
      publicationEpoch: 0,
      publishedEdgeIds: [],
      standbyEdgeIds: [],
      rotationsToday: 0,
      updatedAt: now,
    });
    const profileId = await ctx.db.insert('protocolProfiles', {
      slug: `pf-${accountId}`,
      name: 'pf',
      protocol: 'reality' as const,
      targetAddress: 'target.example',
      targetPort: 443,
      serverNames: [{ sni: 'www.example', status: 'active' }],
      enabled: true,
      updatedAt: now,
    });
    const slotId = await ctx.db.insert('relaySlots', {
      relayId,
      slotKey: 'a1',
      profileId,
      inboundTag: 'T',
      configProfileUuid: 'cp',
      configProfileInboundUuid: 'in',
      originPort: 443,
      templateHostRemark: 'node-a-relay-a1',
      deployed: true,
      retired: false,
      updatedAt: now,
    });
    await ctx.db.insert('edges', {
      relayId,
      slotId,
      accountId,
      provider,
      managed: true,
      name: `fcp-relay-x-${String(accountId).slice(-8)}`,
      steps: [],
      resources: [],
      listeners: [],
      addresses: {},
      publication: 'unpublished',
      status: 'active',
      statusChangedAt: now,
      health: 'unknown',
      destroyAttempts: 0,
      updatedAt: now,
    });
  });
}

const ovhSettings = {
  applicationKey: 'AK',
  endpoint: 'ovh-eu',
  serviceName: 'svc',
  regionName: 'GRA9',
  networkId: 'n',
  subnetId: 's',
};

describe('edgeProviderAccounts', () => {
  test('create validates settings + credentials, masks secrets, audits name/provider only', async () => {
    const t = convexTest(schema, modules);
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name: 'acct-a',
        settings: { projectId: 'x' },
        credentials: { apiKey: 'SECRET' },
      }),
    ).rejects.toThrow(/projectId/);
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name: 'acct-a',
        settings: gcoreSettings,
        credentials: {},
      }),
    ).rejects.toThrow(/missing credentials: apiKey/);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'acct-a',
      settings: gcoreSettings,
      credentials: { apiKey: 'SECRET_KEY' },
    });
    const list = await t.query(internal.edgeProviderAccounts.listForAdmin, {});
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      name: 'acct-a',
      provider: 'gcore',
      settings: { projectId: 11, regionId: 22 },
      credentialsSet: { apiKey: true },
      qualified: false,
      enabled: true,
    });
    expect(JSON.stringify(list)).not.toContain('SECRET_KEY');
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'edge.provider_account.create')).toBe(true);
    expect(JSON.stringify(audit)).not.toContain('SECRET_KEY');
    // Duplicate name refused.
    await expect(
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name: 'acct-a',
        settings: gcoreSettings,
        credentials: { apiKey: 'x' },
      }),
    ).rejects.toThrow(/exists/);
    // The secret is readable only through the internal getter.
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({ type: 'gcore', apiKey: 'SECRET_KEY' });
  });

  test('update keeps the secret on blank, replaces on value, and drops qualification on credential/settings change', async () => {
    const t = convexTest(schema, modules);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'ovh',
      name: 'acct-o',
      settings: {
        applicationKey: 'AK',
        endpoint: 'ovh-eu',
        serviceName: 'svc',
        regionName: 'GRA9',
        networkId: 'n',
        subnetId: 's',
      },
      credentials: { applicationSecret: 'AS1', consumerKey: 'CK1' },
    });
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id,
      qualified: true,
      templateHash: 'h1',
    });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      true,
    );
    // Blank + one new value: CK kept, AS replaced.
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      credentials: { applicationSecret: 'AS2', consumerKey: '' },
    });
    const secret = await t.query(internal.edgeProviderAccounts.getWithSecret, { id });
    expect(secret?.credentials).toEqual({
      type: 'ovh',
      applicationSecret: 'AS2',
      consumerKey: 'CK1',
    });
    const view = await t.query(internal.edgeProviderAccounts.getForAdmin, { id });
    expect(view?.qualified).toBe(false);
    // A pure flag edit does not touch qualification.
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id,
      qualified: true,
      templateHash: 'h1',
    });
    await t.mutation(internal.edgeProviderAccounts.update, { id, enabled: false, priority: 5 });
    const after = await t.query(internal.edgeProviderAccounts.getForAdmin, { id });
    expect(after).toMatchObject({ enabled: false, priority: 5, qualified: true });
    // A different effective template was never qualified: switching to it clears the flag.
    const { id: tplId } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'ovh',
      name: 'Other',
      params: {},
    });
    await t.mutation(internal.edgeProviderAccounts.update, { id, defaultTemplateId: tplId });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      false,
    );
    // Re-sending the same template is not a change.
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    await t.mutation(internal.edgeProviderAccounts.update, { id, defaultTemplateId: tplId });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      true,
    );
  });

  test('remove and settings changes refuse while an edge references the account', async () => {
    const t = convexTest(schema, modules);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'upcloud',
      name: 'acct-u',
      settings: { zone: 'de-fra1' },
      credentials: { token: 'T' },
    });
    const now = Date.now();
    const serverId = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'p',
        slug: 'p',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: now,
      }),
    );
    const relayId = await t.run((ctx) =>
      ctx.db.insert('relays', {
        slug: 'o1',
        backendServerId: serverId,
        nodeHostname: 'node-a',
        originAddress: '198.51.100.7',
        modeSlugs: ['freedom-reality'],
        enabled: true,
        autoRotate: false,
        hostManaged: true,
        providerAffinity: 'rotate',
        desiredPublished: 2,
        standbyPerRelay: 0,
        cooldownMs: 1,
        maxRotationsPerDay: 3,
        drainMs: 1,
        publicationEpoch: 0,
        publishedEdgeIds: [],
        standbyEdgeIds: [],
        rotationsToday: 0,
        updatedAt: now,
      }),
    );
    const profileId = await t.run((ctx) =>
      ctx.db.insert('protocolProfiles', {
        slug: 'pf',
        name: 'pf',
        provider: 'upcloud',
        protocol: 'reality' as const,
        targetAddress: 'target.example',
        targetPort: 443,
        serverNames: [{ sni: 'www.example', status: 'active' }],
        enabled: true,
        updatedAt: now,
      }),
    );
    const slotId = await t.run((ctx) =>
      ctx.db.insert('relaySlots', {
        relayId,
        slotKey: 'a1',
        profileId,
        inboundTag: 'T',
        configProfileUuid: 'cp',
        configProfileInboundUuid: 'in',
        originPort: 443,
        templateHostRemark: 'node-a-relay-a1',
        deployed: true,
        retired: false,
        updatedAt: now,
      }),
    );
    await t.run((ctx) =>
      ctx.db.insert('edges', {
        relayId,
        slotId,
        accountId: id,
        provider: 'upcloud',
        managed: true,
        name: 'fcp-relay-o1-00000000',
        steps: [],
        resources: [],
        listeners: [],
        addresses: {},
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: now,
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: now,
      }),
    );
    await expect(t.mutation(internal.edgeProviderAccounts.remove, { id })).rejects.toThrow(
      /Edges still reference/,
    );
    // The zone locates the live edge's resources: it cannot move under them.
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, { id, settings: { zone: 'nl-ams1' } }),
    ).rejects.toThrow(/still reference this account/);
    // Re-sending the same settings is not a change; flags and credentials stay editable.
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      settings: { zone: 'de-fra1' },
      priority: 3,
    });
    await t.mutation(internal.edgeProviderAccounts.update, { id, credentials: { token: 'T2' } });
    expect(await t.query(internal.edgeProviderAccounts.getForAdmin, { id })).toMatchObject({
      priority: 3,
      settings: { zone: 'de-fra1' },
    });
  });
});

describe('edgeProviderAccounts: change detection + qualification hash', () => {
  test('settings compare canonically: a stored row in another key order re-sent is not a change (no refusal, qualification kept)', async () => {
    const t = convexTest(schema, modules);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'ovh',
      name: 'acct-o',
      settings: ovhSettings,
      credentials: { applicationSecret: 'AS1', consumerKey: 'CK1' },
    });
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    await insertLiveEdge(t, id, 'ovh');
    // Simulate a row whose stored key order differs from the schema's.
    await t.run(async (ctx) => {
      const row = (await ctx.db.get(id))!;
      const reversed = Object.fromEntries(Object.entries(row.settings).reverse());
      await ctx.db.patch(id, { settings: reversed as never });
    });
    // Re-sending the same values (in yet another order) is not a change.
    const shuffled = Object.fromEntries(Object.entries(ovhSettings).sort(() => -1));
    await t.mutation(internal.edgeProviderAccounts.update, { id, settings: shuffled, priority: 2 });
    const view = await t.query(internal.edgeProviderAccounts.getForAdmin, { id });
    expect(view).toMatchObject({ qualified: true, priority: 2, settings: ovhSettings });
    // Same for credentials: stored order differs, same values re-sent → no change.
    await t.run(async (ctx) => {
      await ctx.db.patch(id, {
        credentials: { consumerKey: 'CK1', applicationSecret: 'AS1', type: 'ovh' } as never,
      });
    });
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      credentials: { applicationSecret: 'AS1', consumerKey: 'CK1' },
    });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      true,
    );
  });

  test('only LOCATING settings are locked by live edges; the credential identifier stays editable (but unverified: qualification drops)', async () => {
    const t = convexTest(schema, modules);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'ovh',
      name: 'acct-o',
      settings: ovhSettings,
      credentials: { applicationSecret: 'AS1', consumerKey: 'CK1' },
    });
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    await insertLiveEdge(t, id, 'ovh');
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, {
        id,
        settings: { ...ovhSettings, regionName: 'SBG5' },
      }),
    ).rejects.toThrow(/still reference this account/);
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, {
        id,
        settings: { ...ovhSettings, gatewayId: 'gw-9' },
      }),
    ).rejects.toThrow(/still reference this account/);
    await t.mutation(internal.edgeProviderAccounts.update, {
      id,
      settings: { ...ovhSettings, applicationKey: 'AK-rotated' },
    });
    const view = await t.query(internal.edgeProviderAccounts.getForAdmin, { id });
    expect(view?.settings).toMatchObject({ applicationKey: 'AK-rotated', regionName: 'GRA9' });
    expect(view?.qualified).toBe(false);
    // Scaleway's access key is the same kind of identifier.
    const { id: sid } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'scaleway',
      name: 'acct-s',
      settings: { accessKey: 'SCWAAAAAAAAAAAAAAAAA', zone: 'fr-par-1' },
      credentials: { secretKey: 'S' },
    });
    await insertLiveEdge(t, sid, 'scaleway');
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: sid,
      settings: { accessKey: 'SCWBBBBBBBBBBBBBBBBB', zone: 'fr-par-1' },
    });
    await expect(
      t.mutation(internal.edgeProviderAccounts.update, {
        id: sid,
        settings: { accessKey: 'SCWBBBBBBBBBBBBBBBBB', zone: 'nl-ams-1' },
      }),
    ).rejects.toThrow(/still reference this account/);
  });

  test('setQualified records the EFFECTIVE template hash server-side and ignores a client-supplied one', async () => {
    const t = convexTest(schema, modules);
    await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'acct-g',
      settings: gcoreSettings,
      credentials: { apiKey: 'k' },
    });
    const providerDefault = (
      await t.query(internal.edgeTemplates.list, { provider: 'gcore' })
    ).find((x) => x.isDefault)!;
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id,
      qualified: true,
      templateHash: 'client-says-so',
    });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualifiedTemplateHash,
    ).toBe(providerDefault.paramsHash);
    // With an account default, THAT template's hash is recorded.
    const { id: tplId, paramsHash } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Big',
      params: { flavor: 'lb1-2-4' },
    });
    await t.mutation(internal.edgeProviderAccounts.update, { id, defaultTemplateId: tplId });
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: true });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualifiedTemplateHash,
    ).toBe(paramsHash);
    // ...so editing that template's params is what invalidates it.
    await t.mutation(internal.edgeTemplates.update, { id: tplId, params: { flavor: 'lb1-4-8' } });
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualified).toBe(
      false,
    );
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id, qualified: false });
    expect(
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))?.qualifiedTemplateHash,
    ).toBeNull();
  });
});

describe('edgeTemplates', () => {
  test("an account-scoped default template is that account's default only, never another account's provider default", async () => {
    const t = convexTest(schema, modules);
    const mk = (name: string) =>
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name,
        settings: gcoreSettings,
        credentials: { apiKey: 'k' },
      });
    const a = (await mk('acct-a')).id;
    const b = (await mk('acct-b')).id;
    const base = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Base',
      params: { flavor: 'lb1-1-2' },
      isDefault: true,
    });
    const mine = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Mine',
      params: { flavor: 'lb1-2-4' },
      accountId: a,
      isDefault: true,
    });
    // One default per scope: A's scoped default did not clear the provider-wide one.
    const rows = await t.query(internal.edgeTemplates.list, { provider: 'gcore' });
    expect(
      rows
        .filter((r) => r.isDefault)
        .map((r) => r.name)
        .sort(),
    ).toEqual(['Base', 'Mine']);
    const resolve = (accountId: typeof a, templateId?: typeof base.id) =>
      t.query(internal.edgeTemplates.resolveForProvision, {
        provider: 'gcore',
        accountId,
        templateId: templateId ?? null,
      });
    expect((await resolve(a)).id).toBe(mine.id);
    expect((await resolve(b)).id).toBe(base.id);
    // B may not use A's template even when named explicitly.
    expect((await resolve(b, mine.id)).id).toBe(base.id);
    expect((await resolve(a, base.id)).id).toBe(base.id);
    // A provider with ONLY scoped templates falls back to the compiled defaults for other accounts.
    await t.mutation(internal.edgeTemplates.remove, { id: base.id });
    expect((await resolve(b)).id).toBeNull();
    expect((await resolve(a)).id).toBe(mine.id);
    // Requalification on a scoped default edit touches only the accounts it is the default FOR.
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id: a, qualified: true });
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id: b, qualified: true });
    const upd = await t.mutation(internal.edgeTemplates.update, {
      id: mine.id,
      params: { flavor: 'lb1-4-8' },
    });
    expect(upd.requalify).toBe(1);
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id: a }))?.qualified).toBe(
      false,
    );
    expect((await t.query(internal.edgeProviderAccounts.getForAdmin, { id: b }))?.qualified).toBe(
      true,
    );
  });

  test('ensureDefaults seeds one default per provider; create/update validate through the adapter schema', async () => {
    const t = convexTest(schema, modules);
    const seeded = await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    expect(seeded.created).toBe(4);
    expect((await t.mutation(internal.edgeTemplates.ensureDefaults, {})).created).toBe(0);
    const all = await t.query(internal.edgeTemplates.list, {});
    expect(all.filter((x) => x.isDefault)).toHaveLength(4);
    // Seeding is first-use only: an operator-created template on ANY provider
    // means the table is theirs, and no defaults are added for the others.
    const t2 = convexTest(schema, modules);
    await t2.mutation(internal.edgeTemplates.create, {
      provider: 'upcloud',
      name: 'Mine',
      params: { plan: 'development' },
    });
    expect((await t2.mutation(internal.edgeTemplates.ensureDefaults, {})).created).toBe(0);
    await expect(
      t.mutation(internal.edgeTemplates.create, {
        provider: 'gcore',
        name: 'Bad',
        params: { flavor: '' },
      }),
    ).rejects.toThrow(/flavor/);
    const { id, paramsHash } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Big',
      params: { flavor: 'lb1-2-4' },
      isDefault: true,
    });
    const gcore = await t.query(internal.edgeTemplates.list, { provider: 'gcore' });
    expect(gcore.filter((x) => x.isDefault).map((x) => x.name)).toEqual(['Big']);
    const upd = await t.mutation(internal.edgeTemplates.update, {
      id,
      params: { flavor: 'lb1-4-8' },
    });
    expect(upd.paramsHash).not.toBe(paramsHash);
    const resolved = await t.query(internal.edgeTemplates.resolveForProvision, {
      provider: 'gcore',
    });
    expect(resolved.params).toMatchObject({ flavor: 'lb1-4-8' });
    // The last template of a provider cannot be removed.
    const only = await t.query(internal.edgeTemplates.list, { provider: 'ovh' });
    await expect(
      t.mutation(internal.edgeTemplates.remove, { id: only[0].id as never }),
    ).rejects.toThrow(/at least one/);
    const val = await t.query(internal.edgeTemplates.validate, {
      provider: 'scaleway',
      params: { timeoutClient: 'nope' },
    });
    expect(val.ok).toBe(false);
  });

  test("changing a template's parameters clears the qualification of accounts qualified with it or defaulting to it", async () => {
    const t = convexTest(schema, modules);
    const { id: tplId, paramsHash } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Tpl',
      params: { flavor: 'lb1-2-4' },
    });
    const mk = (name: string) =>
      t.mutation(internal.edgeProviderAccounts.create, {
        provider: 'gcore',
        name,
        settings: { projectId: 11, regionId: 22 },
        credentials: { apiKey: 'k' },
      });
    const byHash = (await mk('by-hash')).id;
    const byDefault = (await mk('by-default')).id;
    const implicit = (await mk('implicit')).id; // no template of its own → provider default
    const other = (await mk('other')).id;
    await t.mutation(internal.edgeTemplates.update, { id: tplId, isDefault: true });
    await t.mutation(internal.edgeProviderAccounts.setQualified, { id: implicit, qualified: true });
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: byHash,
      qualified: true,
      templateHash: paramsHash,
    });
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: byDefault,
      defaultTemplateId: tplId,
    });
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: byDefault,
      qualified: true,
    });
    // `other` provisions from its OWN template, so the default's edits never touch it.
    const { id: otherTpl } = await t.mutation(internal.edgeTemplates.create, {
      provider: 'gcore',
      name: 'Tpl-other',
      params: { flavor: 'lb1-1-2' },
    });
    await t.mutation(internal.edgeProviderAccounts.update, {
      id: other,
      defaultTemplateId: otherTpl,
    });
    await t.mutation(internal.edgeProviderAccounts.setQualified, {
      id: other,
      qualified: true,
      templateHash: 'unrelated',
    });
    // A rename does not touch anyone.
    await t.mutation(internal.edgeTemplates.update, { id: tplId, name: 'Tpl2' });
    // A parameter change does.
    const upd = await t.mutation(internal.edgeTemplates.update, {
      id: tplId,
      params: { flavor: 'lb1-4-8' },
    });
    expect(upd.requalify).toBe(3);
    const q = async (id: typeof byHash) =>
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))!.qualified;
    expect(await q(byHash)).toBe(false);
    expect(await q(byDefault)).toBe(false);
    expect(await q(implicit)).toBe(false);
    expect(await q(other)).toBe(true);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(
      audit.filter(
        (a) => a.action === 'edge.provider_account.qualified' && a.payload?.qualified === false,
      ),
    ).toHaveLength(3);
  });

  test('getInventory decodes the stored snapshot into the admin contract shape', async () => {
    const t = convexTest(schema, modules);
    const { id } = await t.mutation(internal.edgeProviderAccounts.create, {
      provider: 'gcore',
      name: 'inv',
      settings: { projectId: 11, regionId: 22 },
      credentials: { apiKey: 'k' },
    });
    expect(await t.query(internal.edgeProviderAccounts.getInventory, { id })).toEqual({
      inventory: null,
      inventoryAt: null,
    });
    const snapshot = {
      loadBalancers: [
        { id: 'lb-1', name: 'x', addresses: { v4: '198.51.100.2' } },
        { id: 'lb-2', name: 'y', addresses: { v4: '198.51.100.3' } },
      ],
      ips: [],
      flavors: [{ id: 'f', label: 'F' }],
    };
    await t.mutation(internal.edgeProviderAccounts.recordInventory, {
      id,
      inventory: JSON.stringify(snapshot),
    });
    // lb-1 is already in a live edge ledger → owned; lb-2 is free to import.
    await t.run(async (ctx) => {
      const now = Date.now();
      const serverId = await ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'p',
        slug: 'p',
        config: { type: 'remnawave', baseUrl: 'https://panel.test', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: now,
      });
      const relayId = await ctx.db.insert('relays', {
        slug: 'o1',
        backendServerId: serverId,
        nodeHostname: 'node-a',
        originAddress: '198.51.100.7',
        modeSlugs: [],
        enabled: true,
        autoRotate: false,
        hostManaged: true,
        providerAffinity: 'rotate',
        desiredPublished: 1,
        standbyPerRelay: 0,
        cooldownMs: 1,
        maxRotationsPerDay: 3,
        drainMs: 1,
        publicationEpoch: 0,
        publishedEdgeIds: [],
        standbyEdgeIds: [],
        rotationsToday: 0,
        updatedAt: now,
      });
      const profileId = await ctx.db.insert('protocolProfiles', {
        slug: 'pf',
        name: 'pf',
        protocol: 'reality' as const,
        targetAddress: 'target.example',
        targetPort: 443,
        serverNames: [{ sni: 'www.example', status: 'active' }],
        enabled: true,
        updatedAt: now,
      });
      const slotId = await ctx.db.insert('relaySlots', {
        relayId,
        slotKey: 'a1',
        profileId,
        inboundTag: 'T',
        configProfileUuid: 'cp',
        configProfileInboundUuid: 'in',
        originPort: 443,
        templateHostRemark: 'node-a-relay-a1',
        deployed: true,
        retired: false,
        updatedAt: now,
      });
      await ctx.db.insert('edges', {
        relayId,
        slotId,
        accountId: id,
        provider: 'gcore',
        managed: true,
        name: 'adopted-o1',
        steps: [],
        resources: [
          {
            stepId: 'adopted',
            kind: 'lb',
            resourceId: 'lb-1',
            ownership: 'adopted',
            deleteState: 'present',
          },
        ],
        listeners: [],
        addresses: { v4: '198.51.100.2' },
        publication: 'unpublished',
        status: 'active',
        statusChangedAt: now,
        health: 'unknown',
        destroyAttempts: 0,
        updatedAt: now,
      });
    });
    const view = (await t.query(internal.edgeProviderAccounts.getInventory, { id }))!;
    expect(view.inventory).toEqual({
      ...snapshot,
      loadBalancers: [
        { ...snapshot.loadBalancers[0], unowned: false },
        { ...snapshot.loadBalancers[1], unowned: true },
      ],
    });
    expect(typeof view.inventoryAt).toBe('string');
    expect(new Date(view.inventoryAt as string).getTime()).toBeGreaterThan(0);
  });
});
