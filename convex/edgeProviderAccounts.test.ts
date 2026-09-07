/// <reference types="vite/client" />
import { convexTest } from 'convex-test';
import { describe, expect, test } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';

const modules = import.meta.glob('./**/*.*s');

const gcoreSettings = { projectId: 11, regionId: 22 };

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
    expect(audit.some((a) => a.action === 'relay.provider_account.create')).toBe(true);
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
  });

  test('remove refuses while an edge references the account', async () => {
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
  });
});

describe('edgeTemplates', () => {
  test('ensureDefaults seeds one default per provider; create/update validate through the adapter schema', async () => {
    const t = convexTest(schema, modules);
    const seeded = await t.mutation(internal.edgeTemplates.ensureDefaults, {});
    expect(seeded.created).toBe(4);
    expect((await t.mutation(internal.edgeTemplates.ensureDefaults, {})).created).toBe(0);
    const all = await t.query(internal.edgeTemplates.list, {});
    expect(all.filter((x) => x.isDefault)).toHaveLength(4);
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
    const other = (await mk('other')).id;
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
    expect(upd.requalify).toBe(2);
    const q = async (id: typeof byHash) =>
      (await t.query(internal.edgeProviderAccounts.getForAdmin, { id }))!.qualified;
    expect(await q(byHash)).toBe(false);
    expect(await q(byDefault)).toBe(false);
    expect(await q(other)).toBe(true);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(
      audit.filter(
        (a) => a.action === 'relay.provider_account.qualified' && a.payload?.qualified === false,
      ),
    ).toHaveLength(2);
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
      loadBalancers: [{ id: 'lb-1', name: 'x', addresses: { v4: '198.51.100.2' }, unowned: true }],
      ips: [],
      flavors: [{ id: 'f', label: 'F' }],
    };
    await t.mutation(internal.edgeProviderAccounts.recordInventory, {
      id,
      inventory: JSON.stringify(snapshot),
    });
    const view = (await t.query(internal.edgeProviderAccounts.getInventory, { id }))!;
    expect(view.inventory).toEqual(snapshot);
    expect(typeof view.inventoryAt).toBe('string');
    expect(new Date(view.inventoryAt as string).getTime()).toBeGreaterThan(0);
  });
});
