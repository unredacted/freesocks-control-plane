/// <reference types="vite/client" />
/**
 * The bootstrap contract on a fake backend: "Set up this backend" creates the
 * profile from the template (one POST, keys never stored) with one transport
 * per mode, binds each REALITY transport to its family, makes each mode's
 * group and placement; an existing backend is adopted only when the operator
 * says so, and a group an earlier setup named is renamed in place. Then a
 * direct node is enrolled by name, its row and its DISABLED addresses (one per
 * family name) are created, the bootstrap answer carries the secret, and the
 * applied report leads to machine_ready with revision-bound evidence.
 * Identical reruns perform no write. Fixtures use RFC 5737 addresses and
 * `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { addressRemark, addressesOf, ownsAddress } from './nodeIntents';
import { gateOfNode } from './lib/edges/testing/reads';
import {
  SUBSCRIPTION_TEMPLATES,
  base64Utf8,
  templateHash,
} from './lib/backend/subscriptionTemplates';
import { NodeIntentView } from '../src/shared/contracts/servers';

const modules = import.meta.glob('./**/*.*s');
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', 'test-admin-sign');
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const UUID = (n: number) => `${String(n).padStart(8, '0')}-0000-4000-8000-000000000000`;

interface Panel {
  profiles: {
    uuid: string;
    name: string;
    config: any;
    inbounds: { uuid: string; tag: string }[];
  }[];
  squads: { uuid: string; name: string; inbounds: { uuid: string; tag: string }[] }[];
  hosts: any[];
  nodes: any[];
  /** Subscription templates; a backend without any has nothing to reconcile. */
  templates: {
    uuid: string;
    templateType: string;
    templateJson: unknown;
    encodedTemplateYaml: string | null;
  }[];
  /** Answer template writes with 403, as a backend whose token may not write them. */
  refuseTemplates?: boolean;
  writes: { call: string; body: any }[];
  seq: number;
}

function installPanel(): Panel {
  const panel: Panel = {
    profiles: [],
    squads: [],
    hosts: [],
    nodes: [],
    templates: [],
    writes: [],
    seq: 10,
  };
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const path = new URL(typeof input === 'string' ? input : input.toString()).pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body as string) : {};
      if (method === 'GET') {
        if (path === '/api/nodes')
          return json(panel.nodes.map((n) => ({ ...n, isConnected: true })));
        if (path === '/api/hosts') return json(panel.hosts);
        if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
        if (path === '/api/config-profiles') return json({ configProfiles: panel.profiles });
        if (path === '/api/keygen') return json({ pubKey: 'panel-node-secret-placeholder' });
        if (path === '/api/subscription-templates')
          return json(panel.templates.map(({ uuid, templateType }) => ({ uuid, templateType })));
        const tpl = panel.templates.find((x) => path === `/api/subscription-templates/${x.uuid}`);
        if (tpl) return json(tpl);
        const p = panel.profiles.find((x) => path === `/api/config-profiles/${x.uuid}`);
        if (p) return json(p);
        return json({});
      }
      panel.writes.push({ call: `${method} ${path}`, body });
      if (path === '/api/subscription-templates' && method === 'PATCH') {
        if (panel.refuseTemplates) return json({ message: 'Forbidden' }, 403);
        const tpl = panel.templates.find((x) => x.uuid === body.uuid)!;
        if ('templateJson' in body) tpl.templateJson = body.templateJson;
        if ('encodedTemplateYaml' in body) tpl.encodedTemplateYaml = body.encodedTemplateYaml;
        return json(tpl);
      }
      if (path === '/api/config-profiles' && method === 'POST') {
        const uuid = UUID(++panel.seq);
        const inbounds = (body.config.inbounds as { tag: string }[]).map((i) => ({
          uuid: UUID(++panel.seq),
          tag: i.tag,
        }));
        panel.profiles.push({ uuid, name: body.name, config: body.config, inbounds });
        return json({ uuid }, 201);
      }
      if (path === '/api/internal-squads' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          inbounds: (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid })),
        };
        panel.squads.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/internal-squads' && method === 'PATCH') {
        const s = panel.squads.find((x) => x.uuid === body.uuid)!;
        if (typeof body.name === 'string') s.name = body.name;
        if (Array.isArray(body.inbounds))
          s.inbounds = (body.inbounds as string[]).map((uuid) => ({ uuid, tag: uuid }));
        return json(s);
      }
      if (path === '/api/hosts' && method === 'POST') {
        const made = { uuid: UUID(++panel.seq), ...body, isDisabled: body.isDisabled === true };
        panel.hosts.push(made);
        return json({ uuid: made.uuid }, 201);
      }
      if (path === '/api/nodes' && method === 'POST') {
        const made = {
          uuid: UUID(++panel.seq),
          name: body.name,
          address: body.address,
          port: body.port ?? 2222,
          countryCode: body.countryCode ?? 'XX',
          isDisabled: false,
          lastStatusChange: 't0',
          configProfile: {
            activeConfigProfileUuid: body.configProfile.activeConfigProfileUuid,
            activeInbounds: (body.configProfile.activeInbounds as string[]).map((uuid) => ({
              uuid,
              tag: uuid,
            })),
          },
        };
        panel.nodes.push(made);
        return json(made, 201);
      }
      return json({});
    }),
  );
  return panel;
}

const setupInput = {
  profileName: 'FreeSocks-Config',
  modes: [
    {
      slug: 'privacy-reality',
      name: 'Privacy-Reality',
      shape: { transport: 'reality' as const, fronting: 'direct' as const },
      familySlug: 'fam-direct',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-reality',
      name: 'Freedom-Reality',
      shape: { transport: 'reality' as const, fronting: 'edge-l4' as const },
      familySlug: 'fam-fronted',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-xhttp',
      name: 'Freedom-XHTTP',
      shape: { transport: 'xhttp-reality' as const, fronting: 'edge-l4' as const },
      familySlug: 'fam-fronted',
      acceptProxyProtocol: false,
    },
    {
      slug: 'freedom-ws',
      name: 'Freedom-WebSocket',
      shape: { transport: 'ws' as const, fronting: 'edge-l7' as const },
      acceptProxyProtocol: false,
      ws: { path: '/ws', port: 8443 },
    },
  ],
  originDns: null,
  adopt: false,
};

/** Two families with qualified names, and families switched on (binding needs it). */
async function seedFamilies(t: T) {
  await t.mutation(internal.sniFamilies.patchConfig, { patch: { enabled: true } });
  for (const [slug, target, names] of [
    ['fam-direct', 'decoy-a.example', ['decoy-a.example', 'www.decoy-a.example']],
    ['fam-fronted', 'decoy-b.example', ['decoy-b.example']],
  ] as const) {
    await t.mutation(internal.sniFamilies.create, {
      slug,
      label: slug,
      targetAddress: target,
      targetPort: 443,
    });
    await t.mutation(internal.sniFamilies.importNames, { slug, lines: [...names] });
  }
  const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
  for (const n of due)
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: n.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
}

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installPanel();
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  await seedFamilies(t);
  return { t, serverId, panel };
}

/** Poll until the workflow released its lease (real timers: the scheduled run starts on the next tick). */
async function settled<R extends { claim?: unknown }>(get: () => Promise<R | null>): Promise<R> {
  for (let i = 0; i < 500; i++) {
    await new Promise((r) => setTimeout(r, 5));
    const row = await get();
    if (row && !row.claim) return row;
  }
  throw new Error('workflow did not settle');
}

async function runSetup(t: T, serverId: Id<'backendServers'>, input = setupInput) {
  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input,
  });
  // `start` scheduled the run; convex-test executes it on the next tick.
  return settled(() => t.run((ctx) => ctx.db.get(started.setupId)));
}

async function runIntent(t: T, intentId: Id<'panelNodeIntents'>) {
  return settled(() => t.run((ctx) => ctx.db.get(intentId)));
}

describe('setting up a fresh backend', () => {
  test('creates the profile once with a transport per mode, binds families, makes groups and placements', async () => {
    const { t, serverId, panel } = await seed();
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    expect(row.code).toBeUndefined();
    expect(row.adopted).toBe(false);
    expect(row.profileUuid).toBe(panel.profiles[0]!.uuid);
    expect(row.privacy).toBe('ok');
    expect(panel.writes.filter((w) => w.call === 'POST /api/config-profiles')).toHaveLength(1);
    const bySlug = Object.fromEntries(row.modes!.map((m) => [m.slug, m]));
    expect(bySlug['privacy-reality']).toMatchObject({
      tag: 'PRIVACY_REALITY',
      placement: 'bound',
      family: 'bound',
      transport: {
        port: 443,
        serverNames: ['decoy-a.example', 'www.decoy-a.example'],
        target: { address: 'decoy-a.example', port: 443 },
      },
    });
    expect(bySlug['freedom-xhttp']).toMatchObject({
      tag: 'FREEDOM_XHTTP',
      family: 'bound',
      transport: { path: '/', target: { address: 'decoy-b.example', port: 443 } },
    });
    expect(bySlug['freedom-ws']).toMatchObject({
      tag: 'FREEDOM_WEBSOCKET',
      family: 'none',
      transport: { port: 8443, path: '/ws' },
    });
    expect(row.modes!.every((m) => !!m.groupUuid)).toBe(true);
    expect(panel.squads.map((s) => s.name).sort()).toEqual([
      'Freedom-Reality',
      'Freedom-WebSocket',
      'Freedom-XHTTP',
      'Privacy-Reality',
    ]);
    const bindings = await t.run((ctx) => ctx.db.query('sniInboundBindings').collect());
    expect(bindings.map((b) => b.inboundTag).sort()).toEqual([
      'FREEDOM_REALITY',
      'FREEDOM_XHTTP',
      'PRIVACY_REALITY',
    ]);
    const obligations = await t.run((ctx) => ctx.db.query('backendObligations').collect());
    expect(obligations).toHaveLength(1);
    expect(obligations[0]).toMatchObject({
      kind: 'profile.create',
      state: 'confirmed',
      ownership: 'shared',
    });
    // No private key anywhere FCP keeps.
    const rows = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelSetups').collect(),
        await ctx.db.query('panelProfiles').collect(),
        await ctx.db.query('backendObligations').collect(),
        await ctx.db.query('auditLog').collect(),
      ]),
    );
    for (const ib of panel.profiles[0]!.config.inbounds) {
      const privateKey = ib.streamSettings?.realitySettings?.privateKey;
      if (!privateKey) continue;
      expect(privateKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(rows).not.toContain(privateKey);
    }

    // An identical rerun performs no write.
    const before = panel.writes.length;
    const again = await t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: setupInput,
    });
    expect(again.started).toBe(false);
    expect(panel.writes.length).toBe(before);
  });

  test('a mode without a usable family, or an unknown mode, is refused before anything is written', async () => {
    const { t, serverId, panel } = await seed();
    await expect(
      t.mutation(internal.backendSetup.start, {
        backendServerId: serverId,
        input: {
          ...setupInput,
          modes: [{ ...setupInput.modes[0]!, familySlug: 'nope' }],
        },
      }),
    ).rejects.toThrow(/family_missing/);
    await expect(
      t.mutation(internal.backendSetup.start, {
        backendServerId: serverId,
        input: { ...setupInput, modes: [{ ...setupInput.modes[0]!, slug: 'made-up-mode' }] },
      }),
    ).rejects.toThrow(/mode_unknown/);
    expect(panel.writes).toHaveLength(0);
  });

  test('an existing backend is adopted only on the typed say-so; a group an earlier setup named is renamed in place', async () => {
    const { t, serverId, panel } = await seed();
    panel.nodes.push({
      uuid: UUID(1),
      name: 'legacy',
      address: '192.0.2.5',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: UUID(2), activeInbounds: [] },
    });
    // The group also grants a transport of an older release: a mode grants one.
    const legacyGroup = {
      uuid: UUID(3),
      name: 'FreeSocks-Reality',
      inbounds: [{ uuid: UUID(9), tag: 'VLESS_OLD' }],
    };
    panel.squads.push(legacyGroup);
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    await expect(
      t.mutation(internal.backendSetup.start, { backendServerId: serverId, input: setupInput }),
    ).rejects.toThrow(/adopt_required/);
    expect(panel.writes).toHaveLength(0);
    const row = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(row.state).toBe('ready');
    expect(row.adopted).toBe(true);
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    expect(direct.groupUuid).toBe(legacyGroup.uuid);
    expect(direct.renamedFrom).toBe('FreeSocks-Reality');
    expect(panel.squads.find((s) => s.uuid === legacyGroup.uuid)!.name).toBe('Privacy-Reality');
    // Exactly the mode's transport, not the old one beside it.
    expect(
      panel.squads
        .find((x) => x.uuid === legacyGroup.uuid)!
        .inbounds.map((i: { uuid: string }) => i.uuid),
    ).toEqual([direct.transport!.uuid]);
    expect(panel.squads.filter((s) => s.name === 'FreeSocks-Reality')).toHaveLength(0);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(audit.some((a) => a.action === 'servers.setup.group_renamed')).toBe(true);
  });

  // A tag is unique per profile, never per backend: another profile reusing a
  // conventional tag must not make an unambiguous binding fail.
  test('a second profile reusing a transport tag does not stop the family binding', async () => {
    const { t, serverId, panel } = await seed();
    panel.profiles.push({
      uuid: UUID(90),
      name: 'Someone-Elses-Config',
      config: { inbounds: [{ tag: 'PRIVACY_REALITY' }] },
      inbounds: [{ uuid: UUID(91), tag: 'PRIVACY_REALITY' }],
    });
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const row = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(row.state).toBe('ready');
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    expect(direct.family).toBe('bound');
    // The family is bound to THIS profile's transport, not the other one.
    const bindings = await t.run((ctx) => ctx.db.query('sniInboundBindings').collect());
    expect(bindings.map((b) => b.inboundUuid)).toContain(direct.transport!.uuid);
    expect(bindings.map((b) => b.inboundUuid)).not.toContain(UUID(91));
  });

  // A transport already bound to ANOTHER family answers to that family's
  // rollouts: setting up around it would leave two owners of one allowlist.
  test('a transport bound to another family stops the setup with that family', async () => {
    const { t, serverId } = await seed();
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    const direct = row.modes!.find((m) => m.slug === 'privacy-reality')!;
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-other',
      label: 'fam-other',
      targetAddress: 'decoy-a.example',
      targetPort: 443,
    });
    await t.run(async (ctx) => {
      const other = await ctx.db
        .query('sniFamilies')
        .withIndex('by_slug', (q) => q.eq('slug', 'fam-other'))
        .unique();
      const mine = (await ctx.db.query('sniInboundBindings').collect()).find(
        (x) => x.inboundUuid === direct.transport!.uuid,
      )!;
      await ctx.db.patch(mine._id, { familyId: other!._id });
      // The row asks to be looked at again (as a resumed or retried setup does).
      await ctx.db.patch(row._id, {
        modes: row.modes!.map((m) =>
          m.slug === 'privacy-reality' ? { ...m, family: 'unbound' as const } : m,
        ),
      });
    });
    const again = await runSetup(t, serverId);
    expect(again.state).toBe('failed');
    expect(again.code).toBe('servers.family_bound_elsewhere:fam-other');
    expect(again.modes!.find((m) => m.slug === 'privacy-reality')!.family).toBe('bound_elsewhere');
  });
});

describe('subscription templates', () => {
  /** The sing-box template as an earlier release shipped it (other cache names). */
  const earlierSingbox = () => {
    const body = structuredClone(SUBSCRIPTION_TEMPLATES.SINGBOX.body) as {
      experimental: { cache_file: Record<string, unknown> };
    };
    body.experimental.cache_file = {
      ...body.experimental.cache_file,
      path: 'earlier.db',
      cache_id: 'earlier',
    };
    return body;
  };
  function addTemplates(panel: Panel) {
    panel.templates.push(
      {
        uuid: UUID(101),
        templateType: 'SINGBOX',
        templateJson: earlierSingbox(),
        encodedTemplateYaml: null,
      },
      {
        uuid: UUID(102),
        templateType: 'MIHOMO',
        templateJson: null,
        encodedTemplateYaml: base64Utf8(SUBSCRIPTION_TEMPLATES.MIHOMO.body as string),
      },
    );
  }
  const templateWrites = (panel: Panel) =>
    panel.writes.filter((w) => w.call === 'PATCH /api/subscription-templates');
  /** The backend holds the sing-box template an earlier release installed, recorded under its hash. */
  async function onEarlierRelease(
    t: T,
    panel: Panel,
    row: { _id: Id<'panelSetups'>; templates: any[] },
  ) {
    panel.templates[0]!.templateJson = earlierSingbox();
    await t.run((ctx) =>
      ctx.db.patch(row._id, {
        templates: [{ ...row.templates[0]!, hash: 'earlier' }, row.templates[1]!],
      }),
    );
  }
  async function readyOnEarlierRelease() {
    const { t, serverId, panel } = await seed();
    addTemplates(panel);
    const row = await runSetup(t, serverId);
    await onEarlierRelease(t, panel, row);
    return { t, panel, row };
  }
  const resync = (t: T) => t.action(internal.backendSetup.resyncTemplates, {});
  const installed = async (t: T) =>
    (await t.run((ctx) => ctx.db.query('auditLog').collect()))
      .filter((a) => a.action === 'servers.setup.templates_installed')
      .map((a) => (a.payload as { templates: string }).templates);

  test('setup installs only what differs; a changed template reaches a ready backend on the next sweep, once', async () => {
    const { t, serverId, panel } = await seed();
    addTemplates(panel);
    const row = await runSetup(t, serverId);
    expect(row.state).toBe('ready');
    const singbox = await templateHash(SUBSCRIPTION_TEMPLATES.SINGBOX);
    expect(row.templates).toEqual([
      { family: 'SINGBOX', hash: singbox, state: 'matched' },
      {
        family: 'MIHOMO',
        hash: await templateHash(SUBSCRIPTION_TEMPLATES.MIHOMO),
        state: 'matched',
      },
    ]);
    expect(templateWrites(panel).map((w) => w.body.uuid)).toEqual([UUID(101)]);
    expect(await resync(t)).toBe(0);

    // A release changed the sing-box template: the backend still has the earlier one.
    await onEarlierRelease(t, panel, row);
    const before = templateWrites(panel).length;
    expect(await resync(t)).toBe(1);
    // Only the template that differs is written; the setup row stays ready, its lease released.
    expect(
      templateWrites(panel)
        .slice(before)
        .map((w) => w.body.uuid),
    ).toEqual([UUID(101)]);
    expect(panel.templates[0]!.templateJson).toEqual(SUBSCRIPTION_TEMPLATES.SINGBOX.body);
    const after = (await t.run((ctx) => ctx.db.get(row._id)))!;
    expect(after).toMatchObject({ state: 'ready', generation: row.generation });
    expect(after.claim).toBeUndefined();
    expect(after.templates[0]).toEqual({ family: 'SINGBOX', hash: singbox, state: 'matched' });
    expect(await installed(t)).toEqual(['SINGBOX:matched,MIHOMO:matched']);
    // Once: the next sweep has nothing to do.
    expect(await resync(t)).toBe(0);
    expect(templateWrites(panel).length).toBe(before + 1);
  });

  test('a setup holding the lease, or server changes switched off, keep the sweep from writing', async () => {
    const { t, panel, row } = await readyOnEarlierRelease();
    const before = panel.writes.length;
    await t.run((ctx) =>
      ctx.db.patch(row._id, {
        claim: { attemptId: 'a-setup-run', expiresAt: Date.now() + 60_000 },
      }),
    );
    expect(await resync(t)).toBe(0);
    await t.run((ctx) => ctx.db.patch(row._id, { claim: undefined }));
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': false } });
    expect(await resync(t)).toBe(0);
    expect(panel.writes.length).toBe(before);
  });

  test('a refused write is recorded and tried again; audited only when the outcome moves', async () => {
    const { t, panel, row } = await readyOnEarlierRelease();
    panel.refuseTemplates = true;
    expect(await resync(t)).toBe(1);
    const refused = (await t.run((ctx) => ctx.db.get(row._id)))!;
    expect(refused.state).toBe('ready');
    expect(refused.templates[0]).toMatchObject({ family: 'SINGBOX', state: 'refused' });
    expect(await resync(t)).toBe(1);
    panel.refuseTemplates = false;
    expect(await resync(t)).toBe(1);
    expect((await t.run((ctx) => ctx.db.get(row._id)))!.templates[0]).toMatchObject({
      state: 'matched',
    });
    expect(await installed(t)).toEqual([
      'SINGBOX:refused,MIHOMO:matched',
      'SINGBOX:matched,MIHOMO:matched',
    ]);
  });
});

describe('enrolling a direct node', () => {
  test('creates the row and DISABLED addresses (one per family name), serves the secret, and reaches machine_ready on the applied report', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    const observed = {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    };
    const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed,
    });
    let intent = await runIntent(t, intentId);
    expect(intent.state).toBe('ready');
    expect(intent.activation.stage).toBe('registered');
    expect(panel.nodes).toHaveLength(1);
    expect(panel.nodes[0]).toMatchObject({ name: 'node-a', address: '192.0.2.10', port: 2222 });
    expect(panel.hosts.map((h) => h.remark).sort()).toEqual([
      'node-a | decoy-a.example',
      'node-a | www.decoy-a.example',
    ]);
    expect(panel.hosts[0]).toMatchObject({
      address: '203.0.113.10',
      port: 443,
      sni: 'decoy-a.example',
      isDisabled: true,
    });
    expect(intent.nodeUuid).toBe(panel.nodes[0]!.uuid);
    expect(intent.addressUuids?.sort()).toEqual(panel.hosts.map((h) => h.uuid).sort());
    expect(intent.configRevision).toMatch(/:/);
    expect(intent.authRevision).toBeTruthy();

    // The bootstrap answer carries the secret and the mode; nothing FCP keeps holds the secret.
    const boot = await t.action(internal.nodeIntents.bootstrap, { intentId });
    expect(boot).toMatchObject({
      machineRevision: 1,
      secretKey: 'panel-node-secret-placeholder',
      node: {
        port: 2222,
        mode: { slug: 'privacy-reality', shape: { transport: 'reality', fronting: 'direct' } },
      },
      ingress: null,
    });
    const kept = JSON.stringify(
      await t.run(async (ctx) => [
        await ctx.db.query('panelNodeIntents').collect(),
        await ctx.db.query('auditLog').collect(),
        await ctx.db.query('panelOps').collect(),
      ]),
    );
    expect(kept).not.toContain('panel-node-secret-placeholder');
    intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.activation.stage).toBe('bootstrap_available');

    // Applied: idempotent, stale and unknown revisions refused, then machine_ready.
    await expect(
      t.mutation(internal.nodeIntents.applied, {
        intentId,
        appliedRevision: 2,
        nodeStarted: true,
      }),
    ).rejects.toThrow(/revision_unknown/);
    const r1 = await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    expect(r1).toEqual({ stage: 'machine_applied', repeated: false });
    intent = await runIntent(t, intentId);
    expect(intent.activation.stage).toBe('machine_ready');
    expect(intent.activation.evidence.map((e) => e.kind).sort()).toEqual([
      'machine_applied',
      'machine_ready',
    ]);
    const r2 = await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    expect(r2).toEqual({ stage: 'machine_ready', repeated: true });

    // An identical observation rerun changes nothing on the backend.
    const before = panel.writes.length;
    await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed,
    });
    intent = await runIntent(t, intentId);
    expect(panel.writes.length).toBe(before);
    expect(intent.activation.stage).toBe('machine_ready');

    // The gate stays closed before any approval; the role view says so.
    const gate = await gateOfNode(t, {
      backendServerId: serverId,
      nodeName: 'node-a',
    });
    expect(gate.state).toBe('blocked');
    const view = await t.query(internal.nodeIntents.roleViewByName, {
      backendServerId: serverId,
      name: 'node-a',
    });
    expect(view).toMatchObject({
      mode: { slug: 'privacy-reality', name: 'Privacy-Reality' },
      stage: 'machine_ready',
      delivery: 'staged',
    });
  });

  test('a mode change, an unknown mode, an unowned backend node and a stale contract are refused', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    const observed = {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: {},
      capabilities: { caddy: false, ipv6: false },
    };
    await expect(
      t.mutation(internal.nodeIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'privacy-reality',
        contractVersion: 1,
        observed,
      }),
    ).rejects.toThrow(/contract_version/);
    await expect(
      t.mutation(internal.nodeIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'no-such-mode',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/mode_unknown/);
    panel.nodes.push({
      uuid: UUID(99),
      name: 'stranger',
      address: '192.0.2.99',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: panel.profiles[0]!.uuid, activeInbounds: [] },
    });
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    await expect(
      t.mutation(internal.nodeIntents.enroll, {
        backendServerId: serverId,
        name: 'stranger',
        mode: 'privacy-reality',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/node_exists_unowned/);
    await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: 'node-a',
      mode: 'freedom-reality',
      contractVersion: 2,
      observed,
    });
    await expect(
      t.mutation(internal.nodeIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        mode: 'privacy-reality',
        contractVersion: 2,
        observed,
      }),
    ).rejects.toThrow(/mode_change_needs_admin/);
  });

  test('the machine name is for operators only: kept, shown, never in a remark or the desired hash', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    const observed = {
      management: { address: '192.0.2.10', port: 2222 },
      publicIps: { v4: '203.0.113.10' },
      capabilities: { caddy: false, ipv6: false },
    };
    const enroll = (machineName?: string) =>
      t.mutation(internal.nodeIntents.enroll, {
        backendServerId: serverId,
        name: 'node-a',
        machineName,
        mode: 'privacy-reality',
        contractVersion: 2,
        observed,
      });
    const { intentId } = await enroll('node1.example.org');
    let intent = await runIntent(t, intentId);
    expect(intent.machineName).toBe('node1.example.org');
    const before = { hash: intent.desiredHash, generation: intent.generation };
    // What members can see keeps the node name.
    expect(panel.nodes[0]!.name).toBe('node-a');
    for (const h of panel.hosts) expect(String(h.remark)).not.toContain('node1');

    // A run that omits it keeps it; an unusable value is dropped, not refused.
    await enroll();
    await enroll('not a host name!');
    intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.machineName).toBe('node1.example.org');

    // A new one replaces it without touching the machine configuration.
    await enroll('node1b.example.org');
    intent = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect(intent.machineName).toBe('node1b.example.org');
    expect({ hash: intent.desiredHash, generation: intent.generation }).toEqual(before);

    const view = await t.query(internal.serverAdmin.intentsView, { backendServerId: serverId });
    expect(NodeIntentView.parse(view[0])).toMatchObject({
      name: 'node-a',
      machineName: 'node1b.example.org',
    });
  });
});

describe('an address belongs to exactly one node', () => {
  test('a node whose name is the prefix of another never owns its addresses', () => {
    expect(addressRemark('node-a', 'decoy-a.example')).toBe('node-a | decoy-a.example');
    expect(ownsAddress('node-a', addressRemark('node-a', 'decoy-a.example'))).toBe(true);
    // The collision a name prefix used to cause: node-a would have taken
    // node-a-west's addresses for its own, and deleted them as extra.
    expect(ownsAddress('node-a', addressRemark('node-a-west', 'decoy-a.example'))).toBe(false);
    expect(ownsAddress('node-a-west', addressRemark('node-a', 'decoy-a.example'))).toBe(false);
    // Whatever remark it carries, an address the node has recorded is its own
    // (an adopted node's were named by whoever made them).
    const hosts = [
      { hostUuid: 'h1', remark: 'anything at all' },
      { hostUuid: 'h2', remark: addressRemark('node-a', 'www.decoy-a.example') },
      { hostUuid: 'h3', remark: addressRemark('node-a-west', 'decoy-a.example') },
    ];
    expect(
      addressesOf({ name: 'node-a', addressUuids: ['h1'] }, hosts).map((h) => h.hostUuid),
    ).toEqual(['h1', 'h2']);
  });
});
