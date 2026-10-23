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
import { FIXTURE_PANEL_SLUG, createAccount, insertPanelServer } from './lib/edges/testing/fixtures';
import { addressRemark, addressesOf, enrolledOriginOf, ownsAddress } from './nodeIntents';
import { gateOfNode } from './lib/edges/testing/reads';
import {
  SUBSCRIPTION_TEMPLATES,
  base64Utf8,
  templateHash,
} from './lib/backend/subscriptionTemplates';
import { TEMPLATE_RECHECK_MS } from './backendSetup';
import { BackendSetupView, NodeIntentView, NodeRoleView } from '../src/shared/contracts/servers';
import { __setFrontIngressCheckForTests, __setOriginResolutionForTests } from './nodeIntentOps';
import { verifyResolution } from './lib/backend/originDns';

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
  __setOriginResolutionForTests(null);
  __setFrontIngressCheckForTests(null);
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
  /** Called on every template read, and before a template write is applied. */
  onTemplateRead?: () => Promise<void>;
  onTemplateWrite?: () => Promise<void>;
  /** Every node reads as not connected (a machine that is down). */
  offline?: boolean;
  /** The origin-names zone (the DNS provider's API, `/client/v4/zones/<id>/dns_records`). */
  zone: { id: string; type: string; name: string; content: string; comment?: string }[];
  /** Public resolvers answer what the zone holds (true), or nothing yet (false). */
  resolving: boolean;
  /** Every name an origin resolution check asked for. */
  lookups: string[];
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
    zone: [],
    resolving: true,
    lookups: [],
    writes: [],
    seq: 10,
  };
  // The suite resolves no real name either.
  __setOriginResolutionForTests(async ({ hostname, expected }) => {
    panel.lookups.push(hostname);
    const at = panel.resolving ? panel.zone.filter((r) => r.name === hostname) : [];
    const of = (type: string) => at.filter((r) => r.type === type).map((r) => r.content);
    const answers = { v4: of('A'), v6: of('AAAA') };
    return { resolves: verifyResolution(answers, expected), answers };
  });
  const json = (o: unknown, status = 200) =>
    new Response(JSON.stringify({ response: o }), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  const envelope = (result: unknown, extra: Record<string, unknown> = {}) =>
    new Response(JSON.stringify({ result, success: true, errors: [], messages: [], ...extra }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL, init: RequestInit = {}) => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      const path = url.pathname;
      const method = (init.method ?? 'GET').toUpperCase();
      const body = init.body ? JSON.parse(init.body as string) : {};
      const records = /^\/client\/v4\/zones\/[^/]+\/dns_records(?:\/([^/]+))?$/.exec(path);
      if (records) {
        const id = records[1];
        if (method === 'GET' && !id) {
          const hits = panel.zone.filter((r) => r.name === url.searchParams.get('name.exact'));
          return envelope(hits, {
            result_info: { page: 1, per_page: 5, count: hits.length, total_count: hits.length },
          });
        }
        if (method === 'GET') return envelope(panel.zone.find((r) => r.id === id) ?? null);
        panel.writes.push({ call: `${method} ${path}`, body });
        if (method === 'POST') {
          const made = { id: `rec${++panel.seq}`, ...body };
          panel.zone.push(made);
          return envelope(made);
        }
        if (method === 'DELETE') {
          panel.zone = panel.zone.filter((r) => r.id !== id);
          return envelope({ id });
        }
      }
      if (method === 'GET') {
        if (path === '/api/nodes')
          return json(panel.nodes.map((n) => ({ ...n, isConnected: !panel.offline })));
        if (path === '/api/hosts') return json(panel.hosts);
        if (path === '/api/internal-squads') return json({ internalSquads: panel.squads });
        if (path === '/api/config-profiles') return json({ configProfiles: panel.profiles });
        if (path === '/api/keygen') return json({ pubKey: 'panel-node-secret-placeholder' });
        if (path === '/api/subscription-templates')
          return json(panel.templates.map(({ uuid, templateType }) => ({ uuid, templateType })));
        const tpl = panel.templates.find((x) => path === `/api/subscription-templates/${x.uuid}`);
        if (tpl) {
          await panel.onTemplateRead?.();
          return json(tpl);
        }
        const p = panel.profiles.find((x) => path === `/api/config-profiles/${x.uuid}`);
        if (p) return json(p);
        return json({});
      }
      panel.writes.push({ call: `${method} ${path}`, body });
      if (path === '/api/subscription-templates' && method === 'PATCH') {
        if (panel.refuseTemplates) return json({ message: 'Forbidden' }, 403);
        await panel.onTemplateWrite?.();
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

type ModeArg = {
  slug: string;
  name: string;
  shape: {
    transport: 'reality' | 'xhttp-reality' | 'ws';
    fronting: 'direct' | 'edge-l4' | 'edge-l7';
  };
  familySlug?: string;
  acceptProxyProtocol: boolean;
  ws?: { path: string; port: number };
};
type SetupInputArg = {
  profileName: string;
  modes: ModeArg[];
  originDns: { accountId: string; zoneId?: string } | null;
  adopt: boolean;
};

const setupInput: SetupInputArg = {
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

async function runSetup(t: T, serverId: Id<'backendServers'>, input: SetupInputArg = setupInput) {
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

  // Members of a group hold what its transports serve: an adoption takes none
  // of that away. The group is left as it is and the operator decides.
  test('adopting never takes a transport members are served on out of their group', async () => {
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
    const legacyGroup = {
      uuid: UUID(3),
      name: 'FreeSocks-Reality',
      inbounds: [{ uuid: UUID(9), tag: 'VLESS_OLD' }],
    };
    panel.squads.push(legacyGroup);
    // A Host serves the group's transport: its members are given that entry.
    panel.hosts.push({
      uuid: UUID(4),
      remark: 'legacy-ws',
      address: '192.0.2.5',
      port: 443,
      inbound: { configProfileUuid: UUID(2), configProfileInboundUuid: UUID(9) },
      isDisabled: false,
    });
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const row = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(row).toMatchObject({
      state: 'failed',
      code: 'servers.adopt_group_narrows:privacy-reality',
      step: 'groups',
    });
    expect(panel.writes.filter((w) => w.call.includes('/api/internal-squads'))).toEqual([]);
    expect(panel.squads.find((s) => s.uuid === legacyGroup.uuid)).toMatchObject({
      name: 'FreeSocks-Reality',
      inbounds: [{ uuid: UUID(9) }],
    });

    // Once nothing serves it any more, the group is the mode's alone.
    panel.hosts[0]!.isDisabled = true;
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    const again = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(again.state).toBe('ready');
    const direct = again.modes!.find((m) => m.slug === 'privacy-reality')!;
    expect(
      panel.squads
        .find((x) => x.uuid === legacyGroup.uuid)!
        .inbounds.map((i: { uuid: string }) => i.uuid),
    ).toEqual([direct.transport!.uuid]);
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

describe("changing a backend's setup", () => {
  const change = (t: T, serverId: Id<'backendServers'>, over: Partial<SetupInputArg> = {}) =>
    t.mutation(internal.backendSetup.start, {
      backendServerId: serverId,
      input: { ...setupInput, ...over },
    });
  const setupOf = (t: T, serverId: Id<'backendServers'>) =>
    t.run((ctx) =>
      ctx.db
        .query('panelSetups')
        .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
        .unique(),
    );
  async function enroll(t: T, serverId: Id<'backendServers'>, name: string, mode: string) {
    const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name,
      mode,
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4: '203.0.113.10' },
        capabilities: { caddy: mode === 'freedom-ws', ipv6: false },
      },
    });
    return { intentId, intent: await runIntent(t, intentId) };
  }
  /** Poll (real timers) until `ok` holds for what `get` reads. */
  async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
    for (let i = 0; i < 500; i++) {
      const r = await get();
      if (ok(r)) return r;
      await new Promise((res) => setTimeout(res, 5));
    }
    throw new Error('condition never held');
  }
  const changedAudit = async (t: T) =>
    (await t.run((ctx) => ctx.db.query('auditLog').collect()))
      .filter((a) => a.action === 'servers.setup.changed')
      .map((a) => a.payload);

  test('a backend FCP set up asks no adoption for its own nodes: origin names are added in place, nothing on the backend is touched', async () => {
    const { t, serverId, panel } = await seed();
    const first = await runSetup(t, serverId);
    expect(first.readyAt).toBeDefined();
    const { intentId, intent: before } = await enroll(t, serverId, 'node-a', 'privacy-reality');
    // FCP's own node and its addresses are on the backend now.
    expect(panel.nodes).toHaveLength(1);
    expect(panel.hosts).toHaveLength(2);
    const acct = await createAccount(t, { provider: 'cloudflare', name: 'dns' });
    const writes = panel.writes.length;

    const res = await change(t, serverId, { originDns: { accountId: acct } });
    expect(res).toMatchObject({ state: 'ready', started: false, generation: 2 });
    const row = (await setupOf(t, serverId))!;
    expect(row).toMatchObject({
      state: 'ready',
      generation: 2,
      adopted: false,
      originDns: { accountId: acct, zoneName: 'example.org' },
    });
    expect(row.claim).toBeUndefined();
    // Nothing was looked for again: every mode keeps what the setup found.
    expect(row.modes).toEqual(first.modes);
    await new Promise((r) => setTimeout(r, 50));
    expect(panel.writes.length).toBe(writes);
    const after = (await t.run((ctx) => ctx.db.get(intentId)))!;
    expect({ g: after.generation, r: after.machineRevision, s: after.settings }).toEqual({
      g: before.generation,
      r: before.machineRevision,
      s: before.settings,
    });
    expect(await changedAudit(t)).toEqual([
      {
        backendSlug: expect.any(String),
        generation: 2,
        change: 'origin',
        originZone: 'example.org',
        addedModes: '',
      },
    ]);
    const view = BackendSetupView.parse(
      await t.query(internal.backendSetup.view, { backendServerId: serverId }),
    );
    expect(view).toMatchObject({
      established: true,
      generation: 2,
      originDns: { accountId: acct, zoneName: 'example.org' },
    });
    expect(view.modes.find((m) => m.slug === 'freedom-ws')).toMatchObject({
      acceptProxyProtocol: false,
      ws: { path: '/ws', port: 8443 },
    });

    // The same request again, or the modes in another order, changes nothing.
    expect(await change(t, serverId, { originDns: { accountId: acct } })).toMatchObject({
      generation: 2,
      started: false,
    });
    expect(
      await change(t, serverId, {
        originDns: { accountId: acct },
        modes: [...setupInput.modes].reverse(),
      }),
    ).toMatchObject({ generation: 2, started: false });
    // Taking it away again is fine while no node has a name in the zone.
    expect(await change(t, serverId, { originDns: null })).toMatchObject({
      state: 'ready',
      generation: 3,
    });
    expect((await setupOf(t, serverId))!.originDns).toBeNull();
    expect(panel.writes.length).toBe(writes);
  });

  test('origin names go into the zone picked, one of the zones the DNS account reaches', async () => {
    const { t, serverId } = await seed();
    await runSetup(t, serverId);
    const acct = await createAccount(t, { provider: 'cloudflare', name: 'dns' });
    // A second zone the token reaches, as a listing found it.
    await t.mutation(internal.edgeProviderCatalog.record, {
      accountId: acct,
      lists: [
        {
          kind: 'zones',
          items: [
            { id: 'a'.repeat(32), label: 'example.org', facts: { status: 'active' } },
            { id: 'b'.repeat(32), label: 'example.net', facts: { status: 'active' } },
            { id: 'c'.repeat(32), label: 'pending.example.org', facts: { status: 'pending' } },
          ],
        },
      ],
      errors: [],
    });
    // Two zones: the account alone does not say which.
    await expect(change(t, serverId, { originDns: { accountId: acct } })).rejects.toThrow(
      /origin_zone_required/,
    );
    await expect(
      change(t, serverId, { originDns: { accountId: acct, zoneId: 'd'.repeat(32) } }),
    ).rejects.toThrow(/origin_zone_unknown/);
    await expect(
      change(t, serverId, { originDns: { accountId: acct, zoneId: 'c'.repeat(32) } }),
    ).rejects.toThrow(/origin_zone_inactive/);
    expect(
      await change(t, serverId, { originDns: { accountId: acct, zoneId: 'b'.repeat(32) } }),
    ).toMatchObject({ state: 'ready', started: false });
    expect((await setupOf(t, serverId))!.originDns).toEqual({
      accountId: acct,
      zoneId: 'b'.repeat(32),
      zoneName: 'example.net',
    });
    // The account alone now keeps the zone the setup has with it.
    expect(await change(t, serverId, { originDns: { accountId: acct } })).toMatchObject({
      started: false,
    });
    expect((await setupOf(t, serverId))!.originDns?.zoneId).toBe('b'.repeat(32));
    // The zone the setup has stays while its account is switched off (another
    // change of the setup may still go through); a new pick needs it on.
    await t.run((ctx) => ctx.db.patch(acct, { enabled: false }));
    expect(await change(t, serverId, { originDns: { accountId: acct } })).toMatchObject({
      started: false,
    });
    await expect(
      change(t, serverId, { originDns: { accountId: acct, zoneId: 'a'.repeat(32) } }),
    ).rejects.toThrow(/origin_account_unusable/);
    await t.run((ctx) => ctx.db.patch(acct, { enabled: true }));
    // A front account is no DNS account.
    const front = await createAccount(t, {
      provider: 'fastly',
      name: 'front',
      settings: { certificateAuthority: 'certainly' },
    });
    await expect(change(t, serverId, { originDns: { accountId: front } })).rejects.toThrow(
      /origin_account_unusable/,
    );
  });

  test('a setup that never got to ready proves nothing: what is on the backend still asks for adoption', async () => {
    const { t, serverId, panel } = await seed();
    await t.mutation(internal.sniFamilies.create, {
      slug: 'fam-empty',
      label: 'fam-empty',
      targetAddress: 'decoy-c.example',
      targetPort: 443,
    });
    const failed = await runSetup(t, serverId, {
      ...setupInput,
      modes: setupInput.modes.map((m) =>
        m.slug === 'privacy-reality' ? { ...m, familySlug: 'fam-empty' } : m,
      ),
    });
    expect(failed).toMatchObject({ state: 'failed', code: 'servers.family_empty' });
    expect(failed.readyAt).toBeUndefined();
    panel.nodes.push({
      uuid: UUID(99),
      name: 'stranger',
      address: '192.0.2.99',
      port: 2222,
      countryCode: 'XX',
      isDisabled: false,
      lastStatusChange: 't0',
      configProfile: { activeConfigProfileUuid: UUID(98), activeInbounds: [] },
    });
    await t.action(internal.backendObserve.refresh, { backendServerId: serverId });
    await expect(change(t, serverId)).rejects.toThrow(/adopt_required/);
    expect(
      BackendSetupView.parse(
        await t.query(internal.backendSetup.view, { backendServerId: serverId }),
      ).established,
    ).toBe(false);
    expect(panel.writes).toHaveLength(0);
    const adopted = await runSetup(t, serverId, { ...setupInput, adopt: true });
    expect(adopted).toMatchObject({ state: 'ready', adopted: true });
  });

  test('what nodes and members rely on stays as it is: refused before anything is written', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    await enroll(t, serverId, 'node-a', 'privacy-reality');
    const writes = panel.writes.length;
    const [direct, l4, xhttp, ws] = setupInput.modes as [ModeArg, ModeArg, ModeArg, ModeArg];
    await expect(change(t, serverId, { profileName: 'Other-Config' })).rejects.toThrow(
      /setup_profile_kept/,
    );
    await expect(change(t, serverId, { modes: [direct, l4, ws] })).rejects.toThrow(
      /setup_mode_kept:freedom-xhttp/,
    );
    const moves: [ModeArg, string][] = [
      [{ ...ws, ws: { path: '/ws', port: 9443 } }, 'freedom-ws'],
      [{ ...ws, ws: { path: '/feed', port: 8443 } }, 'freedom-ws'],
      [{ ...direct, familySlug: 'fam-fronted' }, 'privacy-reality'],
      [{ ...direct, name: 'Private' }, 'privacy-reality'],
      [{ ...l4, acceptProxyProtocol: true }, 'freedom-reality'],
      [{ ...l4, shape: { transport: 'reality', fronting: 'direct' } }, 'freedom-reality'],
    ];
    for (const [moved, slug] of moves) {
      const modes = [direct, l4, xhttp, ws].map((m) => (m.slug === slug ? moved : m));
      await expect(change(t, serverId, { modes })).rejects.toThrow(
        new RegExp(`setup_mode_kept:${slug}`),
      );
    }

    expect(panel.writes.length).toBe(writes);

    // The zone, while a WebSocket node has a name in it.
    const zoneA = await createAccount(t, { provider: 'cloudflare', name: 'dns-a' });
    await change(t, serverId, { originDns: { accountId: zoneA } });
    await enroll(t, serverId, 'node-w', 'freedom-ws');
    const enrolled = panel.writes.length;
    const zoneB = await createAccount(t, {
      provider: 'cloudflare',
      name: 'dns-b',
      settings: { zoneId: 'b'.repeat(32), zoneName: 'example.net' },
    });
    await expect(change(t, serverId, { originDns: { accountId: zoneB } })).rejects.toThrow(
      /origin_zone_in_use/,
    );
    await expect(change(t, serverId, { originDns: null })).rejects.toThrow(/origin_zone_in_use/);
    // Another account holding the same zone is fine: every name stays what it is.
    const zoneA2 = await createAccount(t, { provider: 'cloudflare', name: 'dns-a2' });
    expect(await change(t, serverId, { originDns: { accountId: zoneA2 } })).toMatchObject({
      state: 'ready',
      started: false,
    });
    expect((await setupOf(t, serverId))!.originDns).toMatchObject({
      accountId: zoneA2,
      zoneName: 'example.org',
    });
    // Nothing on the backend or in the zone moved for any of it.
    expect(panel.writes.length).toBe(enrolled);
  });

  test('a new mode needs its transport in the profile first', async () => {
    const { t, serverId, panel } = await seed();
    const [direct, l4, xhttp, ws] = setupInput.modes;
    await runSetup(t, serverId, { ...setupInput, modes: [direct!, l4!, ws!] });
    const writes = panel.writes.length;
    await expect(change(t, serverId, { modes: [direct!, l4!, ws!, xhttp!] })).rejects.toThrow(
      /setup_transport_missing:FREEDOM_XHTTP:missing/,
    );
    expect((await setupOf(t, serverId))!).toMatchObject({ state: 'ready', generation: 1 });
    expect(panel.writes.length).toBe(writes);
  });

  test('a mode a stopped run never set up can be taken out again, with no adoption asked', async () => {
    const { t, serverId, panel } = await seed();
    const [direct, l4, xhttp, ws] = setupInput.modes as [ModeArg, ModeArg, ModeArg, ModeArg];
    const first = await runSetup(t, serverId, { ...setupInput, modes: [direct, l4, ws] });
    await enroll(t, serverId, 'node-a', 'privacy-reality');
    // The last look said the profile had the transport; the backend says otherwise.
    await t.run(async (ctx) => {
      const p = (await ctx.db
        .query('panelProfiles')
        .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
        .first())!;
      const like = p.inbounds.find((i) => i.tag === 'FREEDOM_REALITY')!;
      await ctx.db.patch(p._id, {
        inbounds: [
          ...p.inbounds,
          { ...like, tag: 'FREEDOM_XHTTP', inboundUuid: UUID(77), network: 'xhttp', path: '/' },
        ],
      });
    });
    const stopped = await runSetup(t, serverId, {
      ...setupInput,
      modes: [direct, l4, ws, xhttp],
    });
    expect(stopped).toMatchObject({ state: 'failed' });
    expect(stopped.code).toMatch(/^servers\.profile_incompatible:FREEDOM_XHTTP:missing/);
    // Still FCP's backend: its own node asks for no adoption, and the mode
    // that never got set up goes again; the rest stays as it was.
    expect(
      BackendSetupView.parse(
        await t.query(internal.backendSetup.view, { backendServerId: serverId }),
      ).established,
    ).toBe(true);
    const writes = panel.writes.length;
    const back = await runSetup(t, serverId, { ...setupInput, modes: [direct, l4, ws] });
    expect(back).toMatchObject({ state: 'ready', adopted: false });
    expect(back.modes).toEqual(first.modes);
    expect(panel.writes.length).toBe(writes);
  });

  test('a node reconciled while the setup runs waits pending and goes on once the setup is ready', async () => {
    const { t, serverId } = await seed();
    const first = await runSetup(t, serverId);
    const { intentId } = await enroll(t, serverId, 'node-a', 'privacy-reality');
    await t.action(internal.nodeIntents.bootstrap, { intentId });
    // A run of the setup is under way (a change, or one an attempt left pending).
    await t.run((ctx) => ctx.db.patch(first._id, { state: 'pending' }));
    // The role reports meanwhile: its reconcile can read nothing, and lets go.
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
    });
    const waiting = await runIntent(t, intentId);
    expect(waiting).toMatchObject({ state: 'pending', code: 'servers.setup_running' });
    expect(waiting.claim).toBeUndefined();
    expect(waiting.activation.stage).toBe('machine_applied');
    // The setup runs to ready, and the node is reconciled at once, not by the sweep.
    const ready = await runSetup(t, serverId);
    expect(ready.state).toBe('ready');
    const done = await until(
      () => t.run((ctx) => ctx.db.get(intentId)),
      (i) => !i!.claim && i!.state !== 'pending',
    );
    expect(done).toMatchObject({ state: 'ready' });
    expect(done!.activation.stage).toBe('machine_ready');
  });

  test('a WebSocket node enrolled before there was a zone takes its managed name when the zone comes', async () => {
    const { t, serverId } = await seed();
    await runSetup(t, serverId);
    const waiting = await enroll(t, serverId, 'node-w', 'freedom-ws');
    expect(waiting.intent).toMatchObject({
      state: 'blocked',
      code: 'servers.origin_hostname_missing',
      machineRevision: 1,
      settings: { originHostnameSource: 'explicit' },
    });
    // One with a hostname of its own keeps it.
    const own = await enroll(t, serverId, 'node-own', 'freedom-ws');
    await t.mutation(internal.nodeIntents.patchSettings, {
      intentId: own.intentId,
      patch: { explicitHostname: 'own.example.net' },
    });
    const ownBefore = await runIntent(t, own.intentId);

    const acct = await createAccount(t, { provider: 'cloudflare', name: 'dns' });
    await change(t, serverId, { originDns: { accountId: acct } });
    const named = await until(
      () => t.run((ctx) => ctx.db.get(waiting.intentId)),
      (i) => i!.settings.originHostnameSource === 'managed' && !i!.claim,
    );
    expect(named!.machineRevision).toBe(2);
    expect(named!.code).not.toBe('servers.origin_hostname_missing');
    const origin = await t.run((ctx) => enrolledOriginOf(ctx, serverId, 'node-w'));
    expect(origin!.originAddress).toBe('node-w.example.org');
    const ownAfter = (await t.run((ctx) => ctx.db.get(own.intentId)))!;
    expect(ownAfter.settings).toEqual(ownBefore.settings);
    expect(ownAfter.machineRevision).toBe(ownBefore.machineRevision);
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).filter(
      (a) =>
        a.action === 'servers.node.settings' &&
        (a.payload as { change?: string }).change === 'origin_name',
    );
    expect(audit.map((a) => (a.payload as { name: string }).name)).toEqual(['node-w']);

    // While a change of the setup runs, edges keep dialing the same name.
    await t.run(async (ctx) => {
      const row = await ctx.db
        .query('panelSetups')
        .withIndex('by_server', (q) => q.eq('backendServerId', serverId))
        .unique();
      await ctx.db.patch(row!._id, { state: 'pending' });
    });
    expect((await t.run((ctx) => enrolledOriginOf(ctx, serverId, 'node-w')))!.originAddress).toBe(
      'node-w.example.org',
    );
  });
});

/**
 * A WebSocket node's managed origin name, in the order the role runs: enroll
 * (`PUT`), wait for `ready`, bootstrap, wait for `origin.dns` to say
 * `resolves`, set the machine up (Caddy's certificate needs the name), report
 * applied. FCP has to prove the name resolves BEFORE the applied report: the
 * role never gets to it otherwise.
 */
describe("a front node's origin name", () => {
  const NAME = 'node-w';
  const HOST = 'node-w.example.org';
  const V4 = '203.0.113.10';

  async function frontNode() {
    const s = await seed();
    const acct = await createAccount(s.t, { provider: 'cloudflare', name: 'dns' });
    await runSetup(s.t, s.serverId, { ...setupInput, originDns: { accountId: acct } });
    return s;
  }
  /** The role's `PUT`: enroll, or report this run's observations. */
  async function put(t: T, serverId: Id<'backendServers'>) {
    const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: NAME,
      mode: 'freedom-ws',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4: V4 },
        capabilities: { caddy: true, ipv6: false },
      },
    });
    return intentId;
  }
  const view = async (t: T, serverId: Id<'backendServers'>) =>
    NodeRoleView.parse(
      await t.query(internal.nodeIntents.roleViewByName, { backendServerId: serverId, name: NAME }),
    );
  /** The role's two waits before it sets the machine up (register_node.yml). */
  const roleWaitsPass = (v: NodeRoleView) =>
    ['ready', 'blocked'].includes(v.registration.state) &&
    ['resolves', 'none'].includes(v.origin.dns);
  const quickRetries = (t: T) =>
    t.run(async (ctx) =>
      (await ctx.db.system.query('_scheduled_functions').collect()).filter(
        (j) => /nodeIntents(\.js)?:resume$/.test(j.name) && j.state.kind === 'pending',
      ),
    );
  const windowChecks = (t: T) =>
    t.run(async (ctx) =>
      (await ctx.db.system.query('_scheduled_functions').collect()).filter(
        (j) => /nodeIntents(\.js)?:afterRoleRunWindow$/.test(j.name) && j.state.kind === 'pending',
      ),
    );
  const ingressOk = {
    resolves: true,
    answers: { v4: [V4], v6: [] },
    tlsValid: true,
    certNames: [HOST],
    pathProxied: true,
    foreignHostAnswered: true,
  };

  test('the name resolves before the applied report: the role is never left waiting on it', async () => {
    const { t, serverId, panel } = await frontNode();
    const ingress: string[] = [];
    __setFrontIngressCheckForTests(async (a) => {
      ingress.push(a.hostname);
      return ingressOk;
    });
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    await t.action(internal.nodeIntents.bootstrap, { intentId });

    // The record is FCP's, and public resolvers answer the node's address.
    expect(panel.zone).toMatchObject([
      { type: 'A', name: HOST, content: V4, comment: `fcp-origin:${FIXTURE_PANEL_SLUG}:${NAME}` },
    ]);
    const v = await view(t, serverId);
    expect(v).toMatchObject({
      registration: { state: 'ready', code: null },
      stage: 'bootstrap_available',
      appliedRevision: null,
      origin: { hostname: HOST, dns: 'resolves' },
    });
    // What the deadlock was: `created` here, and `resolves` only after an
    // applied report the role sends once it has seen `resolves`.
    expect(roleWaitsPass(v)).toBe(true);
    expect(panel.lookups).toEqual([HOST]);
    // Nothing was dialled: TLS, the path and the foreign Host wait for the machine.
    expect(ingress).toEqual([]);
  });

  test('a name that does not resolve yet parks the node and is looked at again shortly', async () => {
    const { t, serverId, panel } = await frontNode();
    panel.resolving = false;
    const intentId = await put(t, serverId);
    const parked = await runIntent(t, intentId);
    expect(parked).toMatchObject({
      state: 'pending',
      code: 'servers.origin_not_resolving',
      origin: { hostname: HOST, dns: 'created' },
    });
    expect(roleWaitsPass(await view(t, serverId))).toBe(false);
    // The role is in contact: a retry in 30 seconds, not at the next sweep.
    const retries = await quickRetries(t);
    expect(retries).toHaveLength(1);
    expect(retries[0]!.scheduledTime - parked.updatedAt).toBeGreaterThanOrEqual(29_000);
    expect(retries[0]!.scheduledTime - parked.updatedAt).toBeLessThanOrEqual(31_000);

    // The name propagates; the retry fires.
    panel.resolving = true;
    await t.mutation(internal.nodeIntents.resume, { intentId });
    const ready = await runIntent(t, intentId);
    expect(ready).toMatchObject({ state: 'ready', origin: { dns: 'resolves' } });
    expect(ready.code).toBeUndefined();
    expect(roleWaitsPass(await view(t, serverId))).toBe(true);
    // One record, written once: the retry only looked.
    expect(panel.zone).toHaveLength(1);
    expect(panel.writes.filter((w) => w.call.startsWith('POST /client/v4/'))).toHaveLength(1);
  });

  test('the role runs again: a kept record keeps `resolves`; a moved one asks again', async () => {
    const { t, serverId, panel } = await frontNode();
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    expect(panel.lookups).toEqual([HOST]);

    // The next deploy runs the role again: the same observations, the same record.
    await put(t, serverId);
    const again = await runIntent(t, intentId);
    expect(again).toMatchObject({ state: 'ready', origin: { dns: 'resolves' } });
    expect(panel.lookups).toEqual([HOST]);
    expect(panel.writes.filter((w) => w.call.includes('/client/v4/'))).toHaveLength(1);

    // The record moved under it (FCP's own, other content): replaced, proved again.
    panel.zone[0]!.content = '203.0.113.99';
    await t.mutation(internal.nodeIntents.reconcileNow, { intentId });
    const replaced = await runIntent(t, intentId);
    expect(replaced).toMatchObject({ state: 'ready', origin: { dns: 'resolves' } });
    expect(panel.zone).toMatchObject([{ content: V4 }]);
    expect(panel.lookups).toEqual([HOST, HOST]);
  });

  test('the applied report still brings the full machine check; the proof is never taken back', async () => {
    const { t, serverId } = await frontNode();
    const ingress: { hostname: string; expected: unknown }[] = [];
    let check = { ...ingressOk, tlsValid: false };
    __setFrontIngressCheckForTests(async (a) => {
      ingress.push({ hostname: a.hostname, expected: a.expected });
      return check;
    });
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    await t.action(internal.nodeIntents.bootstrap, { intentId });
    expect(ingress).toEqual([]);

    // Caddy has no certificate yet.
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: false,
    });
    const waiting = await runIntent(t, intentId);
    expect(waiting).toMatchObject({
      state: 'pending',
      code: 'servers.origin_certificate',
      origin: { dns: 'resolves' },
    });
    expect(waiting.activation.stage).toBe('machine_applied');
    expect(ingress).toEqual([{ hostname: HOST, expected: { v4: V4, v6: null } }]);

    check = ingressOk;
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: true,
    });
    const ready = await runIntent(t, intentId);
    expect(ready).toMatchObject({ state: 'ready', origin: { dns: 'resolves' } });
    expect(ready.activation.stage).toBe('machine_ready');
    expect(ready.activation.evidence.map((e) => e.kind).sort()).toEqual([
      'dns_resolves',
      'ingress_verified',
      'machine_applied',
      'machine_ready',
    ]);
    expect(ingress).toHaveLength(2);
  });

  test('a role run repairing a machine that is down is not held behind the machine check', async () => {
    const { t, serverId, panel } = await frontNode();
    __setFrontIngressCheckForTests(async () => ingressOk);
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: true,
    });
    expect(await runIntent(t, intentId)).toMatchObject({ state: 'ready' });

    // The machine goes down; the sweep sees it.
    panel.offline = true;
    await t.mutation(internal.nodeIntents.reconcileNow, { intentId });
    expect(await runIntent(t, intentId)).toMatchObject({
      state: 'pending',
      code: 'servers.node_offline',
    });

    // The operator runs the role to bring it back. Its `PUT` is answered
    // `ready` (the row is in line), so it goes on to start the node: the
    // machine is looked at when this run reports, not before.
    await new Promise((r) => setTimeout(r, 2));
    await put(t, serverId);
    const during = await runIntent(t, intentId);
    expect(during).toMatchObject({ state: 'ready', origin: { dns: 'resolves' } });
    expect(during.code).toBeUndefined();
    expect(roleWaitsPass(await view(t, serverId))).toBe(true);
    // A ready node is not on the sweep: the end of the run's window comes back for it.
    const windows = await windowChecks(t);
    expect(windows).toHaveLength(1);
    expect(windows[0]!.args[0]).toEqual({ intentId, observedAt: during.observed.at });
    expect(windows[0]!.scheduledTime - during.observed.at).toBeGreaterThanOrEqual(19 * 60_000);

    panel.offline = false;
    await new Promise((r) => setTimeout(r, 2));
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: true,
    });
    expect(await runIntent(t, intentId)).toMatchObject({ state: 'ready' });
    // The run reported: the end of its window has nothing to do.
    expect(
      await t.mutation(internal.nodeIntents.afterRoleRunWindow, {
        intentId,
        observedAt: during.observed.at,
      }),
    ).toBe(false);

    // A run that never reports is over once its window is: the machine is
    // looked at again, and found down.
    panel.offline = true;
    await new Promise((r) => setTimeout(r, 2));
    await put(t, serverId);
    expect(await runIntent(t, intentId)).toMatchObject({ state: 'ready' });
    const observedAt = Date.now() - 21 * 60_000;
    await t.run(async (ctx) => {
      const i = (await ctx.db.get(intentId))!;
      await ctx.db.patch(intentId, {
        observed: { ...i.observed, at: observedAt },
        appliedAt: Date.now() - 30 * 60_000,
      });
    });
    expect(
      await t.mutation(internal.nodeIntents.afterRoleRunWindow, { intentId, observedAt }),
    ).toBe(true);
    expect(await runIntent(t, intentId)).toMatchObject({
      state: 'pending',
      code: 'servers.node_offline',
    });
  });

  /** Live, as a committed go-live leaves it. */
  const makeLive = (t: T, intentId: Id<'panelNodeIntents'>) =>
    t.run(async (ctx) => {
      const i = (await ctx.db.get(intentId))!;
      await ctx.db.patch(intentId, {
        activation: { ...i.activation, stage: 'live' },
        delivery: {
          ...i.delivery,
          disposition: 'live',
          acceptingAssignments: true,
          exposure: { ...i.delivery.exposure, everLive: true },
        },
        approved: {
          machineRevision: i.machineRevision,
          configRevision: i.configRevision ?? '',
          authRevision: i.authRevision,
          deliveryRevision: i.deliveryRevision ?? '',
          reviewHash: 'approved',
          approvedAt: Date.now(),
          committed: { hostUuids: [], edgeIds: [] },
        },
      });
    });
  const putAt = (t: T, serverId: Id<'backendServers'>, v4: string) =>
    t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: NAME,
      mode: 'freedom-ws',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4 },
        capabilities: { caddy: true, ipv6: false },
      },
    });

  // Whoever holds the node's token could otherwise move where the edges send
  // members: an endpoint that moves under a live node is taken out first.
  test('a live node reported at another address closes before its origin record moves, and is verified again', async () => {
    const { t, serverId, panel } = await frontNode();
    __setFrontIngressCheckForTests(async () => ingressOk);
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: true,
    });
    await runIntent(t, intentId);
    await makeLive(t, intentId);
    expect((await gateOfNode(t, { backendServerId: serverId, nodeName: NAME })).state).toBe('open');

    await putAt(t, serverId, '198.51.100.66');
    const after = await runIntent(t, intentId);
    expect(after.delivery.disposition).toBe('unavailable');
    expect(after.maintenance?.reason).toBe('drift');
    expect((await gateOfNode(t, { backendServerId: serverId, nodeName: NAME })).state).toBe(
      'blocked',
    );
    // The gate closed in the report's own transaction, before the record was rewritten.
    const obligations = await t.run((ctx) => ctx.db.query('backendObligations').collect());
    const moved = obligations.find(
      (o) => o.kind === 'dns.record' && o.verb === 'create' && o.intent.includes('198.51.100.66'),
    )!;
    expect(moved.createdAt).toBeGreaterThanOrEqual(after.maintenance!.since);
    expect(panel.zone).toMatchObject([{ type: 'A', name: HOST, content: '198.51.100.66' }]);
    // What was proved at the old address no longer holds: the role applies the
    // new revision, the machine is checked again, and only an approval reopens it.
    expect(after.machineRevision).toBe(2);
    expect(
      after.activation.evidence.filter((e) => e.machineRevision === after.machineRevision),
    ).toEqual([]);
    expect(after.activation.stage).toBe('bootstrap_available');
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    expect(
      audit
        .filter((a) => a.action === 'servers.node.drift')
        .map((a) => (a.payload as { kind: string }).kind),
    ).toEqual(['endpoint']);
  });

  // A retirement takes the node away from every attempt that read it before.
  test('an attempt in flight when the node is retired records nothing, and nothing brings the node back', async () => {
    const { t, serverId, panel } = await frontNode();
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    expect(panel.zone).toHaveLength(1);
    // An attempt holds the lease (a reconcile in flight).
    const inFlight = await t.run(async (ctx) => {
      const i = (await ctx.db.get(intentId))!;
      await ctx.db.patch(intentId, { claim: { attemptId: 'A', expiresAt: Date.now() + 600_000 } });
      return { intentId, generation: i.generation, attemptId: 'A' };
    });
    await t.mutation(internal.nodeIntents.requestRetirement, { intentId, requestedBy: 'admin' });
    // It ends as reconcile's stop() does: fenced, the node stays retiring.
    expect(
      await t.mutation(internal.nodeIntents.progress, {
        ...inFlight,
        patch: { state: 'pending', code: 'servers.origin_not_resolving', release: true },
      }),
    ).toEqual({ ok: false });
    // Nor may it open a record write.
    const opened = await t.mutation(internal.backendObligations.open, {
      backendServerId: serverId,
      ownerKind: 'intent',
      ownerId: intentId,
      ownerGeneration: inFlight.generation,
      attemptId: 'A',
      kind: 'dns.record',
      identity: `A:${HOST}`,
      verb: 'create',
      ownership: 'created',
      intent: JSON.stringify({ type: 'A', name: HOST, content: V4 }),
    });
    expect(opened.ok).toBe(false);
    expect((await t.run((ctx) => ctx.db.get(intentId)))!.state).toBe('retiring');
    expect((await t.query(internal.nodeIntents.stale, { now: Date.now() })).intents).not.toContain(
      intentId,
    );
    await expect(t.action(internal.nodeIntents.bootstrap, { intentId })).rejects.toThrow(
      /node_retiring/,
    );
    // The ladder withdraws the record; the sweep's resume reconciles nothing.
    for (let i = 0; i < 100; i++) await new Promise((r) => setTimeout(r, 5));
    const r = (await t.run((ctx) => ctx.db.query('panelRetirements').collect()))[0]!;
    expect(r.step).toBe('panel_row');
    expect(panel.zone).toEqual([]);
    expect(await t.mutation(internal.nodeIntents.resume, { intentId })).toBe(false);
    for (let i = 0; i < 40; i++) await new Promise((r) => setTimeout(r, 5));
    expect(panel.zone).toEqual([]);
  });

  test('a record written with an account since replaced (same zone) and removed is still withdrawn', async () => {
    const { t, serverId, panel } = await seed();
    const acct = await createAccount(t, { provider: 'cloudflare', name: 'dns' });
    await runSetup(t, serverId, { ...setupInput, originDns: { accountId: acct } });
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    expect(panel.zone).toHaveLength(1);
    // Another account holding the same zone replaces the first, which goes.
    const acct2 = await createAccount(t, { provider: 'cloudflare', name: 'dns-2' });
    expect(
      await t.mutation(internal.backendSetup.start, {
        backendServerId: serverId,
        input: { ...setupInput, originDns: { accountId: acct2 } },
      }),
    ).toMatchObject({ state: 'ready', started: false });
    await t.mutation(internal.edgeProviderAccounts.remove, { id: acct });
    await t.mutation(internal.nodeIntents.requestRetirement, { intentId, requestedBy: 'admin' });
    for (let i = 0; i < 100; i++) await new Promise((r) => setTimeout(r, 5));
    const r = (await t.run((ctx) => ctx.db.query('panelRetirements').collect()))[0]!;
    expect(r.code).not.toBe('servers.obligation_unresolved');
    expect(r.step).toBe('panel_row');
    expect(panel.zone).toEqual([]);
  });

  test('a node given a hostname of its own drops the managed record it had', async () => {
    const { t, serverId, panel } = await frontNode();
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    expect(panel.zone).toHaveLength(1);
    await t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: 'own.example.net' },
    });
    await runIntent(t, intentId);
    expect(panel.zone).toEqual([]);
    const owned = (await t.run((ctx) => ctx.db.query('backendObligations').collect())).filter(
      (o) => o.kind === 'dns.record' && o.verb === 'create' && o.state === 'confirmed',
    );
    expect(owned).toEqual([]);
  });

  // A record write whose answer was lost may still have landed: it is not
  // forgotten because the name it was for is no longer wanted.
  test('a managed record whose write was never settled is withdrawn too, once its attempt is over', async () => {
    const { t, serverId, panel } = await frontNode();
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    expect(panel.zone).toHaveLength(1);
    // The create landed, but its answer was lost: the write is still `sent`.
    const unsettled = (await t.run((ctx) => ctx.db.query('backendObligations').collect())).find(
      (o) => o.kind === 'dns.record' && o.verb === 'create',
    )!;
    await t.run((ctx) => ctx.db.patch(unsettled._id, { state: 'sent' }));
    await t.mutation(internal.nodeIntents.patchSettings, {
      intentId,
      patch: { explicitHostname: 'own.example.net' },
    });
    // While the attempt that sent it could still be running, it is waited for.
    expect(await runIntent(t, intentId)).toMatchObject({
      state: 'pending',
      code: 'servers.obligation_unresolved',
    });
    expect(panel.zone).toHaveLength(1);
    // Once it cannot be, it is looked for by name and marker, and withdrawn.
    await t.run((ctx) => ctx.db.patch(unsettled._id, { updatedAt: Date.now() - 11 * 60_000 }));
    await t.mutation(internal.nodeIntents.resume, { intentId });
    await runIntent(t, intentId);
    expect(panel.zone).toEqual([]);
    expect((await t.run((ctx) => ctx.db.get(unsettled._id)))!).toMatchObject({
      state: 'failed',
      code: 'withdrawn',
    });
  });

  // A write an attempt of the node sent before the retirement may land after
  // it: the ladder waits for it, then removes what it made.
  test('a retirement waits for a node write already sent, then removes what it made', async () => {
    const { t, serverId, panel } = await seed();
    await runSetup(t, serverId);
    // The backend takes the node create, but does not show the node yet.
    const held: any[] = [];
    const inner = globalThis.fetch;
    vi.stubGlobal('fetch', async (input: string | URL, init: RequestInit = {}) => {
      const res = await inner(input, init);
      const url = new URL(typeof input === 'string' ? input : input.toString());
      if (url.pathname === '/api/nodes' && (init.method ?? 'GET').toUpperCase() === 'POST')
        held.push(...panel.nodes.splice(0));
      return res;
    });
    const { intentId } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: 'node-b',
      mode: 'privacy-reality',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.11', port: 2222 },
        publicIps: { v4: '203.0.113.11' },
        capabilities: { caddy: false, ipv6: false },
      },
    });
    expect(await runIntent(t, intentId)).toMatchObject({
      state: 'pending',
      code: 'servers.op_running',
    });
    expect(held).toHaveLength(1);
    await t.mutation(internal.nodeIntents.requestRetirement, { intentId, requestedBy: 'admin' });
    for (let i = 0; i < 100; i++) await new Promise((r) => setTimeout(r, 5));
    const retirement = async () =>
      (await t.run((ctx) => ctx.db.query('panelRetirements').collect()))[0]!;
    expect(await retirement()).toMatchObject({
      stage: 'draining',
      step: 'addresses',
      code: 'servers.op_running',
    });

    // The node shows up: the write settles, and the ladder removes the row.
    panel.nodes.push(...held);
    const op = (await t.run((ctx) => ctx.db.query('panelOps').collect())).find(
      (o) => o.kind === 'node' && o.verb === 'create',
    )!;
    expect(await t.action(internal.backendWrites.run, { opId: op._id })).toEqual({ open: false });
    const { retirementId } = { retirementId: (await retirement())._id };
    await t.action(internal.nodeRetirement.advance, { retirementId });
    expect(panel.writes.some((w) => w.call === `DELETE /api/nodes/${held[0].uuid}`)).toBe(true);
    // Its own removal still waits at the backend row, not behind itself.
    await t.action(internal.nodeRetirement.advance, { retirementId });
    expect((await retirement()).step).toBe('panel_row');
  });

  test("the role's report fences an attempt that looked at the machine before it", async () => {
    const { t, serverId } = await frontNode();
    __setFrontIngressCheckForTests(async () => ingressOk);
    const intentId = await put(t, serverId);
    await runIntent(t, intentId);
    await t.mutation(internal.nodeIntents.applied, {
      intentId,
      appliedRevision: 1,
      nodeStarted: true,
      certificateReady: true,
    });
    const before = await runIntent(t, intentId);
    expect(before).toMatchObject({ state: 'ready' });

    // A reconcile is probing the machine (the path is not proxied: Caddy is
    // broken) when the role's run to repair it reports its observations.
    let entered = false;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let probes = 0;
    __setFrontIngressCheckForTests(async () => {
      probes++;
      entered = true;
      await gate;
      return { ...ingressOk, pathProxied: false };
    });
    await t.mutation(internal.nodeIntents.reconcileNow, { intentId });
    for (let i = 0; i < 500 && !entered; i++) await new Promise((r) => setTimeout(r, 5));
    expect(entered).toBe(true);
    await new Promise((r) => setTimeout(r, 2));
    const { generation } = await t.mutation(internal.nodeIntents.enroll, {
      backendServerId: serverId,
      name: NAME,
      mode: 'freedom-ws',
      contractVersion: 2,
      observed: {
        management: { address: '192.0.2.10', port: 2222 },
        publicIps: { v4: V4 },
        capabilities: { caddy: true, ipv6: false },
      },
    });
    // Unchanged observations, yet the attempt holding the lease is fenced.
    expect(generation).toBe(before.generation + 1);
    release();

    // Its failure is not recorded: the handover reconciles the run's node.
    const after = await runIntent(t, intentId);
    expect(after).toMatchObject({ state: 'ready', generation: before.generation + 1 });
    expect(after.code).toBeUndefined();
    expect(roleWaitsPass(await view(t, serverId))).toBe(true);
    expect(probes).toBe(1);
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

  test('the new hash is recorded, not matched, before the write: activation holds until the outcome', async () => {
    const { t, panel, row } = await readyOnEarlierRelease();
    const singbox = await templateHash(SUBSCRIPTION_TEMPLATES.SINGBOX);
    let during: Awaited<ReturnType<typeof getRow>> = null;
    const getRow = () => t.run((ctx) => ctx.db.get(row._id));
    panel.onTemplateWrite = async () => {
      during = await getRow();
    };
    expect(await resync(t)).toBe(1);
    expect(during!.claim).toBeDefined();
    expect(during!.templates[0]).toEqual({ family: 'SINGBOX', hash: singbox, state: 'drifted' });
    expect(during!.templates[1]!.state).toBe('matched');
    expect((await getRow())!.templates[0]).toEqual({
      family: 'SINGBOX',
      hash: singbox,
      state: 'matched',
    });
  });

  test('server changes switched off during a re-sync stop the next write; the staged record is retried', async () => {
    const { t, panel, row } = await readyOnEarlierRelease();
    panel.onTemplateRead = async () => {
      await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': false } });
    };
    expect(await resync(t)).toBe(0);
    expect(templateWrites(panel)).toHaveLength(1); // the setup's own install only
    const parked = (await t.run((ctx) => ctx.db.get(row._id)))!;
    expect(parked.claim).toBeUndefined();
    expect(parked.templates[0]!.state).toBe('drifted');
    panel.onTemplateRead = undefined;
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
    expect(await resync(t)).toBe(1);
    expect((await t.run((ctx) => ctx.db.get(row._id)))!.templates[0]!.state).toBe('matched');
  });

  test('hourly, the live templates are looked at again: a change made on the backend is put back', async () => {
    const { t, serverId, panel } = await seed();
    addTemplates(panel);
    const row = await runSetup(t, serverId);
    expect(row.templatesCheckedAt).toBeTypeOf('number');
    // Edited on the backend; the record still says matched.
    panel.templates[0]!.templateJson = earlierSingbox();
    expect(await resync(t)).toBe(0);
    await t.run((ctx) =>
      ctx.db.patch(row._id, { templatesCheckedAt: Date.now() - TEMPLATE_RECHECK_MS }),
    );
    expect(await resync(t)).toBe(1);
    expect(panel.templates[0]!.templateJson).toEqual(SUBSCRIPTION_TEMPLATES.SINGBOX.body);
    expect(templateWrites(panel)).toHaveLength(2);
    expect(await installed(t)).toEqual(['SINGBOX:matched,MIHOMO:matched']);
    const audit = (await t.run((ctx) => ctx.db.query('auditLog').collect())).find(
      (a) => a.action === 'servers.setup.templates_installed',
    )!;
    expect(audit.payload).toMatchObject({ written: 'SINGBOX' });
    // Looked at again an hour later, nothing to write.
    await t.run((ctx) =>
      ctx.db.patch(row._id, { templatesCheckedAt: Date.now() - TEMPLATE_RECHECK_MS }),
    );
    expect(await resync(t)).toBe(1);
    expect(templateWrites(panel)).toHaveLength(2);
    expect(await installed(t)).toHaveLength(1);
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
    // (an adopted node's were named by whoever made them). One it has not
    // recorded is its own only on its transport, under the remark FCP gives
    // one of its names: anything else starting with its name is the operator's.
    const own = { configProfileInboundUuid: 't-reality' };
    const hosts = [
      { hostUuid: 'h1', remark: 'anything at all', configProfileInboundUuid: 't-ws' },
      { hostUuid: 'h2', remark: addressRemark('node-a', 'www.decoy-a.example'), ...own },
      { hostUuid: 'h3', remark: addressRemark('node-a-west', 'decoy-a.example'), ...own },
      { hostUuid: 'h4', remark: 'node-a | cdn', ...own },
      {
        hostUuid: 'h5',
        remark: addressRemark('node-a', 'decoy-a.example'),
        configProfileInboundUuid: 't-ws',
      },
    ];
    const transport = {
      uuid: 't-reality',
      serverNames: ['decoy-a.example', 'www.decoy-a.example'],
    };
    const intent = { name: 'node-a', addressUuids: ['h1'] };
    expect(addressesOf(intent, hosts, transport).map((h) => h.hostUuid)).toEqual(['h1', 'h2']);
    expect(addressesOf(intent, hosts, null).map((h) => h.hostUuid)).toEqual(['h1']);
  });
});
