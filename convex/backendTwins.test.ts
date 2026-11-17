/// <reference types="vite/client" />
/**
 * A mode's ENCRYPTED TWIN on a backend (convex/backendTwins.ts), against the
 * fake backend with the real setup, ledger, observation and routes: the
 * encrypted transport is added beside the mode's own, becomes the mode's twin
 * (its group then carries both), survives a change of the setup, and is taken
 * away again. Plus what is refused, and that no key is ever kept.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { insertPanelServer } from './lib/edges/testing/fixtures';
import { installFakeBackend } from './lib/edges/testing/fakeBackend';
import { jsonRes, routeFetch } from './lib/edges/testing/mockFetch';
import { signValue } from './lib/cookies';
import { twinProblem } from './lib/backend/modeTwin';
import { clientEncryption, generateVlessEncryption } from './lib/backend/vlessEncryption';
import { BackendSetupView, ProfilePatchPreview } from '../src/shared/contracts/servers';

const modules = import.meta.glob('./**/*.*s');

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

async function until<R>(get: () => Promise<R>, ok: (r: R) => boolean): Promise<R> {
  for (let i = 0; i < 600; i++) {
    const row = await get();
    if (ok(row)) return row;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error('did not settle');
}

const wsMode = {
  slug: 'freedom-ws',
  name: 'Freedom-WebSocket',
  shape: { transport: 'ws' as const, fronting: 'edge-l7' as const },
  acceptProxyProtocol: false,
  ws: { path: '/ws', port: 8443 },
};
const TWIN_TAG = 'FREEDOM_WEBSOCKET_E';

/** A backend set up with the WebSocket mode, and an admin's calls to it. */
async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
  const panel = installFakeBackend();
  await t.mutation(internal.seed.seedConnectionModes, {});
  await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
  const started = await t.mutation(internal.backendSetup.start, {
    backendServerId: serverId,
    input: { profileName: 'FreeSocks-Config', modes: [wsMode], originDns: null, adopt: false },
  });
  const row = await until(
    () => t.run((ctx) => ctx.db.get(started.setupId)),
    (r) => !!r && !r.claim,
  );
  expect(row!.state).toBe('ready');
  const adminUserId = await t.run((ctx) =>
    ctx.db.insert('adminUsers', {
      username: 'op',
      displayName: 'Op',
      isActive: true,
      updatedAt: Date.now(),
    }),
  );
  const sid = `asid-${Math.random().toString(36).slice(2)}`;
  await t.mutation(internal.sessions.create, { sid, kind: 'admin', adminUserId, ttlMs: 3_600_000 });
  const cookie = `fs_admin_session=${await signValue(sid, 'test-admin-sign')}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/servers/panel-a/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const setup = () => t.run((ctx) => ctx.db.get(started.setupId)).then((r) => r!);
  const mode = async () => (await setup()).modes!.find((m) => m.slug === 'freedom-ws')!;
  const group = async () => {
    const m = await mode();
    return panel.squads.find((s) => s.uuid === m.groupUuid)!;
  };
  const groupTransports = async () =>
    ((await group()).inbounds as { uuid: string }[]).map((i) => i.uuid).sort();
  return { t, serverId, panel, call, setup, mode, groupTransports, setupId: started.setupId };
}

type Seeded = Awaited<ReturnType<typeof seed>>;

/** "Add a transport" through the admin route: preview, then apply what it answered. */
async function addTransport(
  s: Seeded,
  tag: string,
  template: Record<string, unknown>,
): Promise<Record<string, any>> {
  const profileUuid = s.panel.profiles[0].uuid as string;
  const op = { op: 'addInboundFromTemplate', transportTag: tag, template };
  const res = await s.call('POST', `profiles/${profileUuid}/preview`, { ops: [op] });
  expect(res.status).toBe(200);
  const preview = ProfilePatchPreview.parse(await res.json());
  const applied = await s.call('POST', `profiles/${profileUuid}/apply`, {
    ops: preview.ops,
    baseToken: preview.baseToken,
    expectedToken: preview.expectedToken,
    transportUuids: preview.transportUuids,
  });
  expect(applied.status).toBe(200);
  const added = await until(
    async () =>
      (s.panel.profiles[0].config as { inbounds: Record<string, any>[] }).inbounds.find(
        (i) => i.tag === tag,
      ),
    (i) => !!i,
  );
  // What FCP knows of the profile is what it last observed.
  await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
  return added!;
}

const encryptedTwin = { kind: 'ws', port: 8444, path: '/ws-e', encrypted: true };
const twin = (s: Seeded, body: unknown) => s.call('POST', 'modes/freedom-ws/encrypted-twin', body);
const codeOf = async (res: Response) => ((await res.json()) as any).error?.code as string;

describe("a mode's encrypted twin", () => {
  test('the encrypted transport is added beside the mode, becomes its twin, and is taken away again', async () => {
    const s = await seed();
    const own = (await s.mode()).transport!.uuid;
    expect(await s.groupTransports()).toEqual([own]);

    // 1. Add it: its server key is made in the attempt and lives on the backend only.
    const added = await addTransport(s, TWIN_TAG, encryptedTwin);
    expect(added).toMatchObject({
      listen: '127.0.0.1',
      port: 8444,
      protocol: 'vless',
      streamSettings: { network: 'ws', security: 'none', wsSettings: { path: '/ws-e' } },
    });
    const server = added.settings.decryption as string;
    expect(server).toMatch(/^mlkem768x25519plus\.native\.600s\.[A-Za-z0-9_-]{86}$/);
    // The mode's own transport is as it was: plain.
    const config = s.panel.profiles[0].config as { inbounds: Record<string, any>[] };
    expect(config.inbounds.find((i) => i.tag === 'FREEDOM_WEBSOCKET')!.settings.decryption).toBe(
      'none',
    );
    // Adding a transport gives nobody anything: the mode's group is untouched.
    expect(await s.groupTransports()).toEqual([own]);

    // 2. Make it the mode's twin: the group carries both, and the setup knows it.
    const attached = await twin(s, { action: 'attach', transportTag: TWIN_TAG });
    expect(attached.status).toBe(200);
    const m = await s.mode();
    const twinUuid = (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
      (i) => i.tag === TWIN_TAG,
    )!.uuid;
    expect(m.twin).toEqual({
      tag: TWIN_TAG,
      uuid: twinUuid,
      listen: '127.0.0.1',
      port: 8444,
      path: '/ws-e',
    });
    expect(await s.groupTransports()).toEqual([own, twinUuid].sort());
    const view = BackendSetupView.parse(await (await s.call('GET', 'setup')).json());
    expect(view.modes[0]!.twin).toEqual({
      tag: TWIN_TAG,
      port: 8444,
      path: '/ws-e',
      detaching: false,
    });

    // Nothing FCP keeps holds the key: only what is public about the layer.
    const everything = JSON.stringify(
      await s.t.run(async (ctx) => ({
        setups: await ctx.db.query('panelSetups').collect(),
        profiles: await ctx.db.query('panelProfiles').collect(),
        ops: await ctx.db.query('panelOps').collect(),
        audit: await ctx.db.query('auditLog').collect(),
      })),
    );
    expect(everything).not.toContain(server.split('.')[3]);
    expect(everything).toContain(clientEncryption(server)!);

    // Asked again, nothing is sent again.
    const again = await twin(s, { action: 'attach', transportTag: TWIN_TAG });
    expect(await again.json()).toEqual({ op: null });

    // 3. Take it away: the group is the mode's transport alone again; the transport stays.
    const detached = await twin(s, { action: 'detach' });
    expect(detached.status).toBe(200);
    expect((await s.mode()).twin).toBeUndefined();
    expect(await s.groupTransports()).toEqual([own]);
    expect(config.inbounds.some((i) => i.tag === TWIN_TAG)).toBe(true);
    expect(await codeOf(await twin(s, { action: 'detach' }))).toBe('servers.twin_absent');

    const audit = await s.t.run((ctx) => ctx.db.query('auditLog').collect());
    const acts = audit.filter((a) => a.action.startsWith('admin.servers.mode_twin.'));
    expect(acts.map((a) => [a.action, a.payload])).toEqual([
      [
        'admin.servers.mode_twin.attach',
        { backendSlug: 'panel-a', mode: 'freedom-ws', tag: TWIN_TAG, port: 8444, auth: 'mlkem768' },
      ],
      // The second ask changed nothing but is still an admin's act.
      [
        'admin.servers.mode_twin.attach',
        { backendSlug: 'panel-a', mode: 'freedom-ws', tag: TWIN_TAG, port: 8444, auth: 'mlkem768' },
      ],
      [
        'admin.servers.mode_twin.detach',
        { backendSlug: 'panel-a', mode: 'freedom-ws', tag: TWIN_TAG },
      ],
    ]);
  });

  test('a mode with a twin is not read as drifted when the setup changes', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    const before = await s.mode();
    // Another mode's transport, then the mode itself: a new generation of the setup.
    await s.t.run(async (ctx) => {
      await ctx.db.insert('connectionModes', {
        slug: 'freedom-ws-b',
        familySlug: 'freedom',
        deliveryStyle: 'url',
        enabled: false,
        isFamilyDefault: false,
        backends: ['remnawave'],
        order: 9,
        updatedAt: Date.now(),
      });
    });
    await addTransport(s, 'FREEDOM_WS_B', { kind: 'ws', port: 8450, path: '/ws-b' });
    const again = await s.t.mutation(internal.backendSetup.start, {
      backendServerId: s.serverId,
      input: {
        profileName: 'FreeSocks-Config',
        modes: [
          wsMode,
          {
            ...wsMode,
            slug: 'freedom-ws-b',
            name: 'Freedom-WS-B',
            ws: { path: '/ws-b', port: 8450 },
          },
        ],
        originDns: null,
        adopt: false,
      },
    });
    const row = await until(
      () => s.t.run((ctx) => ctx.db.get(again.setupId)),
      (r) => !!r && !r.claim,
    );
    expect([row!.state, row!.code ?? null]).toEqual(['ready', null]);
    // The twin and the group are as they were.
    expect((await s.mode()).twin).toEqual(before.twin);
    expect(await s.groupTransports()).toEqual([before.transport!.uuid, before.twin!.uuid].sort());
  });

  test('what cannot be a twin is refused before anything is sent', async () => {
    const s = await seed();
    const own = (await s.mode()).transport!.uuid;
    const attach = async (transportTag: string) =>
      codeOf(await twin(s, { action: 'attach', transportTag }));

    expect(await attach('NOT_THERE')).toBe('servers.twin_transport_unknown');
    // The mode's own transport, and a plain one beside it.
    expect(await attach('FREEDOM_WEBSOCKET')).toBe('servers.twin_transport_taken');
    await addTransport(s, 'PLAIN_WS', { kind: 'ws', port: 8445, path: '/ws-p' });
    expect(await attach('PLAIN_WS')).toBe('servers.twin_not_encrypted');
    // Encrypted, on the mode's own path: the front server could not tell them apart.
    await addTransport(s, 'SAME_PATH', { kind: 'ws', port: 8446, path: '/ws', encrypted: true });
    expect(await attach('SAME_PATH')).toBe('servers.twin_same_route');
    expect(await s.groupTransports()).toEqual([own]);
    expect((await s.mode()).twin).toBeUndefined();

    // One twin per mode.
    await addTransport(s, TWIN_TAG, encryptedTwin);
    await addTransport(s, 'SECOND_E', { kind: 'ws', port: 8447, path: '/ws-2', encrypted: true });
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    expect(await attach('SECOND_E')).toBe('servers.twin_present');

    // With server changes switched off, nothing is asked of the backend.
    await s.t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': false } });
    expect(await codeOf(await twin(s, { action: 'detach' }))).toBe('servers.manage_disabled');
  });

  test('a group that holds anything else is never rewritten, on the way in or out', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    await addTransport(s, 'PLAIN_WS', { kind: 'ws', port: 8445, path: '/ws-p' });
    const uuidOf = (tag: string) =>
      (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find((i) => i.tag === tag)!
        .uuid;
    const m = await s.mode();
    const squad = s.panel.squads.find((x) => x.uuid === m.groupUuid)!;
    // Someone put another transport into the mode's group on the backend.
    const drift = async (uuids: string[]) => {
      squad.inbounds = uuids.map((uuid) => ({ uuid, tag: uuid }));
      await s.t.action(internal.backendObserve.refresh, { backendServerId: s.serverId });
    };
    const own = m.transport!.uuid;
    await drift([own, uuidOf('PLAIN_WS')]);
    expect(await codeOf(await twin(s, { action: 'attach', transportTag: TWIN_TAG }))).toBe(
      'servers.setup_mode_drifted:freedom-ws',
    );
    expect((await s.mode()).twin).toBeUndefined();

    // With the twin attached, the same edit must not be undone by a detach:
    // rewriting the group to the mode's transport would drop it without a word.
    await drift([own]);
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    const three = [own, uuidOf(TWIN_TAG), uuidOf('PLAIN_WS')];
    await drift(three);
    expect(await codeOf(await twin(s, { action: 'detach' }))).toBe(
      'servers.setup_mode_drifted:freedom-ws',
    );
    expect(await s.groupTransports()).toEqual([...three].sort());
    expect((await s.mode()).twin).toMatchObject({ tag: TWIN_TAG });
  });

  test('an op the backend refuses leaves an attach and a detach that can be asked again', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    const own = (await s.mode()).transport!.uuid;
    const twinUuid = (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
      (i) => i.tag === TWIN_TAG,
    )!.uuid;
    // The backend refuses every change of a group until told otherwise.
    let refusing = true;
    s.panel.stub.route(
      routeFetch((c) =>
        refusing && c.path === '/api/internal-squads' && c.method === 'PATCH'
          ? jsonRes({ message: 'no' }, 400)
          : s.panel.handle(c),
      ),
    );

    // A send that failed has an unknown outcome to the ledger: an operator
    // settles it (the attested recovery) before the same thing is asked again.
    const recoverOpenOp = async () => {
      const open = (await s.t.run((ctx) => ctx.db.query('panelOps').collect())).find(
        (o) => o.open,
      )!;
      const res = await s.call('POST', `ops/${open._id}/recover`, {
        credentialsRevoked: true,
        noInFlightExecutor: true,
        queueDrained: true,
        note: 'the backend refused it',
      });
      expect(res.status).toBe(200);
    };

    // Attach: the group did not change, the twin is recorded, and asking again works.
    await twin(s, { action: 'attach', transportTag: TWIN_TAG });
    expect(await s.groupTransports()).toEqual([own]);
    expect((await s.mode()).twin).toMatchObject({ tag: TWIN_TAG });
    refusing = false;
    await recoverOpenOp();
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    expect(await s.groupTransports()).toEqual([own, twinUuid].sort());

    // Detach: refused by the backend, the group still carries the twin, so the
    // setup must still know it (or nobody could ask again).
    refusing = true;
    await twin(s, { action: 'detach' });
    expect(await s.groupTransports()).toEqual([own, twinUuid].sort());
    expect((await s.mode()).twin).toMatchObject({ tag: TWIN_TAG, detaching: true });
    refusing = false;
    await recoverOpenOp();
    expect((await twin(s, { action: 'detach' })).status).toBe(200);
    expect(await s.groupTransports()).toEqual([own]);
    expect((await s.mode()).twin).toBeUndefined();
    expect(await codeOf(await twin(s, { action: 'detach' }))).toBe('servers.twin_absent');
  });

  test('a detach that changed its mind: attaching again keeps the twin', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    const m = await s.mode();
    await s.t.run((ctx) =>
      ctx.db.patch(s.setupId, {
        modes: [{ ...m, twin: { ...m.twin!, detaching: true } }],
      }),
    );
    expect(await (await twin(s, { action: 'attach', transportTag: TWIN_TAG })).json()).toEqual({
      op: null,
    });
    expect((await s.mode()).twin).toEqual(m.twin);
  });

  test('a transport something already uses is not attached: a twin is proved before members get it', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    const own = (await s.mode()).transport!.uuid;
    const twinUuid = (s.panel.profiles[0].inbounds as { uuid: string; tag: string }[]).find(
      (i) => i.tag === TWIN_TAG,
    )!.uuid;
    const attach = async () => codeOf(await twin(s, { action: 'attach', transportTag: TWIN_TAG }));

    // A node already serves it.
    const nodeId = await s.t.run((ctx) =>
      ctx.db.insert('panelNodes', {
        backendServerId: s.serverId,
        nodeUuid: 'n-1',
        name: 'node-a',
        address: '192.0.2.10',
        port: 2222,
        countryCode: 'NL',
        online: true,
        isDisabled: false,
        usersOnline: 0,
        activeInboundUuids: [own, twinUuid],
        tags: [],
        observedAt: Date.now(),
      }),
    );
    expect(await attach()).toBe('servers.twin_already_served');
    await s.t.run((ctx) => ctx.db.delete(nodeId));

    // An address already names it.
    const hostId = await s.t.run((ctx) =>
      ctx.db.insert('panelHosts', {
        backendServerId: s.serverId,
        hostUuid: 'h-1',
        remark: 'someone-made-this',
        address: 'front.example',
        port: 443,
        isDisabled: true,
        isHidden: false,
        configProfileInboundUuid: twinUuid,
        nodeUuids: [],
        observedAt: Date.now(),
      }),
    );
    expect(await attach()).toBe('servers.twin_already_served');
    expect(await s.groupTransports()).toEqual([own]);
    expect((await s.mode()).twin).toBeUndefined();

    // With neither, it is a twin like any other.
    await s.t.run((ctx) => ctx.db.delete(hostId));
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
  });

  test('a twin a node serves is not taken away', async () => {
    const s = await seed();
    await addTransport(s, TWIN_TAG, encryptedTwin);
    expect((await twin(s, { action: 'attach', transportTag: TWIN_TAG })).status).toBe(200);
    const m = await s.mode();
    await s.t.run((ctx) =>
      ctx.db.insert('panelNodes', {
        backendServerId: s.serverId,
        nodeUuid: 'n-1',
        name: 'node-a',
        address: '192.0.2.10',
        port: 2222,
        countryCode: 'NL',
        online: true,
        isDisabled: false,
        usersOnline: 0,
        activeInboundUuids: [m.transport!.uuid, m.twin!.uuid],
        tags: [],
        observedAt: Date.now(),
      }),
    );
    expect(await codeOf(await twin(s, { action: 'detach' }))).toBe('servers.twin_in_use');
    expect((await s.mode()).twin).toEqual(m.twin);
  });
});

describe('twinProblem', () => {
  const mode = {
    slug: 'freedom-ws',
    shape: { transport: 'ws', fronting: 'edge-l7' },
    tag: 'FREEDOM_WEBSOCKET',
    transport: { uuid: 'i-own', port: 8443, path: '/ws' },
  };
  const encryption = clientEncryption(generateVlessEncryption().decryption)!;
  const inbound = (over: Record<string, unknown> = {}) => ({
    tag: 'WS_E',
    inboundUuid: 'i-twin',
    protocol: 'vless',
    port: 8444 as number | null,
    listen: '127.0.0.1',
    network: 'ws',
    security: 'none',
    path: '/ws-e' as string | null,
    vlessEncryption: { encryption: encryption as string | null },
    ...over,
  });
  const check = (over: Record<string, unknown> = {}, m: typeof mode = mode) =>
    twinProblem({ mode: m, modes: [m], inbounds: [inbound(over)], tag: 'WS_E' });

  test('an encrypted loopback WebSocket transport on a route of its own is a twin', () => {
    expect(check()).toBeNull();
  });

  test('only a WebSocket mode behind a CDN takes one: REALITY is end to end already', () => {
    for (const shape of [
      { transport: 'reality', fronting: 'direct' },
      { transport: 'reality', fronting: 'edge-l4' },
      { transport: 'xhttp-reality', fronting: 'edge-l4' },
      { transport: 'hysteria', fronting: 'direct' },
    ])
      expect(check({}, { ...mode, shape })).toBe('servers.twin_unsupported');
  });

  test('it has to be the same kind of transport, on loopback', () => {
    for (const over of [
      { protocol: 'trojan' },
      { network: 'grpc' },
      { security: 'tls' },
      { listen: '0.0.0.0' },
      { listen: undefined },
      { port: null },
      { path: null },
    ])
      expect(check(over)).toBe('servers.twin_not_websocket');
  });

  test('it has to run a VLESS Encryption FCP can read and its own sessions can speak', () => {
    expect(check({ vlessEncryption: undefined })).toBe('servers.twin_not_encrypted');
    expect(check({ vlessEncryption: { encryption: null } })).toBe(
      'servers.twin_encryption_unreadable',
    );
    expect(
      check({ vlessEncryption: { encryption: encryption.replace('.native.', '.random.') } }),
    ).toBe('servers.twin_encryption_unsupported');
    expect(
      check({ vlessEncryption: { encryption: `${encryption}.${encryption.split('.')[3]}` } }),
    ).toBe('servers.twin_encryption_unsupported');
  });

  test('it needs a port and a path of its own', () => {
    expect(check({ port: 8443 })).toBe('servers.twin_same_route');
    expect(check({ path: '/ws' })).toBe('servers.twin_same_route');
  });

  test("another mode's transport or twin is taken", () => {
    const other = { ...mode, slug: 'other', tag: 'OTHER', twin: { tag: 'WS_E', uuid: 'i-twin' } };
    expect(twinProblem({ mode, modes: [mode, other], inbounds: [inbound()], tag: 'WS_E' })).toBe(
      'servers.twin_transport_taken',
    );
    // Retagged on the backend, it is still the same transport: the uuid says so.
    const retagged = { ...other, twin: { tag: 'OLD_TAG', uuid: 'i-twin' } };
    expect(twinProblem({ mode, modes: [mode, retagged], inbounds: [inbound()], tag: 'WS_E' })).toBe(
      'servers.twin_transport_taken',
    );
  });
});
