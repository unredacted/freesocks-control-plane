/// <reference types="vite/client" />
/**
 * Server-name families: curating names against a target, qualifying them, and
 * binding a family to a panel inbound.
 *
 *  - dormant by default: nothing is qualified and nothing can be bound;
 *  - an import answers a verdict per line; a name belongs to one family, and a
 *    burned name is never offered again, by any family;
 *  - a name that stops qualifying is suspended and comes back by itself;
 *  - a family binds only to a REALITY inbound whose target IS the family's
 *    target, and everything the inbound already lists is recorded as seen, so
 *    none of it can ever serve as a witness of a new generation;
 *  - a bound inbound is no longer edited by hand;
 *  - audit rows carry slugs and counts, never a hostname.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import {
  FIXTURE_CONFIG_PROFILE as PROFILE,
  FIXTURE_INBOUND as INBOUND,
  insertPanelServer,
  markBackendSetUp,
} from './lib/edges/testing/fixtures';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';
type T = TestConvex<typeof schema>;

beforeEach(() => {
  vi.stubEnv('SESSION_SIGNING_KEY', 'test-sign');
  vi.stubEnv('ADMIN_SESSION_SIGNING_KEY', ADMIN_SIGN_KEY);
  vi.stubEnv('IP_HASH_SALT', 'test-salt');
  vi.stubEnv('ACCOUNT_ID_PEPPER', 'test-pepper');
});
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await insertPanelServer(t);
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
  const cookie = `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
  const call = (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/edges/sni/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  // What Servers last read from the panel: one REALITY inbound and one TLS inbound.
  await t.run((ctx) =>
    ctx.db.insert('panelProfiles', {
      backendServerId: serverId,
      profileUuid: PROFILE,
      name: 'Default',
      shapeHash: 'x',
      changeToken: 'y',
      digestKeyId: 'k',
      inbounds: [
        {
          tag: 'REALITY_IN',
          inboundUuid: INBOUND,
          protocol: 'vless',
          port: 443,
          network: 'tcp',
          security: 'reality',
          reality: {
            target: 'target.example:443',
            serverNames: ['old-a.example', 'old-b.example'],
          },
        },
        {
          tag: 'WS_IN',
          inboundUuid: 'i-ws',
          protocol: 'vless',
          port: 8443,
          network: 'ws',
          security: 'tls',
        },
      ],
      observedAt: Date.now(),
    }),
  );
  return { t, serverId, call };
}

const family = {
  slug: 'fam-a',
  label: 'Family A',
  targetAddress: 'target.example',
  targetPort: 443,
};
const auditRows = (t: T) =>
  t.run(async (ctx) =>
    (await ctx.db.query('auditLog').collect()).filter((a) => a.action.startsWith('edge.sni.')),
  );

describe('families and names', () => {
  test('create, import with a verdict per line, and the counts', async () => {
    const { call } = await seed();
    expect((await call('POST', 'families', family)).status).toBe(200);
    expect((await call('POST', 'families', family)).status).toBe(409);
    const imp = await (
      await call('POST', 'families/fam-a/names', {
        text: 'One.Example\ntwo.example\n\n# note\none.example\nnot a name',
      })
    ).json();
    expect(imp.added).toBe(2);
    expect(imp.lines.map((l: { verdict: string }) => l.verdict)).toEqual([
      'added',
      'added',
      'duplicate',
      'invalid',
    ]);
    const list = await (await call('GET', 'families')).json();
    expect(list.families[0]).toMatchObject({
      slug: 'fam-a',
      counts: { total: 2, waiting: 2, ready: 0 },
    });
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.names.map((n: { name: string; seq: number }) => [n.name, n.seq])).toEqual([
      ['one.example', 1],
      ['two.example', 2],
    ]);
  });

  test('a name belongs to ONE family; a burned name is never offered again', async () => {
    const { call } = await seed();
    await call('POST', 'families', family);
    await call('POST', 'families', { ...family, slug: 'fam-b' });
    await call('POST', 'families/fam-a/names', { lines: ['shared.example', 'dead.example'] });
    await call('POST', 'families/fam-a/names/burn', { snis: ['dead.example'] });
    const imp = await (
      await call('POST', 'families/fam-b/names', { lines: ['shared.example', 'dead.example'] })
    ).json();
    expect(imp.lines.map((l: { verdict: string }) => l.verdict)).toEqual([
      'in_other_family',
      'burned',
    ]);
    expect(imp.added).toBe(0);
    // Burned is final, even for its own family.
    await call('POST', 'families/fam-a/names/reactivate', { snis: ['dead.example'] });
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.names.find((n: { name: string }) => n.name === 'dead.example').status).toBe(
      'burned',
    );
  });

  test('a private target is refused; the target of a family cannot be changed', async () => {
    const { call } = await seed();
    const bad = await call('POST', 'families', { ...family, targetAddress: '10.0.0.5' });
    expect((await bad.json()).error.code).toBe('edge.sni.bad_target');
    await call('POST', 'families', family);
    await call('PATCH', 'families/fam-a', { label: 'Renamed', targetAddress: 'elsewhere.example' });
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.family).toMatchObject({
      label: 'Renamed',
      target: { address: 'target.example', port: 443 },
    });
  });
});

describe('qualification', () => {
  test('dormant: nothing is due. Enabled: oldest first, suspended after repeated failures, back by itself', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['one.example', 'two.example'] });
    expect((await t.query(internal.sniFamilies.dueForQualification, {})).names).toEqual([]);
    await call('PATCH', 'config', { enabled: true, suspendAfterFails: 2 });
    const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.map((n) => [n.name, n.address, n.port])).toEqual([
      ['one.example', 'target.example', 443],
      ['two.example', 'target.example', 443],
    ]);
    const [one, two] = due;
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: one.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
    });
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: two.id,
      ok: false,
      code: 'q_cert',
    });
    let detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.family.counts).toMatchObject({ ready: 1, failing: 1, suspended: 0 });
    // A second failure in a row suspends it...
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: two.id,
      ok: false,
      code: 'q_cert',
    });
    detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.names[1]).toMatchObject({ status: 'suspended', code: 'q_cert' });
    // ...and qualifying again brings it back.
    await t.mutation(internal.sniFamilies.recordQualification, {
      id: two.id,
      ok: true,
      tlsVersion: 'TLSv1.3',
    });
    detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.names[1]).toMatchObject({ status: 'active', qualification: 'ok' });
    // Freshly checked names are not due again.
    expect((await t.query(internal.sniFamilies.dueForQualification, {})).names).toEqual([]);
  });
});

describe('binding a family to an inbound', () => {
  test('refused while dormant, on a non-REALITY inbound, and when the targets differ', async () => {
    const { call } = await seed();
    await call('POST', 'families', family);
    const bind = (slug: string, inboundTag: string) =>
      call('POST', `families/${slug}/bind`, { backendSlug: 'panel-a', inboundTag });
    expect((await (await bind('fam-a', 'REALITY_IN')).json()).error.code).toBe('edge.sni.disabled');
    await call('PATCH', 'config', { enabled: true });
    expect((await (await bind('fam-a', 'WS_IN')).json()).error.code).toBe('servers.not_reality');
    expect((await (await bind('fam-a', 'NOPE')).json()).error.code).toBe('servers.unknown_inbound');
    await call('POST', 'families', {
      ...family,
      slug: 'fam-other',
      targetAddress: 'other.example',
    });
    expect((await (await bind('fam-other', 'REALITY_IN')).json()).error.code).toBe(
      'edge.sni.target_mismatch',
    );
  });

  test('binding records every name the inbound already lists as SEEN; one family per inbound', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'config', { enabled: true });
    const bound = await call('POST', 'families/fam-a/bind', {
      backendSlug: 'panel-a',
      inboundTag: 'REALITY_IN',
    });
    expect(bound.status).toBe(200);
    const history = await t.run((ctx) => ctx.db.query('sniInboundNameHistory').collect());
    expect(history.map((h) => [h.name, h.firstSeenGeneration]).sort()).toEqual([
      ['old-a.example', 0],
      ['old-b.example', 0],
    ]);
    expect(
      (
        await call('POST', 'families/fam-a/bind', {
          backendSlug: 'panel-a',
          inboundTag: 'REALITY_IN',
        })
      ).status,
    ).toBe(409);
    // A family in use is not deleted.
    expect((await (await call('DELETE', 'families/fam-a')).json()).error.code).toBe(
      'edge.sni.family_in_use',
    );
    // Unbinding keeps the history: a rebind can never turn an old name into a new witness.
    const { id } = await bound.json();
    expect((await call('DELETE', `bindings/${id}`)).status).toBe(200);
    expect(await t.run((ctx) => ctx.db.query('sniInboundNameHistory').collect())).toHaveLength(2);
    expect((await call('DELETE', 'families/fam-a')).status).toBe(200);
  });

  test('a bound inbound is no longer edited by hand', async () => {
    const { t, serverId, call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'config', { enabled: true });
    await call('POST', 'families/fam-a/bind', { backendSlug: 'panel-a', inboundTag: 'REALITY_IN' });
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
    await markBackendSetUp(t, serverId);
    await expect(
      t.mutation(internal.panelWrites.requestProfilePatch, {
        backendServerId: serverId,
        profileUuid: PROFILE,
        ops: [{ op: 'setRealityServerNames', inboundTag: 'REALITY_IN', names: ['x.example'] }],
        baseToken: 'a',
        expectedToken: 'b',
        inboundUuids: { REALITY_IN: INBOUND },
      }),
    ).rejects.toThrow(/inbound_sni_managed/);
  });
});

describe('judging names per country', () => {
  test('marks are recorded, copied onto the relay listeners that carry the name, and the renders move on', async () => {
    const { t, call } = await seed();
    const { registerRelay, realityListener } = await import('./lib/edges/testing/fixtures');
    const { relayId, listenerIds } = await registerRelay(t, {
      listeners: [realityListener({ tlsNames: ['works.example', 'big-site.example'] })],
    });
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['works.example', 'big-site.example'] });
    const epoch0 = (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const mark = (snis: string[], country: string, state: string) =>
      call('POST', 'families/fam-a/names/country', { snis, country, state });
    expect(await (await mark(['big-site.example'], 'cn', 'blocked')).json()).toEqual({
      count: 1,
      relays: 1,
    });
    await mark(['works.example', 'big-site.example'], 'RU', 'proven');
    const names = (await t.run((ctx) => ctx.db.get(listenerIds.a)))!.tlsNames!;
    expect(names).toEqual([
      { name: 'works.example', status: 'active', provenIn: ['RU'] },
      { name: 'big-site.example', status: 'active', blockedIn: ['CN'], provenIn: ['RU'] },
    ]);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 2);
    // Judging a name does not stale the operator's endpoint test.
    expect((await t.run((ctx) => ctx.db.get(listenerIds.a)))!.revision).toBe(1);
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.curatedCountries).toEqual(['CN', 'RU', 'IR', 'MM']);
    expect(detail.names.find((n: { name: string }) => n.name === 'big-site.example')).toMatchObject(
      {
        blockedIn: ['CN'],
        provenIn: ['RU'],
      },
    );
    // Back to unjudged.
    await mark(['big-site.example'], 'CN', 'unknown');
    expect((await t.run((ctx) => ctx.db.get(listenerIds.a)))!.tlsNames![1]).toEqual({
      name: 'big-site.example',
      status: 'active',
      provenIn: ['RU'],
    });
  });

  test('only curated countries are judged, and the audit row has no hostname', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['hidden-name.example'] });
    const bad = await call('POST', 'families/fam-a/names/country', {
      snis: ['hidden-name.example'],
      country: 'DE',
      state: 'blocked',
    });
    expect((await bad.json()).error.code).toBe('edge.sni.country_not_curated');
    await call('POST', 'families/fam-a/names/country', {
      snis: ['hidden-name.example'],
      country: 'IR',
      state: 'blocked',
    });
    const row = (await auditRows(t)).find((r) => r.action === 'edge.sni.names.country')!;
    expect(row.payload).toEqual({ slug: 'fam-a', country: 'IR', state: 'blocked', count: 1 });
  });
});

describe('audit and scopes', () => {
  test('audit rows carry slugs and counts, never a hostname', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['secret-name.example'] });
    await call('POST', 'families/fam-a/names/retire', { snis: ['secret-name.example'] });
    const rows = await auditRows(t);
    expect(rows.map((r) => r.action)).toEqual([
      'edge.sni.family.create',
      'edge.sni.names.import',
      'edge.sni.names.retire',
    ]);
    expect(JSON.stringify(rows.map((r) => r.payload))).not.toContain('secret-name');
    expect(rows[1].payload).toEqual({ slug: 'fam-a', added: 1, rejected: 0 });
  });

  test('the switches are a settings-scope surface', async () => {
    const { scopeFor } = await import('./httpEdges');
    expect(scopeFor(['sni', 'config'], 'PATCH')).toBe('admin:settings:write');
    expect(scopeFor(['sni', 'config'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['sni', 'families'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['sni', 'families', 'x', 'names'], 'POST')).toBe('admin:servers:write');
  });
});
