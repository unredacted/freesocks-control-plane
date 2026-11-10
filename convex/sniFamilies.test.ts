/// <reference types="vite/client" />
/**
 * Server-name families: curating names against a target, qualifying them, and
 * binding a family to a backend transport.
 *
 *  - dormant by default: nothing is qualified and nothing can be bound;
 *  - an import answers a verdict per line; a name belongs to one family, and a
 *    burned name is never offered again, by any family;
 *  - a name that stops qualifying is suspended and comes back by itself;
 *  - a family binds only to a REALITY transport whose target IS the family's
 *    target, and everything the transport already lists is recorded as seen, so
 *    none of it can ever serve as a witness of a new generation;
 *  - a bound transport is no longer edited by hand;
 *  - audit rows carry slugs and counts, never a hostname.
 *
 * Fixtures use RFC 5737 addresses and `*.example` names only.
 */
import { convexTest, type TestConvex } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
import { signValue } from './lib/cookies';
import { DEFAULT_CENSORED_COUNTRIES } from './lib/censoredCountries';
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
  // What Servers last read from the backend: one REALITY transport and one TLS transport.
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

  test('a slug that is the address of an SNIs page is refused', async () => {
    const { call } = await seed();
    for (const slug of ['find', 'checks', 'settings']) {
      const res = await call('POST', 'families', { ...family, slug });
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe('validation');
    }
    const list = await (await call('GET', 'families')).json();
    expect(list.families).toEqual([]);
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

describe('use anyway: a server name off the list network, on an operator say', () => {
  async function onNetwork() {
    const env = await seed();
    await env.t.run((ctx) =>
      ctx.db.insert('edgeNetworks', {
        slug: 'net-a',
        label: 'Net A',
        asns: [64500],
        announced: { v4: [], v6: [] },
        manualPrefixes: ['192.0.2.0/24'],
        prefixes: { v4: ['192.0.2.0/24'], v6: [] },
        updatedAt: Date.now(),
      }),
    );
    await env.call('POST', 'families', { ...family, network: 'net-a' });
    await env.call('POST', 'families/fam-a/names', { lines: ['off.example', 'other.example'] });
    await env.call('PATCH', 'config', { enabled: true, suspendAfterFails: 2 });
    return env;
  }
  const row = async (call: Awaited<ReturnType<typeof seed>>['call'], name = 'off.example') =>
    (await (await call('GET', 'families/fam-a')).json()).names.find(
      (n: { name: string }) => n.name === name,
    );

  test('without it, the refusal holds: the pass is told nothing, and the failure suspends', async () => {
    const { t, call } = await onNetwork();
    const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.every((n) => n.useAnyway === undefined)).toBe(true);
    const id = due.find((n) => n.name === 'off.example')!.id;
    for (let i = 0; i < 2; i++)
      await t.mutation(internal.sniFamilies.recordQualification, {
        id,
        ok: false,
        code: 'q_off_network',
      });
    expect(await row(call)).toMatchObject({
      status: 'suspended',
      qualification: 'failed',
      code: 'q_off_network',
      useAnyway: null,
    });
  });

  test('with it: checked again, passes, comes back, stays marked with who, when and why', async () => {
    const { t, call } = await onNetwork();
    const id = (await t.query(internal.sniFamilies.dueForQualification, {})).names.find(
      (n) => n.name === 'off.example',
    )!.id;
    for (let i = 0; i < 2; i++)
      await t.mutation(internal.sniFamilies.recordQualification, {
        id,
        ok: false,
        code: 'q_off_network',
      });
    const set = await call('POST', 'families/fam-a/names/use-anyway', {
      snis: ['Off.Example'],
      on: true,
      reason: '  Works from inside the country  ',
    });
    expect(await set.json()).toEqual({ count: 1 });
    // Due again at once, and the pass is told this one may resolve elsewhere.
    const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.find((n) => n.name === 'off.example')).toMatchObject({ useAnyway: true });
    expect(due.find((n) => n.name === 'other.example')?.useAnyway).toBeUndefined();
    // The pass lifts only the network check: the handshake passed.
    await t.mutation(internal.sniFamilies.recordQualification, {
      id,
      ok: true,
      tlsVersion: 'TLSv1.3',
      alpn: 'h2',
      offNetwork: true,
    });
    const r = await row(call);
    expect(r).toMatchObject({
      status: 'active',
      qualification: 'ok',
      offNetwork: true,
      useAnyway: { by: 'Op', reason: 'Works from inside the country' },
    });
    expect(Date.parse(r.useAnyway.at)).toBeGreaterThan(0);
    // Every other check still applies: a bad certificate fails it as ever.
    await t.mutation(internal.sniFamilies.recordQualification, { id, ok: false, code: 'q_cert' });
    expect(await row(call)).toMatchObject({ qualification: 'failed', code: 'q_cert' });
    // Stopped resolving at all: refused, the say stays for when it resolves again.
    await t.mutation(internal.sniFamilies.recordQualification, {
      id,
      ok: false,
      code: 'q_name_unresolved',
    });
    expect(await row(call)).toMatchObject({
      status: 'suspended',
      code: 'q_name_unresolved',
      useAnyway: { by: 'Op' },
    });
  });

  test('taking it back puts the normal check back; a burned name and a list with no network refuse it', async () => {
    const { t, call } = await onNetwork();
    await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: true });
    const id = (await t.query(internal.sniFamilies.dueForQualification, {})).names.find(
      (n) => n.name === 'off.example',
    )!.id;
    await t.mutation(internal.sniFamilies.recordQualification, { id, ok: true, offNetwork: true });
    expect(await row(call)).toMatchObject({ useAnyway: { reason: null } });
    const off = await call('POST', 'families/fam-a/names/use-anyway', {
      snis: ['off.example'],
      on: false,
    });
    expect(await off.json()).toEqual({ count: 1 });
    // The mark goes with it (the next check judges it afresh).
    expect(await row(call)).toMatchObject({ useAnyway: null, offNetwork: false });
    const due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.find((n) => n.name === 'off.example')).toBeDefined();
    expect(due.find((n) => n.name === 'off.example')?.useAnyway).toBeUndefined();
    // Taking back what was never set changes nothing.
    expect(
      await (
        await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: false })
      ).json(),
    ).toEqual({ count: 0 });
    // `on` is required.
    expect(
      (await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'] })).status,
    ).toBe(400);
    // A burned name never comes back, this way either.
    await call('POST', 'families/fam-a/names/burn', { snis: ['other.example'] });
    expect(
      await (
        await call('POST', 'families/fam-a/names/use-anyway', { snis: ['other.example'], on: true })
      ).json(),
    ).toEqual({ count: 0 });
    // No network: nothing to be off.
    await call('POST', 'families', { ...family, slug: 'fam-b', targetAddress: 'b.example' });
    await call('POST', 'families/fam-b/names', { lines: ['b1.example'] });
    const refused = await call('POST', 'families/fam-b/names/use-anyway', {
      snis: ['b1.example'],
      on: true,
    });
    expect((await refused.json()).error.code).toBe('edge.sni.no_network');
  });

  test('a verdict judged before the operator changed it is dropped; the recheck stands', async () => {
    const { t, call } = await onNetwork();
    // A pass picks the name up without the override...
    const id = (await t.query(internal.sniFamilies.dueForQualification, {})).names.find(
      (n) => n.name === 'off.example',
    )!.id;
    // ...the operator says "use anyway" while it runs...
    await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: true });
    // ...and its old refusal arrives: dropped, the name stays due.
    await t.mutation(internal.sniFamilies.recordQualification, {
      id,
      ok: false,
      code: 'q_off_network',
      useAnyway: false,
    });
    expect(await row(call)).toMatchObject({ qualification: 'pending' });
    let due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.find((n) => n.name === 'off.example')).toMatchObject({ useAnyway: true });
    // The other way round: a pass under the override, taken back meanwhile.
    await t.mutation(internal.sniFamilies.recordQualification, {
      id,
      ok: true,
      offNetwork: true,
      useAnyway: true,
    });
    expect(await row(call)).toMatchObject({ qualification: 'ok' });
    await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: false });
    await t.mutation(internal.sniFamilies.recordQualification, {
      id,
      ok: true,
      offNetwork: true,
      useAnyway: true,
    });
    expect(await row(call)).toMatchObject({ offNetwork: false, useAnyway: null });
    due = (await t.query(internal.sniFamilies.dueForQualification, {})).names;
    expect(due.find((n) => n.name === 'off.example')).toBeDefined();
  });

  test('a burn clears it, and taking it back still works on a burned name', async () => {
    const { t, call } = await onNetwork();
    await call('POST', 'families/fam-a/names/use-anyway', {
      snis: ['off.example', 'other.example'],
      on: true,
    });
    await call('POST', 'families/fam-a/names/burn', { snis: ['off.example'] });
    expect(await row(call)).toMatchObject({ status: 'burned', useAnyway: null });
    // A row burned some other way with the say still on (older rows): it can be taken back.
    await t.run(async (ctx) => {
      const n = (await ctx.db.query('sniNames').collect()).find((x) => x.name === 'other.example')!;
      await ctx.db.patch(n._id, { status: 'burned' });
    });
    expect(
      await (
        await call('POST', 'families/fam-a/names/use-anyway', {
          snis: ['other.example'],
          on: false,
        })
      ).json(),
    ).toEqual({ count: 1 });
    expect(await row(call, 'other.example')).toMatchObject({ useAnyway: null });
  });

  test('a network change drops it: it was said about the old network', async () => {
    const { t, call } = await onNetwork();
    await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: true });
    await call('PATCH', 'families/fam-a', { network: null });
    expect(await row(call)).toMatchObject({ useAnyway: null, qualification: 'pending' });
    const n = await t.run(async (ctx) =>
      (await ctx.db.query('sniNames').collect()).find((x) => x.name === 'off.example'),
    );
    expect(n?.networkOverride).toBeUndefined();
  });

  test('audited with the admin, counts only: never the hostname or the reason', async () => {
    const { t, call } = await onNetwork();
    await call('POST', 'families/fam-a/names/use-anyway', {
      snis: ['off.example'],
      on: true,
      reason: 'off.example works there',
    });
    await call('POST', 'families/fam-a/names/use-anyway', { snis: ['off.example'], on: false });
    const rows = (await auditRows(t)).filter((a) => a.action === 'edge.sni.names.use_anyway');
    expect(rows.map((a) => a.payload)).toEqual([
      { slug: 'fam-a', on: true, count: 1, withReason: true },
      { slug: 'fam-a', on: false, count: 1, withReason: false },
    ]);
    expect(rows.every((a) => a.actorType === 'admin' && !!a.actorId)).toBe(true);
    expect(JSON.stringify(rows)).not.toMatch(/off\.example/);
  });

  test('never automatic: only the operator mutation and a network change write it', () => {
    const sources = import.meta.glob<string>(['./**/*.ts', '!./**/*.test.ts', '!./_generated/**'], {
      query: '?raw',
      import: 'default',
      eager: true,
    });
    const writers = Object.entries(sources)
      .filter(([, text]) => /networkOverride:/.test(text))
      .map(([path]) => path)
      .sort();
    expect(writers).toEqual(['./schema.ts', './sniFamilies.ts']);
    const text = sources['./sniFamilies.ts']!;
    // In sniFamilies.ts: `setUseAnyway` sets or clears it, `update` and a burn clear it.
    expect(text.match(/networkOverride:/g)).toHaveLength(3);
    expect(text.match(/networkOverride: undefined/g)).toHaveLength(2);
  });
});

describe('binding a family to a transport', () => {
  test('refused while dormant, on a non-REALITY transport, and when the targets differ', async () => {
    const { call } = await seed();
    await call('POST', 'families', family);
    const bind = (slug: string, transportTag: string) =>
      call('POST', `families/${slug}/bind`, { backendSlug: 'panel-a', transportTag });
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

  test('binding records every name the transport already lists as SEEN; one family per transport', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'config', { enabled: true });
    const bound = await call('POST', 'families/fam-a/bind', {
      backendSlug: 'panel-a',
      transportTag: 'REALITY_IN',
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
          transportTag: 'REALITY_IN',
        })
      ).status,
    ).toBe(409);
    // The pre-rename field is refused by name, alone or alongside the new one.
    for (const body of [
      { backendSlug: 'panel-a', inboundTag: 'REALITY_IN' },
      { backendSlug: 'panel-a', inboundTag: 'REALITY_IN', transportTag: 'REALITY_IN' },
    ]) {
      const res = await call('POST', 'families/fam-a/bind', body);
      expect(res.status).toBe(400);
      expect((await res.json()).error.message).toContain('inboundTag');
    }
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

  test('takeNames: a transport whose names were set by hand brings them into the family', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('POST', 'families', { ...family, slug: 'fam-b' });
    await call('PATCH', 'config', { enabled: true });
    // One of the hand-set names already belongs to another family.
    await call('POST', 'families/fam-b/names', { lines: ['old-b.example'] });
    const res = await call('POST', 'families/fam-a/bind', {
      backendSlug: 'panel-a',
      transportTag: 'REALITY_IN',
      transportUuid: INBOUND,
      takeNames: true,
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.imported.added).toBe(1);
    expect(body.imported.lines.map((l: { verdict: string }) => l.verdict)).toEqual([
      'added',
      'in_other_family',
    ]);
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(
      detail.names.map((n: { name: string; status: string; qualification: string }) => [
        n.name,
        n.status,
        n.qualification,
      ]),
    ).toEqual([['old-a.example', 'active', 'pending']]);
    // They are what the transport listed, so they are SEEN, never a witness.
    expect(
      (await t.run((ctx) => ctx.db.query('sniInboundNameHistory').collect()))
        .map((h) => h.name)
        .sort(),
    ).toEqual(['old-a.example', 'old-b.example']);
    const row = (await auditRows(t)).find((r) => r.action === 'edge.sni.inbound.bind')!;
    expect(row.payload).toMatchObject({ imported: 1, notImported: 1 });
  });

  test('a bound transport is no longer edited by hand', async () => {
    const { t, serverId, call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'config', { enabled: true });
    await call('POST', 'families/fam-a/bind', {
      backendSlug: 'panel-a',
      transportTag: 'REALITY_IN',
    });
    await t.mutation(internal.serverAdmin.patchConfig, { patch: { 'manage.enabled': true } });
    await markBackendSetUp(t, serverId);
    await expect(
      t.mutation(internal.backendWrites.requestProfilePatch, {
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
  test('marks are recorded, copied onto the origin listeners that carry the name, and the renders move on', async () => {
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
    // The listener was on the legacy pick, which ignores the member's country:
    // its first judged name moves it onto `hrw1`, once.
    expect((await t.run((ctx) => ctx.db.get(listenerIds.a)))!.sniPick).toBeUndefined();
    expect(await (await mark(['big-site.example'], 'cn', 'blocked')).json()).toEqual({
      count: 1,
      relays: 1,
      switched: 1,
    });
    expect((await t.run((ctx) => ctx.db.get(listenerIds.a)))!.sniPick).toBe('hrw1');
    const picks = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (r) => r.action === 'relay.listener.sni_pick',
      ),
    );
    expect(picks.map((r) => r.payload)).toEqual([
      { relaySlug: expect.any(String), listenerKey: 'a', version: 'hrw1', reason: 'country_marks' },
    ]);
    expect(
      (await (await mark(['works.example', 'big-site.example'], 'RU', 'proven')).json()).switched,
    ).toBe(0);
    const names = (await t.run((ctx) => ctx.db.get(listenerIds.a)))!.tlsNames!;
    expect(names).toEqual([
      { name: 'works.example', status: 'active', provenIn: ['RU'] },
      { name: 'big-site.example', status: 'active', blockedIn: ['CN'], provenIn: ['RU'] },
    ]);
    expect((await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch).toBe(epoch0 + 2);
    // Judging a name does not stale the operator's endpoint test.
    expect((await t.run((ctx) => ctx.db.get(listenerIds.a)))!.revision).toBe(1);
    const detail = await (await call('GET', 'families/fam-a')).json();
    // Every country on the censored-country list (here: the default one).
    expect(detail.curatedCountries).toEqual(DEFAULT_CENSORED_COUNTRIES.codes);
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

  test('a name judged before it reaches a listener carries its marks there, and the listener moves onto hrw1', async () => {
    const { t, call } = await seed();
    const { registerRelay, realityListener } = await import('./lib/edges/testing/fixtures');
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['plain.example', 'big-site.example'] });
    await call('POST', 'families/fam-a/names/country', {
      snis: ['big-site.example'],
      country: 'CN',
      state: 'blocked',
    });
    const get = (id: Id<'relayListeners'>) => t.run(async (ctx) => (await ctx.db.get(id))!);
    // A listener created with it carries the mark from the start.
    const first = await registerRelay(t, {
      listeners: [realityListener({ tlsNames: ['big-site.example'] })],
    });
    expect(await get(first.listenerIds.a)).toMatchObject({
      tlsNames: [{ name: 'big-site.example', status: 'active', blockedIn: ['CN'] }],
      sniPick: 'hrw1',
    });
    // A legacy listener that gains it later: the mark, the switch, and its audit row.
    const second = await registerRelay(t, {
      slug: 'relay-b',
      nodeName: 'node-b',
      listeners: [realityListener({ tlsNames: ['plain.example'] })],
    });
    expect((await get(second.listenerIds.a)).sniPick).toBeUndefined();
    await registerRelay(t, {
      slug: 'relay-b',
      nodeName: 'node-b',
      listeners: [realityListener({ tlsNames: ['plain.example', 'big-site.example'] })],
    });
    expect(await get(second.listenerIds.a)).toMatchObject({
      tlsNames: [
        { name: 'plain.example', status: 'active' },
        { name: 'big-site.example', status: 'active', blockedIn: ['CN'] },
      ],
      sniPick: 'hrw1',
    });
    const picks = await t.run(async (ctx) =>
      (await ctx.db.query('auditLog').collect()).filter(
        (r) => r.action === 'relay.listener.sni_pick',
      ),
    );
    expect(picks.map((r) => r.payload)).toEqual([
      { relaySlug: 'relay-b', listenerKey: 'a', version: 'hrw1', reason: 'country_marks' },
    ]);
  });

  test('rows from before: the deploy settles them once; a judged listener never goes back to legacy', async () => {
    const { t, call } = await seed();
    const { registerRelay, realityListener } = await import('./lib/edges/testing/fixtures');
    await call('POST', 'families', family);
    await call('POST', 'families/fam-a/names', { lines: ['plain.example', 'big-site.example'] });
    const { relayId, listenerIds } = await registerRelay(t, {
      listeners: [realityListener({ tlsNames: ['plain.example', 'big-site.example'] })],
    });
    // A mark recorded the way an older build left it: in the table only, the
    // listener's entries unmarked and its pick legacy.
    await t.run(async (ctx) => {
      await ctx.db.insert('sniNameCountry', {
        name: 'big-site.example',
        country: 'CN',
        state: 'blocked',
        source: 'operator',
        updatedAt: Date.now(),
      });
      await ctx.db.patch(listenerIds.a, {
        tlsNames: [
          { name: 'plain.example', status: 'active' },
          { name: 'big-site.example', status: 'active' },
        ],
        sniPick: undefined,
      });
    });
    const epoch = async () => (await t.run((ctx) => ctx.db.get(relayId)))!.publicationEpoch;
    const before = await epoch();
    expect(await t.mutation(internal.relayListeners.reconcileCountryMarks, {})).toEqual({
      changed: 1,
      switched: 1,
    });
    expect(await t.run((ctx) => ctx.db.get(listenerIds.a))).toMatchObject({
      tlsNames: [
        { name: 'plain.example', status: 'active' },
        { name: 'big-site.example', status: 'active', blockedIn: ['CN'] },
      ],
      sniPick: 'hrw1',
    });
    expect(await epoch()).toBe(before + 1);
    // Settled: the next deploy changes nothing and moves nobody.
    expect(await t.mutation(internal.relayListeners.reconcileCountryMarks, {})).toEqual({
      changed: 0,
      switched: 0,
    });
    expect(await epoch()).toBe(before + 1);
    // Back to the legacy pick is refused while a name is judged.
    await expect(
      t.mutation(internal.relayListeners.setSniPick, { id: listenerIds.a, version: null }),
    ).rejects.toThrow(/judged per country/);
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

  test('a rename moves the slug with the name and audits what changed, never the name', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    const renamed = await call('PATCH', 'families/fam-a', { label: '  Shared cover A  ' });
    expect(renamed.status).toBe(200);
    // The answer carries the new slug: the page (and an API caller) moves to it.
    expect(await renamed.json()).toEqual({ ok: true, slug: 'shared-cover-a' });
    const listed = await (await call('GET', 'families')).json();
    expect(listed.families).toEqual([
      expect.objectContaining({
        slug: 'shared-cover-a',
        formerSlugs: ['fam-a'],
        label: 'Shared cover A',
      }),
    ]);
    // The same name again, then switched off: only what moved is recorded.
    await call('PATCH', 'families/shared-cover-a', { label: 'Shared cover A', enabled: false });
    // An empty name falls back to the slug, which then stays where it is.
    await call('PATCH', 'families/shared-cover-a', { label: '   ' });
    const detail = await (await call('GET', 'families/shared-cover-a')).json();
    expect(detail.family).toMatchObject({ slug: 'shared-cover-a', label: 'shared-cover-a' });
    const rows = (await auditRows(t)).filter((r) => r.action === 'edge.sni.family.update');
    expect(rows.map((r) => r.payload)).toEqual([
      { slug: 'shared-cover-a', formerSlug: 'fam-a', changed: ['label', 'slug'] },
      { slug: 'shared-cover-a', changed: ['enabled'] },
      { slug: 'shared-cover-a', changed: ['label'] },
    ]);
    expect(JSON.stringify(rows.map((r) => r.payload))).not.toContain('Shared cover');
  });

  test('the slug a list held before a rename still resolves, on every route', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'families/fam-a', { label: 'Shared cover A' });
    // Reads: the old slug answers with the list as it is now.
    const old = await call('GET', 'families/fam-a');
    expect(old.status).toBe(200);
    expect((await old.json()).family).toMatchObject({
      slug: 'shared-cover-a',
      formerSlugs: ['fam-a'],
    });
    // Writes through the old slug land on the same list.
    expect(
      (await call('POST', 'families/fam-a/names', { lines: ['one.target.example'] })).status,
    ).toBe(200);
    expect((await call('PATCH', 'families/fam-a', { enabled: false })).status).toBe(200);
    const now = await (await call('GET', 'families/shared-cover-a')).json();
    expect(now.family.enabled).toBe(false);
    expect(now.names.map((n: { name: string }) => n.name)).toEqual(['one.target.example']);
    // Every other reader of a list by slug (a saved setup, a seed, a template) finds it too.
    const resolved = await t.run(async (ctx) => {
      const { sniFamilyBySlug } = await import('./lib/edges/sni/slug');
      return {
        former: (await sniFamilyBySlug(ctx.db, 'fam-a'))?.slug,
        current: (await sniFamilyBySlug(ctx.db, 'shared-cover-a'))?.slug,
        unknown: await sniFamilyBySlug(ctx.db, 'never-was'),
      };
    });
    expect(resolved).toEqual({
      former: 'shared-cover-a',
      current: 'shared-cover-a',
      unknown: null,
    });
    // A second rename keeps both; the list is still one row.
    await call('PATCH', 'families/fam-a', { label: 'Third name' });
    const listed = await (await call('GET', 'families')).json();
    expect(listed.families).toEqual([
      expect.objectContaining({ slug: 'third-name', formerSlugs: ['fam-a', 'shared-cover-a'] }),
    ]);
    // A delete through an old slug removes it, and frees every slug it held.
    expect((await call('DELETE', 'families/shared-cover-a')).status).toBe(200);
    expect((await call('GET', 'families/fam-a')).status).toBe(404);
    expect((await call('POST', 'families', family)).status).toBe(200);
  });

  test('a rename onto a slug another list has, or had, is refused; a list may take its own back', async () => {
    const { call } = await seed();
    await call('POST', 'families', family);
    await call('PATCH', 'families/fam-a', { label: 'Second' });
    // The slug it left is held: no new list takes it.
    expect((await call('POST', 'families', family)).status).toBe(409);
    await call('POST', 'families', { ...family, slug: 'fam-b', label: 'Family B' });
    // Another list's slug now, and one another list held before: refused, never suffixed.
    for (const label of ['Second', 'Fam A']) {
      const res = await call('PATCH', 'families/fam-b', { label });
      expect(res.status).toBe(409);
      expect((await res.json()).error.code).toBe('edge.sni.slug_taken');
    }
    const b = await (await call('GET', 'families/fam-b')).json();
    expect(b.family).toMatchObject({ slug: 'fam-b', label: 'Family B', formerSlugs: [] });
    // Its own former slug is its to take back, and the one it leaves is kept.
    const back = await call('PATCH', 'families/second', { label: 'fam a' });
    expect(await back.json()).toEqual({ ok: true, slug: 'fam-a' });
    const a = await (await call('GET', 'families/second')).json();
    expect(a.family).toMatchObject({ slug: 'fam-a', label: 'fam a', formerSlugs: ['second'] });
  });

  test('a name that gives no slug, or the address of an SNIs page, is refused', async () => {
    const { t, call } = await seed();
    await call('POST', 'families', family);
    for (const label of ['Find', 'Settings', 'checks']) {
      const res = await call('PATCH', 'families/fam-a', { label });
      expect(res.status).toBe(409);
      expect((await res.json()).error.code).toBe('edge.sni.slug_reserved');
    }
    const none = await call('PATCH', 'families/fam-a', { label: '***' });
    expect((await none.json()).error.code).toBe('edge.sni.slug_empty');
    const detail = await (await call('GET', 'families/fam-a')).json();
    expect(detail.family).toMatchObject({ slug: 'fam-a', label: 'Family A', formerSlugs: [] });
    expect((await auditRows(t)).filter((r) => r.action === 'edge.sni.family.update')).toEqual([]);
  });

  test('the switches are a settings-scope surface', async () => {
    const { scopeFor } = await import('./httpEdges');
    expect(scopeFor(['sni', 'config'], 'PATCH')).toBe('admin:settings:write');
    expect(scopeFor(['sni', 'config'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['sni', 'families'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['sni', 'families', 'x', 'names'], 'POST')).toBe('admin:servers:manage');
  });
});
