/// <reference types="vite/client" />
/**
 * The relay admin surface (`/api/v1/admin/relays/*`): auth + scopes, the IaC
 * by-slug upsert round trip (origin → slot → adopted edge → publishedEndpoints),
 * account creation without secret echo, the render preview, config patches,
 * and the sealing policy coverage of every verb under the prefix.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import { signValue } from './lib/cookies';
import { sha256Hex } from './lib/crypto';
import {
  bytesToB64Url,
  isSealedWire,
  kidFromPublicKey,
  routePolicy,
} from '../src/shared/crypto/envelope';
import { serializePublicKey, serverKeyPairFromSeed } from '../src/shared/crypto/hpke';
import { clientOpenResponse, clientPrepareRequest } from '../src/shared/crypto/channel';
import {
  RelayAccountsResponse,
  RelayConfigView,
  RelayOriginBySlugResponse,
  RelayRenderPreviewResponse,
  RelaySummary,
} from '../src/shared/contracts/relays';

const modules = import.meta.glob('./**/*.*s');
const ADMIN_SIGN_KEY = 'test-admin-sign';

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

async function adminCookie(t: ReturnType<typeof convexTest>) {
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
  return `fs_admin_session=${await signValue(sid, ADMIN_SIGN_KEY)}`;
}

async function token(t: ReturnType<typeof convexTest>, scopes: string[]): Promise<string> {
  const plaintext = `fsv1_${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
  const tokenHash = await sha256Hex(plaintext);
  await t.run(async (ctx) => {
    const admin = await ctx.db.insert('adminUsers', {
      username: `tok-${plaintext.slice(-8)}`,
      displayName: 'T',
      isActive: true,
      updatedAt: Date.now(),
    });
    await ctx.db.insert('apiTokens', {
      name: 'test',
      tokenHash,
      tokenPrefix: plaintext.slice(0, 12),
      createdByAdminId: admin,
      scopes,
      subjectType: 'service',
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

async function seed() {
  const t = convexTest(schema, modules);
  await t.run((ctx) =>
    ctx.db.insert('backendServers', {
      backend: 'remnawave',
      name: 'panel-a',
      slug: 'panel-a',
      config: { type: 'remnawave', baseUrl: 'https://panel.example', apiToken: 'tok' },
      isActive: true,
      priority: 0,
      keyCount: 0,
      updatedAt: Date.now(),
    }),
  );
  const cookie = await adminCookie(t);
  const call = (
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    t.fetch(`/api/v1/admin/relays/${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  return { t, cookie, call };
}

const SLOT = {
  profileSlug: 'prof-u',
  inboundTag: 'VLESS_RELAY_U',
  configProfileUuid: '11111111-1111-4111-8111-111111111111',
  configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
  originPort: 443,
};

describe('relay admin routes', () => {
  test('sealing policy: every verb under the prefix is covered (GET reveal, POST both, PATCH/PUT seal, DELETE plain)', () => {
    const p = '/api/v1/admin/relays/origins/by-slug/x';
    expect(routePolicy(p, 'GET')).toEqual({ request: 'plain', response: 'reveal' });
    expect(routePolicy('/api/v1/admin/relays/render/preview', 'POST')).toEqual({
      request: 'seal',
      response: 'reveal',
    });
    expect(routePolicy('/api/v1/admin/relays/config', 'PATCH')).toEqual({
      request: 'seal',
      response: 'plain',
    });
    expect(routePolicy(p, 'PUT')).toEqual({ request: 'seal', response: 'plain' });
    expect(routePolicy(p, 'DELETE')).toBeUndefined();
    expect(routePolicy('/api/v1/admin/relays/summary', 'GET')).toEqual({
      request: 'plain',
      response: 'reveal',
    });
  });

  test('auth: anonymous 401; a servers:read token reads but cannot write; config needs the settings scope', async () => {
    const { t } = await seed();
    const anon = await t.fetch('/api/v1/admin/relays/summary');
    expect(anon.status).toBe(401);
    const reader = await token(t, ['admin:servers:read']);
    const ok = await t.fetch('/api/v1/admin/relays/summary', {
      headers: { authorization: `Bearer ${reader}` },
    });
    expect(ok.status).toBe(200);
    const denied = await t.fetch('/api/v1/admin/relays/origins', {
      method: 'POST',
      headers: { authorization: `Bearer ${reader}`, 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'x' }),
    });
    expect([401, 403]).toContain(denied.status);
    const cfgDenied = await t.fetch('/api/v1/admin/relays/config', {
      headers: { authorization: `Bearer ${reader}` },
    });
    expect([401, 403]).toContain(cfgDenied.status);
    const settings = await token(t, ['admin:settings:read']);
    const cfgOk = await t.fetch('/api/v1/admin/relays/config', {
      headers: { authorization: `Bearer ${settings}` },
    });
    expect(cfgOk.status).toBe(200);
  });

  test('IaC round trip: by-slug origin upsert, slot upsert, adopt + publish, publishedEndpoints for the role', async () => {
    const { t, call } = await seed();
    // Provider account + profile first (the slot's profile is provider-scoped).
    const acct = await call('POST', 'providers', {
      provider: 'upcloud',
      name: 'acct-u',
      settings: { zone: 'de-fra1' },
      credentials: { token: 'SECRET_TOKEN_VALUE' },
    });
    expect(acct.status).toBe(200);
    const list = RelayAccountsResponse.parse(await (await call('GET', 'providers')).json());
    expect(list.accounts).toHaveLength(1);
    expect(list.accounts[0].credentialsSet).toEqual({ token: true });
    expect(list.credentialFields.upcloud).toEqual(['token']);
    expect(JSON.stringify(list)).not.toContain('SECRET_TOKEN_VALUE');
    const prof = await call('POST', 'profiles', {
      slug: 'prof-u',
      name: 'Profile U',
      provider: 'upcloud',
      targetAddress: 'target.example',
      serverNames: ['a.example', 'b.example'],
    });
    expect(prof.status).toBe(200);

    // Origin by slug (idempotent), then the slot by key.
    const put1 = await call('PUT', 'origins/by-slug/node-one', {
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-one',
      originAddress: '203.0.113.10',
    });
    expect(put1.status).toBe(200);
    const view1 = RelayOriginBySlugResponse.parse(await put1.json());
    expect(view1.origin.slug).toBe('node-one');
    expect(view1.publishedEndpoints).toEqual([]);
    const slot = await call('PUT', 'origins/by-slug/node-one/slots/u', SLOT);
    expect(slot.status).toBe(200);
    expect(await slot.json()).toMatchObject({
      created: true,
      templateHostRemark: 'node-one-relay-u',
    });
    const slotAgain = await call('PUT', 'origins/by-slug/node-one/slots/u', SLOT);
    expect(await slotAgain.json()).toMatchObject({ created: false });
    const slotGet = await call('GET', 'origins/by-slug/node-one/slots/u');
    expect(slotGet.status).toBe(200);
    expect(await slotGet.json()).toMatchObject({
      slotKey: 'u',
      profileSlug: 'prof-u',
      provider: 'upcloud',
    });

    // Adopt the hand-made edge and publish it at index 0.
    const view2 = RelayOriginBySlugResponse.parse(
      await (await call('GET', 'origins/by-slug/node-one')).json(),
    );
    const slotId = view2.slots[0].id;
    const adopt = await call('POST', `origins/${view2.origin.id}/adopt`, {
      slotId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
    });
    expect(adopt.status).toBe(200);
    expect(await adopt.json()).toMatchObject({ poolIndex: 0 });
    const view3 = RelayOriginBySlugResponse.parse(
      await (await call('GET', 'origins/by-slug/node-one')).json(),
    );
    expect(view3.publishedEndpoints).toHaveLength(1);
    expect(view3.publishedEndpoints[0]).toMatchObject({
      poolIndex: 0,
      slotKey: 'u',
      slotRemark: 'node-one-relay-u',
      port: 443,
      addresses: { v4: '198.51.100.7', v6: '2001:db8::7' },
      activeServerNames: ['a.example', 'b.example'],
    });
    // Edges + summary + endpoints views.
    const edges = await (await call('GET', `edges?originId=${view2.origin.id}`)).json();
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ managed: false, publication: 'published', poolIndex: 0 });
    const summary = RelaySummary.parse(await (await call('GET', 'summary')).json());
    expect(summary.counts).toMatchObject({ origins: 1, published: 1, suspected: 0, rotating: 0 });
    expect(summary.origins[0].pool[0]).toMatchObject({
      poolIndex: 0,
      addresses: { v4: '198.51.100.7' },
    });
    const endpoints = await (await call('GET', `origins/${view2.origin.id}/endpoints`)).json();
    expect(endpoints.sample.primary).toMatchObject({ edgeId: edges[0].id });
    expect(['a.example', 'b.example']).toContain(endpoints.sample.primary.sni);

    // Render preview: per-family synthetic body, the edge replaces the template, never the origin.
    const prev = await call('POST', 'render/preview', {
      originId: view2.origin.id,
      family: 'v2rayng',
    });
    expect(prev.status).toBe(200);
    const preview = RelayRenderPreviewResponse.parse(await prev.json());
    expect(preview.format).toBe('links');
    // Rendering is off by default → passthrough with the reason.
    expect(preview.applied).toBe(false);
    expect(preview.reason).toBe('disabled');
    const patched = await call('PATCH', 'config', { render: { enabled: true } });
    expect(await patched.json()).toEqual({ changedKeys: ['render.enabled'] });
    const preview2 = RelayRenderPreviewResponse.parse(
      await (
        await call('POST', 'render/preview', { originId: view2.origin.id, family: 'v2rayng' })
      ).json(),
    );
    expect(preview2.applied).toBe(true);
    expect(preview2.body).toContain('198.51.100.7');
    expect(preview2.body).toContain('FreeSocks%20Primary');
    expect(preview2.body).not.toContain('node-one-relay-u');
    const singbox = RelayRenderPreviewResponse.parse(
      await (
        await call('POST', 'render/preview', { originId: view2.origin.id, family: 'singbox' })
      ).json(),
    );
    expect(singbox.format).toBe('singbox-json');
    expect(
      JSON.parse(singbox.body).outbounds.some((o: { type: string }) => o.type === 'urltest'),
    ).toBe(true);

    // Delete by slug → teardown request; unmanaged edges are forgotten by reconcile.
    const del = await call('DELETE', 'origins/by-slug/node-one');
    expect(del.status).toBe(200);
    expect(await del.json()).toMatchObject({ ok: true });
    const gone = await call('GET', 'origins/by-slug/missing');
    expect(gone.status).toBe(404);
  });

  test('config: GET returns the sanitized namespace + secret status; PATCH writes are audited as keys only', async () => {
    const { t, call } = await seed();
    const view = RelayConfigView.parse(await (await call('GET', 'config')).json());
    expect(view.config.render.enabled).toBe(false);
    expect(view.secrets).toEqual({ globalpingToken: false, ripeAtlasKey: false });
    expect(view.families).toContain('singbox');
    const res = await call('PATCH', 'config', {
      probe: { enabled: true, countries: ['ir', 'RU'] },
      render: { clients: { v2rayng: { enabled: false } } },
      secrets: { globalpingToken: 'gp_SECRET' },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.changedKeys.sort()).toEqual(
      ['probe.countries', 'probe.enabled', 'probe.secret', 'render.clients.v2rayng'].sort(),
    );
    const after = RelayConfigView.parse(await (await call('GET', 'config')).json());
    expect(after.config.probe.enabled).toBe(true);
    expect(after.config.probe.countries).toEqual(['IR', 'RU']);
    expect(after.config.render.clients.v2rayng.enabled).toBe(false);
    expect(after.secrets.globalpingToken).toBe(true);
    expect(JSON.stringify(after)).not.toContain('gp_SECRET');
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const a = audit.find((x) => x.action === 'admin.relay.config.change');
    expect(a?.payload).toEqual({
      changedKeys: expect.arrayContaining(['probe.enabled', 'probe.secret']),
    });
    expect(JSON.stringify(audit)).not.toContain('gp_SECRET');
    // Unknown paths are ignored, never written.
    const junk = await call('PATCH', 'config', { nonsense: true, render: { nope: 1 } });
    expect(await junk.json()).toEqual({ changedKeys: [] });
  });

  test('validation errors come back as the JSON envelope, not 500s', async () => {
    const { call } = await seed();
    const bad = await call('PUT', 'origins/by-slug/node-two', {
      backendServerSlug: 'missing',
      nodeHostname: 'node-two',
      originAddress: 'x',
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: { code: 'validation' } });
    const missing = await call('GET', 'edges/abc');
    expect([400, 404]).toContain(missing.status);
    const unknown = await call('GET', 'nothing/here');
    expect(unknown.status).toBe(404);
  });

  test('seal-both end to end: a sealed POST body is opened, and the response is sealed to the request ephemeral', async () => {
    const SERVER_SEED = new Uint8Array(32).fill(9);
    vi.stubEnv('FS_SERVER_HPKE_SK', bytesToB64Url(SERVER_SEED));
    const kp = await serverKeyPairFromSeed(SERVER_SEED);
    const kid = await kidFromPublicKey(await serializePublicKey(kp.publicKey));
    const { t, call, cookie } = await seed();
    await call('POST', 'profiles', {
      slug: 'prof-u',
      name: 'Profile U',
      provider: 'upcloud',
      targetAddress: 'target.example',
      serverNames: ['a.example'],
    });
    const put = RelayOriginBySlugResponse.parse(
      await (
        await call('PUT', 'origins/by-slug/node-one', {
          backendServerSlug: 'panel-a',
          nodeHostname: 'node-one',
          originAddress: '203.0.113.10',
        })
      ).json(),
    );
    const path = '/api/v1/admin/relays/render/preview';
    const prep = await clientPrepareRequest({
      serverPub: kp.publicKey,
      serverKid: kid,
      method: 'POST',
      path,
      policy: routePolicy(path, 'POST')!,
      bodyObj: { originId: put.origin.id, family: 'v2rayng' },
    });
    expect(isSealedWire(prep.body)).toBe(true);
    const res = await t.fetch(path, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify(prep.body),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-fs-sealed')).toBe('1');
    const wire = await res.json();
    expect(isSealedWire(wire)).toBe(true);
    const opened = RelayRenderPreviewResponse.parse(
      await clientOpenResponse({
        serverKid: kid,
        method: 'POST',
        path,
        respEphPriv: prep.respEphPriv!,
        wire,
      }),
    );
    expect(opened.family).toBe('v2rayng');
    expect(opened.format).toBe('links');
  });
});
