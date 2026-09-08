/// <reference types="vite/client" />
/**
 * The relay admin surface (`/api/v1/admin/edges/*`): auth + scopes, the IaC
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
import { z } from 'zod';
import {
  EDGE_PROVIDER_IDS,
  EdgeAdmin,
  EdgeDetail,
  EdgeInventoryResponse,
  EdgeProviderAccountsResponse,
  EdgeConfigView,
  EdgeRotationDetail,
  EdgeRotationStartedResponse,
  EdgeTemplatesResponse,
  ProbeAuditResponse,
  ProbeReachabilityMatrix,
  ProbeRequestedResponse,
  ProbeRunsResponse,
  ProbeSummary,
  ProbeTargetsResponse,
  RelayBySlugMinimalResponse,
  RelayBySlugResponse,
  RelayEndpointsResponse,
  EdgeRenderPreviewResponse,
  EdgeSummary,
} from '../src/shared/contracts/edges';
import { scopeFor, throttlePolicyFor } from './httpEdges';

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
    t.fetch(`/api/v1/admin/edges/${path}`, {
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

/** seed() + provider account + profile + relay + slot + a published (index 0) and an unpublished adopted edge. */
async function fixture() {
  const s = await seed();
  const { call } = s;
  const acct = (await (
    await call('POST', 'providers', {
      provider: 'upcloud',
      name: 'acct-u',
      settings: { zone: 'de-fra1' },
      credentials: { token: 'SECRET_TOKEN_VALUE' },
    })
  ).json()) as { id: string };
  await call('POST', 'profiles', {
    slug: 'prof-u',
    name: 'Profile U',
    provider: 'upcloud',
    targetAddress: 'target.example',
    serverNames: ['a.example', 'b.example'],
  });
  const view = RelayBySlugResponse.parse(
    await (
      await call('PUT', 'relays/by-slug/node-one', {
        backendServerSlug: 'panel-a',
        nodeHostname: 'node-one',
        originAddress: '203.0.113.10',
      })
    ).json(),
  );
  await call('PUT', 'relays/by-slug/node-one/slots/u', SLOT);
  const slots = RelayBySlugResponse.parse(
    await (await call('GET', 'relays/by-slug/node-one')).json(),
  ).slots;
  const slotId = slots[0].id;
  const relayId = view.relay.id;
  const published = (await (
    await call('POST', `relays/${relayId}/adopt`, {
      slotId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
    })
  ).json()) as { edgeId: string };
  const standby = (await (
    await call('POST', `relays/${relayId}/adopt`, { slotId, ipv4: '198.51.100.8', publish: false })
  ).json()) as { edgeId: string };
  return {
    ...s,
    accountId: acct.id,
    relayId,
    slotId,
    publishedEdgeId: published.edgeId,
    standbyEdgeId: standby.edgeId,
  };
}

/** A raw `t.fetch` against the prefix with a bearer token (no cookie). */
function bearerCall(t: ReturnType<typeof convexTest>, tok: string) {
  return (method: string, path: string, body?: unknown) =>
    t.fetch(`/api/v1/admin/edges/${path}`, {
      method,
      headers: { authorization: `Bearer ${tok}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
}

describe('relay admin routes', () => {
  test('sealing policy: every verb under the prefix is covered (GET reveal, POST both, PATCH/PUT seal, DELETE plain)', () => {
    const p = '/api/v1/admin/edges/relays/by-slug/x';
    expect(routePolicy(p, 'GET')).toEqual({ request: 'plain', response: 'reveal' });
    expect(routePolicy('/api/v1/admin/edges/render/preview', 'POST')).toEqual({
      request: 'seal',
      response: 'reveal',
    });
    expect(routePolicy('/api/v1/admin/edges/config', 'PATCH')).toEqual({
      request: 'seal',
      response: 'plain',
    });
    expect(routePolicy(p, 'PUT')).toEqual({ request: 'seal', response: 'plain' });
    expect(routePolicy(p, 'DELETE')).toBeUndefined();
    expect(routePolicy('/api/v1/admin/edges/summary', 'GET')).toEqual({
      request: 'plain',
      response: 'reveal',
    });
  });

  test('sealing policy by route class: every GET reveals, every POST seals both legs, PATCH/PUT seal the request, no DELETE is sealed', () => {
    const P = '/api/v1/admin/edges/';
    const REVEAL = { request: 'plain', response: 'reveal' };
    const BOTH = { request: 'seal', response: 'reveal' };
    const REQ = { request: 'seal', response: 'plain' };
    // reads: config, providers (+inventory), templates, profiles, relays, edges, rotations, probes
    for (const g of [
      'config',
      'providers',
      'providers/acc1/inventory',
      'templates',
      'profiles',
      'relays',
      'relays/node-candidates?backendServerId=x',
      'relays/r1/endpoints',
      'relays/r1/slots',
      'list?relayId=r1',
      'e1',
      'e1/live',
      'rotations/rot1',
      'probes/matrix',
      'probes/summary',
      'probes/targets',
      'probes/audit',
    ]) {
      expect(routePolicy(P + g.split('?')[0], 'GET')).toEqual(REVEAL);
    }
    // writes + provider calls: credential uploads and every action POST carry secrets / handles
    for (const p of [
      'providers',
      'providers/discover',
      'providers/test-credentials',
      'providers/acc1/inventory/refresh',
      'providers/acc1/qualify',
      'templates',
      'templates/validate',
      'templates/ensure-defaults',
      'profiles',
      'relays',
      'relays/node-candidates/refresh',
      'relays/r1/adopt',
      'relays/r1/burn',
      'relays/r1/probe',
      'e1/publish',
      'e1/live/refresh',
      'e1/probe',
      'e1/retry-destroy',
      'probes',
      'probes/targets',
      'render/preview',
    ]) {
      expect(routePolicy(P + p, 'POST')).toEqual(BOTH);
    }
    for (const p of ['config', 'providers/acc1', 'templates/t1', 'profiles/p1', 'relays/r1']) {
      expect(routePolicy(P + p, 'PATCH')).toEqual(REQ);
    }
    for (const p of ['relays/by-slug/n1', 'relays/by-slug/n1/slots/u']) {
      expect(routePolicy(P + p, 'PUT')).toEqual(REQ);
    }
    for (const p of ['providers/acc1', 'templates/t1', 'relays/r1', 'relays/by-slug/n1', 'e1']) {
      expect(routePolicy(P + p, 'DELETE')).toBeUndefined();
    }
  });

  test('scope table: config → settings, everything else → servers; only render/preview + templates/validate are read-scoped POSTs', () => {
    expect(scopeFor(['config'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['config'], 'PATCH')).toBe('admin:settings:write');
    expect(scopeFor(['summary'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['render', 'preview'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['templates', 'validate'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['templates'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['templates', 'ensure-defaults'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['render', 'preview', 'x'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['providers', 'a'], 'PATCH')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'r'], 'DELETE')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'by-slug', 'n'], 'PUT')).toBe('admin:servers:write');
  });

  test('throttle table: the provider-calling POSTs and the probe POSTs are the only throttled routes', () => {
    const P = 'admin.edges.provider-call';
    expect(throttlePolicyFor(['providers', 'discover'])).toBe(P);
    expect(throttlePolicyFor(['providers', 'test-credentials'])).toBe(P);
    expect(throttlePolicyFor(['providers', 'a1', 'inventory', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['relays', 'node-candidates', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'live', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['render', 'preview'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'probe'])).toBe('admin.edges.probe');
    expect(throttlePolicyFor(['relays', 'r1', 'probe'])).toBe('admin.edges.probe');
    expect(throttlePolicyFor(['probes'])).toBe('admin.edges.probe');
    for (const p of [
      ['providers'],
      ['providers', 'a1', 'qualify'],
      ['templates'],
      ['templates', 'validate'],
      ['relays'],
      ['relays', 'r1', 'adopt'],
      ['relays', 'r1', 'burn'],
      ['edges', 'e1', 'publish'],
      ['probes', 'targets'],
    ]) {
      expect(throttlePolicyFor(p)).toBeNull();
    }
  });

  test('auth: anonymous 401; a servers:read token reads but cannot write; config needs the settings scope', async () => {
    const { t } = await seed();
    const anon = await t.fetch('/api/v1/admin/edges/summary');
    expect(anon.status).toBe(401);
    const reader = await token(t, ['admin:servers:read']);
    const ok = await t.fetch('/api/v1/admin/edges/summary', {
      headers: { authorization: `Bearer ${reader}` },
    });
    expect(ok.status).toBe(200);
    const denied = await t.fetch('/api/v1/admin/edges/relays', {
      method: 'POST',
      headers: { authorization: `Bearer ${reader}`, 'content-type': 'application/json' },
      body: JSON.stringify({ slug: 'x' }),
    });
    expect([401, 403]).toContain(denied.status);
    const cfgDenied = await t.fetch('/api/v1/admin/edges/config', {
      headers: { authorization: `Bearer ${reader}` },
    });
    expect([401, 403]).toContain(cfgDenied.status);
    const settings = await token(t, ['admin:settings:read']);
    const cfgOk = await t.fetch('/api/v1/admin/edges/config', {
      headers: { authorization: `Bearer ${settings}` },
    });
    expect(cfgOk.status).toBe(200);
  });

  test('scopes pinned: servers:read cannot PATCH providers / burn / DELETE relays but may preview + validate; settings:write alone reaches only config', async () => {
    const { t, accountId, relayId, publishedEdgeId } = await fixture();
    const reader = bearerCall(t, await token(t, ['admin:servers:read']));
    expect((await reader('PATCH', `providers/${accountId}`, { name: 'renamed' })).status).toBe(401);
    expect(
      (await reader('POST', `relays/${relayId}/burn`, { edgeId: publishedEdgeId })).status,
    ).toBe(401);
    expect((await reader('DELETE', `relays/${relayId}`)).status).toBe(401);
    expect((await reader('POST', `templates/ensure-defaults`, {})).status).toBe(401);
    // Pure reads over POST: the read scope is enough.
    const preview = await reader('POST', 'render/preview', { relayId, family: 'v2rayng' });
    expect(preview.status).toBe(200);
    EdgeRenderPreviewResponse.parse(await preview.json());
    const validate = await reader('POST', 'templates/validate', {
      provider: 'upcloud',
      params: {},
    });
    expect(validate.status).toBe(200);
    expect(await validate.json()).toHaveProperty('ok');
    // The relay still exists and the account is untouched.
    expect((await reader('GET', `relays/by-slug/node-one`)).status).toBe(200);

    const settingsWriter = bearerCall(t, await token(t, ['admin:settings:write']));
    expect((await settingsWriter('GET', 'summary')).status).toBe(401);
    expect((await settingsWriter('GET', 'providers')).status).toBe(401);
    expect((await settingsWriter('POST', 'relays', { slug: 'x' })).status).toBe(401);
    expect(
      (await settingsWriter('POST', 'render/preview', { relayId, family: 'other' })).status,
    ).toBe(401);
    expect((await settingsWriter('DELETE', `relays/${relayId}`)).status).toBe(401);
    expect((await settingsWriter('PATCH', 'config', { render: { enabled: false } })).status).toBe(
      200,
    );
    // A percent-encoded `config` still resolves to the settings scope (decode precedes the scope check).
    expect((await settingsWriter('GET', '%63onfig')).status).toBe(401);
    expect(
      (await bearerCall(t, await token(t, ['admin:settings:read']))('GET', '%63onfig')).status,
    ).toBe(200);
  });

  test('malformed percent escapes answer 400 validation on every verb (the unsealed DELETE included)', async () => {
    const { t, call, cookie } = await seed();
    for (const [method, path] of [
      ['GET', 'relays/by-slug/%E0%A4%A'],
      ['POST', 'relays/%ZZ/probe'],
      ['PATCH', 'providers/%E0%A4%A'],
      ['PUT', 'relays/by-slug/%E0%A4%A'],
      ['DELETE', 'relays/by-slug/%E0%A4%A'],
    ] as const) {
      const res = await call(
        method,
        path,
        method === 'GET' || method === 'DELETE' ? undefined : {},
      );
      expect(res.status, `${method} ${path}`).toBe(400);
      expect(await res.json()).toMatchObject({ error: { code: 'validation' } });
    }
    // Anonymous too: never a 500.
    const anon = await t.fetch('/api/v1/admin/edges/relays/by-slug/%E0%A4%A', { method: 'DELETE' });
    expect(anon.status).toBe(400);
    void cookie;
  });

  test('fail(): a non-ConvexError logs only its class + a request id, never the message (argument values)', async () => {
    const { call } = await seed();
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const res = await call('GET', 'edges/not-a-real-id-VALUE');
      expect(res.status).toBe(400);
      const body = (await res.json()) as {
        error: { code: string; details?: { requestId?: string } };
      };
      expect(body.error.code).toBe('admin.error');
      expect(body.error.details?.requestId).toMatch(/\w+/);
      expect(spy).toHaveBeenCalled();
      const logged = spy.mock.calls.map((c) => c.map(String).join(' ')).join('\n');
      expect(logged).toContain('[edges] unhandled error kind=');
      expect(logged).toContain(body.error.details!.requestId!);
      expect(logged).not.toContain('not-a-real-id-VALUE');
    } finally {
      spy.mockRestore();
    }
  });

  test('rate limit: the provider-calling POSTs trip per actor; another actor keeps its own bucket', async () => {
    const { t, call, relayId } = await fixture();
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'admin.edges.provider-call',
      max: 2,
      windowMs: 60_000,
      enabled: true,
    });
    const body = { relayId, family: 'v2rayng' };
    expect((await call('POST', 'render/preview', body)).status).toBe(200);
    expect((await call('POST', 'render/preview', body)).status).toBe(200);
    const third = await call('POST', 'render/preview', body);
    expect(third.status).toBe(429);
    expect(await third.json()).toMatchObject({
      error: { code: 'rate_limit.exceeded', details: { retryAfterMs: expect.any(Number) } },
    });
    // A different actor (a token) is a different bucket.
    const reader = bearerCall(t, await token(t, ['admin:servers:read']));
    expect((await reader('POST', 'render/preview', body)).status).toBe(200);
    // Non-throttled writes on the same actor are unaffected.
    expect((await call('PATCH', 'config', { render: { enabled: true } })).status).toBe(200);
    // The probe policy is its own bucket.
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'admin.edges.probe',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const { publishedEdgeId } = await (async () => {
      const edges = z
        .array(EdgeAdmin)
        .parse(await (await call('GET', `list?relayId=${relayId}`)).json());
      return { publishedEdgeId: edges.find((e) => e.publication === 'published')!.id };
    })();
    expect((await call('POST', `${publishedEdgeId}/probe`, {})).status).toBe(200);
    expect((await call('POST', `${publishedEdgeId}/probe`, {})).status).toBe(429);
  });

  test('per-edge probe: audited with the actor, returns the run ids; a skipped-only target is an error', async () => {
    const { t, call, publishedEdgeId, relayId, slotId } = await fixture();
    const res = await call('POST', `${publishedEdgeId}/probe`, {});
    expect(res.status).toBe(200);
    const parsed = ProbeRequestedResponse.parse(await res.json());
    expect(parsed.runIds.length).toBeGreaterThan(0);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const row = audit.find((a) => a.action === 'probe.requested');
    expect(row?.actorType).toBe('admin');
    expect(row?.actorId).toBeTruthy();
    // An edge without any address cannot be probed: the skip surfaces as the error code.
    const noAddr = (await (
      await call('POST', `relays/${relayId}/adopt`, { slotId, publish: false })
    ).json()) as { edgeId?: string; error?: unknown };
    if (noAddr.edgeId) {
      const bad = await call('POST', `${noAddr.edgeId}/probe`, {});
      expect(bad.status).toBe(409);
      expect(await bad.json()).toMatchObject({ error: { code: 'edge.no_address' } });
    }
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
    const list = EdgeProviderAccountsResponse.parse(await (await call('GET', 'providers')).json());
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
    const put1 = await call('PUT', 'relays/by-slug/node-one', {
      backendServerSlug: 'panel-a',
      nodeHostname: 'node-one',
      originAddress: '203.0.113.10',
    });
    expect(put1.status).toBe(200);
    const view1 = RelayBySlugResponse.parse(await put1.json());
    expect(view1.relay.slug).toBe('node-one');
    expect(view1.publishedEndpoints).toEqual([]);
    const slot = await call('PUT', 'relays/by-slug/node-one/slots/u', SLOT);
    expect(slot.status).toBe(200);
    expect(await slot.json()).toMatchObject({
      created: true,
      templateHostRemark: 'node-one-relay-u',
    });
    const slotAgain = await call('PUT', 'relays/by-slug/node-one/slots/u', SLOT);
    expect(await slotAgain.json()).toMatchObject({ created: false });
    const slotGet = await call('GET', 'relays/by-slug/node-one/slots/u');
    expect(slotGet.status).toBe(200);
    expect(await slotGet.json()).toMatchObject({
      slotKey: 'u',
      profileSlug: 'prof-u',
      provider: 'upcloud',
    });

    // Adopt the hand-made edge and publish it at index 0.
    const view2 = RelayBySlugResponse.parse(
      await (await call('GET', 'relays/by-slug/node-one')).json(),
    );
    const slotId = view2.slots[0].id;
    const adopt = await call('POST', `relays/${view2.relay.id}/adopt`, {
      slotId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
    });
    expect(adopt.status).toBe(200);
    expect(await adopt.json()).toMatchObject({ poolIndex: 0 });
    const view3 = RelayBySlugResponse.parse(
      await (await call('GET', 'relays/by-slug/node-one')).json(),
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
    const edges = await (await call('GET', `edges?relayId=${view2.relay.id}`)).json();
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({ managed: false, publication: 'published', poolIndex: 0 });
    const summary = EdgeSummary.parse(await (await call('GET', 'summary')).json());
    expect(summary.counts).toMatchObject({ relays: 1, published: 1, suspected: 0, rotating: 0 });
    expect(summary.relays[0].pool[0]).toMatchObject({
      poolIndex: 0,
      addresses: { v4: '198.51.100.7' },
    });
    const endpoints = await (await call('GET', `relays/${view2.relay.id}/endpoints`)).json();
    expect(endpoints.sample.primary).toMatchObject({ edgeId: edges[0].id });
    expect(['a.example', 'b.example']).toContain(endpoints.sample.primary.sni);

    // Render preview: per-family synthetic body, the edge replaces the template, never the origin.
    const prev = await call('POST', 'render/preview', {
      relayId: view2.relay.id,
      family: 'v2rayng',
    });
    expect(prev.status).toBe(200);
    const preview = EdgeRenderPreviewResponse.parse(await prev.json());
    expect(preview.format).toBe('links');
    // Rendering is off by default → passthrough with the reason.
    expect(preview.applied).toBe(false);
    expect(preview.reason).toBe('disabled');
    const patched = await call('PATCH', 'config', { render: { enabled: true } });
    expect(await patched.json()).toEqual({ changedKeys: ['render.enabled'] });
    const preview2 = EdgeRenderPreviewResponse.parse(
      await (
        await call('POST', 'render/preview', { relayId: view2.relay.id, family: 'v2rayng' })
      ).json(),
    );
    expect(preview2.applied).toBe(true);
    expect(preview2.body).toContain('198.51.100.7');
    expect(preview2.body).toContain('FreeSocks%20Primary');
    expect(preview2.body).not.toContain('node-one-relay-u');
    const singbox = EdgeRenderPreviewResponse.parse(
      await (
        await call('POST', 'render/preview', { relayId: view2.relay.id, family: 'singbox' })
      ).json(),
    );
    expect(singbox.format).toBe('singbox-json');
    expect(
      JSON.parse(singbox.body).outbounds.some((o: { type: string }) => o.type === 'urltest'),
    ).toBe(true);

    // Delete by slug → teardown request; unmanaged edges are forgotten by reconcile.
    const del = await call('DELETE', 'relays/by-slug/node-one');
    expect(del.status).toBe(200);
    expect(await del.json()).toMatchObject({ ok: true });
    const gone = await call('GET', 'relays/by-slug/missing');
    expect(gone.status).toBe(404);
  });

  test('config: GET returns the sanitized namespace + secret status; PATCH writes are audited as keys only', async () => {
    const { t, call } = await seed();
    const view = EdgeConfigView.parse(await (await call('GET', 'config')).json());
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
    const after = EdgeConfigView.parse(await (await call('GET', 'config')).json());
    expect(after.config.probe.enabled).toBe(true);
    expect(after.config.probe.countries).toEqual(['IR', 'RU']);
    expect(after.config.render.clients.v2rayng.enabled).toBe(false);
    expect(after.secrets.globalpingToken).toBe(true);
    expect(JSON.stringify(after)).not.toContain('gp_SECRET');
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const a = audit.find((x) => x.action === 'admin.edge.config.change');
    expect(a?.payload).toEqual({
      changedKeys: expect.arrayContaining(['probe.enabled', 'probe.secret']),
    });
    expect(JSON.stringify(audit)).not.toContain('gp_SECRET');
    // Unknown paths are ignored, never written.
    const junk = await call('PATCH', 'config', { nonsense: true, render: { nope: 1 } });
    expect(await junk.json()).toEqual({ changedKeys: [] });
  });

  test('templates: GET is a pure read (no seeding); POST ensure-defaults seeds once under the write scope', async () => {
    const { t, call } = await seed();
    const reader = bearerCall(t, await token(t, ['admin:servers:read']));
    const res = await reader('GET', 'templates');
    expect(res.status).toBe(200);
    const body = EdgeTemplatesResponse.parse(await res.json());
    expect(body.templates).toEqual([]);
    const n = EDGE_PROVIDER_IDS.length;
    expect(Object.keys(body.schemas).sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
    expect(await t.run((ctx) => ctx.db.query('edgeTemplates').collect())).toHaveLength(0);
    // Seeding is the explicit write.
    expect((await reader('POST', 'templates/ensure-defaults', {})).status).toBe(401);
    const seeded = await call('POST', 'templates/ensure-defaults', {});
    expect(seeded.status).toBe(200);
    expect(await seeded.json()).toEqual({ created: n });
    const after = EdgeTemplatesResponse.parse(await (await call('GET', 'templates')).json());
    expect(after.templates.filter((x) => x.isDefault)).toHaveLength(n);
    expect(Object.keys(after.schemas).sort()).toEqual(
      after.templates.map((x) => x.provider).sort(),
    );
    // Idempotent.
    expect(await (await call('POST', 'templates/ensure-defaults', {})).json()).toEqual({
      created: 0,
    });
  });

  test('contract pinning: every shape the CMS parses matches the server output', async () => {
    const { t, call, accountId, relayId, publishedEdgeId, standbyEdgeId } = await fixture();
    // Edge list + detail (with a recorded live snapshot so `live` is non-null).
    const list = z
      .array(EdgeAdmin)
      .parse(await (await call('GET', `list?relayId=${relayId}`)).json());
    expect(list.map((e) => e.id).sort()).toEqual([publishedEdgeId, standbyEdgeId].sort());
    await t.mutation(internal.edgeAdmin.recordLive, {
      edgeId: publishedEdgeId as never,
      snapshot: JSON.stringify({
        summary: {
          status: 'running',
          addresses: { v4: '198.51.100.7' },
          members: [{ address: '203.0.113.10', port: 443, health: 'up' }],
          listeners: [{ port: 443, protocol: 'tcp' }],
        },
        raw: { provider_internal: 'x' },
      }),
    });
    await call('POST', `${publishedEdgeId}/probe`, {});
    const detail = EdgeDetail.parse(await (await call('GET', publishedEdgeId)).json());
    expect(detail.live?.summary.status).toBe('running');
    expect(detail.probes.length).toBeGreaterThan(0);
    expect(EdgeDetail.parse(await (await call('GET', standbyEdgeId)).json()).live).toBeNull();
    // Rotation detail: publish the standby through the machine (index 1 → no Host flip).
    const started = EdgeRotationStartedResponse.parse(
      await (await call('POST', `${standbyEdgeId}/publish`, {})).json(),
    );
    const rot = EdgeRotationDetail.parse(
      await (await call('GET', `rotations/${started.rotationId}`)).json(),
    );
    expect(rot.kind).toBe('publish');
    expect(rot.toEdgeId).toBe(standbyEdgeId);
    expect(rot.audit.length).toBeGreaterThan(0);
    // Inventory: null before a pull, the recorded snapshot after.
    expect(
      EdgeInventoryResponse.parse(
        await (await call('GET', `providers/${accountId}/inventory`)).json(),
      ),
    ).toMatchObject({ inventory: null, inventoryAt: null });
    await t.mutation(internal.edgeProviderAccounts.recordInventory, {
      id: accountId as never,
      inventory: JSON.stringify({
        loadBalancers: [
          { id: 'lb-1', name: 'lb-one', status: 'running', addresses: { v4: '198.51.100.7' } },
        ],
        ips: [{ id: 'ip-1', address: '198.51.100.7', attachedTo: 'lb-1' }],
        flavors: [{ id: 'f1', label: 'small' }],
      }),
    });
    const inv = EdgeInventoryResponse.parse(
      await (await call('GET', `providers/${accountId}/inventory`)).json(),
    );
    expect(inv.inventory?.loadBalancers).toHaveLength(1);
    expect(inv.inventoryAt).toBeTruthy();
    // Endpoints + by-slug (full and the proposed minimal projection parse the same payload).
    const endpoints = RelayEndpointsResponse.parse(
      await (await call('GET', `relays/${relayId}/endpoints`)).json(),
    );
    expect(endpoints.published[0].edgeId).toBe(publishedEdgeId);
    const bySlug = await (await call('GET', 'relays/by-slug/node-one')).json();
    RelayBySlugResponse.parse(bySlug);
    const minimal = RelayBySlugMinimalResponse.parse(bySlug);
    expect(minimal.publishedEndpoints[0]).toMatchObject({ poolIndex: 0, port: 443 });
    expect(minimal.relay).not.toHaveProperty('suspicion');
    expect(minimal.publishedEndpoints[0]).not.toHaveProperty('provider');
    // Probe views.
    ProbeSummary.parse(await (await call('GET', 'probes/summary?window=86400000')).json());
    const summary = ProbeSummary.parse(await (await call('GET', 'probes/summary')).json());
    expect(summary.buckets.length).toBeGreaterThan(0);
    ProbeReachabilityMatrix.parse(await (await call('GET', 'probes/matrix')).json());
    const runs = ProbeRunsResponse.parse(
      await (await call('GET', `probes?target=edge:${publishedEdgeId}`)).json(),
    );
    expect(runs.runs.length).toBeGreaterThan(0);
    ProbeTargetsResponse.parse(await (await call('GET', 'probes/targets')).json());
    const feed = ProbeAuditResponse.parse(await (await call('GET', 'probes/audit')).json());
    expect(feed.entries.some((e) => e.action === 'probe.requested')).toBe(true);
  });

  test('validation errors come back as the JSON envelope, not 500s', async () => {
    const { call } = await seed();
    const bad = await call('PUT', 'relays/by-slug/node-two', {
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
    const put = RelayBySlugResponse.parse(
      await (
        await call('PUT', 'relays/by-slug/node-one', {
          backendServerSlug: 'panel-a',
          nodeHostname: 'node-one',
          originAddress: '203.0.113.10',
        })
      ).json(),
    );
    const path = '/api/v1/admin/edges/render/preview';
    const prep = await clientPrepareRequest({
      serverPub: kp.publicKey,
      serverKid: kid,
      method: 'POST',
      path,
      policy: routePolicy(path, 'POST')!,
      bodyObj: { relayId: put.relay.id, family: 'v2rayng' },
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
    const opened = EdgeRenderPreviewResponse.parse(
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
