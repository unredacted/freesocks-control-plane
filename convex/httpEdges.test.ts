/// <reference types="vite/client" />
/**
 * The relay admin surface (`/api/v1/admin/edges/*`): auth + scopes (incl. the
 * any-of register scope and its token boundary on the by-slug routes), the
 * node role's ONE-body registration round trip (origin + listeners → adopted
 * edge → publishedEndpoints / connectionPlan), the listener routes, the
 * removed profiles/slots routes, account creation without secret echo, the
 * render preview, config patches, and the sealing policy coverage of every
 * verb under the prefix.
 */
import { convexTest } from 'convex-test';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import schema from './schema';
import { internal } from './_generated/api';
import type { Id } from './_generated/dataModel';
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
  EdgeVerificationBinding,
  EdgeVerifyResponse,
  ProbeAuditResponse,
  ProbeReachabilityMatrix,
  ProbeRequestedResponse,
  ProbeRunsResponse,
  ProbeSummary,
  ProbeTargetsResponse,
  EdgeRenderPreviewResponse,
  RelayBySlugResponse,
  RelayEndpointsResponse,
} from '../src/shared/contracts/edges';
import {
  isRegistrationRoute,
  scopeFor,
  throttlePolicyFor,
  throttlePolicyForGet,
} from './httpEdges';
import { __setEdgeProviderForTests } from './lib/edges/providers/registry';
import { qualificationBinding } from './lib/edges/frontCheck/binding';
import type { AdoptionInspection } from './lib/edges/providers/types';

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

/** An `fsv1_` token with `scopes`, optionally confined to a registration boundary. */
async function token(
  t: ReturnType<typeof convexTest>,
  scopes: string[],
  edgeRegistration?: { backendServerIds: Id<'backendServers'>[]; nodeNames?: string[] },
): Promise<string> {
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
      ...(edgeRegistration ? { edgeRegistration } : {}),
      updatedAt: Date.now(),
    });
  });
  return plaintext;
}

async function seed() {
  const t = convexTest(schema, modules);
  const serverId = await t.run((ctx) =>
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
  return { t, cookie, call, serverId };
}

const ORIGIN_NODE_ONE = { kind: 'panel-node', backendSlug: 'panel-a', nodeName: 'node-one' };

/** The node role's REALITY listener, provider-scoped to upcloud. */
const LISTENER_U = {
  listenerKey: 'u',
  protocol: 'vless',
  streamTransport: 'raw',
  security: 'reality',
  originPort: 443,
  tlsNames: ['a.example', 'b.example'],
  realityTarget: { address: 'target.example', port: 443 },
  providerScope: { provider: 'upcloud' },
  panelBinding: {
    inboundTag: 'VLESS_RELAY_U',
    configProfileUuid: '11111111-1111-4111-8111-111111111111',
    configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
  },
};

const REGISTER_BODY = {
  origin: ORIGIN_NODE_ONE,
  originAddress: '203.0.113.10',
  listeners: [LISTENER_U],
};

type BySlugView = {
  relay: {
    id: string;
    slug: string;
    hostMode: string;
    publicationEpoch: number;
    originAddress: string;
  };
  listeners: Array<{ listenerKey: string; templateHostRemark: string | null; layers: string[] }>;
  publishedEndpoints: Array<Record<string, unknown> & { poolIndex: number; listenerKey: string }>;
  connectionPlan: Array<Record<string, unknown>>;
  hostsPlan: { mode: string; hosts: unknown[] };
  registration?: { created: boolean; changed: boolean; listeners: Record<string, unknown> };
};

/**
 * seed() + provider account + relay registered by the NODE ROLE (a bounded
 * register token, so listener `u` is role-owned) + a published (index 0) and
 * an unpublished adopted edge. `roleCall` re-registers as the role.
 */
async function fixture() {
  const s = await seed();
  const { call, t, serverId } = s;
  const acct = (await (
    await call('POST', 'providers', {
      provider: 'upcloud',
      name: 'acct-u',
      settings: { zone: 'de-fra1' },
      credentials: { token: 'SECRET_TOKEN_VALUE' },
    })
  ).json()) as { id: string };
  const roleCall = bearerCall(
    t,
    await token(t, ['admin:edges:register'], { backendServerIds: [serverId] }),
  );
  const view = (await (
    await roleCall('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
  ).json()) as BySlugView;
  const relayId = view.relay.id;
  const listeners = (await (await call('GET', `relays/${relayId}/listeners`)).json()) as {
    listeners: Array<{ id: string; listenerKey: string }>;
  };
  const listenerId = listeners.listeners[0].id;
  const published = (await (
    await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
      // The operator's statement that this imported address already serves.
      verified: true,
    })
  ).json()) as { edgeId: string };
  const standby = (await (
    await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      ipv4: '198.51.100.8',
      publish: false,
    })
  ).json()) as { edgeId: string };
  return {
    ...s,
    roleCall,
    accountId: acct.id,
    relayId,
    listenerId,
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
    // reads: config, providers (+inventory), templates, relays (+ listeners, by-slug), edges, rotations, probes
    for (const g of [
      'config',
      'providers',
      'providers/acc1/inventory',
      'templates',
      'relays',
      'relays/node-candidates?backendServerId=x',
      'relays/r1/endpoints',
      'relays/r1/listeners',
      'relays/by-slug/n1',
      'relays/by-slug/n1/listeners/u',
      'list?relayId=r1',
      'e1',
      'e1/live',
      'rotations/rot1',
      'probes/matrix',
      'probes/summary',
      'probes/targets',
      'probes/audit',
      'setup-runs',
      'setup-runs/run1',
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
      'providers/acc1/rotate-credentials',
      'templates',
      'templates/validate',
      'templates/ensure-defaults',
      'relays',
      'relays/node-candidates/refresh',
      'relays/r1/adopt',
      'relays/r1/listeners',
      'relays/r1/provision',
      'relays/r1/qualification-credential',
      'relays/r1/burn',
      'relays/r1/probe',
      'listeners/retire-name',
      'listeners/l1/retire-name',
      'listeners/l1/reactivate-name',
      'listeners/l1/enable',
      'listeners/l1/disable',
      'e1/publish',
      'e1/live/refresh',
      'e1/probe',
      'e1/retry-destroy',
      'probes',
      'probes/targets',
      'render/preview',
      'setup-runs/plan',
      'setup-runs',
      'setup-runs/run1/cancel',
      'setup-runs/run1/retry',
      'setup-runs/run1/continue',
      'relays/r1/require-edges',
    ]) {
      expect(routePolicy(P + p, 'POST')).toEqual(BOTH);
    }
    for (const p of ['config', 'providers/acc1', 'templates/t1', 'relays/r1']) {
      expect(routePolicy(P + p, 'PATCH')).toEqual(REQ);
    }
    expect(routePolicy(P + 'relays/by-slug/n1', 'PUT')).toEqual(REQ);
    for (const p of [
      'providers/acc1',
      'templates/t1',
      'relays/r1',
      'relays/r1/listeners/u',
      'relays/by-slug/n1',
      'relays/by-slug/n1/listeners/u',
      'e1',
    ]) {
      expect(routePolicy(P + p, 'DELETE')).toBeUndefined();
    }
  });

  test('scope table: config → settings, everything else → servers; by-slug GET/PUT/DELETE accept the register scope (any-of)', () => {
    expect(scopeFor(['config'], 'GET')).toBe('admin:settings:read');
    expect(scopeFor(['config'], 'PATCH')).toBe('admin:settings:write');
    expect(scopeFor(['summary'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['render', 'preview'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['templates', 'validate'], 'POST')).toBe('admin:servers:read');
    expect(scopeFor(['templates'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['templates', 'ensure-defaults'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['render', 'preview', 'x'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['providers', 'a'], 'PATCH')).toBe('admin:servers:write');
    expect(scopeFor(['providers', 'a', 'rotate-credentials'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'r'], 'DELETE')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'r', 'listeners'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'r', 'listeners'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['listeners', 'retire-name'], 'POST')).toBe('admin:servers:write');
    // Qualifying writes a verdict onto the edge: a write scope, not a read one.
    expect(scopeFor(['edges', 'e1', 'qualify'], 'POST')).toBe('admin:servers:write');
    // Guided setup runs: reads under the read scope, the plan (a panel call) and every verb under write.
    expect(scopeFor(['setup-runs'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['setup-runs', 'run1'], 'GET')).toBe('admin:servers:read');
    expect(scopeFor(['setup-runs', 'plan'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['setup-runs'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['setup-runs', 'run1', 'continue'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'r1', 'require-edges'], 'POST')).toBe('admin:servers:write');
    // The registration routes: any-of (register OR the full servers scope).
    expect(scopeFor(['relays', 'by-slug', 'n'], 'GET')).toEqual([
      'admin:edges:register',
      'admin:servers:read',
    ]);
    expect(scopeFor(['relays', 'by-slug', 'n'], 'PUT')).toEqual([
      'admin:edges:register',
      'admin:servers:write',
    ]);
    expect(scopeFor(['relays', 'by-slug', 'n'], 'DELETE')).toEqual([
      'admin:edges:register',
      'admin:servers:write',
    ]);
    expect(scopeFor(['relays', 'by-slug', 'n', 'listeners', 'u'], 'GET')).toEqual([
      'admin:edges:register',
      'admin:servers:read',
    ]);
    expect(scopeFor(['relays', 'by-slug', 'n', 'listeners', 'u'], 'DELETE')).toEqual([
      'admin:edges:register',
      'admin:servers:write',
    ]);
    // POST / PATCH under by-slug are not registration verbs (and not routes).
    expect(scopeFor(['relays', 'by-slug', 'n'], 'POST')).toBe('admin:servers:write');
    expect(scopeFor(['relays', 'by-slug', 'n'], 'PATCH')).toBe('admin:servers:write');
    expect(isRegistrationRoute(['relays', 'by-slug', 'n'])).toBe(true);
    expect(isRegistrationRoute(['relays', 'by-slug'])).toBe(false);
    expect(isRegistrationRoute(['relays', 'r1'])).toBe(false);
  });

  test('throttle table: the provider-calling POSTs and the probe POSTs are the only throttled routes', () => {
    const P = 'admin.edges.provider-call';
    expect(throttlePolicyFor(['providers', 'discover'])).toBe(P);
    expect(throttlePolicyFor(['providers', 'test-credentials'])).toBe(P);
    expect(throttlePolicyFor(['providers', 'a1', 'inventory', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['providers', 'a1', 'rotate-credentials'])).toBe(P);
    expect(throttlePolicyFor(['relays', 'node-candidates', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['relays', 'r1', 'adopt'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'live', 'refresh'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'qualify'])).toBe(P);
    expect(throttlePolicyFor(['relays', 'r1', 'qualification-credential'])).toBe(P);
    expect(throttlePolicyFor(['render', 'preview'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'probe'])).toBe('admin.edges.probe');
    expect(throttlePolicyFor(['relays', 'r1', 'probe'])).toBe('admin.edges.probe');
    expect(throttlePolicyFor(['probes'])).toBe('admin.edges.probe');
    // The setup plan lists the node's inbounds and Hosts from the panel; the run verbs do not.
    expect(throttlePolicyFor(['setup-runs', 'plan'])).toBe(P);
    for (const p of [
      ['setup-runs'],
      ['setup-runs', 'run1', 'continue'],
      ['relays', 'r1', 'require-edges'],
      ['providers'],
      ['providers', 'a1', 'qualify'],
      ['templates'],
      ['templates', 'validate'],
      ['relays'],
      ['relays', 'r1', 'burn'],
      ['relays', 'r1', 'listeners'],
      ['listeners', 'retire-name'],
      ['edges', 'e1', 'publish'],
      ['probes', 'targets'],
    ]) {
      expect(throttlePolicyFor(p)).toBeNull();
    }
    // The GET that reaches a panel and opens sockets is throttled under the same
    // policy; the test link is a POST (it may mint a credential) and is throttled there.
    expect(throttlePolicyForGet(['relays', 'inbound-candidates'])).toBe(P);
    expect(throttlePolicyFor(['edges', 'e1', 'test-link'])).toBe(P);
    expect(throttlePolicyForGet(['edges', 'e1', 'test-link'])).toBeNull();
    for (const p of [
      ['relays'],
      ['relays', 'node-candidates'],
      ['relays', 'lookup'],
      ['edges', 'e1'],
      ['edges', 'e1', 'verification-binding'],
      ['probes'],
      ['attention'],
    ]) {
      expect(throttlePolicyForGet(p)).toBeNull();
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
    expect((await reader('DELETE', `relays/${relayId}?disposition=keep-dark`)).status).toBe(401);
    expect((await reader('POST', `templates/ensure-defaults`, {})).status).toBe(401);
    expect((await reader('POST', `relays/${relayId}/listeners`, LISTENER_U)).status).toBe(401);
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
    // The relay still exists and the account is untouched; the read scope satisfies the any-of by-slug GET.
    expect((await reader('GET', `relays/by-slug/node-one`)).status).toBe(200);
    expect((await reader('GET', `relays/${relayId}/listeners`)).status).toBe(200);

    const settingsWriter = bearerCall(t, await token(t, ['admin:settings:write']));
    expect((await settingsWriter('GET', 'summary')).status).toBe(401);
    expect((await settingsWriter('GET', 'providers')).status).toBe(401);
    expect((await settingsWriter('POST', 'relays', { slug: 'x' })).status).toBe(401);
    expect(
      (await settingsWriter('POST', 'render/preview', { relayId, family: 'other' })).status,
    ).toBe(401);
    expect((await settingsWriter('DELETE', `relays/${relayId}`)).status).toBe(401);
    expect((await settingsWriter('GET', 'relays/by-slug/node-one')).status).toBe(401);
    expect((await settingsWriter('PATCH', 'config', { render: { enabled: false } })).status).toBe(
      200,
    );
    // A percent-encoded `config` still resolves to the settings scope (decode precedes the scope check).
    expect((await settingsWriter('GET', '%63onfig')).status).toBe(401);
    expect(
      (await bearerCall(t, await token(t, ['admin:settings:read']))('GET', '%63onfig')).status,
    ).toBe(200);
  });

  test('register token: GET/PUT/DELETE by-slug inside its boundary; 403 edge.registration_boundary outside; nothing else under the prefix', async () => {
    const { t, call, serverId } = await seed();
    const otherServer = await t.run((ctx) =>
      ctx.db.insert('backendServers', {
        backend: 'remnawave',
        name: 'panel-b',
        slug: 'panel-b',
        config: { type: 'remnawave', baseUrl: 'https://panel-b.example', apiToken: 'tok' },
        isActive: true,
        priority: 0,
        keyCount: 0,
        updatedAt: Date.now(),
      }),
    );
    const bounded = bearerCall(
      t,
      await token(t, ['admin:edges:register'], { backendServerIds: [serverId] }),
    );
    // Inside: the role registers, reads and updates its own node.
    const put = await bounded('PUT', 'relays/by-slug/node-one', REGISTER_BODY);
    expect(put.status).toBe(200);
    const view = (await put.json()) as BySlugView;
    expect(view.relay.slug).toBe('node-one');
    expect(view.registration).toMatchObject({ created: true, changed: true });
    expect(view.listeners.map((l) => l.listenerKey)).toEqual(['u']);
    // A register token is a `role` source: no actor admin, the row is role-owned.
    const row = (await t.run((ctx) =>
      ctx.db
        .query('relayListeners')
        .withIndex('by_relay', (q) => q.eq('relayId', view.relay.id as Id<'relays'>))
        .unique(),
    ))!;
    expect(row.source).toBe('role');
    const again = (await (
      await bounded('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
    ).json()) as BySlugView;
    expect(again.registration).toMatchObject({ created: false, changed: false });
    expect((await bounded('GET', 'relays/by-slug/node-one')).status).toBe(200);
    const one = await bounded('GET', 'relays/by-slug/node-one/listeners/u');
    expect(one.status).toBe(200);
    expect(await one.json()).toMatchObject({
      listenerKey: 'u',
      templateHostRemark: 'node-one-relay-u',
    });
    expect((await bounded('GET', 'relays/by-slug/node-one/listeners/nope')).status).toBe(404);
    expect((await bounded('GET', 'relays/by-slug/never-registered')).status).toBe(404);
    // Outside: another backend server, or a node outside the token's node list.
    const outside = await bounded('PUT', 'relays/by-slug/node-b', {
      ...REGISTER_BODY,
      origin: { kind: 'panel-node', backendSlug: 'panel-b', nodeName: 'node-b' },
    });
    expect(outside.status).toBe(403);
    expect(await outside.json()).toMatchObject({ error: { code: 'edge.registration_boundary' } });
    // A manual origin is never inside a boundary.
    const manual = await bounded('PUT', 'relays/by-slug/hand', {
      origin: { kind: 'manual' },
      originAddress: '203.0.113.77',
      listeners: [{ ...LISTENER_U, panelBinding: undefined }],
    });
    expect(manual.status).toBe(403);
    // A relay registered by the operator on the OTHER panel: the bounded token may not read or delete it.
    await call('PUT', 'relays/by-slug/node-b', {
      ...REGISTER_BODY,
      originAddress: '203.0.113.11',
      origin: { kind: 'panel-node', backendSlug: 'panel-b', nodeName: 'node-b' },
    });
    expect((await bounded('GET', 'relays/by-slug/node-b')).status).toBe(403);
    expect((await bounded('DELETE', 'relays/by-slug/node-b')).status).toBe(403);
    expect((await bounded('DELETE', 'relays/by-slug/node-b/listeners/u')).status).toBe(403);
    expect(await t.query(internal.relays.getBySlug, { slug: 'node-b' })).not.toBeNull();
    // Node-scoped boundary: the listed node only.
    const nodeBound = bearerCall(
      t,
      await token(t, ['admin:edges:register'], {
        backendServerIds: [serverId, otherServer],
        nodeNames: ['node-two'],
      }),
    );
    expect((await nodeBound('GET', 'relays/by-slug/node-one')).status).toBe(403);
    expect(
      (
        await nodeBound('PUT', 'relays/by-slug/node-two', {
          ...REGISTER_BODY,
          originAddress: '203.0.113.12',
          origin: { kind: 'panel-node', backendSlug: 'panel-a', nodeName: 'node-two' },
        })
      ).status,
    ).toBe(200);
    // A register token WITHOUT a boundary may register nothing.
    const unbounded = bearerCall(t, await token(t, ['admin:edges:register']));
    const none = await unbounded('PUT', 'relays/by-slug/node-three', {
      ...REGISTER_BODY,
      originAddress: '203.0.113.13',
      origin: { kind: 'panel-node', backendSlug: 'panel-a', nodeName: 'node-three' },
    });
    expect(none.status).toBe(403);
    expect(await none.json()).toMatchObject({ error: { code: 'edge.registration_boundary' } });
    // The register scope reaches NOTHING else under the prefix.
    const relayId = view.relay.id;
    for (const [method, path, body] of [
      ['GET', 'providers', undefined],
      ['GET', 'config', undefined],
      ['GET', 'summary', undefined],
      ['GET', `relays/${relayId}/listeners`, undefined],
      ['GET', `list?relayId=${relayId}`, undefined],
      ['POST', `relays/${relayId}/rotate`, { edgeId: 'x' }],
      ['POST', `relays/${relayId}/provision`, {}],
      ['POST', 'providers', { provider: 'upcloud', name: 'x', settings: {}, credentials: {} }],
      ['PATCH', `relays/${relayId}`, { enabled: false }],
      ['PATCH', 'config', { render: { enabled: true } }],
      ['DELETE', `relays/${relayId}?disposition=keep-dark`, undefined],
    ] as const) {
      const res = await bounded(method, path, body);
      expect([401, 403], `${method} ${path}`).toContain(res.status);
    }
    // A token with BOTH scopes is not confined (the full scope wins).
    const full = bearerCall(
      t,
      await token(t, ['admin:edges:register', 'admin:servers:read', 'admin:servers:write'], {
        backendServerIds: [],
      }),
    );
    expect((await full('GET', 'relays/by-slug/node-b')).status).toBe(200);
    // Inside its boundary the role decommissions its node: the default disposition restores direct delivery.
    const del = await bounded('DELETE', 'relays/by-slug/node-one');
    expect(del.status).toBe(200);
    expect(await del.json()).toEqual({ ok: true, deleted: false });
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'node-one',
      }),
    ).toBeNull();
    expect((await t.query(internal.relays.getBySlug, { slug: 'node-one' }))!.deleting).toBe(true);
  });

  test('malformed percent escapes answer 400 validation on every verb (the unsealed DELETE included)', async () => {
    const { t, call } = await seed();
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
    const anon = await t.fetch('/api/v1/admin/edges/relays/by-slug/%E0%A4%A', { method: 'DELETE' });
    expect(anon.status).toBe(400);
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
      // The fixture already imported two edges through `…/adopt`, a
      // provider-calling POST on this same bucket.
      max: 4,
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
    const reader = bearerCall(t, await token(t, ['admin:servers:read']));
    expect((await reader('POST', 'render/preview', body)).status).toBe(200);
    expect((await call('PATCH', 'config', { render: { enabled: true } })).status).toBe(200);
    await t.mutation(internal.rateLimits.setPolicy, {
      policyKey: 'admin.edges.probe',
      max: 1,
      windowMs: 60_000,
      enabled: true,
    });
    const edges = z
      .array(EdgeAdmin)
      .parse(await (await call('GET', `list?relayId=${relayId}`)).json());
    const publishedEdgeId = edges.find((e) => e.publication === 'published')!.id;
    expect((await call('POST', `${publishedEdgeId}/probe`, {})).status).toBe(200);
    expect((await call('POST', `${publishedEdgeId}/probe`, {})).status).toBe(429);
  });

  test('sni-pick: the version is REQUIRED; a missing field is never read as the legacy null', async () => {
    const { t, call, listenerId } = await fixture();
    for (const body of [{}, { versoin: 'hrw1' }, { version: 'nope' }]) {
      const res = await call('POST', `listeners/${listenerId}/sni-pick`, body);
      expect(res.status).toBe(400);
      expect((await res.json()).error.code).toBe('validation');
    }
    expect(
      ((await t.run((ctx) => ctx.db.get(listenerId as never))) as { sniPick?: string }).sniPick,
    ).toBeUndefined();
    const on = await call('POST', `listeners/${listenerId}/sni-pick`, { version: 'hrw1' });
    expect(await on.json()).toMatchObject({ ok: true, changed: true, sniPick: 'hrw1' });
    // An explicit null is the deliberate way back.
    const off = await call('POST', `listeners/${listenerId}/sni-pick`, { version: null });
    expect(await off.json()).toMatchObject({ ok: true, changed: true, sniPick: null });
  });

  test('per-edge probe: audited with the actor, returns the run ids; a skipped-only target is an error', async () => {
    const { t, call, publishedEdgeId, relayId, listenerId } = await fixture();
    const res = await call('POST', `${publishedEdgeId}/probe`, {});
    expect(res.status).toBe(200);
    const parsed = ProbeRequestedResponse.parse(await res.json());
    expect(parsed.runIds.length).toBeGreaterThan(0);
    const audit = await t.run((ctx) => ctx.db.query('auditLog').collect());
    const row = audit.find((a) => a.action === 'probe.requested');
    expect(row?.actorType).toBe('admin');
    expect(row?.actorId).toBeTruthy();
    const noAddr = (await (
      await call('POST', `relays/${relayId}/adopt`, { listenerId, publish: false })
    ).json()) as { edgeId?: string; error?: unknown };
    if (noAddr.edgeId) {
      const bad = await call('POST', `${noAddr.edgeId}/probe`, {});
      expect(bad.status).toBe(409);
      expect(await bad.json()).toMatchObject({ error: { code: 'edge.no_address' } });
    }
  });

  test('IaC round trip: ONE by-slug body registers origin + listeners, adopt + publish, publishedEndpoints / connectionPlan for the role', async () => {
    const { t, call, serverId } = await seed();
    const roleCall = bearerCall(
      t,
      await token(t, ['admin:edges:register'], { backendServerIds: [serverId] }),
    );
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

    // The role's registration (idempotent): origin + listeners in one body.
    const put1 = await roleCall('PUT', 'relays/by-slug/node-one', REGISTER_BODY);
    expect(put1.status).toBe(200);
    const view1 = (await put1.json()) as BySlugView;
    expect(view1.relay).toMatchObject({
      slug: 'node-one',
      hostMode: 'fcp',
      originAddress: '203.0.113.10',
    });
    expect(view1.registration).toMatchObject({
      created: true,
      changed: true,
      listeners: { created: ['u'], updated: [], unchanged: [], retired: [], blockedNames: [] },
    });
    expect(view1.listeners).toEqual([
      expect.objectContaining({
        listenerKey: 'u',
        protocol: 'vless',
        streamTransport: 'raw',
        security: 'reality',
        transport: 'tcp',
        originPort: 443,
        layers: ['l4'],
        deployed: true,
        retired: false,
        templateHostRemark: 'node-one-relay-u',
      }),
    ]);
    expect(view1.publishedEndpoints).toEqual([]);
    expect(view1.connectionPlan).toEqual([]);
    expect(view1.hostsPlan).toEqual({ mode: 'fcp', hosts: [] });
    // The role's view leaks no detector state, limits or pool-wide provider names.
    expect(view1.relay).not.toHaveProperty('suspicion');
    expect(view1.relay).not.toHaveProperty('maxRotationsPerDay');
    expect(JSON.stringify(view1.listeners)).not.toContain('upcloud');
    // The delivery binding covers the node from now on.
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'node-one',
      }),
    ).toMatchObject({ relaySlug: 'node-one', state: 'active' });
    const put2 = (await (
      await roleCall('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
    ).json()) as BySlugView;
    expect(put2.registration).toMatchObject({
      created: false,
      changed: false,
      listeners: { unchanged: ['u'] },
    });
    expect(put2.relay.publicationEpoch).toBe(view1.relay.publicationEpoch);
    // A cookie admin's by-slug body is an ADMIN source: it adds its own listener
    // and never prunes the role's (different owner), and the role's next body
    // leaves the admin listener alone.
    const adminPut = (await (
      await call('PUT', 'relays/by-slug/node-one', {
        ...REGISTER_BODY,
        listeners: [
          {
            ...LISTENER_U,
            listenerKey: 'x',
            originPort: 8443,
            panelBinding: {
              ...LISTENER_U.panelBinding,
              inboundTag: 'VLESS_RELAY_X',
              configProfileInboundUuid: '55555555-5555-4555-8555-555555555555',
            },
          },
        ],
      })
    ).json()) as BySlugView;
    expect(adminPut.registration).toMatchObject({ listeners: { created: ['x'], retired: [] } });
    expect(adminPut.listeners.map((l) => l.listenerKey)).toEqual(['u', 'x']);
    const rolePut = (await (
      await roleCall('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
    ).json()) as BySlugView;
    expect(rolePut.registration).toMatchObject({ changed: false });
    expect(rolePut.listeners.map((l) => l.listenerKey)).toEqual(['u', 'x']);
    const owned = await roleCall('PUT', 'relays/by-slug/node-one', {
      ...REGISTER_BODY,
      listeners: [LISTENER_U, { ...LISTENER_U, listenerKey: 'x', originPort: 9443 }],
    });
    expect(owned.status).toBe(409);
    expect(await owned.json()).toMatchObject({ error: { code: 'edge.listener_key_owned' } });
    expect((await call('DELETE', 'relays/by-slug/node-one/listeners/x')).status).toBe(200);
    const one = await call('GET', 'relays/by-slug/node-one/listeners/u');
    expect(one.status).toBe(200);
    expect(await one.json()).toMatchObject({
      listenerKey: 'u',
      security: 'reality',
      templateHostRemark: 'node-one-relay-u',
    });

    // Adopt the hand-made edge and publish it at index 0.
    const relayId = view1.relay.id;
    const listeners = (await (await call('GET', `relays/${relayId}/listeners`)).json()) as {
      listeners: Array<{ id: string; listenerKey: string; source: string; providerScope: unknown }>;
      publishedEndpoints: unknown[];
      connectionPlan: unknown[];
      hostsPlan: { mode: string };
    };
    expect(listeners.listeners[0]).toMatchObject({
      listenerKey: 'u',
      source: 'role',
      providerScope: { provider: 'upcloud', accountId: null },
    });
    const listenerId = listeners.listeners[0].id;
    // Without the operator's statement that the address already serves, an L4
    // import cannot publish (the gate wants a confirmed endpoint).
    const untested = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
    });
    expect(untested.status).toBe(409);
    expect(await untested.json()).toMatchObject({ error: { code: 'edge.unverified_endpoint' } });
    const adopt = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      ipv4: '198.51.100.7',
      ipv6: '2001:db8::7',
      publish: true,
      verified: true,
    });
    expect(adopt.status).toBe(200);
    expect(await adopt.json()).toMatchObject({ poolIndex: 0 });
    const view3 = (await (await call('GET', 'relays/by-slug/node-one')).json()) as BySlugView;
    expect(view3.publishedEndpoints).toHaveLength(1);
    expect(view3.publishedEndpoints[0]).toEqual({
      listenerKey: 'u',
      poolIndex: 0,
      layer: 'l4',
      port: 443,
      addresses: { v4: '198.51.100.7', v6: '2001:db8::7', hostname: null },
      sni: 'a.example',
      hostHeader: null,
    });
    expect(view3.connectionPlan).toEqual([
      { listenerKey: 'u', address: '198.51.100.7', port: 443, sni: 'a.example', host: null },
    ]);
    // Edges + summary + endpoints views.
    const edges = z
      .array(EdgeAdmin)
      .parse(await (await call('GET', `edges?relayId=${relayId}`)).json());
    expect(edges).toHaveLength(1);
    expect(edges[0]).toMatchObject({
      managed: false,
      publication: 'published',
      poolIndex: 0,
      listenerId,
    });
    // The role bootstraps its Host from publishedEndpoints[0]: an index-0 edge that
    // is not usable (here: no address) must keep it waiting rather than hand it a dud.
    await t.run((ctx) => ctx.db.patch(edges[0].id as Id<'edges'>, { addresses: {} }));
    const viewDud = (await (await call('GET', 'relays/by-slug/node-one')).json()) as BySlugView;
    expect(viewDud.publishedEndpoints).toEqual([]);
    expect(viewDud.connectionPlan).toEqual([]);
    await t.run((ctx) =>
      ctx.db.patch(edges[0].id as Id<'edges'>, {
        addresses: { v4: '198.51.100.7', v6: '2001:db8::7' },
      }),
    );
    const summary = (await (await call('GET', 'summary')).json()) as {
      counts: Record<string, number>;
      relays: Array<{
        relay: { slug: string; origin: unknown; hostMode: string };
        pool: Array<Record<string, unknown>>;
      }>;
    };
    expect(summary.counts).toMatchObject({ relays: 1, published: 1, suspected: 0, rotating: 0 });
    expect(summary.relays[0].relay).toMatchObject({
      slug: 'node-one',
      hostMode: 'fcp',
      origin: { kind: 'panel-node', nodeName: 'node-one' },
    });
    expect(summary.relays[0].pool[0]).toMatchObject({
      poolIndex: 0,
      addresses: { v4: '198.51.100.7' },
    });
    const endpoints = (await (await call('GET', `relays/${relayId}/endpoints`)).json()) as {
      published: Array<Record<string, unknown>>;
      sample: { primary: { edgeId: string; sni: string | null } };
    };
    expect(endpoints.published[0]).toMatchObject({
      listenerKey: 'u',
      protocol: 'vless',
      security: 'reality',
      activeNames: ['a.example', 'b.example'],
    });
    expect(endpoints.sample.primary).toMatchObject({ edgeId: edges[0].id });
    expect(['a.example', 'b.example']).toContain(endpoints.sample.primary.sni);

    // Render preview: per-family synthetic body, the edge replaces the template,
    // never the origin. The preview always renders (the `render.enabled` switch
    // decides RAW-vs-render on the fronted /sub route, not what a render looks like).
    const prev = await call('POST', 'render/preview', { relayId, family: 'v2rayng' });
    expect(prev.status).toBe(200);
    const preview = EdgeRenderPreviewResponse.parse(await prev.json());
    expect(preview.format).toBe('links');
    expect(preview.applied).toBe(true);
    expect(preview.delivery).toEqual({ kind: 'serve' });
    expect(preview.body).toContain('198.51.100.7');
    expect(preview.body).not.toContain('192.0.2.10');
    expect(preview.body).not.toContain('node-one-relay-u');
    const patched = await call('PATCH', 'config', { render: { enabled: true } });
    expect(await patched.json()).toEqual({ changedKeys: ['render.enabled'] });
    const preview2 = EdgeRenderPreviewResponse.parse(
      await (await call('POST', 'render/preview', { relayId, family: 'v2rayng' })).json(),
    );
    expect(preview2.body).toBe(preview.body);
    const singbox = EdgeRenderPreviewResponse.parse(
      await (await call('POST', 'render/preview', { relayId, family: 'singbox' })).json(),
    );
    expect(singbox.format).toBe('singbox-json');
    expect(
      JSON.parse(singbox.body).outbounds.some((o: { type: string }) => o.type === 'urltest'),
    ).toBe(true);

    // The removed profiles / slots surface is gone: 404 on every verb.
    for (const [method, path] of [
      ['GET', 'profiles'],
      ['POST', 'profiles'],
      ['PATCH', 'profiles/p1'],
      ['DELETE', 'profiles/p1'],
      ['GET', `relays/${relayId}/slots`],
      ['PUT', 'relays/by-slug/node-one/slots/u'],
      ['GET', 'relays/by-slug/node-one/slots/u'],
      ['DELETE', 'relays/by-slug/node-one/slots/u'],
    ] as const) {
      const res = await call(
        method,
        path,
        method === 'GET' || method === 'DELETE' ? undefined : {},
      );
      expect(res.status, `${method} ${path}`).toBe(404);
    }

    // Delete by slug (the role decommissions the node): restore-direct by default.
    const del = await call('DELETE', 'relays/by-slug/node-one');
    expect(del.status).toBe(200);
    expect(await del.json()).toMatchObject({ ok: true });
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'node-one',
      }),
    ).toBeNull();
    const gone = await call('GET', 'relays/by-slug/missing');
    expect(gone.status).toBe(404);

    // Legacy adoption (`operation_mode=adopt_relay`): the running proxy is the
    // operator's statement that the address already serves, so the import is
    // published at index 0 with a `named_connection` verification (not refused
    // as an untested endpoint) and the legacy Host is recorded on its listener.
    const legacy = await roleCall('PUT', 'relays/by-slug/node-legacy', {
      origin: { ...ORIGIN_NODE_ONE, nodeName: 'node-legacy' },
      originAddress: '203.0.113.11',
      listeners: [LISTENER_U],
      hostModeRequest: 'operator',
      adoption: {
        edge: { address: '198.51.100.8', port: 443 },
        hosts: [
          {
            uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
            remark: 'legacy-u',
            inboundUuid: LISTENER_U.panelBinding.configProfileInboundUuid,
            sni: 'a.example',
          },
        ],
      },
    });
    expect(legacy.status).toBe(200);
    const legacyView = (await legacy.json()) as BySlugView & {
      registration: { adopted: { edgeId: string; poolIndex: number | null } | null };
    };
    expect(legacyView.relay.hostMode).toBe('operator');
    expect(legacyView.registration.adopted).toMatchObject({ poolIndex: 0 });
    expect(legacyView.publishedEndpoints).toEqual([
      expect.objectContaining({
        listenerKey: 'u',
        poolIndex: 0,
        addresses: { v4: '198.51.100.8', v6: null, hostname: null },
      }),
    ]);
    const legacyEdge = (await t.query(internal.edges.get, {
      id: legacyView.registration.adopted!.edgeId as Id<'edges'>,
    }))!;
    expect(legacyEdge).toMatchObject({
      managed: false,
      publication: 'published',
      verification: { rung: 'verified', by: 'admin', method: 'named_connection' },
    });
    const legacyListener = (await t.run((ctx) => ctx.db.get(legacyEdge.listenerId)))!;
    expect(legacyListener.legacyHosts).toEqual([
      expect.objectContaining({ remark: 'legacy-u', sni: 'a.example' }),
    ]);
    // Idempotent: the same body again adopts nothing new.
    const legacyAgain = (await (
      await roleCall('PUT', 'relays/by-slug/node-legacy', {
        origin: { ...ORIGIN_NODE_ONE, nodeName: 'node-legacy' },
        originAddress: '203.0.113.11',
        listeners: [LISTENER_U],
        hostModeRequest: 'operator',
        adoption: {
          edge: { address: '198.51.100.8', port: 443 },
          hosts: [
            {
              uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
              remark: 'legacy-u',
              inboundUuid: LISTENER_U.panelBinding.configProfileInboundUuid,
              sni: 'a.example',
            },
          ],
        },
      })
    ).json()) as BySlugView & { registration: { adopted: { edgeId: string } | null } };
    expect(legacyAgain.registration.adopted?.edgeId).toBe(legacyEdge._id);
    expect(legacyAgain.publishedEndpoints).toHaveLength(1);
  });

  test('listener routes: admin upsert, enable/disable, name retire/reactivate (per listener and fleet-wide), retire by key and by slug', async () => {
    const { t, call, roleCall, relayId, listenerId, standbyEdgeId, publishedEdgeId } =
      await fixture();
    const WS = {
      listenerKey: 'w',
      protocol: 'vless',
      streamTransport: 'ws',
      security: 'tls',
      originPort: 443,
      tlsNames: ['ws.example'],
      transportParams: { path: '/ws' },
      originTransport: {
        scheme: 'https',
        certPublic: true,
        certNames: ['ws.example'],
        acceptsHostHeader: 'any',
      },
      panelBinding: {
        inboundTag: 'VLESS_WS',
        configProfileUuid: '11111111-1111-4111-8111-111111111111',
        configProfileInboundUuid: '33333333-3333-4333-8333-333333333333',
      },
    };
    const up = await call('POST', `relays/${relayId}/listeners`, WS);
    expect(up.status).toBe(200);
    const created = (await up.json()) as {
      id: string;
      created: boolean;
      templateHostRemark: string;
    };
    expect(created).toMatchObject({
      created: true,
      changed: true,
      templateHostRemark: 'node-one-relay-w',
    });
    const view = (await (await call('GET', `relays/${relayId}/listeners`)).json()) as {
      listeners: Array<{
        id: string;
        listenerKey: string;
        source: string;
        enabled: boolean;
        layers: string[];
      }>;
    };
    expect(view.listeners.map((l) => [l.listenerKey, l.source])).toEqual([
      ['u', 'role'],
      ['w', 'admin'],
    ]);
    expect(view.listeners[1].layers).toEqual(['l4', 'l7']);
    // A role re-registration leaves the admin listener alone.
    const again = (await (
      await roleCall('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
    ).json()) as BySlugView;
    expect(again.registration).toMatchObject({ changed: false });
    expect(again.listeners.map((l) => l.listenerKey)).toEqual(['u', 'w']);
    // Invalid combinations answer 400 with the code.
    const bad = await call('POST', `relays/${relayId}/listeners`, {
      ...WS,
      listenerKey: 'x',
      security: 'reality',
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: { code: 'invalid_combination' } });
    // enable / disable.
    expect((await call('POST', `listeners/${created.id}/disable`, {})).status).toBe(200);
    expect(
      (await (await call('GET', `relays/${relayId}/listeners`)).json()).listeners.find(
        (l: { listenerKey: string }) => l.listenerKey === 'w',
      ).enabled,
    ).toBe(false);
    expect((await call('POST', `listeners/${created.id}/enable`, {})).status).toBe(200);
    // Name retire / reactivate on the role's listener (an admin edit of a role row's names is allowed).
    const retire = await call('POST', `listeners/${listenerId}/retire-name`, {
      snis: ['a.example'],
    });
    expect(await retire.json()).toEqual({ ok: true, retired: 1 });
    const last = await call('POST', `listeners/${listenerId}/retire-name`, { sni: 'b.example' });
    expect(last.status).toBe(409);
    expect(await last.json()).toMatchObject({ error: { code: 'conflict' } });
    expect(
      await (
        await call('POST', `listeners/${listenerId}/reactivate-name`, { snis: ['a.example'] })
      ).json(),
    ).toEqual({
      ok: true,
      reactivated: 1,
    });
    // Fleet-wide.
    const everywhere = await call('POST', 'listeners/retire-name', { name: 'a.example' });
    expect(await everywhere.json()).toEqual({ ok: true, retired: 1, listeners: 1 });
    expect((await call('POST', 'listeners/retire-name', { name: '' })).status).toBe(400);
    // Retire the listener with edges on it: refused; without them: gone (by key, then by slug).
    const inUse = await call('DELETE', `relays/${relayId}/listeners/u`);
    expect(inUse.status).toBe(409);
    expect(await inUse.json()).toMatchObject({ error: { code: 'edge.listener_in_use' } });
    for (const id of [standbyEdgeId, publishedEdgeId]) {
      await t.mutation(internal.edges.patchEdge, {
        edgeId: id as Id<'edges'>,
        status: 'destroyed',
      });
    }
    await t.run((ctx) => ctx.db.patch(relayId as Id<'relays'>, { publishedEdgeIds: [] }));
    expect(await (await call('DELETE', `relays/by-slug/node-one/listeners/u`)).json()).toEqual({
      ok: true,
    });
    expect(await (await call('DELETE', `relays/${relayId}/listeners/w`)).json()).toEqual({
      ok: true,
    });
    const after = (await (await call('GET', `relays/${relayId}/listeners`)).json()) as {
      listeners: Array<{ listenerKey: string; retired: boolean }>;
    };
    expect(after.listeners.map((l) => [l.listenerKey, l.retired])).toEqual([
      ['u', true],
      ['w', true],
    ]);
  });

  test('DELETE relays/{id} needs a disposition from the CMS; by-slug defaults to restore-direct', async () => {
    const { t, call, relayId, serverId } = await fixture();
    const noDisposition = await call('DELETE', `relays/${relayId}`);
    expect(noDisposition.status).toBe(409);
    expect(await noDisposition.json()).toMatchObject({
      error: { code: 'edge.delivery_disposition_required' },
    });
    expect(
      (await t.query(internal.relays.get, { id: relayId as Id<'relays'> }))!.deleting,
    ).toBeUndefined();
    const dark = await call('DELETE', `relays/${relayId}?disposition=keep-dark&force=true`);
    expect(dark.status).toBe(200);
    expect(await dark.json()).toEqual({ ok: true, deleted: false });
    // keep-dark: members of the node stay edge-required (503) until another relay claims it.
    expect(
      await t.query(internal.relays.deliveryBinding, {
        backendServerId: serverId,
        nodeName: 'node-one',
      }),
    ).toMatchObject({ relaySlug: 'node-one', state: 'active' });
    // Forced: every managed edge drains at once.
    const edges = await t.run((ctx) => ctx.db.query('edges').collect());
    expect(
      edges.every((e) => e.status === 'destroyed' || (e.drainUntil ?? Infinity) <= Date.now()),
    ).toBe(true);
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
    expect((await reader('POST', 'templates/ensure-defaults', {})).status).toBe(401);
    const seeded = await call('POST', 'templates/ensure-defaults', {});
    expect(seeded.status).toBe(200);
    expect(await seeded.json()).toEqual({ created: n });
    const after = EdgeTemplatesResponse.parse(await (await call('GET', 'templates')).json());
    expect(after.templates.filter((x) => x.isDefault)).toHaveLength(n);
    expect(Object.keys(after.schemas).sort()).toEqual(
      after.templates.map((x) => x.provider).sort(),
    );
    expect(await (await call('POST', 'templates/ensure-defaults', {})).json()).toEqual({
      created: 0,
    });
  });

  test('contract pinning: every shape the CMS parses matches the server output', async () => {
    const { t, call, accountId, relayId, publishedEdgeId, standbyEdgeId } = await fixture();
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
    const standbyDetail = EdgeDetail.parse(await (await call('GET', standbyEdgeId)).json());
    expect(standbyDetail.live).toBeNull();
    // The imported spare was never confirmed: the detail says so, and a
    // publish is refused until the operator ticks the endpoint.
    expect(standbyDetail.edge.verification).toMatchObject({
      required: true,
      current: false,
      stale: false,
      record: null,
    });
    const refused = await call('POST', `${standbyEdgeId}/publish`, {});
    expect(refused.status).toBe(409);
    expect(await refused.json()).toMatchObject({ error: { code: 'edge.unverified_endpoint' } });
    // Verification binding + the confirmation that echoes it (a stale echo is refused).
    const binding = EdgeVerificationBinding.parse(
      await (await call('GET', `${standbyEdgeId}/verification-binding`)).json(),
    );
    expect(binding).toMatchObject({
      edgeId: standbyEdgeId,
      layer: 'l4',
      endpoint: '198.51.100.8:443',
      publishableAfter: true,
      blocker: null,
    });
    const stale = await call('POST', `${standbyEdgeId}/verify`, {
      ...binding,
      listenerRevision: binding.listenerRevision + 1,
    });
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ error: { code: 'edge.verification_stale' } });
    const verified = EdgeVerifyResponse.parse(
      await (
        await call('POST', `${standbyEdgeId}/verify`, {
          endpoint: binding.endpoint,
          listenerRevision: binding.listenerRevision,
          configHash: binding.configHash,
          method: 'test_link',
        })
      ).json(),
    );
    expect(verified).toMatchObject({ ok: true, edgeId: standbyEdgeId });
    expect(
      EdgeDetail.parse(await (await call('GET', standbyEdgeId)).json()).edge.verification,
    ).toMatchObject({ current: true, record: { rung: 'verified', method: 'test_link' } });
    // Rotation detail: publish the standby through the machine (index 1 behind the template → no Host flip).
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
    // Endpoints + by-slug: parsed with the shared contracts AND pinned structurally.
    const endpoints = RelayEndpointsResponse.parse(
      await (await call('GET', `relays/${relayId}/endpoints`)).json(),
    );
    expect(endpoints.relaySlug).toBe('node-one');
    expect(endpoints.published[0]).toMatchObject({
      edgeId: publishedEdgeId,
      listenerKey: 'u',
      templateHostRemark: 'node-one-relay-u',
      protocol: 'vless',
      streamTransport: 'raw',
      security: 'reality',
      layer: 'l4',
      port: 443,
      hostHeader: null,
    });
    const bySlugRaw = await (await call('GET', 'relays/by-slug/node-one')).json();
    const bySlug = RelayBySlugResponse.parse(bySlugRaw);
    expect(Object.keys(bySlugRaw as object).sort()).toEqual(
      ['relay', 'listeners', 'publishedEndpoints', 'connectionPlan', 'hostsPlan'].sort(),
    );
    expect(Object.keys((bySlugRaw as BySlugView).relay).sort()).toEqual(
      [
        'id',
        'slug',
        'hostMode',
        'delivery',
        'enabled',
        'deleting',
        'publicationEpoch',
        'originAddress',
        'lastRegisteredAt',
      ].sort(),
    );
    expect(bySlug.relay).not.toHaveProperty('suspicion');
    expect(Object.keys((bySlugRaw as BySlugView).publishedEndpoints[0]).sort()).toEqual(
      ['listenerKey', 'poolIndex', 'layer', 'port', 'addresses', 'sni', 'hostHeader'].sort(),
    );
    expect(bySlug.publishedEndpoints[0]).toMatchObject({ poolIndex: 0, port: 443 });
    expect(bySlug.publishedEndpoints[0]).not.toHaveProperty('provider');
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
      origin: { kind: 'panel-node', backendSlug: 'missing', nodeName: 'node-two' },
      originAddress: 'x',
      listeners: [],
    });
    expect(bad.status).toBe(400);
    expect(await bad.json()).toMatchObject({ error: { code: 'validation' } });
    // A body that fails the Convex validator (an unknown origin kind) is the redacted admin.error, never a 500.
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const shape = await call('PUT', 'relays/by-slug/node-two', {
        origin: { kind: 'weird' },
        originAddress: '203.0.113.5',
      });
      expect(shape.status).toBe(400);
      expect(await shape.json()).toMatchObject({ error: { code: 'admin.error' } });
    } finally {
      spy.mockRestore();
    }
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
    const put = (await (
      await call('PUT', 'relays/by-slug/node-one', REGISTER_BODY)
    ).json()) as BySlugView;
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

describe('relay admin routes: importing an existing L7 front', () => {
  const ORIGIN = '203.0.113.10';
  const HOSTNAME = 'front-a.example.org';

  afterEach(() => __setEdgeProviderForTests('cloudflare', null));

  /**
   * A Cloudflare stand-in whose `inspectForAdoption` reports what a real one
   * would: the record's own id, every hostname the resource serves, what it
   * dials, and whether it is shared with other hostnames.
   */
  function fakeCloudflare(over: Partial<AdoptionInspection> = {}) {
    const calls: Array<{ resourceId: string; hostname: string }> = [];
    __setEdgeProviderForTests('cloudflare', {
      id: 'cloudflare',
      templateSchema: z.object({}).passthrough(),
      templateFields: [],
      defaultTemplate: {},
      testCredentials: async () => ({ ok: true, observed: { zoneSslMode: 'flexible' } }),
      planProvision: () => [],
      runStep: async () => ({ status: 'done', resources: [] }),
      discover: async () => ({ status: 'unresolved' }),
      describe: async () => ({ state: 'active', addresses: {}, health: 'unknown' }),
      inspect: async () => ({ summary: { addresses: [], members: [], listeners: [] }, raw: {} }),
      inventory: async () => ({ loadBalancers: [], ips: [], flavors: [] }),
      planDestroy: () => [],
      runDestroy: async () => ({ status: 'confirmed_gone' }),
      inspectForAdoption: async (_cfg: unknown, resourceId: string, hostname: string) => {
        calls.push({ resourceId, hostname });
        return {
          resources: [
            {
              kind: 'dns_record',
              resourceId,
              ownership: 'adopted' as const,
              meta: { zoneId: 'z1' },
            },
            {
              kind: 'service',
              resourceId: 'svc-1',
              ownership: 'adopted' as const,
              meta: { version: 7 },
            },
          ],
          hostname,
          hostnames: [HOSTNAME, 'someone-else.example.org'],
          shared: true,
          content: ORIGIN,
          ...over,
        };
      },
    } as never);
    return calls;
  }

  /**
   * seed() + a Cloudflare account, a relay and an L7-only ws listener: the
   * origin speaks plaintext HTTP behind the front, so the listener carries NO
   * names of its own (behind a front the member presents the edge hostname).
   */
  async function l7Fixture() {
    const s = await seed();
    const { call, t } = s;
    const acct = (await (
      await call('POST', 'providers', {
        provider: 'cloudflare',
        name: 'acct-cf',
        settings: { zoneId: 'a'.repeat(32), zoneName: 'example.org' },
        credentials: { apiToken: 'cf' },
      })
    ).json()) as { id: string };
    // The zone's encryption mode comes from the credential test, never typed.
    await t.run((ctx) =>
      ctx.db.patch(acct.id as Id<'edgeProviderAccounts'>, {
        observedSettings: JSON.stringify({ zoneSslMode: 'flexible' }),
        observedAt: Date.now(),
      }),
    );
    const view = (await (
      await call('PUT', 'relays/by-slug/node-one', {
        origin: ORIGIN_NODE_ONE,
        originAddress: ORIGIN,
        listeners: [
          {
            listenerKey: 'w',
            protocol: 'vless',
            streamTransport: 'ws',
            security: 'tls',
            originPort: 8080,
            tlsNames: [],
            transportParams: { path: '/ws' },
            originTransport: {
              scheme: 'http',
              certPublic: false,
              certNames: [],
              acceptsHostHeader: 'any',
            },
            panelBinding: {
              inboundTag: 'VLESS_RELAY_W',
              configProfileUuid: '11111111-1111-4111-8111-111111111111',
              configProfileInboundUuid: '22222222-2222-4222-8222-222222222222',
            },
          },
        ],
      })
    ).json()) as BySlugView;
    expect(view.listeners).toHaveLength(1);
    expect(view.listeners[0].layers).toEqual(['l7']);
    const listeners = (await (await call('GET', `relays/${view.relay.id}/listeners`)).json()) as {
      listeners: Array<{ id: string }>;
    };
    return {
      ...s,
      accountId: acct.id,
      relayId: view.relay.id,
      listenerId: listeners.listeners[0].id,
    };
  }

  test('the resource is inspected first: the import carries its real children and a frozen intent', async () => {
    const { t, call, accountId, relayId, listenerId } = await l7Fixture();
    const calls = fakeCloudflare();
    const res = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      accountId,
      resourceId: 'rec-1',
      hostname: HOSTNAME,
      publish: true,
    });
    const body = (await res.json()) as { edgeId: string; poolIndex: number | null; code: string };
    expect(res.status).toBe(200);
    expect(calls).toEqual([{ resourceId: 'rec-1', hostname: HOSTNAME }]);
    const edge = (await t.query(internal.edges.get, { id: body.edgeId as Id<'edges'> }))!;
    expect(edge.layer).toBe('l7');
    expect(edge.managed).toBe(true);
    expect(edge.listenerId).toBe(listenerId);
    expect(edge.addresses.hostname).toBe(HOSTNAME);
    // The intent is frozen against the hostname the resource ALREADY serves.
    const intent = JSON.parse(edge.provisionIntent!) as {
      hostname: string;
      zoneSslMode: string;
      originPort: number;
    };
    expect(intent.hostname).toBe(HOSTNAME);
    expect(intent.zoneSslMode).toBe('flexible');
    expect(intent.originPort).toBe(8080);
    const raw = await t.run((ctx) => ctx.db.get(body.edgeId as Id<'edges'>));
    expect(raw!.resources.map((r) => [r.kind, r.resourceId, r.ownership])).toEqual([
      ['dns_record', 'rec-1', 'adopted'],
      ['service', 'svc-1', 'adopted'],
    ]);
    expect(JSON.parse(raw!.resources[1].meta!)).toEqual({ version: 7, shared: true });
    // An L7 import is NEVER published on the operator's word: no end-to-end proof, no publication.
    expect(body.poolIndex).toBeNull();
    expect(body.code).toBe('front_unqualified');
    expect(edge.publication).toBe('unpublished');
  });

  test('a resource that does not dial this origin, or does not serve the hostname, is refused', async () => {
    const { call, accountId, relayId, listenerId } = await l7Fixture();
    fakeCloudflare({ content: '198.51.100.99' });
    const foreign = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      accountId,
      resourceId: 'rec-1',
      hostname: HOSTNAME,
      publish: false,
    });
    expect(foreign.status).toBeGreaterThanOrEqual(400);
    expect(await foreign.json()).toMatchObject({ error: { code: 'edge.not_owned' } });
    fakeCloudflare({ hostnames: ['someone-else.example.org'] });
    const wrongHost = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      accountId,
      resourceId: 'rec-1',
      hostname: HOSTNAME,
      publish: false,
    });
    expect(await wrongHost.json()).toMatchObject({ error: { code: 'edge.not_owned' } });
  });

  test('a DNS-only (unproxied) record is refused by the import, not silently adopted', async () => {
    const { call, accountId, relayId, listenerId } = await l7Fixture();
    fakeCloudflare({
      resources: [
        {
          kind: 'dns_record',
          resourceId: 'rec-1',
          ownership: 'adopted' as const,
          meta: { zoneId: 'z1', proxied: false },
        },
      ],
    });
    const res = await call('POST', `relays/${relayId}/adopt`, {
      listenerId,
      accountId,
      resourceId: 'rec-1',
      hostname: HOSTNAME,
      publish: false,
    });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(await res.json()).toMatchObject({ error: { code: 'edge.record_not_proxied' } });
  });

  test('an L4 edge on a name-free HTTP-transport listener is refused; the L7 one publishes with a current proof', async () => {
    const { t, call, relayId, listenerId } = await l7Fixture();
    fakeCloudflare();
    // An L4 forwarder would have to SELECT one of the listener's own names, and it has none.
    const l4 = (await (
      await call('POST', `relays/${relayId}/adopt`, {
        listenerId,
        ipv4: '198.51.100.7',
        publish: false,
      })
    ).json()) as { edgeId: string };
    const l4Publish = await call('POST', `${l4.edgeId}/publish`, { direct: true });
    expect(await l4Publish.json()).toMatchObject({
      error: { code: 'edge.listener_no_active_name' },
    });
    // The same listener behind a front publishes: its name IS the edge hostname.
    const l7 = (await (
      await call('POST', `relays/${relayId}/adopt`, {
        listenerId,
        hostname: HOSTNAME,
        publish: false,
      })
    ).json()) as { edgeId: string };
    const edgeId = l7.edgeId as Id<'edges'>;
    // A front is published only with a CURRENT end-to-end proof bound to exactly this configuration.
    await t.run(async (ctx) => {
      const edge = (await ctx.db.get(edgeId))!;
      const listener = (await ctx.db.get(edge.listenerId))!;
      const intent = {
        hostname: HOSTNAME,
        zoneId: 'a'.repeat(32),
        zoneName: 'example.org',
        originTransport: listener.originTransport!,
        originPort: listener.originPort,
        zoneSslMode: 'flexible',
        templateHash: 'h1',
        templateParams: {},
      };
      const now = Date.now();
      const binding = qualificationBinding({
        listener,
        intent,
        params: listener.transportParams ?? {},
      });
      expect(binding).toMatchObject({
        hostname: HOSTNAME,
        listenerId: listener._id,
        listenerRevision: listener.revision,
        protocol: 'vless',
        streamTransport: 'ws',
        security: 'tls',
      });
      await ctx.db.patch(edgeId, {
        provisionIntent: JSON.stringify(intent),
        frontQualification: {
          ok: true,
          checkedAt: now,
          expiresAt: now + 3_600_000,
          binding: { ...binding, listenerId: binding.listenerId as Id<'relayListeners'> },
        },
      });
    });
    // The first published edge becomes the listener's template edge: on an
    // FCP-owned relay that is the rotation machine's job, so leave the Host to the operator.
    await t.mutation(internal.relays.update, { id: relayId as Id<'relays'>, hostMode: 'operator' });
    expect(
      await t.mutation(internal.relays.publishEdge, { relayId: relayId as Id<'relays'>, edgeId }),
    ).toMatchObject({ poolIndex: 0 });
    // The role's view now hands out the fronted hostname as address, SNI and Host header.
    const view = (await (await call('GET', 'relays/by-slug/node-one')).json()) as BySlugView;
    expect(view.publishedEndpoints[0]).toMatchObject({
      listenerKey: 'w',
      layer: 'l7',
      addresses: { v4: null, v6: null, hostname: HOSTNAME },
      sni: HOSTNAME,
      hostHeader: HOSTNAME,
    });
    expect(view.connectionPlan).toEqual([
      { listenerKey: 'w', address: HOSTNAME, port: 443, sni: HOSTNAME, host: HOSTNAME },
    ]);
    expect(view.hostsPlan.mode).toBe('operator');
    expect(view.hostsPlan.hosts).toEqual([
      expect.objectContaining({
        listenerKey: 'w',
        remark: 'node-one-relay-w',
        address: HOSTNAME,
        port: 443,
      }),
    ]);
    // A listener edit (revision bump) makes the proof stale: publication is refused again.
    await t.mutation(internal.relays.unpublishEdge, {
      relayId: relayId as Id<'relays'>,
      edgeId,
      keepActive: true,
    });
    await t.mutation(internal.relayListeners.setEnabled, {
      id: listenerId as Id<'relayListeners'>,
      enabled: false,
    });
    await t.mutation(internal.relayListeners.setEnabled, {
      id: listenerId as Id<'relayListeners'>,
      enabled: true,
    });
    await expect(
      t.mutation(internal.relays.publishEdge, { relayId: relayId as Id<'relays'>, edgeId }),
    ).rejects.toThrow(/front_qualification_stale/);
  });
});
