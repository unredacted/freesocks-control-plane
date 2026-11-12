import { afterEach, describe, expect, test, vi } from 'vitest';
import { GcoreTemplate, gcoreProvider } from './gcore';
import { chooseDdosTemplate, decodeDdosState, DDOS_STEP_KIND } from './gcoreDdos';
import type { GcoreConfig, Ledger, LedgerResource } from './types';
import { jsonRes, mockFetch, type Captured } from '../testing/mockFetch';

afterEach(() => vi.unstubAllGlobals());

const cfg: GcoreConfig = { type: 'gcore', apiKey: 'SECRET_GCORE_KEY', projectId: 11, regionId: 22 };
const spec = {
  name: 'fcp-relay-o1-deadbeef',
  listeners: [{ edgePort: 443, members: [{ address: '198.51.100.7', port: 443 }] }],
};
const ADDR = '203.0.113.5';
const LB = { id: 'lb-1', provisioning_status: 'ACTIVE', vip_address: ADDR };
const lbRes: LedgerResource = {
  stepId: 'lb',
  kind: 'lb',
  resourceId: 'lb-1',
  ownership: 'created',
  deleteState: 'present',
};
const ledger: Ledger = { steps: [], resources: [lbRes] };
const PROFILES = '/cloud/v1/ddos/profiles/11/22';
const TEMPLATES = [
  { id: 7, name: 'TCP generic', description: 'Any TCP service', fields: [] },
  { id: 9, name: 'Game server', description: null, fields: [] },
];

interface World {
  access?: boolean;
  templates?: typeof TEMPLATES;
  profiles?: Array<Record<string, unknown>>;
  task?: string;
  lb?: Record<string, unknown>;
  createStatus?: number;
}

/** A small Gcore: the balancer, the DDoS endpoints and the tasks they start. */
function gcoreWorld(w: World) {
  return (c: Captured): Response => {
    const p = c.path;
    if (p === '/cloud/v1/loadbalancers/11/22/lb-1') return jsonRes(w.lb ?? LB);
    if (p === '/cloud/v1/ddos/accessibility/22')
      return jsonRes({ is_accessible: w.access ?? true, http_code: 200, message: 'ok' });
    if (p === '/cloud/v1/ddos/profile-templates/22')
      return jsonRes({ count: 2, results: w.templates ?? TEMPLATES });
    if (p === '/cloud/v1/pricing/22/ddos')
      return jsonRes({
        price: {
          feature_name: 'Advanced DDoS Protection',
          price_currency: 'EUR',
          price_per_30d: 60,
          price_per_day: 2,
          unit_name: 'PC',
        },
      });
    if (p === PROFILES && c.method === 'GET') return jsonRes({ results: w.profiles ?? [] });
    if (p === PROFILES && c.method === 'POST')
      return w.createStatus
        ? jsonRes({ type: 'not-available', title: 'nope' }, w.createStatus)
        : jsonRes({ tasks: ['t-create'] });
    if (p.startsWith(`${PROFILES}/`) && c.method !== 'GET') return jsonRes({ tasks: ['t-other'] });
    if (p.startsWith('/cloud/v1/tasks/'))
      return jsonRes({ id: p.split('/').pop(), state: w.task ?? 'FINISHED' });
    return jsonRes({ message: 'not found' }, 404);
  };
}

const profile = (over: Record<string, unknown> = {}) => ({
  id: 41,
  ip_address: ADDR,
  options: { active: true, bgp: true },
  status: { status: 'Updated', error_description: '' },
  profile_template: { id: 7, name: 'TCP generic' },
  managed_by: 'user',
  ...over,
});

describe('gcore ddos: choosing the profile template', () => {
  test('by number, by name in any case, or the only one; never a guess between several', () => {
    expect(chooseDdosTemplate(TEMPLATES, '9')).toEqual({ ok: true, id: 9, name: 'Game server' });
    expect(chooseDdosTemplate(TEMPLATES, ' tcp GENERIC ')).toMatchObject({ ok: true, id: 7 });
    expect(chooseDdosTemplate([TEMPLATES[0]], undefined)).toMatchObject({ ok: true, id: 7 });
    expect(chooseDdosTemplate(TEMPLATES, undefined)).toEqual({
      ok: false,
      code: 'ddos_template_required',
    });
    expect(chooseDdosTemplate(TEMPLATES, 'nope')).toEqual({
      ok: false,
      code: 'ddos_template_unknown',
    });
    expect(chooseDdosTemplate([], 'x')).toEqual({ ok: false, code: 'ddos_no_templates' });
  });
});

describe('gcore ddos: the template option', () => {
  test('optional, so a stored template parses to the object it always did', () => {
    expect(GcoreTemplate.parse({})).not.toHaveProperty('ddosProtection');
    expect(GcoreTemplate.safeParse({ ddosProtection: 'sometimes' }).success).toBe(false);
  });

  test('off plans the load balancer alone; on or required adds the protection step after it', () => {
    const off = gcoreProvider.planProvision(cfg, spec, GcoreTemplate.parse({}));
    expect(off.map((s) => s.kind)).toEqual(['create_lb']);
    for (const mode of ['on', 'required'] as const) {
      const steps = gcoreProvider.planProvision(
        cfg,
        spec,
        GcoreTemplate.parse({ ddosProtection: mode }),
      );
      expect(steps.map((s) => s.kind)).toEqual(['create_lb', DDOS_STEP_KIND]);
    }
  });
});

describe('gcore ddos: the provisioning step', () => {
  const step = gcoreProvider.planProvision(
    cfg,
    spec,
    GcoreTemplate.parse({ ddosProtection: 'required' }),
  )[1]!;
  const tplOf = (over: Record<string, unknown>) =>
    GcoreTemplate.parse({ ddosProtection: 'required', ...over });

  test('creates the profile on the public IPv4, then turns it on, then records it', async () => {
    // Created inactive: the step turns it on with BGP.
    const w: World = { profiles: [] };
    const stub = mockFetch(gcoreWorld(w));
    const first = await gcoreProvider.runStep(
      cfg,
      step,
      spec,
      tplOf({ ddosProfileTemplate: 'TCP generic' }),
      ledger,
    );
    expect(first.status).toBe('requested');
    const created = stub.calls.find((c) => c.path === PROFILES && c.method === 'POST');
    expect(created?.body).toEqual({ profile_template: 7, ip_address: ADDR });

    w.profiles = [profile({ options: { active: false, bgp: false } })];
    const second = await gcoreProvider.pollStep!(
      cfg,
      step,
      first.status === 'requested' ? first.opRef : '',
      ledger,
    );
    expect(second).toMatchObject({ status: 'requested' });
    const action = stub.calls.find((c) => c.path === `${PROFILES}/41/action`);
    expect(action?.body).toEqual({ active: true, bgp: true });
    expect(decodeDdosState(second.status === 'requested' ? second.opRef : '')).toMatchObject({
      phase: 'activate',
      profileId: 41,
    });

    const third = await gcoreProvider.pollStep!(
      cfg,
      step,
      second.status === 'requested' ? second.opRef : '',
      ledger,
    );
    expect(third).toEqual({
      status: 'done',
      resources: [
        { kind: 'ddos_profile', resourceId: '41', ownership: 'created', meta: { address: ADDR } },
      ],
    });
  });

  test('waits while the load balancer is not active, without asking about protection', async () => {
    const stub = mockFetch(gcoreWorld({ lb: { ...LB, provisioning_status: 'PENDING_CREATE' } }));
    const out = await gcoreProvider.runStep(cfg, step, spec, tplOf({}), ledger);
    expect(out.status).toBe('requested');
    expect(stub.calls.some((c) => c.path.startsWith('/cloud/v1/ddos/'))).toBe(false);
  });

  test('a profile already on the address (a lost answer) is adopted, never created twice', async () => {
    const stub = mockFetch(gcoreWorld({ profiles: [profile()] }));
    const out = await gcoreProvider.runStep(cfg, step, spec, tplOf({}), ledger);
    expect(out).toMatchObject({ status: 'done', resources: [{ resourceId: '41' }] });
    expect(stub.calls.some((c) => c.method === 'POST')).toBe(false);
  });

  test('required stops the run when the region cannot protect it; on goes on without it', async () => {
    mockFetch(gcoreWorld({ access: false }));
    expect(await gcoreProvider.runStep(cfg, step, spec, tplOf({}), ledger)).toMatchObject({
      status: 'partial',
      refused: true,
      code: 'ddos_unavailable',
    });
    expect(
      await gcoreProvider.runStep(cfg, step, spec, tplOf({ ddosProtection: 'on' }), ledger),
    ).toEqual({ status: 'done', resources: [] });
  });

  test('several templates and none named: required stops on ddos_template_required', async () => {
    mockFetch(gcoreWorld({}));
    expect(await gcoreProvider.runStep(cfg, step, spec, tplOf({}), ledger)).toMatchObject({
      status: 'partial',
      code: 'ddos_template_required',
    });
  });

  test("a refused create stops a required run without counting against the account's key", async () => {
    mockFetch(gcoreWorld({ templates: [TEMPLATES[0]], createStatus: 403 }));
    const out = await gcoreProvider.runStep(cfg, step, spec, tplOf({}), ledger);
    expect(out).toMatchObject({ status: 'partial', refused: true, code: 'ddos_refused' });
    expect(out).not.toHaveProperty('httpStatus');
  });

  test('discovery finds a profile on the address; a quiet listing settles like the balancer', async () => {
    mockFetch(gcoreWorld({ profiles: [profile()] }));
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toMatchObject({
      status: 'found',
      resources: [{ kind: 'ddos_profile', resourceId: '41' }],
    });
    mockFetch(gcoreWorld({ profiles: [] }));
    expect(await gcoreProvider.discover(cfg, step, spec, ledger, 1)).toEqual({
      status: 'unresolved',
    });
    const settled: Ledger = {
      steps: [
        {
          stepId: 'ddos',
          kind: DDOS_STEP_KIND,
          resourceName: spec.name,
          state: 'unresolved',
          attempt: 0,
          startedAt: 1,
        },
      ],
      resources: [lbRes],
    };
    expect(await gcoreProvider.discover(cfg, step, spec, settled, 3)).toEqual({
      status: 'confirmed_absent',
    });
  });
});

describe('gcore ddos: destroy', () => {
  const prof: LedgerResource = {
    stepId: 'ddos',
    kind: 'ddos_profile',
    resourceId: '41',
    ownership: 'created',
    deleteState: 'present',
    meta: JSON.stringify({ address: ADDR }),
  };

  test('a ledgered profile goes before the load balancer and the floating IP', () => {
    const l: Ledger = {
      steps: [],
      resources: [lbRes, { ...lbRes, kind: 'floating_ip', resourceId: 'fip-1' }, prof],
    };
    expect(gcoreProvider.planDestroy(cfg, l).map((r) => r.kind)).toEqual([
      'ddos_profile',
      'lb',
      'floating_ip',
    ]);
  });

  test('deletes a profile and reads it back by address', async () => {
    const stub = mockFetch(gcoreWorld({ profiles: [profile({ status: { status: 'Deleting' } })] }));
    expect(await gcoreProvider.runDestroy(cfg, prof, ledger)).toEqual({
      status: 'delete_requested',
      opRef: 't-other',
    });
    expect(stub.calls.at(-1)).toMatchObject({ method: 'DELETE', path: `${PROFILES}/41` });
    expect(await gcoreProvider.confirmDestroyed!(cfg, prof, ledger)).toEqual({
      status: 'unresolved',
    });
    mockFetch(gcoreWorld({ profiles: [profile({ status: { status: 'Error Deleting' } })] }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, prof, ledger)).toEqual({
      status: 'still_present',
    });
    mockFetch(gcoreWorld({ profiles: [] }));
    expect(await gcoreProvider.confirmDestroyed!(cfg, prof, ledger)).toEqual({
      status: 'confirmed_gone',
    });
    mockFetch(() => jsonRes({ message: 'gone' }, 404));
    expect(await gcoreProvider.runDestroy(cfg, prof, ledger)).toEqual({
      status: 'confirmed_gone',
    });
  });

  test('the load balancer waits for a profile the ledger never recorded to go first', async () => {
    const stub = mockFetch(gcoreWorld({ profiles: [profile()] }));
    expect(await gcoreProvider.runDestroy(cfg, lbRes, ledger)).toEqual({ status: 'unresolved' });
    expect(stub.calls.filter((c) => c.method === 'DELETE').map((c) => c.path)).toEqual([
      `${PROFILES}/41`,
    ]);
    // Next pass: still deleting, so nothing is asked again and the balancer waits.
    const s2 = mockFetch(gcoreWorld({ profiles: [profile({ status: { status: 'Deleting' } })] }));
    expect(await gcoreProvider.runDestroy(cfg, lbRes, ledger)).toEqual({ status: 'unresolved' });
    expect(s2.calls.some((c) => c.method === 'DELETE')).toBe(false);
  });
});

describe('gcore ddos: the edge page', () => {
  test('the view: coverage, templates, the profile on the address, the price', async () => {
    mockFetch(gcoreWorld({ profiles: [profile()] }));
    const v = await gcoreProvider.ddos!.view(cfg, ledger);
    expect(v).toMatchObject({
      available: true,
      templates: [
        { id: 7, name: 'TCP generic', description: 'Any TCP service' },
        { id: 9, name: 'Game server', description: null },
      ],
      profiles: [{ id: '41', address: ADDR, active: true, bgp: true, templateId: 7 }],
      addresses: { v4: ADDR },
      price: { feature: 'Advanced DDoS Protection', per30d: 60, currency: 'EUR' },
      unread: [],
    });
  });

  test('a protection service that cannot answer leaves the view readable', async () => {
    const base = gcoreWorld({});
    mockFetch((c) =>
      c.path.startsWith('/cloud/v1/ddos/') || c.path.startsWith('/cloud/v1/pricing/')
        ? jsonRes({ message: 'down' }, 503)
        : base(c),
    );
    const v = await gcoreProvider.ddos!.view(cfg, ledger);
    expect(v).toMatchObject({ available: null, templates: [], profiles: [], price: null });
    expect(v.unread.sort()).toEqual(['price', 'profiles', 'region', 'templates']);
  });

  test('enable creates and turns on; disable turns off; remove deletes', async () => {
    const w: World = { templates: [TEMPLATES[0]], profiles: [] };
    const stub = mockFetch((c) => {
      // The create lands an inactive profile.
      if (c.path === PROFILES && c.method === 'POST')
        w.profiles = [profile({ options: { active: false, bgp: false } })];
      return gcoreWorld(w)(c);
    });
    expect(await gcoreProvider.ddos!.change(cfg, ledger, { action: 'enable' })).toEqual({
      state: 'done',
    });
    expect(stub.calls.find((c) => c.path === `${PROFILES}/41/action`)?.body).toEqual({
      active: true,
      bgp: true,
    });

    w.profiles = [profile()];
    const s2 = mockFetch(gcoreWorld(w));
    expect(await gcoreProvider.ddos!.change(cfg, ledger, { action: 'enable' })).toEqual({
      state: 'unchanged',
    });
    expect(await gcoreProvider.ddos!.change(cfg, ledger, { action: 'disable' })).toEqual({
      state: 'done',
    });
    expect(s2.calls.find((c) => c.path === `${PROFILES}/41/action`)?.body).toEqual({
      active: false,
      bgp: false,
    });
    expect(await gcoreProvider.ddos!.change(cfg, ledger, { action: 'remove' })).toEqual({
      state: 'done',
    });
    expect(s2.calls.at(-2)).toMatchObject({ method: 'DELETE', path: `${PROFILES}/41` });
  });

  test('enable with another template switches the profile to it', async () => {
    const stub = mockFetch(gcoreWorld({ profiles: [profile()] }));
    expect(
      await gcoreProvider.ddos!.change(cfg, ledger, {
        action: 'enable',
        profileTemplate: 'Game server',
      }),
    ).toEqual({ state: 'done' });
    expect(stub.calls.find((c) => c.method === 'PATCH')).toMatchObject({
      path: `${PROFILES}/41`,
      body: { profile_template: 9, ip_address: ADDR },
    });
  });

  test('enable refuses a region without protection, before creating anything', async () => {
    const stub = mockFetch(gcoreWorld({ access: false }));
    await expect(
      gcoreProvider.ddos!.change(cfg, ledger, { action: 'enable' }),
    ).rejects.toMatchObject({ meta: { code: 'ddos_unavailable' } });
    expect(stub.calls.some((c) => c.method === 'POST')).toBe(false);
  });
});
