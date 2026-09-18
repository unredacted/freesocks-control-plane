import { describe, expect, it } from 'vitest';
import { EDGE_PROVIDER_IDS } from '@shared/contracts/edges';
import { SETUP_STEP_IDS } from '@shared/contracts/edgeCodes';
import { LISTENER_COMBOS } from '@shared/contracts/edgeProtocolIds';
import { ListenerSpec, SetupDraft } from '@shared/contracts/edges';
import {
  addressIssue,
  emptyOrigin,
  originIssue,
  suggestSlug,
  toCreateOrigin,
  toWireOrigin,
} from '../forms/origin';
import {
  emptyListenerForm,
  listenerFormIssues,
  normalizeCertName,
  toDraftListener,
  toListenerSpec,
} from '../forms/listenerForm';
import { relaySlugIssue, suggestListenerKey } from '../forms/prefill';
import {
  PROVIDER_FIELDS,
  applyDiscovery,
  credentialLabel,
  missingRequired,
  optionsFor,
  settingsBody,
} from '../forms/providerFields';
import { draftIsEmpty, emptyDraft, parseDraft, toSetupDraft } from './draft';
import { formatRoleVars, roleVarRows } from './roleVars';
import { STEP_COPY, isSetupStepId, resolveShownStep, stepNote, stepperSteps } from './steps';
import { backendServersHref, issueLink } from './issueActions';

const EM_DASH = '—';

describe('origin', () => {
  it('accepts public literals and names, refuses private ones in words', () => {
    expect(addressIssue('198.51.100.10')).toBeNull();
    expect(addressIssue('2001:db8::10')).toBeNull();
    expect(addressIssue('origin.example')).toBeNull();
    for (const bad of ['', '10.0.0.1', '192.168.1.4', '127.0.0.1', '169.254.1.1', '100.64.0.1'])
      expect(addressIssue(bad)).not.toBeNull();
    for (const bad of [
      '::1',
      'fe80::1',
      'fd00::1',
      'localhost',
      'node.local',
      'https://a.example',
      'a.example:443',
      '300.1.1.1',
      'nodot',
    ])
      expect(addressIssue(bad)).not.toBeNull();
  });

  it('names the first missing piece per kind', () => {
    expect(originIssue(emptyOrigin('panel-node'))).toMatch(/panel/);
    expect(
      originIssue({ ...emptyOrigin('panel-node'), backendServerId: 'b1', backendSlug: 'p' }),
    ).toMatch(/node/);
    expect(originIssue({ ...emptyOrigin('manual'), address: '198.51.100.7' })).toBeNull();
  });

  it('projects to the admin (id) and the draft (slug) origin shapes', () => {
    const o = {
      ...emptyOrigin('panel-node'),
      backendServerId: 'b1',
      backendSlug: 'panel-a',
      nodeName: 'Node 1',
      nodeUuid: 'u1',
      address: '198.51.100.7',
    };
    expect(toCreateOrigin(o)).toEqual({
      kind: 'panel-node',
      backendServerId: 'b1',
      nodeName: 'Node 1',
      nodeUuid: 'u1',
    });
    expect(toWireOrigin(o)).toEqual({
      kind: 'panel-node',
      backendSlug: 'panel-a',
      nodeName: 'Node 1',
      nodeUuid: 'u1',
    });
    expect(toWireOrigin({ ...o, nodeName: '' })).toBeNull();
    expect(toWireOrigin(emptyOrigin('manual'))).toEqual({ kind: 'manual' });
    expect(toWireOrigin(null)).toBeNull();
    expect(suggestSlug(o)).toBe('node-1');
  });
});

describe('listener form', () => {
  it('builds a spec the contract accepts for every catalogue combination', () => {
    for (const c of LISTENER_COMBOS) {
      const f = emptyListenerForm();
      f.listenerKey = 'k1';
      f.combo = c.key;
      f.originPort = '443';
      if (c.usesSni) f.tlsNames = ['cdn.example'];
      if (c.needsTarget) f.targetAddress = 'target.example';
      expect(listenerFormIssues(f, 'panel-node'), c.key).toEqual([]);
      const spec = toListenerSpec(f, 'panel-node');
      expect(ListenerSpec.safeParse(spec).success, c.key).toBe(true);
      expect(spec.tlsNames === undefined).toBe(!c.usesSni);
      expect(spec.realityTarget === undefined).toBe(!c.needsTarget);
    }
  });

  it('explains what is missing', () => {
    const f = emptyListenerForm();
    const issues = listenerFormIssues(f, 'panel-node');
    expect(issues.length).toBeGreaterThanOrEqual(3);
    for (const i of issues) expect(i).not.toContain(EM_DASH);
  });

  it('lets an L7-only listener (plain HTTP origin) go without server names', () => {
    const f = emptyListenerForm();
    f.listenerKey = 'ws';
    f.combo = 'vless/ws/tls';
    f.frontable = true;
    f.scheme = 'http';
    expect(listenerFormIssues(f, 'panel-node')).toEqual([]);
    const spec = toListenerSpec(f, 'panel-node');
    expect(spec.originTransport).toEqual({
      scheme: 'http',
      certPublic: false,
      certNames: [],
      acceptsHostHeader: 'names',
    });
    expect(toDraftListener(f).originTransport?.scheme).toBe('http');
  });

  it('never sends a panel binding or a remark rule for a non-panel origin', () => {
    const f = emptyListenerForm('backend-server');
    f.listenerKey = 'ss';
    f.originPort = '8388';
    f.bindPanel = true;
    f.matchRule = 'whole-body';
    const spec = toListenerSpec(f, 'backend-server');
    expect(spec.panelBinding).toBeUndefined();
    expect(spec.matchRule).toEqual({ kind: 'whole-body' });
  });

  it('normalises certificate names with one leading wildcard', () => {
    expect(normalizeCertName('*.Example.ORG')).toBe('*.example.org');
    expect(normalizeCertName('a.*.example')).toBeNull();
  });

  it('suggests free listener keys and validates slugs', () => {
    expect(suggestListenerKey({ combo: 'vless/raw/reality' }, [])).toBe('reality');
    expect(suggestListenerKey({ combo: 'vless/raw/reality' }, ['reality'])).toBe('reality2');
    expect(suggestListenerKey({ combo: 'vless/ws/tls' }, [])).toBe('ws');
    expect(suggestListenerKey({ combo: 'shadowsocks/raw/none' }, [])).toBe('ss');
    expect(relaySlugIssue('node-1')).toBeNull();
    expect(relaySlugIssue('Node 1')).not.toBeNull();
    expect(relaySlugIssue('-a')).not.toBeNull();
  });
});

describe('provider fields', () => {
  it('covers every provider id', () => {
    expect(Object.keys(PROVIDER_FIELDS).sort()).toEqual([...EDGE_PROVIDER_IDS].sort());
  });

  it('builds numeric settings and drops blanks', () => {
    expect(settingsBody('gcore', { projectId: '12', regionId: '7', networkId: ' ' })).toEqual({
      projectId: 12,
      regionId: 7,
    });
    expect(missingRequired('gcore', { projectId: '12' })).toEqual(['Region']);
    expect(missingRequired('scaleway', {}, 'credentials')).toEqual(['Access key (public id)']);
  });

  it('preselects single choices, keeps the zone name in step, drops stale subnets', () => {
    const accounts = [{ id: 'a1', name: 'DNS', provider: 'cloudflare' as const }];
    const next = applyDiscovery(
      'cloudflare',
      {},
      { discovered: { zones: [{ id: 'z'.repeat(32), label: 'front.example' }] }, accounts },
    );
    expect(next).toMatchObject({ zoneId: 'z'.repeat(32), zoneName: 'front.example' });

    const nets = {
      networks: [
        { id: 'n1', label: 'one', subnets: [{ id: 's1', label: 'a' }] },
        { id: 'n2', label: 'two', subnets: [{ id: 's2', label: 'b' }] },
      ],
    };
    const kept = applyDiscovery(
      'ovh',
      { networkId: 'n2', subnetId: 's1' },
      { discovered: nets, accounts },
    );
    expect(kept['subnetId']).toBe('s2');

    const dns = PROVIDER_FIELDS.fastly.find((f) => f.from === 'dnsAccounts')!;
    expect(optionsFor(dns, { discovered: null, accounts, values: {} })).toEqual([
      { id: 'a1', label: 'DNS' },
    ]);
  });

  it('words credential field names', () => {
    expect(credentialLabel('apiToken')).toBe('API token');
    expect(credentialLabel('someNewSecret')).toBe('Some New Secret');
  });
});

describe('draft storage', () => {
  it('round-trips and tolerates junk', () => {
    const d = emptyDraft();
    d.origin = { ...emptyOrigin('manual'), address: '198.51.100.9' };
    const l = emptyListenerForm();
    l.combo = 'vless/ws/tls';
    l.tlsNames = ['cdn.example'];
    d.listeners = [l];
    const back = parseDraft(JSON.stringify(d));
    expect(back).toEqual(d);
    expect(parseDraft('not json')).toBeNull();
    expect(parseDraft(null)).toBeNull();
    expect(
      parseDraft(JSON.stringify({ origin: { kind: 'nope' }, listeners: [{ combo: 'x' }, 3] })),
    ).toEqual(emptyDraft());
    const stale = parseDraft(
      JSON.stringify({
        listeners: [{ combo: 'vless/raw/tls', originPort: 443, tlsNames: [1, 'a.example'] }],
      }),
    );
    expect(stale?.listeners[0]?.originPort).toBe('443');
    expect(stale?.listeners[0]?.tlsNames).toEqual(['a.example']);
    expect(draftIsEmpty(emptyDraft())).toBe(true);
  });

  it('projects to the setup-status draft body', () => {
    const d = emptyDraft();
    d.origin = { ...emptyOrigin('backend-server'), backendServerId: 'b', backendSlug: 'outline-a' };
    const l = emptyListenerForm('backend-server');
    l.originPort = '8388';
    d.listeners = [l];
    const body = toSetupDraft(d);
    expect(SetupDraft.safeParse(body).success).toBe(true);
    expect(body).toEqual({
      origin: { kind: 'backend-server', backendSlug: 'outline-a' },
      listeners: [
        { protocol: 'shadowsocks', streamTransport: 'raw', security: 'none', originPort: 8388 },
      ],
    });
    expect(toSetupDraft(emptyDraft())).toEqual({ origin: null, listeners: [] });
  });
});

describe('role vars', () => {
  const vars = {
    fcp_relay_host_mode: 'fcp',
    zzz_extra: 'a b',
    fcp_relay_listeners: 'reality,ws',
    fcp_relay_slug: 'node1',
    fcp_relay_register_scope: 'admin:edges:register',
  };
  it('orders known keys first and formats YAML-style lines', () => {
    expect(roleVarRows(vars).map((r) => r.key)).toEqual([
      'fcp_relay_slug',
      'fcp_relay_listeners',
      'fcp_relay_register_scope',
      'fcp_relay_host_mode',
      'zzz_extra',
    ]);
    expect(formatRoleVars(vars)).toBe(
      [
        'fcp_relay_slug: node1',
        'fcp_relay_listeners: [reality, ws]',
        'fcp_relay_register_scope: "admin:edges:register"',
        'fcp_relay_host_mode: fcp',
        'zzz_extra: "a b"',
      ].join('\n'),
    );
    expect(formatRoleVars(null)).toBe('');
    expect(formatRoleVars({ fcp_relay_listeners: '' })).toBe('fcp_relay_listeners: []');
    expect(formatRoleVars({ a: 'true', b: '123' })).toBe('a: "true"\nb: "123"');
  });
});

describe('steps', () => {
  const step = (
    id: (typeof SETUP_STEP_IDS)[number],
    status: 'done' | 'ready' | 'blocked' | 'skipped',
    blockers = 0,
    warnings = 0,
  ) => ({
    id,
    status,
    blockers: Array.from({ length: blockers }, () => ({ code: 'x', subject: null, detail: null })),
    warnings: Array.from({ length: warnings }, () => ({ code: 'y', subject: null, detail: null })),
    facts: {},
  });

  it('has copy for every step, without em-dashes', () => {
    for (const id of SETUP_STEP_IDS) {
      expect(STEP_COPY[id].title.length).toBeGreaterThan(0);
      expect(STEP_COPY[id].title + STEP_COPY[id].description).not.toContain(EM_DASH);
    }
    expect(isSetupStepId('publish')).toBe(true);
    expect(isSetupStepId('nope')).toBe(false);
  });

  it('notes blockers and warnings, and maps onto the stepper', () => {
    expect(stepNote(step('edge', 'blocked', 2))).toBe('2 blockers');
    expect(stepNote(step('relay', 'done', 0, 1))).toBe('1 warning');
    expect(stepNote(step('origin', 'done'))).toBe('');
    const out = stepperSteps([step('origin', 'done'), step('account', 'ready', 1)]);
    expect(out[0]).toEqual({
      id: 'origin',
      title: STEP_COPY.origin.title,
      description: STEP_COPY.origin.description,
      status: 'done',
    });
    expect(out[1]?.note).toBe('1 blocker');
  });

  it('shows the peeked step only when it is a real one', () => {
    const status = {
      steps: [step('origin', 'done'), step('account', 'ready')],
      currentStep: 'account' as const,
    };
    expect(resolveShownStep(status, null)).toBe('account');
    expect(resolveShownStep(status, 'origin')).toBe('origin');
    expect(resolveShownStep(status, 'publish')).toBe('account');
    expect(resolveShownStep(status, 'bogus')).toBe('account');
  });
});

describe('issue links', () => {
  const ctx = { relaySlug: 'node1', accountId: 'acc1', returnTo: '/admin/edges/setup?relay=node1' };
  it('sends the operator to the page that fixes the code', () => {
    expect(issueLink('backend_unreachable', ctx)?.href).toBe(backendServersHref(ctx.returnTo));
    expect(backendServersHref(ctx.returnTo)).toBe(
      '/admin/backend-servers?return=%2Fadmin%2Fedges%2Fsetup%3Frelay%3Dnode1',
    );
    expect(issueLink('credentials_failed', ctx)?.href).toBe('/admin/edges/providers/acc1');
    expect(issueLink('credentials_failed', { ...ctx, accountId: null })?.href).toBe(
      '/admin/edges/providers',
    );
    expect(issueLink('edge.needs_names', ctx)?.href).toBe(
      '/admin/edges/relays/node1?tab=listeners',
    );
    expect(issueLink('needs_names', { ...ctx, relaySlug: null })).toBeNull();
    expect(issueLink('pool_empty', ctx)).toBeNull();
  });
  it('never puts an API path or an em-dash in a label', () => {
    for (const code of [
      'no_backend_server',
      'template_invalid',
      'quarantined',
      'probe_sources_none',
    ]) {
      const l = issueLink(code, ctx);
      expect(l?.label).toBeTruthy();
      expect(l?.label).not.toContain(EM_DASH);
      expect(l?.href).not.toContain('/api/');
    }
  });
});
