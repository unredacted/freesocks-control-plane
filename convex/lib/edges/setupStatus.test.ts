/**
 * The guided setup's step logic, on plain facts: which step is current, what
 * blocks it, what is only a warning, what a manual origin skips, and when the
 * setup counts as complete. Everything here is a fixture value; nothing names
 * a deployment.
 */
import { describe, expect, test } from 'vitest';
import {
  computeSetupStatus,
  type SetupAccountFacts,
  type SetupInput,
  type SetupListenerFacts,
  type SetupRelayFacts,
} from './setupStatus';
import { SETUP_BLOCKER_CODES, SETUP_STEP_IDS } from '../../../src/shared/contracts/edgeCodes';

const listener = (over: Partial<SetupListenerFacts> = {}): SetupListenerFacts => ({
  key: 'a',
  label: 'VLESS + REALITY',
  validCombo: true,
  deployed: true,
  enabled: true,
  retired: false,
  layers: ['l4'],
  excluded: { l7: 'protocol_not_http_transport' },
  needsTarget: true,
  hasTarget: true,
  usesSni: true,
  activeNames: 2,
  l7Only: false,
  templateEdgeId: null,
  ...over,
});

const account = (over: Partial<SetupAccountFacts> = {}): SetupAccountFacts => ({
  id: 'acct1',
  name: 'acct-a',
  provider: 'gcore',
  layer: 'l4',
  enabled: true,
  tested: true,
  testFailed: false,
  qualified: false,
  qualificationCurrent: false,
  frontsListeners: ['a'],
  dnsAccountMissing: false,
  zoneModeUnknown: false,
  zoneWebsocketsOff: false,
  templateOk: true,
  templateInvalid: false,
  defaultTemplateId: null,
  ...over,
});

const relay = (over: Partial<SetupRelayFacts> = {}): SetupRelayFacts => ({
  id: 'r1',
  slug: 'node-one',
  enabled: true,
  deleting: false,
  quarantined: false,
  hostMode: 'fcp',
  autoRotate: false,
  publishedCount: 0,
  rotation: null,
  lastRotation: null,
  edges: [],
  deliveryRequired: true,
  connectionPlanCount: 0,
  mirrorsUnvalidated: 0,
  qualificationCredential: false,
  credentialSupported: true,
  ...over,
});

const base = (over: Partial<SetupInput> = {}): SetupInput => ({
  origin: {
    kind: 'panel-node',
    backendPresent: true,
    backendHealthy: true,
    backendHostManagement: true,
    backendNodeInventory: true,
  },
  listeners: [listener()],
  accounts: [account()],
  relay: relay(),
  render: { enabled: true, preview: null },
  config: {
    edgeEnabled: false,
    autoRotate: false,
    l7AutoSelect: false,
    probeEnabled: false,
    probeSourcesOn: 0,
    probeCountries: 0,
  },
  ...over,
});

const step = (r: ReturnType<typeof computeSetupStatus>, id: string) =>
  r.steps.find((s) => s.id === id)!;
const codes = (r: ReturnType<typeof computeSetupStatus>, id: string) =>
  step(r, id).blockers.map((b) => b.code);

describe('computeSetupStatus', () => {
  test('every step id appears once, in order, and every blocker code is in the shared vocabulary', () => {
    const r = computeSetupStatus(base({ accounts: [], relay: null, origin: null }));
    expect(r.steps.map((s) => s.id)).toEqual([...SETUP_STEP_IDS]);
    for (const s of r.steps)
      for (const b of [...s.blockers, ...s.warnings]) expect(SETUP_BLOCKER_CODES).toContain(b.code);
  });

  test('nothing configured: origin missing is the current step, later steps carry their own blockers but are not ready', () => {
    const r = computeSetupStatus(base({ origin: null, accounts: [], relay: null, listeners: [] }));
    expect(r.currentStep).toBe('origin');
    expect(step(r, 'origin').status).toBe('ready');
    expect(codes(r, 'origin')).toEqual(['no_origin']);
    expect(step(r, 'account').status).toBe('blocked');
    expect(codes(r, 'account')).toEqual(['no_provider_account']);
    expect(codes(r, 'relay')).toEqual(['no_relay']);
    expect(r.complete).toBe(false);
  });

  test('an untested account blocks the account step by name; a failed test says so', () => {
    const r = computeSetupStatus(
      base({
        accounts: [
          account({ id: 'u', name: 'untested', tested: false }),
          account({ id: 'f', name: 'failed', tested: false, testFailed: true }),
        ],
      }),
    );
    expect(r.currentStep).toBe('account');
    expect(step(r, 'account').blockers).toEqual([
      { code: 'credentials_untested', subject: 'untested', detail: null },
      { code: 'credentials_failed', subject: 'failed', detail: null },
    ]);
  });

  test('an account that cannot front any listener is not compatible (L7-only account, raw REALITY listener)', () => {
    const r = computeSetupStatus(
      base({ accounts: [account({ layer: 'l7', provider: 'cloudflare', frontsListeners: [] })] }),
    );
    expect(codes(r, 'account')).toEqual(['no_compatible_account']);
  });

  test('a tested but unqualified account passes the account step; the edge step is current with no_edge and members_dark is a warning on the relay step', () => {
    const r = computeSetupStatus(base());
    expect(step(r, 'account').status).toBe('done');
    expect(step(r, 'template').status).toBe('done');
    expect(step(r, 'relay').status).toBe('done');
    expect(step(r, 'relay').warnings.map((w) => w.code)).toEqual(['members_dark']);
    expect(r.currentStep).toBe('edge');
    expect(codes(r, 'edge')).toEqual(['no_edge']);
    expect(r.context).toMatchObject({ accountId: 'acct1', listenerKey: 'a' });
  });

  test('listener problems block the relay step per listener key', () => {
    const r = computeSetupStatus(
      base({
        listeners: [
          listener({ key: 'a', deployed: false }),
          listener({ key: 'b', hasTarget: false }),
          listener({ key: 'c', activeNames: 0 }),
          listener({ key: 'd', validCombo: false }),
          listener({
            key: 'e',
            layers: [],
            excluded: { l4: 'no_udp_provider', l7: 'protocol_not_http_transport' },
          }),
        ],
      }),
    );
    expect(step(r, 'relay').blockers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ code: 'listener_not_deployed', subject: 'a' }),
        expect.objectContaining({ code: 'needs_target', subject: 'b' }),
        expect.objectContaining({ code: 'needs_names', subject: 'c' }),
        expect.objectContaining({ code: 'invalid_combination', subject: 'd' }),
        expect.objectContaining({ code: 'no_udp_provider', subject: 'e' }),
      ]),
    );
    expect(r.currentStep).toBe('relay');
  });

  test('a failed bootstrap provision is reported on the edge step; a running one is rotation_running', () => {
    const failed = computeSetupStatus(
      base({
        relay: relay({
          lastRotation: { kind: 'provision', phase: 'failed', outcome: 'accounts_exhausted' },
        }),
      }),
    );
    expect(step(failed, 'edge').blockers).toEqual([
      { code: 'no_edge', subject: 'node-one', detail: null },
      { code: 'provision_failed', subject: 'node-one', detail: 'accounts_exhausted' },
    ]);
    const running = computeSetupStatus(
      base({
        relay: relay({
          rotation: {
            id: 'rot',
            kind: 'provision',
            phase: 'provisioning',
            terminal: false,
            outcome: null,
          },
        }),
      }),
    );
    expect(codes(running, 'edge')).toEqual(['rotation_running']);
  });

  test('an active edge from an unqualified account: qualification is current and names the account', () => {
    const r = computeSetupStatus(
      base({
        relay: relay({
          edges: [
            {
              id: 'e1',
              listenerKey: 'a',
              layer: 'l4',
              provider: 'gcore',
              accountId: 'acct1',
              status: 'active',
              publication: 'unpublished',
              poolIndex: null,
              frontQualification: null,
              publishable: { ok: true },
            },
          ],
        }),
      }),
    );
    expect(step(r, 'edge').status).toBe('done');
    expect(r.currentStep).toBe('qualification');
    expect(step(r, 'qualification').blockers).toEqual([
      { code: 'account_unqualified', subject: 'acct-a', detail: null },
    ]);
    expect(r.context.edgeId).toBe('e1');
  });

  test('a stale qualification (template changed) and an L7 edge without a credential are distinct blockers', () => {
    const r = computeSetupStatus(
      base({
        accounts: [
          account({
            id: 'l7',
            name: 'front',
            provider: 'cloudflare',
            layer: 'l7',
            qualified: true,
          }),
        ],
        listeners: [listener({ key: 'w', layers: ['l4', 'l7'], excluded: {} })],
        relay: relay({
          edges: [
            {
              id: 'e7',
              listenerKey: 'w',
              layer: 'l7',
              provider: 'cloudflare',
              accountId: 'l7',
              status: 'active',
              publication: 'unpublished',
              poolIndex: null,
              frontQualification: null,
              publishable: { ok: false, code: 'front_unqualified' },
            },
          ],
        }),
      }),
    );
    expect(codes(r, 'qualification')).toEqual([
      'qualification_stale',
      'qualification_credential_missing',
    ]);
  });

  test('publish: an empty pool with only unpublishable candidates lists why; operator Hosts are a warning', () => {
    const r = computeSetupStatus(
      base({
        accounts: [account({ qualified: true, qualificationCurrent: true })],
        relay: relay({
          hostMode: 'operator',
          edges: [
            {
              id: 'e1',
              listenerKey: 'a',
              layer: 'l4',
              provider: 'gcore',
              accountId: 'acct1',
              status: 'active',
              publication: 'unpublished',
              poolIndex: null,
              frontQualification: null,
              publishable: { ok: false, code: 'edge_unhealthy' },
            },
          ],
        }),
      }),
    );
    expect(r.currentStep).toBe('publish');
    expect(step(r, 'publish').blockers).toEqual([
      { code: 'pool_empty', subject: 'node-one', detail: null },
      { code: 'no_publishable_edge', subject: 'e1', detail: 'edge_unhealthy' },
    ]);
    expect(step(r, 'publish').warnings.map((w) => w.code)).toEqual(['hosts_operator_managed']);
  });

  const published = (): SetupRelayFacts =>
    relay({
      publishedCount: 1,
      connectionPlanCount: 1,
      edges: [
        {
          id: 'e1',
          listenerKey: 'a',
          layer: 'l4',
          provider: 'gcore',
          accountId: 'acct1',
          status: 'active',
          publication: 'published',
          poolIndex: 0,
          frontQualification: null,
          publishable: null,
        },
      ],
    });

  test('rendering: disabled switch, disabled relay, a preview that did not apply and mismatches each block', () => {
    const r = computeSetupStatus(
      base({
        accounts: [account({ qualified: true, qualificationCurrent: true })],
        relay: published(),
        render: {
          enabled: false,
          preview: {
            family: 'singbox',
            applied: false,
            reason: 'no_match',
            emitted: 0,
            mismatched: 1,
          },
        },
      }),
    );
    expect(step(r, 'publish').status).toBe('done');
    expect(r.currentStep).toBe('rendering');
    expect(codes(r, 'rendering')).toEqual([
      'render_disabled',
      'preview_not_applied',
      'entry_mismatch',
    ]);
  });

  test('a manual origin skips rendering; its publish step is done once the connection plan exists', () => {
    const r = computeSetupStatus(
      base({
        origin: {
          kind: 'manual',
          backendPresent: true,
          backendHealthy: null,
          backendHostManagement: false,
          backendNodeInventory: false,
        },
        accounts: [account({ qualified: true, qualificationCurrent: true })],
        relay: published(),
      }),
    );
    expect(step(r, 'rendering').status).toBe('skipped');
    expect(step(r, 'publish').status).toBe('done');
    expect(r.complete).toBe(true);
    expect(r.currentStep).toBeNull();
  });

  test('complete setup: automation stays optional (warnings only) and never blocks completion', () => {
    const r = computeSetupStatus(
      base({
        accounts: [account({ qualified: true, qualificationCurrent: true })],
        relay: published(),
        render: {
          enabled: true,
          preview: { family: 'singbox', applied: true, reason: null, emitted: 2, mismatched: 0 },
        },
      }),
    );
    expect(r.complete).toBe(true);
    expect(r.currentStep).toBeNull();
    expect(step(r, 'automation').status).toBe('ready');
    expect(step(r, 'automation').warnings.map((w) => w.code)).toEqual([
      'probes_disabled',
      'edge_layer_disabled',
      'auto_rotate_off',
    ]);
  });

  test('automation with everything on is done; an L7 listener with the L7 gate off is a warning', () => {
    const on = computeSetupStatus(
      base({
        accounts: [account({ qualified: true, qualificationCurrent: true })],
        relay: { ...published(), autoRotate: true },
        render: { enabled: true, preview: null },
        listeners: [listener(), listener({ key: 'w', layers: ['l4', 'l7'], excluded: {} })],
        config: {
          edgeEnabled: true,
          autoRotate: true,
          l7AutoSelect: false,
          probeEnabled: true,
          probeSourcesOn: 2,
          probeCountries: 3,
        },
      }),
    );
    expect(step(on, 'automation').warnings.map((w) => w.code)).toEqual(['l7_auto_select_blocked']);
  });

  test('origin problems: a missing backend blocks; missing Host management on a panel node is only a warning', () => {
    const missing = computeSetupStatus(
      base({
        origin: {
          kind: 'panel-node',
          backendPresent: false,
          backendHealthy: null,
          backendHostManagement: false,
          backendNodeInventory: false,
        },
      }),
    );
    expect(codes(missing, 'origin')).toEqual(['no_backend_server']);
    const noHosts = computeSetupStatus(
      base({
        origin: {
          kind: 'panel-node',
          backendPresent: true,
          backendHealthy: true,
          backendHostManagement: false,
          backendNodeInventory: false,
        },
      }),
    );
    expect(step(noHosts, 'origin').status).toBe('done');
    expect(step(noHosts, 'origin').warnings.map((w) => w.code)).toEqual([
      'backend_no_host_management',
      'backend_no_node_inventory',
    ]);
  });
});
