import { describe, expect, test } from 'vitest';
import { ATTENTION_ACTIONS } from '../../src/shared/contracts/edgeCodes';
import { attentionTarget } from '../../src/client/routes/admin/edges/lib/attention';
import {
  EMPTY_STATE,
  HOLD_DOWN_MS,
  MAX_FRESH_MESSAGES,
  REMIND_MS,
  RESOLVE_AFTER_MS,
  addressLike,
  adminOrigin,
  alertPath,
  alertTitle,
  alertWorthy,
  applyEffects,
  describeAlert,
  parseAlertState,
  planAlerts,
  sinceLine,
  testMessage,
  type AlertSource,
  type AlertState,
} from './alertMessages';

const NOW = Date.parse('2026-11-08T12:00:00Z');
const MIN = 60_000;

function src(over: Partial<AlertSource> & Pick<AlertSource, 'kind'>): AlertSource {
  return {
    id: `${over.kind}:1`,
    severity: 'critical',
    code: null,
    facts: {},
    since: null,
    action: 'open_relay',
    relaySlug: 'fra-1',
    edgeId: null,
    listenerKey: null,
    accountId: null,
    rotationId: null,
    labels: { node: 'Frankfurt 1' },
    ...over,
  };
}

/** One source per kind that alerts, as the attention list or the system signals raise it. */
const EVERY_ALERT: AlertSource[] = [
  src({
    kind: 'quarantine',
    code: 'flip_unconfirmed',
    action: 'resolve_quarantine',
    rotationId: 'r1',
  }),
  src({
    kind: 'fleet_brake',
    relaySlug: null,
    labels: {},
    action: 'open_settings',
    facts: { suspected: 5, evaluated: 6, threshold: 50 },
  }),
  src({ kind: 'auto_replace_held', listenerKey: 'vless-ws', code: 'reblocked_soon' }),
  src({
    kind: 'needs_operator',
    action: 'resolve_operator',
    edgeId: 'e1',
    code: 'provision_failed',
    labels: { node: 'Frankfurt 1', account: 'CDN main', location: 'Europe' },
  }),
  src({
    kind: 'account_api_failing',
    relaySlug: null,
    labels: {},
    accountId: 'a1',
    action: 'open_account',
    code: 'timeout',
    facts: { name: 'CDN main', failures: 7 },
  }),
  src({ kind: 'rotation_stuck', facts: { kind: 'replace', phase: 'verifying', minutes: 95 } }),
  src({
    kind: 'host_unresolved',
    listenerKey: 'vless-ws',
    code: 'ambiguous',
    action: 'look_at_host',
  }),
  src({ kind: 'members_dark', code: 'empty_pool', action: 'open_setup' }),
  src({
    kind: 'delivery_refusals',
    relaySlug: null,
    labels: {},
    action: 'open_settings',
    code: 'empty_pool',
    facts: { total: 240, byReason: { empty_pool: 200, app_notice: 40 }, windowMinutes: 60 },
  }),
  src({
    kind: 'freedom_node_withheld',
    severity: 'warning',
    code: 'withheld_no_edge',
    facts: { serverSlug: 'panel-a', node: 'Frankfurt 1' },
  }),
  src({ kind: 'direct_host_reappeared', facts: { count: 2 } }),
  src({
    kind: 'node_awaiting_approval',
    severity: 'warning',
    action: 'open_node',
    relaySlug: null,
    labels: {},
    code: 'awaiting_approval',
    facts: { node: 'Warsaw 2', serverSlug: 'panel-a', nodeUuid: 'u-2' },
  }),
  src({
    kind: 'node_ready_to_protect',
    severity: 'warning',
    action: 'protect_node',
    relaySlug: null,
    labels: {},
    facts: { node: 'Warsaw 2', serverSlug: 'panel-a', nodeUuid: 'u-2' },
  }),
  src({ kind: 'needs_test', code: 'no_verified_spare', facts: { untestedSpares: 1 } }),
  src({
    kind: 'certificate_waiting',
    relaySlug: null,
    labels: {},
    accountId: 'a1',
    action: 'open_account',
    code: 'caa_blocks',
    facts: { name: 'CDN main', state: 'failed', notAfter: '2026-11-10T00:00:00Z' },
  }),
  src({ kind: 'address_name_stuck', facts: { attempts: 4, removing: true } }),
  src({ kind: 'audience_only_left', listenerKey: 'vless-reality', facts: { count: 2 } }),
  src({
    kind: 'client_check_unavailable',
    relaySlug: null,
    labels: {},
    action: 'open_settings',
    code: 'timeout',
  }),
  src({
    kind: 'location_refused',
    severity: 'warning',
    accountId: 'a2',
    action: 'open_account',
    code: 'quota_exceeded',
    facts: { name: 'Cloud B', location: 'Istanbul', minutesLeft: 300 },
  }),
  src({
    kind: 'block_suspected',
    severity: 'warning',
    code: 'daily_cap',
    facts: { heldBack: true, score: 0.82, countries: ['IR', 'RU'] },
  }),
  src({
    kind: 'account_spend_cap',
    severity: 'warning',
    relaySlug: null,
    labels: {},
    accountId: 'a1',
    action: 'open_account',
    facts: { name: 'CDN main', monthly: 45, cap: 45, currency: 'EUR' },
  }),
  src({
    kind: 'fleet_rotation_cap',
    severity: 'warning',
    relaySlug: null,
    labels: {},
    action: 'open_settings',
    facts: { used: 20, cap: 20 },
  }),
  src({
    kind: 'edge_unreachable',
    severity: 'warning',
    action: 'open_edge',
    edgeId: 'e1',
    labels: { node: 'Frankfurt 1', account: 'CDN main', location: 'Europe' },
    facts: { countries: ['IR'], probes: [{ country: 'IR', ok: 0, failed: 6 }] },
  }),
  src({
    kind: 'probe_source_failing',
    severity: 'warning',
    relaySlug: null,
    labels: {},
    action: 'open_settings',
    code: 'credential_refused',
    facts: { source: 'vantage-a', streak: 12, lastOkAt: '2026-11-08T08:00:00Z' },
  }),
  src({
    kind: 'node_offline',
    action: null,
    relaySlug: null,
    labels: { node: 'Frankfurt 1' },
    facts: { serverSlug: 'panel-a', nodeUuid: 'u-1' },
    path: '/admin/servers/nodes/u-1?instance=panel-a',
  }),
  src({
    kind: 'backend_unhealthy',
    action: null,
    relaySlug: null,
    labels: {},
    facts: { serverSlug: 'panel-a' },
    path: '/admin/servers/backends',
  }),
  src({
    kind: 'cron_stale',
    severity: 'warning',
    action: null,
    relaySlug: null,
    labels: {},
    facts: { job: 'edge-probe', description: 'Probe edges', everyMs: 5 * MIN },
    path: '/admin/dashboard',
  }),
  src({
    kind: 'cron_failing',
    severity: 'warning',
    action: null,
    relaySlug: null,
    labels: {},
    facts: { job: 'mirror-refresh', description: 'Refresh mirrors', everyMs: 6 * 60 * MIN },
    path: '/admin/dashboard',
  }),
  src({
    kind: 'spend_near_cap',
    severity: 'warning',
    action: null,
    relaySlug: null,
    labels: { account: 'CDN main' },
    accountId: 'a1',
    facts: { monthly: 41, cap: 45, currency: 'EUR' },
    path: '/admin/edges/providers/a1',
  }),
];

describe('one alert', () => {
  test('every kind that alerts is named, says what, since when and what next, in three lines', () => {
    const plan = planAlerts({
      now: NOW,
      state: EMPTY_STATE,
      current: EVERY_ALERT.map((s) => ({ ...s, id: s.kind })),
      origin: 'https://admin.example.org',
      topic: 't',
    });
    expect(EVERY_ALERT.every((s) => alertWorthy(s))).toBe(true);
    for (const s of EVERY_ALERT) {
      const t = describeAlert(s, NOW);
      // Every kind has its own words, not the generic fallback.
      expect(t.what, s.kind).not.toMatch(/^Reason:|needs you to look at this/);
      expect(t.next, s.kind).toMatch(/^Next: [A-Z]/);
      expect(t.path.startsWith('/admin/'), s.kind).toBe(true);
      const all = `${alertTitle(t)}\n${t.what}\n${t.next}`;
      // Plain words: no em-dash, never "names" for hostnames, no raw ids.
      expect(all, s.kind).not.toMatch(/—|\bnames?\b|undefined|null|NaN|\[object/);
    }
    // The most urgent go out one each, with their click link; the rest wait.
    expect(plan.messages).toHaveLength(MAX_FRESH_MESSAGES);
    for (const m of plan.messages) {
      expect(m.body.message.split('\n')).toHaveLength(3);
      expect(m.body.click).toMatch(/^https:\/\/admin\.example\.org\/admin\//);
      expect(m.body.topic).toBe('t');
    }
  });

  test('the words carry the numbers and labels that matter', () => {
    const by = (kind: string) => {
      const t = describeAlert(
        EVERY_ALERT.find((s) => s.kind === kind)!,
        NOW,
      );
      return `${alertTitle(t)} | ${t.what} | ${t.next}`;
    };
    expect(by('edge_unreachable')).toBe(
      'Address unreachable: Frankfurt 1 | An address in use at CDN main, Europe is reachable from 0 of 6 probes in IR. | Next: Check the country view; replace the address if FCP has not.',
    );
    expect(by('spend_near_cap')).toContain(
      'Spend near cap: CDN main | EUR 41 of EUR 45 a month (91%).',
    );
    expect(by('account_spend_cap')).toContain('EUR 45 of EUR 45 a month');
    expect(by('fleet_brake')).toContain('5 of 6 nodes look blocked at once (brake above 50%)');
    expect(by('rotation_stuck')).toContain('A replacement has run 1 h 35 min, at step "Verifying"');
    expect(by('account_api_failing')).toMatch(
      /^Provider account failing: CDN main \| Its API failed 7 times/,
    );
    expect(by('location_refused')).toMatch(/^Provider refused a location: Cloud B, Istanbul/);
    expect(by('location_refused')).toContain('for 5 h');
    expect(by('block_suspected')).toContain('looks blocked in IR, RU (score 0.82)');
    expect(by('block_suspected')).toContain('"daily cap reached" holds it');
    expect(by('delivery_refusals')).toContain(
      '240 refusals in the last 1 h, most for "empty pool" (200)',
    );
    expect(by('node_awaiting_approval')).toMatch(
      /^Node waits for approval: Warsaw 2 \| .*on backend panel-a/,
    );
    expect(by('certificate_waiting')).toContain('it expires in 1 day');
    expect(by('probe_source_failing')).toContain('last good 4 h ago');
    expect(by('cron_stale')).toMatch(
      /^Scheduled job stopped: edge-probe \| It has stopped running; it should run every 5 min\. It does: Probe edges\./,
    );
  });

  test('priority by severity; prompts that only wait on the operator are default priority', () => {
    const p = (kind: string) =>
      describeAlert(
        EVERY_ALERT.find((s) => s.kind === kind)!,
        NOW,
      );
    expect(p('quarantine')).toMatchObject({ priority: 5, tags: ['rotating_light', 'quarantine'] });
    expect(p('block_suspected')).toMatchObject({
      priority: 4,
      tags: ['warning', 'block_suspected'],
    });
    expect(p('node_ready_to_protect').priority).toBe(3);
    expect(p('node_awaiting_approval').priority).toBe(3);
  });

  test('never an address, an internal id, free text or a secret', () => {
    const t = describeAlert(
      src({
        kind: 'needs_operator',
        id: 'needs_operator:jd7abc',
        code: 'refused: token tk_live_123 at 203.0.113.9',
        relaySlug: 'fra-1',
        edgeId: 'jd7edge',
        labels: { node: '203.0.113.10', account: 'CDN main', location: '2001:db8::1' },
      }),
      NOW,
    );
    const all = JSON.stringify(t);
    expect(all).not.toMatch(/203\.0\.113|2001:db8|tk_live|refused:/);
    // An address-like label falls back to the node's slug.
    expect(alertTitle(t)).toBe('Address needs you: fra-1');
    // The edge id only travels inside the link, as the admin page needs it.
    expect(t.what).not.toContain('jd7edge');
  });

  test('every form of an IP address is refused as a label', () => {
    for (const a of [
      '203.0.113.9',
      'node 203.0.113.9',
      '::1',
      'fe80::',
      'fe80::1%eth0',
      '2001:db8::1',
      '2001:0db8:0000:0000:0000:0000:0000:0001',
      '::ffff:192.0.2.1',
      'edge (::1)',
    ])
      expect(addressLike(a), a).toBe(true);
    for (const ok of [
      'Frankfurt 1',
      'CDN main',
      'node-one',
      '🇩🇪 Frankfurt',
      'v1.2',
      'Europe West 10:20',
    ])
      expect(addressLike(ok), ok).toBe(false);
    const t = describeAlert(src({ kind: 'members_dark', labels: { node: 'fe80::1' } }), NOW);
    expect(alertTitle(t)).toBe('Members get nothing: fra-1');
  });

  test('an unknown critical kind still says something useful', () => {
    const t = describeAlert(src({ kind: 'brand_new_kind', code: 'daily_cap' }), NOW);
    expect(alertTitle(t)).toBe('Brand new kind: Frankfurt 1');
    expect(t.what).toBe('Reason: daily cap reached.');
    expect(t.next).toMatch(/^Next: /);
  });
});

describe('links', () => {
  test('every attention action opens the page its admin row opens', () => {
    for (const action of ATTENTION_ACTIONS) {
      for (const shape of [
        {
          relaySlug: 'fra-1',
          facts: { runId: 'run1', family: 'fam', nodeUuid: 'u1', serverSlug: 'p' },
        },
        { relaySlug: null, facts: {} },
      ]) {
        const s = src({
          kind: 'quarantine',
          action,
          relaySlug: shape.relaySlug,
          edgeId: 'e1',
          rotationId: 'r1',
          accountId: 'a1',
          listenerKey: 'vless-ws',
          facts: shape.facts,
        });
        const item = {
          id: s.id,
          kind: 'quarantine' as const,
          severity: 'critical' as const,
          relaySlug: s.relaySlug,
          relayId: null,
          edgeId: s.edgeId,
          listenerKey: s.listenerKey,
          accountId: s.accountId,
          rotationId: s.rotationId,
          code: null,
          facts: s.facts,
          action,
          since: null,
        };
        expect(alertPath(s), `${action} ${shape.relaySlug}`).toBe(attentionTarget(item));
      }
    }
  });

  test('the admin origin is the first WEBAUTHN_ORIGIN, https only', () => {
    expect(adminOrigin('https://ops.example.org, https://other.example.org')).toBe(
      'https://ops.example.org',
    );
    expect(adminOrigin('https://ops.example.org/admin')).toBe('https://ops.example.org');
    expect(adminOrigin('http://ops.example.org')).toBeNull();
    expect(adminOrigin('http://localhost:5173')).toBe('http://localhost:5173');
    expect(adminOrigin(undefined)).toBeNull();
    expect(adminOrigin('not a url')).toBeNull();
  });

  test('without an origin, alerts go out without a click link', () => {
    const plan = planAlerts({
      now: NOW,
      state: EMPTY_STATE,
      current: [src({ kind: 'members_dark', code: 'empty_pool' })],
      origin: null,
      topic: '',
    });
    expect(plan.messages[0]!.body).not.toHaveProperty('click');
    expect(plan.messages[0]!.body).not.toHaveProperty('topic');
    expect(testMessage(null, '').message).toContain('WEBAUTHN_ORIGIN');
    expect(testMessage('https://ops.example.org', 'x')).toMatchObject({
      click: 'https://ops.example.org/admin/settings',
      topic: 'x',
    });
  });
});

describe('since', () => {
  test('time of day today, the date before today, and how long', () => {
    expect(sinceLine(NOW - 35 * MIN, NOW)).toBe('Since 11:25 UTC (35 min).');
    expect(sinceLine(Date.parse('2026-11-06T09:05:00Z'), NOW)).toBe(
      'Since 6 Nov 09:05 UTC (2 d 2 h).',
    );
  });

  test("an item's own start is used, else when FCP first saw it", () => {
    const plan = planAlerts({
      now: NOW,
      state: EMPTY_STATE,
      current: [src({ kind: 'quarantine', since: '2026-11-08T10:00:00.000Z' })],
      origin: null,
      topic: '',
    });
    expect(plan.messages[0]!.body.message).toContain('Since 10:00 UTC (2 h).');
  });
});

describe('the plan', () => {
  const run = (state: AlertState, current: AlertSource[], now: number) => {
    const plan = planAlerts({ now, state, current, origin: null, topic: '' });
    let next = plan.base;
    for (const m of plan.messages) next = applyEffects(next, m.effects, now);
    return { plan, next };
  };

  test('sent once while open; a warning that blinks alerts only once it stays', () => {
    const blocked = src({
      kind: 'edge_unreachable',
      severity: 'warning',
      facts: { countries: ['IR'] },
    });
    let { plan, next } = run(EMPTY_STATE, [blocked], NOW);
    expect(plan.messages).toHaveLength(0);
    expect(next.pending[blocked.id]).toBe(NOW);
    ({ plan, next } = run(next, [blocked], NOW + HOLD_DOWN_MS.edge_unreachable! - MIN));
    expect(plan.messages).toHaveLength(0);
    ({ plan, next } = run(next, [blocked], NOW + HOLD_DOWN_MS.edge_unreachable!));
    expect(plan.messages).toHaveLength(1);
    expect(next.pending).toEqual({});
    ({ plan } = run(next, [blocked], NOW + HOLD_DOWN_MS.edge_unreachable! + 5 * MIN));
    expect(plan.messages).toHaveLength(0);
    // Gone before its hold-down passed: never sent, and forgotten.
    const blink = run(EMPTY_STATE, [blocked], NOW).next;
    expect(run(blink, [], NOW + 5 * MIN).next.pending).toEqual({});
  });

  test('a failed post keeps the hold-down that already passed', () => {
    const offline = src({ kind: 'node_offline', path: '/admin/servers' });
    const first = planAlerts({
      now: NOW,
      state: EMPTY_STATE,
      current: [offline],
      origin: null,
      topic: '',
    });
    expect(first.messages).toHaveLength(0);
    const later = NOW + HOLD_DOWN_MS.node_offline!;
    const due = planAlerts({
      now: later,
      state: first.base,
      current: [offline],
      origin: null,
      topic: '',
    });
    expect(due.messages).toHaveLength(1);
    // The post failed: the base keeps when it was first seen, so the next tick sends it.
    const retry = planAlerts({
      now: later + 5 * MIN,
      state: due.base,
      current: [offline],
      origin: null,
      topic: '',
    });
    expect(retry.messages).toHaveLength(1);
  });

  test('a held-down alert with no start of its own says how long since FCP first saw it', () => {
    const offline = src({ kind: 'node_offline', path: '/admin/servers' });
    const first = planAlerts({
      now: NOW,
      state: EMPTY_STATE,
      current: [offline],
      origin: null,
      topic: '',
    });
    const later = NOW + HOLD_DOWN_MS.node_offline!;
    const due = planAlerts({
      now: later,
      state: first.base,
      current: [offline],
      origin: null,
      topic: '',
    });
    expect(due.messages[0]!.body.message).toContain('Since 12:00 UTC (15 min).');
    // A retry after a failed post still counts from the first sighting.
    const retry = planAlerts({
      now: later + 5 * MIN,
      state: due.base,
      current: [offline],
      origin: null,
      topic: '',
    });
    expect(retry.messages[0]!.body.message).toContain('Since 12:00 UTC (20 min).');
  });

  test("an item's own hold-down wins over its kind's", () => {
    const never = src({
      kind: 'cron_stale',
      severity: 'warning',
      holdDownMs: 60 * MIN,
      facts: { job: 'x', never: true },
    });
    expect(run(EMPTY_STATE, [never], NOW).plan.messages).toHaveLength(0);
    const r = run(run(EMPTY_STATE, [never], NOW).next, [never], NOW + 60 * MIN);
    expect(r.plan.messages).toHaveLength(1);
    expect(r.plan.messages[0]!.body.message).toMatch(/^It has never run\./);
  });

  test('a warning that turns critical is not sent twice', () => {
    const w = src({ kind: 'host_unresolved', severity: 'critical' });
    const { next } = run(EMPTY_STATE, [w], NOW);
    expect(run(next, [{ ...w, severity: 'warning' }], NOW + MIN).plan.messages).toHaveLength(0);
    expect(run(next, [w], NOW + 2 * MIN).plan.messages).toHaveLength(0);
  });

  test('several of one kind share a message; past the cap the rest wait and arrive in full', () => {
    const offline = ['A', 'B', 'C', 'D', 'E'].map((n) =>
      src({
        kind: 'members_dark',
        id: `members_dark:${n}`,
        code: 'empty_pool',
        labels: { node: `Node ${n}` },
      }),
    );
    const { plan } = run(EMPTY_STATE, offline, NOW);
    expect(plan.messages).toHaveLength(1);
    expect(plan.messages[0]!.body.title).toBe('Members get nothing: 5 at once');
    expect(plan.messages[0]!.body.message).toMatch(/^Node A, Node B, Node C and 2 more\. First: /);
    expect(plan.messages[0]!.effects).toHaveLength(5);

    const kinds = EVERY_ALERT.filter((s) => !HOLD_DOWN_MS[s.kind]);
    const many = run(EMPTY_STATE, kinds, NOW);
    expect(many.plan.messages).toHaveLength(MAX_FRESH_MESSAGES);
    // The most urgent go first, one each.
    expect(many.plan.messages.every((m) => m.body.priority === 5)).toBe(true);
    // The rest arrive in full over the next ticks, each once, with its own link.
    let state = many.next;
    let tick = NOW;
    let delivered = MAX_FRESH_MESSAGES;
    while (Object.keys(state.sent).length < kinds.length) {
      tick += 5 * MIN;
      const r = run(state, kinds, tick);
      expect(r.plan.messages.length).toBeGreaterThan(0);
      expect(r.plan.messages.length).toBeLessThanOrEqual(MAX_FRESH_MESSAGES);
      for (const m of r.plan.messages) expect(m.body.message.split('\n')).toHaveLength(3);
      delivered += r.plan.messages.length;
      state = r.next;
    }
    expect(delivered).toBe(kinds.length);
    expect(run(state, kinds, tick + 5 * MIN).plan.messages).toHaveLength(0);
  });

  test('a critical alert still open is sent again every 12 h; a warning is not', () => {
    const crit = src({ kind: 'members_dark', code: 'empty_pool' });
    const warn = src({ kind: 'location_refused', severity: 'warning', facts: { name: 'B' } });
    let { next } = run(EMPTY_STATE, [crit, warn], NOW);
    let r = run(next, [crit, warn], NOW + REMIND_MS - MIN);
    expect(r.plan.messages).toHaveLength(0);
    r = run(r.next, [crit, warn], NOW + REMIND_MS);
    expect(r.plan.messages).toHaveLength(1);
    expect(r.plan.messages[0]!.body).toMatchObject({
      title: 'Still open: Members get nothing: Frankfurt 1',
      priority: 4,
    });
    next = r.next;
    expect(run(next, [crit, warn], NOW + REMIND_MS + 6 * 60 * MIN).plan.messages).toHaveLength(0);
    expect(run(next, [crit, warn], NOW + 2 * REMIND_MS).plan.messages).toHaveLength(1);
  });

  test('resolved once gone for the window; back before it, still open and silent', () => {
    const crit = src({ kind: 'quarantine', code: 'flip_unconfirmed' });
    let r = run(EMPTY_STATE, [crit], NOW);
    r = run(r.next, [], NOW + 5 * MIN);
    expect(r.plan.messages).toHaveLength(0);
    expect(r.next.sent[crit.id]!.goneAt).toBe(NOW + 5 * MIN);
    // Back within the window: nothing sent, the gone mark cleared.
    r = run(r.next, [crit], NOW + 10 * MIN);
    expect(r.plan.messages).toHaveLength(0);
    expect(r.next.sent[crit.id]!.goneAt).toBeUndefined();
    // Gone for good.
    r = run(r.next, [], NOW + 15 * MIN);
    r = run(r.next, [], NOW + 15 * MIN + RESOLVE_AFTER_MS);
    expect(r.plan.messages).toHaveLength(1);
    expect(r.plan.messages[0]!.body).toMatchObject({
      title: 'Resolved: Node paused for safety: Frankfurt 1',
      priority: 2,
      tags: ['white_check_mark'],
    });
    expect(r.next.sent).toEqual({});
    // A failed "Resolved" post keeps the entry for the next tick.
    const gone = run(run(EMPTY_STATE, [crit], NOW).next, [], NOW + MIN).next;
    const failed = planAlerts({
      now: NOW + MIN + RESOLVE_AFTER_MS,
      state: gone,
      current: [],
      origin: null,
      topic: '',
    });
    expect(failed.messages).toHaveLength(1);
    expect(failed.base.sent[crit.id]).toBeDefined();
  });

  test('several resolved together share one message', () => {
    const a = src({ kind: 'quarantine', id: 'q:a', labels: { node: 'A' } });
    const b = src({ kind: 'members_dark', id: 'd:b', labels: { node: 'B' } });
    let r = run(EMPTY_STATE, [a, b], NOW);
    r = run(r.next, [], NOW + MIN);
    r = run(r.next, [], NOW + MIN + RESOLVE_AFTER_MS);
    expect(r.plan.messages).toHaveLength(1);
    expect(r.plan.messages[0]!.body.title).toBe('Resolved: 2 alerts');
  });

  test('a state from before titles were kept is read, and its gone ids are forgotten quietly', () => {
    const old = parseAlertState({
      sent: { 'quarantine:x': NOW - 60 * MIN },
      lastSentAt: NOW - 60 * MIN,
    });
    expect(old.sent['quarantine:x']).toEqual({ at: NOW - 60 * MIN, title: '' });
    let r = run(old, [], NOW);
    r = run(r.next, [], NOW + RESOLVE_AFTER_MS);
    expect(r.plan.messages).toHaveLength(0);
    expect(r.next.sent).toEqual({});
    expect(parseAlertState(null)).toEqual(EMPTY_STATE);
    expect(parseAlertState({ sent: { x: 'bad' }, pending: { y: 'bad' } })).toMatchObject({
      sent: {},
      pending: {},
    });
  });
});
